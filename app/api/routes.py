"""REST API routes (all under /api, plus /health)."""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import get_db, get_settings_dep
from app.config import Settings
from app.schemas.audit import AuditLogOut, AuditPage
from app.schemas.evaluation import EvaluationRequest, EvaluationResponse
from app.schemas.policy import PolicyCreate, PolicyOut, PolicyUpdate
from app.services import audit_service, catalog, policy_service
from app.services.catalog import Decision
from app.services.policy_engine import AccessInput, evaluate
from app.services.policy_validation import EFFECTS, FIELD_SPECS, OPERATORS
from app.services.scenarios import SCENARIOS

router = APIRouter()

USER_PATTERN = r"^[A-Za-z0-9_.@-]+$"


class DashboardOut(BaseModel):
    total_requests: int
    allowed: int
    denied: int
    step_up: int
    risk_distribution: list
    policy_activity: list
    timeline: list
    recent_decisions: List[AuditLogOut]
    activity_window: int


@router.get("/health", tags=["system"], summary="Liveness and database check")
def health(db: Session = Depends(get_db)):
    from sqlalchemy import text
    db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__, "database": "ok"}


@router.get("/api/catalog", tags=["reference"], summary="Roles, resources, enums and policy field whitelist")
def get_catalog():
    return {
        "roles": [r.value for r in catalog.Role],
        "actions": [a.value for a in catalog.Action],
        "device_trust": [d.value for d in catalog.DeviceTrust],
        "access_contexts": [c.value for c in catalog.AccessContext],
        "resources": [{"id": k, "name": v["name"], "sensitivity": v["sensitivity"],
                       "description": v["description"], "permissions": v["permissions"]}
                      for k, v in catalog.RESOURCES.items()],
        "identities": catalog.SAMPLE_IDENTITIES,
        "policy_fields": FIELD_SPECS, "policy_operators": OPERATORS, "policy_effects": list(EFFECTS),
    }


@router.get("/api/scenarios", tags=["reference"], summary="Sample simulator scenarios")
def get_scenarios():
    return SCENARIOS


@router.post("/api/evaluate", response_model=EvaluationResponse, tags=["evaluation"],
             summary="Evaluate a simulated access request and write an audit event")
def evaluate_request(payload: EvaluationRequest, db: Session = Depends(get_db)):
    inp = AccessInput(
        user_id=payload.user_id, role=payload.role.value, resource_id=payload.resource_id,
        action=payload.action.value, device_trust=payload.device_trust.value,
        mfa_verified=payload.mfa_verified, failed_logins=payload.failed_logins,
        access_context=payload.access_context.value,
    )
    result = evaluate(inp, policy_service.load_rules(db))
    entry = audit_service.record_evaluation(db, inp, result)
    return EvaluationResponse(
        request_id=entry.event_id, timestamp=entry.timestamp, user_id=inp.user_id, role=inp.role,
        resource_id=inp.resource_id, action=inp.action, decision=result.decision,
        risk_score=result.risk_score, risk_level=result.risk_level,
        risk_factors=[f.as_dict() for f in result.risk_factors],
        matched_rules=[m.as_dict() for m in result.matched_rules],
        explanation=result.explanation, remediation=result.remediation,
    )


@router.get("/api/dashboard", response_model=DashboardOut, tags=["dashboard"], summary="Dashboard statistics")
def dashboard(db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)):
    return audit_service.dashboard_stats(db, activity_window=settings.dashboard_activity_window)


@router.get("/api/policies", response_model=List[PolicyOut], tags=["policies"], summary="List policies")
def list_policies(db: Session = Depends(get_db)):
    return policy_service.list_policies(db)


@router.get("/api/policies/{policy_id}", response_model=PolicyOut, tags=["policies"], summary="Get one policy")
def get_policy(policy_id: int, db: Session = Depends(get_db)):
    return policy_service.get_policy(db, policy_id)


@router.post("/api/policies", response_model=PolicyOut, status_code=201, tags=["policies"],
             summary="Create a policy (validated, never executed as code)")
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)):
    return policy_service.create_policy(db, payload)


@router.patch("/api/policies/{policy_id}", response_model=PolicyOut, tags=["policies"],
              summary="Update a policy (mandatory policies are immutable except text fields)")
def update_policy(policy_id: int, payload: PolicyUpdate, db: Session = Depends(get_db)):
    return policy_service.update_policy(db, policy_id, payload)


@router.delete("/api/policies/{policy_id}", status_code=204, tags=["policies"],
               summary="Delete a non-mandatory policy")
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    policy_service.delete_policy(db, policy_id)
    return Response(status_code=204)


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _audit_filters(
    q: Optional[str] = Query(None, max_length=100, description="Search user, resource, event id, explanation"),
    decision: Optional[Decision] = None,
    user_id: Optional[str] = Query(None, max_length=64, pattern=USER_PATTERN),
    resource_id: Optional[str] = Query(None, max_length=64),
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    max_risk: Optional[int] = Query(None, ge=0, le=100),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
) -> dict:
    date_from = _utc(date_from)
    date_to = _utc(date_to)
    if min_risk is not None and max_risk is not None and min_risk > max_risk:
        raise HTTPException(status_code=422, detail="min_risk must be <= max_risk")
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=422, detail="date_from must be <= date_to")
    return dict(q=q, decision=decision.value if decision else None, user_id=user_id, resource_id=resource_id,
                min_risk=min_risk, max_risk=max_risk, date_from=date_from, date_to=date_to)


@router.get("/api/audit-logs", response_model=AuditPage, tags=["audit"], summary="Search audit logs (paginated)")
def audit_logs(
    page: int = Query(1, ge=1, le=1_000_000),
    page_size: int = Query(20, ge=1),
    filters: dict = Depends(_audit_filters),
    db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep),
):
    if page_size > settings.max_page_size:
        raise HTTPException(status_code=422, detail=f"page_size must be <= {settings.max_page_size}")
    return audit_service.query_logs(db, page=page, page_size=page_size, **filters)


@router.get("/api/audit-logs/export", tags=["audit"], summary="Export filtered audit logs as CSV")
def export_audit_logs(filters: dict = Depends(_audit_filters), db: Session = Depends(get_db),
                      settings: Settings = Depends(get_settings_dep)):
    stream = audit_service.export_csv(db, max_rows=settings.export_max_rows, **filters)
    return StreamingResponse(stream, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="policypulse_audit_logs.csv"'})
