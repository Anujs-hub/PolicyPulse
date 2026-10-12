"""Persistence, querying, dashboard statistics and CSV export for audit events."""
import csv
import io
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.policy_engine import ENGINE_VERSION, AccessInput, EngineDecision

CSV_COLUMNS = ["event_id", "timestamp", "user_id", "role", "resource_id", "action", "decision",
               "risk_score", "risk_level", "matched_rules", "explanation", "remediation", "metadata"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
RISK_BUCKETS = [("0-19", 0, 19), ("20-39", 20, 39), ("40-59", 40, 59), ("60-79", 60, 79), ("80-100", 80, 100)]


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection by prefixing risky cells with an apostrophe."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def record_evaluation(db: Session, inp: AccessInput, result: EngineDecision) -> AuditLog:
    entry = AuditLog(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        user_id=inp.user_id, role=inp.role, resource_id=inp.resource_id, action=inp.action,
        decision=result.decision, risk_score=result.risk_score, risk_level=result.risk_level,
        matched_rules=[m.as_dict() for m in result.matched_rules],
        explanation=result.explanation, remediation=result.remediation,
        event_metadata={
            "device_trust": inp.device_trust, "mfa_verified": inp.mfa_verified,
            "failed_logins": inp.failed_logins, "access_context": inp.access_context,
            "resource_sensitivity": result.context.get("resource_sensitivity"),
            "rbac_permitted": result.context.get("rbac_permitted"),
            "risk_factors": [f.as_dict() for f in result.risk_factors],
            "skipped_rules": result.skipped_rules, "engine_version": ENGINE_VERSION,
            "simulated": True,
        },
    )
    db.add(entry)
    db.commit()
    return entry


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _filters(*, q=None, decision=None, user_id=None, resource_id=None, min_risk=None,
             max_risk=None, date_from=None, date_to=None) -> list:
    conds = []
    if decision:
        conds.append(AuditLog.decision == decision)
    if user_id:
        conds.append(AuditLog.user_id == user_id)
    if resource_id:
        conds.append(AuditLog.resource_id == resource_id)
    if min_risk is not None:
        conds.append(AuditLog.risk_score >= min_risk)
    if max_risk is not None:
        conds.append(AuditLog.risk_score <= max_risk)
    if date_from:
        conds.append(AuditLog.timestamp >= date_from)
    if date_to:
        conds.append(AuditLog.timestamp <= date_to)
    if q:
        like = f"%{_escape_like(q)}%"
        conds.append(or_(
            AuditLog.user_id.like(like, escape="\\"), AuditLog.resource_id.like(like, escape="\\"),
            AuditLog.event_id.like(like, escape="\\"), AuditLog.explanation.like(like, escape="\\"),
        ))
    return conds


def query_logs(db: Session, *, page: int, page_size: int, **filters) -> Dict[str, Any]:
    conds = _filters(**filters)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*conds)) or 0
    rows = db.scalars(
        select(AuditLog).where(*conds).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size).limit(page_size)
    ).all()
    pages = max(1, -(-total // page_size))
    return {"items": rows, "total": total, "page": page, "page_size": page_size, "pages": pages}


def export_csv(db: Session, *, max_rows: int, **filters) -> Iterator[str]:
    conds = _filters(**filters)
    rows = db.scalars(
        select(AuditLog).where(*conds).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(max_rows)
    ).all()
    import json
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow(CSV_COLUMNS)
    yield buf.getvalue(); buf.seek(0); buf.truncate()
    for r in rows:
        writer.writerow([csv_safe(v) for v in (
            r.event_id, r.timestamp.isoformat(), r.user_id, r.role, r.resource_id, r.action,
            r.decision, r.risk_score, r.risk_level,
            json.dumps([m["code"] for m in r.matched_rules]), r.explanation,
            json.dumps(r.remediation), json.dumps(r.event_metadata, sort_keys=True),
        )])
        yield buf.getvalue(); buf.seek(0); buf.truncate()


def dashboard_stats(db: Session, *, activity_window: int, recent: int = 10) -> Dict[str, Any]:
    total = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    by_decision = dict(db.execute(select(AuditLog.decision, func.count()).group_by(AuditLog.decision)).all())
    counts = {d: int(by_decision.get(d, 0)) for d in ("ALLOW", "DENY", "STEP_UP")}

    buckets = []
    for label, lo, hi in RISK_BUCKETS:
        n = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.risk_score.between(lo, hi))) or 0
        buckets.append({"label": label, "count": int(n)})

    window = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(activity_window)).all()
    rule_hits: Counter = Counter()
    for row in window:
        for m in row.matched_rules:
            rule_hits[(m["code"], m["name"])] += 1
    policy_activity = [{"code": c, "name": n, "hits": h} for (c, n), h in rule_hits.most_common(10)]

    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    since = datetime.combine(days[0], datetime.min.time(), tzinfo=timezone.utc)
    per_day = {d.isoformat(): {"ALLOW": 0, "DENY": 0, "STEP_UP": 0} for d in days}
    for ts, dec in db.execute(select(AuditLog.timestamp, AuditLog.decision).where(AuditLog.timestamp >= since)).all():
        key = (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).date().isoformat()
        if key in per_day:
            per_day[key][dec] += 1
    timeline = [{"date": d, **v} for d, v in per_day.items()]

    recent_rows = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(recent)).all()
    return {
        "total_requests": total, "allowed": counts["ALLOW"], "denied": counts["DENY"],
        "step_up": counts["STEP_UP"], "risk_distribution": buckets,
        "policy_activity": policy_activity, "timeline": timeline,
        "recent_decisions": recent_rows,
        "activity_window": min(activity_window, total),
    }
