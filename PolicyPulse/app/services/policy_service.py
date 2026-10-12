"""Policy CRUD with safety rules for mandatory policies."""
import uuid
from typing import List

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.policy import Policy
from app.schemas.policy import PolicyCreate, PolicyUpdate
from app.services.policy_engine import PolicyRule
from app.services.policy_validation import validate_policy_definition

MANDATORY_EDITABLE = {"description", "remediation"}


def to_rule(p: Policy) -> PolicyRule:
    return PolicyRule(code=p.code, name=p.name, description=p.description or "", conditions=list(p.conditions or []),
                      effect=p.effect, priority=p.priority, enabled=p.enabled, mandatory=p.mandatory,
                      remediation=p.remediation or "")


def list_policies(db: Session) -> List[Policy]:
    return list(db.scalars(select(Policy).order_by(Policy.priority, Policy.code)).all())


def load_rules(db: Session) -> List[PolicyRule]:
    return [to_rule(p) for p in list_policies(db) if p.enabled or p.mandatory]


def get_policy(db: Session, policy_id: int) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


def _conflict(msg: str) -> HTTPException:
    return HTTPException(status_code=409, detail=msg)


def create_policy(db: Session, payload: PolicyCreate) -> Policy:
    policy = Policy(
        code=f"TMP-{uuid.uuid4().hex[:12]}", name=payload.name, description=payload.description,
        conditions=payload.normalised_conditions(), effect=payload.effect, priority=payload.priority,
        enabled=payload.enabled, mandatory=False, remediation=payload.remediation,
    )
    db.add(policy)
    try:
        db.flush()
        policy.code = f"CUST-{policy.id:04d}"
        db.commit()
    except IntegrityError:
        db.rollback()
        raise _conflict("A policy with this name already exists")
    return policy


def update_policy(db: Session, policy_id: int, payload: PolicyUpdate) -> Policy:
    policy = get_policy(db, policy_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail=[{"loc": ["body"], "msg": "no fields to update", "type": "value_error"}])
    if policy.mandatory:
        forbidden = sorted(set(changes) - MANDATORY_EDITABLE)
        if forbidden:
            raise HTTPException(
                status_code=403,
                detail=f"Mandatory policy {policy.code} cannot be changed or disabled (immutable fields: {forbidden})",
            )
    new_effect = changes.get("effect", policy.effect)
    new_conditions = changes.get("conditions", policy.conditions)
    try:
        normalised = validate_policy_definition(new_conditions, new_effect)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": ["body", "conditions"], "msg": str(exc), "type": "value_error"}])
    for key, value in changes.items():
        setattr(policy, key, value)
    policy.conditions = normalised
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise _conflict("A policy with this name already exists")
    return policy


def delete_policy(db: Session, policy_id: int) -> None:
    policy = get_policy(db, policy_id)
    if policy.mandatory:
        raise HTTPException(status_code=403, detail=f"Mandatory policy {policy.code} cannot be deleted")
    db.delete(policy)
    db.commit()
