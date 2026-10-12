"""Safe default policies seeded on first start (idempotent, matched by ``code``)."""
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.policy import Policy


def _c(field: str, operator: str, value: Any) -> Dict[str, Any]:
    return {"field": field, "operator": operator, "value": value}


PRIVILEGED = ["write", "delete", "admin"]

DEFAULT_POLICIES: List[Dict[str, Any]] = [
    dict(code="P-001", name="Block excessive failed logins", effect="DENY", priority=10, mandatory=True,
         description="Five or more failed logins indicate credential guessing; access is blocked outright.",
         conditions=[_c("failed_logins", "gte", 5)],
         remediation="Wait for the lockout window or have an administrator reset credentials, and investigate possible credential stuffing."),
    dict(code="P-002", name="Deny untrusted devices on sensitive resources", effect="DENY", priority=20, mandatory=True,
         description="Untrusted devices may never reach high or critical sensitivity resources.",
         conditions=[_c("device_trust", "eq", "untrusted"), _c("sensitivity_level", "gte", 3)],
         remediation="Use a managed, compliant device (simulated device posture) and retry."),
    dict(code="P-003", name="Deny anonymised networks for critical resources", effect="DENY", priority=30, mandatory=False,
         description="Critical resources cannot be reached through anonymising networks.",
         conditions=[_c("access_context", "eq", "anonymized_network"), _c("resource_sensitivity", "eq", "critical")],
         remediation="Connect from a corporate network or approved VPN."),
    dict(code="P-004", name="Deny critical risk scores", effect="DENY", priority=40, mandatory=False,
         description="A composite risk score of 85 or more is too risky to permit.",
         conditions=[_c("risk_score", "gte", 85)],
         remediation="Reduce risk factors (trusted device, MFA, normal context) before retrying."),
    dict(code="P-101", name="Require MFA for privileged actions", effect="STEP_UP", priority=100, mandatory=False,
         description="Write, delete and admin operations require verified MFA.",
         conditions=[_c("mfa_verified", "eq", False), _c("action", "in", PRIVILEGED)],
         remediation="Complete multi-factor authentication, then resubmit the request."),
    dict(code="P-102", name="Require MFA for high-sensitivity resources", effect="STEP_UP", priority=110, mandatory=False,
         description="High and critical resources require verified MFA for any action.",
         conditions=[_c("mfa_verified", "eq", False), _c("sensitivity_level", "gte", 3)],
         remediation="Complete multi-factor authentication, then resubmit the request."),
    dict(code="P-103", name="Step up on unusual access context", effect="STEP_UP", priority=120, mandatory=False,
         description="Unusual time, location or network triggers extra verification.",
         conditions=[_c("access_context", "neq", "normal"), _c("mfa_verified", "eq", False)],
         remediation="Verify with MFA, or retry from your usual location and hours."),
    dict(code="P-104", name="Step up after repeated failed logins", effect="STEP_UP", priority=130, mandatory=False,
         description="Three or more failed logins require additional verification.",
         conditions=[_c("failed_logins", "gte", 3), _c("mfa_verified", "eq", False)],
         remediation="Verify with MFA and consider resetting your password."),
    dict(code="P-105", name="Step up on elevated risk", effect="STEP_UP", priority=140, mandatory=False,
         description="A risk score of 60 or more requires verified MFA.",
         conditions=[_c("risk_score", "gte", 60), _c("mfa_verified", "eq", False)],
         remediation="Complete MFA to reduce the risk of this session."),
    dict(code="P-201", name="Allow permitted low-risk access", effect="ALLOW", priority=500, mandatory=False,
         description="RBAC-permitted requests with a risk score of 49 or lower are allowed.",
         conditions=[_c("rbac_permitted", "eq", True), _c("risk_score", "lte", 49)],
         remediation=""),
    dict(code="P-202", name="Allow permitted access with MFA on trusted devices", effect="ALLOW", priority=510, mandatory=False,
         description="RBAC-permitted requests with verified MFA on a trusted device are allowed up to risk 69.",
         conditions=[_c("rbac_permitted", "eq", True), _c("mfa_verified", "eq", True),
                     _c("device_trust", "eq", "trusted"), _c("risk_score", "lte", 69)],
         remediation=""),
]


def seed_default_policies(db: Session) -> int:
    existing = set(db.scalars(select(Policy.code)).all())
    created = 0
    for spec in DEFAULT_POLICIES:
        if spec["code"] not in existing:
            db.add(Policy(enabled=True, **spec))
            created += 1
    db.commit()
    return created
