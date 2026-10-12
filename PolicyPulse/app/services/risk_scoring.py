"""Deterministic additive risk scoring (0-100).

score = min(100, sum(points of every factor))

Factor                     Points
-------------------------  -----------------------------------------------
Resource sensitivity       low 0 | medium 10 | high 20 | critical 30
Requested action           read 0 | write 5 | delete 10 | admin 15
Device trust               trusted 0 | unmanaged 15 | untrusted 25
MFA not verified           +15
Failed logins              5 per failed attempt, capped at 25
Access context             normal 0 | unusual_time 8 | unusual_location 15
                           | anonymized_network 20
RBAC violation             +20 (role lacks permission for resource/action)

Levels: 0-29 low | 30-59 medium | 60-79 high | 80-100 critical
"""
from dataclasses import dataclass
from typing import List

SENSITIVITY_POINTS = {"low": 0, "medium": 10, "high": 20, "critical": 30}
ACTION_POINTS = {"read": 0, "write": 5, "delete": 10, "admin": 15}
DEVICE_POINTS = {"trusted": 0, "unmanaged": 15, "untrusted": 25}
CONTEXT_POINTS = {"normal": 0, "unusual_time": 8, "unusual_location": 15, "anonymized_network": 20}
MFA_MISSING_POINTS = 15
FAILED_LOGIN_POINTS_EACH = 5
FAILED_LOGIN_POINTS_CAP = 25
RBAC_VIOLATION_POINTS = 20
MAX_SCORE = 100

LEVEL_BOUNDS = ((29, "low"), (59, "medium"), (79, "high"), (100, "critical"))


@dataclass(frozen=True)
class RiskFactor:
    factor: str
    value: str
    points: int

    def as_dict(self) -> dict:
        return {"factor": self.factor, "value": self.value, "points": self.points}


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    factors: List[RiskFactor]


def risk_level(score: int) -> str:
    for upper, name in LEVEL_BOUNDS:
        if score <= upper:
            return name
    return "critical"


def compute_risk(
    *, sensitivity: str, action: str, device_trust: str, mfa_verified: bool,
    failed_logins: int, access_context: str, rbac_permitted: bool,
) -> RiskResult:
    factors = [
        RiskFactor("resource_sensitivity", sensitivity, SENSITIVITY_POINTS.get(sensitivity, 30)),
        RiskFactor("action", action, ACTION_POINTS.get(action, 15)),
        RiskFactor("device_trust", device_trust, DEVICE_POINTS.get(device_trust, 25)),
        RiskFactor("mfa", "verified" if mfa_verified else "missing", 0 if mfa_verified else MFA_MISSING_POINTS),
        RiskFactor("failed_logins", str(failed_logins),
                   min(max(failed_logins, 0) * FAILED_LOGIN_POINTS_EACH, FAILED_LOGIN_POINTS_CAP)),
        RiskFactor("access_context", access_context, CONTEXT_POINTS.get(access_context, 20)),
        RiskFactor("rbac", "permitted" if rbac_permitted else "violation",
                   0 if rbac_permitted else RBAC_VIOLATION_POINTS),
    ]
    score = max(0, min(MAX_SCORE, sum(f.points for f in factors)))
    return RiskResult(score=score, level=risk_level(score), factors=factors)
