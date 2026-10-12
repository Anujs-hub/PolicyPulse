from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field

from app.services.catalog import AccessContext, Action, DeviceTrust, Role
from app.services.catalog import RESOURCES
from pydantic import field_validator


class EvaluationRequest(BaseModel):
    """Simulated access request. Every attribute is self-asserted: this is NOT authentication."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    user_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$",
                         description="Simulated identity label (not verified).")
    role: Role
    resource_id: str = Field(min_length=1, max_length=64)
    action: Action
    device_trust: DeviceTrust
    mfa_verified: bool = Field(strict=True, description="Simulated MFA status (not verified).")
    failed_logins: int = Field(ge=0, le=100, strict=True)
    access_context: AccessContext = AccessContext.normal

    @field_validator("resource_id")
    @classmethod
    def _known_resource(cls, v: str) -> str:
        if v not in RESOURCES:
            raise ValueError(f"unknown resource_id; allowed: {sorted(RESOURCES)}")
        return v


class MatchedRuleOut(BaseModel):
    code: str
    name: str
    effect: str
    priority: int
    mandatory: bool
    decisive: bool
    system: bool


class RiskFactorOut(BaseModel):
    factor: str
    value: str
    points: int


class EvaluationResponse(BaseModel):
    request_id: str
    timestamp: datetime
    user_id: str
    role: str
    resource_id: str
    action: str
    decision: str
    risk_score: int
    risk_level: str
    risk_factors: List[RiskFactorOut]
    matched_rules: List[MatchedRuleOut]
    explanation: str
    remediation: List[str]
    disclaimer: str = ("Educational simulation: identity, MFA and device posture are self-asserted "
                       "inputs, not verified facts.")
