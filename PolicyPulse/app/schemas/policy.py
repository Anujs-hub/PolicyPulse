from datetime import datetime
from typing import Any, List, Optional

from datetime import timezone
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.policy_validation import EFFECTS, validate_policy_definition


class ConditionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(max_length=40)
    operator: str = Field(max_length=10)
    value: Any


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=80)
    description: str = Field(default="", max_length=500)
    conditions: List[ConditionIn] = Field(min_length=1, max_length=8)
    effect: str
    priority: int = Field(default=300, ge=1, le=1000)
    enabled: bool = True
    remediation: str = Field(default="", max_length=500)

    @field_validator("effect")
    @classmethod
    def _effect(cls, v: str) -> str:
        if v not in EFFECTS:
            raise ValueError(f"effect must be one of {list(EFFECTS)}")
        return v

    @model_validator(mode="after")
    def _validate_definition(self) -> "PolicyCreate":
        # Raises ValueError (-> HTTP 422) for unknown fields/operators/values or unsafe ALLOW rules.
        validate_policy_definition([c.model_dump() for c in self.conditions], self.effect)
        return self

    def normalised_conditions(self) -> list:
        return validate_policy_definition([c.model_dump() for c in self.conditions], self.effect)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Optional[str] = Field(default=None, min_length=3, max_length=80)
    description: Optional[str] = Field(default=None, max_length=500)
    conditions: Optional[List[ConditionIn]] = Field(default=None, min_length=1, max_length=8)
    effect: Optional[str] = None
    priority: Optional[int] = Field(default=None, ge=1, le=1000)
    enabled: Optional[bool] = None
    remediation: Optional[str] = Field(default=None, max_length=500)

    @field_validator("effect")
    @classmethod
    def _effect(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in EFFECTS:
            raise ValueError(f"effect must be one of {list(EFFECTS)}")
        return v


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    code: str
    name: str
    description: str
    conditions: list
    effect: str
    priority: int
    enabled: bool
    mandatory: bool
    remediation: str
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at")
    @classmethod
    def tz_utc(cls, v: datetime) -> datetime:
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
