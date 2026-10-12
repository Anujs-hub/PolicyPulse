from datetime import datetime
from typing import Any, Dict, List

from datetime import timezone
from pydantic import BaseModel, ConfigDict, field_validator


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    event_id: str
    timestamp: datetime
    user_id: str
    role: str
    resource_id: str
    action: str
    decision: str
    risk_score: int
    risk_level: str
    matched_rules: List[Dict[str, Any]]
    explanation: str
    remediation: List[str]
    event_metadata: Dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def tz_utc(cls, v: datetime) -> datetime:
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


class AuditPage(BaseModel):
    items: List[AuditLogOut]
    total: int
    page: int
    page_size: int
    pages: int
