from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(16))
    decision: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_level: Mapped[str] = mapped_column(String(16))
    matched_rules: Mapped[list] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text)
    remediation: Mapped[list] = mapped_column(JSON)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSON)
