from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    conditions: Mapped[list] = mapped_column(JSON)  # list of {field, operator, value}
    effect: Mapped[str] = mapped_column(String(16))  # ALLOW | DENY | STEP_UP
    priority: Mapped[int] = mapped_column(Integer, default=500)  # lower = evaluated first
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
