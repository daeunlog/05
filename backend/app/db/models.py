from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    scan_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        nullable=False,
    )
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    model_status: Mapped[str] = mapped_column(String(32), nullable=False)
    model_prediction: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_is_mock: Mapped[bool] = mapped_column(Boolean, nullable=False)
    virustotal_status: Mapped[str] = mapped_column(String(32), nullable=False)
    virustotal_stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False)


class VTCache(Base):
    __tablename__ = "vt_cache"

    url_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    stats: Mapped[dict] = mapped_column(JSON, nullable=False)
    last_analysis_date: Mapped[int | None] = mapped_column(nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
