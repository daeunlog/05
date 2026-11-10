from datetime import datetime, timezone
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: UUID
    created_at: datetime
    model_status: str
    model_prediction: str | None
    model_confidence: float | None
    model_is_mock: bool
    virustotal_status: str
    virustotal_stats: dict[str, int] | None
    risk_level: str
    is_complete: bool

    @field_validator("created_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class HistoryResponse(BaseModel):
    total: int
    items: list[HistoryItem]
