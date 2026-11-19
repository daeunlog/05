from typing import Literal
from uuid import UUID

from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=32768)
    allow_external_lookup: bool = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        try:
            parts = urlsplit(value)
            if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
                raise PydanticCustomError("unsupported_scheme", "HTTP or HTTPS required")
            if not parts.hostname or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
                raise ValueError
            parts.port
            AnyHttpUrl(value)
        except PydanticCustomError:
            raise
        except ValueError:
            raise PydanticCustomError("invalid_url", "Invalid URL") from None
        return value


class ModelResult(BaseModel):
    prediction: Literal["benign", "phishing", "malware", "defacement"]
    confidence: float
    is_mock: Literal[False] = False
    scores: dict[str, float]
    ai_risk_score: float = Field(ge=0, le=1)
    ai_risk_level: Literal["low", "caution", "danger"]
    truncated: bool
    model_version: str


class VirusTotalStats(BaseModel):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int


class VirusTotalResult(BaseModel):
    status: Literal[
        "skipped",
        "withheld",
        "completed",
        "not_found",
        "rate_limited",
        "timeout",
        "error",
        "disabled",
    ] = "skipped"
    stats: VirusTotalStats | None = None
    last_analysis_date: int | None = None
    error_code: Literal[
        "missing_api_key",
        "not_found",
        "rate_limited",
        "request_timeout",
        "authentication_error",
        "permission_error",
        "http_error",
        "network_error",
        "invalid_response",
        "cache_error",
    ] | None = None


class ScanResponse(BaseModel):
    scan_id: UUID
    url: str
    model: ModelResult
    virustotal: VirusTotalResult
    risk_level: Literal["unknown", "low", "caution", "danger"]
    is_complete: bool
    cached: bool
