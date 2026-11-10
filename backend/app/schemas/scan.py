from typing import Literal
from uuid import UUID

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    url: HttpUrl
    allow_external_lookup: bool = False


class ModelResult(BaseModel):
    prediction: Literal["benign"]
    confidence: float
    is_mock: Literal[True]


class VirusTotalStats(BaseModel):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int


class VirusTotalResult(BaseModel):
    status: Literal[
        "skipped",
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
    url: HttpUrl
    model: ModelResult
    virustotal: VirusTotalResult
    risk_level: Literal["unknown"]
    is_complete: Literal[False]
    cached: bool
