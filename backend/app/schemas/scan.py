from typing import Literal
from uuid import UUID

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    url: HttpUrl


class ModelResult(BaseModel):
    prediction: Literal["benign"]
    confidence: float
    is_mock: Literal[True]


class VirusTotalResult(BaseModel):
    status: Literal["pending"] = "pending"


class ScanResponse(BaseModel):
    scan_id: UUID
    url: HttpUrl
    model: ModelResult
    virustotal: VirusTotalResult
    risk_level: Literal["unknown"]
    is_complete: Literal[False]
    cached: Literal[False]
