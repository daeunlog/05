from uuid import uuid4

from fastapi import APIRouter

from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    VirusTotalResult,
)
from app.services.model_service import predict_url

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
def scan_url(request: ScanRequest) -> ScanResponse:
    return ScanResponse(
        scan_id=uuid4(),
        url=request.url,
        model=predict_url(request.url),
        virustotal=VirusTotalResult(),
        risk_level="unknown",
        is_complete=False,
        cached=False,
    )
