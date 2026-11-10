from uuid import uuid4

from fastapi import APIRouter

from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    VirusTotalResult,
)
from app.services.model_service import predict_url
from app.services.virustotal_service import get_url_report

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest) -> ScanResponse:
    virustotal = VirusTotalResult()
    if request.allow_external_lookup:
        report = await get_url_report(str(request.url))
        virustotal = VirusTotalResult(**report)

    return ScanResponse(
        scan_id=uuid4(),
        url=request.url,
        model=predict_url(request.url),
        virustotal=virustotal,
        risk_level="unknown",
        is_complete=False,
        cached=False,
    )
