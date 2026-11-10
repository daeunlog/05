from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.db.database import get_db
from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    VirusTotalResult,
)
from app.services.cache_service import get_cached_url_report, save_url_report
from app.services.history_service import save_scan_history
from app.services.model_service import predict_url
from app.services.virustotal_service import get_url_report

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def scan_url(
    request: ScanRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    scan_id = uuid4()
    virustotal = VirusTotalResult()
    cached = False

    if request.allow_external_lookup:
        url = str(request.url)
        try:
            report = await run_in_threadpool(get_cached_url_report, db, url)
        except Exception:
            virustotal = VirusTotalResult(
                status="error",
                error_code="cache_error",
            )
        else:
            if report is not None:
                virustotal = VirusTotalResult(**report)
                cached = True
            else:
                report = await get_url_report(url)
                virustotal = VirusTotalResult(**report)

                if report["status"] == "completed":
                    try:
                        await run_in_threadpool(
                            save_url_report,
                            db,
                            url,
                            report,
                        )
                    except Exception:
                        virustotal = VirusTotalResult(
                            status="error",
                            error_code="cache_error",
                        )

    response = ScanResponse(
        scan_id=scan_id,
        url=request.url,
        model=predict_url(request.url),
        virustotal=virustotal,
        risk_level="unknown",
        is_complete=False,
        cached=cached,
    )

    try:
        await run_in_threadpool(
            save_scan_history,
            db,
            str(request.url),
            response,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to save scan history",
        ) from exc

    return response
