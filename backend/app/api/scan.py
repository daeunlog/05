from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.db.database import get_db
from app.core.identity import owner_id
from app.services.decision import can_share, final_decision
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
    owner: str = Depends(owner_id),
) -> ScanResponse:
    scan_id = uuid4()
    virustotal = VirusTotalResult()
    cached = False

    model = await run_in_threadpool(predict_url, request.url)
    if request.allow_external_lookup and not can_share(request.url):
        virustotal = VirusTotalResult(status="withheld")
    elif request.allow_external_lookup:
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

    level, complete = final_decision(model, virustotal)
    response = ScanResponse(
        scan_id=scan_id,
        url=request.url,
        model=model,
        virustotal=virustotal,
        risk_level=level,
        is_complete=complete,
        cached=cached,
    )

    try:
        await run_in_threadpool(
            save_scan_history,
            db,
            str(request.url),
            response,
            owner,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to save scan history",
        ) from exc

    return response
