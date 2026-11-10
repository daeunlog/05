from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.db.database import get_db
from app.schemas.history import HistoryItem, HistoryResponse
from app.services.history_service import get_scan_history


router = APIRouter(prefix="/api", tags=["history"])


# Local development/demo endpoint only. Public deployments must add user
# authentication and per-user history access control before exposing it.
@router.get("/history", response_model=HistoryResponse)
async def list_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
) -> HistoryResponse:
    try:
        total, records = await run_in_threadpool(
            get_scan_history,
            db,
            limit,
            offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to load scan history",
        ) from exc

    return HistoryResponse(
        total=total,
        items=[HistoryItem.model_validate(record) for record in records],
    )
