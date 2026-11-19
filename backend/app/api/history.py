from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.db.database import get_db
from app.core.identity import owner_id
from app.schemas.history import HistoryItem, HistoryResponse
from app.services.history_service import get_scan_history


router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history", response_model=HistoryResponse)
async def list_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
    owner: str = Depends(owner_id),
) -> HistoryResponse:
    try:
        total, records = await run_in_threadpool(
            get_scan_history,
            db,
            limit,
            offset,
            owner,
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
