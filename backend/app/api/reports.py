from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.identity import owner_id
from app.db.database import get_db
from app.db.models import ScanOwner, ScanReport

router = APIRouter(prefix="/api/scans", tags=["reports"])


class Feedback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["false_positive", "suspicious"]


@router.post("/{scan_id}/reports")
def report(scan_id: UUID, feedback: Feedback, db: Session = Depends(get_db),
           owner: str = Depends(owner_id)):
    try:
        record = db.get(ScanOwner, str(scan_id))
        if record is None or record.owner != owner:
            raise HTTPException(404, "scan_not_found")
        db.execute(insert(ScanReport).values(scan_id=str(scan_id), kind=feedback.kind)
                   .on_conflict_do_nothing())
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(500, "report_save_failed") from None
    return {"scan_id": scan_id, "kind": feedback.kind, "status": "received"}
