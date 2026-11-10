from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import ScanHistory
from app.schemas.scan import ScanResponse
from app.services.cache_service import generate_cache_key


def save_scan_history(db: Session, url: str, result: ScanResponse) -> None:
    """Persist one scan response without storing the original URL or secrets."""
    try:
        history = ScanHistory(
            scan_id=str(result.scan_id),
            created_at=datetime.now(timezone.utc),
            url_hash=generate_cache_key(url),
            model_status="completed",
            model_prediction=result.model.prediction,
            model_confidence=result.model.confidence,
            model_is_mock=result.model.is_mock,
            virustotal_status=result.virustotal.status,
            virustotal_stats=(
                result.virustotal.stats.model_dump()
                if result.virustotal.stats is not None
                else None
            ),
            risk_level=result.risk_level,
            is_complete=result.is_complete,
        )
        db.add(history)
        db.commit()
    except Exception:
        db.rollback()
        raise


def get_scan_history(
    db: Session,
    limit: int,
    offset: int,
) -> tuple[int, list[ScanHistory]]:
    """Return the total count and a newest-first page of scan history."""
    try:
        total = db.scalar(select(func.count()).select_from(ScanHistory)) or 0
        records = list(
            db.scalars(
                select(ScanHistory)
                .order_by(
                    ScanHistory.created_at.desc(),
                    ScanHistory.scan_id.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
    except Exception:
        db.rollback()
        raise

    return total, records
