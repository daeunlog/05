import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.database import Base
from app.db.models import VTCache
from app.services import cache_service


TEST_URL = "https://Example.com:443/login?next=%2Fhome#section"
TEST_SECRET = "test-only-cache-secret"
STATS = {
    "malicious": 1,
    "suspicious": 2,
    "harmless": 3,
    "undetected": 4,
    "timeout": 5,
}


def completed_report(stats: dict | None = None, last_analysis_date: int = 1_700_000_000):
    return {
        "status": "completed",
        "stats": STATS if stats is None else stats,
        "last_analysis_date": last_analysis_date,
        "error_code": None,
    }


@pytest.fixture(autouse=True)
def fake_cache_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "CACHE_HASH_SECRET", TEST_SECRET)


@pytest.fixture
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'cache-test.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with test_session() as session:
        yield session

    engine.dispose()


def test_save_and_get_cached_report(db: Session) -> None:
    assert cache_service.save_url_report(db, TEST_URL, completed_report()) is True

    assert cache_service.get_cached_url_report(db, TEST_URL) == completed_report()
    cached = db.scalar(select(VTCache))
    assert cached is not None
    assert len(cached.url_hash) == 64
    assert cached.url_hash != TEST_URL
    assert cached.expires_at - cached.checked_at == timedelta(hours=24)


def test_same_normalized_url_updates_existing_cache(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    second_time = first_time + timedelta(hours=1)
    times = iter((first_time, second_time))
    monkeypatch.setattr(cache_service, "_utc_now", lambda: next(times))

    cache_service.save_url_report(db, TEST_URL, completed_report())
    updated_stats = {**STATS, "malicious": 9}
    equivalent_url = "https://example.com/login?next=%2Fhome"
    cache_service.save_url_report(
        db,
        equivalent_url,
        completed_report(updated_stats, 1_800_000_000),
    )

    assert db.scalar(select(func.count()).select_from(VTCache)) == 1
    cached = db.scalar(select(VTCache))
    assert cached is not None
    assert cached.stats == updated_stats
    assert cached.last_analysis_date == 1_800_000_000
    assert cached.checked_at == second_time.replace(tzinfo=None)
    assert cached.expires_at == (second_time + timedelta(hours=24)).replace(tzinfo=None)


def test_cache_miss_returns_none(db: Session) -> None:
    assert cache_service.get_cached_url_report(db, TEST_URL) is None


def test_expired_cache_returns_none(db: Session) -> None:
    cache_service.save_url_report(db, TEST_URL, completed_report())
    cached = db.scalar(select(VTCache))
    assert cached is not None
    cached.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    assert cache_service.get_cached_url_report(db, TEST_URL) is None


@pytest.mark.parametrize("status", ["not_found", "rate_limited", "timeout", "error", "disabled"])
def test_non_completed_reports_are_not_cached(db: Session, status: str) -> None:
    report = {
        "status": status,
        "stats": None,
        "last_analysis_date": None,
        "error_code": "http_error" if status == "error" else None,
    }

    assert cache_service.save_url_report(db, TEST_URL, report) is False
    assert db.scalar(select(func.count()).select_from(VTCache)) == 0


def test_missing_cache_secret_raises_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "CACHE_HASH_SECRET", "")

    with pytest.raises(cache_service.CacheConfigurationError):
        cache_service.generate_cache_key(TEST_URL)


def test_raw_url_and_secret_are_not_stored(db: Session) -> None:
    cache_service.save_url_report(db, TEST_URL, completed_report())

    row = db.execute(text("SELECT * FROM vt_cache")).mappings().one()
    serialized_row = json.dumps(dict(row), default=str)
    assert TEST_URL not in serialized_row
    assert TEST_SECRET not in serialized_row
    assert "url" not in row
    assert "api_key" not in row


def test_database_failure_rolls_back() -> None:
    db = Mock(spec=Session)
    db.get.return_value = None
    db.commit.side_effect = OperationalError("commit failed", {}, Exception())

    with pytest.raises(OperationalError):
        cache_service.save_url_report(db, TEST_URL, completed_report())

    db.rollback.assert_called_once_with()
