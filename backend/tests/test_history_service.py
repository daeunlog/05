import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.api import scan
from app import main as main_module
from app.core.config import settings
from app.db.database import Base, get_db
from app.db.models import ScanHistory
from app.main import app
from app.schemas.scan import ModelResult, ScanResponse, VirusTotalResult
from app.services import history_service
from app.services.cache_service import generate_cache_key


TEST_URL = "https://example.com/login"
TEST_SECRET = "test-only-history-secret"
STATS = {
    "malicious": 1,
    "suspicious": 2,
    "harmless": 3,
    "undetected": 4,
    "timeout": 5,
}
COMPLETED_REPORT = {
    "status": "completed",
    "stats": STATS,
    "last_analysis_date": 1_700_000_000,
    "error_code": None,
}
client = TestClient(app)


@pytest.fixture(autouse=True)
def fake_cache_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "CACHE_HASH_SECRET", TEST_SECRET)


@pytest.fixture
def database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'history-test.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    def provide_test_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = provide_test_db
    yield session_factory
    app.dependency_overrides.clear()
    engine.dispose()


def test_scan_result_is_saved_with_response_scan_id(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scan,
        "get_cached_url_report",
        lambda db, url: COMPLETED_REPORT,
    )

    async def unexpected_external_lookup(url: str):
        raise AssertionError("VirusTotal must not be called on a cache hit")

    monkeypatch.setattr(scan, "get_url_report", unexpected_external_lookup)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    with database() as db:
        history = db.scalar(select(ScanHistory))

    assert history is not None
    assert history.scan_id == payload["scan_id"]
    assert history.url_hash == generate_cache_key(TEST_URL)
    assert history.model_status == "completed"
    assert history.model_prediction == "benign"
    assert history.model_confidence == 0.85
    assert history.model_is_mock is True
    assert history.virustotal_status == "completed"
    assert history.virustotal_stats == STATS
    assert history.risk_level == "unknown"
    assert history.is_complete is False
    assert history.created_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)


def test_same_url_creates_distinct_history_rows(database) -> None:
    first = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": False},
    )
    second = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": False},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["scan_id"] != second.json()["scan_id"]
    with database() as db:
        rows = list(db.scalars(select(ScanHistory)))
    assert len(rows) == 2
    assert {row.scan_id for row in rows} == {
        first.json()["scan_id"],
        second.json()["scan_id"],
    }


def test_external_lookup_disabled_scan_is_saved(database) -> None:
    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": False},
    )

    assert response.status_code == 200
    with database() as db:
        history = db.scalar(select(ScanHistory))
    assert history is not None
    assert history.virustotal_status == "skipped"
    assert history.virustotal_stats is None


def test_raw_url_and_secrets_are_not_stored(database) -> None:
    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": False},
    )

    assert response.status_code == 200
    with database() as db:
        row = db.execute(text("SELECT * FROM scan_history")).mappings().one()
    serialized_row = json.dumps(dict(row), default=str)
    assert TEST_URL not in serialized_row
    assert TEST_SECRET not in serialized_row
    assert "url" not in row
    assert "api_key" not in row


def test_history_database_failure_rolls_back() -> None:
    result = ScanResponse(
        scan_id="3f619f12-8843-4e44-98aa-b5b3b43b472a",
        url=TEST_URL,
        model=ModelResult(
            prediction="benign",
            confidence=0.85,
            is_mock=True,
        ),
        virustotal=VirusTotalResult(),
        risk_level="unknown",
        is_complete=False,
        cached=False,
    )
    db = Mock(spec=Session)
    db.commit.side_effect = OperationalError("commit failed", {}, Exception())

    with pytest.raises(OperationalError):
        history_service.save_scan_history(db, TEST_URL, result)

    db.rollback.assert_called_once_with()


def test_application_lifespan_initializes_database_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(main_module, "init_db", lambda: calls.append("init"))

    async def run_lifespan() -> None:
        async with main_module.lifespan(app):
            pass

    asyncio.run(run_lifespan())

    assert calls == ["init"]
