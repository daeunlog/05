from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.db.database import Base, get_db
from app.db.models import ScanHistory
from app.main import app


client = TestClient(app)


def make_history(index: int, created_at: datetime) -> ScanHistory:
    return ScanHistory(
        scan_id=f"00000000-0000-0000-0000-{index:012d}",
        created_at=created_at,
        url_hash=f"{index:064x}",
        model_status="completed",
        model_prediction="benign",
        model_confidence=0.85,
        model_is_mock=True,
        virustotal_status="completed",
        virustotal_stats={
            "malicious": index,
            "suspicious": 0,
            "harmless": 1,
            "undetected": 2,
            "timeout": 0,
        },
        risk_level="unknown",
        is_complete=False,
    )


@pytest.fixture
def history_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'history-api-test.db'}",
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


def test_empty_history(history_database) -> None:
    response = client.get("/api/history")

    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}


def test_history_response_contains_allowed_fields_only(history_database) -> None:
    created_at = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    with history_database() as db:
        db.add(make_history(1, created_at))
        db.commit()

    response = client.get("/api/history")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert set(item) == {
        "scan_id",
        "created_at",
        "model_status",
        "model_prediction",
        "model_confidence",
        "model_is_mock",
        "virustotal_status",
        "virustotal_stats",
        "risk_level",
        "is_complete",
    }
    assert item["scan_id"] == "00000000-0000-0000-0000-000000000001"
    assert item["created_at"].endswith("Z")
    assert item["virustotal_stats"]["malicious"] == 1
    assert "url" not in item
    assert "url_hash" not in item
    assert "api_key" not in item
    assert "cache_hash_secret" not in item


def test_history_is_sorted_newest_first_with_scan_id_tiebreaker(
    history_database,
) -> None:
    older = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer = older + timedelta(hours=1)
    with history_database() as db:
        db.add_all(
            [
                make_history(1, newer),
                make_history(2, newer),
                make_history(3, older),
            ]
        )
        db.commit()

    response = client.get("/api/history")

    assert response.status_code == 200
    assert [item["scan_id"] for item in response.json()["items"]] == [
        "00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000003",
    ]


def test_history_limit_and_offset(history_database) -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with history_database() as db:
        db.add_all(
            [make_history(index, start + timedelta(minutes=index)) for index in range(1, 6)]
        )
        db.commit()

    response = client.get("/api/history?limit=2&offset=1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 5
    assert [item["scan_id"] for item in payload["items"]] == [
        "00000000-0000-0000-0000-000000000004",
        "00000000-0000-0000-0000-000000000003",
    ]


@pytest.mark.parametrize("limit", [0, 101])
def test_invalid_limit_returns_422(history_database, limit: int) -> None:
    response = client.get(f"/api/history?limit={limit}")

    assert response.status_code == 422


def test_database_error_returns_sanitized_500() -> None:
    db = Mock(spec=Session)
    db.scalar.side_effect = OperationalError("sensitive SQL", {}, Exception())

    def provide_failing_db():
        yield db

    app.dependency_overrides[get_db] = provide_failing_db
    try:
        response = client.get("/api/history")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json() == {"detail": "Failed to load scan history"}
    assert "sensitive SQL" not in response.text
    db.rollback.assert_called_once_with()
