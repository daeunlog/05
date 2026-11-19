from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.api import scan
from app.db.database import get_db
from app.main import app


pytestmark = pytest.mark.usefixtures("stub_prediction")
client = TestClient(app, headers={"Authorization": "Bearer " + "ab" * 32})
TEST_URL = "https://example.com/login"
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


@pytest.fixture(autouse=True)
def override_database(monkeypatch: pytest.MonkeyPatch) -> Session:
    db = Session()

    monkeypatch.setattr(scan, "save_scan_history", lambda db, url, result, owner: None)

    def provide_test_db():
        yield db

    app.dependency_overrides[get_db] = provide_test_db
    yield db
    app.dependency_overrides.clear()
    db.close()


def test_scan_skips_cache_and_external_lookup_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_cache_call(*args):
        raise AssertionError("Cache must not be accessed")

    async def unexpected_external_call(url: str):
        raise AssertionError("VirusTotal must not be called")

    monkeypatch.setattr(scan, "get_cached_url_report", unexpected_cache_call)
    monkeypatch.setattr(scan, "save_url_report", unexpected_cache_call)
    monkeypatch.setattr(scan, "get_url_report", unexpected_external_call)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": False},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["virustotal"] == {
        "status": "skipped",
        "stats": None,
        "last_analysis_date": None,
        "error_code": None,
    }
    assert payload["cached"] is False
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False


def test_scan_uses_cache_without_external_lookup(
    monkeypatch: pytest.MonkeyPatch,
    override_database: Session,
) -> None:
    cache_calls = []

    def cache_hit(db: Session, url: str):
        cache_calls.append((db, url))
        return COMPLETED_REPORT

    async def unexpected_external_call(url: str):
        raise AssertionError("VirusTotal must not be called on a cache hit")

    monkeypatch.setattr(scan, "get_cached_url_report", cache_hit)
    monkeypatch.setattr(scan, "get_url_report", unexpected_external_call)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert cache_calls == [(override_database, TEST_URL)]
    assert payload["virustotal"] == COMPLETED_REPORT
    assert payload["cached"] is True
    assert payload["risk_level"] == "danger"
    assert payload["is_complete"] is True


def test_scan_cache_miss_fetches_and_saves_report(
    monkeypatch: pytest.MonkeyPatch,
    override_database: Session,
) -> None:
    requested_urls = []
    saved_reports = []

    monkeypatch.setattr(scan, "get_cached_url_report", lambda db, url: None)

    async def completed_lookup(url: str):
        requested_urls.append(url)
        return COMPLETED_REPORT

    def save_report(db: Session, url: str, report: dict) -> bool:
        saved_reports.append((db, url, report))
        return True

    monkeypatch.setattr(scan, "get_url_report", completed_lookup)
    monkeypatch.setattr(scan, "save_url_report", save_report)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert UUID(payload["scan_id"]).version == 4
    assert requested_urls == [TEST_URL]
    assert saved_reports == [(override_database, TEST_URL, COMPLETED_REPORT)]
    assert payload["virustotal"] == COMPLETED_REPORT
    assert payload["cached"] is False
    assert payload["risk_level"] == "danger"
    assert payload["is_complete"] is True


def test_scan_expired_cache_refetches_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_calls = []
    save_calls = []

    monkeypatch.setattr(scan, "get_cached_url_report", lambda db, url: None)

    async def completed_lookup(url: str):
        external_calls.append(url)
        return COMPLETED_REPORT

    def save_report(db: Session, url: str, report: dict) -> bool:
        save_calls.append((url, report))
        return True

    monkeypatch.setattr(scan, "get_url_report", completed_lookup)
    monkeypatch.setattr(scan, "save_url_report", save_report)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    assert external_calls == [TEST_URL]
    assert save_calls == [(TEST_URL, COMPLETED_REPORT)]
    assert response.json()["cached"] is False


def test_scan_does_not_cache_virustotal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error_report = {
        "status": "error",
        "stats": None,
        "last_analysis_date": None,
        "error_code": "network_error",
    }

    monkeypatch.setattr(scan, "get_cached_url_report", lambda db, url: None)

    async def failed_lookup(url: str):
        return error_report

    def unexpected_save(*args):
        raise AssertionError("An error response must not be cached")

    monkeypatch.setattr(scan, "get_url_report", failed_lookup)
    monkeypatch.setattr(scan, "save_url_report", unexpected_save)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["virustotal"] == error_report
    assert payload["cached"] is False
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False


def test_scan_cache_error_stops_external_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_cache_lookup(db: Session, url: str):
        raise RuntimeError("database unavailable")

    async def unexpected_external_call(url: str):
        raise AssertionError("VirusTotal must not be called after a cache error")

    monkeypatch.setattr(scan, "get_cached_url_report", failed_cache_lookup)
    monkeypatch.setattr(scan, "get_url_report", unexpected_external_call)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["virustotal"] == {
        "status": "error",
        "stats": None,
        "last_analysis_date": None,
        "error_code": "cache_error",
    }
    assert payload["cached"] is False
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False


def test_scan_history_failure_returns_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan, "get_cached_url_report", lambda db, url: None)

    async def completed_lookup(url: str):
        return COMPLETED_REPORT

    def save_report(db: Session, url: str, report: dict) -> bool:
        return True

    def failed_history_save(db: Session, url: str, result, owner) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(scan, "get_url_report", completed_lookup)
    monkeypatch.setattr(scan, "save_url_report", save_report)
    monkeypatch.setattr(scan, "save_scan_history", failed_history_save)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Failed to save scan history"}
