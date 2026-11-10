from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from app.api import scan
from app.main import app


client = TestClient(app)
TEST_URL = "https://example.com/login"


def test_scan_skips_external_lookup_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unexpected_lookup(url: str):
        raise AssertionError("VirusTotal lookup must not be called")

    monkeypatch.setattr(scan, "get_url_report", unexpected_lookup)

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
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False


def test_scan_returns_mocked_virustotal_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_stats = {
        "malicious": 1,
        "suspicious": 2,
        "harmless": 3,
        "undetected": 4,
        "timeout": 5,
    }
    requested_urls: list[str] = []

    async def completed_lookup(url: str):
        requested_urls.append(url)
        return {
            "status": "completed",
            "stats": expected_stats,
            "last_analysis_date": 1_700_000_000,
            "error_code": None,
        }

    monkeypatch.setattr(scan, "get_url_report", completed_lookup)

    response = client.post(
        "/api/scan",
        json={"url": TEST_URL, "allow_external_lookup": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert UUID(payload["scan_id"]).version == 4
    assert payload["url"] == TEST_URL
    assert requested_urls == [TEST_URL]
    assert payload["model"] == {
        "prediction": "benign",
        "confidence": 0.85,
        "is_mock": True,
    }
    assert payload["virustotal"] == {
        "status": "completed",
        "stats": expected_stats,
        "last_analysis_date": 1_700_000_000,
        "error_code": None,
    }
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False
    assert payload["cached"] is False


def test_scan_preserves_virustotal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed_lookup(url: str):
        return {
            "status": "error",
            "stats": None,
            "last_analysis_date": None,
            "error_code": "network_error",
        }

    monkeypatch.setattr(scan, "get_url_report", failed_lookup)

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
        "error_code": "network_error",
    }
    assert payload["risk_level"] == "unknown"
    assert payload["is_complete"] is False
