import asyncio
import base64
from collections.abc import Callable

import httpx
import pytest

from app.services import virustotal_service


TEST_URL = "https://example.com/login"
TEST_API_KEY = "test-api-key"
EMPTY_RESULT = {
    "stats": None,
    "last_analysis_date": None,
}


@pytest.fixture(autouse=True)
def use_fake_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        virustotal_service.settings,
        "VIRUSTOTAL_API_KEY",
        TEST_API_KEY,
    )


def install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    original_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def create_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(virustotal_service.httpx, "AsyncClient", create_client)


def get_report() -> virustotal_service.URLReport:
    return asyncio.run(virustotal_service.get_url_report(TEST_URL))


def test_completed_report(monkeypatch: pytest.MonkeyPatch) -> None:
    stats = {
        "malicious": 1,
        "suspicious": 2,
        "harmless": 3,
        "undetected": 4,
        "timeout": 5,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        expected_id = base64.urlsafe_b64encode(TEST_URL.encode("utf-8")).decode(
            "ascii"
        ).rstrip("=")
        assert str(request.url) == (
            f"https://www.virustotal.com/api/v3/urls/{expected_id}"
        )
        assert request.headers["x-apikey"] == TEST_API_KEY
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": stats,
                        "last_analysis_date": 1_700_000_000,
                    }
                }
            },
        )

    install_mock_transport(monkeypatch, handler)

    assert get_report() == {
        "status": "completed",
        "stats": stats,
        "last_analysis_date": 1_700_000_000,
        "error_code": None,
    }


def test_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    install_mock_transport(monkeypatch, lambda request: httpx.Response(404))

    assert get_report() == {
        "status": "not_found",
        **EMPTY_RESULT,
        "error_code": "not_found",
    }


def test_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    install_mock_transport(monkeypatch, lambda request: httpx.Response(429))

    assert get_report() == {
        "status": "rate_limited",
        **EMPTY_RESULT,
        "error_code": "rate_limited",
    }


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [(401, "authentication_error"), (403, "permission_error")],
)
def test_authentication_and_permission_errors(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    error_code: str,
) -> None:
    install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(status_code),
    )

    assert get_report() == {
        "status": "error",
        **EMPTY_RESULT,
        "error_code": error_code,
    }


def test_request_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("request timed out", request=request)

    install_mock_transport(monkeypatch, handler)

    assert get_report() == {
        "status": "timeout",
        **EMPTY_RESULT,
        "error_code": "request_timeout",
    }


def test_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    install_mock_transport(monkeypatch, lambda request: httpx.Response(500))

    assert get_report() == {
        "status": "error",
        **EMPTY_RESULT,
        "error_code": "http_error",
    }


def test_missing_analysis_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={"data": {"attributes": {}}},
        ),
    )

    assert get_report() == {
        "status": "error",
        **EMPTY_RESULT,
        "error_code": "invalid_response",
    }
