from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api import scan
from app.core.config import settings
from app.main import app
from app.services import model_service
from app.schemas.scan import VirusTotalResult
from app.services.decision import can_share, final_decision


auth = {"Authorization": "Bearer " + "cd" * 32}


def test_model_errors(monkeypatch, tmp_path):
    c = TestClient(app, headers=auth)
    monkeypatch.setattr(model_service, "classifier", None)
    monkeypatch.setattr(settings, "MODEL_ARTIFACTS_DIR", tmp_path)
    model_service.load_model()
    r = c.post("/api/scan", json={"url":"https://example.com"})
    assert (r.status_code, r.json()["detail"]) == (503, "model_load_failed")
    failing = Mock()
    failing.predict.side_effect = RuntimeError("private data")
    monkeypatch.setattr(model_service, "classifier", failing)
    r = c.post("/api/scan", json={"url":"https://example.com"})
    assert (r.status_code, r.json()) == (500, {"detail":"inference_failed"})


@pytest.mark.parametrize("url", ["https://localhost", "https://127.0.0.1", "https://192.168.1.1",
                                 "https://example.com/?token=abc", "https://example.com/#auth",
                                 "https://user:pass@example.com/", "https://example.com/reset/private",
                                 "https://secret.example.com"])
def test_privacy(url):
    assert not can_share(url)


@pytest.mark.usefixtures("stub_prediction")
def test_vt_error_through_api(monkeypatch):
    c = TestClient(app, headers=auth)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "unit-test")
    monkeypatch.setattr(scan, "get_cached_url_report", lambda *_: None)
    monkeypatch.setattr(scan, "save_scan_history", lambda *_: None)
    constructor = httpx.AsyncClient
    transport = httpx.MockTransport(lambda req: httpx.Response(429))
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: constructor(transport=transport, **kw))
    r = c.post("/api/scan", json={"url":"https://example.com", "allow_external_lookup":True})
    assert r.status_code == 200
    assert r.json()["virustotal"]["status"] == "rate_limited"
    assert (r.json()["risk_level"], r.json()["is_complete"]) == ("unknown", False)


def test_history_requires_token():
    assert TestClient(app).get("/api/history").status_code == 401


@pytest.mark.parametrize(("level", "truncated", "counts", "expected"), [
    ("low", False, (0, 0, 1), ("low", True)),
    ("low", True, (0, 0, 1), ("unknown", False)),
    ("low", False, (0, 0, 0), ("unknown", False)),
    ("low", False, (0, 1, 0), ("caution", True)),
    ("caution", False, (1, 0, 0), ("danger", True)),
    ("danger", False, None, ("danger", False)),
])
def test_final_grade(model_result, level, truncated, counts, expected):
    model = model_result.model_copy(update={"ai_risk_level": level, "truncated": truncated})
    vt = VirusTotalResult(status="timeout")
    if counts is not None:
        malicious, suspicious, harmless = counts
        vt = VirusTotalResult(status="completed", stats=dict(malicious=malicious,
                              suspicious=suspicious, harmless=harmless, undetected=1, timeout=0))
    assert final_decision(model, vt) == expected
