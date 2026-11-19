import pytest

from app.api import scan
from app.schemas.scan import ModelResult


@pytest.fixture
def model_result():
    return ModelResult(prediction="benign", confidence=0.85, ai_risk_score=0.15,
                       scores={"benign": 0.85, "phishing": 0.05, "malware": 0.05, "defacement": 0.05},
                       ai_risk_level="low", truncated=False, model_version="unit-test")


@pytest.fixture
def stub_prediction(monkeypatch, model_result):
    monkeypatch.setattr(scan, "predict_url", lambda url: model_result)
