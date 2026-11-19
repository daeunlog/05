from threading import Lock

from app.core.config import settings

from app.schemas.scan import ModelResult


classifier = None
_predict_lock = Lock()


def load_model() -> None:
    global classifier
    try:
        from qsing_model.infer import UrlRiskClassifier
        directory = settings.MODEL_ARTIFACTS_DIR.resolve()
        if not (directory / "encoder").is_dir():
            raise FileNotFoundError
        classifier = UrlRiskClassifier.from_artifacts(str(directory), device="cpu")
    except Exception:
        classifier = None


def predict_url(url: str) -> ModelResult:
    from fastapi import HTTPException
    if classifier is None:
        raise HTTPException(503, "model_load_failed")
    try:
        with _predict_lock:
            result = classifier.predict(url)
        if result["status"] in {"invalid_url", "unsupported_scheme"}:
            raise HTTPException(422, result["status"])
        predicted = result["predicted_type"]
        return ModelResult(prediction=predicted, confidence=result["scores"][predicted],
                           scores=result["scores"], ai_risk_score=result["ai_risk_score"],
                           ai_risk_level=result["risk_level"], truncated=result["truncated"],
                           model_version=result["model_version"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "inference_failed") from None
