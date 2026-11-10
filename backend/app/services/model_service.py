from pydantic import HttpUrl

from app.schemas.scan import ModelResult


def predict_url(url: HttpUrl) -> ModelResult:
    """Return the fixed mock prediction without accessing the URL."""
    return ModelResult(
        prediction="benign",
        confidence=0.85,
        is_mock=True,
    )
