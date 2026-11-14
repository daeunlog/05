"""서버용 추론 모듈 (설계 4장).

    from qsing_model.infer import UrlRiskClassifier
    clf = UrlRiskClassifier.from_artifacts("model/artifacts", device="cpu")   # 서버 시작 시 1회
    result = clf.predict("http://secure-login.example.xyz/verify?id=1")

- artifacts/ 만 있으면 인터넷 없이 동작한다(인코더 포함).
- 검사하지 못한 URL은 risk_level=None으로 돌려준다. 'low'는 모델이 점수를 실제로 계산했을 때만 나온다.
- 모델 내부 오류는 ModelError로 올린다. 서버는 이를 '검사 실패'로 처리한다.
"""

import json
import os

import numpy as np

from .head import NumpyHead
from .labels import BENIGN_ID, LABELS
from .risk import risk_level
from . import urls as U

RESULT_KEYS = ("status", "url", "predicted_type", "scores", "ai_risk_score", "risk_level",
               "truncated", "signals", "model_version")


class ModelError(RuntimeError):
    """모델 계산 중 오류. 서버는 '검사 실패' 상태로 응답한다."""


class UrlRiskClassifier:
    def __init__(self, embed_fn, head, config, thresholds):
        """embed_fn(list[str]) -> (np.ndarray [n, d], np.ndarray[bool] [n]) : 모델 입력 문자열 → 임베딩, 잘림 여부"""
        self.embed_fn = embed_fn
        self.head = head
        self.config = dict(config)
        self.t_low = float(thresholds["t_low"])
        self.t_high = float(thresholds["t_high"])
        self.normalization = self.config["normalization"]
        self.model_version = self.config.get("model_version", "unknown")

    @classmethod
    def from_artifacts(cls, artifacts_dir, device="cpu", num_threads=None, batch_size=64):
        from .embed import Embedder

        with open(os.path.join(artifacts_dir, "model_config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        with open(os.path.join(artifacts_dir, "thresholds.json"), encoding="utf-8") as f:
            thr = json.load(f)
        head = NumpyHead.load(os.path.join(artifacts_dir, "head.npz"), cfg["head"])
        emb = Embedder(os.path.join(artifacts_dir, "encoder"), device=device, fp16=False,
                       max_tokens=cfg.get("max_tokens", 256), num_threads=num_threads)

        def embed_fn(texts):
            return emb.encode(texts, batch_size=batch_size, out_dtype=np.float32)

        return cls(embed_fn, head, cfg, thr)

    def _not_scored(self, url, status):
        return {"status": status, "url": url if isinstance(url, str) else None, "predicted_type": None,
                "scores": None, "ai_risk_score": None, "risk_level": None, "truncated": False,
                "signals": None, "model_version": self.model_version}

    def predict(self, url):
        return self.predict_batch([url])[0]

    def predict_batch(self, urls):
        results = [None] * len(urls)
        todo = []
        for i, u in enumerate(urls):
            status, host = U.check_url(u)
            if status != "ok":
                results[i] = self._not_scored(u, status)
                continue
            s = u.strip()
            too_long = len(s) > U.MAX_URL_CHARS
            text = U.normalize(s[:U.MAX_URL_CHARS], self.normalization)
            todo.append((i, s, host, text, too_long))
        if not todo:
            return results
        try:
            X, truncated = self.embed_fn([t[3] for t in todo])
            probs = np.asarray(self.head.probs(np.asarray(X, dtype=np.float32)), dtype=np.float64)
            if probs.shape != (len(todo), len(LABELS)) or not np.all(np.isfinite(probs)):
                raise ValueError(f"잘못된 확률 출력: shape={probs.shape}")
        except Exception as e:  # noqa: BLE001 — 서버에는 한 가지 예외로 알린다
            raise ModelError(f"모델 계산 실패: {e}") from e
        for j, (i, s, host, _text, too_long) in enumerate(todo):
            p = probs[j]
            risk = float(1.0 - p[BENIGN_ID])
            results[i] = {
                "status": "ok",
                "url": s,
                "predicted_type": LABELS[int(np.argmax(p))],
                "scores": {name: float(p[k]) for k, name in enumerate(LABELS)},
                "ai_risk_score": risk,
                "risk_level": risk_level(risk, self.t_low, self.t_high),
                "truncated": bool(truncated[j]) or too_long,
                "signals": U.signals(s, host),
                "model_version": self.model_version,
            }
        return results
