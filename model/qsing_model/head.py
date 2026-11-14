"""분류 헤드 (설계 3.2절).

- 학습: torch 모듈 (build_torch_head)
- 저장: numpy .npz (pickle을 쓰지 않으므로 torch.load보다 안전)
- 추론: NumpyHead — 서버에서 torch 없이도 헤드 계산이 가능하고, 테스트도 쉽다
"""

import json
import math

import numpy as np

HEAD_KINDS = ("linear", "mlp")


def build_torch_head(kind, in_dim=256, hidden=128, n_classes=4, dropout=0.1):
    import torch.nn as nn

    if kind == "linear":
        return nn.Sequential(nn.Linear(in_dim, n_classes))
    if kind == "mlp":
        return nn.Sequential(nn.Linear(in_dim, hidden), nn.GELU(), nn.Dropout(dropout), nn.Linear(hidden, n_classes))
    raise ValueError(f"알 수 없는 헤드: {kind}")


def head_spec(kind, in_dim=256, hidden=128, n_classes=4, dropout=0.1):
    return {"kind": kind, "in_dim": in_dim, "hidden": hidden if kind == "mlp" else None,
            "n_classes": n_classes, "dropout": dropout if kind == "mlp" else None, "activation": "gelu_erf" if kind == "mlp" else None}


def torch_head_to_numpy(module):
    return {k.replace(".", "_"): v.detach().cpu().float().numpy() for k, v in module.state_dict().items()}


def save_head(path, weights):
    np.savez(path, **weights)


def _erf(x):
    try:
        from scipy.special import erf
        return erf(x)
    except ImportError:
        return np.vectorize(math.erf, otypes=[np.float64])(x)


def _gelu(x):
    return 0.5 * x * (1.0 + _erf(x / math.sqrt(2.0)))


def softmax(z):
    z = z - z.max(axis=-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=-1, keepdims=True)


class NumpyHead:
    """torch nn.Sequential 헤드와 같은 계산을 numpy로 한다(추론 전용, dropout 없음)."""

    def __init__(self, spec, weights):
        self.spec = dict(spec)
        self.w = {k: np.asarray(v, dtype=np.float64) for k, v in weights.items()}
        kind = self.spec["kind"]
        need = ["0_weight", "0_bias"] + (["3_weight", "3_bias"] if kind == "mlp" else [])
        missing = [k for k in need if k not in self.w]
        if missing:
            raise ValueError(f"헤드 가중치 누락: {missing}")

    @classmethod
    def load(cls, npz_path, spec):
        with np.load(npz_path, allow_pickle=False) as z:
            weights = {k: z[k] for k in z.files}
        return cls(spec, weights)

    def logits(self, X):
        X = np.asarray(X, dtype=np.float64)
        h = X @ self.w["0_weight"].T + self.w["0_bias"]
        if self.spec["kind"] == "mlp":
            h = _gelu(h) @ self.w["3_weight"].T + self.w["3_bias"]
        return h

    def probs(self, X):
        return softmax(self.logits(X))


def spec_to_json(spec):
    return json.dumps(spec, ensure_ascii=False)
