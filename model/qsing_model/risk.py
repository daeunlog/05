"""위험도 점수와 등급 (설계 3.4절).

ai_risk_score = 1 - P(benign). 모델 예측 점수이며 실제 피해 확률이 아니다.
임계값은 val 세트로만 정한다.
"""

import math

import numpy as np

from .labels import BENIGN_ID

DEFAULT_BENIGN_FPR_TARGET = 0.01      # 정상 URL 중 '위험'에 들어가는 비율 상한
DEFAULT_MALICIOUS_RECALL_TARGET = 0.99  # 악성 URL 중 '주의 이상'에 들어가는 비율 하한

LEVELS = ("low", "caution", "danger")


def risk_score(probs):
    probs = np.asarray(probs, dtype=float)
    return 1.0 - probs[..., BENIGN_ID]


def choose_thresholds(risk, y_true, benign_fpr_target=DEFAULT_BENIGN_FPR_TARGET,
                      malicious_recall_target=DEFAULT_MALICIOUS_RECALL_TARGET):
    """val 세트의 위험 점수로 t_low, t_high를 정한다.

    t_high: 정상 URL 중 risk >= t_high 비율이 benign_fpr_target 이하가 되는 가장 작은 값
    t_low : 악성 URL 중 risk >= t_low 비율이 malicious_recall_target 이상이 되는 가장 큰 값

    보통은 정상·악성 점수가 겹쳐 t_low < t_high가 되고, 겹치는 구간이 '주의'가 된다(status='overlap').
    t_low >= t_high면 두 목표가 이미 함께 충족될 만큼 잘 갈린 것이다(status='separated').
    이때는 t_low를 t_high로 맞춰 '주의' 구간을 비우고, 원래 값은 t_low_raw로 남긴다.
    """
    risk = np.asarray(risk, dtype=float)
    y_true = np.asarray(y_true, dtype=int)
    b = np.sort(risk[y_true == BENIGN_ID])
    m = np.sort(risk[y_true != BENIGN_ID])
    if len(b) == 0 or len(m) == 0:
        raise ValueError("val 세트에 정상·악성이 모두 있어야 합니다.")

    k = int(math.floor(benign_fpr_target * len(b)))  # 위험에 허용되는 정상 URL 수
    if k >= len(b):
        t_high = 0.0
    else:
        t_high = float(np.nextafter(b[len(b) - k - 1], np.inf))

    r = int(math.ceil(malicious_recall_target * len(m)))  # 주의 이상이어야 하는 악성 URL 수
    r = min(max(r, 1), len(m))
    t_low = float(m[len(m) - r])

    t_low_raw = t_low
    status = "overlap"
    if t_low >= t_high:
        status = "separated"
        t_low = t_high

    achieved = {
        "benign_in_danger": float((b >= t_high).mean()),
        "malicious_caution_or_above": float((m >= t_low).mean()),
        "benign_low": float((b < t_low).mean()),
        "malicious_danger": float((m >= t_high).mean()),
    }
    result = {
        "t_low": t_low,
        "t_high": t_high,
        "t_low_raw": t_low_raw,
        "status": status,
        "benign_fpr_target": benign_fpr_target,
        "malicious_recall_target": malicious_recall_target,
        "fitted_on": "val",
        "n_benign": int(len(b)),
        "n_malicious": int(len(m)),
        "achieved_on_val": achieved,
    }
    return result


def risk_level(score, t_low, t_high):
    if score >= t_high:
        return "danger"
    if score >= t_low:
        return "caution"
    return "low"


def flagged(scores, t_low):
    """임계값 판정에서 '악성'으로 보는 기준: 주의 이상."""
    return np.asarray(scores, dtype=float) >= t_low
