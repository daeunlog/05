"""평가 지표 (설계 3.3절, 개정 1).

필수 지표 7종: accuracy, per_class(precision/recall/f1/support), macro_f1, confusion_matrix,
benign_fpr, malicious_fnr. 하나라도 빠지면 MissingMetricError.
numpy만 사용하므로 어디서나 같은 값이 나온다.
"""

import math

import numpy as np

from .labels import LABELS, BENIGN_ID

REQUIRED_KEYS = ("accuracy", "per_class", "macro_f1", "confusion_matrix", "benign_fpr", "malicious_fnr")
PER_CLASS_KEYS = ("precision", "recall", "f1", "support")


class MissingMetricError(KeyError):
    pass


def _safe_div(a, b):
    return float(a) / float(b) if b else 0.0


def confusion(y_true, y_pred, k=len(LABELS)):
    cm = np.zeros((k, k), dtype=np.int64)
    np.add.at(cm, (np.asarray(y_true, dtype=int), np.asarray(y_pred, dtype=int)), 1)
    return cm


def benign_fpr(y_true, flagged):
    """정답 benign 중 '악성으로 판정(flagged)'된 비율."""
    y_true = np.asarray(y_true)
    flagged = np.asarray(flagged, dtype=bool)
    b = y_true == BENIGN_ID
    return _safe_div((flagged & b).sum(), b.sum())


def malicious_fnr(y_true, flagged):
    """정답 악성 중 benign으로 판정(flagged=False)된 비율."""
    y_true = np.asarray(y_true)
    flagged = np.asarray(flagged, dtype=bool)
    m = y_true != BENIGN_ID
    return _safe_div((~flagged & m).sum(), m.sum())


def four_class_metrics(y_true, y_pred, flagged_by_threshold=None):
    """필수 지표 7종. flagged_by_threshold가 있으면 임계값 기준 오탐·미탐도 함께 낸다.

    benign_fpr / malicious_fnr 는 dict: {"argmax": ..., "threshold": ...}
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    cm = confusion(y_true, y_pred)
    per_class = {}
    f1s = []
    for i, name in enumerate(LABELS):
        tp = cm[i, i]
        p = _safe_div(tp, cm[:, i].sum())
        r = _safe_div(tp, cm[i, :].sum())
        f1 = _safe_div(2 * p * r, p + r)
        per_class[name] = {"precision": p, "recall": r, "f1": f1, "support": int(cm[i, :].sum())}
        f1s.append(f1)
    flag_argmax = y_pred != BENIGN_ID
    out = {
        "n": int(len(y_true)),
        "accuracy": _safe_div((y_true == y_pred).sum(), len(y_true)),
        "per_class": per_class,
        "macro_f1": float(np.mean(f1s)),
        "confusion_matrix": {"labels": list(LABELS), "matrix": cm.tolist(), "rows": "true", "cols": "pred"},
        "benign_fpr": {"argmax": benign_fpr(y_true, flag_argmax)},
        "malicious_fnr": {"argmax": malicious_fnr(y_true, flag_argmax)},
    }
    if flagged_by_threshold is not None:
        out["benign_fpr"]["threshold"] = benign_fpr(y_true, flagged_by_threshold)
        out["malicious_fnr"]["threshold"] = malicious_fnr(y_true, flagged_by_threshold)
    validate_required(out)
    return out


def validate_required(m):
    missing = [k for k in REQUIRED_KEYS if k not in m]
    if "per_class" in m:
        for name in LABELS:
            if name not in m["per_class"]:
                missing.append(f"per_class.{name}")
            else:
                missing += [f"per_class.{name}.{k}" for k in PER_CLASS_KEYS if k not in m["per_class"][name]]
    if missing:
        raise MissingMetricError(f"필수 지표 누락: {missing}")
    return True


def auroc(y_pos, score):
    """y_pos(1=양성)와 점수로 AUROC (동점은 평균 순위). 한 클래스만 있으면 nan."""
    y = np.asarray(y_pos, dtype=bool)
    s = np.asarray(score, dtype=float)
    n_pos, n_neg = int(y.sum()), int((~y).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((ranks[y].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def binary_metrics(y_true, risk, flagged_argmax, flagged_threshold=None):
    """정답이 benign/악성 두 종류뿐인 세트(PhiUSIIL)용: 오탐률, 미탐률, AUROC."""
    y_true = np.asarray(y_true, dtype=int)
    out = {
        "n": int(len(y_true)),
        "n_benign": int((y_true == BENIGN_ID).sum()),
        "n_malicious": int((y_true != BENIGN_ID).sum()),
        "auroc": auroc(y_true != BENIGN_ID, risk),
        "benign_fpr": {"argmax": benign_fpr(y_true, flagged_argmax)},
        "malicious_fnr": {"argmax": malicious_fnr(y_true, flagged_argmax)},
    }
    if flagged_threshold is not None:
        out["benign_fpr"]["threshold"] = benign_fpr(y_true, flagged_threshold)
        out["malicious_fnr"]["threshold"] = malicious_fnr(y_true, flagged_threshold)
    return out


def wilson_ci(k, n, z=1.959963984540054):
    """비율 k/n의 95% Wilson 신뢰구간."""
    if n == 0:
        return [float("nan"), float("nan")]
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [max(0.0, centre - half), min(1.0, centre + half)]


def external_metrics(sources, y_true, y_pred, flagged_threshold=None):
    """외부 최신 평가(개정 1). 출처마다 클래스가 하나뿐이므로 Precision·Macro F1은 내지 않는다.

    악성 출처: malicious_fnr, type_match_rate / benign 출처: benign_fpr. 모두 95% Wilson CI 포함.
    """
    sources = np.asarray(sources)
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    out = {}
    for src in sorted(set(sources.tolist())):
        sel = sources == src
        yt, yp = y_true[sel], y_pred[sel]
        n = int(sel.sum())
        rec = {"n": n}
        decisions = {"argmax": yp != BENIGN_ID}
        if flagged_threshold is not None:
            decisions["threshold"] = np.asarray(flagged_threshold, dtype=bool)[sel]
        if (yt == BENIGN_ID).all():
            rec["label"] = "benign"
            rec["benign_fpr"] = {}
            for name, fl in decisions.items():
                k = int(fl.sum())
                rec["benign_fpr"][name] = {"value": _safe_div(k, n), "ci95": wilson_ci(k, n)}
        else:
            rec["label"] = LABELS[int(np.bincount(yt).argmax())]
            rec["malicious_fnr"] = {}
            for name, fl in decisions.items():
                k = int((~fl).sum())
                rec["malicious_fnr"][name] = {"value": _safe_div(k, n), "ci95": wilson_ci(k, n)}
            k = int((yp == yt).sum())
            rec["type_match_rate"] = {"value": _safe_div(k, n), "ci95": wilson_ci(k, n)}
        out[src] = rec
    return out
