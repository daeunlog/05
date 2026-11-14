"""도메인 그룹 단위 70:15:15 분리와 누수 검사 (설계 2.4절, 개정 3).

분리 방법(개정 3): 그룹(등록 도메인)을 크기가 큰 것부터 하나씩, train/val/test 중
'넣었을 때 목표치(세트 비율 × 클래스별 전체 건수)와의 상대 제곱오차가 가장 적게 늘어나는' 세트에 배정한다.
같은 그룹은 한 세트에만 들어가며, 결과는 시드로 고정된다. scikit-learn 버전에 영향받지 않는다.
(처음 쓴 StratifiedGroupKFold는 Kaggle 환경에서 클래스 비율이 최대 11.7%p 어긋나 교체)
"""

import numpy as np
import pandas as pd

SPLITS = ("train", "val", "test")
RATIOS = (0.70, 0.15, 0.15)
RATIO_TOLERANCE_PP = 2.0


class SplitCheckError(RuntimeError):
    pass


def group_split(df, seed=42, ratios=RATIOS):
    """반환: df 사본에 'split' 컬럼(train/val/test) 추가"""
    d = df.reset_index(drop=True).copy()
    labels = sorted(d["label"].unique())
    counts = pd.crosstab(d["group_key"], d["label"]).reindex(columns=labels, fill_value=0)
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(counts))                     # 같은 크기끼리의 순서는 시드로 섞는다
    sizes = counts.values.sum(1)[order]
    order = order[np.argsort(-sizes, kind="stable")]         # 큰 그룹부터
    G = counts.values.astype(np.float64)
    total = G.sum(0)                                         # 클래스별 전체 건수
    r = np.asarray(ratios, dtype=np.float64)
    target = r[:, None] * total[None, :]                     # [세트, 클래스] 목표 건수
    weight = 1.0 / np.maximum(total, 1.0)
    cur = np.zeros_like(target)
    assign = np.empty(len(G), dtype=np.int64)
    for gi in order:
        g = G[gi]
        before = ((cur - target) ** 2 * weight).sum(1)
        after = ((cur + g - target) ** 2 * weight).sum(1)
        s = int(np.argmin(after - before))
        cur[s] += g
        assign[gi] = s
    split_of_group = pd.Series(np.array(SPLITS)[assign], index=counts.index)
    d["split"] = d["group_key"].map(split_of_group).values
    return d


def check_split(d, tolerance_pp=RATIO_TOLERANCE_PP, top_n=20):
    """누수·비율 검사. 실패하면 SplitCheckError. 반환: 리포트 dict"""
    rep = {"method": "greedy group assignment (largest first), ratios 70/15/15"}
    groups = {s: set(d.loc[d["split"] == s, "group_key"]) for s in SPLITS}
    overlaps = {
        "train&val": len(groups["train"] & groups["val"]),
        "train&test": len(groups["train"] & groups["test"]),
        "val&test": len(groups["val"] & groups["test"]),
    }
    rep["group_overlaps"] = overlaps

    overall = d["label"].value_counts(normalize=True) * 100
    ratios = {}
    worst = 0.0
    for s in SPLITS:
        part = d.loc[d["split"] == s, "label"].value_counts(normalize=True) * 100
        part = part.reindex(overall.index, fill_value=0.0)
        worst = max(worst, float((part - overall).abs().max()))
        ratios[s] = {k: round(float(v), 2) for k, v in part.items()}
    rep["overall_pct"] = {k: round(float(v), 2) for k, v in overall.items()}
    rep["split_pct"] = ratios
    rep["max_ratio_diff_pp"] = round(worst, 3)
    rep["sizes"] = {s: int((d["split"] == s).sum()) for s in SPLITS}
    rep["size_pct"] = {s: round(100 * n / len(d), 2) for s, n in rep["sizes"].items()}
    top = d.groupby("group_key").size().sort_values(ascending=False).head(top_n)
    first_split = d.drop_duplicates("group_key").set_index("group_key")["split"]
    rep["top_groups"] = [{"group_key": g, "rows": int(n), "split": first_split[g]} for g, n in top.items()]

    errors = []
    if any(v > 0 for v in overlaps.values()):
        errors.append(f"세트 간 그룹 교집합이 있습니다: {overlaps}")
    if worst > tolerance_pp:
        errors.append(f"클래스 비율 차이 {worst:.2f}%p가 허용치 {tolerance_pp}%p를 넘습니다.")
    for s, want in zip(SPLITS, RATIOS):
        if abs(rep["size_pct"][s] - 100 * want) > 3.0:
            errors.append(f"{s} 크기 {rep['size_pct'][s]}%가 목표 {100 * want:.0f}%에서 3%p 넘게 벗어났습니다.")
    rep["passed"] = not errors
    if errors:
        raise SplitCheckError(" / ".join(errors) + f"\n리포트: {rep}")
    return rep
