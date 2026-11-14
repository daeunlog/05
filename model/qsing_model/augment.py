"""v3 (설계 개정 4): 정상 홈페이지 형태 보강과 원인 확인.

v2에서 PhiUSIIL 정상 URL 99%, Tranco 홈페이지 24%를 악성으로 판정했다.
가설: Malicious URLs의 benign은 경로가 긴 URL 위주라 '도메인만 있는 URL'을 정상으로 본 적이 거의 없다.

- path_profile: 클래스별 홈페이지 형태(경로·쿼리 없음) 비율로 가설을 확인한다.
- homepage_rows: 각 세트의 정상 URL 호스트로 'https://호스트/'를 만들어 정상으로 추가한다.
  악성 URL(어느 클래스든, 어느 세트든)에 나온 호스트는 제외한다(변조된 정상 사이트 등 라벨이 모호).
  호스트의 등록 도메인이 원래 행과 같으므로 세트 배정이 그대로 유지되어 누수가 없다.
  새 출처를 쓰지 않으므로 출처-클래스 혼입도 없다.
"""

import os
import time

import numpy as np
import pandas as pd

from . import urls as U
from .labels import LABELS, to_ids


def is_homepage(url):
    """경로가 비었거나 '/'뿐이고 쿼리·프래그먼트가 없는 URL."""
    try:
        sp = U.split_url(url.strip())
    except ValueError:
        return False
    return sp.path in ("", "/") and not sp.query and not sp.fragment


def path_profile(df):
    """클래스별 홈페이지 형태 비율(%), 쿼리 포함 비율(%), 길이 중앙값."""
    home = df["url"].map(is_homepage)
    query = df["url"].map(lambda u: "?" in u)
    length = df["url"].str.len()
    out = pd.DataFrame({
        "rows": df.groupby("label").size(),
        "homepage_pct": home.groupby(df["label"]).mean() * 100,
        "query_pct": query.groupby(df["label"]).mean() * 100,
        "median_len": length.groupby(df["label"]).median(),
    })
    return out.round(2)


def homepage_rows(d):
    """분리된 Malicious URLs(d, split 컬럼 포함)에서 정상 홈페이지 보강 행을 만든다."""
    host = d["url"].map(U.parse_host)
    mal_hosts = set(host[d["label"] != "benign"])
    existing = set(d["url"].map(U.loose_key))
    rows = []
    benign = d[d["label"] == "benign"].assign(_host=host[d["label"] == "benign"])
    for (h, split, g), _ in benign.groupby(["_host", "split", "group_key"]):
        if h in mal_hosts:
            continue
        url = f"https://{h}/"
        if U.loose_key(url) in existing:
            continue
        rows.append((url, "benign", "aug_homepage", split, g))
    out = pd.DataFrame(rows, columns=["url", "label", "source", "split", "group_key"])
    return out.drop_duplicates("url").reset_index(drop=True)


def run_v3(cfg, P, v2_reports_dir=None, log=print, zip_path="/kaggle/working/qsing_artifacts",
           extra_rows=None, post_eval=None):
    """P1 → P10 원인 확인 → P2 → 보강 → 임베딩 → 학습(선택 기준에 홈페이지 val 추가) → P6 → P5(+홈페이지) → P7.

    P: qsing_model.pipeline 모듈. cfg.normalizations는 ('strip',) 권장(v2에서 raw의 scheme 지름길 확인).
    extra_rows(cfg, P, d, aug, log) -> 보강 행 DataFrame (개정 6): split이 'train'이면 학습에, 그 밖의 값이면 평가 전용.
    post_eval(cfg, P, aug, sel, thr, mm, log) -> 내보내기 전에 metrics에 추가 평가를 넣는다.
    """
    from .head import NumpyHead
    from .metrics import four_class_metrics, benign_fpr
    from .risk import risk_score

    P.p1_prepare(cfg)
    P._hr("P10 원인 확인: 클래스별 홈페이지 형태 비율")
    mal_c = P.load_df(cfg, "mal_clean")
    prof = path_profile(mal_c)
    log(prof.to_string())
    rep10 = {"malicious_urls": prof.to_dict(orient="index")}
    if P.has_df(cfg, "phi_clean"):
        pp = path_profile(P.load_df(cfg, "phi_clean"))
        rep10["phiusiil"] = pp.to_dict(orient="index")
        log("PhiUSIIL:\n" + pp.to_string())
    P._jdump(rep10, cfg.path("reports", "p10_path_profile.json"))

    P.p2_split(cfg)
    d = P.load_df(cfg, "mal_split")
    P._hr("P11 정상 홈페이지 보강 행 만들기")
    aug = homepage_rows(d)
    if extra_rows is not None:
        aug = pd.concat([aug, extra_rows(cfg, P, d, aug, log)], ignore_index=True)
    P.save_df(aug, cfg, "home_aug")
    rep11 = {s: int((aug["split"] == s).sum()) for s in ("train", "val", "test")}
    rep11["excluded_rule"] = "악성 URL에 나온 호스트 제외, 이미 있는 URL 제외"
    rep11["train_by_source"] = {k: int(v) for k, v in aug.loc[aug["split"] == "train", "source"].value_counts().items()}
    log(f"보강 행: {rep11}")
    P._jdump(rep11, cfg.path("reports", "p11_augment.json"))

    if v2_reports_dir and os.path.exists(os.path.join(v2_reports_dir, "p3_baseline_metrics.json")):
        import shutil
        shutil.copy(os.path.join(v2_reports_dir, "p3_baseline_metrics.json"), cfg.path("reports", "p3_baseline_metrics.json"))
        log("기준선(P3)은 v2 결과를 그대로 사용 (같은 test 세트)")
    else:
        P.p3_baseline(cfg)

    P.p4_embed(cfg)
    from .embed import Embedder
    emb = Embedder(cfg.repo, revision=cfg.revision)
    for norm in cfg.normalizations:
        X, _ = emb.encode([U.normalize(u, norm) for u in aug["url"]], batch_size=cfg.embed_batch, progress=True)
        np.save(cfg.path("emb", f"{norm}_home.npy"), X)
    del emb
    P._free_gpu()

    def xy(norm, split, with_aug):
        X, y = P._load_xy(cfg, norm, split)
        if not with_aug:
            return X, y
        sel = (aug["split"] == split).values
        Xa = np.load(cfg.path("emb", f"{norm}_home.npy"))[sel]
        return np.concatenate([X, Xa]), np.concatenate([y, np.array(to_ids(aug.loc[sel, "label"]), dtype=int)])

    P._hr("P11 헤드 학습 (train + 홈페이지 보강), 선택 = val Macro F1 최저값(원본·scheme 변형·홈페이지 포함)")
    from .train import train_head
    runs = []

    def robust(info):
        worst, f1s = P._robust_val_f1(cfg, info)
        head = NumpyHead.load(info["head_file"], info["spec"])
        Xh, yh = xy(info["normalization"], "val", True)
        f1s["home"] = four_class_metrics(yh, head.probs(Xh.astype(np.float32)).argmax(1))["macro_f1"]
        return min(worst, f1s["home"]), f1s

    for norm in cfg.normalizations:
        Xtr, ytr = xy(norm, "train", True)
        Xva, yva = xy(norm, "val", False)
        for kind in cfg.head_kinds:
            info = P._train_one(cfg, train_head, norm, kind, cfg.seed, Xtr, ytr, Xva, yva)
            info["val_macro_f1_worst"], info["val_macro_f1_variants"] = robust(info)
            runs.append(info)
    table = pd.DataFrame([{"normalization": r["normalization"], "kind": r["kind"], "seed": r["seed"],
                           "val_f1_original": r["val_macro_f1_variants"]["original"],
                           "val_f1_home": r["val_macro_f1_variants"]["home"],
                           "val_f1_worst": r["val_macro_f1_worst"], "best_epoch": r["best_epoch"],
                           "seconds": r["seconds"]} for r in runs])
    log("\n" + table.to_string(index=False))
    best = max(runs, key=lambda r: (round(r["val_macro_f1_worst"], 6), -cfg.head_kinds.index(r["kind"])))
    seed_runs = [best]
    Xtr, ytr = xy(best["normalization"], "train", True)
    Xva, yva = xy(best["normalization"], "val", False)
    for s in cfg.extra_seeds:
        info = P._train_one(cfg, train_head, best["normalization"], best["kind"], s, Xtr, ytr, Xva, yva)
        info["val_macro_f1_worst"], info["val_macro_f1_variants"] = robust(info)
        seed_runs.append(info)
    f1s = [r["best_val_macro_f1"] for r in seed_runs]
    sel = {
        "normalization": best["normalization"], "kind": best["kind"], "seed": cfg.seed,
        "head_file": best["head_file"], "spec": best["spec"],
        "val_macro_f1": best["best_val_macro_f1"], "val_macro_f1_worst": best["val_macro_f1_worst"],
        "val_macro_f1_variants": best["val_macro_f1_variants"],
        "selection_metric": "val Macro F1 최저값 (원본, scheme 제거, https 추가, 정상 홈페이지 보강 val)",
        "training_data": "Malicious URLs train + " + ", ".join(f"{k} {v}행" for k, v in rep11["train_by_source"].items()),
        "seeds": [r["seed"] for r in seed_runs], "seed_val_macro_f1": f1s,
        "seed_val_macro_f1_worst": [r["val_macro_f1_worst"] for r in seed_runs],
        "seed_mean": float(np.mean(f1s)), "seed_std": float(np.std(f1s, ddof=1)) if len(f1s) > 1 else 0.0,
        "all_runs": [{**row, "val_f1_noscheme": None, "val_f1_https": None} for row in table.to_dict(orient="records")],
        "selected_on": "val",
    }
    P._jdump(sel, cfg.path("reports", "p4_selection.json"))
    log(f"선택: {sel['normalization']} + {sel['kind']}, val 최저 {sel['val_macro_f1_worst']:.4f}, "
        f"시드 평균 {sel['seed_mean']:.4f} ± {sel['seed_std']:.4f}")

    thr = P.p6_thresholds(cfg)
    m = P.p5_evaluate(cfg)

    P._hr("P12 홈페이지 형태 평가 (test 세트 정상 호스트의 홈페이지)")
    head = NumpyHead.load(sel["head_file"], sel["spec"])
    norm = sel["normalization"]
    sel_te = (aug["split"] == "test").values
    Xa = np.load(cfg.path("emb", f"{norm}_home.npy"))[sel_te].astype(np.float32)
    pa = head.probs(Xa)
    ya = np.array(to_ids(aug.loc[sel_te, "label"]))
    home = {"n": int(sel_te.sum()),
            "benign_fpr": {"argmax": benign_fpr(ya, pa.argmax(1) != 0),
                           "threshold": benign_fpr(ya, risk_score(pa) >= thr["t_low"])}}
    Xt, yt = xy(norm, "test", True)
    pt = head.probs(Xt.astype(np.float32))
    mt = four_class_metrics(yt, pt.argmax(1), flagged_by_threshold=risk_score(pt) >= thr["t_low"])
    home["test_plus_home"] = {k: mt[k] for k in ("n", "accuracy", "macro_f1", "benign_fpr", "malicious_fnr")}
    log(f"홈페이지 형태 test (n={home['n']}): 정상 오탐률 {home['benign_fpr']}")
    log(f"test + 홈페이지: {home['test_plus_home']}")
    mm = P._jload(cfg.path("reports", "metrics.json"))
    mm["test_homepage"] = home
    mm["path_profile"] = rep10
    mm["augment"] = rep11
    if post_eval is not None:
        mm = post_eval(cfg, P, aug, sel, thr, mm, log)
    P._jdump(mm, cfg.path("reports", "metrics.json"))

    P.p7_export(cfg, zip_path=zip_path)
    return P.run_summary_md(cfg)
