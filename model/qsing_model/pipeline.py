"""Kaggle 노트북에서 부르는 페이즈별 함수.

실행 순서: P0 → P1 → P2 → P3 → P4(임베딩·학습) → P6(임계값) → P5(평가) → P7(내보내기)
모델 선택은 val Macro F1의 최저값(원본, scheme 제거, https 추가 변형)으로 한다 — scheme 유무만 보고 분류하는 지름길을 걸러내기 위해서다.
P6을 P5보다 먼저 하는 이유: P5의 '임계값 기준 오탐·미탐률'에 P6 임계값이 필요하기 때문이다.
임계값은 val 세트로만 정하므로 test 세트를 미리 보는 일은 없다.

각 페이즈는 결과를 cfg.out_dir 아래 파일로 저장하므로, 중간에 끊겨도 해당 페이즈부터 다시 돌릴 수 있다.
"""

import dataclasses
import datetime as _dt
import json
import os
import shutil
import time

import numpy as np
import pandas as pd

from . import data as D
from .labels import LABELS, BENIGN_ID, to_ids
from . import urls as U
from .metrics import four_class_metrics, binary_metrics, external_metrics
from .risk import choose_thresholds, risk_score
from .head import NumpyHead, head_spec, torch_head_to_numpy, save_head


@dataclasses.dataclass
class Config:
    out_dir: str = "/kaggle/working/qsing_out"
    repo: str = "CrabInHoney/urlbert-tiny-v6"
    revision: str = None                # P0에서 커밋 해시로 고정
    baseline_head: str = "malicious_urls_4class"
    baseline_label_map: dict = None     # 자동 매핑 실패 시 {외부 id: 우리 라벨}
    collected_at: str = dataclasses.field(default_factory=lambda: _dt.date.today().isoformat())

    malicious_urls_csv: str = None
    phiusiil_csv: str = None
    urlhaus_csv: str = None
    openphish_txts: list = dataclasses.field(default_factory=list)
    phishtank_csv: str = None
    tranco_csv: str = None
    tranco_top_n: int = 100_000
    tranco_sample_n: int = 10_000

    seed: int = 42
    extra_seeds: tuple = (43, 44)
    normalizations: tuple = ("raw", "strip")
    head_kinds: tuple = ("linear", "mlp")
    lr: float = 1e-3
    weight_decay: float = 0.01
    batch_size: int = 2048
    max_epochs: int = 30
    patience: int = 3
    embed_batch: int = 1024
    ratio_tolerance_pp: float = 2.0

    benign_fpr_target: float = 0.01
    malicious_recall_target: float = 0.99

    latency_n: int = 200
    throughput_n: int = 2000
    cpu_threads: int = None
    smoke_rows: int = 0                 # >0이면 리허설: 데이터를 이 행 수 정도로 줄여 전 과정을 빠르게 점검

    def path(self, *parts):
        p = os.path.join(self.out_dir, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def save(self):
        with open(self.path("config.json"), "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(self), f, ensure_ascii=False, indent=2, default=str)


def smoke_config(cfg, rows=6000):
    """리허설용 설정: 작은 표본, 짧은 학습, 별도 폴더."""
    return dataclasses.replace(cfg, out_dir=os.path.join(cfg.out_dir, "_smoke"), smoke_rows=rows, max_epochs=2,
                               patience=1, extra_seeds=(43,), ratio_tolerance_pp=8.0, latency_n=10, throughput_n=50,
                               tranco_sample_n=300)


# ------------------------------------------------------------------ 저장 도우미
def _jdump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=_json_default)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def _jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_df(df, cfg, name):
    try:
        import pyarrow  # noqa: F401
        df.to_parquet(cfg.path("data", name + ".parquet"), index=False)
    except ImportError:
        df.to_pickle(cfg.path("data", name + ".pkl"))


def load_df(cfg, name):
    p = cfg.path("data", name + ".parquet")
    if os.path.exists(p):
        return pd.read_parquet(p)
    return pd.read_pickle(cfg.path("data", name + ".pkl"))


def has_df(cfg, name):
    return any(os.path.exists(cfg.path("data", name + ext)) for ext in (".parquet", ".pkl"))


def _sample(df, n, seed):
    if not n or len(df) <= n:
        return df
    frac = n / len(df)
    return df.groupby("label", group_keys=False).sample(frac=frac, random_state=seed).reset_index(drop=True)


def _hr(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


# ------------------------------------------------------------------ P0
def p0_environment(cfg, show_code=True):
    _hr("P0 환경 확인")
    rep = {"time": _dt.datetime.now().isoformat(timespec="seconds")}
    try:
        import torch
        rep["torch"] = torch.__version__
        rep["cuda"] = bool(torch.cuda.is_available())
        rep["gpu"] = torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    except ImportError:
        rep["torch"] = None
    try:
        import transformers
        rep["transformers"] = transformers.__version__
    except ImportError:
        rep["transformers"] = None
    rep["tldextract"] = U.using_tldextract()
    for k, v in rep.items():
        print(f"  {k}: {v}")
    if not rep["tldextract"]:
        print("  [경고] tldextract가 없어 등록 도메인 추출이 간이 규칙으로 동작합니다. 첫 셀의 pip install을 확인하세요.")
    if not rep.get("cuda"):
        print("  [경고] GPU가 없습니다. Kaggle 오른쪽 Settings → Accelerator에서 GPU를 켜세요.")

    from .baseline import resolve_revision, show_remote_code
    cfg.revision = resolve_revision(cfg.repo, cfg.revision)
    rep["revision"] = cfg.revision
    print(f"  모델 저장소 {cfg.repo} 커밋 고정: {cfg.revision}")
    if show_code:
        print("\n[검토] 제공 헤드를 불러올 때 실행될 수 있는 원격 코드:")
        rep["remote_code"] = show_remote_code(cfg.repo, cfg.revision, cfg.baseline_head)
    cfg.save()
    _jdump(rep, cfg.path("reports", "p0_environment.json"))
    return rep


# ------------------------------------------------------------------ P1
def p1_prepare(cfg):
    _hr("P1 데이터 점검·전처리")
    rep = {}
    mal = D.load_malicious_urls(cfg.malicious_urls_csv, cfg.collected_at)
    mal_c, rep["malicious_urls"] = D.clean(mal)
    if cfg.smoke_rows:
        mal_c = _sample(mal_c, cfg.smoke_rows, cfg.seed)
        rep["smoke_rows"] = len(mal_c)
    print("Malicious URLs 정제:", {k: v for k, v in rep["malicious_urls"].items()})
    prof = D.scheme_profile(mal_c)
    rep["scheme_profile_pct"] = prof.to_dict(orient="index")
    print("\n클래스별 scheme 분포(%) — 편향 점검:")
    print(prof.to_string())
    save_df(mal_c, cfg, "mal_clean")
    mal_groups = set(mal_c["group_key"])

    if cfg.phiusiil_csv:
        phi = D.load_phiusiil(cfg.phiusiil_csv, cfg.collected_at)
        phi_c, r = D.clean(phi)
        phi_c, removed = D.remove_groups(phi_c, mal_groups)
        r["removed_train_overlap"] = removed
        if cfg.smoke_rows:
            phi_c = _sample(phi_c, cfg.smoke_rows // 3, cfg.seed)
        r["final"] = D.describe(phi_c)
        rep["phiusiil"] = r
        save_df(phi_c, cfg, "phi_clean")
        print("\nPhiUSIIL:", r["final"], f"(Malicious URLs와 겹친 도메인 {removed}건 제거)")
    else:
        print("\n[건너뜀] PhiUSIIL 파일이 지정되지 않았습니다.")

    frames = []
    if cfg.urlhaus_csv:
        frames.append(D.load_urlhaus(cfg.urlhaus_csv, cfg.collected_at))
    if cfg.openphish_txts:
        frames.append(pd.concat([D.load_url_lines(p, "phishing", "openphish", cfg.collected_at)
                                 for p in cfg.openphish_txts], ignore_index=True))
    if cfg.phishtank_csv:
        frames.append(D.load_phishtank(cfg.phishtank_csv, cfg.collected_at))
    if cfg.tranco_csv:
        frames.append(D.load_tranco(cfg.tranco_csv, cfg.collected_at, cfg.tranco_top_n, cfg.tranco_sample_n, cfg.seed))
    frames = [f for f in frames if len(f)]
    if frames:
        ext, r = D.build_external(frames, mal_groups)
        if cfg.smoke_rows:
            ext = ext.groupby("source", group_keys=False).head(300).reset_index(drop=True)
        rep["external"] = r
        save_df(ext, cfg, "external")
        print("\n외부 최신 데이터:")
        for src, rr in r.items():
            print(f"  {src}: 입력 {rr['input']} → 최종 {rr.get('final', 0)} (학습 도메인 겹침 제거 {rr['removed_train_overlap']})")
    else:
        print("\n[건너뜀] 외부 최신 데이터 파일이 지정되지 않았습니다.")
    _jdump(rep, cfg.path("reports", "p1_prepare.json"))
    return rep


# ------------------------------------------------------------------ P2
def p2_split(cfg):
    _hr("P2 도메인 그룹 분리 (70:15:15)")
    from .split import group_split, check_split
    mal_c = load_df(cfg, "mal_clean")
    t0 = time.time()
    d = group_split(mal_c, seed=cfg.seed)
    rep = check_split(d, tolerance_pp=cfg.ratio_tolerance_pp)
    rep["seconds"] = round(time.time() - t0, 1)
    save_df(d, cfg, "mal_split")
    _jdump(rep, cfg.path("reports", "p2_split.json"))
    print("세트 크기:", rep["sizes"], rep["size_pct"])
    print("세트 간 도메인 교집합:", rep["group_overlaps"])
    print("최대 클래스 비율 차이(%p):", rep["max_ratio_diff_pp"])
    print("URL 수 상위 도메인:", [(g["group_key"], g["rows"], g["split"]) for g in rep["top_groups"][:10]])
    return rep


# ------------------------------------------------------------------ P3
def p3_baseline(cfg):
    _hr("P3 기준선: 제공 malicious_urls_4class 헤드 (학습 데이터와 겹쳐 점수가 부풀려졌을 수 있음)")
    # 제공 헤드는 원격 코드라 환경에 따라 실패할 수 있다. 기준선은 비교용이므로 실패해도 나머지 페이즈는 진행한다.
    try:
        return _p3_baseline(cfg)
    except Exception as e:  # noqa: BLE001
        rep = {"failed": True, "error": f"{type(e).__name__}: {e}"}
        _jdump(rep, cfg.path("reports", "p3_baseline_failed.json"))
        print(f"[경고] 기준선 평가 실패 — 나머지 페이즈는 계속 진행합니다.\n  {rep['error']}")
        print("  라벨 매핑 문제라면 설정 셀의 baseline_label_map을 지정하고 이 셀만 다시 실행하세요.")
        _free_gpu()
        return rep


def _p3_baseline(cfg):
    from .baseline import ProvidedHead
    d = load_df(cfg, "mal_split")
    te = d[d["split"] == "test"]
    ph = ProvidedHead(cfg.repo, cfg.revision, cfg.baseline_head, label_map=cfg.baseline_label_map)
    print("제공 헤드 id2label:", ph.id2label, "→ 매핑:", ph.label_map, "max_length:", ph.max_length)
    probs = ph.predict_probs(te["url"].map(lambda u: U.normalize(u, "raw")).tolist())
    y = np.array(to_ids(te["label"]))
    m = four_class_metrics(y, probs.argmax(1))
    m["note"] = "제공 헤드는 Malicious URLs Dataset으로 학습되어 이 test 세트와 겹칠 수 있음(재현용, 독립 성능 근거 아님)"
    m["id2label"] = ph.id2label
    m["label_map"] = ph.label_map
    _jdump(m, cfg.path("reports", "p3_baseline_metrics.json"))
    print(f"기준선 test: accuracy {m['accuracy']:.4f}, macro F1 {m['macro_f1']:.4f}, "
          f"오탐률 {m['benign_fpr']['argmax']:.4f}, 미탐률 {m['malicious_fnr']['argmax']:.4f}")
    del ph
    _free_gpu()
    return m


def _free_gpu():
    try:
        import gc
        import torch
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except ImportError:
        pass


# ------------------------------------------------------------------ P4
def _sets(cfg):
    sets = {"mal": load_df(cfg, "mal_split")}
    if has_df(cfg, "phi_clean"):
        sets["phi"] = load_df(cfg, "phi_clean")
    if has_df(cfg, "external"):
        sets["ext"] = load_df(cfg, "external")
    return sets


def p4_embed(cfg):
    _hr("P4-1 임베딩 계산 (인코더 고정, CLS+MEAN 256차원)")
    from .embed import Embedder
    emb = Embedder(cfg.repo, revision=cfg.revision)
    print(f"device={emb.device}, fp16={emb.fp16}, dim={emb.dim}")
    rep = {}
    for name, df in _sets(cfg).items():
        for norm in cfg.normalizations:
            texts = [U.normalize(u, norm) for u in df["url"]]
            X, tr = emb.encode(texts, batch_size=cfg.embed_batch, progress=True)
            np.save(cfg.path("emb", f"{norm}_{name}.npy"), X)
            np.save(cfg.path("emb", f"{norm}_{name}_trunc.npy"), tr)
            rep[f"{norm}_{name}"] = {"rows": len(texts), "seconds": round(emb.last_seconds, 1),
                                     "truncated_pct": round(100 * float(tr.mean()), 4)}
            print(f"  {norm}/{name}: {len(texts)}건, {emb.last_seconds:.1f}초, 256토큰 초과 {100 * tr.mean():.3f}%")
    if "raw" in cfg.normalizations:
        # scheme 편향 점검용 변형(val·test만). strip은 정의상 변형과 입력이 같아 계산하지 않는다.
        d = load_df(cfg, "mal_split")
        rows = np.where(d["split"].isin(["val", "test"]).values)[0]
        np.save(cfg.path("emb", "raw_mal_variant_rows.npy"), rows)
        urls_ = d["url"].values[rows]
        for v in U.SCHEME_VARIANTS:
            X, _ = emb.encode([U.normalize(U.scheme_variant(u, v), "raw") for u in urls_],
                              batch_size=cfg.embed_batch, progress=True)
            np.save(cfg.path("emb", f"raw_mal_{v}.npy"), X)
            rep[f"raw_mal_{v}"] = {"rows": int(len(rows)), "seconds": round(emb.last_seconds, 1)}
            print(f"  raw/mal 변형[{v}] (val+test): {len(rows)}건, {emb.last_seconds:.1f}초")
    _jdump(rep, cfg.path("reports", "p4_embed.json"))
    del emb
    _free_gpu()
    return rep


def _load_xy(cfg, norm, split):
    d = load_df(cfg, "mal_split")
    X = np.load(cfg.path("emb", f"{norm}_mal.npy"))
    sel = (d["split"] == split).values
    return X[sel], np.array(to_ids(d.loc[sel, "label"]))


def _variant_xy(cfg, norm, split, variant):
    """scheme 변형 입력의 (X, y). strip 정규화는 변형해도 입력이 같으므로 원본을 그대로 쓴다."""
    if norm in ("strip", "strip2"):
        return _load_xy(cfg, norm, split)
    path = cfg.path("emb", f"{norm}_mal_{variant}.npy")
    if not os.path.exists(path):
        return None
    d = load_df(cfg, "mal_split")
    rows = np.load(cfg.path("emb", f"{norm}_mal_variant_rows.npy"))
    sel = d["split"].values[rows] == split
    X = np.load(path)[sel]
    return X, np.array(to_ids(d["label"].values[rows][sel]))


def _robust_val_f1(cfg, info):
    """원본 val과 scheme 변형 val의 Macro F1, 그리고 그중 최저값."""
    head = NumpyHead.load(info["head_file"], info["spec"])
    f1s = {"original": info["best_val_macro_f1"]}
    for v in U.SCHEME_VARIANTS:
        xy = _variant_xy(cfg, info["normalization"], "val", v)
        if xy is not None:
            f1s[v] = four_class_metrics(xy[1], head.probs(xy[0].astype(np.float32)).argmax(1))["macro_f1"]
    return min(f1s.values()), f1s


def p4_train(cfg):
    _hr("P4-2 헤드 학습: {raw, strip} × {Linear, MLP}, 선택 기준 = val Macro F1 최저값(원본·scheme 제거·https 추가)")
    from .train import train_head
    runs = []
    for norm in cfg.normalizations:
        Xtr, ytr = _load_xy(cfg, norm, "train")
        Xva, yva = _load_xy(cfg, norm, "val")
        for kind in cfg.head_kinds:
            runs.append(_train_one(cfg, train_head, norm, kind, cfg.seed, Xtr, ytr, Xva, yva))
    for r in runs:
        r["val_macro_f1_worst"], r["val_macro_f1_variants"] = _robust_val_f1(cfg, r)
    table = pd.DataFrame([{"normalization": r["normalization"], "kind": r["kind"], "seed": r["seed"],
                           "val_f1_original": r["val_macro_f1_variants"]["original"],
                           "val_f1_noscheme": r["val_macro_f1_variants"].get("noscheme"),
                           "val_f1_https": r["val_macro_f1_variants"].get("https"),
                           "val_f1_worst": r["val_macro_f1_worst"], "best_epoch": r["best_epoch"], "seconds": r["seconds"]}
                          for r in runs])
    print("\n조합별 val Macro F1 (원본 / scheme 제거 / https 추가 / 최저):\n" + table.to_string(index=False))
    # 최저값이 가장 높은 조합. 동점이면 strip(입력 형태에 덜 민감) → linear(단순) 우선
    norm_rank = {"strip": 0, "raw": 1}
    best = max(runs, key=lambda r: (round(r["val_macro_f1_worst"], 6), -norm_rank.get(r["normalization"], 2),
                                    -cfg.head_kinds.index(r["kind"])))
    print(f"\n선택: normalization={best['normalization']}, head={best['kind']} "
          f"(val Macro F1 최저 {best['val_macro_f1_worst']:.4f}, 원본 {best['best_val_macro_f1']:.4f})")

    seed_runs = [best]
    if cfg.extra_seeds:
        Xtr, ytr = _load_xy(cfg, best["normalization"], "train")
        Xva, yva = _load_xy(cfg, best["normalization"], "val")
        for s in cfg.extra_seeds:
            seed_runs.append(_train_one(cfg, train_head, best["normalization"], best["kind"], s, Xtr, ytr, Xva, yva))
    for r in seed_runs[1:]:
        r["val_macro_f1_worst"], r["val_macro_f1_variants"] = _robust_val_f1(cfg, r)
    f1s = [r["best_val_macro_f1"] for r in seed_runs]
    worst = [r["val_macro_f1_worst"] for r in seed_runs]
    selection = {
        "normalization": best["normalization"], "kind": best["kind"], "seed": cfg.seed,
        "head_file": best["head_file"], "spec": best["spec"],
        "val_macro_f1": best["best_val_macro_f1"],
        "val_macro_f1_worst": best["val_macro_f1_worst"],
        "val_macro_f1_variants": best["val_macro_f1_variants"],
        "selection_metric": "val Macro F1의 최저값 (원본, scheme 제거, https 추가 변형)",
        "seed_val_macro_f1_worst": worst,
        "seeds": [r["seed"] for r in seed_runs], "seed_val_macro_f1": f1s,
        "seed_mean": float(np.mean(f1s)), "seed_std": float(np.std(f1s, ddof=1)) if len(f1s) > 1 else 0.0,
        "all_runs": table.to_dict(orient="records"),
        "selected_on": "val",
    }
    _jdump(selection, cfg.path("reports", "p4_selection.json"))
    print(f"시드 {selection['seeds']}: val Macro F1 평균 {selection['seed_mean']:.4f} ± {selection['seed_std']:.4f}")
    return selection


def _train_one(cfg, train_head, norm, kind, seed, Xtr, ytr, Xva, yva):
    model, info = train_head(Xtr, ytr, Xva, yva, kind, seed=seed, lr=cfg.lr, weight_decay=cfg.weight_decay,
                             batch_size=cfg.batch_size, max_epochs=cfg.max_epochs, patience=cfg.patience)
    name = f"{norm}_{kind}_s{seed}"
    path = cfg.path("heads", name + ".npz")
    save_head(path, torch_head_to_numpy(model))
    info.update({"normalization": norm, "head_file": path, "spec": head_spec(kind, in_dim=Xtr.shape[1])})
    _jdump(info, cfg.path("heads", name + ".json"))
    return info


def _selected_head(cfg):
    sel = _jload(cfg.path("reports", "p4_selection.json"))
    return sel, NumpyHead.load(sel["head_file"], sel["spec"])


# ------------------------------------------------------------------ P6
def p6_thresholds(cfg):
    _hr("P6 위험도 임계값 (val 세트로만 결정)")
    sel, head = _selected_head(cfg)
    Xva, yva = _load_xy(cfg, sel["normalization"], "val")
    risk = risk_score(head.probs(Xva.astype(np.float32)))
    thr = choose_thresholds(risk, yva, cfg.benign_fpr_target, cfg.malicious_recall_target)
    _jdump(thr, cfg.path("reports", "thresholds.json"))
    print(f"t_low(주의 시작) = {thr['t_low']:.6f}, t_high(위험 시작) = {thr['t_high']:.6f}, 상태 = {thr['status']}")
    print("val에서 달성:", thr["achieved_on_val"])
    if thr["status"] == "separated":
        print("→ 정상·악성 점수가 목표 기준으로 겹치지 않아 '주의' 구간이 비었습니다. 팀에서 목표값을 조정할지 정하세요.")
    return thr


# ------------------------------------------------------------------ P5
def p5_evaluate(cfg):
    _hr("P5 평가 (test 세트는 여기서 처음 사용)")
    sel, head = _selected_head(cfg)
    thr = _jload(cfg.path("reports", "thresholds.json"))
    norm = sel["normalization"]
    out = {"model": {k: sel[k] for k in ("normalization", "kind", "seed", "val_macro_f1", "val_macro_f1_worst",
                                         "val_macro_f1_variants", "seed_mean", "seed_std")},
           "thresholds": thr}

    Xte, yte = _load_xy(cfg, norm, "test")
    p = head.probs(Xte.astype(np.float32))
    risk = risk_score(p)
    m = four_class_metrics(yte, p.argmax(1), flagged_by_threshold=risk >= thr["t_low"])
    d = load_df(cfg, "mal_split")
    trunc = np.load(cfg.path("emb", f"{norm}_mal_trunc.npy"))[(d["split"] == "test").values]
    m["truncated_pct"] = round(100 * float(trunc.mean()), 4)
    out["test"] = m
    _print_four(m, "우리 헤드 test")
    rob = {}
    for v in U.SCHEME_VARIANTS:
        xy = _variant_xy(cfg, norm, "test", v)
        if xy is not None:
            pv = head.probs(xy[0].astype(np.float32))
            mv = four_class_metrics(xy[1], pv.argmax(1), flagged_by_threshold=risk_score(pv) >= thr["t_low"])
            rob[v] = {k: mv[k] for k in ("n", "accuracy", "macro_f1", "benign_fpr", "malicious_fnr")}
    if rob:
        out["test_scheme_variants"] = rob
        print("scheme 변형 test (편향 점검):", json.dumps(rob, ensure_ascii=False, default=_json_default))
    _save_confusion_png(m, cfg.path("reports", "confusion_matrix.png"))

    if os.path.exists(cfg.path("emb", f"{norm}_phi.npy")):
        phi = load_df(cfg, "phi_clean")
        yphi = np.array(to_ids(phi["label"]))
        out["phiusiil"] = {}
        for n2 in cfg.normalizations:
            hp = _head_for(cfg, sel, n2)
            if hp is None:
                continue
            pp = hp.probs(np.load(cfg.path("emb", f"{n2}_phi.npy")).astype(np.float32))
            rr = risk_score(pp)
            r = binary_metrics(yphi, rr, pp.argmax(1) != BENIGN_ID,
                               rr >= thr["t_low"] if n2 == norm else None)
            r["role"] = "selected" if n2 == norm else "reference(참고용)"
            out["phiusiil"][n2] = r
            print(f"PhiUSIIL [{n2}, {r['role']}]: AUROC {r['auroc']:.4f}, 오탐률 {r['benign_fpr']}, 미탐률 {r['malicious_fnr']}")

    if os.path.exists(cfg.path("emb", f"{norm}_ext.npy")):
        ext = load_df(cfg, "external")
        pe = head.probs(np.load(cfg.path("emb", f"{norm}_ext.npy")).astype(np.float32))
        out["external"] = external_metrics(ext["source"].values, np.array(to_ids(ext["label"])), pe.argmax(1),
                                           risk_score(pe) >= thr["t_low"])
        out["external_note"] = "출처마다 클래스가 하나뿐이라 Precision·Macro F1·Accuracy는 산출하지 않음. defacement 외부 평가 없음."
        for src, r in out["external"].items():
            print(f"외부 [{src}] n={r['n']}: " + json.dumps({k: v for k, v in r.items() if k not in ('n', 'label')},
                                                          ensure_ascii=False, default=_json_default))

    bpath = cfg.path("reports", "p3_baseline_metrics.json")
    if os.path.exists(bpath):
        b = _jload(bpath)
        rows = []
        for name, mm in (("제공 헤드(기준선, 부풀려졌을 수 있음)", b), ("우리 헤드", m)):
            rows.append({"모델": name, "Accuracy": mm["accuracy"], "Macro F1": mm["macro_f1"],
                         "정상 오탐률(argmax)": mm["benign_fpr"]["argmax"], "악성 미탐률(argmax)": mm["malicious_fnr"]["argmax"]})
        out["comparison"] = rows
        print("\n기준선 비교 (같은 test 세트, 같은 평가 함수):\n" + pd.DataFrame(rows).to_string(index=False))

    _jdump(out, cfg.path("reports", "metrics.json"))
    return out


def _head_for(cfg, sel, norm):
    if norm == sel["normalization"]:
        return NumpyHead.load(sel["head_file"], sel["spec"])
    path = cfg.path("heads", f"{norm}_{sel['kind']}_s{cfg.seed}.npz")
    return NumpyHead.load(path, sel["spec"]) if os.path.exists(path) else None


def _print_four(m, title):
    print(f"\n[{title}] n={m['n']}  Accuracy {m['accuracy']:.4f}  Macro F1 {m['macro_f1']:.4f}")
    for name in LABELS:
        pc = m["per_class"][name]
        print(f"  {name:11s} P {pc['precision']:.4f}  R {pc['recall']:.4f}  F1 {pc['f1']:.4f}  n={pc['support']}")
    print(f"  정상 URL 오탐률: {m['benign_fpr']}")
    print(f"  악성 URL 미탐률: {m['malicious_fnr']}")
    print("  혼동행렬(행=정답, 열=예측):")
    print(pd.DataFrame(m["confusion_matrix"]["matrix"], index=LABELS, columns=LABELS).to_string())


def _save_confusion_png(m, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    cm = np.array(m["confusion_matrix"]["matrix"], dtype=float)
    norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(5.2, 4.4), dpi=150)
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(4), LABELS, rotation=30, ha="right")
    ax.set_yticks(range(4), LABELS)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    for i in range(4):
        for j in range(4):
            ax.text(j, i, f"{int(cm[i, j])}\n{norm[i, j]:.1%}", ha="center", va="center", fontsize=7.5,
                    color="white" if norm[i, j] > 0.6 else "black")
    ax.set_title(f"Test confusion matrix (macro F1 {m['macro_f1']:.4f})", fontsize=9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ------------------------------------------------------------------ P7
def p7_export(cfg, zip_path="/kaggle/working/qsing_artifacts"):
    _hr("P7 서버용 산출물 내보내기 + CPU 추론 점검")
    from .embed import Embedder
    from .infer import UrlRiskClassifier
    sel, _ = _selected_head(cfg)
    art = os.path.join(cfg.out_dir, "artifacts")
    if os.path.exists(art):
        shutil.rmtree(art)
    os.makedirs(art)
    emb = Embedder(cfg.repo, revision=cfg.revision, device="cpu")
    emb.save(os.path.join(art, "encoder"))
    del emb
    shutil.copy(sel["head_file"], os.path.join(art, "head.npz"))
    trained = _dt.date.today().isoformat()
    model_cfg = {
        "repo": cfg.repo, "revision": cfg.revision,
        "model_version": f"urlbert-tiny-v6@{str(cfg.revision)[:12]}+head-{sel['kind']}-{sel['normalization']}-{trained}",
        "normalization": sel["normalization"], "pooling": "cls+mean", "max_tokens": 256,
        "head": sel["spec"], "labels": list(LABELS), "trained_at": trained,
        "selection": {k: sel[k] for k in ("val_macro_f1", "val_macro_f1_worst", "selection_metric", "seed",
                                          "seed_mean", "seed_std", "selected_on")},
        "notes": "ai_risk_score = 1 - P(benign). 모델 예측 점수이며 실제 피해 확률이 아님.",
    }
    _jdump(model_cfg, os.path.join(art, "model_config.json"))
    shutil.copy(cfg.path("reports", "thresholds.json"), os.path.join(art, "thresholds.json"))
    for f in ("metrics.json", "confusion_matrix.png"):
        if os.path.exists(cfg.path("reports", f)):
            shutil.copy(cfg.path("reports", f), os.path.join(art, f))

    clf = UrlRiskClassifier.from_artifacts(art, device="cpu", num_threads=cfg.cpu_threads)
    samples = ["https://www.naver.com/", "http://secure-login.example-bank.xyz/verify?id=1",
               "javascript:alert(1)", "", "http://192.168.10.5/bins/x86"]
    print("예시 결과:")
    for r in clf.predict_batch(samples):
        print("  ", json.dumps({k: r[k] for k in ("status", "url", "predicted_type", "ai_risk_score", "risk_level")},
                               ensure_ascii=False))

    # 학습 때(GPU, fp16) 임베딩과 서버(CPU, fp32) 결과가 같은 판단을 내리는지 확인
    d = load_df(cfg, "mal_split")
    te = d[d["split"] == "test"].sample(n=min(500, (d["split"] == "test").sum()), random_state=cfg.seed)
    X = np.load(cfg.path("emb", f"{sel['normalization']}_mal.npy"))[te.index.values]
    head = NumpyHead.load(sel["head_file"], sel["spec"])
    p_train = head.probs(X.astype(np.float32))
    res = clf.predict_batch(te["url"].tolist())
    p_srv = np.array([[r["scores"][k] for k in LABELS] for r in res])
    parity = {"n": len(te), "argmax_agreement": float((p_train.argmax(1) == p_srv.argmax(1)).mean()),
              "max_abs_prob_diff": float(np.abs(p_train - p_srv).max())}
    print("학습 임베딩 vs 서버 추론 일치:", parity)

    urls_ = d.loc[d["split"] == "test", "url"].sample(n=min(cfg.latency_n, (d["split"] == "test").sum()), random_state=1).tolist()
    clf.predict(urls_[0])  # 워밍업
    lat = []
    for u in urls_:
        t0 = time.perf_counter()
        clf.predict(u)
        lat.append((time.perf_counter() - t0) * 1000)
    bulk = d.loc[d["split"] == "test", "url"].head(cfg.throughput_n).tolist()
    t0 = time.perf_counter()
    clf.predict_batch(bulk)
    sec = time.perf_counter() - t0
    try:
        import torch
        threads = torch.get_num_threads()
    except ImportError:
        threads = None
    latency = {"device": "cpu", "threads": threads, "single_url_ms_p50": float(np.percentile(lat, 50)),
               "single_url_ms_p95": float(np.percentile(lat, 95)), "n_single": len(lat),
               "batch_urls_per_sec": len(bulk) / sec, "n_batch": len(bulk),
               "note": "Kaggle CPU 기준. 실제 서버 사양에 따라 달라짐. 외부 검사(VirusTotal) 시간은 포함하지 않음."}
    print("AI 단독 분석 시간(CPU):", latency)

    for path in (cfg.path("reports", "metrics.json"), os.path.join(art, "metrics.json")):
        if os.path.exists(path):
            mm = _jload(path)
            mm["latency"] = latency
            mm["parity"] = parity
            _jdump(mm, path)
    archive = shutil.make_archive(zip_path, "zip", art)
    print(f"\n산출물 폴더: {art}\n다운로드용 zip: {archive}")
    return {"artifacts_dir": art, "zip": archive, "latency": latency, "parity": parity, "model_config": model_cfg}


# ------------------------------------------------------------------ 요약
def run_summary_md(cfg):
    """work_history.md에 붙여넣을 실행 결과 요약(마크다운)."""
    L = []
    today = _dt.date.today().isoformat()
    L.append(f"\n---\n\n## {today} · 모델 학습·평가 실행 결과 (Kaggle)\n")
    p1 = _jload(cfg.path("reports", "p1_prepare.json")) if os.path.exists(cfg.path("reports", "p1_prepare.json")) else {}
    if p1:
        mu = p1["malicious_urls"]
        L.append(f"- P1 Malicious URLs 정제: 입력 {mu['input']} → {mu['output']} (형식 오류·미지원 {mu['dropped_invalid_or_unsupported']}, "
                 f"중복 {mu['dropped_exact_duplicates']}, 라벨 충돌 {mu['dropped_label_conflicts']})")
        L.append(f"  - 클래스별 건수: {mu['label_counts']}")
    p2 = cfg.path("reports", "p2_split.json")
    if os.path.exists(p2):
        r = _jload(p2)
        L.append(f"- P2 분리: {r['sizes']} / 도메인 교집합 {r['group_overlaps']} / 최대 비율 차이 {r['max_ratio_diff_pp']}%p")
    sel_p = cfg.path("reports", "p4_selection.json")
    if os.path.exists(sel_p):
        s = _jload(sel_p)
        L.append(f"- P4 선택: {s['normalization']} + {s['kind']} (val Macro F1 원본 {s['val_macro_f1']:.4f}, "
                 f"scheme 변형 포함 최저 {s['val_macro_f1_worst']:.4f}, 시드 평균 {s['seed_mean']:.4f} ± {s['seed_std']:.4f})")
        for row in s["all_runs"]:
            L.append(f"  - {row['normalization']}+{row['kind']}: 원본 {row['val_f1_original']:.4f} / 최저 {row['val_f1_worst']:.4f}")
    thr_p = cfg.path("reports", "thresholds.json")
    if os.path.exists(thr_p):
        t = _jload(thr_p)
        L.append(f"- P6 임계값: t_low {t['t_low']:.6f}, t_high {t['t_high']:.6f} ({t['status']})")
    mp = cfg.path("reports", "metrics.json")
    if os.path.exists(mp):
        m = _jload(mp)
        te = m["test"]
        L.append(f"- P5 test: Accuracy {te['accuracy']:.4f}, Macro F1 {te['macro_f1']:.4f}, "
                 f"정상 오탐률 {te['benign_fpr']}, 악성 미탐률 {te['malicious_fnr']}")
        for name in LABELS:
            pc = te["per_class"][name]
            L.append(f"  - {name}: P {pc['precision']:.4f} / R {pc['recall']:.4f} / F1 {pc['f1']:.4f} (n={pc['support']})")
        for v, r in m.get("test_scheme_variants", {}).items():
            L.append(f"  - scheme 변형[{v}] test: Macro F1 {r['macro_f1']:.4f}, 정상 오탐률 {r['benign_fpr']}")
        for row in m.get("comparison", []):
            L.append(f"  - 비교 {row['모델']}: Accuracy {row['Accuracy']:.4f}, Macro F1 {row['Macro F1']:.4f}")
        for n2, r in m.get("phiusiil", {}).items():
            L.append(f"- PhiUSIIL [{n2}, {r['role']}]: AUROC {r['auroc']:.4f}, 오탐률 {r['benign_fpr']}, 미탐률 {r['malicious_fnr']}")
        for src, r in m.get("external", {}).items():
            key = "benign_fpr" if r["label"] == "benign" else "malicious_fnr"
            v = r[key]["argmax"]
            L.append(f"- 외부 {src} (n={r['n']}): {key} {v['value']:.4f} [95% CI {v['ci95'][0]:.4f}–{v['ci95'][1]:.4f}]")
        if "latency" in m:
            la = m["latency"]
            L.append(f"- CPU 추론 시간: p50 {la['single_url_ms_p50']:.1f}ms, p95 {la['single_url_ms_p95']:.1f}ms, "
                     f"배치 {la['batch_urls_per_sec']:.0f} URL/초")
        if "parity" in m:
            L.append(f"- 학습(GPU fp16) vs 서버(CPU fp32) 예측 일치율: {m['parity']['argmax_agreement']:.4f}")
    text = "\n".join(L) + "\n"
    with open(cfg.path("reports", "run_summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    return text
