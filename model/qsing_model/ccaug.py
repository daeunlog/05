"""v5 (설계 개정 6): 다른 출처 정상 URL 보강 (Common Crawl).

Malicious URLs의 정상 URL은 ISCX-URL-2016에서 왔고, 그 데이터는 도메인만 있는 URL을 제거하고 만들었다.
같은 데이터 안에서 형식만 바꾸는 방법(v3 홈페이지 보강, v4 strip2)으로는 다른 출처 정상 URL 오탐을 다 줄이지 못했다.

- 추가 데이터: HuggingFace JPxxx/url-benchmark-dataset (정상 = Common Crawl, 악성 = PhishTank·URLhaus 등, Apache-2.0)
- train 세트에만 정상 URL을 추가한다. val·test·외부 평가 세트는 v4와 같다.
- 누수 방지: val·test 도메인, 외부 평가 도메인, 악성에 나온 호스트, 이미 있는 URL을 뺀다. 도메인당 최대 per_domain건.
- holdout: 학습에 쓰지 않은 도메인의 정상·악성 URL로 '처음 보는 출처' 평가를 한다(악성 종류 라벨이 없어 2종 지표만).
"""

import numpy as np
import pandas as pd

from . import data as D
from . import urls as U
from .labels import BENIGN_ID, to_ids

JP_REPO = "JPxxx/url-benchmark-dataset"
JP_FILE = "data/train-00000-of-00001.parquet"
_LABEL_MAP = {"benign": "benign", "0": "benign", "malicious": "malicious", "1": "malicious"}


def fetch_jp():
    """Kaggle 입력에 parquet이 있으면 그것을, 없으면 HuggingFace에서 내려받는다."""
    hits = D.find_files([JP_FILE.split("/")[-1]], roots=("/kaggle/input",))
    if hits:
        return hits[0]
    from huggingface_hub import hf_hub_download
    return hf_hub_download(JP_REPO, JP_FILE, repo_type="dataset")


def load_jp(path):
    """url, label(benign|malicious) 두 컬럼으로 읽는다. 라벨은 문자열이든 0/1이든 받는다."""
    if str(path).lower().endswith(".csv"):
        raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    else:
        raw = pd.read_parquet(path, columns=["url", "label"])
    lab = raw["label"].astype(str).str.strip().str.lower().map(_LABEL_MAP)
    if lab.isna().any():
        raise ValueError(f"알 수 없는 label 값: {raw.loc[lab.isna(), 'label'].unique()[:5]}")
    share = float((lab == "benign").mean())
    if not 0.5 < share < 0.99:
        raise ValueError(f"benign 비율 {share:.3f}가 데이터 카드(약 0.9)와 다릅니다. 라벨 해석을 확인하세요.")
    return pd.DataFrame({"url": raw["url"].astype(str), "label": lab})


def cc_rows(d, aug, jp, eval_groups, collected_at, seed=42, n_train=200_000, n_hold=20_000, per_domain=3,
            pool_benign=1_000_000, pool_malicious=150_000):
    """보강 행을 만든다. 반환: (DataFrame[url,label,source,split,group_key], 리포트).

    d: 분리된 Malicious URLs(split, group_key 포함) / aug: 이미 만든 보강 행 / jp: load_jp 결과
    eval_groups: 외부 평가 세트(PhiUSIIL·OpenPhish·Tranco)의 등록 도메인 집합
    """
    rep = {"jp_rows": int(len(jp)), "jp_label_counts": {k: int(v) for k, v in jp["label"].value_counts().items()}}
    ben, mal = jp[jp["label"] == "benign"], jp[jp["label"] == "malicious"]
    if len(ben) > pool_benign:
        ben = ben.sample(n=pool_benign, random_state=seed)
    if len(mal) > pool_malicious:
        mal = mal.sample(n=pool_malicious, random_state=seed)
    # 악성은 종류를 모르므로 임시로 phishing 라벨을 붙인다(2종 평가에만 사용).
    frame = pd.concat([D._frame(ben["url"], ["benign"] * len(ben), "cc_benign", collected_at),
                       D._frame(mal["url"], ["phishing"] * len(mal), "jp_malicious", collected_at)], ignore_index=True)
    c, rep["clean"] = D.clean(frame)
    c["host"] = c["url"].map(U.parse_host)
    c["_lk"] = c["url"].map(U.loose_key)

    mal_groups_all = set(d["group_key"])
    valtest_groups = set(d.loc[d["split"] != "train", "group_key"])
    eval_groups = set(eval_groups)
    jp_mal = c[c["label"] != "benign"]
    mal_hosts = set(d.loc[d["label"] != "benign", "url"].map(U.parse_host)) | set(jp_mal["host"])
    existing = set(d["url"].map(U.loose_key)) | set(aug["url"].map(U.loose_key))

    b = c[c["label"] == "benign"]
    steps = {"benign_after_clean": int(len(b))}
    b = b[~b["group_key"].isin(valtest_groups)]
    steps["after_drop_valtest_domains"] = int(len(b))
    b = b[~b["group_key"].isin(eval_groups)]
    steps["after_drop_external_eval_domains"] = int(len(b))
    b = b[~b["host"].isin(mal_hosts)]
    steps["after_drop_malicious_hosts"] = int(len(b))
    b = b[~b["_lk"].isin(existing)]
    steps["after_drop_existing_urls"] = int(len(b))
    b = b.sample(frac=1.0, random_state=seed)
    b = b.groupby("group_key", sort=False).head(per_domain)
    steps["after_per_domain_cap"] = int(len(b))
    steps["domains_after_cap"] = int(b["group_key"].nunique())

    # holdout 정상: Malicious URLs에도 JP 악성에도 없는 도메인을 통째로 떼어 둔다.
    new = b[~b["group_key"].isin(mal_groups_all | set(jp_mal["group_key"]))]
    sizes = new.groupby("group_key", sort=False).size()
    k = int(np.searchsorted(sizes.cumsum().values, n_hold)) + 1
    k = max(1, min(k, len(sizes) // 5)) if len(sizes) else 0
    hold_groups = set(sizes.index[:k])
    hold_b = new[new["group_key"].isin(hold_groups)]
    tr = b[~b["group_key"].isin(hold_groups)]
    if len(tr) > n_train:
        tr = tr.sample(n=n_train, random_state=seed)

    # holdout 악성: 학습 데이터·외부 평가·train 보강 어디에도 없는 도메인.
    m = jp_mal[~jp_mal["group_key"].isin(mal_groups_all | eval_groups | set(tr["group_key"]) | hold_groups)]
    steps["malicious_after_clean"] = int(len(jp_mal))
    steps["malicious_unseen_domains"] = int(len(m))
    m = m.sample(frac=1.0, random_state=seed).groupby("group_key", sort=False).head(per_domain)
    if len(m) > n_hold:
        m = m.sample(n=n_hold, random_state=seed)

    def pack(df, label, source, split):
        return pd.DataFrame({"url": df["url"].values, "label": label, "source": source, "split": split,
                             "group_key": df["group_key"].values})

    out = pd.concat([pack(tr, "benign", "cc_benign", "train"),
                     pack(hold_b, "benign", "cc_benign_holdout", "holdout"),
                     pack(m, "phishing", "jp_malicious_holdout", "holdout")], ignore_index=True)

    tr_groups, hold_all = set(tr["group_key"]), hold_groups | set(m["group_key"])
    assert not tr_groups & valtest_groups, "train 보강 도메인이 val·test와 겹침"
    assert not tr_groups & eval_groups, "train 보강 도메인이 외부 평가와 겹침"
    assert not hold_all & (mal_groups_all | tr_groups), "holdout 도메인이 학습 데이터와 겹침"

    from .augment import is_homepage
    rep["steps"] = steps
    rep["train"] = {"rows": int(len(tr)), "domains": int(tr["group_key"].nunique()),
                    "homepage_pct": round(100 * float(tr["url"].map(is_homepage).mean()), 2) if len(tr) else None,
                    "median_len": float(tr["url"].str.len().median()) if len(tr) else None,
                    "https_pct": round(100 * float(tr["url"].str.lower().str.startswith("https://").mean()), 2) if len(tr) else None}
    rep["holdout"] = {"benign_rows": int(len(hold_b)), "benign_domains": int(len(hold_groups)),
                      "malicious_rows": int(len(m)), "malicious_domains": int(m["group_key"].nunique()),
                      "benign_homepage_pct": round(100 * float(hold_b["url"].map(is_homepage).mean()), 2) if len(hold_b) else None,
                      "malicious_homepage_pct": round(100 * float(m["url"].map(is_homepage).mean()), 2) if len(m) else None}
    rep["rules"] = ["val·test 도메인 제외", "외부 평가(PhiUSIIL·OpenPhish·Tranco) 도메인 제외", "악성에 나온 호스트 제외",
                    "이미 있는 URL 제외", f"도메인당 최대 {per_domain}건", f"seed {seed}"]
    return out, rep


def run_v5(cfg, P, v2_reports_dir=None, jp_path=None, log=print, zip_path="/kaggle/working/qsing_artifacts", **kw):
    """v4 흐름(run_v3, strip2) + Common Crawl 정상 보강(train) + holdout 평가 + 보강 없는 헤드와 비교."""
    from . import augment as A
    from .head import NumpyHead
    from .metrics import binary_metrics, four_class_metrics
    from .risk import risk_score

    def extra(cfg, P, d, aug, log):
        P._hr("P14 다른 출처 정상 URL 보강 (Common Crawl, JPxxx/url-benchmark-dataset)")
        jp = load_jp(jp_path or fetch_jp())
        eval_groups = set()
        for name in ("phi_clean", "external"):
            if P.has_df(cfg, name):
                eval_groups |= set(P.load_df(cfg, name)["group_key"])
        rows, rep = cc_rows(d, aug, jp, eval_groups, cfg.collected_at, seed=cfg.seed, **kw)
        P._jdump(rep, cfg.path("reports", "p14_cc_augment.json"))
        log(f"JPxxx: {rep['jp_label_counts']}")
        log(f"필터 단계: {rep['steps']}")
        log(f"train 보강: {rep['train']}")
        log(f"holdout: {rep['holdout']}")
        return rows

    def post(cfg, P, aug, sel, thr, mm, log):
        P._hr("P15 처음 보는 출처 평가 (JPxxx holdout: 학습에 없는 도메인의 정상·악성)")
        from .train import train_head
        norm = sel["normalization"]
        Xa = np.load(cfg.path("emb", f"{norm}_home.npy"))
        hold = (aug["split"] == "holdout").values
        Xh, yh = Xa[hold].astype(np.float32), np.array(to_ids(aug.loc[hold, "label"]))

        def evaluate(head, t_low=None):
            p = head.probs(Xh)
            rr = risk_score(p)
            r = binary_metrics(yh, rr, p.argmax(1) != BENIGN_ID, rr >= t_low if t_low is not None else None)
            Xt, yt = P._load_xy(cfg, norm, "test")
            t = four_class_metrics(yt, head.probs(Xt.astype(np.float32)).argmax(1))
            r["test_check"] = {"macro_f1": t["macro_f1"], "benign_fpr": t["benign_fpr"]["argmax"],
                               "malicious_fnr": t["malicious_fnr"]["argmax"]}
            return r

        res = {"with_cc(v5)": evaluate(NumpyHead.load(sel["head_file"], sel["spec"]), thr["t_low"])}
        # 비교 기준: 같은 시드·같은 설정에서 Common Crawl 보강만 뺀 헤드 (= v4 재현)
        Xm, ym = P._load_xy(cfg, norm, "train")
        home = ((aug["split"] == "train") & (aug["source"] == "aug_homepage")).values
        Xtr = np.concatenate([Xm, Xa[home]])
        ytr = np.concatenate([ym, np.array(to_ids(aug.loc[home, "label"]), dtype=int)])
        Xva, yva = P._load_xy(cfg, norm, "val")
        info = P._train_one(cfg, train_head, norm + "_nocc", sel["kind"], cfg.seed, Xtr, ytr, Xva, yva)
        res["without_cc(v4 재현)"] = evaluate(NumpyHead.load(info["head_file"], info["spec"]))
        res["without_cc(v4 재현)"]["val_macro_f1"] = info["best_val_macro_f1"]
        res["note"] = "악성 종류 라벨이 없어 2종 지표만 계산. JPxxx는 인코더 벤치마크 계열 데이터라 수치가 낙관적일 수 있음."
        for name in ("with_cc(v5)", "without_cc(v4 재현)"):
            r = res[name]
            log(f"holdout [{name}] n={r['n']} (정상 {r['n_benign']}, 악성 {r['n_malicious']}): AUROC {r['auroc']:.4f}, "
                f"오탐률 {r['benign_fpr']}, 미탐률 {r['malicious_fnr']}, test 확인 {r['test_check']}")
        mm["jp_holdout"] = res
        mm["cc_augment"] = P._jload(cfg.path("reports", "p14_cc_augment.json"))
        return mm

    text = A.run_v3(cfg, P, v2_reports_dir, log, zip_path, extra_rows=extra, post_eval=post)
    m = P._jload(cfg.path("reports", "metrics.json"))
    L = ["", "## v5 추가 (개정 6)"]
    ca = m["cc_augment"]
    L.append(f"- Common Crawl 정상 보강(train): {ca['train']['rows']}행, 도메인 {ca['train']['domains']}개, "
             f"홈페이지 형태 {ca['train']['homepage_pct']}%")
    for name in ("with_cc(v5)", "without_cc(v4 재현)"):
        r = m["jp_holdout"][name]
        L.append(f"- JPxxx holdout [{name}] (정상 {r['n_benign']}, 악성 {r['n_malicious']}): AUROC {r['auroc']:.4f}, "
                 f"오탐률 {r['benign_fpr']}, 미탐률 {r['malicious_fnr']}")
    text += "\n".join(L) + "\n"
    with open(cfg.path("reports", "run_summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    return text
