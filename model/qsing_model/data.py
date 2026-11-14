"""데이터셋 로딩·정제·점검 (설계 문서 2장, 개정 1).

공통 스키마: url, label, source, collected_at (+ group_key)
"""

import fnmatch
import glob
import os
import re

import numpy as np
import pandas as pd

from .labels import LABELS
from . import urls as U

SCHEMA = ["url", "label", "source", "collected_at"]


# ---------------------------------------------------------------- 파일 찾기
def find_file(patterns, roots=("/kaggle/input",), required=True):
    """roots 아래에서 glob 패턴(여러 개 가능)에 맞는 첫 파일 경로. 대소문자 무시."""
    if isinstance(patterns, str):
        patterns = [patterns]
    for root in roots:
        for path in sorted(glob.glob(os.path.join(root, "**", "*"), recursive=True)):
            name = os.path.basename(path).lower()
            if os.path.isfile(path) and any(fnmatch.fnmatch(name, p.lower()) for p in patterns):
                return path
    if required:
        raise FileNotFoundError(f"{roots} 아래에서 {patterns} 파일을 찾지 못했습니다. Kaggle 'Add Input'으로 데이터를 붙였는지 확인하세요.")
    return None


def find_files(patterns, roots=("/kaggle/input",)):
    if isinstance(patterns, str):
        patterns = [patterns]
    out = []
    for root in roots:
        for path in sorted(glob.glob(os.path.join(root, "**", "*"), recursive=True)):
            name = os.path.basename(path).lower()
            if os.path.isfile(path) and any(fnmatch.fnmatch(name, p.lower()) for p in patterns):
                out.append(path)
    return out


# ---------------------------------------------------------------- 로더
def _frame(urls_, labels, source, collected_at):
    df = pd.DataFrame({"url": list(urls_), "label": list(labels)})
    df["source"] = source
    df["collected_at"] = collected_at
    return df[SCHEMA]


def load_malicious_urls(path, collected_at):
    """Kaggle sid321axn/malicious-urls-dataset (컬럼 url, type)."""
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = {c.lower().strip(): c for c in raw.columns}
    if "url" not in cols or "type" not in cols:
        raise ValueError(f"예상한 컬럼(url, type)이 없습니다: {list(raw.columns)}")
    lab = raw[cols["type"]].str.strip().str.lower()
    unknown = sorted(set(lab) - set(LABELS))
    if unknown:
        raise ValueError(f"알 수 없는 type 값: {unknown}")
    return _frame(raw[cols["url"]], lab, "malicious_urls", collected_at)


def load_phiusiil(path, collected_at):
    """UCI PhiUSIIL (컬럼 URL, label: 1=정상, 0=피싱). 나머지 특징 컬럼은 버린다."""
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = {c.lower().strip(): c for c in raw.columns}
    if "url" not in cols or "label" not in cols:
        raise ValueError(f"예상한 컬럼(URL, label)이 없습니다: {list(raw.columns)}")
    lab = raw[cols["label"]].str.strip().map({"1": "benign", "0": "phishing"})
    if lab.isna().any():
        bad = raw.loc[lab.isna(), cols["label"]].unique()[:5]
        raise ValueError(f"label 값이 0/1이 아닙니다: {bad}")
    return _frame(raw[cols["url"]], lab, "phiusiil", collected_at)


def load_urlhaus(path, collected_at):
    """URLhaus CSV 덤프(주석 줄 '#'). url 컬럼은 'http'로 시작하는 값이 가장 많은 열로 찾는다."""
    raw = pd.read_csv(path, comment="#", header=None, dtype=str, keep_default_na=False,
                      quotechar='"', skipinitialspace=True, on_bad_lines="skip")
    best = max(raw.columns, key=lambda c: raw[c].str.lower().str.startswith("http").mean())
    return _frame(raw[best], ["malware"] * len(raw), "urlhaus", collected_at)


def load_url_lines(path, label, source, collected_at):
    """한 줄에 URL 하나인 텍스트(OpenPhish feed.txt 등)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return _frame(lines, [label] * len(lines), source, collected_at)


def load_phishtank(path, collected_at):
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = {c.lower().strip(): c for c in raw.columns}
    return _frame(raw[cols["url"]], ["phishing"] * len(raw), "phishtank", collected_at)


def load_tranco(path, collected_at, top_n=100_000, sample_n=10_000, seed=42):
    """Tranco top-1m.csv (rank,domain, 헤더 없음). 상위 top_n 중 sample_n개를 https://<domain>/ 으로."""
    raw = pd.read_csv(path, header=None, names=["rank", "domain"], dtype=str, keep_default_na=False)
    raw = raw[raw["rank"].str.isdigit()]
    raw = raw[raw["rank"].astype(int) <= top_n]
    if sample_n and len(raw) > sample_n:
        raw = raw.sample(n=sample_n, random_state=seed)
    return _frame("https://" + raw["domain"].str.strip() + "/", ["benign"] * len(raw), "tranco", collected_at)


# ---------------------------------------------------------------- 정제
def clean(df):
    """정제 규칙(설계 2.2절). 반환: (정제된 df + group_key, 단계별 리포트 dict)."""
    rep = {"input": int(len(df))}
    d = df.copy()
    d["url"] = d["url"].astype(str).str.strip()
    d = d[d["url"] != ""]
    rep["after_empty"] = int(len(d))

    statuses = d["url"].map(U.check_url)
    ok = statuses.map(lambda t: t[0] == "ok")
    rep["dropped_invalid_or_unsupported"] = int((~ok).sum())
    d = d[ok].copy()
    d["host"] = statuses[ok].map(lambda t: t[1])

    before = len(d)
    d = d.drop_duplicates(subset=["url", "label"])
    rep["dropped_exact_duplicates"] = int(before - len(d))

    d["_lk"] = d["url"].map(U.loose_key)
    nlab = d.groupby("_lk")["label"].nunique()
    conflict_keys = set(nlab[nlab > 1].index)
    conflict = d["_lk"].isin(conflict_keys)
    rep["dropped_label_conflicts"] = int(conflict.sum())
    rep["conflict_keys"] = int(len(conflict_keys))
    d = d[~conflict]

    uniq = {h: U.registered_domain(h) for h in d["host"].unique()}
    d["group_key"] = d["host"].map(uniq)
    d = d.drop(columns=["_lk", "host"]).reset_index(drop=True)
    rep["output"] = int(len(d))
    rep["label_counts"] = {k: int(v) for k, v in d["label"].value_counts().items()}
    return d, rep


def scheme_profile(df):
    """클래스별 scheme 분포(%) 표. 열: https, http, none, other, www_start."""
    kinds = df["url"].map(U.scheme_kind)
    www = df["url"].map(lambda u: bool(re.match(r"^(https?://)?www\.", u.strip(), re.IGNORECASE)))
    t = pd.crosstab(df["label"], kinds, normalize="index") * 100
    for c in ("https", "http", "none", "other"):
        if c not in t.columns:
            t[c] = 0.0
    t = t[["https", "http", "none", "other"]]
    t["www_start"] = www.groupby(df["label"]).mean() * 100
    return t.round(2)


def remove_groups(df, groups):
    """groups에 속한 group_key 행을 제거. 반환: (df, 제거 건수)"""
    mask = df["group_key"].isin(set(groups))
    return df[~mask].reset_index(drop=True), int(mask.sum())


def build_external(frames, train_groups):
    """외부 최신 평가 세트(개정 1). frames: 출처별 df 리스트(정제 전).

    - 각 출처를 정제하고, 학습 데이터(Malicious URLs)에 나온 그룹 키를 제거
    - Tranco(benign) 중 악성 피드에 나온 그룹 키를 제거
    반환: (df, 리포트)
    """
    rep = {}
    cleaned = []
    for f in frames:
        src = f["source"].iloc[0] if len(f) else "empty"
        c, r = clean(f)
        c, removed = remove_groups(c, train_groups)
        r["removed_train_overlap"] = removed
        rep[src] = r
        cleaned.append(c)
    ext = pd.concat(cleaned, ignore_index=True) if cleaned else pd.DataFrame(columns=SCHEMA + ["group_key"])
    mal_groups = set(ext.loc[ext["label"] != "benign", "group_key"])
    is_tr = (ext["source"] == "tranco") & ext["group_key"].isin(mal_groups)
    if "tranco" in rep:
        rep["tranco"]["removed_feed_overlap"] = int(is_tr.sum())
    ext = ext[~is_tr].reset_index(drop=True)
    for src, n in ext["source"].value_counts().items():
        rep[src]["final"] = int(n)
    return ext, rep


def describe(df):
    return {"rows": int(len(df)), "groups": int(df["group_key"].nunique()),
            "label_counts": {k: int(v) for k, v in df["label"].value_counts().items()}}
