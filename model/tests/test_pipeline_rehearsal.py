"""파이프라인 리허설: torch/transformers 없이 가짜 임베더·가짜 학습기로 P1→P2→P4→P6→P5→P7 흐름을 점검한다.

실제 모델 계산은 Kaggle에서 확인한다. 여기서는 파일 입출력, 페이즈 간 연결, 지표·임계값·내보내기 형식을 본다.
"""

import hashlib
import json
import os
import sys
import tempfile
import types
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import sklearn  # noqa: F401
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class FakeEmbedder:
    """문자 3-gram 해시 특징 256차원 (결정적)."""

    def __init__(self, source=None, revision=None, device=None, fp16=None, max_tokens=256, num_threads=None):
        self.device, self.fp16, self.dim, self.last_seconds = "cpu", False, 256, 0.0

    def save(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "config.json"), "w") as f:
            f.write("{}")

    def encode(self, texts, batch_size=512, out_dtype=np.float16, progress=False):
        X = np.zeros((len(texts), 256), dtype=np.float32)
        for i, t in enumerate(texts):
            t = str(t)
            for j in range(len(t) - 2):
                h = int(hashlib.md5(t[j:j + 3].encode()).hexdigest()[:6], 16) % 256
                X[i, h] += 1.0
            X[i] /= max(1.0, np.linalg.norm(X[i]))
        return X.astype(out_dtype), np.array([len(str(t)) > 200 for t in texts])


class FakeModel:
    def __init__(self, w):
        self.w = w


def fake_train_head(X_train, y_train, X_val, y_val, kind, seed=42, lr=1e-3, weight_decay=0.01, batch_size=2048,
                    max_epochs=30, patience=3, device=None, log=print):
    from qsing_model.metrics import four_class_metrics
    from qsing_model.head import _gelu
    rng = np.random.default_rng(seed)

    def fit(F, y):
        Y = np.eye(4)[y]
        W = rng.normal(scale=0.01, size=(4, F.shape[1]))
        b = np.zeros(4)
        for _ in range(300):
            Z = F @ W.T + b
            P = np.exp(Z - Z.max(1, keepdims=True))
            P /= P.sum(1, keepdims=True)
            G = (P - Y) / len(F)
            W -= 5.0 * G.T @ F
            b -= 5.0 * G.sum(0)
        return W, b

    X = np.asarray(X_train, dtype=np.float64)
    Xv = np.asarray(X_val, dtype=np.float64)
    if kind == "mlp":
        W0 = rng.normal(scale=0.5, size=(128, X.shape[1]))
        b0 = np.zeros(128)
        W3, b3 = fit(_gelu(X @ W0.T + b0), y_train)
        w = {"0_weight": W0, "0_bias": b0, "3_weight": W3, "3_bias": b3}
        pred = (_gelu(Xv @ W0.T + b0) @ W3.T + b3).argmax(1)
    else:
        W, b = fit(X, y_train)
        w = {"0_weight": W, "0_bias": b}
        pred = (Xv @ W.T + b).argmax(1)
    f1 = four_class_metrics(y_val, pred)["macro_f1"]
    return FakeModel(w), {"kind": kind, "seed": seed, "best_val_macro_f1": f1,
                          "best_epoch": 1, "epochs_run": 1, "seconds": 0.0, "history": []}


def make_inputs(tmp, n_groups=500):
    rng = np.random.default_rng(0)
    rows = []
    words = {"benign": ["news", "shop", "blog", "docs"], "phishing": ["login", "verify", "account", "secure"],
             "malware": ["bins", "x86", "payload", "mozi"], "defacement": ["index.php?option=com", "itemid", "view=article"]}
    labels = ["benign"] * 6 + ["phishing", "phishing", "malware", "defacement"]
    for g in range(n_groups):
        lab = labels[g % len(labels)]
        for j in range(1 + g % 4):
            w = words[lab][(g + j) % len(words[lab])]
            prefix = "" if lab == "benign" else "http://"
            rows.append((f"{prefix}sub{j}.site{g}.com/{w}/{j}", lab))
    rows += [("javascript:alert(1)", "malware"), ("", "benign")]
    mal = os.path.join(tmp, "malicious_phish.csv")
    pd.DataFrame(rows, columns=["url", "type"]).to_csv(mal, index=False)

    phi = os.path.join(tmp, "PhiUSIIL_Phishing_URL_Dataset.csv")
    pd.DataFrame({"URL": [f"https://www.good{i}.org/news" for i in range(60)] + [f"http://verify{i}.xyz/login" for i in range(60)]
                  + ["http://site1.com/x"], "label": [1] * 60 + [0] * 60 + [1]}).to_csv(phi, index=False)

    uh = os.path.join(tmp, "csv.txt")
    with open(uh, "w") as f:
        f.write("# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n")
        for i in range(40):
            f.write(f'"{i}","2026-11-01","http://10.0.{i}.1/bins/payload","online","","malware_download","elf","x","r"\n')
    op = os.path.join(tmp, "feed.txt")
    with open(op, "w") as f:
        f.write("\n".join(f"https://account-verify{i}.top/login" for i in range(40)))
    tr = os.path.join(tmp, "top-1m.csv")
    with open(tr, "w") as f:
        f.write("\n".join(f"{i + 1},popular{i}.com" for i in range(100)))
    return dict(malicious_urls_csv=mal, phiusiil_csv=phi, urlhaus_csv=uh, openphish_txts=[op], tranco_csv=tr)


@unittest.skipUnless(HAS_SKLEARN, "scikit-learn 없음")
class TestRehearsal(unittest.TestCase):
    def test_full_flow(self):
        import qsing_model.embed as E
        import qsing_model.train as T
        import qsing_model.pipeline as P
        saved = (E.Embedder, T.train_head, P.torch_head_to_numpy)
        E.Embedder = FakeEmbedder
        T.train_head = fake_train_head
        P.torch_head_to_numpy = lambda m: m.w
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = P.Config(out_dir=os.path.join(tmp, "out"), revision="0123456789abcdef", ratio_tolerance_pp=6.0,
                               tranco_sample_n=50, latency_n=5, throughput_n=20, **make_inputs(tmp))
                r1 = P.p1_prepare(cfg)
                mu = r1["malicious_urls"]
                self.assertEqual(mu["input"] - mu["after_empty"], 1)          # 빈 값
                self.assertEqual(mu["dropped_invalid_or_unsupported"], 1)    # javascript:
                self.assertEqual(r1["phiusiil"]["removed_train_overlap"], 1)
                self.assertEqual(set(r1["external"]), {"urlhaus", "openphish", "tranco"})
                r2 = P.p2_split(cfg)
                self.assertEqual(sum(r2["group_overlaps"].values()), 0)
                b = P.p3_baseline(cfg)  # 여기서는 torch/원격 헤드가 없어 실패 → 기록만 남기고 진행해야 한다
                if b.get("failed"):
                    self.assertTrue(os.path.exists(cfg.path("reports", "p3_baseline_failed.json")))
                P.p4_embed(cfg)
                sel = P.p4_train(cfg)
                # 가짜 데이터는 정상 URL에만 scheme이 없어 raw가 scheme 지름길을 배운다 → 최저값 기준으로 strip이 뽑혀야 한다
                self.assertEqual(sel["normalization"], "strip")
                self.assertIn("https", sel["val_macro_f1_variants"])
                self.assertEqual(len(sel["seeds"]), 3)
                thr = P.p6_thresholds(cfg)
                self.assertLessEqual(thr["t_low"], thr["t_high"])
                m = P.p5_evaluate(cfg)
                for k in ("accuracy", "per_class", "macro_f1", "confusion_matrix", "benign_fpr", "malicious_fnr"):
                    self.assertIn(k, m["test"])
                self.assertIn("threshold", m["test"]["benign_fpr"])
                self.assertEqual(set(m["phiusiil"]), {"raw", "strip"})
                self.assertEqual(set(m["external"]), {"urlhaus", "openphish", "tranco"})
                self.assertGreater(m["test"]["macro_f1"], 0.5)
                self.assertIn("test_scheme_variants", m)
                ex = P.p7_export(cfg, zip_path=os.path.join(tmp, "artifacts_zip"))
                art = ex["artifacts_dir"]
                for f in ("head.npz", "model_config.json", "thresholds.json", "metrics.json", "encoder/config.json"):
                    self.assertTrue(os.path.exists(os.path.join(art, f)), f)
                self.assertEqual(ex["parity"]["argmax_agreement"], 1.0)
                with open(os.path.join(art, "metrics.json")) as f:
                    self.assertIn("latency", json.load(f))
                self.assertTrue(os.path.exists(ex["zip"]))
                md = P.run_summary_md(cfg)
                self.assertIn("P5 test", md)
                # 서버 쪽 사용법 그대로
                from qsing_model.infer import UrlRiskClassifier
                clf = UrlRiskClassifier.from_artifacts(art)
                r = clf.predict("http://sub0.site9.com/login/0")
                self.assertEqual(r["status"], "ok")
                self.assertIn(r["risk_level"], ("low", "caution", "danger"))
                self.assertIsNone(clf.predict("javascript:alert(1)")["risk_level"])
        finally:
            E.Embedder, T.train_head, P.torch_head_to_numpy = saved


if __name__ == "__main__":
    unittest.main()
