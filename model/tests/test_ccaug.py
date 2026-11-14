import os
import sys
import tempfile
import unittest

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qsing_model import ccaug as C  # noqa: E402


def _d():
    return pd.DataFrame([
        ("site-a.com/x", "benign", "train", "site-a.com"),
        ("val-site.com/y", "benign", "val", "val-site.com"),
        ("test-site.com/z", "benign", "test", "test-site.com"),
        ("http://evil.com/login", "phishing", "train", "evil.com"),
        ("shared.com/ok", "benign", "train", "shared.com"),
        ("http://bad.shared.com/x", "phishing", "train", "shared.com"),
    ], columns=["url", "label", "split", "group_key"])


def _jp():
    ben = ["https://new1.org/a", "https://new1.org/b", "https://new1.org/c", "https://new1.org/d",
           "https://val-site.com/page",          # val 도메인 → 제외
           "https://www.test-site.com/other",    # test 도메인 → 제외
           "https://phi-eval.org/",              # 외부 평가 도메인 → 제외
           "https://bad.shared.com/page",        # 악성에 나온 호스트 → 제외
           "https://good.shared.com/page",       # 같은 도메인이지만 다른 호스트, train 도메인 → 유지
           "http://www.site-a.com/x",            # 이미 있는 URL → 제외
           "https://jpbad.com/fine"]             # JP 악성에 나온 호스트 → 제외
    ben += [f"https://fresh{i}.net/page/{i}" for i in range(40)]
    mal = ["http://jpbad.com/steal", "http://evil.com/again"] + [f"http://fresh-mal{i}.top/login" for i in range(6)]
    return pd.DataFrame({"url": ben + mal, "label": ["benign"] * len(ben) + ["malicious"] * len(mal)})


class TestCcRows(unittest.TestCase):
    def setUp(self):
        aug = pd.DataFrame(columns=["url", "label", "source", "split", "group_key"])
        self.out, self.rep = C.cc_rows(_d(), aug, _jp(), {"phi-eval.org"}, "2026-11-13", n_train=1000, n_hold=6)

    def test_train_filters(self):
        tr = self.out[self.out["split"] == "train"]
        urls = set(tr["url"])
        self.assertTrue((tr["label"] == "benign").all())
        self.assertTrue((tr["source"] == "cc_benign").all())
        for bad in ("https://val-site.com/page", "https://www.test-site.com/other", "https://phi-eval.org/",
                    "https://bad.shared.com/page", "http://www.site-a.com/x", "https://jpbad.com/fine"):
            self.assertNotIn(bad, urls)
        self.assertIn("https://good.shared.com/page", urls)
        self.assertLessEqual(tr.groupby("group_key").size().max(), 3)
        self.assertEqual(int(tr["url"].str.contains("new1.org").sum()) +
                         int(self.out.loc[self.out["split"] == "holdout", "url"].str.contains("new1.org").sum()), 3)

    def test_holdout_is_unseen(self):
        tr = self.out[self.out["split"] == "train"]
        ho = self.out[self.out["split"] == "holdout"]
        self.assertGreater(len(ho[ho["source"] == "cc_benign_holdout"]), 0)
        self.assertFalse(set(ho["group_key"]) & set(tr["group_key"]))
        self.assertFalse(set(ho["group_key"]) & set(_d()["group_key"]))
        m = ho[ho["source"] == "jp_malicious_holdout"]
        # evil.com은 Malicious URLs에 있는 도메인이라 제외, jpbad.com은 처음 보는 도메인이라 포함
        self.assertEqual(len(m), 6)   # n_hold=6으로 제한
        self.assertTrue(set(m["group_key"]) <= set([f"fresh-mal{i}.top" for i in range(6)] + ["jpbad.com"]))
        self.assertNotIn("evil.com", set(m["group_key"]))
        self.assertTrue((m["label"] == "phishing").all())

    def test_report(self):
        s = self.rep["steps"]
        self.assertGreater(s["benign_after_clean"], s["after_drop_valtest_domains"])
        self.assertGreater(s["after_drop_valtest_domains"], s["after_drop_external_eval_domains"])
        self.assertEqual(self.rep["train"]["rows"], int((self.out["split"] == "train").sum()))


class TestLoadJp(unittest.TestCase):
    def test_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "jp.csv")
            pd.DataFrame({"url": [f"a{i}.com" for i in range(10)], "label": [0] * 9 + [1], "fold": 0}).to_csv(p, index=False)
            self.assertEqual(C.load_jp(p)["label"].value_counts().to_dict(), {"benign": 9, "malicious": 1})
            pd.DataFrame({"url": [f"a{i}.com" for i in range(10)], "label": [1] * 9 + [0]}).to_csv(p, index=False)
            with self.assertRaises(ValueError):   # 0/1 해석이 뒤집혀 보이면 중단
                C.load_jp(p)
            pd.DataFrame({"url": ["a.com", "b.com"], "label": ["benign", "weird"]}).to_csv(p, index=False)
            with self.assertRaises(ValueError):
                C.load_jp(p)


class TestRunV5Rehearsal(unittest.TestCase):
    def test_flow(self):
        from test_pipeline_rehearsal import FakeEmbedder, fake_train_head, make_inputs
        import qsing_model.embed as E
        import qsing_model.train as T
        import qsing_model.pipeline as P
        saved = (E.Embedder, T.train_head, P.torch_head_to_numpy)
        E.Embedder, T.train_head, P.torch_head_to_numpy = FakeEmbedder, fake_train_head, (lambda m: m.w)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                jp = os.path.join(tmp, "jp.csv")
                ben = [f"https://cc{i}.net/{w}/{j}" for i in range(150) for j, w in enumerate(("news", "docs"))]
                ben += ["https://www.good1.org/about", "https://popular3.com/x", "sub0.site7.com/extra"]
                mal = [f"http://jpmal{i}.top/login" for i in range(30)]
                pd.DataFrame({"url": ben + mal, "label": ["benign"] * len(ben) + ["malicious"] * len(mal)}).to_csv(jp, index=False)
                cfg = P.Config(out_dir=os.path.join(tmp, "out"), revision="0123456789abcdef", normalizations=("strip2",),
                               tranco_sample_n=50, latency_n=5, throughput_n=20, **make_inputs(tmp))
                md = C.run_v5(cfg, P, jp_path=jp, zip_path=os.path.join(tmp, "artifacts_zip"), n_train=120, n_hold=30)
                m = P._jload(cfg.path("reports", "metrics.json"))
                self.assertEqual(set(m["jp_holdout"]) - {"note"}, {"with_cc(v5)", "without_cc(v4 재현)"})
                self.assertGreater(m["jp_holdout"]["with_cc(v5)"]["n_benign"], 0)
                self.assertGreater(m["jp_holdout"]["with_cc(v5)"]["n_malicious"], 0)
                self.assertEqual(m["cc_augment"]["train"]["rows"], 120)
                self.assertEqual(m["augment"]["train_by_source"]["cc_benign"], 120)
                sel = P._jload(cfg.path("reports", "p4_selection.json"))
                self.assertIn("cc_benign", sel["training_data"])
                aug = P.load_df(cfg, "home_aug")
                ext_groups = set(P.load_df(cfg, "external")["group_key"]) | set(P.load_df(cfg, "phi_clean")["group_key"])
                d = P.load_df(cfg, "mal_split")
                tr = aug[(aug["split"] == "train") & (aug["source"] == "cc_benign")]
                self.assertFalse(set(tr["group_key"]) & ext_groups)
                self.assertFalse(set(tr["group_key"]) & set(d.loc[d["split"] != "train", "group_key"]))
                self.assertIn("v5 추가", md)
                self.assertTrue(os.path.exists(os.path.join(cfg.out_dir, "artifacts", "head.npz")))
                self.assertTrue(os.path.exists(cfg.path("heads", "strip2_nocc_" + sel["kind"] + "_s42.npz")))
        finally:
            E.Embedder, T.train_head, P.torch_head_to_numpy = saved


if __name__ == "__main__":
    unittest.main()
