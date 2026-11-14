import os
import sys
import tempfile
import unittest

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qsing_model import augment as A  # noqa: E402


class TestAugment(unittest.TestCase):
    def test_is_homepage(self):
        self.assertTrue(A.is_homepage("naver.com"))
        self.assertTrue(A.is_homepage("https://www.naver.com/"))
        self.assertFalse(A.is_homepage("naver.com/news"))
        self.assertFalse(A.is_homepage("naver.com/?q=1"))
        self.assertFalse(A.is_homepage("naver.com#top"))

    def test_path_profile(self):
        df = pd.DataFrame({"url": ["a.com", "b.com/x", "evil.com", "evil2.com/"], "label": ["benign", "benign", "phishing", "phishing"]})
        p = A.path_profile(df)
        self.assertAlmostEqual(p.loc["benign", "homepage_pct"], 50.0)
        self.assertAlmostEqual(p.loc["phishing", "homepage_pct"], 100.0)

    def test_homepage_rows(self):
        d = pd.DataFrame([
            ("en.wikipedia.org/wiki/A", "benign", "train", "wikipedia.org"),
            ("en.wikipedia.org/wiki/B", "benign", "train", "wikipedia.org"),
            ("good.com/page", "benign", "val", "good.com"),
            ("hacked.com/about", "benign", "test", "hacked.com"),
            ("http://hacked.com/index.php?option=com", "defacement", "test", "hacked.com"),  # 악성에 나온 호스트 → 제외
            ("already.com/x", "benign", "train", "already.com"),
            ("https://already.com/", "benign", "train", "already.com"),                     # 이미 있음 → 추가 안 함
        ], columns=["url", "label", "split", "group_key"])
        out = A.homepage_rows(d)
        self.assertEqual(sorted(out["url"]), ["https://en.wikipedia.org/", "https://good.com/"])
        self.assertEqual(dict(zip(out["url"], out["split"])), {"https://en.wikipedia.org/": "train", "https://good.com/": "val"})
        self.assertTrue((out["label"] == "benign").all())


class TestRunV3Rehearsal(unittest.TestCase):
    def test_flow(self):
        from test_pipeline_rehearsal import FakeEmbedder, fake_train_head, make_inputs
        import qsing_model.embed as E
        import qsing_model.train as T
        import qsing_model.pipeline as P
        saved = (E.Embedder, T.train_head, P.torch_head_to_numpy)
        E.Embedder, T.train_head, P.torch_head_to_numpy = FakeEmbedder, fake_train_head, (lambda m: m.w)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = P.Config(out_dir=os.path.join(tmp, "out"), revision="0123456789abcdef", normalizations=("strip",),
                               tranco_sample_n=50, latency_n=5, throughput_n=20, **make_inputs(tmp))
                md = A.run_v3(cfg, P, zip_path=os.path.join(tmp, "artifacts_zip"))
                m = P._jload(cfg.path("reports", "metrics.json"))
                self.assertIn("test_homepage", m)
                self.assertIn("path_profile", m)
                self.assertGreater(m["augment"]["train"], 0)
                sel = P._jload(cfg.path("reports", "p4_selection.json"))
                self.assertIn("home", sel["val_macro_f1_variants"])
                self.assertIn("P5 test", md)
                self.assertTrue(os.path.exists(os.path.join(cfg.out_dir, "artifacts", "head.npz")))
        finally:
            E.Embedder, T.train_head, P.torch_head_to_numpy = saved


if __name__ == "__main__":
    unittest.main()
