import json
import os
import sys
import tempfile
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qsing_model.head import NumpyHead, head_spec, save_head, softmax  # noqa: E402
from qsing_model.infer import UrlRiskClassifier, ModelError, RESULT_KEYS  # noqa: E402

try:
    import torch  # noqa: F401
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


def fake_embed(texts):
    """문자열에 'evil'이 있으면 악성 쪽 벡터. 256차원."""
    X = np.zeros((len(texts), 256), dtype=np.float32)
    for i, t in enumerate(texts):
        X[i, 0] = 1.0 if "evil" in t else 0.0
        X[i, 1] = 1.0
    return X, np.array([len(t) > 50 for t in texts])


def fake_head():
    # logits = X @ W.T + b ; 'evil'이면 phishing 로짓이 커진다
    W = np.zeros((4, 256))
    W[1, 0] = 8.0
    b = np.array([2.0, 0.0, -1.0, -1.0])
    return NumpyHead(head_spec("linear"), {"0_weight": W, "0_bias": b})


CFG = {"normalization": "strip", "model_version": "test@0000+head-2026-11-10"}
THR = {"t_low": 0.3, "t_high": 0.8}


class TestNumpyHead(unittest.TestCase):
    def test_linear_and_mlp(self):
        rng = np.random.default_rng(0)
        X = rng.normal(size=(5, 256))
        lin = NumpyHead(head_spec("linear"), {"0_weight": rng.normal(size=(4, 256)), "0_bias": rng.normal(size=4)})
        p = lin.probs(X)
        self.assertEqual(p.shape, (5, 4))
        np.testing.assert_allclose(p.sum(1), 1.0)
        w = {"0_weight": rng.normal(size=(128, 256)), "0_bias": rng.normal(size=128),
             "3_weight": rng.normal(size=(4, 128)), "3_bias": rng.normal(size=4)}
        mlp = NumpyHead(head_spec("mlp"), w)
        # GELU(erf) 손계산과 비교
        import math
        h = X @ w["0_weight"].T + w["0_bias"]
        g = 0.5 * h * (1 + np.vectorize(math.erf)(h / math.sqrt(2)))
        np.testing.assert_allclose(mlp.logits(X), g @ w["3_weight"].T + w["3_bias"], rtol=1e-10)
        with self.assertRaises(ValueError):
            NumpyHead(head_spec("mlp"), {"0_weight": w["0_weight"], "0_bias": w["0_bias"]})

    def test_save_load_no_pickle(self):
        rng = np.random.default_rng(1)
        w = {"0_weight": rng.normal(size=(4, 256)), "0_bias": rng.normal(size=4)}
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "head.npz")
            save_head(p, w)
            h = NumpyHead.load(p, head_spec("linear"))
            np.testing.assert_allclose(h.logits(np.ones((1, 256))), np.ones((1, 256)) @ w["0_weight"].T + w["0_bias"])

    def test_softmax_stable(self):
        p = softmax(np.array([[1000.0, 0.0, 0.0, 0.0]]))
        self.assertTrue(np.all(np.isfinite(p)))

    @unittest.skipUnless(HAS_TORCH, "torch 없음")
    def test_matches_torch(self):
        import torch
        from qsing_model.head import build_torch_head, torch_head_to_numpy
        torch.manual_seed(0)
        m = build_torch_head("mlp").eval()
        X = np.random.default_rng(2).normal(size=(7, 256)).astype(np.float32)
        with torch.no_grad():
            ref = torch.softmax(m(torch.from_numpy(X)), 1).numpy()
        got = NumpyHead(head_spec("mlp"), torch_head_to_numpy(m)).probs(X)
        np.testing.assert_allclose(got, ref, atol=1e-5)


class TestInfer(unittest.TestCase):
    def setUp(self):
        self.clf = UrlRiskClassifier(fake_embed, fake_head(), CFG, THR)

    def test_ok_result_shape(self):
        r = self.clf.predict("http://www.evil-login.com/verify?id=1")
        self.assertEqual(set(r.keys()), set(RESULT_KEYS))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["predicted_type"], "phishing")
        self.assertEqual(r["risk_level"], "danger")
        self.assertAlmostEqual(sum(r["scores"].values()), 1.0)
        self.assertAlmostEqual(r["ai_risk_score"], 1 - r["scores"]["benign"])
        self.assertEqual(r["signals"]["subdomain_depth"], 1)
        self.assertEqual(r["model_version"], CFG["model_version"])

    def test_benign_is_low(self):
        r = self.clf.predict("https://naver.com/")
        self.assertEqual(r["predicted_type"], "benign")
        self.assertEqual(r["risk_level"], "low")

    def test_not_scored_never_low(self):
        for u, st in [("", "invalid_url"), (None, "invalid_url"), (42, "invalid_url"), ("nodot", "invalid_url"),
                      ("javascript:alert(1)", "unsupported_scheme"), ("intent://x#Intent;end", "unsupported_scheme"),
                      ("tel:01012345678", "unsupported_scheme"), ("ftp://a.com/f", "unsupported_scheme")]:
            r = self.clf.predict(u)
            self.assertEqual(r["status"], st, u)
            self.assertIsNone(r["risk_level"], u)
            self.assertIsNone(r["scores"], u)
            self.assertEqual(set(r.keys()), set(RESULT_KEYS))

    def test_truncated(self):
        r = self.clf.predict("http://a.com/" + "x" * 3000)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["status"], "ok")

    def test_strip_normalization_applied(self):
        seen = []

        def spy(texts):
            seen.extend(texts)
            return fake_embed(texts)
        UrlRiskClassifier(spy, fake_head(), CFG, THR).predict("HTTPS://WWW.Example.com/Path")
        self.assertEqual(seen, ["Example.com/Path"])

    def test_batch_order_mixed(self):
        rs = self.clf.predict_batch(["https://a.com", "javascript:x", "http://evil.com"])
        self.assertEqual([r["status"] for r in rs], ["ok", "unsupported_scheme", "ok"])
        self.assertEqual(rs[2]["predicted_type"], "phishing")

    def test_model_error(self):
        def broken(texts):
            raise RuntimeError("boom")
        clf = UrlRiskClassifier(broken, fake_head(), CFG, THR)
        with self.assertRaises(ModelError):
            clf.predict("http://a.com")

    def test_json_serializable(self):
        json.dumps(self.clf.predict_batch(["http://evil.com", ""]))


if __name__ == "__main__":
    unittest.main()
