import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qsing_model import metrics as M  # noqa: E402
from qsing_model import risk as R  # noqa: E402

# 라벨 id: 0 benign, 1 phishing, 2 malware, 3 defacement


class TestFourClass(unittest.TestCase):
    def setUp(self):
        #           b  b  b  b  p  p  m  d
        self.yt = [0, 0, 0, 0, 1, 1, 2, 3]
        self.yp = [0, 0, 1, 0, 1, 0, 2, 2]

    def test_hand_computed(self):
        m = M.four_class_metrics(self.yt, self.yp)
        self.assertAlmostEqual(m["accuracy"], 5 / 8)
        cm = np.array(m["confusion_matrix"]["matrix"])
        self.assertEqual(cm[0].tolist(), [3, 1, 0, 0])
        self.assertEqual(cm[1].tolist(), [1, 1, 0, 0])
        self.assertEqual(cm[3].tolist(), [0, 0, 1, 0])
        pc = m["per_class"]
        self.assertAlmostEqual(pc["benign"]["precision"], 3 / 4)
        self.assertAlmostEqual(pc["benign"]["recall"], 3 / 4)
        self.assertAlmostEqual(pc["phishing"]["precision"], 1 / 2)
        self.assertAlmostEqual(pc["phishing"]["recall"], 1 / 2)
        self.assertAlmostEqual(pc["malware"]["precision"], 1 / 2)
        self.assertAlmostEqual(pc["malware"]["recall"], 1.0)
        self.assertAlmostEqual(pc["malware"]["f1"], 2 / 3)
        self.assertEqual(pc["defacement"]["f1"], 0.0)
        self.assertEqual(pc["defacement"]["support"], 1)
        self.assertAlmostEqual(m["macro_f1"], (0.75 + 0.5 + 2 / 3 + 0) / 4)
        # 정상 4개 중 1개가 악성으로 판정 / 악성 4개 중 1개가 정상으로 판정
        self.assertAlmostEqual(m["benign_fpr"]["argmax"], 1 / 4)
        self.assertAlmostEqual(m["malicious_fnr"]["argmax"], 1 / 4)

    def test_threshold_decision(self):
        flagged = np.array([0, 0, 0, 0, 1, 1, 1, 0], dtype=bool)
        m = M.four_class_metrics(self.yt, self.yp, flagged_by_threshold=flagged)
        self.assertEqual(m["benign_fpr"]["threshold"], 0.0)
        self.assertAlmostEqual(m["malicious_fnr"]["threshold"], 1 / 4)

    def test_missing_key_raises(self):
        m = M.four_class_metrics(self.yt, self.yp)
        del m["macro_f1"]
        with self.assertRaises(M.MissingMetricError):
            M.validate_required(m)
        m = M.four_class_metrics(self.yt, self.yp)
        del m["per_class"]["malware"]["recall"]
        with self.assertRaises(M.MissingMetricError):
            M.validate_required(m)


class TestOtherMetrics(unittest.TestCase):
    def test_auroc(self):
        self.assertAlmostEqual(M.auroc([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8]), 0.75)
        self.assertAlmostEqual(M.auroc([0, 1], [0.5, 0.5]), 0.5)
        self.assertTrue(np.isnan(M.auroc([1, 1], [0.1, 0.2])))

    def test_wilson(self):
        lo, hi = M.wilson_ci(50, 100)
        self.assertAlmostEqual(lo, 0.4038, places=3)
        self.assertAlmostEqual(hi, 0.5962, places=3)
        lo, hi = M.wilson_ci(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.2775, places=3)

    def test_external(self):
        src = ["urlhaus"] * 4 + ["tranco"] * 2
        yt = [2, 2, 2, 2, 0, 0]
        yp = [2, 1, 0, 2, 0, 1]
        out = M.external_metrics(src, yt, yp)
        self.assertAlmostEqual(out["urlhaus"]["malicious_fnr"]["argmax"]["value"], 1 / 4)
        self.assertAlmostEqual(out["urlhaus"]["type_match_rate"]["value"], 2 / 4)
        self.assertAlmostEqual(out["tranco"]["benign_fpr"]["argmax"]["value"], 1 / 2)
        self.assertNotIn("macro_f1", out["urlhaus"])

    def test_binary(self):
        out = M.binary_metrics([0, 0, 1, 1], [0.1, 0.6, 0.7, 0.2], [False, True, True, False])
        self.assertAlmostEqual(out["benign_fpr"]["argmax"], 0.5)
        self.assertAlmostEqual(out["malicious_fnr"]["argmax"], 0.5)
        self.assertAlmostEqual(out["auroc"], 0.75)


class TestRisk(unittest.TestCase):
    def test_overlap_targets(self):
        rng = np.random.default_rng(0)
        b = rng.beta(2, 8, 2000)   # 정상: 낮은 점수, 악성과 겹침
        m = rng.beta(8, 2, 2000)   # 악성: 높은 점수
        risk = np.concatenate([b, m])
        y = np.array([0] * 2000 + [1] * 2000)
        t = R.choose_thresholds(risk, y)
        self.assertEqual(t["status"], "overlap")
        self.assertLess(t["t_low"], t["t_high"])
        self.assertLessEqual((b >= t["t_high"]).mean(), 0.01)
        self.assertGreaterEqual((m >= t["t_low"]).mean(), 0.99)
        # t_high는 가장 작은 값: 21번째로 큰 정상 점수까지 내리면 1%를 넘는다
        self.assertGreater((b >= np.sort(b)[len(b) - 21]).mean(), 0.01)
        # t_low는 가장 큰 값: 조금만 올려도 99% 아래로 떨어진다
        self.assertLess((m >= np.nextafter(t["t_low"], 1)).mean(), 0.99)

    def test_separated(self):
        rng = np.random.default_rng(1)
        b = rng.beta(1, 30, 1000)
        m = rng.beta(30, 1, 1000)
        t = R.choose_thresholds(np.concatenate([b, m]), np.array([0] * 1000 + [2] * 1000))
        self.assertEqual(t["status"], "separated")
        self.assertEqual(t["t_low"], t["t_high"])
        self.assertGreaterEqual(t["t_low_raw"], t["t_high"])
        self.assertLessEqual(t["achieved_on_val"]["benign_in_danger"], 0.01)
        self.assertGreaterEqual(t["achieved_on_val"]["malicious_caution_or_above"], 0.99)

    def test_needs_both_classes(self):
        with self.assertRaises(ValueError):
            R.choose_thresholds([0.1, 0.2], [0, 0])

    def test_levels(self):
        self.assertEqual(R.risk_level(0.1, 0.2, 0.8), "low")
        self.assertEqual(R.risk_level(0.2, 0.2, 0.8), "caution")
        self.assertEqual(R.risk_level(0.8, 0.2, 0.8), "danger")
        self.assertAlmostEqual(float(R.risk_score([0.3, 0.5, 0.1, 0.1])), 0.7)


if __name__ == "__main__":
    unittest.main()
