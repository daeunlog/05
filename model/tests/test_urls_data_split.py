import os
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qsing_model import urls as U  # noqa: E402
from qsing_model import data as D  # noqa: E402
from qsing_model.labels import map_external_labels  # noqa: E402

try:
    import sklearn  # noqa: F401
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class TestSchemeAndHost(unittest.TestCase):
    def test_detect_scheme(self):
        self.assertEqual(U.detect_scheme("http://a.com/x"), ("http", "hierarchical"))
        self.assertEqual(U.detect_scheme("HTTPS://a.com"), ("https", "hierarchical"))
        self.assertEqual(U.detect_scheme("javascript:alert(1)"), ("javascript", "opaque"))
        self.assertEqual(U.detect_scheme("intent://scan/#Intent;end")[1], "hierarchical")
        self.assertEqual(U.detect_scheme("a.com:8080/x"), (None, "none"))
        self.assertEqual(U.detect_scheme("localhost:8080"), (None, "none"))
        self.assertEqual(U.detect_scheme("a.com/x"), (None, "none"))

    def test_parse_host(self):
        self.assertEqual(U.parse_host("http://Login.Example.COM:8080/a?b=1"), "login.example.com")
        self.assertEqual(U.parse_host("example.com/path"), "example.com")
        self.assertEqual(U.parse_host("http://user:pw@evil.com/x"), "evil.com")
        self.assertEqual(U.parse_host("http://192.168.0.1/a"), "192.168.0.1")
        self.assertEqual(U.parse_host("http://[2001:db8::1]/a"), "2001:db8::1")
        self.assertIsNone(U.parse_host(""))
        self.assertIsNone(U.parse_host("   "))
        self.assertIsNone(U.parse_host("nodot"))
        self.assertIsNone(U.parse_host(None))
        self.assertEqual(U.parse_host("example.com/a b c"), "example.com")

    def test_registered_domain(self):
        self.assertEqual(U.registered_domain("login.secure.example.co.kr"), "example.co.kr")
        self.assertEqual(U.registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(U.registered_domain("example.com"), "example.com")
        self.assertEqual(U.registered_domain("192.168.0.1"), "192.168.0.1")
        self.assertEqual(U.registered_domain("www.bbc.co.uk"), "bbc.co.uk")

    def test_check_url(self):
        self.assertEqual(U.check_url("http://a.com")[0], "ok")
        self.assertEqual(U.check_url("a.com")[0], "ok")
        self.assertEqual(U.check_url("")[0], "invalid_url")
        self.assertEqual(U.check_url(None)[0], "invalid_url")
        self.assertEqual(U.check_url(123)[0], "invalid_url")
        self.assertEqual(U.check_url("javascript:alert(1)")[0], "unsupported_scheme")
        self.assertEqual(U.check_url("tel:01012345678")[0], "unsupported_scheme")
        self.assertEqual(U.check_url("data:text/html,hi")[0], "unsupported_scheme")
        self.assertEqual(U.check_url("intent://scan/#Intent;end")[0], "unsupported_scheme")
        self.assertEqual(U.check_url("ftp://a.com/f")[0], "unsupported_scheme")
        self.assertEqual(U.check_url("http://")[0], "invalid_url")

    def test_normalize(self):
        self.assertEqual(U.normalize("  HTTPS://WWW.Example.com/A?B ", "strip"), "Example.com/A?B")
        self.assertEqual(U.normalize("www.a.com/x", "strip"), "a.com/x")
        self.assertEqual(U.normalize(" http://a.com ", "raw"), "http://a.com")
        self.assertEqual(U.normalize("https://www.A.com/", "strip2"), "A.com")
        self.assertEqual(U.normalize("a.com", "strip2"), "a.com")
        self.assertEqual(U.normalize("a.com/x/", "strip2"), "a.com/x/")
        self.assertEqual(U.normalize("a.com/?q=1", "strip2"), "a.com/?q=1")
        self.assertEqual(U.normalize("a.com:8080/", "strip2"), "a.com:8080")
        with self.assertRaises(ValueError):
            U.normalize("a.com", "nope")

    def test_scheme_variant(self):
        self.assertEqual(U.scheme_variant("http://www.a.com/x", "noscheme"), "www.a.com/x")
        self.assertEqual(U.scheme_variant("a.com/x", "https"), "https://a.com/x")
        self.assertEqual(U.scheme_variant("http://a.com/x", "https"), "http://a.com/x")
        # strip 정규화는 scheme 변형에 영향받지 않는다 (P4 변형 계산을 생략하는 근거)
        for u in ["http://www.A.com/P?q", "a.com/x", "https://b.co.kr", "www.c.com"]:
            for v in U.SCHEME_VARIANTS:
                for mode in ("strip", "strip2"):
                    self.assertEqual(U.normalize(U.scheme_variant(u, v), mode), U.normalize(u, mode))
        # strip2: 홈페이지 형식(끝 '/' 유무)이 같은 입력이 된다
        self.assertEqual(U.normalize("https://www.naver.com/", "strip2"), U.normalize("naver.com", "strip2"))

    def test_loose_key_keeps_path_case(self):
        self.assertEqual(U.loose_key("http://WWW.A.com/Path?Q=1"), "a.com/Path?Q=1")
        self.assertEqual(U.loose_key("a.com/Path?Q=1"), "a.com/Path?Q=1")

    def test_signals(self):
        s = U.signals("http://user@login.secure.example.com/x")
        self.assertTrue(s["has_at_symbol"])
        self.assertEqual(s["subdomain_depth"], 2)
        self.assertFalse(s["is_ip_host"])
        self.assertTrue(U.signals("http://10.0.0.1/a")["is_ip_host"])
        self.assertTrue(U.signals("https://bit.ly/abc")["is_known_shortener"])
        self.assertTrue(U.signals("http://xn--80ak6aa92e.com/")["has_punycode"])
        self.assertEqual(U.signals("a.com")["url_length"], 5)


class TestClean(unittest.TestCase):
    def _df(self, rows):
        return pd.DataFrame(rows, columns=["url", "label"]).assign(source="t", collected_at="2026-11-10")

    def test_clean_rules(self):
        df = self._df([
            ("http://a.com/x", "benign"),
            ("http://a.com/x", "benign"),          # 완전 중복
            ("  b.com/Path ", "phishing"),
            ("https://www.b.com/Path", "malware"),  # loose_key 충돌 -> 둘 다 제거
            ("", "benign"),                         # 빈 값
            ("javascript:alert(1)", "malware"),     # 지원 안 하는 scheme
            ("http://c.example.co.kr/Q?A=B", "defacement"),
        ])
        out, rep = D.clean(df)
        self.assertEqual(rep["input"], 7)
        self.assertEqual(rep["after_empty"], 6)
        self.assertEqual(rep["dropped_invalid_or_unsupported"], 1)
        self.assertEqual(rep["dropped_exact_duplicates"], 1)
        self.assertEqual(rep["dropped_label_conflicts"], 2)
        self.assertEqual(rep["output"], 2)
        self.assertIn("http://c.example.co.kr/Q?A=B", set(out["url"]))  # 경로·쿼리 보존
        self.assertEqual(set(out["group_key"]), {"a.com", "example.co.kr"})

    def test_scheme_profile(self):
        df = self._df([("http://a.com", "benign"), ("a.com", "benign"), ("https://www.b.com", "phishing")])
        t = D.scheme_profile(df)
        self.assertAlmostEqual(t.loc["benign", "http"], 50.0)
        self.assertAlmostEqual(t.loc["benign", "none"], 50.0)
        self.assertAlmostEqual(t.loc["phishing", "www_start"], 100.0)

    def test_loaders(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "malicious_phish.csv")
            pd.DataFrame({"url": ["a.com", "http://b.com"], "type": ["benign", "phishing"]}).to_csv(p, index=False)
            m = D.load_malicious_urls(p, "2026-11-10")
            self.assertEqual(list(m.columns), D.SCHEMA)
            self.assertEqual(list(m["label"]), ["benign", "phishing"])

            p2 = os.path.join(tmp, "PhiUSIIL_Phishing_URL_Dataset.csv")
            pd.DataFrame({"FILENAME": ["x", "y"], "URL": ["https://ok.com", "http://bad.com"], "label": [1, 0]}).to_csv(p2, index=False)
            ph = D.load_phiusiil(p2, "2026-11-10")
            self.assertEqual(list(ph["label"]), ["benign", "phishing"])

            p3 = os.path.join(tmp, "csv.txt")
            with open(p3, "w") as f:
                f.write("################\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n")
                f.write('"1","2026-11-01 00:00:00","http://1.2.3.4/x.sh","online","2026-11-01","malware_download","elf","https://urlhaus.abuse.ch/url/1/","r"\n')
            uh = D.load_urlhaus(p3, "2026-11-10")
            self.assertEqual(list(uh["url"]), ["http://1.2.3.4/x.sh"])
            self.assertEqual(list(uh["label"]), ["malware"])

            p4 = os.path.join(tmp, "top-1m.csv")
            with open(p4, "w") as f:
                f.write("1,google.com\n2,naver.com\n3,example.org\n")
            tr = D.load_tranco(p4, "2026-11-10", top_n=2, sample_n=0)
            self.assertEqual(sorted(tr["url"]), ["https://google.com/", "https://naver.com/"])

            self.assertTrue(D.find_file("*malicious*.csv", roots=(tmp,)).endswith("malicious_phish.csv"))
            self.assertIsNone(D.find_file("nothing*.csv", roots=(tmp,), required=False))

    def test_build_external(self):
        def f(rows, src):
            return pd.DataFrame(rows, columns=["url", "label"]).assign(source=src, collected_at="2026-11-10")
        uh = f([("http://evil.com/a", "malware"), ("http://train.com/a", "malware")], "urlhaus")
        tr = f([("https://evil.com/", "benign"), ("https://good.com/", "benign")], "tranco")
        ext, rep = D.build_external([uh, tr], train_groups={"train.com"})
        self.assertEqual(sorted(ext["url"]), ["http://evil.com/a", "https://good.com/"])
        self.assertEqual(rep["urlhaus"]["removed_train_overlap"], 1)
        self.assertEqual(rep["tranco"]["removed_feed_overlap"], 1)


class TestLabelMapping(unittest.TestCase):
    def test_map(self):
        m = map_external_labels({0: "benign", 1: "defacement", 2: "phishing", 3: "malware"})
        self.assertEqual(m, {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"})
        with self.assertRaises(ValueError):
            map_external_labels({0: "LABEL_0", 1: "LABEL_1", 2: "LABEL_2", 3: "LABEL_3"})


class TestSplit(unittest.TestCase):
    def test_group_split(self):
        from qsing_model.split import group_split, check_split
        rows = []
        labs = ["benign"] * 6 + ["phishing", "phishing", "malware", "defacement"]
        for g in range(400):
            lab = labs[g % len(labs)]
            for j in range(1 + g % 3):
                rows.append((f"http://s{j}.dom{g}.com/p", lab, f"dom{g}.com"))
        df = pd.DataFrame(rows, columns=["url", "label", "group_key"])
        d = group_split(df, seed=42)
        rep = check_split(d, tolerance_pp=2.0)
        self.assertTrue(rep["passed"])
        self.assertEqual(sum(rep["group_overlaps"].values()), 0)
        self.assertTrue(60 < rep["size_pct"]["train"] < 80)
        # 같은 시드면 같은 결과
        d2 = group_split(df, seed=42)
        self.assertTrue((d["split"] == d2["split"]).all())

    def test_big_groups_and_skew(self):
        """한 도메인이 매우 큰 경우(실제 데이터와 비슷)에도 비율을 지키고, 큰 도메인이 한 세트에만 있는지"""
        from qsing_model.split import group_split, check_split
        rng = np.random.default_rng(3)
        rows = []
        for lab, n_groups in (("benign", 3000), ("phishing", 1200), ("malware", 400), ("defacement", 300)):
            for g in range(n_groups):
                size = int(rng.zipf(1.8)) if lab != "defacement" else int(rng.integers(5, 40))
                size = min(size, 400)
                rows += [(f"u{lab}{g}_{j}", lab, f"{lab}{g}.com") for j in range(size)]
        rows += [(f"big{j}", "benign", "huge.com") for j in range(2000)]
        df = pd.DataFrame(rows, columns=["url", "label", "group_key"])
        d = group_split(df, seed=42)
        rep = check_split(d)
        self.assertLessEqual(rep["max_ratio_diff_pp"], 2.0)
        self.assertEqual(d.loc[d["group_key"] == "huge.com", "split"].nunique(), 1)


if __name__ == "__main__":
    unittest.main()
