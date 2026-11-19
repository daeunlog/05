"""Run directly from backend with python tests/smoke_http.py."""
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qsing_model.infer import UrlRiskClassifier


def verify():
    artifacts = Path(os.environ.get("MODEL_ARTIFACTS_DIR", ROOT / "model/artifacts")).resolve()
    direct = UrlRiskClassifier.from_artifacts(str(artifacts), device="cpu")
    with tempfile.TemporaryDirectory() as tmp, socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp}/smoke.db",
                   CACHE_HASH_SECRET=secrets.token_hex(32), VIRUSTOTAL_API_KEY="",
                   MODEL_ARTIFACTS_DIR=str(artifacts))
        proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host",
                                "127.0.0.1", "--port", str(port), "--no-access-log"],
                                cwd=ROOT, env=env)
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60, trust_env=False,
                              headers={"Authorization": "Bearer " + secrets.token_hex(32)}) as c:
                for _ in range(600):
                    if proc.poll() is not None:
                        raise RuntimeError("Server exited")
                    try:
                        assert c.get("/health").json()["model_status"] == "ready"
                        break
                    except httpx.ConnectError:
                        time.sleep(.2)
                else:
                    raise RuntimeError("Startup timed out")
                ids = []
                for url in ("https://example.com", "https://example.com/"):
                    expected = direct.predict(url)
                    body = c.post("/api/scan", json={"url": url, "allow_external_lookup": True}).raise_for_status().json()
                    m = body["model"]
                    assert m["scores"] == expected["scores"] and m["prediction"] == expected["predicted_type"]
                    assert m["ai_risk_score"] == expected["ai_risk_score"] and m["ai_risk_level"] == expected["risk_level"]
                    assert m["truncated"] == expected["truncated"] and m["model_version"] == expected["model_version"]
                    assert body["virustotal"]["status"] == "disabled" and body["risk_level"] != "low"
                    for source, version, prediction, benign, risk in [
                        ("direct", expected["model_version"], expected["predicted_type"], expected["scores"]["benign"], expected["ai_risk_score"]),
                        ("HTTP", m["model_version"], m["prediction"], m["scores"]["benign"], m["ai_risk_score"]),
                    ]:
                        assert risk == 1 - benign
                        print(url, source, version, prediction, "P(benign)=", benign, "ai_risk_score=", risk)
                    print("VirusTotal:", body["virustotal"]["status"], body["virustotal"]["error_code"])
                    ids.append(body["scan_id"])
                assert {i["scan_id"] for i in c.get("/api/history").json()["items"]} == set(ids)
                path = f"/api/scans/{ids[0]}/reports"
                for _ in range(2):
                    assert c.post(path, json={"kind":"suspicious"}).json()["status"] == "received"
                with sqlite3.connect(Path(tmp) / "smoke.db") as reader:
                    assert reader.execute("SELECT scan_id, kind FROM scan_report").fetchall() == [(ids[0], "suspicious")]
                reader.close()
                other = {"Authorization": "Bearer " + secrets.token_hex(32)}
                assert c.get("/api/history", headers=other).json() == {"items": [], "total": 0}
                assert c.post(path, headers=other, json={"kind":"suspicious"}).status_code == 404
                for url, code in [("bad", "invalid_url"), ("ftp://example.com", "unsupported_scheme")]:
                    res = c.post("/api/scan", json={"url":url})
                    assert res.status_code == 422 and res.json()["detail"][0]["type"] == code
                assert c.post("/api/scan", json={"url":"https://example.com/?token=private",
                              "allow_external_lookup": True}).json()["virustotal"]["status"] == "withheld"
                print("HTTP scan/history/reports, ownership, validation, privacy and missing key: PASS")
        finally:
            proc.terminate()
            proc.wait(timeout=30)


if __name__ == "__main__":
    verify()
