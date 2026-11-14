# URL 위험 분류 모델 — 서버 연동 안내 (김다은 님용)

> 작성: 2026-11-10 · 모델 담당 박성빈
> 실제 성능·응답 시간 수치는 Kaggle 실행 후 `model/artifacts/metrics.json`에 들어갑니다.

## 1. 한 줄 요약

서버 시작 시 모델을 한 번 불러오고, 요청마다 `clf.predict(url)`을 부르면 됩니다.
외부 API 키나 인터넷 연결은 필요 없습니다. 인코더까지 포함한 모델 파일 전체가 `model/artifacts/`에 들어 있습니다.

## 2. 준비

```
Qsing/model/
├─ qsing_model/        ← 파이썬 패키지 (서버 코드에서 import)
├─ artifacts/          ← Kaggle 실행 결과 (encoder/, head.npz, model_config.json, thresholds.json, metrics.json)
└─ requirements-server.txt
```

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r model/requirements-server.txt
```

## 3. FastAPI 예시

```python
import sys, threading
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel

sys.path.insert(0, "model")                      # Qsing/model 경로
from qsing_model.infer import UrlRiskClassifier, ModelError

clf = None
lock = threading.Lock()                          # 동시 요청에서 모델 호출을 하나씩 처리


@asynccontextmanager
async def lifespan(app):
    global clf
    clf = UrlRiskClassifier.from_artifacts("model/artifacts", device="cpu", num_threads=2)
    yield


app = FastAPI(lifespan=lifespan)


class AnalyzeRequest(BaseModel):
    url: str


@app.post("/analyze")
def analyze(req: AnalyzeRequest):               # def(동기) → FastAPI가 스레드풀에서 실행
    try:
        with lock:
            ai = clf.predict(req.url)
    except ModelError:
        ai = {"status": "model_error", "risk_level": None}
    # TODO(서버): VirusTotal 결과와 합쳐 최종 판정
    return {"ai": ai}
```

## 4. `predict()` 반환 형식

```json
{
  "status": "ok",
  "url": "http://secure-login.example.xyz/verify?id=1",
  "predicted_type": "phishing",
  "scores": {"benign": 0.03, "phishing": 0.91, "malware": 0.04, "defacement": 0.02},
  "ai_risk_score": 0.97,
  "risk_level": "danger",
  "truncated": false,
  "signals": {"is_ip_host": false, "subdomain_depth": 1, "has_at_symbol": false,
              "has_punycode": false, "url_length": 44, "is_known_shortener": false},
  "model_version": "urlbert-tiny-v6@<커밋 12자리>+head-<종류>-<정규화>-<학습 날짜>"
}
```

| 키 | 의미 |
|---|---|
| `status` | `ok`, `invalid_url`, `unsupported_scheme` |
| `predicted_type` | `benign`, `phishing`, `malware`, `defacement` 중 확률이 가장 높은 것 |
| `scores` | 4종 확률 (합 1) |
| `ai_risk_score` | `1 − P(benign)`. **모델 예측 점수이며 실제 피해 확률이 아님** |
| `risk_level` | `low` / `caution` / `danger` → 앱의 낮음·주의·위험. 검사하지 못하면 `null` |
| `truncated` | URL이 2048자 또는 256토큰을 넘어 잘린 채 검사됨 |
| `signals` | URL 규칙 점검 결과. **보조 정보이며 AI의 판단 이유가 아님** |
| `model_version` | 어떤 모델로 검사했는지 기록용 |

## 5. 상태별 처리 — 검사하지 못한 URL을 안전으로 내보내지 않기

| 상황 | `status` | `risk_level` | 앱 표시 |
|---|---|---|---|
| 빈 값, 문자열 아님, 호스트 추출 불가 | `invalid_url` | `null` | 확인 불가 |
| `javascript:`, `intent:`, `tel:`, `data:`, `ftp://` 등 http·https 이외 | `unsupported_scheme` | `null` | 확인 불가 |
| 모델 내부 오류 | `ModelError` 예외 | — | 검사 실패 |
| 정상 검사 | `ok` | `low`·`caution`·`danger` | 위험도 표시 |

`low`는 모델이 실제로 점수를 계산했을 때만 나옵니다.

## 6. 여러 URL 한 번에

`clf.predict_batch([url1, url2, ...])`는 입력 순서대로 결과 리스트를 돌려줍니다. 잘못된 URL이 섞여 있어도 해당 항목만 `invalid_url` 등으로 표시됩니다.

## 7. 한계 (앱·발표에 표시)

- URL 문자열만 봅니다. 웹페이지 내용은 검사하지 않습니다.
- 단축 URL은 `is_known_shortener`로 표시만 하고 최종 목적지는 확인하지 않습니다.
- 위험도 경계값(`thresholds.json`)은 val 세트 기준 "정상 URL의 1% 이하만 위험, 악성 URL의 99% 이상이 주의 이상"으로 정했습니다. 팀 합의로 바꿀 수 있습니다.
- 응답 시간은 `metrics.json`의 `latency`(Kaggle CPU 기준)를 참고하세요. 실제 서버 사양에 따라 다릅니다.
