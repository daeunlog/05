# QRSafe Android 백엔드

Android에서 QR을 해독한 뒤 **읽은 URL 문자열 그대로** JSON에 넣는다. FastAPI는 CPU에서 학습된 4종 분류기를 실행하고, 동의가 있으면 VirusTotal 기존 보고서를 확인한다. 대상 사이트 방문, 리디렉션 추적, 신규 분석 제출은 하지 않는다.

## Windows PowerShell 빠른 시작

Windows x64에서 Git, Python 3.11과 `py` 런처가 필요하다. 처음 설치할 때는 인터넷과 저장소 읽기 권한이 필요하다.

```powershell
git clone --branch feature/backend https://github.com/daeunlog/05.git qrsafe
cd qrsafe/backend
powershell -ExecutionPolicy Bypass -File .\setup.ps1
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

설치 스크립트는 가상환경과 패키지를 준비하고 처음에만 `.env.example`로부터 임의의 서버 HMAC 키가 든 `.env`를 생성한다. 재시작 시 같은 키를 유지한다. 기존 환경을 쓰는 경우 `CACHE_HASH_SECRET`이 비어 있으면 설정해야 검사 이력이 저장된다.

| 서버 설정 | 용도 |
|---|---|
| `MODEL_ARTIFACTS_DIR` | 기본값은 이 프로젝트의 `backend/model/artifacts`. 다른 위치라면 절대경로 지정 |
| `VIRUSTOTAL_API_KEY` | 선택. 비어 있으면 캐시 미스 시 `disabled` |
| `CACHE_HASH_SECRET` | 이력 및 캐시 URL의 HMAC-SHA256 키. 서버에만 보관 |
| `DATABASE_URL` | 기본 `sqlite:///./qrsafe.db`. 시작 시 필요한 테이블 생성 |
| `APP_ENV`, `APP_NAME` | 기본 설정은 `development`, `QRSafe API` |

모델 팀 커밋 `7be5b747b6d98ea0e6807183bd82662bd0d5006e`의 `model/artifacts_v5`를 사용한다. `setup.ps1`은 추론 패키지를 `backend/qsing_model/`에, v5 가중치·토크나이저·전처리 설정·분류 헤드·임계값을 `backend/model/artifacts/`에 설치한다. 별도로 받을 파일은 없다. 서버는 워커당 한 번 CPU에 로드하고 원문 URL을 `predict(url)`에 전달한다. v5의 `model_version`은 `urlbert-tiny-v6@020744435b3b+head-mlp-strip2-2026-11-12`, `normalization`은 `strip2`다. Transformers는 인코더 BOS/EOS 토큰 ID 범위 경고를 출력한다.

**기존 v3 설치 갱신:** 서버를 종료한 뒤 `feature/backend`에서 `git pull --ff-only`를 실행한다. `backend`에서 위 `setup.ps1` 명령을 다시 실행하고 서버를 시작한다. 설치기는 기존 배포본을 확인한 뒤 갱신한다. `MODEL_ARTIFACTS_DIR`를 별도로 지정했다면 해당 값을 기본 설치 폴더로 변경하거나 해제해야 새 모델을 로드한다.

## 기존 Android 규격에서 달라진 점 (bbfd93c 기준)

| 항목 | 이전 | 현재 |
|---|---|---|
| 경로·요청 | `GET /health`, `POST /api/scan`, `GET /api/history` | 세 경로와 검사 요청 필드는 동일. `POST /api/scans/{scan_id}/reports` 추가 |
| 인증·이력 | 인증 없이 전체 조회 | 검사·이력·신고에 설치별 Bearer 토큰 필수(누락 시 401). 본인 이력만 조회. health는 공개 |
| model | benign, confidence=0.85, is_mock=true | 4종 prediction, 예측 클래스 confidence, is_mock=false. scores·ai_risk_score·ai_risk_level·truncated·model_version 추가 |
| 최종 판정·VT | unknown / false 고정 | 통합 판정표에 따라 risk_level·is_complete 결정. 민감 URL에는 VT 상태 withheld 추가 |
| 상태·검증 | health.status=ok, 검증 오류에 입력 포함 가능 | health에 model_status 추가, 모델 로드 실패 시 degraded. 422 detail 배열에 type·loc만 전달(모델이 입력을 거부하면 detail 문자열) |

[Swagger UI](http://127.0.0.1:8000/docs) · [OpenAPI JSON](http://127.0.0.1:8000/openapi.json) · [ReDoc](http://127.0.0.1:8000/redoc)

## Android 연결과 소유권

- Emulator 기본 주소는 `http://10.0.2.2:8000`. PC 자체 테스트는 `http://127.0.0.1:8000`. `GET /health`의 `model_status`가 `ready`면 모델 로딩 완료다.
- 실기기는 같은 신뢰된 LAN에서만 서버를 `--host 0.0.0.0`으로 실행하고 `http://<PC의 IPv4>:8000`을 사용한다. 방화벽 TCP 8000 허용 범위를 테스트 기기로 제한한다. 앱은 INTERNET 권한과 로컬 HTTP용 debug 네트워크 설정이 필요하다. 외부 배포에는 HTTPS가 필요하다.
- 앱은 최초 설치 시 암호학적 난수 32바이트를 **64자리 hex**로 인코딩해 기기의 보안 저장소에 보관한다. 모든 검사·조회·신고 요청에 `Authorization: Bearer <설치 토큰>`을 넣는다. 설치별 접근권한이며 이 토큰 소지자는 그 설치의 이력을 볼 수 있다. 서버에는 토큰 다이제스트만 저장한다. 토큰을 잃으면 기존 이력에 접근할 수 없다. 소유자 식별 전 생성된 과거 행은 어떤 설치에도 공개하지 않는다.
- JSON 본문에는 `Content-Type: application/json`을 사용한다. API 키와 HMAC 키는 앱으로 전달하지 않는다.

## 복사해서 검사 → 조회 → 신고하기

서버가 실행된 상태에서 다른 PowerShell 창을 열고 `backend`에서 실행한다. 같은 설치를 재현할 때는 같은 토큰을 사용한다.

```powershell
$base = 'http://127.0.0.1:8000'
$token = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod "$base/health"
$scan = Invoke-RestMethod "$base/api/scan" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"url":"https://example.com/","allow_external_lookup":false}'
$scan | ConvertTo-Json -Depth 5
Invoke-RestMethod "$base/api/history?limit=20&offset=0" -Headers $headers | ConvertTo-Json -Depth 5
Invoke-RestMethod "$base/api/scans/$($scan.scan_id)/reports" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"kind":"false_positive"}'
```

### POST /api/scan

요청의 `url`은 HTTP(S) 문자열이다. `allow_external_lookup` 기본값은 false. 성공 응답 예시(점수는 표시용 반올림):

```json
{
  "scan_id":"3f619f12-8843-4e44-98aa-b5b3b43b472a",
  "url":"https://example.com/",
  "model":{
    "prediction":"benign","confidence":0.905677,"is_mock":false,
    "scores":{"benign":0.905677,"phishing":0.080441,"malware":0.013880,"defacement":0.000002},
    "ai_risk_score":0.094323,"ai_risk_level":"caution","truncated":false,
    "model_version":"urlbert-tiny-v6@020744435b3b+head-mlp-strip2-2026-11-12"
  },
  "virustotal":{"status":"skipped","stats":null,"last_analysis_date":null,"error_code":null},
  "risk_level":"caution","is_complete":false,"cached":false
}
```

`confidence`는 예측 클래스의 점수, `scores`는 클래스별 점수, `ai_risk_score`는 모델이 반환한 **1 − P(benign)**이다. 모두 **0~1**이며 UI에서 백분율로 표시할 때만 100을 곱한다. 실제 피해 확률을 뜻하지 않는다. `ai_risk_level`은 모델 단독 등급이고 앱에 표시하는 통합 등급은 최상위 `risk_level`이다.

### 외부 조회와 통합 판정

동의가 없으면 `skipped`. 동의해도 사용자 정보, 쿼리, fragment, IP, 내부 호스트 또는 토큰을 포함할 수 있는 경로 등은 보수적으로 `withheld` 처리한다. 허용 범위는 공개 접미사의 기본 도메인 또는 www, 기본/80/443 포트, 빈 경로·`/`·`/login`·`/login/`이다. 허용 URL은 로컬 캐시를 먼저 읽고 미스 시 서버 키로 VirusTotal의 기존 URL 보고서만 조회한다(타임아웃 10초). 완료 결과만 개발 정책상 24시간 캐싱한다. 적중 시에만 `cached=true`. 조회 승인 시 URL이 외부 사업자에게 전달될 수 있다.

다음은 위에서 아래로 적용하는 서버의 표시 정책이다. VT 완료는 통계가 있는 `completed`를 뜻한다.

| 조건 | 표시 등급 | is_complete |
|---|---|---|
| AI danger 또는 VT malicious ≥ 1 | danger | VT 완료 여부 |
| AI caution 또는 VT suspicious ≥ 1 | caution | VT 완료 여부 |
| AI low, 입력 잘림 없음, VT 완료 및 harmless ≥ 1 | low | true |
| 나머지(미조회·실패·결과 부족 등) | unknown | false |

`virustotal.stats`에는 malicious, suspicious, harmless, undetected, timeout 엔진 수가 들어간다. `last_analysis_date`는 Unix 초 또는 null. 외부 조회 실패도 이력 저장 성공 시 HTTP 200 안에서 표현된다.

| VT status | error_code |
|---|---|
| skipped / withheld / completed | null |
| disabled / not_found / rate_limited / timeout | missing_api_key / not_found / rate_limited / request_timeout (각각) |
| error | authentication_error, permission_error, http_error, network_error, invalid_response, cache_error |

### GET /api/history · POST /api/scans/{scan_id}/reports

조회는 현재 토큰 소유자의 최신순이며 limit 기본 20(1~100), offset 기본 0(0 이상)이다. 원문 URL과 해시는 응답에서 제외한다. 서버는 URL 원문 대신 정규화된 URL의 HMAC만 저장한다.

```json
{"total":1,"items":[{"scan_id":"3f619f12-8843-4e44-98aa-b5b3b43b472a","created_at":"2026-11-19T02:00:00Z","model_status":"completed","model_prediction":"benign","model_confidence":0.905677,"model_is_mock":false,"virustotal_status":"skipped","virustotal_stats":null,"risk_level":"caution","is_complete":false}]}
```

신고 종류는 `false_positive`(오탐) 또는 `suspicious`(의심 URL)이다. URL·자유 텍스트는 받지 않는다. 같은 검사·종류를 재전송해도 신고는 한 건이다.

```json
{"scan_id":"3f619f12-8843-4e44-98aa-b5b3b43b472a","kind":"false_positive","status":"received"}
```

### HTTP 오류

| HTTP | 앱 처리 |
|---|---|
| 401 | 설치 토큰 형식/누락 확인 |
| 404 | 신고 대상이 없거나 다른 설치의 검사 |
| 422 | 잘못된 입력. URL 형식과 스킴은 invalid_url, unsupported_scheme로 구분. 필드/길이/페이지 범위 오류도 422 |
| 503 | model_load_failed. 서버 산출물·의존성 확인 |
| 500 | inference_failed 또는 저장·조회 오류. 검사 실패로 표시 |

검사 응답의 `url`은 요청 앱으로 되돌아오므로 앱에서도 요청·응답 본문이나 토큰을 로깅하지 않는다.

## 검증

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tests\smoke_http.py
```

첫 명령은 임시 DB·모델/외부 API 대역으로 분기와 오류를 검증한다. 두 번째는 실물 CPU 모델과 임시 SQLite, 빈 VT 키, 로컬 Uvicorn 서버로 두 입력의 단독/API 일치, 이력, 신고, 소유권, 민감 URL 보류를 확인한다.
