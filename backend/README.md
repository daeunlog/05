# QRSafe Android 연동 가이드

## 빠른 시작

Windows x64, Git, Python 3.11(`py -3.11`)을 준비한다. 최초 설치에는 인터넷과 저장소 읽기 권한이 필요하다. 아래에서 **처음 설치** 또는 **v3에서 갱신** 중 하나를 실행한 뒤 서버를 시작한다.

### 처음 설치

PowerShell에서 프로젝트를 받을 폴더를 열고 실행한다.

```powershell
git clone --branch feature/backend https://github.com/daeunlog/05.git qrsafe
cd .\qrsafe\backend
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

설치기가 CPU 모델, 가상환경, 패키지를 준비한다. 최초 실행 시 `.env.example`을 바탕으로 서버용 HMAC 키를 생성해 `.env`에 저장한다. 기본 검사는 VirusTotal 키 없이도 가능하다.

### v3에서 갱신

기존 서버를 `Ctrl+C`로 종료하고, 기존 저장소 안에서 실행한다.

```powershell
cd (git rev-parse --show-toplevel)
git switch feature/backend
git pull --ff-only
cd .\backend
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

설치기가 기존 배포 파일을 확인하고 같은 폴더에 v5를 설치한다. 예전에 환경변수나 `backend/.env`의 `MODEL_ARTIFACTS_DIR`를 v3 폴더로 지정했다면 해당 설정을 해제하거나 v5 폴더로 변경한다. 기존 `CACHE_HASH_SECRET`은 유지한다.

### 서버 시작과 준비 확인

설치가 성공하면 **같은 PowerShell 창**에서 아래 서버를 실행하고 창을 열어 둔다.

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

서버에 `Application startup complete`가 표시되면 **두 번째 PowerShell 창**에서 확인한다. 상태 확인에는 인증 헤더가 필요 없다.

```powershell
$base = 'http://127.0.0.1:8000'
$health = Invoke-RestMethod "$base/health"
$health | Select-Object status, model_status, service, version
if ($health.model_status -ne 'ready') { throw '모델 경로와 setup.ps1 실행 결과를 확인하세요.' }
```

정상 결과는 `status=ok`, **`model_status=ready`**다. PC 브라우저에서 [Swagger UI](http://127.0.0.1:8000/docs), [OpenAPI JSON](http://127.0.0.1:8000/openapi.json), [ReDoc](http://127.0.0.1:8000/redoc)을 열 수 있다.

## 1. 접속 주소 선택

| 요청하는 곳 | 기본 주소 | 연결 확인 |
|---|---|---|
| PC 브라우저 | `http://127.0.0.1:8000` | `/health` 또는 `/docs` 열기 |
| Android Studio Emulator | `http://10.0.2.2:8000` | `10.0.2.2`는 에뮬레이터를 실행한 **PC의 루프백**을 가리킨다. 빠른 시작의 서버를 그대로 사용한다. |
| Android 실기기 | `http://<PC의 LAN IPv4>:8000` | PC와 기기를 같은 신뢰된 LAN에 연결하고 기기 브라우저에서 `/health` 열기 |

실기기 테스트 시 PC에서 `ipconfig`로 사용 중인 어댑터의 IPv4를 확인한다. 빠른 시작 서버를 종료한 뒤 `backend`에서 아래처럼 실행한다. Windows 방화벽의 TCP 8000 인바운드 허용 범위는 신뢰된 개인 네트워크의 테스트 기기로 제한한다.

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

Android 매니페스트에 `android.permission.INTERNET` 권한을 선언한다. 로컬 HTTP 연결이 차단되면 debug 빌드의 평문 통신 설정을 확인한다. 외부 배포에는 HTTPS를 사용한다.

## 2. 설치 토큰 준비

앱은 **최초 설치 시 한 번** 암호학적 난수 32바이트를 생성하고 64자리 hex 문자열로 인코딩한다. Kotlin에서는 다음처럼 생성할 수 있다.

```kotlin
val bytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
val token = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
```

Android Keystore로 보호한 앱 전용 저장소에 토큰을 보관하고, 앱 재시작과 검사·이력·신고 요청에 같은 값을 사용한다. 서버는 토큰 해시로 소유권을 확인한다. 토큰을 잃거나 새로 만들면 이전 설치의 이력을 조회할 수 없다. 요청 본문과 인증 헤더는 앱 로그에서 제외한다.

| 헤더 | 값 | 적용 |
|---|---|---|
| `Authorization` | `Bearer <64자리 hex 설치 토큰>` | 검사·이력·신고 모두 |
| `Content-Type` | `application/json` | JSON 본문을 보내는 POST |

PC에서 한 설치를 재현하려면 상태를 확인한 **두 번째 PowerShell 창**에서 아래를 한 번만 실행한다. 이어지는 세 요청이 같은 `$headers`를 사용한다.

```powershell
$token = py -3.11 -c "import secrets; print(secrets.token_hex(32))"
$headers = @{ Authorization = "Bearer $token" }
```

## 3. URL 검사

**`POST /api/scan`**에 QR에서 읽은 HTTP(S) URL 문자열을 그대로 보낸다. `allow_external_lookup` 기본값은 `false`다. 사용자가 외부 조회에 동의한 경우에만 `true`를 보낸다.

```powershell
$scan = Invoke-RestMethod -Method Post -Uri "$base/api/scan" -Headers $headers -ContentType 'application/json' -Body '{"url":"https://example.com/","allow_external_lookup":false}'
$scan | ConvertTo-Json -Depth 5
```

응답 예시다. 점수는 표시용으로 반올림했으며 `scan_id`는 요청마다 달라진다.

```json
{
  "scan_id": "3f619f12-8843-4e44-98aa-b5b3b43b472a",
  "url": "https://example.com/",
  "model": {
    "prediction": "benign",
    "confidence": 0.905677,
    "is_mock": false,
    "scores": {"benign": 0.905677, "phishing": 0.080441, "malware": 0.013880, "defacement": 0.000002},
    "ai_risk_score": 0.094323,
    "ai_risk_level": "caution",
    "truncated": false,
    "model_version": "urlbert-tiny-v6@020744435b3b+head-mlp-strip2-2026-11-12"
  },
  "virustotal": {"status": "skipped", "stats": null, "last_analysis_date": null, "error_code": null},
  "risk_level": "caution",
  "is_complete": false,
  "cached": false
}
```

### 결과 화면에 연결할 필드

| 화면 요소 | 필드 | 해석 |
|---|---|---|
| 대표 위험 등급 | **`risk_level`** | 서버의 통합 판정. `danger`, `caution`, `low`, `unknown` 중 하나. `unknown`은 판단 보류로 표시 |
| AI 분류 | `model.prediction`, `model.confidence` | 점수가 가장 높은 클래스와 그 점수. 정상 점수는 항상 `model.scores.benign`에서 읽는다. |
| AI 위험도 | `model.ai_risk_score`, `model.ai_risk_level` | 점수는 `1 − P(benign)`, 등급은 모델 임계값으로 결정한다. 점수 범위는 **0~1**이며 백분율 표시 때만 100을 곱한다. |
| 외부 조회 | `virustotal.status`, `cached` | 조회 상태와 캐시 재사용 여부. `completed`이면 `stats`에서 엔진별 집계, `last_analysis_date`에서 분석 시각(Unix 초 또는 null)을 읽는다. |
| 판정 완료 여부 | `is_complete` | `false`여도 서버가 `caution`이나 `danger`를 반환하면 해당 경고를 표시한다. |

v5 실측에서 `https://example.com`과 `https://example.com/`은 모두 정상 점수 **0.905677**, AI 위험 점수 **0.094323**이었다. 가장 높은 클래스는 `benign`이지만 위험 점수가 주의 임계값을 넘어서 AI 등급은 **`caution`**이다. 위 요청처럼 외부 조회를 생략하면 최종 등급도 `caution`이며 `is_complete=false`다.

서버는 아래 조건을 위에서부터 적용한다. 표에서 VT 완료는 통계를 받은 `completed` 상태다.

| 첫 번째로 만족하는 조건 | 최종 `risk_level` | `is_complete` |
|---|---|---|
| AI가 danger이거나 VT `malicious` ≥ 1 | danger | VT 완료 여부 |
| AI가 caution이거나 VT `suspicious` ≥ 1 | caution | VT 완료 여부 |
| AI가 low이고 입력 잘림이 없으며 VT 완료 및 `harmless` ≥ 1 | low | true |
| 그 외 | unknown | false |

## 4. 내 이력 조회

**`GET /api/history`**는 같은 설치 토큰의 이력을 최신순으로 반환한다. `limit`은 기본 20(1~100), `offset`은 기본 0(0 이상)이다. `total`은 설치의 전체 건수이며 `items`에는 현재 페이지가 들어간다. 이력에는 원문 URL과 URL 해시가 노출되지 않는다.

```powershell
Invoke-RestMethod "$base/api/history?limit=20&offset=0" -Headers $headers | ConvertTo-Json -Depth 5
```

```json
{
  "total": 1,
  "items": [{
    "scan_id": "3f619f12-8843-4e44-98aa-b5b3b43b472a",
    "created_at": "2026-11-19T02:00:00Z",
    "model_status": "completed", "model_prediction": "benign", "model_confidence": 0.905677, "model_is_mock": false,
    "virustotal_status": "skipped", "virustotal_stats": null, "risk_level": "caution", "is_complete": false
  }]
}
```

## 5. 검사 결과 신고

**`POST /api/scans/{scan_id}/reports`**에는 검사 응답이나 이력에서 받은 `scan_id`를 사용한다. 본문의 `kind`는 `false_positive`(오탐) 또는 `suspicious`(의심 URL)다. 같은 검사에 같은 종류의 신고를 재전송해도 한 건으로 저장한다.

```powershell
Invoke-RestMethod -Method Post -Uri "$base/api/scans/$($scan.scan_id)/reports" -Headers $headers -ContentType 'application/json' -Body '{"kind":"false_positive"}'
```

```json
{"scan_id":"3f619f12-8843-4e44-98aa-b5b3b43b472a","kind":"false_positive","status":"received"}
```

## 검증 현황

| 상태 | 범위 |
|---|---|
| 백엔드 확인 완료 | pytest 57개 통과. 실제 v5 CPU 모델로 HTTP 검사 → 이력 조회 → 신고 저장 및 다른 설치의 접근 차단 확인 |
| 모델 확인 완료 | 위 두 URL 각각에서 단독 `predict()`와 HTTP 응답의 모델 버전·예측·클래스별 점수·위험 점수가 일치 |
| 팀 확인 완료 | VirusTotal 실키로 기존 보고서를 조회하고 동일 URL 재검사에서 캐시 재사용(`cached=false → true`) 확인 |
| Android 앱 실기동 확인 필요 | 에뮬레이터와 실기기에서 QR 스캔 → 결과 화면 → 이력 → 신고까지 실행하고, 앱 재시작 후 같은 설치 이력이 보이는지 확인 |

## 오류 코드

HTTP 오류는 요청 전체의 실패다. HTTP 200을 받은 경우에도 외부 조회 결과는 `virustotal.status`와 `virustotal.error_code`로 확인한다.

| HTTP | 코드 또는 메시지 | 앱 처리 |
|---|---|---|
| 401 | `installation_token_required` | 저장한 토큰과 Bearer 헤더 형식 확인 |
| 404 | `scan_not_found` | 신고 대상 ID와 소유 설치 확인 |
| 422 | `invalid_url`, `unsupported_scheme`, 필수 필드·길이·쿼리 범위 오류 등 | 입력 수정. 검증 오류의 `detail`은 보통 `type`·`loc` 배열이며 모델의 입력 거부는 문자열 |
| 503 | `model_load_failed` | 서버 모델 경로·설치 상태와 `/health` 확인 |
| 500 | `inference_failed`, `Failed to save scan history`, `Failed to load scan history`, `report_save_failed` | 해당 작업을 실패로 표시 |

외부 조회 동의 시 서버는 공개 접미사가 있는 기본 도메인 또는 www, 포트 생략·80·443, 경로 생략·`/`·`/login`·`/login/`만 허용한다. IP, 사용자 정보, 쿼리, fragment 등 민감할 수 있는 입력은 보류한다. 허용된 URL은 캐시를 먼저 확인하고, 미스 시 VirusTotal **기존 보고서**를 조회한다(타임아웃 10초). 완료 결과의 캐시 TTL은 개발 정책상 24시간이다. 서버가 대상 웹페이지를 방문하거나 새 분석을 제출하는 기능은 없다.

| `virustotal.status` | `error_code` | 의미 |
|---|---|---|
| skipped / withheld / completed | null | 각각 동의 생략·전송 보류·보고서 조회 완료 |
| disabled | missing_api_key | 서버 키 미설정 |
| not_found | not_found | 기존 보고서 없음 |
| rate_limited | rate_limited | 호출 한도 초과 |
| timeout | request_timeout | 응답 시간 초과 |
| error | authentication_error, permission_error, http_error, network_error, invalid_response, cache_error | 각각 외부 인증·권한·HTTP·네트워크·응답 형식·캐시 오류 |

## 서버 환경변수

`backend/.env.example`이 설정 양식이다. 실제 키는 서버의 `backend/.env`에만 보관한다.

| 변수 | 기본값 또는 설정 방법 |
|---|---|
| `MODEL_ARTIFACTS_DIR` | 기본 `backend/model/artifacts/`. 직접 지정할 때는 절대경로 사용 |
| `VIRUSTOTAL_API_KEY` | 선택. 비어 있으면 외부 조회 허용 후 캐시 미스 시 `disabled` |
| `CACHE_HASH_SECRET` | 신규 설치 시 자동 생성. 캐시와 이력의 URL HMAC에 사용하므로 기존 환경에서도 비어 있으면 설정하고 재시작 간 같은 값을 유지 |
| `DATABASE_URL` | `sqlite:///./qrsafe.db`. 서버 시작 시 필요한 테이블 생성 |
| `APP_ENV`, `APP_NAME` | 각각 `development`, `QRSafe API` |

설치 원본은 모델 팀 커밋 `7be5b747b6d98ea0e6807183bd82662bd0d5006e`의 `model/artifacts_v5`다. 설치기는 추론 패키지를 `backend/qsing_model/`에, 인코더·토크나이저·헤드·임계값·전처리 설정을 기본 모델 폴더에 준비한다. 서버는 워커 시작 시 한 번 로드해 모델의 `strip2` 전처리를 사용한다.

## 테스트 명령

PowerShell에서 `backend` 폴더를 열고 실행한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tests\smoke_http.py
```

첫 명령은 임시 DB와 테스트 대역으로 API 동작과 오류 분기를 검증한다. 두 번째는 실제 모델·임시 SQLite·로컬 HTTP 서버로 검사 흐름을 검증하며, 빈 VirusTotal 키로 실행한다. 실키 조회와 캐시 재사용은 별도 확인 항목이다.
