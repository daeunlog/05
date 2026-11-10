# QRSafe Backend API

QRSafe 백엔드는 QR 코드에서 추출한 URL을 검사하기 위한 FastAPI 서비스입니다. 목표 AI 모델은 [`CrabInHoney/urlbert-tiny-v6`](https://huggingface.co/CrabInHoney/urlbert-tiny-v6)의 `malicious_urls_4class` 분류 head를 이용한 4종 URL 분류입니다. 현재는 실제 URLBERT 모델 대신 고정 결과를 반환하는 Mock 모델을 사용하며, 선택적으로 VirusTotal API v3의 기존 URL 분석 결과를 조회합니다.

> 현재 `model.prediction="benign"`은 Mock 결과일 뿐 실제 안전 판정이 아닙니다. 최종 위험도 결합 로직이 아직 없으므로 `risk_level`은 항상 `unknown`, `is_complete`는 항상 `false`입니다.

## 목차

1. [기술 스택](#기술-스택)
2. [목표 AI 모델과 판정 계획](#목표-ai-모델과-판정-계획)
3. [Windows PowerShell에서 실행](#windows-powershell에서-실행)
4. [환경변수](#환경변수)
5. [API 공통 정보](#api-공통-정보)
6. [GET /health](#get-health)
7. [POST /api/scan](#post-apiscan)
8. [GET /api/history](#get-apihistory)
9. [HTTP 상태 코드와 오류 처리](#http-상태-코드와-오류-처리)
10. [Android에서 접속](#android에서-접속)
11. [Swagger UI](#swagger-ui)
12. [현재 구현 상태](#현재-구현-상태)

## 기술 스택

- FastAPI 및 Uvicorn
- Pydantic v2, pydantic-settings
- SQLAlchemy ORM, SQLite
- httpx 비동기 HTTP 클라이언트
- pytest

SQLite에는 VirusTotal 캐시(`vt_cache`)와 검사 이력(`scan_history`)을 저장합니다. 검사 이력에는 원본 URL 대신 서버 비밀키 기반 HMAC-SHA256 해시만 저장됩니다.

## 목표 AI 모델과 판정 계획

제안서의 실제 AI 목표는 `CrabInHoney/urlbert-tiny-v6`와 이 모델 저장소의 `malicious_urls_4class` 분류 head를 이용해 URL을 `benign`, `defacement`, `phishing`, `malware`의 4종으로 분류하는 것입니다. 현재 백엔드에는 PyTorch, Transformers 또는 해당 모델이 연결되어 있지 않으며, API는 고정된 `benign`, `0.85`, `is_mock=true`만 반환합니다.

향후 모델의 4종 softmax 확률이 제공되면 모델 기반 위험 신호를 다음과 같이 계산할 계획입니다.

```text
model_risk = 1 - P(benign)
```

이 값과 VirusTotal의 `malicious`, `suspicious`, `harmless`, `undetected`, `timeout` 통계에서 얻은 탐지 신호를 결합해 최종 `risk_level`을 산출할 예정입니다. 결합 가중치, 임계값, VirusTotal 결과가 없을 때의 정책은 아직 확정·구현되지 않았습니다. 따라서 현재 응답의 `risk_level="unknown"`과 `is_complete=false`는 최종 판정이 완료되지 않았다는 뜻이며 안전 판정을 의미하지 않습니다.

URLBERT는 **URL 문자열 자체**를 분석하는 모델입니다. 실제 웹페이지 본문, HTML/DOM, 다운로드 파일, 실행 동작을 검사하지 않으며 HTTP 요청을 따라간 뒤의 리디렉션 최종 목적지도 확인하지 않습니다. 이 한계 때문에 향후에도 모델 결과만으로 안전을 확정해서는 안 되며, 별도의 동적 분석이나 리디렉션 검사 기능이 필요합니다. 현재 백엔드 역시 검사 대상 URL에 직접 접속하지 않습니다.

## Windows PowerShell에서 실행

저장소 루트에서 다음 명령을 실행합니다.

```powershell
cd backend

py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

Copy-Item .env.example .env
# .env를 열어 아래 환경변수를 설정합니다.

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

PowerShell 실행 정책 때문에 가상환경 활성화가 차단되는 경우 현재 터미널에만 다음 설정을 적용할 수 있습니다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

서버 시작 시 SQLAlchemy 테이블이 자동으로 생성됩니다. 기본 SQLite 파일은 `backend/qrsafe.db`이며 Git에서 제외됩니다.

테스트 실행:

```powershell
python -m pytest -q
```

## 환경변수

`backend/.env.example`을 `backend/.env`로 복사한 뒤 값을 설정합니다. `.env`와 실제 비밀값을 Git에 커밋하면 안 됩니다.

```dotenv
APP_NAME=QRSafe API
APP_ENV=development

DATABASE_URL=sqlite:///./qrsafe.db

VIRUSTOTAL_API_KEY=
CACHE_HASH_SECRET=
USE_MOCK_MODEL=true
```

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `APP_NAME` | `QRSafe API` | 설정 객체에 로드되는 앱 이름. 현재 FastAPI 제목도 같은 문자열로 고정되어 있음 |
| `APP_ENV` | `development` | 설정 객체에 로드되는 환경 이름. 현재 환경별 분기 로직은 없음 |
| `DATABASE_URL` | `sqlite:///./qrsafe.db` | SQLAlchemy DB 연결 URL |
| `VIRUSTOTAL_API_KEY` | 빈 문자열 | VirusTotal API 키. 비어 있으면 외부 조회 결과가 `disabled`가 될 수 있음 |
| `CACHE_HASH_SECRET` | 빈 문자열 | URL 캐시 키와 이력 해시를 만드는 HMAC 비밀키. **실제 검사 요청 전에 반드시 설정** |
| `USE_MOCK_MODEL` | `true` | Mock 모델 사용 설정. 현재 구현은 이 값과 무관하게 실제 모델을 로드하지 않음 |

`CACHE_HASH_SECRET`에는 충분히 긴 무작위 값을 사용하세요. 안전하지 않은 공통 기본값은 제공되지 않으며, 비어 있으면 캐시 및 이력 저장 과정에서 설정 오류가 발생합니다. 로컬에서 값을 생성하는 한 가지 방법은 다음과 같습니다.

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

출력된 값은 개발자가 자신의 `.env`에만 저장해야 합니다. 이 문서나 소스 코드에 실제 VirusTotal API 키 또는 HMAC 비밀키를 기록하지 마세요.

## API 공통 정보

로컬 기본 주소:

```text
http://127.0.0.1:8000
```

요청과 응답 본문은 JSON입니다. 날짜는 UTC ISO 8601 형식, `last_analysis_date`는 VirusTotal이 반환한 Unix timestamp입니다.

## GET /health

서버 실행 상태를 확인합니다.

요청:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/health"
```

성공 응답 (`200 OK`):

```json
{
  "status": "ok",
  "service": "qrsafe-backend",
  "version": "0.1.0"
}
```

## POST /api/scan

HTTP 또는 HTTPS URL을 검사하고 요청마다 새로운 `scan_id`를 생성합니다. 요청 결과는 `scan_history`에 저장됩니다.

### 요청

```json
{
  "url": "https://example.com/login",
  "allow_external_lookup": false
}
```

| 필드 | 타입 | 필수 | 설명 |
| --- | --- | --- | --- |
| `url` | string | 예 | HTTP/HTTPS URL. 다른 스킴이나 잘못된 URL은 `422` |
| `allow_external_lookup` | boolean | 아니요 | 기본값 `false`. VirusTotal 및 캐시 조회 허용 여부 |

`allow_external_lookup` 동작:

- `false`: VirusTotal과 캐시를 조회하지 않고 `virustotal.status="skipped"`, `cached=false`를 반환합니다. 검사 이력은 저장합니다.
- `true`: 유효한 SQLite 캐시를 먼저 확인합니다. 적중하면 외부 API를 호출하지 않고 `cached=true`를 반환합니다.
- 캐시가 없거나 만료되면 VirusTotal의 **기존 분석 결과 조회 API**를 호출합니다. 완료된 결과만 24시간 캐시하며, 이번 응답은 새 외부 조회 결과이므로 `cached=false`입니다. 24시간 TTL은 현재 개발 버전의 임시 정책으로 운영 정책이 확정된 값이 아닙니다.
- 이 API는 URL을 VirusTotal에 새 분석 대상으로 제출하지 않습니다.

PowerShell 요청 예시:

```powershell
$body = @{
    url = "https://example.com/login"
    allow_external_lookup = $true
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/scan" `
    -ContentType "application/json" `
    -Body $body
```

외부 조회를 비활성화한 성공 응답 예시 (`200 OK`):

```json
{
  "scan_id": "3f619f12-8843-4e44-98aa-b5b3b43b472a",
  "url": "https://example.com/login",
  "model": {
    "prediction": "benign",
    "confidence": 0.85,
    "is_mock": true
  },
  "virustotal": {
    "status": "skipped",
    "stats": null,
    "last_analysis_date": null,
    "error_code": null
  },
  "risk_level": "unknown",
  "is_complete": false,
  "cached": false
}
```

VirusTotal 통계가 있는 경우 `stats` 형식:

```json
{
  "malicious": 1,
  "suspicious": 0,
  "harmless": 82,
  "undetected": 10,
  "timeout": 0
}
```

`virustotal.status` 값:

| 값 | 의미 |
| --- | --- |
| `skipped` | 외부 조회가 비활성화됨 |
| `completed` | 기존 VirusTotal 분석 결과 조회 성공 |
| `not_found` | VirusTotal에 기존 분석 결과가 없음 |
| `rate_limited` | VirusTotal 요청 한도 초과 |
| `timeout` | VirusTotal 요청 시간 초과 |
| `error` | 캐시, 인증, 네트워크, HTTP 또는 응답 형식 오류 |
| `disabled` | VirusTotal API 키가 설정되지 않음 |

`error_code`는 `missing_api_key`, `not_found`, `rate_limited`, `request_timeout`, `authentication_error`, `permission_error`, `http_error`, `network_error`, `invalid_response`, `cache_error` 중 하나이거나 `null`입니다.

VirusTotal 조회 실패나 결과 미존재는 안전 판정으로 취급되지 않습니다. 또한 현재 Mock 모델의 `benign` 결과만으로 최종 판정을 완료하지 않으므로 다음 값은 고정입니다.

- `risk_level="unknown"`: 최종 위험도 결합 로직이 아직 구현되지 않음
- `is_complete=false`: 실제 AI 모델과 최종 판정 파이프라인이 완료되지 않음

## GET /api/history

저장된 검사 이력을 최신순으로 조회합니다. 동일한 생성 시각이면 `scan_id` 내림차순으로 정렬됩니다.

> **보안 주의:** 현재 사용자 인증과 사용자별 접근 제어가 없습니다. 이 API는 로컬 개발·시연 전용이며 외부 공개 서버에 그대로 배포하면 안 됩니다. 공개 배포 전 인증·인가와 사용자별 이력 분리를 반드시 구현해야 합니다.

### 쿼리 파라미터

| 이름 | 타입 | 기본값 | 범위 |
| --- | --- | --- | --- |
| `limit` | integer | `20` | 1~100 |
| `offset` | integer | `0` | 0 이상 |

요청:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/history?limit=20&offset=0"
```

성공 응답 예시 (`200 OK`):

```json
{
  "total": 1,
  "items": [
    {
      "scan_id": "3f619f12-8843-4e44-98aa-b5b3b43b472a",
      "created_at": "2026-11-10T03:15:30.123456Z",
      "model_status": "completed",
      "model_prediction": "benign",
      "model_confidence": 0.85,
      "model_is_mock": true,
      "virustotal_status": "skipped",
      "virustotal_stats": null,
      "risk_level": "unknown",
      "is_complete": false
    }
  ]
}
```

DB에 이력이 없으면 다음과 같이 반환합니다.

```json
{
  "total": 0,
  "items": []
}
```

개인정보 및 보안상 검사 이력 응답에는 원본 URL과 `url_hash`가 모두 포함되지 않습니다. API 키와 HMAC 비밀키도 저장하거나 반환하지 않습니다.

## HTTP 상태 코드와 오류 처리

| API | 상태 코드 | 의미 |
| --- | --- | --- |
| 모든 API | `200` | 요청 처리 성공 |
| `POST /api/scan` | `422` | URL 형식, HTTP/HTTPS 스킴 또는 요청 필드 검증 실패 |
| `GET /api/history` | `422` | `limit` 또는 `offset` 범위/타입 검증 실패 |
| `POST /api/scan` | `500` | 검사 이력 DB 저장 실패 (`Failed to save scan history`) |
| `GET /api/history` | `500` | 검사 이력 DB 조회 실패 (`Failed to load scan history`) |

VirusTotal의 404, 429, 인증 오류, 시간 초과 및 네트워크 오류는 일반적으로 `POST /api/scan`의 HTTP 응답 자체를 실패시키지 않습니다. HTTP `200` 응답 안의 `virustotal.status`와 `error_code`로 표현됩니다. 따라서 Android 클라이언트는 HTTP 상태 코드뿐 아니라 이 두 필드를 함께 확인해야 합니다.

캐시 DB 오류는 `virustotal.status="error"`, `error_code="cache_error"`로 표현될 수 있습니다. DB 전체 장애로 검사 이력까지 저장하지 못하면 API는 HTTP `500`을 반환합니다.

FastAPI의 `422` 응답 본문은 검증 실패 위치와 사유가 포함된 표준 `detail` 배열 형식입니다. 서버의 DB 오류 응답은 내부 SQL이나 비밀정보를 노출하지 않는 고정 메시지를 사용합니다.

## Android에서 접속

일반적인 로컬 개발과 Android Emulator 테스트에서는 서버를 PC의 loopback 주소에만 바인딩합니다.

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Android 앱에는 인터넷 권한이 필요합니다.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

### Android Emulator

Android Studio 기본 Emulator에서 `127.0.0.1`은 PC가 아니라 Emulator 자신입니다. 호스트 PC의 서버에는 다음 주소로 접속합니다.

```text
http://10.0.2.2:8000
```

예:

```text
POST http://10.0.2.2:8000/api/scan
GET  http://10.0.2.2:8000/api/history?limit=20&offset=0
```

### 실제 Android 기기

1. PC와 Android 기기를 같은 Wi-Fi/LAN에 연결합니다.
2. PC PowerShell에서 `ipconfig`를 실행해 사용 중인 네트워크 어댑터의 IPv4 주소를 확인합니다.
3. 실기기 테스트가 필요할 때만 서버를 모든 인터페이스에 바인딩합니다.

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

4. 앱의 Base URL을 `http://<PC_IPV4>:8000`으로 설정합니다. 예시 자리표시자는 실제 PC 주소로 교체해야 합니다.
5. Windows Defender 방화벽에서 필요하면 TCP 8000 포트를 **현재 신뢰된 Private 네트워크와 개발 시간에만** 허용합니다. Public 네트워크에는 열지 마세요.

```text
http://<PC_IPV4>:8000/health
```

Android 9(API 28) 이상에서는 평문 HTTP가 앱 설정에 따라 차단될 수 있습니다. 개발 빌드에서만 Network Security Config 또는 `android:usesCleartextTraffic="true"`를 검토하고, 운영 환경에서는 HTTPS를 사용하세요.

`0.0.0.0`은 서버가 여러 네트워크 인터페이스에서 연결을 받게 하므로 기본 실행값으로 사용하지 않습니다. 실기기 테스트가 끝나면 서버를 종료하거나 `127.0.0.1` 바인딩으로 되돌리고, 방화벽 허용 규칙도 제거하거나 비활성화하세요.

## Swagger UI

서버 실행 후 브라우저에서 다음 주소를 엽니다.

- [Swagger UI](http://127.0.0.1:8000/docs)
- [ReDoc](http://127.0.0.1:8000/redoc)
- [OpenAPI JSON](http://127.0.0.1:8000/openapi.json)

## 현재 구현 상태

구현됨:

- FastAPI 서버, 상태 확인 및 Swagger/OpenAPI
- HTTP/HTTPS URL 요청 검증
- 고정 `benign`, `0.85`를 반환하는 Mock URLBERT 서비스
- VirusTotal API v3 기존 URL 분석 결과 조회
- VirusTotal 완료 결과의 24시간 SQLite 캐시(개발 버전 임시 TTL 정책)
- HMAC-SHA256 URL 식별자와 SQLite 검사 이력 저장
- 페이지네이션 기반 검사 이력 조회
- 외부 API 및 DB 오류 상태 구분

아직 구현되지 않음:

- `CrabInHoney/urlbert-tiny-v6` 및 `malicious_urls_4class` 기반 실제 4종 URL 분류
- `1 - P(benign)`과 VirusTotal 탐지 통계를 결합한 최종 위험도 판정
- VirusTotal 신규 URL 분석 제출
- 제안서에 포함된 사용자 URL 신고 및 오탐(false positive) 피드백 접수 API
- 실제 웹페이지 콘텐츠 분석 및 리디렉션 최종 목적지 검사
- 사용자 인증, 사용자별 이력 분리 및 접근 제어
- 운영 환경용 HTTPS, 권한 정책 및 배포 구성
- 검사 이력 상세 조회·삭제 API
