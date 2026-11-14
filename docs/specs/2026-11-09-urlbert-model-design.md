# URLBERT 기반 URL 위험 분류 모델 — 설계 문서

- 작성일: 2026-11-09 (11주차)
- 범위: 큐싱 탐지 서비스 중 **데이터·AI 모델 파트** (제안서 2장·3장)
- 실행 환경: 학습·평가는 Kaggle Notebook(GPU), 로직 단위 테스트와 문서는 로컬
- 접근법: **B안** — 기본 인코더 위에 4종 분류 헤드를 직접 학습해 메인으로 쓰고, 제공 헤드는 기준선으로 비교
- 상태: 설계 승인됨 (섹션 1~4, 2026-11-09)

---

## 0. 배경과 결정 이유

`CrabInHoney/urlbert-tiny-v6` 모델 카드에 따르면 제공 헤드 중 `malicious_urls_4class`는 Malicious URLs Dataset(Kaggle)으로, `phiusiil_phishing_url`은 PhiUSIIL로 학습되었다. 따라서 제공 헤드를 이 두 데이터셋으로 평가하면 학습에 쓴 데이터로 시험하는 셈이 되어 성능이 부풀려진다(제안서 2.3절 우려 사항).

반면 기본 인코더의 학습 데이터(phishdestroy/destroylist, ealvaradob/phishing-dataset, cybersectony/PhishingEmailDetectionv2.0)에는 두 데이터셋이 포함되어 있지 않다. 그래서 인코더 위에 헤드를 직접 학습하고 도메인 단위로 분리한 test 세트로 평가하면 독립적인 성능 근거를 만들 수 있다.

모델 사양(모델 카드 기준): 파라미터 약 2.03M, hidden 128, 6층, attention head 4개, 최대 256토큰(URL당 평균 24.8토큰), 권장 풀링은 CLS+MEAN, 라이선스 Apache-2.0.

C안(인코더 전체 파인튜닝)은 B안 완료 후 일정이 남으면 확장 과제로 진행한다.

---

## 1. 페이즈 구성

| 페이즈 | 내용 | 실행 위치 | 산출물 |
|---|---|---|---|
| P0 환경 준비 | 폴더 구조, work_history.md, Kaggle 노트북 뼈대 작성. Kaggle GPU 확인, 모델 다운로드, 저장소 커밋 해시 고정, 4종 헤드 `id2label` 출력과 원격 모델링 코드 검토 | 로컬 + Kaggle | 노트북, 환경 확인 결과 |
| P1 데이터 점검·전처리 | 두 데이터셋을 공통 스키마로 변환, 정제, 클래스별 scheme 분포 점검 | Kaggle | 정제 CSV, 점검 리포트 |
| P2 그룹 분리 | 등록 도메인(IP면 IP) 단위로 70:15:15 분리, 누수 검사, PhiUSIIL 겹치는 도메인 제거 | Kaggle | train/val/test 분할 파일 |
| P3 기준선 | 제공 `malicious_urls_4class` 헤드를 우리 test 세트로 평가 (점수 부풀려짐 명시) | Kaggle | 기준선 지표 |
| P4 우리 헤드 학습 | 인코더 고정, CLS+MEAN 임베딩을 한 번만 계산, {raw, strip} × {Linear, MLP} 비교 | Kaggle GPU | 헤드 가중치 |
| P5 평가 | 필수 지표 7종, PhiUSIIL 일반화 평가, CPU 추론 시간 | Kaggle | metrics.json, 그래프 |
| P6 위험도 임계값 | val 세트로 낮음·주의·위험 경계 결정 | Kaggle | thresholds.json |
| P7 서버용 추론 모듈 | `UrlRiskClassifier`와 연동 문서 | 로컬 | infer.py, docs/model_api.md |

### 폴더 구조

```
Qsing/
├─ work_history.md                  ← 페이즈별 작업 기록 (아래로만 추가, 기존 내용 수정·삭제 금지)
├─ docs/
│  ├─ specs/2026-11-09-urlbert-model-design.md
│  └─ model_api.md                  ← P7, 서버 담당자용 연동 문서
└─ model/
   ├─ qsing_model/                  ← 모든 로직 (data, split, embed, head, train, evaluate, risk, infer)
   ├─ tests/                        ← 단위 테스트
   ├─ notebooks/qsing_kaggle.ipynb  ← 패키지를 불러와 페이즈 순서대로 실행만 함
   └─ artifacts/                    ← 학습 결과물 (P4~P6)
```

- 노트북에는 로직을 두지 않는다. 학습과 추론이 같은 전처리 코드를 쓰게 하기 위해서다(제안서 2.2절).
- Kaggle로 코드를 옮길 때는 `model/`을 zip으로 묶어 Kaggle Dataset으로 업로드한다.
- Kaggle 노트북에서 인터넷(모델 다운로드, pip)을 켜려면 Kaggle 계정의 휴대폰 인증이 필요하다.

---

## 2. 데이터 전처리와 분리 규칙

### 2.1 공통 스키마와 라벨

공통 컬럼: `url, label, source, collected_at` (+ 처리 중 `group_key`, `split`)

| 출처 | 원본 | 변환 | 용도 |
|---|---|---|---|
| Malicious URLs (`sid321axn/malicious-urls-dataset`) | `url`, `type` ∈ {benign, phishing, malware, defacement} | `label = type` | 4종 학습·검증·평가 |
| PhiUSIIL (UCI 967) | `URL`, `label` (1=정상, 0=피싱). 나머지 특징 컬럼은 사용 안 함 | 1→`benign`, 0→`phishing` | **일반화 평가 전용 (학습 금지)** |
| 사용자 신고 | — | `source=user_report` | 스키마만 지원. 이번 범위에서 구현 안 함 |

- `source`: 데이터셋 식별자. `collected_at`: 데이터를 받은 날짜(ISO 8601).
- 4종 라벨 순서는 `benign, phishing, malware, defacement`로 고정하고 모든 산출물에서 이 순서를 쓴다.

### 2.2 정제 규칙

1. 앞뒤 공백을 제거한다. 빈 URL과 호스트를 추출할 수 없는 URL은 버린다.
2. 완전히 같은 URL에 같은 라벨이면 하나만 남긴다.
3. 충돌 검사는 비교용 키로 한다. 비교용 키는 앞쪽 scheme과 `www.`를 떼고 호스트를 소문자로 바꾼 값이다. 같은 키에 서로 다른 라벨이 붙어 있으면 해당 행을 모두 제외한다.
4. 경로와 쿼리는 대소문자까지 보존한다.
5. 단계별로 제거된 건수를 점검 리포트에 기록한다.

### 2.3 그룹 키

- 등록 도메인을 그룹 키로 쓴다(예: `login.secure.example.co.kr` → `example.co.kr`). 추출은 `tldextract`를 내장 Public Suffix List 스냅샷으로 오프라인 모드(`suffix_list_urls=()`)로 실행해 결과를 고정한다.
- 호스트가 IP 주소(IPv4/IPv6)면 IP 자체가 그룹 키다.
- scheme이 없는 URL은 도메인을 추출할 때만 `http://`를 임시로 붙인다. 저장되는 URL은 바꾸지 않는다.
- 포트와 사용자정보(`user@`)는 그룹 키에서 제외한다.

### 2.4 70:15:15 분리

- `StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=42)`로 폴드 20개를 만들고 train 14개, val 3개, test 3개로 묶는다.
- 분리 후 검사 (하나라도 실패하면 P2가 실패로 끝난다):
  - 세트 간 그룹 키 교집합이 0
  - 세트별 클래스 비율이 전체 비율과 ±2%p 이내
  - URL 수 상위 20개 도메인 목록을 리포트에 출력
- test 세트는 P5에서만 사용한다. 모델 선택(P4)과 임계값 결정(P6)은 val 세트로만 한다.

### 2.5 PhiUSIIL 일반화 평가 세트

- Malicious URLs의 어느 세트에든 등장한 그룹 키는 PhiUSIIL에서 제거한다.
- 남은 데이터 전체를 "정상 vs 정상 아님" 이진 평가에 쓴다. 판정에는 우리 모델의 `P(benign)`을 사용한다.

### 2.6 scheme 편향 점검과 비교 실험

- P1: 클래스별로 `http://`, `https://`, scheme 없음, `www.` 시작 비율을 표로 출력한다.
- P4: 모델 입력을 두 버전으로 만든다.
  - `raw`: URL을 그대로 입력
  - `strip`: 앞쪽 `http(s)://`와 `www.`를 제거하고 입력
- **모델 선택은 val Macro F1로만** 한다. PhiUSIIL 결과는 두 버전 모두 참고용으로 보고한다.
- 선택된 정규화 방식은 `model_config.json`에 기록하고 `infer.py`가 같은 방식을 적용한다.

---

## 3. 학습·평가·위험도

### 3.1 P3 기준선 (제공 헤드)

- 로딩: `AutoModelForSequenceClassification.from_pretrained(REPO, subfolder="heads/malicious_urls_4class", trust_remote_code=True, revision=<고정 커밋 해시>)`
- `trust_remote_code=True`는 저장소의 파이썬 코드를 실행한다. 따라서 P0에서 커밋 해시를 고정하고 원격 모델링 코드를 출력해 검토한다.
- `id2label`을 우리 라벨 4종에 매핑한 뒤 test 세트로 평가한다. 결과에는 "학습 데이터와 겹쳐 점수가 부풀려졌을 수 있음"을 명시한다.
- 평가는 3.3절과 같은 함수로 한다.

### 3.2 P4 우리 헤드

임베딩
- 인코더를 FP16으로 실행한다. [CLS] 벡터(128)와 attention mask 기준 평균 벡터(128)를 이어 붙여 256차원을 만든다.
- 토큰화는 `truncation=True, max_length=256`으로 한다. 길이순으로 정렬해 배치를 만들고, 잘린 URL에는 플래그를 기록한다.
- 결과는 `.npy`(float16)로 저장한다. raw와 strip 두 버전을 만든다(각 약 330MB).

헤드 후보
- Linear: 256 → 4
- MLP: 256 → 128 → 4 (GELU, dropout 0.1)

학습 설정
- AdamW, lr 1e-3, weight decay 0.01, 배치 2048
- 최대 30 epoch. val Macro F1이 3 epoch 연속 개선되지 않으면 조기 종료
- 클래스 가중치: `balanced` (클래스 빈도에 반비례)

실험
- {raw, strip} × {Linear, MLP} 4개 조합을 val Macro F1로 비교해 하나를 선택한다.
- 선택된 조합은 시드 3개(42, 43, 44)로 다시 학습해 평균±표준편차를 보고한다. 산출물로는 시드 42 모델을 쓴다.
- 실제 소요 시간을 work_history.md에 기록한다.

### 3.3 P5 평가 — 필수 지표 (제안서 3.4절)

일곱 항목은 **필수**다. `evaluate.py`의 단일 함수가 모두 계산하고, 하나라도 빠지면 예외를 발생시켜 P5를 멈춘다.

| 항목 | `metrics.json` 키 | 정의 |
|---|---|---|
| Accuracy | `accuracy` | 4종 예측이 정답과 일치한 비율 |
| 클래스별 Precision·Recall·F1 | `per_class.{benign,phishing,malware,defacement}.{precision,recall,f1,support}` | 클래스별 계산. support는 표본 수 |
| Macro F1 | `macro_f1` | 4개 클래스 F1의 단순 평균 |
| 혼동행렬 | `confusion_matrix` (+ `confusion_matrix.png`) | 행=정답, 열=예측. 라벨 순서 고정 |
| 정상 URL 오탐률 | `benign_fpr` | 정답 benign 중 benign이 아니라고 판정된 비율 |
| 악성 URL 미탐률 | `malicious_fnr` | 정답 악성(phishing·malware·defacement) 중 benign으로 판정된 비율 |

- 4종 지표(Accuracy~혼동행렬)는 argmax 판정 기준이다.
- `benign_fpr`, `malicious_fnr`는 두 기준으로 낸다.
  - `decision=argmax`: argmax 결과가 benign인지로 판정
  - `decision=threshold`: P6 위험도가 주의 이상이면 악성으로 판정
- 평가 범위:
  - Malicious URLs test 세트: 일곱 항목 전부
  - PhiUSIIL 일반화 세트: 정답이 2종뿐이므로 `benign_fpr`, `malicious_fnr`, AUROC만 산출 (4종 지표를 내지 않는다, 제안서 2.1절)
- 비교표: 기준선(제공 헤드) vs 우리 헤드, 같은 test 세트와 같은 함수로 비교
- 추론 시간(AI 단독 분석 시간): CPU에서 URL 1개씩 처리할 때 p50·p95 지연, 배치 처리량. Kaggle CPU 기준임을 명시한다.
- 이번 범위 밖 (13주차 통합 단계에서 측정): 외부 검사 포함 응답 시간, 앱·서버 통신 성공률

### 3.4 P6 위험도 임계값 (val 세트로만 결정)

- `ai_risk_score = 1 − P(benign)`. 이 값은 모델 예측 점수이며 실제 피해 확률이 아니다(제안서 3.3절).
- `t_high`(위험 기준): val 정상 URL 중 `risk ≥ t_high`인 비율이 1% 이하가 되는 가장 작은 값
- `t_low`(주의 기준): val 악성 URL 중 `risk ≥ t_low`인 비율이 99% 이상이 되는 가장 큰 값
- 판정: `risk < t_low` → `low`, `t_low ≤ risk < t_high` → `caution`, `risk ≥ t_high` → `danger`
- 1%와 99%는 초기 목표값이며 측정 후 팀이 조정할 수 있다(설정값으로 분리).
- `t_low ≥ t_high`이면 두 목표를 동시에 만족할 수 없다는 뜻이다. 이 경우 임계값을 자동으로 정하지 않고 결과를 보고해 팀의 결정을 받는다.
- VirusTotal 결과와의 통합 판정은 서버 파트 범위다.

### 3.5 산출물 (`model/artifacts/`)

| 파일 | 내용 |
|---|---|
| `encoder/` | 고정 리비전 인코더와 토크나이저 (`save_pretrained`, 약 8MB) |
| `head.pt` | 헤드 가중치 |
| `model_config.json` | 인코더 리비전, 풀링, 정규화 방식(raw/strip), 헤드 구조, 라벨 순서, 학습 날짜 |
| `thresholds.json` | `t_low`, `t_high`, 목표값(1%, 99%), 결정에 쓴 세트 |
| `metrics.json` | 3.3절 지표 (test, PhiUSIIL, 기준선) |
| `confusion_matrix.png` | 혼동행렬 그림 |

---

## 4. 서버용 추론 모듈 (`qsing_model/infer.py`)

### 4.1 사용법

```python
from qsing_model.infer import UrlRiskClassifier

clf = UrlRiskClassifier.from_artifacts("model/artifacts", device="cpu")  # 서버 시작 시 1회 로드
result = clf.predict("http://secure-login.example.xyz/verify?id=1")
results = clf.predict_batch([...])
```

- `artifacts/`만 있으면 인터넷 없이 실행된다.
- 서버 의존성: `torch`(CPU), `transformers`, `tldextract`
- 정규화와 풀링은 `model_config.json`을 읽어 학습 때와 똑같이 적용한다.
- 추론은 `torch.inference_mode()`에서 실행하고, 스레드 수는 인자로 설정할 수 있다.

### 4.2 반환 형식 (`status = "ok"`)

```json
{
  "status": "ok",
  "url": "http://secure-login.example.xyz/verify?id=1",
  "predicted_type": "phishing",
  "scores": {"benign": 0.03, "phishing": 0.91, "malware": 0.04, "defacement": 0.02},
  "ai_risk_score": 0.97,
  "risk_level": "danger",
  "truncated": false,
  "signals": {
    "is_ip_host": false, "subdomain_depth": 1, "has_at_symbol": false,
    "has_punycode": false, "url_length": 44, "is_known_shortener": false
  },
  "model_version": "urlbert-tiny-v6@<P0에서 고정한 커밋 해시>+head-<학습 날짜>"
}
```

- `risk_level` ∈ {`low`, `caution`, `danger`} ↔ 앱의 낮음·주의·위험
- `signals`: URL 규칙 점검 결과(제안서 3.3절). URL에서 관찰된 보조 정보이며 AI의 판단 이유가 아니다.
- `is_known_shortener`: 유명 단축 URL 서비스 도메인인지만 표시한다. 최종 목적지는 확인하지 않는다(제안서 4.3절 확장 기능).

### 4.3 오류·예외 처리 — 검사 못 한 URL을 안전으로 내보내지 않음 (제안서 1.3절)

| 상황 | `status` | `risk_level` | `scores` |
|---|---|---|---|
| 빈 값, 문자열 아님, 호스트 추출 불가 | `invalid_url` | `null` | `null` |
| `http`·`https` 이외 scheme (`javascript:`, `data:`, `intent:`, `tel:` 등) | `unsupported_scheme` | `null` | `null` |
| 2048자 초과 또는 256토큰 초과 | `ok` + `truncated: true` | 정상 계산 | 정상 계산 |
| 모델 내부 오류 | `ModelError` 예외 → 서버가 "검사 실패"로 처리 | — | — |

`risk_level = null`은 앱에서 "확인 불가"로 표시한다. `low`는 모델이 실제로 점수를 계산했을 때만 나온다.

### 4.4 함께 제공

- `docs/model_api.md`: 반환 형식, FastAPI 시작 시 로드 예제, 응답 시간 측정값, 한계(웹페이지 내용과 단축 URL 목적지는 확인하지 않음)
- 단위 테스트: 4.3절 각 상황과 반환 형식의 필수 키. 가짜 모델로 실행해 실제 모델 없이도 돌아간다.

---

## 5. 테스트 계획

| 대상 | 방법 | 실행 위치 |
|---|---|---|
| 등록 도메인 추출 (서브도메인, `co.kr`, IP, scheme 없음, 포트, `user@`) | pytest | 로컬 (의존성이 없으면 Kaggle 첫 셀) |
| 정제 (중복, 충돌 제거, 경로·쿼리 보존) | pytest | 위와 같음 |
| 분리 (세트 간 그룹 교집합 0, 비율 검사) | pytest + P2 실행 시 검사 | 로컬 + Kaggle |
| `strip` 정규화 | pytest | 로컬 |
| 필수 지표 7종 (손계산 예제와 비교, 키 누락 시 예외) | pytest | 로컬 |
| 임계값 결정 (목표 충족, `t_low ≥ t_high` 처리) | pytest | 로컬 |
| 추론 모듈 반환 형식과 오류 처리 | pytest (가짜 모델) | 로컬 |
| 실제 학습·평가 | 노트북 실행 | Kaggle (사용자 실행) |

## 6. 범위 밖

- FastAPI 서버, VirusTotal 연동, DB (김다은)
- Android 앱 (이송월)
- 인코더 전체 파인튜닝 (C안, 일정 여유 시)
- 사용자 신고 데이터 재학습 파이프라인
- 단축 URL·리디렉션 최종 목적지 추적

---

## 개정 1 (2026-11-09) — 외부 최신 데이터 평가 추가

> 기존 섹션은 수정하지 않고 이 개정 사항을 덧붙인다. 아래 내용이 기존 섹션과 겹치면 이 개정이 우선한다.

### 배경

4종 test 점수는 Malicious URLs 한 출처에서 나온 수치다. 도메인 단위 분리로 누수는 막지만 출처·수집 시기가 같아서, 실제 서비스 환경의 성능을 대표한다고 보기 어렵다. 출처와 수집 시기가 모두 다른 최신 URL로 **평가 전용** 세트를 추가한다.

학습에는 섞지 않는다. 클래스마다 출처가 하나씩이면(malware=URLhaus, phishing=OpenPhish, benign=Tranco) 모델이 위험 여부가 아니라 출처의 URL 모양을 학습할 수 있기 때문이다. 다양한 출처를 학습에 섞는 실험은 확장 과제로 남기고, 그때는 "URL만 보고 출처를 맞히는지" 검사를 함께 수행한다.

### 평가 출처 (P1에서 스냅샷 수집)

| 출처 | 매핑 라벨 | 접근 방법 | 이용 조건 | 비고 |
|---|---|---|---|---|
| URLhaus (abuse.ch) | malware | 무료 abuse.ch Auth-Key로 최근 30일 CSV 다운로드 | 공정 이용 원칙, 상업적 이용은 유료 | 필수 |
| OpenPhish Community Feed | phishing | GitHub `openphish/public_feed` (12시간마다 갱신) | 비상업적 이용만 허용 | 필수. 며칠에 걸쳐 여러 스냅샷을 합쳐 표본 확보 |
| Tranco Top 1M | benign | tranco-list.eu, 고정 list ID 사용 | 연구용 공개 | 필수. 도메인만 있으므로 `https://<domain>/` 형태로 변환 |
| PhishTank online-valid | phishing | 키 없이 수동 다운로드 (하루 다운로드 횟수 제한) | 제한적 라이선스 | 선택. 신규 회원가입이 막혀 있어 키 발급 불가 |
| defacement | — | 적절한 공개 출처 없음 | — | **외부 평가 범위에서 제외**, 결과 문서에 명시 |

### 수집·전처리 규칙

1. 각 출처를 정해진 날짜에 한 번 내려받아 파일로 고정하고, 그 파일을 Kaggle Dataset으로 올린다. 수집 날짜와 Tranco list ID를 기록한다.
2. URL은 문자열로만 다룬다. **어떤 URL에도 접속하지 않는다**(제안서 2.2절).
3. 2.2절과 같은 정제 규칙을 적용한다.
4. Malicious URLs 어느 세트에든 등장한 그룹 키는 제거하고, 제거 건수를 기록한다. 공유 호스팅 도메인에 올라간 악성 URL이 함께 제거될 수 있으므로 이 수치도 리포트에 남긴다.
5. Tranco 도메인 중 URLhaus·OpenPhish·PhishTank에 등장한 그룹 키는 benign 세트에서 제거한다.
6. Tranco는 상위 100,000개 중 10,000개를 무작위로 뽑는다(시드 42).

### 평가 지표

이 세트는 출처마다 클래스가 하나뿐이고 클래스 간 비율이 우리가 정한 값이다. 그래서 비율에 따라 값이 바뀌는 Precision, Macro F1, Accuracy는 의미가 없어 **산출하지 않는다**. 대신 출처별로 다음을 낸다.

| 출처 | 지표 | 키 |
|---|---|---|
| URLhaus, OpenPhish, (PhishTank) | 악성 URL 미탐률 (정답이 악성인데 benign으로 판정된 비율) | `external.<source>.malicious_fnr` |
| 위와 같음 | 유형 일치율 (예측 유형 = 매핑 라벨인 비율) | `external.<source>.type_match_rate` |
| Tranco | 정상 URL 오탐률 | `external.tranco.benign_fpr` |
| 전체 | 표본 수, 제거 건수, 95% Wilson 신뢰구간 | `external.<source>.n`, `.removed`, `.ci95` |

- 오탐률·미탐률은 3.3절과 같이 `decision=argmax`와 `decision=threshold` 두 기준으로 낸다.
- 표본이 수백~수천 건 규모일 수 있으므로 신뢰구간을 함께 보고한다.
- 3.3절의 필수 지표 7종은 Malicious URLs test 세트 기준으로 그대로 유지한다.

### 한계 (결과 문서에 명시)

- Tranco 기반 정상 URL은 홈페이지 형태뿐이다. 경로·쿼리가 긴 실제 정상 URL에서의 오탐률은 이보다 높을 수 있다.
- defacement 유형은 외부 평가를 하지 못한다.
- 피드는 "그 시점에 신고된 악성 URL"이라 라벨에 오류가 섞여 있을 수 있다.

### 페이즈 변경

- P1: 외부 출처 스냅샷 수집·정제 추가 (OpenPhish는 여러 날에 걸쳐 수집)
- P5: "P5-ext 외부 최신 데이터 평가" 추가
- 산출물: `metrics.json`에 `external` 항목 추가
