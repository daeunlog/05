# 큐싱 탐지 앱 — 작업 기록

> 페이즈별 작업 내용을 기록한다. 새 내용은 항상 아래에 추가하며 기존 내용은 수정·삭제하지 않는다.

---

## 2026-11-09 · 설계 단계

### 결정 사항
- 범위: AI 모델 파트부터 진행 (데이터·URLBERT·평가·서버용 추론 모듈)
- 학습 환경: Kaggle Notebook (GPU)
- 접근법: B안 — 기본 인코더 위에 4종 헤드를 직접 학습, 제공 `malicious_urls_4class` 헤드는 기준선
  - 이유: 모델 카드상 제공 헤드가 Malicious URLs Dataset·PhiUSIIL로 학습되어, 이 데이터로 평가하면 성능이 부풀려짐
- 필수 평가 지표 7종 고정: Accuracy, 클래스별 Precision·Recall·F1, Macro F1, 혼동행렬, 정상 URL 오탐률, 악성 URL 미탐률

### 페이즈 계획
P0 환경 준비 → P1 데이터 점검·전처리 → P2 그룹 분리 → P3 기준선 → P4 헤드 학습 → P5 평가 → P6 위험도 임계값 → P7 서버용 추론 모듈

### 산출물
- `docs/specs/2026-11-09-urlbert-model-design.md` (설계 문서)
- `work_history.md` (이 파일)

### 메모
- 로컬 작업 환경: GPU·인터넷·PyTorch 없음 → 학습은 Kaggle에서 사용자가 실행
- Qsing 폴더는 git 저장소가 아님 (커밋 생략)
- 로컬 패키지 확인: pandas·numpy·matplotlib 있음 / pytest·scikit-learn·tldextract 없음 → 이 셋에 의존하는 테스트는 Kaggle 첫 셀에서 실행, 나머지는 표준 라이브러리(unittest)로 로컬 실행

---

## 2026-11-09 · 설계 개정 1 — 외부 최신 데이터 평가 추가

### 결정 사항
- 학습 데이터는 Malicious URLs 유지. 추가 데이터는 **평가 전용**으로만 사용
  - 이유: 클래스마다 출처가 하나씩이면 모델이 위험 여부 대신 출처의 URL 모양을 학습할 위험
- 평가 출처: URLhaus(malware), OpenPhish Community Feed(phishing), Tranco(benign), PhishTank(phishing, 선택)
- defacement는 공개 출처가 없어 외부 평가에서 제외
- 외부 세트에서는 Precision·Macro F1을 내지 않고 출처별 미탐률·오탐률·유형 일치율과 95% 신뢰구간 보고

### 확인한 출처 현황 (2026-11-09)
- URLhaus: 무료 abuse.ch Auth-Key 필요, 공정 이용 원칙, 상업적 이용은 유료
- OpenPhish Community Feed: 12시간마다 갱신, 비상업적 이용만 허용
- PhishTank: 신규 회원가입이 막혀 있음, 키 없이 하루 몇 번만 다운로드 가능
- Tranco: 연구용 Top 1M 목록, 고정 list ID로 재현 가능

### 변경 파일
- `docs/specs/2026-11-09-urlbert-model-design.md` — 하단에 "개정 1" 섹션 추가 (기존 내용 수정 없음)
- 교수님 설명 문서 작성 예정
- 교수님 설명 문서 작성 완료 (Claude Docs): https://claude.ai/artifact/W3XoLpTXhhmLtwitcFzN6t
  - 내용: 데이터셋별 역할, 제공 헤드 대신 직접 학습하는 이유, 추가 데이터를 학습에 섞지 않는 이유, 분리 규칙, 필수 지표 7종, 외부 최신 데이터 평가, 위험도 산출, 한계, 일정
  - 일정 가정: 11/24 서버 담당에게 모델 전달 (팀 확인 필요)


---

## 2026-11-10 · 구현 — P0~P7 코드와 Kaggle 노트북

### 페이즈별 작업
| 페이즈 | 구현 | 위치 |
|---|---|---|
| 기반 | 4종 라벨 순서, URL 파싱(scheme 판별·호스트·등록 도메인·정규화·보조 신호) | `model/qsing_model/labels.py`, `urls.py` |
| P0 | 환경 확인, 저장소 커밋 해시 고정, 제공 헤드 원격 코드 출력 | `pipeline.p0_environment`, `baseline.py` |
| P1 | 데이터 로더(Malicious URLs, PhiUSIIL, URLhaus, OpenPhish, PhishTank, Tranco), 정제, scheme 분포 점검, 외부 평가 세트 구성 | `data.py`, `pipeline.p1_prepare` |
| P2 | StratifiedGroupKFold 20폴드 → 14/3/3, 도메인 교집합·비율(±2%p) 검사 | `split.py`, `pipeline.p2_split` |
| P3 | 제공 헤드 기준선 평가 (라벨 자동 매핑, max_length 보정) | `baseline.py`, `pipeline.p3_baseline` |
| P4 | CLS+MEAN 임베딩(FP16, 길이순 배치, 잘림 표시), Linear/MLP 헤드 학습(AdamW, balanced 가중치, 조기 종료) | `embed.py`, `head.py`, `train.py`, `pipeline.p4_*` |
| P6 | val 기준 임계값 (정상 1% 이하 위험, 악성 99% 이상 주의 이상) | `risk.py`, `pipeline.p6_thresholds` |
| P5 | 필수 지표 7종(누락 시 예외), PhiUSIIL 이진 평가·AUROC, 외부 출처별 지표·Wilson 95% CI, 기준선 비교, 혼동행렬 그림, scheme 변형 test | `metrics.py`, `pipeline.p5_evaluate` |
| P7 | 서버용 `UrlRiskClassifier`, artifacts 내보내기(인코더 포함), 학습-서버 일치율, CPU 추론 시간 | `infer.py`, `pipeline.p7_export` |
| 노트북 | 코드 복사·패키지 확인 → 단위 테스트 → 입력 자동 탐색 → P0 → 리허설(6천 건) → 본 실행 → 요약 | `model/notebooks/qsing_kaggle.ipynb` |

### 테스트 (로컬, torch 없음)
- `python -m pytest model/tests` → 37 통과, 1 건너뜀(torch와 numpy 헤드 비교 — Kaggle에서 실행)
- 파이프라인 리허설: 가짜 임베더·가짜 학습기로 P1→P2→P4→P6→P5→P7 전체 흐름과 산출물 형식 확인

### 구현 중 발견해 바꾼 것 (설계 개정 2 → `docs/specs/2026-11-10-urlbert-model-design-개정2.md`)
1. **임계값 판단 정정**: `t_low ≥ t_high`는 "목표 동시 충족 불가"가 아니라 "두 목표가 이미 함께 충족(잘 갈림)"이다. 이 경우 '주의' 구간을 비우고 `status=separated`로 보고
2. **모델 선택 기준 보강**: val Macro F1 → val Macro F1의 **최저값**(원본 / scheme 제거 / https 추가). 리허설에서 raw 모델이 scheme 지름길을 학습해 원본 val 1.00, 변형 val 0.57이 나옴
3. 실행 순서 P6 → P5 (임계값 기준 오탐·미탐률에 P6 결과 필요, P6은 val만 사용)
4. 헤드 저장을 `head.npz`로 (pickle 미사용), 서버 헤드 계산은 numpy
5. 리허설 단계, 학습-서버 일치율, artifacts 기반 CPU 추론 시간 측정 추가

### 문서
- `docs/model_api.md` — 서버 연동 안내 (FastAPI 예시, 반환 형식, 상태별 처리)
- `model/README.md` — 집/Kaggle에서 실행하는 순서, 막힐 때 조치
- 교수님 설명 문서(Claude Docs) 정정 2곳(임계값 판단, 모델 선택 기준) → `docs/URLBERT_큐싱탐지모델_데이터셋평가계획.pdf` 다시 내보냄

### 다음 할 일
- [ ] Kaggle에 `qsing-code`, PhiUSIIL, (선택) 외부 데이터 업로드 후 노트북 Run All
- [ ] 노트북 마지막 셀의 실행 결과 요약을 이 파일 아래에 붙여넣기
- [ ] `qsing_artifacts.zip`을 `model/artifacts/`에 풀고 김다은 님께 전달 (11/24 목표, 팀 확인 필요)

---

## 2026-11-12 · 실행 — 페이즈 계획

### 상황
- 11/10 구현 파일을 Qsing 폴더에 배치 (`_archive/Qsing_2026-11-10.zip`에서 복사, work_history는 11/10 기록만 덧붙임)
- 로컬 PC 작업 환경과 클라우드 작업 환경 모두 인터넷·PyTorch 없음 → 학습은 Kaggle GPU에서 실행, Kaggle 조작은 Claude 앱 내장 브라우저로 진행
- 업로드를 줄이기 위해 **자급식 노트북** 사용: 코드를 노트북에 내장하고, PhiUSIIL·OpenPhish·Tranco는 노트북이 직접 다운로드. Kaggle에서는 노트북 1개 + Malicious URLs 데이터셋 연결만 필요

### 페이즈
| 페이즈 | 내용 | 위치 |
|---|---|---|
| P0 준비 | 파일 배치, 로컬 테스트, 자급식 노트북 생성, Kaggle 접속·로그인 확인 | 로컬 + 브라우저 |
| P1 데이터 점검·전처리 | Malicious URLs 정제, scheme 분포, PhiUSIIL·외부 데이터 다운로드·정제 | Kaggle |
| P2 그룹 분리 | 도메인 단위 70:15:15 + 누수 검사 | Kaggle |
| P3 기준선 | 제공 malicious_urls_4class 헤드 평가 | Kaggle |
| P4 임베딩·헤드 학습 | {raw, strip} × {Linear, MLP}, val Macro F1 최저값으로 선택, 시드 3개 | Kaggle GPU |
| P6 위험도 임계값 | val 기준 t_low, t_high | Kaggle |
| P5 평가 | 필수 지표 7종, PhiUSIIL, 외부, 기준선 비교, scheme 변형 | Kaggle |
| P7 산출물 | artifacts 내보내기, 학습-서버 일치율, CPU 추론 시간 | Kaggle |
| P8 결과 회수·기록 | 결과 다운로드 → `model/artifacts`, 리포트 정리, 이 파일에 결과 기록 | 로컬 |

### P0 진행
- [x] 파일 배치 (24개)
- [x] 로컬 테스트: 38개 실행, 통과 (scikit-learn·torch가 없어 3개 건너뜀 — Kaggle 첫 셀에서 전체 실행)
- [x] 자급식 노트북 생성: `model/notebooks/qsing_kaggle_selfcontained.ipynb` (코드 zip 내장, PhiUSIIL·OpenPhish·Tranco 자동 다운로드, URLhaus는 Auth-Key가 없어 이번엔 건너뜀)
- [x] Kaggle 로그인·휴대폰 인증 (사용자 진행)
- [x] Kaggle 노트북 `qsing-urlbert-train` 생성 (Import), 입력: Malicious URLs dataset, GPU T4 x2, Internet On
- [x] 2026-11-12 21:57 "Save & Run All (Commit)" 시작 — 버전 이름 `P1-P7 full run`
- [ ] Version 1 실패 (43초): 단위 테스트에서 그룹 분리 클래스 비율이 11.69%p 어긋남 (Kaggle scikit-learn의 StratifiedGroupKFold). 다른 테스트 36개는 통과(torch↔numpy 헤드 일치 포함). Kaggle 환경: Python 3.13, torch 2.11, transformers 5.20
  - 조치: 분리 방법을 "큰 그룹부터 순차 배정"으로 교체 → 같은 데이터에서 최대 0.14%p. 초대형 도메인 테스트 추가. transformers 5.x 저장 인자 대비 (`docs/specs/2026-11-12-urlbert-model-design-개정3.md`)
  - 노트북 재생성 후 Kaggle에 다시 Import 필요
- [x] 2026-11-12 22:03 Version 2 "P1-P7 full run v2 (split fix)" 시작 — 단위 테스트 39개 통과
  - 외부 데이터 수집(2026-11-12): PhiUSIIL(UCI zip), OpenPhish 피드 300줄(GitHub public_feed), Tranco list ID `PY2NJ` (https://tranco-list.eu/list/PY2NJ/), URLhaus는 건너뜀
  - 모델 저장소 커밋 고정: `020744435b3be870dabb2bba0b41237bea69b84b`
  - 제공 헤드 원격 코드 검토: SmartHead 모델(인코더 + CLS·MEAN 풀링 + 분류 헤드). 파일 쓰기·외부 전송 없음. 단, 헤드가 인코더를 `encoder_name_or_path`로 다시 내려받을 때 커밋을 고정하지 않음 → 기준선(P3)만 해당, 우리 모델과 서버 추론에는 영향 없음
- [x] 2026-11-12 22:19 Version 2 완료 (P0~P7 전체, 리허설 포함). 출력: `qsing_artifacts.zip`(서버용), `qsing_reports.zip`(지표·리포트)

---

## 2026-11-12 · 모델 학습·평가 실행 결과 (Kaggle Version 2)

### 페이즈별 결과
- P1 Malicious URLs 정제: 입력 651,191 → 632,812 (형식 오류·미지원 89, 중복 10,065, 라벨 충돌 8,225)
  - 클래스별: benign 423,928 / defacement 95,308 / phishing 89,931 / malware 23,645
- P2 분리: train 442,969 / val 94,922 / test 94,921, 세트 간 도메인 교집합 0, 최대 클래스 비율 차이 0.001%p
- P3 기준선(제공 헤드, 학습 데이터와 겹쳐 부풀려졌을 수 있음): test Accuracy 0.9907, Macro F1 0.9808
- P4 조합별 val Macro F1 (원본 / scheme 변형 포함 최저)
  - raw+linear 0.8975 / 0.5169, raw+mlp 0.9339 / 0.5772, strip+linear 0.7732 / 0.7732, **strip+mlp 0.8287 / 0.8287 (선택)**
  - 시드 3개 평균 0.8289 ± 0.0003
- P6 임계값: t_low 0.2511, t_high 0.9860 (overlap)
- P5 test (우리 헤드, strip+mlp)
  - Accuracy 0.8429, Macro F1 0.8255
  - benign P 0.9828 / R 0.8031 / F1 0.8839 (n=63,589)
  - phishing P 0.5289 / R 0.9083 / F1 0.6685 (n=13,489)
  - malware P 0.8473 / R 0.8638 / F1 0.8555 (n=3,547)
  - defacement P 0.8422 / R 0.9531 / F1 0.8942 (n=14,296)
  - 정상 URL 오탐률: argmax 0.1969, 임계값(주의 이상) 0.3079
  - 악성 URL 미탐률: argmax 0.0285, 임계값 0.0101
  - scheme 변형 test(scheme 제거, https 추가): Macro F1 0.8255로 동일 (strip 정규화라 영향 없음)
- PhiUSIIL 일반화(선택 모델): AUROC 0.4322, 정상 오탐률 0.9919, 악성 미탐률 0.0432
- 외부 OpenPhish (n=275): 악성 미탐률 0.0727 [95% CI 0.0476–0.1097]
- 외부 Tranco 홈페이지 (n=9,093): 정상 오탐률 0.2408 [95% CI 0.2322–0.2497]
- P7 CPU 추론(Kaggle CPU 2스레드): URL 1개 p50 5.3ms, p95 8.6ms, 배치 1,179 URL/초
- 학습(GPU fp16) vs 서버(CPU fp32) 예측 일치율 0.998

### 해석 (객관적으로)
1. **scheme 지름길이 실제 데이터에서도 확인됨**: raw 모델은 원본 val에서 0.93이지만 scheme만 바꾸면 0.52~0.58로 떨어짐. 선택 기준을 "최저값"으로 보강한 것(개정 2)이 없었다면 raw+mlp가 선택됐을 것
2. **같은 출처 test 성능은 중간 수준**: Macro F1 0.83, 정상 URL 5개 중 1개를 악성으로 판정, 피싱 정밀도 0.53
3. **다른 출처 일반화가 매우 나쁨**: PhiUSIIL 정상 URL의 99%를 악성으로 판정, AUROC 0.43(무작위보다 낮음). Tranco 인기 사이트 홈페이지도 24% 오탐
4. 가설(미검증): Malicious URLs의 benign은 경로가 긴 URL 위주이고 도메인만 있는 URL(홈페이지)이 적어, 모델이 "도메인만 있으면 악성"을 학습했을 가능성. P1 데이터에서 클래스별 '경로 없는 URL' 비율을 재서 확인해야 함
5. 결론: **현재 모델은 서비스에 그대로 쓰기 어려움** (정상 사이트 오탐이 너무 많음). 제공 헤드의 0.98은 학습 데이터 중복 때문일 수 있어 비교 근거가 되지 못함

### 다음 결정 필요 (팀)
- 결과 파일(`qsing_artifacts.zip` 약 7.8MB, `qsing_reports.zip`) 다운로드 → `model/artifacts`, `docs/results/`
- 개선 방향 선택: (a) 경로 없는 정상 URL 편향 확인 후 학습 데이터 보강(출처 편향 검사 포함) (b) 인코더 파인튜닝(C안) (c) 현재 결과를 한계와 함께 그대로 보고

---

## 2026-11-12 · 개선 v3 — 페이즈 계획 (방향 (a), 사용자 위임)

| 페이즈 | 내용 |
|---|---|
| P9 결과 회수 | v2 출력(`qsing_artifacts.zip`, `qsing_reports.zip`) 다운로드 → `model/artifacts_v2/`, `docs/results/v2/` |
| P10 원인 확인 | 클래스별 '경로 없는 URL(홈페이지 형태)' 비율 측정 → 가설 검증 |
| P11 보강 학습 | train 세트 정상 URL의 호스트로 홈페이지 형태(`https://호스트/`)를 만들어 정상으로 추가. 악성 URL에 한 번이라도 나온 호스트는 제외(변조 사이트 등 라벨 모호). 같은 도메인이라 분리 세트가 바뀌지 않음 → 누수 없음. 새 출처를 쓰지 않으므로 출처-클래스 혼입 없음 |
| P12 평가 | v2와 같은 test·PhiUSIIL·외부 세트로 비교 + val/test 홈페이지 형태 오탐률. 선택 기준에 '홈페이지 형태 val' 추가(최저값) |
| P13 기록 | 결과·비교·결정 기록 |

- 정규화는 strip만 사용 (v2에서 raw는 scheme 지름길 확인)
- 실행 방식: 새 Kaggle 노트북이 v2 노트북의 출력(코드·외부 데이터)을 입력으로 받아 실행 → 노트북 업로드 없이 셀 하나로 진행

### v3 진행
- [x] P9 결과 회수: 리포트 수치는 v2 실행 로그에서 기록(위 결과 섹션). `qsing_artifacts.zip`은 브라우저로 다운로드를 시도했으나, 다운로드 폴더 접근 권한이 자동 승인에서 거절되어 Qsing 폴더로 옮기지 못함 → 사용자가 직접 옮기거나 v3 결과로 대체
- [x] `model/qsing_model/augment.py` 추가 (경로 없는 URL 비율 측정, 정상 홈페이지 보강, v3 실행 흐름) + `tests/test_augment.py` (로컬 42개 통과, 가짜 모델로 v3 흐름 리허설 포함)
- [x] Kaggle 노트북 `qsing-urlbert-train-v3` 생성: 입력 = Malicious URLs dataset + v2 노트북 출력(코드·외부 데이터), GPU T4 x2
  - 셀 1개: `model/notebooks/qsing_kaggle_v3_driver.py`를 zlib+base64로 압축한 한 줄(`qsing_kaggle_v3_cell.txt`). 압축 체크섬으로 입력 오류 시 즉시 실패
  - 커밋 고정 `020744435b3be870dabb2bba0b41237bea69b84b`, 정규화 strip만, 기준선(P3)은 v2 결과 재사용
- [x] 2026-11-12 22:52 Save & Run All 시작 (대기열)
- [x] 2026-11-12 22:55 v3 실행 완료

### P10 원인 확인 결과 (클래스별 홈페이지 형태 비율 = 경로·쿼리 없는 URL)
| 데이터 | benign | phishing | malware | defacement |
|---|---|---|---|---|
| Malicious URLs | 11.18% | 25.87% | 4.28% | 0.00% |
| PhiUSIIL | 100.00% | 69.19% | — | — |

- 가설 부분 확인: Malicious URLs에서 홈페이지 형태는 피싱이 정상보다 2.3배 많음. PhiUSIIL 정상 URL은 100% 홈페이지 형태
- 보강 행: train 35,659 / val 24,439 / test 24,458

### v3 결과 (strip + mlp, 홈페이지 보강) vs v2
| 지표 | v2 | v3 |
|---|---|---|
| test Macro F1 | 0.8255 | 0.8207 |
| test 정상 오탐률 (argmax) | 0.1969 | 0.1959 |
| test 악성 미탐률 (argmax) | 0.0285 | 0.0308 |
| 홈페이지 형태 test 정상 오탐률 | — | 0.0266 |
| Tranco 홈페이지 정상 오탐률 | 0.2408 | **0.0705** [0.0654–0.0759] |
| PhiUSIIL 정상 오탐률 / AUROC | 0.9919 / 0.432 | 0.9859 / 0.425 |
| OpenPhish 악성 미탐률 | 0.0727 | 0.1127 [0.0806–0.1556] |
| 학습-서버 일치율 | 0.998 | 1.000 |
| CPU p50 / p95 | 5.3 / 8.6 ms | 5.2 / 6.7 ms |

### 해석
- Tranco 홈페이지 오탐은 크게 줄었으나 PhiUSIIL은 그대로
- 형식 차이: 보강 데이터와 Tranco는 `https://도메인/`(끝에 '/') → strip 후 `도메인/`, PhiUSIIL 정상은 `https://www.도메인.com`(끝 '/' 없음) → `도메인.com`
- 새 가설: 모델이 "끝 '/' 있음 = 정상"을 학습했을 가능성. Tranco 개선분 일부가 이 형식 덕일 수 있음
- OpenPhish 미탐률이 늘어남(7.3%→11.3%, 신뢰구간 겹침)

### 다음 (v4)
- 정규화 `strip2` 추가: strip + '도메인/'처럼 경로가 '/' 하나뿐이면 끝 '/' 제거 → 홈페이지 형식 통일. 서버 추론도 같은 정규화 사용
- 같은 보강으로 재학습 후 PhiUSIIL·Tranco·OpenPhish 다시 비교

### v4 준비 (실행 대기)
- [x] `urls.normalize`에 `strip2` 추가 (홈페이지 형태의 끝 '/' 제거 → `naver.com/`과 `naver.com`이 같은 입력), 테스트 추가 (로컬 42개 통과), 파이프라인 변형 처리에 strip2 반영
- [x] `model/notebooks/qsing_kaggle_v4_driver.py` / `qsing_kaggle_v4_cell.txt` 준비 (urls.py·augment.py 포함, 정규화 strip2, 출력 `qsing_out_v4`)
- [ ] Kaggle 실행: Claude 앱 창이 가려져 있어 Kaggle 편집기(iframe)가 화면에 그려지지 않아 중단. 빈 새 노트북 `notebook4da52f4ac7`가 하나 만들어져 있음(초안, 실행 안 함)
  - 재개 방법: v3 노트북과 같이 입력 2개(Malicious URLs, qsing-urlbert-train 출력) + GPU T4 x2 설정 후 `qsing_kaggle_v4_cell.txt` 한 줄을 셀에 넣고 Save & Run All

### 결과 문서 정리 (2026-11-12 23:15)
- `docs/results/모델_결과_비교.md` — v2·v3 비교표, 지표 설명, 클래스별 성능, 혼동행렬, 지금까지 알게 된 것
- `docs/results/v2/run_summary.md`, `docs/results/v3/run_summary.md` — 버전별 상세 수치

### 마무리 기준 (사용자 요청으로 끝점 확정)
- v4가 마지막 실험. 결과와 상관없이 그 후 정리하고 종료
- 최종 모델 선택: test 정상 오탐률·악성 미탐률이 v3보다 나빠지지 않으면서 PhiUSIIL·Tranco 오탐률이 낮으면 v4, 아니면 v3
- 남는 한계는 보고서·발표에 명시, 추가 개선(인코더 파인튜닝 등)은 11/24 서버 전달 이후로 미룸

### v2 산출물 반영 (사용자가 zip 업로드)
- `qsing_artifacts.zip`(v2, 임계값 0.2511 / test Macro F1 0.8255 일치 확인) → `model/artifacts_v2/` (인코더·head.npz·설정·지표), 원본 zip은 `_archive/qsing_artifacts_v2.zip`
- `docs/results/v2/`에 metrics.json, confusion_matrix.png 추가, 비교 문서에 v2 혼동행렬 추가

### v4 실행
- [x] 2026-11-12 23:31 Kaggle 노트북 `qsing-urlbert-train-v4` Save & Run All 시작 (입력: Malicious URLs + qsing-urlbert-train 출력, GPU T4 x2, 셀 = `qsing_kaggle_v4_cell.txt`, 정규화 strip2)
- [x] 2026-11-12 23:40 v4 완료

### v4 결과 (strip2) — v3 대비
- test Macro F1 0.821 → 0.785, 정상 오탐률 19.6% → 24.2%, 악성 미탐률 3.1% → 8.2% (나빠짐)
- PhiUSIIL AUROC 0.43 → **0.85**, 정상 오탐률 98.6% → **25.5%**, 악성 미탐률 7.1% → 20.9%
- Tranco 홈페이지 오탐률 7.0% → 39.9%, 홈페이지 형태 test 오탐률 2.7% → 20.5%
- OpenPhish 미탐률 11.3% → 4.7%
- 해석: v3의 홈페이지·Tranco 개선은 끝 '/' 형식 덕이었음이 확인됨('/' 지름길 가설 지지). '/'를 지우자 다른 출처 구분 능력은 크게 좋아졌지만 같은 출처 성능은 떨어짐

### 최종 결정 (사전 기준 적용)
- **최종 모델 = v3** — v4는 test 정상 오탐률·악성 미탐률이 v3보다 나빠져 기준 미달
- 한계(보고서·발표에 명시): v3는 홈페이지 판단이 끝 '/'에 의존. '/' 없는 홈페이지 주소는 오탐 가능성 높음. 다른 출처 데이터(PhiUSIIL) 오탐 98.6%
- 대안: 일반화를 중시하면 v4 (PhiUSIIL AUROC 0.85). 팀 판단으로 교체 가능
- 결과 문서: `docs/results/모델_결과_비교.md`, `docs/results/v4/run_summary.md`
- 남은 일: v3 서버용 zip(Kaggle `qsing-urlbert-train-v3` 출력의 `qsing_artifacts.zip`)을 받아 `model/artifacts/`에 배치. 실험은 여기서 종료

---

## 2026-11-13 · v5 — 페이즈 계획 (사용자 요청: "v5해", "멈추지말고 v5 끝까지")

### 배경
- 사용자 질문("데이터셋은 저거밖에 없는거야? 계획서에 보면 종류 많은데")을 계기로 학습 데이터 구성을 다시 조사
- 확인한 사실(출처 2곳 이상 대조): Malicious URLs는 ISCX-URL-2016 등 여러 출처를 합친 데이터이고, 핵심 출처인 ISCX-URL-2016의 정상 URL은 만들 때 "도메인만 있는 URL"을 일부러 제거함 → v2~v4에서 본 '홈페이지 형태 정상 URL 부족'은 데이터 제작 방식에서 온 편향. 이 데이터 하나로는 없애기 어려움
- 그래서 "v4가 마지막 실험"이라는 11/12 기준을 사용자 결정으로 다시 열고 v5를 진행

### 무엇을 바꾸나 (설계 개정 6 — `docs/specs/2026-11-13-urlbert-model-design-개정6.md`)
- v4 설정(정규화 strip2, 정상 홈페이지 보강, MLP 헤드, 인코더 고정)은 그대로
- **train 세트에만** 다른 출처 정상 URL을 추가: HuggingFace `JPxxx/url-benchmark-dataset`(Apache-2.0)의 정상 URL(Common Crawl 2021·2025의 오래 유지된 URL) 최대 200,000건
- val·test·PhiUSIIL·OpenPhish·Tranco는 v4와 완전히 같게 유지 → v4와 직접 비교 가능
- 새 평가 1개 추가: 같은 JPxxx 데이터에서 **학습에 쓰지 않은 도메인**만 모은 holdout(정상 약 2만 + 악성 약 2만, 악성 출처는 PhishTank·URLhaus 등). 같은 실행에서 "보강만 뺀 헤드(v4 재현)"도 학습해 같은 holdout으로 비교

### 페이즈
| 페이즈 | 내용 |
|---|---|
| P14 계획 기록 | 이 섹션 + 개정 6 명세. 최종 선택 기준을 실행 전에 확정 |
| P15 코드·테스트 | `qsing_model/ccaug.py`(불러오기·누수 방지 필터·holdout 구성·평가), `augment.run_v3` 확장 지점, `tests/test_ccaug.py`, Kaggle 드라이버·셀 |
| P16 Kaggle 실행 | v4 노트북을 복사해 셀만 v5로 교체 → Save & Run All |
| P17 결과 기록 | `docs/results/v5/run_summary.md`, 비교 문서 추가, `docs/results/버전별_학습_과정.md`(사용자 요청: 버전마다 어떤 값이 나왔고 어떻게 학습됐고 그래서 어떻게 됐는지) |
| P18 검증 | 문서 수치를 Kaggle 로그 원본과 대조 |

### 누수·편향 방지 규칙 (추가하는 정상 URL)
1. 등록 도메인이 Malicious URLs의 val·test 세트에 있으면 제외 (세트 간 도메인 교집합 0 유지)
2. 등록 도메인이 PhiUSIIL·OpenPhish·Tranco 평가 세트에 있으면 제외 (외부 평가가 '처음 보는 도메인'으로 남도록)
3. 호스트가 Malicious URLs 또는 JPxxx의 악성 URL에 한 번이라도 나오면 제외 (라벨 모호)
4. 이미 있는 URL과 같으면 제외, 형식 검사·중복·라벨 충돌 제거는 기존 `clean`과 동일
5. 도메인당 최대 3건 (특정 사이트 쏠림 방지), 시드 42로 표본 추출
- 알려진 한계: 정상 클래스만 출처가 2개가 됨 → 모델이 "Common Crawl 모양 = 정상"을 배울 위험. holdout의 악성 미탐률과 OpenPhish·PhiUSIIL 미탐률로 감시
- 참고: JPxxx 데이터는 urlbert-tiny-v6 모델 카드가 벤치마크로 쓰는 데이터와 같은 계열. 인코더는 고정이고 우리는 헤드만 학습하므로 절차는 같지만, holdout 수치는 "완전히 낯선 데이터"보다 후하게 나올 수 있음(명시)

### 최종 선택 기준 (실행 전 확정, v5가 마지막 실험)
v5를 최종 모델로 하려면 아래를 모두 만족해야 함. 하나라도 어기면 기존 결정(v3, 대안 v4) 유지.
1. 일반화 유지: PhiUSIIL AUROC ≥ 0.80
2. 정상 오탐 개선: Tranco 홈페이지 오탐률 < 39.9%(v4) **그리고** PhiUSIIL 정상 오탐률 ≤ 27.5%(v4 25.5% + 2%p)
3. 악성 탐지 유지: test 악성 미탐률(argmax) ≤ 10% **그리고** OpenPhish 미탐률(argmax) ≤ 11.3%(v3 수준)

### v5 진행 (2026-11-13)
- [x] P14 계획·개정 6 명세 기록, 최종 선택 기준을 실행 전에 확정(위)
- [x] P15 코드·테스트: `qsing_model/ccaug.py`, `augment.run_v3`에 확장 지점(extra_rows, post_eval) 추가, `tests/test_ccaug.py`. 로컬 테스트 48개 실행 OK(2개 건너뜀: torch 없음). `qsing_kaggle_v5_cell.txt`를 풀면 드라이버 원본과 일치함을 확인
- [x] P16 Kaggle 실행: v4 노트북을 복사한 `fork-of-qsing-urlbert-train-v4`에 v5 셀 입력 → 00:13 Save & Run All → 418.6초 만에 성공. JPxxx parquet(137,281,781 bytes)은 실행 중 HuggingFace에서 받음(스냅샷 bdbd2691a386)
- [x] P17 결과 기록: `docs/results/v5/run_summary.md`, `docs/results/모델_결과_비교.md` 아래에 v5 섹션 추가, `docs/results/버전별_학습_과정.md` 신규(사용자 요청 문서)
- [x] P18 검증: 문서 수치를 Kaggle 로그와 대조(아래)

### v5 결과 (v4 대비, 같은 val·test·외부 세트)
- 추가 데이터: Common Crawl 정상 200,000행(도메인 182,450개, 홈페이지 형태 43.63%). 필터 단계 999,964 → 919,491 → 887,321 → 830,014 → 745,338 → 514,348
- 선택: strip2 + mlp, val 최저 0.7852(원본 0.7914), 시드 평균 0.7940 ± 0.0027, 임계값 t_low 0.0770 / t_high 0.9717 (overlap)
- test: Macro F1 0.785 → 0.789, 정상 오탐률 24.2% → 19.5%, 악성 미탐률 8.2% → **14.6%** (피싱 Recall 0.793 → 0.681)
- PhiUSIIL: AUROC 0.851 → 0.866, 정상 오탐률 25.5% → **10.1%**, 악성 미탐률 20.9% → 31.5%
- Tranco 오탐률 39.9% → 23.2%, 홈페이지 형태 test 오탐률 20.5% → 11.4%, OpenPhish 미탐률 4.7% → 5.8%
- JPxxx holdout(정상 2만 + 악성 2만): v5 AUROC 0.940 / 오탐 17.0% / 미탐 8.5%, 보강 뺀 헤드 AUROC 0.807 / 오탐 49.5% / 미탐 6.2%
- 같은 실행에서 재현한 v4 헤드의 test 수치(0.7845 / 0.2418 / 0.0816)가 11/12 v4 실행과 일치
- CPU p50 5.0ms / p95 6.4ms, 학습-서버 일치율 1.000

### 해석 (객관적으로)
- 다른 출처 정상 URL 보강은 정상 오탐을 확실히 줄였으나 피싱 미탐을 늘림. 오탐·미탐 맞바꿈이 v4에 이어 반복
- holdout 정상은 보강 데이터와 같은 출처라 v5에 유리한 평가임(문서에 명시). 출처가 다른 PhiUSIIL·Tranco에서도 같은 방향이라 개선 자체는 사실로 봄

### 최종 결정 (사전 기준 적용)
- 기준 5개 중 4개 통과, **test 악성 미탐률 ≤ 10% 미달(14.6%)** → v5 채택 안 함
- **최종 모델 = v3 유지, 대안 v4.** v5는 정상 오탐을 최우선으로 볼 때의 후보로 보관
- 실험은 v5로 종료. 남은 일: 팀이 고른 버전의 `qsing_artifacts.zip`을 Kaggle Output에서 받아 `model/artifacts/`에 배치

## 2026-11-14 · 팀 공유 정리

| 페이즈 | 내용 |
|---|---|
| P19 팀 공유 문서 | Claude 문서 "큐싱 탐지 앱 — AI 모델 진행 현황 (팀 공유)" 작성 (요약, 서버 연동, 데이터셋, 버전 비교, 팀 결정 드롭다운, 남은 일) |
| P20 테스트 요약 | `docs/results/테스트_요약.md` — 테스트 데이터셋 5종, 테스트 방법 6가지, 최종 모델(v3) 7개 지표·혼동행렬, 버전별 핵심 수치 |
| P21 모델 파일 회수 | v3·v4·v5 `qsing_artifacts.zip`을 Kaggle에서 받아 Qsing으로 옮기려 했으나, 다운로드 폴더 접근이 다시 자동 승인에서 거절되고 사용자가 중단 → 보류 |
- P21 (재개) 모델 파일 회수 완료: 사용자가 다운로드 폴더를 연결 → Kaggle에서 받은 zip 3개를 지표로 버전 확인 후 압축 해제
  - `model/artifacts_v3/`, `model/artifacts_v4/`, `model/artifacts_v5/` 생성, 서버 기본 경로 `model/artifacts/` = v3 복사본(README.txt 포함)
  - 원본 zip은 `_archive/qsing_artifacts_v3~v5.zip`에 보관. 네 버전의 인코더 파일은 동일(md5 일치), 헤드 5개 모두 numpy로 로드·확률 합 1 확인 (torch가 없어 인코더까지 넣은 실제 추론은 이 PC에서 미실행)
- P22 테스트 요약 다시 작성: 사용자 요청("ai느낌 없애고")으로 `docs/results/테스트_요약.md`를 보고서 문체로 다시 쓰고 PDF(2쪽)로 저장
