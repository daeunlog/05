# URLBERT 모델 설계 — 개정 6 (v5: 다른 출처 정상 URL 보강)

> 2026-11-13 · 앞 개정: 개정 1(명세 본문 하단), 개정 2·3(별도 파일), 개정 4(v3 정상 홈페이지 보강)·개정 5(v4 strip2 정규화)는 `work_history.md`와 코드 주석에 기록

## 1. 바꾸는 이유
- v2~v4 공통 문제: 정상 URL 판단이 학습 데이터(Malicious URLs)의 정상 URL 모양에 묶여 있음. 다른 출처 정상 URL 오탐률이 높음(v4 기준 PhiUSIIL 25.5%, Tranco 39.9%)
- 조사 결과: Malicious URLs의 정상 URL은 대부분 ISCX-URL-2016에서 왔고, ISCX-URL-2016은 정상 URL을 만들 때 도메인만 있는 URL을 제거함. 데이터 제작 단계의 편향이라 같은 데이터 안에서 형식만 바꾸는 방법(v3, v4)으로는 한계가 있음

## 2. 바꾸는 내용
| 항목 | v4 | v5 |
|---|---|---|
| 정규화 | strip2 | strip2 (같음) |
| 헤드 | linear·mlp 중 val 최저 Macro F1로 선택 | 같음 |
| train 데이터 | Malicious URLs train + 정상 홈페이지 보강 | v4 + **Common Crawl 정상 URL 최대 200,000건** |
| val / test | Malicious URLs 도메인 그룹 분리 | 같음 (추가 없음) |
| 외부 평가 | PhiUSIIL, OpenPhish, Tranco | 같음 + **JPxxx holdout**(학습에 없는 도메인의 정상·악성) |

- 추가 데이터: HuggingFace `JPxxx/url-benchmark-dataset` (약 300만 URL, 정상 약 270만은 Common Crawl 2021·2025, 악성 약 30만은 PhishTank·URLhaus 등, Apache-2.0, 컬럼 `url`·`label`·`fold`)
- 4종 분류는 유지: 추가하는 것은 정상(benign)뿐. 악성 3종(phishing·malware·defacement)의 학습 데이터는 그대로

## 3. 추가 규칙
1. 형식 검사·완전 중복·라벨 충돌 제거: 기존 `data.clean`
2. 등록 도메인이 Malicious URLs val·test 세트에 있으면 제외
3. 등록 도메인이 PhiUSIIL·OpenPhish·Tranco 평가 세트에 있으면 제외
4. 호스트가 Malicious URLs 또는 JPxxx 악성 URL에 나오면 제외
5. 이미 있는 URL(scheme·www 무시)과 같으면 제외
6. 도메인당 최대 3건, 시드 42

## 4. holdout 평가
- 정상: 위 규칙을 통과한 URL 중 Malicious URLs에도 JPxxx 악성에도 없는 도메인을 무작위로 골라 약 2만 건. 이 도메인들은 train 보강에서 빠짐
- 악성: JPxxx 악성 URL 중 Malicious URLs·외부 평가 세트·train 보강 어디에도 없는 도메인, 도메인당 최대 3건, 약 2만 건. 악성 종류 라벨이 없어 정상/악성 2종 지표(AUROC, 오탐률, 미탐률)만 계산
- 비교 기준: 같은 실행에서 Common Crawl 보강만 뺀 헤드(v4 재현)를 같은 시드로 학습해 같은 holdout에 적용

## 5. 위험과 감시 방법
- 정상 클래스의 출처가 2개 → "Common Crawl 모양 = 정상" 지름길 위험. holdout 악성 미탐률, OpenPhish·PhiUSIIL 미탐률이 v4보다 크게 늘면 지름길로 판단
- JPxxx는 인코더(urlbert-tiny-v6)의 벤치마크 계열 데이터 → holdout 수치는 낙관적일 수 있음. 최종 판단은 PhiUSIIL·Tranco·OpenPhish를 함께 봄

## 6. 최종 선택 기준 (실행 전 확정)
아래를 모두 만족하면 v5, 아니면 기존 결정(v3, 대안 v4) 유지. v5가 마지막 실험.
1. PhiUSIIL AUROC ≥ 0.80
2. Tranco 홈페이지 오탐률 < 39.9% 그리고 PhiUSIIL 정상 오탐률 ≤ 27.5%
3. test 악성 미탐률(argmax) ≤ 10% 그리고 OpenPhish 미탐률(argmax) ≤ 11.3%
