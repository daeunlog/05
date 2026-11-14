# v2 실행 결과 요약 (Kaggle `qsing-urlbert-train` Version 2, 2026-11-12)

- 모델: urlbert-tiny-v6 @ 020744435b3b (인코더 고정) + MLP 헤드, 정규화 strip
- 학습 데이터: Malicious URLs train 442,969건 (보강 없음)
- 선택: val Macro F1 최저값 0.8287 (원본 0.8287), 시드 3개 평균 0.8289 ± 0.0003
- 조합별 val Macro F1 (원본 / scheme 변형 포함 최저): raw+linear 0.8975 / 0.5169, raw+mlp 0.9339 / 0.5772, strip+linear 0.7732 / 0.7732, strip+mlp 0.8287 / 0.8287
- 임계값(val): t_low 0.251137, t_high 0.986038 (overlap)

## 데이터
- Malicious URLs 정제: 651,191 → 632,812 (형식 오류·미지원 89, 중복 10,065, 라벨 충돌 8,225)
- 클래스별: benign 423,928 / defacement 95,308 / phishing 89,931 / malware 23,645
- 분리: train 442,969 / val 94,922 / test 94,921, 세트 간 도메인 교집합 0, 최대 클래스 비율 차이 0.001%p

## test (Malicious URLs, n=94,921)
- Accuracy 0.8429, Macro F1 0.8255
- benign P 0.9828 / R 0.8031 / F1 0.8839 (n=63,589)
- phishing P 0.5289 / R 0.9083 / F1 0.6685 (n=13,489)
- malware P 0.8473 / R 0.8638 / F1 0.8555 (n=3,547)
- defacement P 0.8422 / R 0.9531 / F1 0.8942 (n=14,296)
- 정상 URL 오탐률: argmax 0.1969, 임계값 0.3079
- 악성 URL 미탐률: argmax 0.0285, 임계값 0.0101
- 혼동행렬(행=정답, 열=예측; benign, phishing, malware, defacement) — 그림: `confusion_matrix.png`
  - benign: 51070, 10121, 321, 2077
  - phishing: 631, 12252, 150, 456
  - malware: 47, 416, 3064, 20
  - defacement: 214, 376, 81, 13625
- 전체 지표 원본: `metrics.json`, 서버용 모델: `model/artifacts_v2/`

## 일반화
- PhiUSIIL (strip, 선택 모델): AUROC 0.4322, 정상 오탐률 argmax 0.9919 / 임계값 0.9982, 악성 미탐률 argmax 0.0432 / 임계값 0.0202
- PhiUSIIL (raw, 참고): AUROC 0.3989, 정상 오탐률 1.0000, 악성 미탐률 0.0013
- OpenPhish (n=275): 악성 미탐률 argmax 0.0727 [95% CI 0.0476–0.1097]
- Tranco (n=9,093, list PY2NJ): 정상 오탐률 argmax 0.2408 [0.2322–0.2497], 임계값 0.4447 [0.4345–0.4550]

## 기타
- 기준선(제공 헤드, 학습 데이터와 겹쳐 부풀려졌을 수 있음): Accuracy 0.9907, Macro F1 0.9808, 정상 오탐률 0.0048, 악성 미탐률 0.0088
- 학습-서버 일치율 0.998 (n=500), CPU p50 5.3ms / p95 8.6ms, 배치 1,179 URL/초
