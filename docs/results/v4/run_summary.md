# v4 실행 결과 요약 (Kaggle `qsing-urlbert-train-v4`, 2026-11-12)

- 모델: urlbert-tiny-v6 @ 020744435b3b (인코더 고정) + MLP 헤드, 정규화 **strip2** (strip + 홈페이지 끝 '/' 제거)
- 학습: Malicious URLs train + 정상 홈페이지 보강 35,659행 (v3와 같음)
- 선택: val Macro F1 최저값 0.7723 (원본 0.7870, 홈페이지 val 0.7723), 시드 3개 평균 0.7874 ± 0.0102
- 조합: strip2+linear 원본 0.7510 / 최저 0.7300, strip2+mlp 원본 0.7870 / 최저 0.7723
- 임계값(val): t_low 0.169875, t_high 0.984302 (overlap)

## test (Malicious URLs, n=94,921)
- Accuracy 0.7948, Macro F1 0.7845
- benign P 0.9497 / R 0.7582 / F1 0.8432 (n=63,589)
- phishing P 0.4357 / R 0.7931 / F1 0.5625 (n=13,489)
- malware P 0.8138 / R 0.8652 / F1 0.8388 (n=3,547)
- defacement P 0.8502 / R 0.9412 / F1 0.8934 (n=14,296)
- 정상 URL 오탐률: argmax 0.2418, 임계값 0.4934
- 악성 URL 미탐률: argmax 0.0816, 임계값 0.0102
- 혼동행렬(행=정답, 열=예측; benign, phishing, malware, defacement)
  - benign: 48216, 13005, 393, 1975
  - phishing: 2218, 10698, 197, 376
  - malware: 143, 315, 3069, 20
  - defacement: 195, 533, 112, 13456

## 홈페이지 형태
- test 정상 호스트의 홈페이지(n=24,458) 정상 오탐률: argmax 0.2052, 임계값 0.6846
- test + 홈페이지(n=119,379): Macro F1 0.7698, 정상 오탐률 argmax 0.2316

## 일반화
- PhiUSIIL: **AUROC 0.8508**, 정상 오탐률 argmax 0.2551 / 임계값 0.8088, 악성 미탐률 argmax 0.2089 / 임계값 0.0260
- OpenPhish (n=275): 악성 미탐률 argmax 0.0473 [0.0278–0.0792], 임계값 0.0109 [0.0037–0.0316], 유형 일치율 0.8909
- Tranco (n=9,093): 정상 오탐률 argmax 0.3989 [0.3889–0.4090], 임계값 0.8805 [0.8736–0.8870]

## 기타
- 학습-서버 일치율 1.000 (n=500), CPU p50 5.5ms / p95 7.0ms, 배치 1,129 URL/초
- 예시: `https://www.naver.com/` → benign, 위험 점수 0.172 → 등급 '주의'
