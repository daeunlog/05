# v3 실행 결과 요약 (Kaggle `qsing-urlbert-train-v3`, 2026-11-12)

- 모델: urlbert-tiny-v6 @ 020744435b3b (인코더 고정) + MLP 헤드, 정규화 strip, 학습 = Malicious URLs train + 정상 홈페이지 보강 35,659행
- 선택: val Macro F1 최저값 0.8217 (원본 0.8217, 홈페이지 val 0.8260), 시드 3개 평균 0.8278 ± 0.0053
- 임계값(val): t_low 0.218965, t_high 0.985318 (overlap)

## test (Malicious URLs, n=94,921)
- Accuracy 0.8417, Macro F1 0.8207
- benign P 0.9815 / R 0.8041 / F1 0.8840 (n=63,589)
- phishing P 0.5299 / R 0.9026 / F1 0.6678 (n=13,489)
- malware P 0.8172 / R 0.8661 / F1 0.8410 (n=3,547)
- defacement P 0.8403 / R 0.9459 / F1 0.8900 (n=14,296)
- 정상 URL 오탐률: argmax 0.1959, 임계값 0.3314
- 악성 URL 미탐률: argmax 0.0308, 임계값 0.0100
- 혼동행렬(행=정답, 열=예측; benign, phishing, malware, defacement)
  - benign: 51130, 9931, 395, 2133
  - phishing: 704, 12175, 193, 417
  - malware: 50, 405, 3072, 20
  - defacement: 211, 464, 99, 13522

## 홈페이지 형태
- test 정상 호스트의 홈페이지(n=24,458) 정상 오탐률: argmax 0.0266, 임계값 0.0876
- test + 홈페이지(n=119,379): Macro F1 0.8249, 정상 오탐률 argmax 0.1489

## 일반화
- PhiUSIIL: AUROC 0.4250, 정상 오탐률 argmax 0.9859 / 임계값 0.9972, 악성 미탐률 argmax 0.0713 / 임계값 0.0322
- OpenPhish (n=275): 악성 미탐률 argmax 0.1127 [0.0806–0.1556], 임계값 0.0618 [0.0390–0.0968], 유형 일치율 0.8655
- Tranco (n=9,093, list PY2NJ): 정상 오탐률 argmax 0.0705 [0.0654–0.0759], 임계값 0.1890 [0.1811–0.1972]

## 기타
- 기준선(제공 헤드, 부풀려졌을 수 있음): Accuracy 0.9907, Macro F1 0.9808
- 학습-서버 일치율 1.000 (n=500), CPU p50 5.2ms / p95 6.7ms, 배치 1,176 URL/초
