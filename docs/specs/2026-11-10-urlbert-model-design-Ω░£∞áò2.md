# URLBERT 모델 설계 — 개정 2 (2026-11-10, 구현 중 발견 사항)

> 원본: `2026-11-09-urlbert-model-design.md` (+ 개정 1). 원본은 수정하지 않고 이 문서로 덧붙인다.
> 아래 내용이 원본과 다르면 이 개정이 우선한다.

## 1. 위험도 임계값 판단 정정 (원본 3.4절)

원본: "`t_low ≥ t_high`이면 두 목표를 동시에 만족할 수 없다는 뜻이다."
**정정: 반대다.** `t_low ≥ t_high`는 악성 URL 99%가 이미 정상 URL 상위 1%보다 높은 점수를 받는 경우로, 두 목표가 **함께 충족**된다. 이 경우 '주의' 구간이 필요 없다.

- 구현: `t_low ≥ t_high`이면 `t_low = t_high`로 맞춰 '주의' 구간을 비우고 `status = "separated"`, 원래 값은 `t_low_raw`에 남긴다.
- 보통의 경우(`t_low < t_high`)는 `status = "overlap"`이며 겹치는 구간이 '주의'가 된다.
- 'separated'가 나오면 팀이 목표값(1%, 99%)을 조정해 '주의' 구간을 둘지 정한다.

## 2. 모델 선택 기준 보강 (원본 2.6절, 3.2절)

원본: {raw, strip} × {Linear, MLP}를 **val Macro F1**로 선택.
**변경: val Macro F1의 최저값**으로 선택한다. 최저값은 아래 세 입력 중 가장 낮은 Macro F1이다.

| 변형 | 내용 |
|---|---|
| 원본 | val URL 그대로 |
| scheme 제거 | 앞쪽 `http(s)://` 제거 |
| https 추가 | scheme이 없는 URL에 `https://` 추가 (실제 QR URL과 비슷한 형태) |

- 이유: 합성 데이터 리허설에서 `raw` 모델이 "scheme이 있으면 악성"이라는 지름길을 학습해 `https://www.naver.com/`을 피싱으로 판정했다. val 세트도 같은 편향을 갖고 있어 원본 val Macro F1(1.00)로는 잡히지 않았고, 변형 val에서는 0.57까지 떨어졌다.
- 여전히 val만 쓰므로 test·PhiUSIIL·외부 평가는 선택에 관여하지 않는다.
- `strip`은 정의상 세 변형의 모델 입력이 같으므로 변형 임베딩을 따로 계산하지 않는다(단위 테스트로 확인).
- 동점이면 `strip`(입력 형태에 덜 민감) → `linear`(단순) 순으로 고른다.
- P5에서 선택 모델의 test 세트 scheme 변형 결과(`test_scheme_variants`)를 함께 보고한다.

## 3. 실행 순서

P0 → P1 → P2 → P3 → P4 → **P6 → P5** → P7.
P5의 "임계값 기준 오탐·미탐률"에 P6 임계값이 필요하다. P6은 val만 쓰므로 test를 미리 보지 않는다.

## 4. 헤드 저장 형식

`head.pt` 대신 **`head.npz`**(numpy). pickle을 쓰지 않아 `torch.load`보다 안전하고, 서버에서 헤드 계산은 numpy로 한다(`NumpyHead`, torch `nn.GELU` 기본값과 같은 erf GELU).

## 5. 추가 점검 항목

- **리허설**: 본 실행 전 6천 건 표본으로 P1~P7 전체를 한 번 돌린다(`qsing_out/_smoke`).
- **학습-서버 일치율**: 학습 때(GPU, fp16) 임베딩과 서버 추론(CPU, fp32) 결과의 예측 일치율을 test 500건으로 측정해 `metrics.json`의 `parity`에 기록한다.
- **추론 시간**: 내보낸 `artifacts/`를 실제로 불러와 CPU에서 측정한다(P7, `metrics.json`의 `latency`).
