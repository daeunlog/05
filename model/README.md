# 큐싱 탐지 — URLBERT 모델 파트

설계: `../docs/specs/2026-11-09-urlbert-model-design.md` (+ 개정 1, `2026-11-10-...-개정2.md`)
서버 연동: `../docs/model_api.md`

## 폴더

```
model/
├─ qsing_model/            파이썬 패키지 (모든 로직)
│  ├─ labels.py  urls.py  data.py  split.py      ← 데이터·전처리·분리
│  ├─ metrics.py  risk.py                         ← 필수 지표 7종, 위험도 임계값
│  ├─ embed.py  head.py  train.py  baseline.py    ← 임베딩·헤드 학습·기준선 (torch)
│  ├─ infer.py                                    ← 서버용 UrlRiskClassifier
│  └─ pipeline.py                                 ← 노트북이 부르는 P0~P7
├─ tests/                  단위 테스트 + 파이프라인 리허설 (torch 없이도 실행)
├─ notebooks/qsing_kaggle.ipynb
├─ artifacts/              ← Kaggle 결과 zip을 여기에 풉니다 (처음엔 없음)
├─ requirements-server.txt
└─ requirements-train.txt
```

## 집에서 할 일 (순서대로)

### 1. 받은 zip을 Qsing 폴더에 풀기
`Qsing/` 위에 그대로 덮어쓰면 됩니다. `work_history.md`는 기존 내용이 그대로 들어 있고 맨 아래에 11/10 기록이 추가된 버전입니다.

### 2. (선택) 내 PC에서 테스트
```bash
cd Qsing/model
pip install numpy pandas scikit-learn pytest
python -m pytest -q tests
```
torch가 없으면 torch 비교 테스트 1개만 건너뜁니다.

### 3. Kaggle에 올릴 것

| Kaggle Dataset 이름(예) | 내용 | 필수 |
|---|---|---|
| `qsing-code` | 함께 받은 `qsing-code_for_kaggle.zip`을 그대로 업로드 (또는 `model` 폴더를 직접 zip) | 필수 |
| (검색해서 추가) `sid321axn/malicious-urls-dataset` | 학습 데이터 | 필수 |
| `phiusiil` | [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)에서 받은 CSV | 권장 |
| `qsing-external` | 외부 최신 데이터 (아래) | 선택 |

외부 최신 데이터는 없어도 노트북이 해당 평가만 건너뛰고 돌아갑니다. 넣으려면 파일 이름을 이렇게 맞춰 한 데이터셋에 같이 올리세요.

- `urlhaus.csv` — [URLhaus](https://urlhaus.abuse.ch/api/)에 로그인해 무료 Auth-Key를 받은 뒤 CSV 덤프를 내려받기
- `openphish_YYYYMMDD.txt` — [OpenPhish Community Feed](https://github.com/openphish/public_feed)의 feed 파일. 12시간마다 바뀌므로 며칠에 걸쳐 여러 개 저장
- `tranco.csv` — [Tranco](https://tranco-list.eu/) 최신 Top 1M 목록 (list ID를 work_history에 적어두기)

URL에는 절대 접속하지 말고 파일로만 다루세요.

### 4. Kaggle 노트북 실행
1. Kaggle → Code → New Notebook → File → Import Notebook → `notebooks/qsing_kaggle.ipynb`
2. 오른쪽 패널: **Add Input**으로 위 데이터셋 붙이기, **Accelerator: GPU**, **Internet: On**
3. **Run All**
   - 첫 셀: 코드 복사, tldextract 설치
   - 단위 테스트 → 설정(입력 파일 자동 탐색, 찾은 경로 출력) → P0(원격 코드 출력 — 한 번 읽어보기)
   - 리허설(6천 건, 수 분) → 본 실행 P1~P7
4. 오른쪽 Output에서 `qsing_artifacts.zip`, `qsing_reports.zip` 다운로드

### 5. 결과 정리
- `qsing_artifacts.zip` → `Qsing/model/artifacts/`에 풀기 → 김다은 님께 `model/` 폴더와 `docs/model_api.md` 전달
- 노트북 마지막 셀 출력(실행 결과 요약)을 `work_history.md` 맨 아래에 붙여넣기

## 막히면

| 증상 | 조치 |
|---|---|
| `qsing_model 코드를 찾지 못했습니다` | `qsing-code` 데이터셋을 Add Input으로 붙였는지 확인 |
| `FileNotFoundError ... malicious` | Malicious URLs 데이터셋을 붙였는지 확인 |
| `transformers를 업그레이드했습니다` | Run → Restart & Run All |
| HuggingFace 다운로드 실패 | Settings에서 Internet On (휴대폰 인증 필요) |
| `라벨 매핑 실패` | P3 출력의 id2label을 보고 설정 셀의 `baseline_label_map` 주석을 풀어 지정 |
| `SplitCheckError` (비율 차이) | 메시지의 상위 도메인을 확인. 필요하면 설정에 `ratio_tolerance_pp=3.0` 추가 후 재실행 |
| GPU 메모리 부족 | 설정에 `embed_batch=256` 추가 |

각 페이즈 결과는 `/kaggle/working/qsing_out`에 저장되므로, 중간에 끊겨도 실패한 셀부터 다시 돌리면 됩니다(같은 세션 안에서).
