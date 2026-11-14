"""큐싱 탐지 앱 — URLBERT 기반 URL 위험 분류 모델 패키지.

모듈 구성
- labels   : 4종 라벨 순서와 매핑
- urls     : URL 파싱, 그룹 키(등록 도메인), 정규화(raw/strip), 보조 신호
- data     : 데이터셋 로딩·정제·scheme 점검·외부 평가 세트 구성
- split    : 도메인 그룹 단위 70:15:15 분리와 누수 검사
- metrics  : 필수 지표 7종, AUROC, 외부 평가 지표(Wilson 신뢰구간)
- risk     : 위험도 임계값 결정과 등급 판정
- embed    : URLBERT 인코더 CLS+MEAN 임베딩 (torch 필요)
- head     : 분류 헤드 (학습은 torch, 추론은 numpy)
- train    : 헤드 학습 (torch 필요)
- baseline : 제공 malicious_urls_4class 헤드 평가 (torch 필요)
- infer    : 서버용 UrlRiskClassifier
- pipeline : Kaggle 노트북에서 부르는 페이즈별 함수
"""

__version__ = "0.1.0"
