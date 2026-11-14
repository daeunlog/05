"""4종 라벨 정의. 모든 산출물에서 이 순서를 쓴다."""

LABELS = ("benign", "phishing", "malware", "defacement")
LABEL_TO_ID = {name: i for i, name in enumerate(LABELS)}
BENIGN_ID = LABEL_TO_ID["benign"]
MALICIOUS_LABELS = ("phishing", "malware", "defacement")


def to_ids(labels):
    """라벨 문자열 시퀀스를 정수 id 리스트로 바꾼다. 모르는 라벨이면 KeyError."""
    return [LABEL_TO_ID[str(x)] for x in labels]


def map_external_labels(id2label):
    """외부 모델의 id2label을 우리 라벨 이름으로 매핑한다.

    키워드로 대응시키고, 4종이 1:1로 대응되지 않으면 ValueError를 낸다.
    반환값: {외부 id(int): 우리 라벨 이름}
    """
    rules = (
        ("benign", ("benign", "legit", "legal", "safe", "good", "normal", "clean")),
        ("phishing", ("phish",)),
        ("defacement", ("deface",)),
        ("malware", ("malware", "malicious")),
    )
    mapping = {}
    for raw_id, raw_name in id2label.items():
        name = str(raw_name).lower()
        found = None
        for ours, keys in rules:
            if any(k in name for k in keys):
                found = ours
                break
        if found is None:
            raise ValueError(f"라벨 매핑 실패: {raw_id} -> {raw_name!r}. 노트북에서 수동 매핑을 지정하세요.")
        mapping[int(raw_id)] = found
    if sorted(mapping.values()) != sorted(LABELS):
        raise ValueError(f"4종이 1:1로 대응되지 않음: {id2label} -> {mapping}. 노트북에서 수동 매핑을 지정하세요.")
    return mapping
