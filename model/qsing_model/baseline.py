"""P0·P3: 제공 헤드(malicious_urls_4class) 관련 (설계 3.1절).

주의: 제공 헤드는 trust_remote_code=True로만 로드된다. 이는 HuggingFace 저장소의 파이썬 코드를 실행하므로
1) 저장소 커밋(revision)을 고정하고 2) show_remote_code()로 코드를 먼저 읽어본 뒤 로드한다.
서버용 추론(infer.py)은 이 모듈을 쓰지 않는다.
"""

import numpy as np

from .labels import LABEL_TO_ID, map_external_labels

DEFAULT_HEAD = "malicious_urls_4class"


def resolve_revision(repo, revision=None):
    """'main' 등 이름 대신 고정 커밋 해시를 돌려준다."""
    from huggingface_hub import HfApi

    return HfApi().model_info(repo, revision=revision).sha


def show_remote_code(repo, revision, head=DEFAULT_HEAD, print_fn=print):
    """헤드 로드 시 실행될 수 있는 .py 파일을 출력하고 파일 목록을 돌려준다."""
    from huggingface_hub import HfApi, hf_hub_download

    files = HfApi().list_repo_files(repo, revision=revision)
    head_prefix = f"heads/{head}/"
    head_files = [f for f in files if f.startswith(head_prefix)]
    py = [f for f in files if f.endswith(".py") and (f.startswith(head_prefix) or "/" not in f)]
    print_fn(f"[{head}] 폴더 파일: {head_files}")
    for f in py:
        path = hf_hub_download(repo, f, revision=revision)
        with open(path, encoding="utf-8") as fh:
            print_fn(f"\n===== {f} =====\n{fh.read()}")
    if not py:
        print_fn("(실행될 .py 파일이 없습니다)")
    return {"head_files": head_files, "python_files": py}


class ProvidedHead:
    def __init__(self, repo, revision, head=DEFAULT_HEAD, device=None, label_map=None):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            repo, subfolder=f"heads/{head}", trust_remote_code=True, revision=revision).to(self.device).eval()
        self.tokenizer = AutoTokenizer.from_pretrained(repo, revision=revision)
        cfg_len = getattr(self.model.config, "max_length", None)
        # PretrainedConfig 기본값(20)이 들어있으면 모델 카드의 256을 쓴다
        self.max_length = int(cfg_len) if cfg_len and int(cfg_len) >= 64 else 256
        self.id2label = {int(k): v for k, v in self.model.config.id2label.items()}
        self.label_map = {int(k): v for k, v in label_map.items()} if label_map else map_external_labels(self.id2label)

    def predict_probs(self, texts, batch_size=1024):
        """우리 라벨 순서(benign, phishing, malware, defacement)의 확률 [n, 4]."""
        torch = self.torch
        texts = [str(t) for t in texts]
        n = len(texts)
        out = np.zeros((n, 4), dtype=np.float32)
        order = np.argsort([len(t) for t in texts], kind="stable")
        cols = [LABEL_TO_ID[self.label_map[j]] for j in range(len(self.label_map))]
        with torch.inference_mode():
            for s in range(0, n, batch_size):
                idx = order[s:s + batch_size]
                enc = self.tokenizer([texts[i] for i in idx], padding=True, truncation=True,
                                     max_length=self.max_length, return_tensors="pt").to(self.device)
                logits = self.model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).logits.float()
                p = torch.softmax(logits, dim=-1).cpu().numpy()
                out[np.ix_(idx, cols)] = p
        return out
