"""URLBERT 인코더 임베딩 (설계 3.2절): [CLS] 벡터 + attention mask 기준 평균 벡터 = 256차원.

torch, transformers가 필요하다. ModernBERT는 transformers 4.48 이상에서 지원된다.
인코더는 transformers 기본 클래스로 불러오므로 원격 코드(trust_remote_code)를 실행하지 않는다.
"""

import contextlib
import time

import numpy as np

DEFAULT_REPO = "CrabInHoney/urlbert-tiny-v6"
MAX_TOKENS = 256
POOLING = "cls+mean"


class Embedder:
    def __init__(self, source=DEFAULT_REPO, revision=None, device=None, fp16=None, max_tokens=MAX_TOKENS, num_threads=None):
        import torch
        from transformers import AutoModel, AutoTokenizer

        self.torch = torch
        if num_threads:
            torch.set_num_threads(int(num_threads))
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(source, revision=revision)
        self.model = AutoModel.from_pretrained(source, revision=revision).to(self.device).eval()
        self.fp16 = self.device.startswith("cuda") if fp16 is None else bool(fp16)
        self.max_tokens = int(max_tokens)
        self.hidden = int(self.model.config.hidden_size)
        self.dim = 2 * self.hidden

    def save(self, out_dir):
        self.tokenizer.save_pretrained(out_dir)
        try:
            self.model.save_pretrained(out_dir, safe_serialization=True)
        except TypeError:  # transformers 5.x: safetensors가 기본이고 인자가 없어졌을 수 있음
            self.model.save_pretrained(out_dir)

    def encode(self, texts, batch_size=512, out_dtype=np.float16, progress=False):
        """반환: (임베딩 [n, 256], 잘림 여부 [n])"""
        torch = self.torch
        texts = [str(t) for t in texts]
        n = len(texts)
        out = np.zeros((n, self.dim), dtype=out_dtype)
        truncated = np.zeros(n, dtype=bool)
        if n == 0:
            return out, truncated
        order = np.argsort(np.fromiter((len(t) for t in texts), dtype=np.int64, count=n), kind="stable")
        starts = range(0, n, batch_size)
        if progress:
            try:
                from tqdm.auto import tqdm
                starts = tqdm(starts, total=(n + batch_size - 1) // batch_size, desc="embed")
            except ImportError:
                pass
        t0 = time.time()
        with torch.inference_mode():
            for s in starts:
                idx = order[s:s + batch_size]
                batch = [texts[i] for i in idx]
                full_ids = self.tokenizer(batch, add_special_tokens=True, truncation=False)["input_ids"]
                truncated[idx] = np.array([len(x) > self.max_tokens for x in full_ids])
                enc = self.tokenizer(batch, padding=True, truncation=True, max_length=self.max_tokens, return_tensors="pt")
                ids = enc["input_ids"].to(self.device)
                mask = enc["attention_mask"].to(self.device)
                amp = (torch.autocast(device_type="cuda", dtype=torch.float16) if self.fp16
                       else contextlib.nullcontext())
                with amp:
                    h = self.model(input_ids=ids, attention_mask=mask).last_hidden_state
                h = h.float()
                m = mask.unsqueeze(-1).float()
                mean = (h * m).sum(dim=1) / m.sum(dim=1).clamp(min=1.0)
                vec = torch.cat([h[:, 0], mean], dim=1)
                out[idx] = vec.cpu().numpy().astype(out_dtype)
        self.last_seconds = time.time() - t0
        return out, truncated
