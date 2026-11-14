"""헤드 학습 (설계 3.2절). torch 필요.

AdamW(lr 1e-3, wd 0.01), 배치 2048, 최대 30 epoch, val Macro F1이 3 epoch 연속 개선 없으면 조기 종료,
클래스 가중치 balanced. 가장 좋은 epoch의 가중치를 돌려준다.
"""

import time

import numpy as np

from .head import build_torch_head
from .metrics import four_class_metrics


def class_weights(y, k=4):
    counts = np.bincount(np.asarray(y, dtype=int), minlength=k).astype(np.float64)
    return len(y) / (k * np.maximum(counts, 1.0))


def _predict_logits(torch, model, X, batch=65536):
    outs = []
    model.eval()
    with torch.inference_mode():
        for s in range(0, X.shape[0], batch):
            outs.append(model(X[s:s + batch]).float())
    return torch.cat(outs)


def train_head(X_train, y_train, X_val, y_val, kind, seed=42, lr=1e-3, weight_decay=0.01, batch_size=2048,
               max_epochs=30, patience=3, device=None, log=print):
    import torch
    import torch.nn as nn

    torch.manual_seed(seed)
    np.random.seed(seed)
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    Xtr = torch.from_numpy(np.asarray(X_train, dtype=np.float32)).to(device)
    ytr = torch.from_numpy(np.asarray(y_train, dtype=np.int64)).to(device)
    Xva = torch.from_numpy(np.asarray(X_val, dtype=np.float32)).to(device)
    y_val = np.asarray(y_val, dtype=int)

    model = build_torch_head(kind, in_dim=Xtr.shape[1]).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    w = torch.tensor(class_weights(y_train), dtype=torch.float32, device=device)
    loss_fn = nn.CrossEntropyLoss(weight=w)
    gen = torch.Generator(device="cpu").manual_seed(seed)

    best_f1, best_state, best_epoch, bad = -1.0, None, 0, 0
    history = []
    t0 = time.time()
    n = Xtr.shape[0]
    for epoch in range(1, max_epochs + 1):
        model.train()
        perm = torch.randperm(n, generator=gen).to(device)
        total = 0.0
        for s in range(0, n, batch_size):
            idx = perm[s:s + batch_size]
            opt.zero_grad(set_to_none=True)
            loss = loss_fn(model(Xtr[idx]), ytr[idx])
            loss.backward()
            opt.step()
            total += float(loss.item()) * len(idx)
        pred = _predict_logits(torch, model, Xva).argmax(dim=1).cpu().numpy()
        f1 = four_class_metrics(y_val, pred)["macro_f1"]
        history.append({"epoch": epoch, "train_loss": total / n, "val_macro_f1": f1})
        log(f"  [{kind} seed={seed}] epoch {epoch:2d}  loss {total / n:.4f}  val macroF1 {f1:.4f}")
        if f1 > best_f1 + 1e-6:
            best_f1, best_epoch, bad = f1, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    model.load_state_dict(best_state)
    model = model.cpu().eval()
    info = {"kind": kind, "seed": seed, "best_val_macro_f1": best_f1, "best_epoch": best_epoch,
            "epochs_run": len(history), "seconds": round(time.time() - t0, 2), "history": history,
            "hyperparams": {"lr": lr, "weight_decay": weight_decay, "batch_size": batch_size,
                            "max_epochs": max_epochs, "patience": patience, "class_weights": "balanced"}}
    return model, info


def predict_probs_torch(model, X, device=None):
    import torch

    device = device or "cpu"
    model = model.to(device)
    Xt = torch.from_numpy(np.asarray(X, dtype=np.float32)).to(device)
    logits = _predict_logits(torch, model, Xt)
    return torch.softmax(logits, dim=1).cpu().numpy()
