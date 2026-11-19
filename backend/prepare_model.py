"""Materialize the runtime from the model team's immutable Git revision."""
from pathlib import Path
import subprocess

BACKEND = Path(__file__).resolve().parent
REV = "7be5b747b6d98ea0e6807183bd82662bd0d5006e"
SOURCES = ("__init__.py", "embed.py", "head.py", "infer.py", "labels.py", "risk.py", "urls.py")
ARTIFACTS = ("head.npz", "model_config.json", "thresholds.json", "encoder/config.json",
             "encoder/model.safetensors", "encoder/tokenizer.json", "encoder/tokenizer_config.json")


def git(*args, **kwargs):
    return subprocess.run(["git", *args], cwd=BACKEND.parent, **kwargs)


def prepare():
    if git("cat-file", "-e", REV + "^{commit}", stderr=subprocess.DEVNULL).returncode:
        git("fetch", "origin", REV, check=True)
    paths = [(f"model/qsing_model/{name}", BACKEND / "qsing_model" / name) for name in SOURCES]
    paths += [(f"model/artifacts/{name}", BACKEND / "model/artifacts" / name) for name in ARTIFACTS]
    for source, dest in paths:
        data = git("cat-file", "blob", f"{REV}:{source}", stdout=subprocess.PIPE, check=True).stdout
        if dest.exists():
            local = dest.read_bytes()
            if local == data or (dest.suffix in {".py", ".json"} and
                                 local.replace(b"\r\n", b"\n") == data.replace(b"\r\n", b"\n")):
                continue
            raise SystemExit(f"Existing file differs from the pinned model: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as out:
            out.write(data)
    print(f"CPU model ready: {REV}")


if __name__ == "__main__":
    prepare()
