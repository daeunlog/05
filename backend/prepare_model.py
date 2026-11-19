"""Materialize the runtime from the model team's immutable Git revision."""
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

BACKEND = Path(__file__).resolve().parent
REV = "7be5b747b6d98ea0e6807183bd82662bd0d5006e"
SOURCES = ("__init__.py", "embed.py", "head.py", "infer.py", "labels.py", "risk.py", "urls.py")
ARTIFACTS = ("head.npz", "thresholds.json", "encoder/config.json", "encoder/model.safetensors",
             "encoder/tokenizer.json", "encoder/tokenizer_config.json", "model_config.json")


def git(*args, **kwargs):
    return subprocess.run(["git", *args], cwd=BACKEND.parent, **kwargs)


def blob(source):
    return git("cat-file", "blob", f"{REV}:{source}", stdout=subprocess.PIPE, check=True).stdout


def matches(local, data, dest):
    if dest.suffix in {".py", ".json"}:
        return local.replace(b"\r\n", b"\n") == data.replace(b"\r\n", b"\n")
    return local == data


def prepare():
    if git("cat-file", "-e", REV + "^{commit}", stderr=subprocess.DEVNULL).returncode:
        git("fetch", "origin", REV, check=True)
    paths = [(f"model/qsing_model/{n}", BACKEND / "qsing_model" / n, None) for n in SOURCES]
    paths += [(f"model/artifacts_v5/{n}", BACKEND / "model/artifacts" / n,
               f"model/artifacts/{n}") for n in ARTIFACTS]
    # Validate the entire installation before replacing any managed file.
    with TemporaryDirectory(dir=BACKEND) as staging:
        pending = []
        for source, dest, previous in paths:
            data = blob(source)
            if dest.exists():
                local = dest.read_bytes()
                if local == data or (previous is None and matches(local, data, dest)):
                    continue
                if previous is None or not (matches(local, data, dest) or matches(local, blob(previous), dest)):
                    raise SystemExit(f"Existing file differs from the pinned model: {dest}")
            staged = Path(staging) / str(len(pending))
            staged.write_bytes(data)
            pending.append((staged, dest))
        for staged, dest in pending:
            dest.parent.mkdir(parents=True, exist_ok=True)
            staged.replace(dest)
    print(f"CPU model ready: {REV}:model/artifacts_v5")


if __name__ == "__main__":
    prepare()
