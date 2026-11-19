$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    py -3.11 prepare_model.py
    if ($LASTEXITCODE) { throw "Model preparation failed" }
    if (-not (Test-Path .\.venv\Scripts\python.exe)) {
        py -3.11 -m venv .venv
        if ($LASTEXITCODE) { throw "Python 3.11 venv creation failed" }
    }
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE) { throw "Package installation failed" }
    if (-not (Test-Path -LiteralPath .env)) {
        & .\.venv\Scripts\python.exe -c "from pathlib import Path; import secrets; p=Path('.env.example').read_text(encoding='utf-8'); f=open('.env','x',encoding='utf-8'); f.write(p.replace('CACHE_HASH_SECRET=', 'CACHE_HASH_SECRET='+secrets.token_hex(32), 1)); f.close()"
        if ($LASTEXITCODE) { throw "Configuration creation failed" }
    }
} finally {
    Pop-Location
}
