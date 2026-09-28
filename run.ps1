# EmbedXPL-Forge — launcher with local .venv (Windows)
# Usage: .\run.ps1 -m exploits/routers/dlink/multi_hnap_rce -s "target 192.168.1.1"

$venv_python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venv_python)) {
    Write-Host "[!] Venv not found. Running setup_venv.ps1 ..." -ForegroundColor Yellow
    & "$PSScriptRoot\setup_venv.ps1"
}

& $venv_python "$PSScriptRoot\exf.py" @args
