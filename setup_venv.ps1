# setup_venv.ps1 — Virtual environment for EmbedXPL-Forge (Windows)
# Author: André Henrique (@mrhenrike)

$ErrorActionPreference = "Stop"
$VenvDir = ".venv"
$Root = $PSScriptRoot
Set-Location $Root

Write-Host "=== EmbedXPL-Forge — Virtual Environment Setup (Windows) ===" -ForegroundColor Cyan
Write-Host ""

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+\.\d+)") {
            $pythonCmd = $cmd
            Write-Host "Python found: $ver ($cmd)" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "ERROR: Python not found." -ForegroundColor Red
    Write-Host "Install: winget install Python.Python.3.12" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment at $VenvDir..."
    & $pythonCmd -m venv $VenvDir
} else {
    Write-Host "venv already exists at $VenvDir" -ForegroundColor Yellow
}

$pip = Join-Path $VenvDir "Scripts\pip.exe"
$py = Join-Path $VenvDir "Scripts\python.exe"

& $pip install --upgrade pip --quiet
Write-Host "--- Installing core dependencies ---" -ForegroundColor Cyan
& $pip install -r requirements.txt
& $pip install -e . --quiet
New-Item -ItemType File -Path (Join-Path $VenvDir ".embedxpl-venv-ready") -Force | Out-Null

Write-Host ""
Write-Host "=== Environment ready! ===" -ForegroundColor Green
Write-Host "Run:      .\run.ps1"
Write-Host "Or:       python exf.py"
Write-Host "Activate: .\.venv\Scripts\Activate.ps1"
Write-Host "Doctor:   .\.venv\Scripts\python.exe tools\env_doctor.py"
