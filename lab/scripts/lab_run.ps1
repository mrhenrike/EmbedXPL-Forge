# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# EmbedXPL-Forge — Lab Runner Script (PowerShell)
# Levanta o ambiente Docker local, executa módulos de detecção de botnet
# contra os alvos simulados e captura saída em .log/lab-run.log.
#
# Usage: .\lab\scripts\lab_run.ps1 [from the EmbedXPL-Forge root]
# Requires: Docker Desktop running, Python virtualenv with embedxpl installed

param(
    [string]$EmbedXPLRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
    [string]$LogDir        = "$EmbedXPLRoot\.log",
    [string]$LogFile       = "$LogDir\lab-run.log",
    [int]   $WarmupSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# --- helpers -----------------------------------------------------------------

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Invoke-EmbedXPL {
    param(
        [string]$Module,
        [hashtable]$Options
    )
    $optStr = ($Options.GetEnumerator() | ForEach-Object { "set $($_.Key) $($_.Value)" }) -join "; "
    $cmd = "python -m embedxpl --module $Module --run"
    Write-Log "Executing: $cmd  options: $optStr"

    $output = & python -m embedxpl --module $Module --set-run $optStr 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Module $Module returned exit code $LASTEXITCODE" "WARN"
    }
    $output | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8 }
    return $output
}

# --- init --------------------------------------------------------------------

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

Write-Log "=========================================================="
Write-Log " EmbedXPL-Forge Botnet Detection Lab Run"
Write-Log " Root : $EmbedXPLRoot"
Write-Log " Log  : $LogFile"
Write-Log "=========================================================="

# --- docker compose up -------------------------------------------------------

$labDir = "$EmbedXPLRoot\lab"
Write-Log "Starting Docker lab from $labDir ..."
Push-Location $labDir

$composeOutput = & docker compose up -d --build 2>&1
$composeOutput | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8 }

if ($LASTEXITCODE -ne 0) {
    Write-Log "docker compose up failed (exit $LASTEXITCODE) -- aborting." "ERROR"
    Pop-Location
    exit 1
}
Write-Log "Docker lab started. Waiting $WarmupSeconds seconds for services to be ready..."
Start-Sleep -Seconds $WarmupSeconds

Pop-Location

# --- run botnet detection modules against lab targets -----------------------
# Lab endpoints (mapped to localhost):
#   vulnerable-router  -> 127.0.0.1:18080
#   telnet-iot         -> 127.0.0.1:10023 (port 23) / 127.0.0.1:12323 (port 2323)
#   iot-upnp           -> 127.0.0.1:14902

Set-Location $EmbedXPLRoot

Write-Log "----------------------------------------------------------"
Write-Log "MODULE: scanners/threat_detection/mirai_infection_scan"
Write-Log "----------------------------------------------------------"
$r1 = & python -m embedxpl -m scanners/threat_detection/mirai_infection_scan `
    --set target 127.0.0.1 --set port_list "10023,12323" --set timeout 5 `
    --run 2>&1
$r1 | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8; Write-Host $_ }

Write-Log "----------------------------------------------------------"
Write-Log "MODULE: scanners/threat_detection/mirai_default_creds_sweep"
Write-Log "----------------------------------------------------------"
$r2 = & python -m embedxpl -m scanners/threat_detection/mirai_default_creds_sweep `
    --set target 127.0.0.1 --set port 10023 --set timeout 5 `
    --run 2>&1
$r2 | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8; Write-Host $_ }

Write-Log "----------------------------------------------------------"
Write-Log "MODULE: scanners/threat_detection/botnet_c2_port_scan"
Write-Log "----------------------------------------------------------"
$r3 = & python -m embedxpl -m scanners/threat_detection/botnet_c2_port_scan `
    --set target 127.0.0.1 --set timeout 3 `
    --run 2>&1
$r3 | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8; Write-Host $_ }

Write-Log "----------------------------------------------------------"
Write-Log "MODULE: scanners/threat_detection/mozi_dht_presence_scan"
Write-Log "----------------------------------------------------------"
$r4 = & python -m embedxpl -m scanners/threat_detection/mozi_dht_presence_scan `
    --set target 127.0.0.1 --set timeout 3 `
    --run 2>&1
$r4 | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8; Write-Host $_ }

Write-Log "----------------------------------------------------------"
Write-Log "MODULE: exploits/routers/tplink/wr940n_740n_841n_ssid_cmd_injection_cve_2023_33538"
Write-Log "(testing against simulated vulnerable router on port 18080)"
Write-Log "----------------------------------------------------------"
$r5 = & python -m embedxpl `
    -m exploits/routers/tplink/wr940n_740n_841n_ssid_cmd_injection_cve_2023_33538 `
    --set target 127.0.0.1 --set port 18080 `
    --set username admin --set password admin --set command id `
    --run 2>&1
$r5 | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8; Write-Host $_ }

# --- tear down ---------------------------------------------------------------

Write-Log "=========================================================="
Write-Log "All modules executed. Tearing down Docker lab..."
Push-Location $labDir
$downOutput = & docker compose down 2>&1
$downOutput | ForEach-Object { Add-Content -Path $LogFile -Value $_ -Encoding UTF8 }
Pop-Location

Write-Log "Lab run complete. Full log: $LogFile"
Write-Log "=========================================================="
