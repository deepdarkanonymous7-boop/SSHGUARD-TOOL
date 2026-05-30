# SSHGuard v2.0 — Windows PowerShell Launcher
# Run from PowerShell: .\run_windows.ps1
# Or with options:     .\run_windows.ps1 --watch --export json,html
# If blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python not found. Install Python 3.7+ from https://python.org" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$pyCheck = python -c "import sys; exit(0 if sys.version_info >= (3,7) else 1)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] SSHGuard requires Python 3.7+." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "  SSHGuard v2.0 — Defensive SSH & System Monitor" -ForegroundColor Green
Write-Host "  Starting scan..." -ForegroundColor DarkGray
Write-Host ""

python sshguard.py @Args

Write-Host ""
Read-Host "Press Enter to exit"
