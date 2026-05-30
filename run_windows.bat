@echo off
REM SSHGuard v2.0 — Windows Launcher
REM Double-click to run a full scan, or open a cmd window and use:
REM   run_windows.bat --module ssh --watch

setlocal

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.7+ from https://python.org
    echo         and make sure it is added to PATH.
    pause
    exit /b 1
)

python -c "import sys; exit(0 if sys.version_info >= (3,7) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] SSHGuard requires Python 3.7+.
    pause
    exit /b 1
)

echo.
echo   SSHGuard v2.0 — Defensive SSH ^& System Monitor
echo   Starting full scan...
echo.

python sshguard.py %*

echo.
pause
