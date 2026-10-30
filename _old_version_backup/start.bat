@echo off
title Secure Online Voting System - RSA + AES
color 0B

echo ======================================================================
echo    Starting Secure Online Voting System (RSA-2048 + AES-256-GCM)
echo ======================================================================
echo.

cd /d "%~dp0"

:: Prefer venv python if available, otherwise fallback to system python
set "PYTHON_EXE=python"
if exist "%~dp0venv\Scripts\python.exe" (
    echo [INFO] Using virtual environment Python...
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
)

echo.
echo ======================================================================
echo  Server launching on: http://127.0.0.1:5000
echo.
echo  Demo Credentials:
echo    Admin:   admin@election.gov   / Admin@Secure2026!
echo    Voter 1: alice@vote.com       / Voter@Secure2026!
echo    Voter 2: bob@vote.com         / Voter@Secure2026!
echo.
echo  Press CTRL+C to stop the server.
echo ======================================================================
echo.

:: Automatically open browser after 2 seconds
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"

"%PYTHON_EXE%" app.py

pause
