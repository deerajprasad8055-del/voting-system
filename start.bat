@echo off
title SecureVote - RSA + AES Hybrid Voting System
color 0B

echo ======================================================================
echo    Starting SecureVote Web Application (RSA-2048 + AES-256-GCM)
echo ======================================================================
echo.

cd /d "%~dp0"

:: Prefer venv python if available, otherwise fallback to system python
set "PYTHON_EXE=python"
if exist "%~dp0venv\Scripts\python.exe" (
    echo [INFO] Using virtual environment Python...
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
)

:: Ensure database and keys are initialized
echo [INFO] Checking cryptographic keys and database...
"%PYTHON_EXE%" seed.py

echo.
echo ======================================================================
echo  Server is launching on: http://127.0.0.1:5000
echo.
echo  Demo Credentials:
echo    Admin:   admin@securevote.com   / Admin@123
echo    Voter 1: alice@securevote.com   / Voter@123
echo    Voter 2: bob@securevote.com     / Voter@123
echo    Voter 3: charlie@securevote.com / Voter@123
echo.
echo  Press CTRL+C to stop the server at any time.
echo ======================================================================
echo.

:: Automatically open browser after 2 seconds in background
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"

:: Run the Flask application
"%PYTHON_EXE%" app.py

pause
