@echo off
title G66 Network Forensics Platform - RIG EK & KPOT Stealer
echo ======================================================================
echo           GROUP G66 - NETWORK FORENSIC ANALYSIS SOC PLATFORM
echo   Case Study: RIG Exploit Kit Drive-by Infection Delivering KPOT Stealer
echo ======================================================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not added to your system PATH!
    echo Please install Python 3.10+ from https://www.python.org and check
    echo "Add python.exe to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Ensure in script directory
cd /d "%~dp0"

:: Check virtual environment
if not exist ".venv" (
    echo [INFO] Creating Python virtual environment in .venv ...
    python -m venv .venv
)

:: Activate virtual environment
if exist ".venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment (.venv) ...
    call .venv\Scripts\activate.bat
)

:: Install/Verify requirements
echo [INFO] Verifying Python dependencies ...
python -m pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

:: Open web browser after a short delay
echo [INFO] Launching default web browser to http://127.0.0.1:5000 ...
start "" http://127.0.0.1:5000

echo.
echo ======================================================================
echo  SOC Server running at http://127.0.0.1:5000
echo  Press Ctrl+C in this terminal window to stop the server.
echo ======================================================================
echo.

python app.py

pause
