@echo off
chcp 65001 > nul
title OSINT Auto-Scanner
color 0A
cls

echo ========================================================
echo        AUTOMATED OSINT TOOLKIT LAUNCHER
echo ========================================================
echo.

:: 1. Check Python installation
python --version > nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.8+ and check "Add to PATH".
    pause
    exit
)

:: 2. Install dependencies (silent mode)
echo [*] Installing dependencies...
pip install -r requirements.txt > nul 2>&1

:: 3. Run main script
echo.
echo [*] Launching main.py...
echo.
python main.py

echo.
echo ========================================================
echo        SCAN FINISHED. Closing...
echo ========================================================
pause