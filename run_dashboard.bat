@echo off
TITLE Cyber Utilities & Forensics Dashboard
COLOR 0A
CLS
ECHO =========================================================
ECHO        CYBER UTILITIES & FORENSICS SUITE (2026)
ECHO =========================================================
ECHO [!] Checking Python Environment...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [X] Python is not installed or not found in system PATH!
    ECHO Please install Python 3.10+ and re-run.
    PAUSE
    EXIT /B
)

ECHO [+] Python found! Installing/Verifying requirements...
python -m pip install -r requirements.txt --quiet

ECHO [+] Launching Cyber Utilities Dashboard...
python -m streamlit run app.py

PAUSE
