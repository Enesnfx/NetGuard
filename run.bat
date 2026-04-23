@echo off
title NetGuard
cd /d "%~dp0"
python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo NetGuard exited with error %ERRORLEVEL%.
    echo Make sure Python 3.10+ is installed and on PATH.
    pause
)
