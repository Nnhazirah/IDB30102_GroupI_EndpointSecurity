@echo off
setlocal enabledelayedexpansion
title Endpoint Security Sentinel - GUI Dashboard
color 0b

echo ===========================================================================
echo   ENDPOINT SECURITY SENTINEL - BEHAVIOURAL RANSOMWARE DETECTION
echo   Group I - IDB30102 Research Project
echo ===========================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0c
    echo [ERROR] Python was not found in system PATH.
    echo Please install Python 3.9+ and ensure it is added to your PATH.
    echo.
    pause
    exit /b 1
)

:: 2. Set Directory
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%04_Source_Code\gui_app.py" (
    cd /d "%SCRIPT_DIR%04_Source_Code"
) else if exist "%SCRIPT_DIR%IDB30102_GroupI_EndpointSecurity\04_Source_Code\gui_app.py" (
    cd /d "%SCRIPT_DIR%IDB30102_GroupI_EndpointSecurity\04_Source_Code"
) else (
    cd /d "%cd%\04_Source_Code"
)

echo [*] Starting Endpoint Security GUI Dashboard...
python gui_app.py

if %errorlevel% neq 0 (
    echo.
    echo [NOTE] The application closed with an exit code.
    pause
)
