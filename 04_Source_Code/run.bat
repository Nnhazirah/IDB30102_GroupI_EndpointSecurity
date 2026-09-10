@echo off
setlocal enabledelayedexpansion
title IDB30102 Endpoint Security - Behavioural Detection System
color 0b

echo ===========================================================================
echo   IDB30102 GROUP I: ENDPOINT SECURITY
echo   Behavioural Detection of File-Encrypting Ransomware using Machine Learning
echo ===========================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0c
    echo [ERROR] Python is not found in your system PATH!
    echo Please install Python 3.9+ from https://www.python.org/ and ensure
    echo "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VER=%%i
echo [+] Found %PYTHON_VER%
echo.

:: 2. Resolve directory paths
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%04_Source_Code" (
    set "PROJECT_ROOT=%SCRIPT_DIR%"
) else if exist "%SCRIPT_DIR%IDB30102_GroupI_EndpointSecurity\04_Source_Code" (
    set "PROJECT_ROOT=%SCRIPT_DIR%IDB30102_GroupI_EndpointSecurity\"
) else (
    set "PROJECT_ROOT=%cd%\"
)

cd /d "%PROJECT_ROOT%"

echo ---------------------------------------------------------------------------
echo   Please select an operating mode:
echo   [1] Launch Modern Desktop GUI Dashboard (Recommended)
echo   [2] Run Terminal Evaluation and Training Pipeline (CLI)
echo   [3] Install / Verify Dependencies (requirements.txt)
echo   [4] Exit
echo ---------------------------------------------------------------------------
set /p MODE="Enter choice (default is 1): "

if "%MODE%"=="" set MODE=1
if "%MODE%"=="1" goto launch_gui
if "%MODE%"=="2" goto launch_cli
if "%MODE%"=="3" goto install_deps
if "%MODE%"=="4" exit /b 0

:launch_gui
echo.
echo [*] Launching Desktop GUI Dashboard...
cd /d "%PROJECT_ROOT%04_Source_Code"
start "" python gui_app.py
exit /b 0

:launch_cli
echo.
echo [*] Running Terminal Detection Pipeline...
cd /d "%PROJECT_ROOT%04_Source_Code"
python run_pipeline.py
echo.
pause
exit /b 0

:install_deps
echo.
echo [*] Installing dependencies from requirements.txt...
python -m pip install -r 04_Source_Code\requirements.txt
echo.
pause
exit /b 0
