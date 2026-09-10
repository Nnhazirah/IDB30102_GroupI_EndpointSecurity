@echo off
setlocal enabledelayedexpansion
title IDB30102 Endpoint Security - Ransomware Detection System
color 0b

echo ===========================================================================
echo   IDB30102 GROUP I: ENDPOINT SECURITY
echo   Behavioural Detection of File-Encrypting Ransomware using Machine Learning
echo ===========================================================================
echo.

:: 1. Check Python installation
echo [*] Checking Python environment...
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

:: 3. Install/verify dependencies
echo [*] Checking and verifying Python dependencies...
python -m pip install -r 04_Source_Code\requirements.txt
if %errorlevel% neq 0 (
    echo [WARNING] Some dependencies encountered an issue during verification.
)
echo.

:: 4. Run detection pipeline
echo ===========================================================================
echo   Launching Behavioural Detection and Model Training Pipeline...
echo ===========================================================================
echo.

cd /d "%PROJECT_ROOT%04_Source_Code"
python run_pipeline.py

echo.
echo ===========================================================================
echo   Execution finished. Models and evaluation results are saved in:
echo   - Models:  %PROJECT_ROOT%04_Source_Code\saved_models\
echo   - Dataset: %PROJECT_ROOT%05_Data_or_Sample_Input\
echo   - Results: %PROJECT_ROOT%06_Result_or_Expected_Outcome\
echo ===========================================================================
echo.
pause
