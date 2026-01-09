@echo off
REM ============================================
REM ClickHouse Setup Script for Boundary-SIEM
REM Downloads portable ClickHouse for Windows
REM ============================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo.
echo ========================================
echo    ClickHouse Portable Setup
echo ========================================
echo.

REM Configuration
set "CH_VERSION=24.8.4.13"
set "CH_DIR=clickhouse"
set "CH_EXE=%CH_DIR%\clickhouse.exe"

REM Check if already installed
if exist "%CH_EXE%" (
    echo [OK] ClickHouse already installed
    echo.
    "%CH_EXE%" --version
    echo.
    goto :end
)

echo [INFO] Downloading ClickHouse %CH_VERSION% for Windows...
echo.

REM Create directory
if not exist "%CH_DIR%" mkdir "%CH_DIR%"
if not exist "%CH_DIR%\data" mkdir "%CH_DIR%\data"
if not exist "%CH_DIR%\logs" mkdir "%CH_DIR%\logs"

REM Download using PowerShell
set "CH_URL=https://github.com/ClickHouse/ClickHouse/releases/download/v%CH_VERSION%-stable/clickhouse-windows.zip"
set "CH_ZIP=%CH_DIR%\clickhouse.zip"

echo [INFO] Downloading from: %CH_URL%
echo [INFO] This may take a few minutes...
echo.

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%CH_URL%' -OutFile '%CH_ZIP%' -UseBasicParsing}"

if not exist "%CH_ZIP%" (
    echo [ERROR] Download failed. Please check your internet connection.
    echo.
    echo Manual installation:
    echo   1. Download ClickHouse from: https://clickhouse.com/docs/en/install
    echo   2. Place clickhouse.exe in the 'clickhouse' folder
    echo.
    pause
    exit /b 1
)

echo [INFO] Extracting...
powershell -Command "Expand-Archive -Path '%CH_ZIP%' -DestinationPath '%CH_DIR%' -Force"

REM Clean up zip
del "%CH_ZIP%" 2>nul

REM Verify installation
if exist "%CH_EXE%" (
    echo.
    echo [SUCCESS] ClickHouse installed successfully!
    echo.
    "%CH_EXE%" --version
) else (
    REM Try to find clickhouse.exe in subdirectories
    for /r "%CH_DIR%" %%f in (clickhouse.exe) do (
        if exist "%%f" (
            move "%%f" "%CH_EXE%" >nul 2>nul
            echo [SUCCESS] ClickHouse installed successfully!
            goto :verify
        )
    )
    echo [WARNING] clickhouse.exe not found in expected location
    echo           Please check the %CH_DIR% folder manually
)

:verify
if exist "%CH_EXE%" (
    echo.
    "%CH_EXE%" --version
)

:end
echo.
echo ========================================
echo    Setup Complete
echo ========================================
echo.
echo ClickHouse is ready to use with Boundary-SIEM.
echo Run 'Start-SIEM.bat' to start the system.
echo.
pause
