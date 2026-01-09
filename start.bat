@echo off
REM ============================================
REM Boundary-SIEM Start Script
REM Automatically starts ClickHouse and SIEM
REM ============================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo.
echo ========================================
echo    Boundary-SIEM Startup
echo ========================================
echo.

REM Check if the binary exists
if not exist "bin\siem-ingest.exe" (
    echo [ERROR] Binary not found: bin\siem-ingest.exe
    echo.
    echo Please run build.bat first to compile the project
    echo.
    pause
    exit /b 1
)

REM ----------------------------------------
REM Start ClickHouse if available
REM ----------------------------------------
set "CH_EXE=clickhouse\clickhouse.exe"
set "CH_RUNNING=0"

if exist "%CH_EXE%" (
    echo [INFO] Checking ClickHouse status...

    REM Check if ClickHouse is already running
    tasklist /FI "IMAGENAME eq clickhouse.exe" 2>nul | find /i "clickhouse.exe" >nul
    if !ERRORLEVEL! equ 0 (
        echo [OK] ClickHouse is already running
        set "CH_RUNNING=1"
    ) else (
        echo [INFO] Starting ClickHouse server...

        REM Create data directories if needed
        if not exist "clickhouse\data" mkdir "clickhouse\data"
        if not exist "clickhouse\logs" mkdir "clickhouse\logs"

        REM Start ClickHouse in background
        start "ClickHouse Server" /MIN cmd /c ""%CH_EXE%" server --config-file=clickhouse\config.xml 2>clickhouse\logs\stderr.log"

        REM Wait for ClickHouse to start
        echo [INFO] Waiting for ClickHouse to initialize...
        timeout /t 3 /nobreak >nul

        REM Verify it started
        tasklist /FI "IMAGENAME eq clickhouse.exe" 2>nul | find /i "clickhouse.exe" >nul
        if !ERRORLEVEL! equ 0 (
            echo [OK] ClickHouse started successfully
            set "CH_RUNNING=1"
        ) else (
            echo [WARNING] ClickHouse may not have started properly
            echo           Check clickhouse\logs\ for details
        )
    )
) else (
    echo [WARNING] ClickHouse not found at: %CH_EXE%
    echo           Run setup-clickhouse.bat to install it
    echo           Or disable storage in configs\config.yaml
    echo.

    REM Check if storage is enabled in config
    findstr /C:"enabled: true" configs\config.yaml >nul 2>nul
    if !ERRORLEVEL! equ 0 (
        echo [ERROR] Storage is enabled but ClickHouse is not installed
        echo         Please either:
        echo           1. Run setup-clickhouse.bat to install ClickHouse
        echo           2. Edit configs\config.yaml and set storage.enabled: false
        echo.
        pause
        exit /b 1
    )
)

REM ----------------------------------------
REM Start SIEM Service
REM ----------------------------------------
echo.
echo [INFO] Starting Boundary-SIEM Ingest Service...
echo.
echo ----------------------------------------
echo  HTTP API:     http://localhost:8080
echo  Health:       http://localhost:8080/health
echo  Search API:   http://localhost:8080/v1/search
echo  CEF TCP:      localhost:5515
echo  ClickHouse:   %CH_RUNNING% (1=running, 0=not available)
echo ----------------------------------------
echo.
echo Press Ctrl+C to stop the service
echo.

REM Start the service
bin\siem-ingest.exe

REM If we get here, the service has stopped
echo.
echo [INFO] SIEM service stopped

REM Optionally stop ClickHouse when SIEM stops
if exist "%CH_EXE%" (
    echo [INFO] Stopping ClickHouse...
    taskkill /F /IM clickhouse.exe >nul 2>nul
)

pause
