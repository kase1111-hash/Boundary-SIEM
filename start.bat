@echo off
REM ============================================
REM Boundary-SIEM Start Script
REM One-click startup for Windows
REM ============================================

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

REM Check if config exists
if exist "configs\config.yaml" (
    echo [INFO] Using configuration: configs\config.yaml
) else (
    echo [WARNING] No config file found at configs\config.yaml
    echo          Using default configuration
)

echo.
echo [INFO] Starting Boundary-SIEM Ingest Service...
echo.
echo ----------------------------------------
echo  HTTP API:    http://localhost:8080
echo  Health:      http://localhost:8080/health
echo  Metrics:     http://localhost:8080/metrics
echo  CEF UDP:     localhost:5514
echo  CEF TCP:     localhost:5515
echo ----------------------------------------
echo.
echo Press Ctrl+C to stop the service
echo.

REM Start the service
bin\siem-ingest.exe

REM If we get here, the service has stopped
echo.
echo [INFO] Service stopped
pause
