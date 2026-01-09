@echo off
REM ============================================
REM Boundary-SIEM Portable Build Script
REM Builds standalone Windows EXE for USB drive
REM ============================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo    Boundary-SIEM Portable Builder
echo    Standalone Windows EXE for USB
echo ========================================
echo.

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM ----------------------------------------
REM Configuration
REM ----------------------------------------
set "OUTPUT_DIR=Boundary-SIEM-Portable"
set "BUILD_DATE=%date:~-4%%date:~4,2%%date:~7,2%"

REM ----------------------------------------
REM Step 1: Check Prerequisites
REM ----------------------------------------
echo [STEP 1/7] Checking prerequisites...

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go is not installed or not in PATH
    echo.
    echo To build from source, you need Go 1.21 or later:
    echo   https://golang.org/dl/
    echo.
    pause
    exit /b 1
)

echo [OK] Go version:
go version
echo.

REM ----------------------------------------
REM Step 2: Clean Previous Build
REM ----------------------------------------
echo [STEP 2/7] Preparing build directory...

if exist "%OUTPUT_DIR%" (
    echo [INFO] Removing previous portable build...
    rmdir /s /q "%OUTPUT_DIR%" 2>nul
)

REM Create portable directory structure
mkdir "%OUTPUT_DIR%"
mkdir "%OUTPUT_DIR%\bin"
mkdir "%OUTPUT_DIR%\data"
mkdir "%OUTPUT_DIR%\data\events"
mkdir "%OUTPUT_DIR%\logs"
mkdir "%OUTPUT_DIR%\certs"
mkdir "%OUTPUT_DIR%\configs"

echo [OK] Directory structure created
echo.

REM ----------------------------------------
REM Step 3: Download Dependencies
REM ----------------------------------------
echo [STEP 3/7] Downloading Go dependencies...

go mod download
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download dependencies
    pause
    exit /b 1
)

go mod tidy
echo [OK] Dependencies ready
echo.

REM ----------------------------------------
REM Step 4: Build Static Windows Binaries
REM ----------------------------------------
echo [STEP 4/7] Building portable Windows executables...

REM Set version
set VERSION=portable
where git >nul 2>nul
if %ERRORLEVEL% equ 0 (
    for /f "tokens=*" %%i in ('git describe --tags --always 2^>nul') do set VERSION=%%i
)
set VERSION=%VERSION%-portable

REM Build flags for static, portable executable
REM CGO_ENABLED=0: Pure Go, no C dependencies
REM -ldflags "-s -w": Strip debug symbols for smaller size
REM -trimpath: Remove file system paths from binary
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

echo [INFO] Building siem-ingest.exe (version: %VERSION%)...
echo        Target: Windows x64, Static Binary
go build -trimpath -ldflags="-s -w -X main.version=%VERSION%" -o "%OUTPUT_DIR%\bin\siem-ingest.exe" .\cmd\siem-ingest
if %ERRORLEVEL% neq 0 (
    echo [ERROR] siem-ingest build failed
    pause
    exit /b 1
)
echo [OK] siem-ingest.exe built

echo [INFO] Building boundary-siem.exe (TUI)...
go build -trimpath -ldflags="-s -w -X main.version=%VERSION%" -o "%OUTPUT_DIR%\bin\boundary-siem.exe" .\cmd\boundary-siem
if %ERRORLEVEL% neq 0 (
    echo [ERROR] boundary-siem build failed
    pause
    exit /b 1
)
echo [OK] boundary-siem.exe built
echo.

REM ----------------------------------------
REM Step 5: Copy Configuration Files
REM ----------------------------------------
echo [STEP 5/7] Setting up portable configuration...

REM Copy config if exists, otherwise create default
if exist "configs\config.yaml" (
    copy "configs\config.yaml" "%OUTPUT_DIR%\configs\config.yaml" >nul
    echo [OK] Configuration file copied
) else (
    REM Create minimal portable config
    (
        echo # Boundary-SIEM Portable Configuration
        echo # All paths are relative for USB portability
        echo.
        echo server:
        echo   http_port: 8080
        echo   read_timeout: 30s
        echo   write_timeout: 30s
        echo.
        echo ingest:
        echo   max_batch_size: 1000
        echo   max_payload_size: 10485760
        echo   cef:
        echo     udp:
        echo       enabled: false
        echo       address: ":5514"
        echo     tcp:
        echo       enabled: true
        echo       address: ":5515"
        echo       tls_enabled: false
        echo     parser:
        echo       strict_mode: false
        echo.
        echo queue:
        echo   size: 100000
        echo   overflow_policy: reject
        echo.
        echo validation:
        echo   max_event_age: 168h
        echo   max_future: 5m
        echo   strict_mode: false
        echo.
        echo auth:
        echo   enabled: false
        echo.
        echo logging:
        echo   level: info
        echo   format: json
        echo.
        echo storage:
        echo   enabled: false
        echo.
        echo consumer:
        echo   workers: 4
        echo   poll_interval: 10ms
        echo   shutdown_wait: 30s
    ) > "%OUTPUT_DIR%\configs\config.yaml"
    echo [OK] Default configuration created
)
echo.

REM ----------------------------------------
REM Step 6: Create Portable Launcher Scripts
REM ----------------------------------------
echo [STEP 6/7] Creating portable launcher scripts...

REM Main launcher - Start Service
(
    echo @echo off
    echo REM ============================================
    echo REM Boundary-SIEM Portable Launcher
    echo REM Run from USB drive or any location
    echo REM ============================================
    echo.
    echo setlocal enabledelayedexpansion
    echo.
    echo REM Get the directory where this script is located
    echo set "PORTABLE_DIR=%%~dp0"
    echo cd /d "%%PORTABLE_DIR%%"
    echo.
    echo echo.
    echo echo ========================================
    echo echo    Boundary-SIEM Portable Edition
    echo echo ========================================
    echo echo.
    echo echo [INFO] Running from: %%PORTABLE_DIR%%
    echo echo.
    echo.
    echo REM Check if binary exists
    echo if not exist "bin\siem-ingest.exe" ^(
    echo     echo [ERROR] Binary not found: bin\siem-ingest.exe
    echo     echo         This portable package may be corrupted.
    echo     pause
    echo     exit /b 1
    echo ^)
    echo.
    echo echo ----------------------------------------
    echo echo  Endpoints:
    echo echo    HTTP API:    http://localhost:8080
    echo echo    Health:      http://localhost:8080/health
    echo echo    CEF TCP:     localhost:5515
    echo echo ----------------------------------------
    echo echo.
    echo echo Press Ctrl+C to stop the service
    echo echo.
    echo.
    echo REM Start service with config from portable directory
    echo "%%PORTABLE_DIR%%bin\siem-ingest.exe" -config "%%PORTABLE_DIR%%configs\config.yaml"
    echo.
    echo echo.
    echo echo [INFO] Service stopped
    echo pause
) > "%OUTPUT_DIR%\Start-SIEM.bat"
echo [OK] Start-SIEM.bat created

REM TUI launcher
(
    echo @echo off
    echo REM ============================================
    echo REM Boundary-SIEM TUI Launcher ^(Portable^)
    echo REM ============================================
    echo.
    echo setlocal enabledelayedexpansion
    echo.
    echo set "PORTABLE_DIR=%%~dp0"
    echo cd /d "%%PORTABLE_DIR%%"
    echo.
    echo set "SERVER_URL=http://localhost:8080"
    echo if not "%%~1"=="" set "SERVER_URL=%%~1"
    echo.
    echo echo.
    echo echo ========================================
    echo echo    Boundary-SIEM TUI ^(Portable^)
    echo echo ========================================
    echo echo.
    echo echo [INFO] Connecting to: %%SERVER_URL%%
    echo echo.
    echo echo ----------------------------------------
    echo echo  Controls:
    echo echo    [1] Dashboard    [2] Events
    echo echo    [Tab] Switch tabs
    echo echo    [j/k] Navigate
    echo echo    [q] Quit
    echo echo ----------------------------------------
    echo echo.
    echo.
    echo if not exist "bin\boundary-siem.exe" ^(
    echo     echo [ERROR] TUI binary not found
    echo     pause
    echo     exit /b 1
    echo ^)
    echo.
    echo "%%PORTABLE_DIR%%bin\boundary-siem.exe" -s %%SERVER_URL%%
    echo.
    echo echo.
    echo pause
) > "%OUTPUT_DIR%\Start-TUI.bat"
echo [OK] Start-TUI.bat created

REM Quick info script
(
    echo @echo off
    echo echo.
    echo echo ========================================
    echo echo    Boundary-SIEM Portable Edition
    echo echo ========================================
    echo echo.
    echo echo This is a portable SIEM ^(Security Information
    echo echo and Event Management^) system that runs
    echo echo directly from a USB drive without installation.
    echo echo.
    echo echo FILES:
    echo echo   Start-SIEM.bat   - Start the SIEM service
    echo echo   Start-TUI.bat    - Launch terminal dashboard
    echo echo   bin\             - Executable files
    echo echo   configs\         - Configuration files
    echo echo   data\            - Event data storage
    echo echo   logs\            - Application logs
    echo echo.
    echo echo QUICK START:
    echo echo   1. Run Start-SIEM.bat to start the service
    echo echo   2. Run Start-TUI.bat in another window
    echo echo   3. Access http://localhost:8080 in browser
    echo echo.
    echo echo ========================================
    echo echo.
    echo pause
) > "%OUTPUT_DIR%\README.bat"
echo [OK] README.bat created
echo.

REM ----------------------------------------
REM Step 7: Create Distribution Package (Optional)
REM ----------------------------------------
echo [STEP 7/7] Creating distribution package...

REM Check if zip is available (PowerShell method)
where powershell >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "ZIP_NAME=Boundary-SIEM-Portable-%VERSION%.zip"
    echo [INFO] Creating %ZIP_NAME%...
    powershell -Command "Compress-Archive -Path '%OUTPUT_DIR%\*' -DestinationPath '%ZIP_NAME%' -Force" 2>nul
    if exist "%ZIP_NAME%" (
        echo [OK] Distribution ZIP created: %ZIP_NAME%
    ) else (
        echo [SKIP] ZIP creation failed - folder is still available
    )
) else (
    echo [SKIP] PowerShell not available - manual zip required
)

REM ----------------------------------------
REM Summary
REM ----------------------------------------
echo.
echo ========================================
echo    Portable Build Complete!
echo ========================================
echo.
echo Output Directory: %OUTPUT_DIR%\
echo.
echo Contents:
for /f %%a in ('dir /s /b "%OUTPUT_DIR%\bin\*.exe" 2^>nul ^| find /c ".exe"') do echo   Executables: %%a
echo   - Start-SIEM.bat  (Service launcher)
echo   - Start-TUI.bat   (Dashboard launcher)
echo   - README.bat      (Quick help)
echo.

REM Show file sizes
echo Binary Sizes:
for %%f in ("%OUTPUT_DIR%\bin\*.exe") do (
    set "SIZE=%%~zf"
    set /a "SIZE_MB=!SIZE! / 1048576"
    echo   %%~nxf: !SIZE_MB! MB
)
echo.

echo ========================================
echo    USB Drive Instructions
echo ========================================
echo.
echo 1. Copy the entire '%OUTPUT_DIR%' folder to your USB drive
echo 2. Run 'Start-SIEM.bat' to launch the service
echo 3. Run 'Start-TUI.bat' to open the dashboard
echo.
echo No installation required - runs directly from USB!
echo All data stays within the portable folder.
echo.

if exist "Boundary-SIEM-Portable-*.zip" (
    echo Distribution Package:
    dir /b Boundary-SIEM-Portable-*.zip 2>nul
    echo.
)

echo ========================================
echo.
pause
