@echo off
REM ============================================
REM Boundary-SIEM Build Script
REM One-click setup and build for Windows
REM ============================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo    Boundary-SIEM One-Click Setup
echo ========================================
echo.

REM ----------------------------------------
REM Step 1: Check Prerequisites
REM ----------------------------------------
echo [STEP 1/6] Checking prerequisites...

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go is not installed or not in PATH
    echo Please install Go 1.26+ from https://go.dev/dl/
    pause
    exit /b 1
)

echo [OK] Go version:
go version
echo.

REM ----------------------------------------
REM Step 2: Create Required Directories
REM ----------------------------------------
echo [STEP 2/6] Creating required directories...

REM Create all required directories
for %%d in (bin data data\events logs certs configs) do (
    if not exist "%%d" (
        mkdir "%%d"
        echo [CREATED] %%d\
    ) else (
        echo [EXISTS] %%d\
    )
)
echo.

REM ----------------------------------------
REM Step 3: Generate Development Certificates
REM ----------------------------------------
echo [STEP 3/6] Checking TLS certificates...

if not exist "certs\server.crt" (
    echo [INFO] No certificates found. Generating self-signed development certificates...

    REM Check if openssl is available
    where openssl >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo [INFO] Using OpenSSL to generate certificates...

        REM Generate private key
        openssl genrsa -out certs\server.key 2048 2>nul

        REM Generate self-signed certificate
        openssl req -new -x509 -sha256 -key certs\server.key -out certs\server.crt -days 365 -subj "/CN=localhost/O=Boundary-SIEM/C=US" 2>nul

        if exist "certs\server.crt" (
            echo [SUCCESS] Development certificates generated:
            echo           - certs\server.crt
            echo           - certs\server.key
            echo.
            echo [WARNING] These are SELF-SIGNED certificates for development only!
            echo           Use proper CA-signed certificates in production.
        ) else (
            echo [WARNING] Certificate generation failed
            echo           TLS features will be disabled
        )
    ) else (
        echo [INFO] OpenSSL not found - skipping certificate generation
        echo        To enable TLS, install OpenSSL and re-run build.bat
        echo        Or manually place certificates in certs\ directory
    )
) else (
    echo [EXISTS] TLS certificates already configured
)
echo.

REM ----------------------------------------
REM Step 4: Download Dependencies
REM ----------------------------------------
echo [STEP 4/6] Downloading Go dependencies...

go mod download
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download dependencies
    pause
    exit /b 1
)

go mod tidy
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to tidy modules
    pause
    exit /b 1
)

echo [SUCCESS] Dependencies downloaded
echo.

REM ----------------------------------------
REM Step 5: Build Binaries
REM ----------------------------------------
echo [STEP 5/6] Building binaries...

REM Set version from git if available
set VERSION=dev
where git >nul 2>nul
if %ERRORLEVEL% equ 0 (
    for /f "tokens=*" %%i in ('git describe --tags --always 2^>nul') do set VERSION=%%i
)

REM Build the ingest service
echo [INFO] Building siem-ingest (version: %VERSION%)...
go build -ldflags="-s -w -X main.version=%VERSION%" -o bin\siem-ingest.exe .\cmd\siem-ingest
if %ERRORLEVEL% neq 0 (
    echo [ERROR] siem-ingest build failed
    pause
    exit /b 1
)
echo [SUCCESS] bin\siem-ingest.exe

REM Build the TUI
echo [INFO] Building boundary-siem TUI...
go build -ldflags="-s -w -X main.version=%VERSION%" -o bin\boundary-siem.exe .\cmd\boundary-siem
if %ERRORLEVEL% neq 0 (
    echo [ERROR] TUI build failed
    pause
    exit /b 1
)
echo [SUCCESS] bin\boundary-siem.exe

REM Build the rule validator
echo [INFO] Building siem-rules...
go build -ldflags="-s -w" -o bin\siem-rules.exe .\cmd\siem-rules
if %ERRORLEVEL% neq 0 (
    echo [ERROR] siem-rules build failed
    pause
    exit /b 1
)
echo [SUCCESS] bin\siem-rules.exe
echo.

REM ----------------------------------------
REM Step 6: Build Frontend (Optional)
REM ----------------------------------------
echo [STEP 6/6] Building frontend (optional)...

where npm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    if exist "web" (
        echo [INFO] Node.js found, building frontend...
        pushd web

        call npm install >nul 2>nul
        if %ERRORLEVEL% neq 0 (
            echo [WARNING] Failed to install frontend dependencies
            popd
            goto :summary
        )

        call npm run build >nul 2>nul
        if %ERRORLEVEL% neq 0 (
            echo [WARNING] Frontend build failed
            popd
            goto :summary
        )

        echo [SUCCESS] Frontend built
        popd
    ) else (
        echo [SKIP] No web directory found
    )
) else (
    echo [SKIP] Node.js not installed (optional for web UI)
)

:summary
echo.
echo ========================================
echo    Setup Complete!
echo ========================================
echo.
echo Directory Structure:
echo   bin\             - Compiled binaries
echo   data\            - Event data storage
echo   logs\            - Application logs
echo   certs\           - TLS certificates
echo   configs\         - Configuration files
echo.
echo Binaries Built:
echo   bin\siem-ingest.exe    - SIEM Ingest Service
echo   bin\boundary-siem.exe  - Terminal User Interface
echo   bin\siem-rules.exe     - Rule validator
echo.
echo ========================================
echo    Quick Start Guide
echo ========================================
echo.
echo 1. SET AN API KEY (the shipped config requires one):
echo    set SIEM_API_KEY=dev-key-change-me
echo.
echo 2. START THE SERVICE:
echo    start.bat
echo.
echo 3. LAUNCH THE TUI (separate terminal, same SIEM_API_KEY):
echo    run-tui.bat
echo.
echo 4. TEST THE API:
echo    curl http://localhost:8080/health
echo    curl -H "X-API-Key: %%SIEM_API_KEY%%" http://localhost:8080/v1/alerts
echo.
echo ========================================
echo    Security Notes
echo ========================================
echo.
echo - Plain UDP is DISABLED by default (insecure)
echo - Enable TLS in configs\config.yaml for production
echo - Authentication is enabled: every API call needs the X-API-Key header
echo - Review startup diagnostics for warnings
echo.
pause
