@echo off
REM ============================================
REM Boundary-SIEM Build Script
REM One-click assembly for Windows
REM ============================================

echo.
echo ========================================
echo    Boundary-SIEM Build Script
echo ========================================
echo.

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go is not installed or not in PATH
    echo Please install Go 1.24.7+ from https://golang.org/dl/
    pause
    exit /b 1
)

echo [INFO] Go version:
go version
echo.

REM Create bin directory if it doesn't exist
if not exist "bin" (
    echo [INFO] Creating bin directory...
    mkdir bin
)

REM Download and tidy dependencies
echo [INFO] Downloading dependencies...
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

echo [INFO] Dependencies downloaded successfully
echo.

REM Build the ingest service
echo [INFO] Building siem-ingest...
go build -ldflags="-s -w" -o bin\siem-ingest.exe .\cmd\siem-ingest
if %ERRORLEVEL% neq 0 (
    echo [ERROR] siem-ingest build failed
    pause
    exit /b 1
)
echo [SUCCESS] Ingest service: bin\siem-ingest.exe
echo.

REM Build the TUI
echo [INFO] Building boundary-siem TUI...
go build -ldflags="-s -w" -o bin\boundary-siem.exe .\cmd\boundary-siem
if %ERRORLEVEL% neq 0 (
    echo [ERROR] TUI build failed
    pause
    exit /b 1
)
echo [SUCCESS] TUI application: bin\boundary-siem.exe
echo.

REM Check if Node.js is available for frontend build
where npm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [INFO] Node.js found, building frontend...

    if exist "web" (
        pushd web

        echo [INFO] Installing frontend dependencies...
        call npm install
        if %ERRORLEVEL% neq 0 (
            echo [WARNING] Failed to install frontend dependencies
            popd
            goto :end
        )

        echo [INFO] Building frontend...
        call npm run build
        if %ERRORLEVEL% neq 0 (
            echo [WARNING] Frontend build failed
            popd
            goto :end
        )

        echo [SUCCESS] Frontend build complete
        popd
    ) else (
        echo [INFO] No web directory found, skipping frontend build
    )
) else (
    echo [INFO] Node.js not found, skipping frontend build
    echo        Install Node.js to build the web frontend
)

:end
echo.
echo ========================================
echo    Build Complete!
echo ========================================
echo.
echo Binaries:
echo   - bin\siem-ingest.exe   (Ingest Service)
echo   - bin\boundary-siem.exe (Terminal UI)
echo.
echo Run 'start.bat' to launch the ingest service
echo Run 'run-tui.bat' to launch the TUI
echo.
pause
