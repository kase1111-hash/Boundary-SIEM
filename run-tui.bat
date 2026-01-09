@echo off
REM ============================================
REM Boundary-SIEM TUI Launch Script
REM One-click startup for Windows
REM ============================================

echo.
echo ========================================
echo    Boundary-SIEM TUI
echo ========================================
echo.

REM Check if the binary exists
if not exist "bin\boundary-siem.exe" (
    echo [ERROR] Binary not found: bin\boundary-siem.exe
    echo.
    echo Please run build.bat first to compile the project
    echo.
    pause
    exit /b 1
)

REM Default server URL
set SERVER_URL=http://localhost:8080

REM Check for command line argument
if not "%~1"=="" (
    set SERVER_URL=%~1
)

echo [INFO] Connecting to: %SERVER_URL%
echo.
echo ----------------------------------------
echo  Controls:
echo    [1] Dashboard    [2] Events
echo    [Tab] Switch tabs
echo    [j/k] or arrows to navigate
echo    [q] Quit
echo ----------------------------------------
echo.

REM Start the TUI
bin\boundary-siem.exe -s %SERVER_URL%

REM If we get here, the TUI has exited
echo.
echo [INFO] TUI closed
pause
