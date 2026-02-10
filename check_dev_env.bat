@echo off
echo ========================================================
echo      Agent Security Extension Environment Check
echo ========================================================
echo.

echo [1/2] Checking for Node.js (Required for VS Code Extension)...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [X] Node.js is NOT found.
    echo     Please install from: https://nodejs.org/
) else (
    echo [OK] Node.js is installed.
    node --version
)

echo.
echo [2/2] Checking for Python (Required for Security Analyzer)...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [X] Python is NOT found in PATH.
    echo     Please install from: https://www.python.org/downloads/
    echo     IMPORTANT: Check "Add Python to PATH" during installation.
) else (
    echo [OK] Python is installed.
    python --version
)

echo.
echo ========================================================
echo.
pause
