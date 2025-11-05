@echo off
REM SecureOps AI Frontend Startup Script for Windows

echo.
echo 🌐 Starting SecureOps AI Frontend...
echo ===================================
echo.

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Check if Node.js is available
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if npm is available
npm --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is not available
    pause
    exit /b 1
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo [INFO] Installing dependencies...
    npm install
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Start the development server
echo [INFO] Starting frontend server on http://localhost:3010
echo [INFO] Press Ctrl+C to stop the server
echo.

npm run dev