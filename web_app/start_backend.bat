@echo off
REM SecureOps AI Backend Startup Script for Windows

echo.
echo 🚀 Starting SecureOps AI Backend...
echo ====================================
echo.

REM Navigate to backend directory
cd /d "%~dp0backend"

REM Set environment variables
set ENVIRONMENT=development
set DEBUG=true
set HOST=0.0.0.0
set PORT=8000

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Start the backend server
echo [INFO] Starting backend server on http://localhost:8000
echo [INFO] Press Ctrl+C to stop the server
echo.

python start.py

pause