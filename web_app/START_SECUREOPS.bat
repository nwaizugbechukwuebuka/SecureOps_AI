@echo off
REM SecureOps AI - Complete System Startup Script for Windows

setlocal enabledelayedexpansion

echo.
echo 🛡️ SecureOps AI - Complete System Startup
echo ========================================
echo.

REM Get script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Function to check if port is available
:check_port
set "port=%1"
netstat -an | findstr ":%port% " > nul
if %errorlevel% == 0 (
    echo [WARNING] Port %port% is already in use
    for /f "tokens=5" %%i in ('netstat -ano ^| findstr ":%port% "') do (
        echo [INFO] Process using port %port%: %%i
        set /p "kill=Do you want to kill process %%i? (y/N): "
        if /i "!kill!"=="y" (
            taskkill /F /PID %%i
            echo [INFO] Process %%i terminated
        )
    )
)
exit /b 0

REM Check dependencies
echo [INFO] Checking system dependencies...

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo [INFO] Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)
echo [✓] Python is available

REM Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH
    echo [INFO] Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)
echo [✓] Node.js is available

REM Check npm
npm --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is not available
    pause
    exit /b 1
)
echo [✓] npm is available

echo.
echo [INFO] Setting up environment...

REM Create necessary directories
if not exist "backend\data" mkdir "backend\data"
if not exist "backend\logs" mkdir "backend\logs"
if not exist "backend\uploads" mkdir "backend\uploads"
echo [✓] Backend directories created

REM Check and kill processes on ports 3010 and 8000
echo.
echo [INFO] Checking ports...
call :check_port 3010
call :check_port 8000

REM Install backend dependencies if needed
cd /d "%SCRIPT_DIR%backend"
if not exist "__pycache__" (
    echo [INFO] Installing backend dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install backend dependencies
        pause
        exit /b 1
    )
)
echo [✓] Backend dependencies ready

REM Install frontend dependencies if needed
cd /d "%SCRIPT_DIR%frontend"
if not exist "node_modules" (
    echo [INFO] Installing frontend dependencies...
    npm install
    if errorlevel 1 (
        echo [ERROR] Failed to install frontend dependencies
        pause
        exit /b 1
    )
)
echo [✓] Frontend dependencies ready

echo.
echo 🚀 Starting Services...
echo ====================

REM Start backend in background
cd /d "%SCRIPT_DIR%backend"
echo [INFO] Starting backend server on http://localhost:8000...
start /b cmd /c "python start.py > ..\logs\backend.log 2>&1"

REM Wait for backend to start
echo [INFO] Waiting for backend to start...
set "backend_ready=false"
for /l %%i in (1,1,30) do (
    timeout /t 1 >nul
    curl -f "http://localhost:8000/health" >nul 2>&1
    if !errorlevel! == 0 (
        set "backend_ready=true"
        goto backend_started
    )
    echo [INFO] Waiting... (%%i/30)
)

:backend_started
if "%backend_ready%" == "false" (
    echo [ERROR] Backend failed to start within 30 seconds
    echo [INFO] Check logs\backend.log for details
    pause
    exit /b 1
)
echo [✓] Backend is ready at http://localhost:8000

REM Start frontend
cd /d "%SCRIPT_DIR%frontend"
echo [INFO] Starting frontend server on http://localhost:3010...
start /b cmd /c "npm run dev > ..\logs\frontend.log 2>&1"

REM Wait for frontend to start
echo [INFO] Waiting for frontend to start...
set "frontend_ready=false"
for /l %%i in (1,1,30) do (
    timeout /t 1 >nul
    curl -f "http://localhost:3010" >nul 2>&1
    if !errorlevel! == 0 (
        set "frontend_ready=true"
        goto frontend_started
    )
    echo [INFO] Waiting... (%%i/30)
)

:frontend_started
if "%frontend_ready%" == "false" (
    echo [ERROR] Frontend failed to start within 30 seconds
    echo [INFO] Check logs\frontend.log for details
)

echo.
echo 🎉 SecureOps AI is Ready!
echo ========================
echo.
echo 🌐 Frontend Application: http://localhost:3010
echo 🔧 Backend API:          http://localhost:8000  
echo 📚 API Documentation:    http://localhost:8000/docs
echo 📖 API ReDoc:            http://localhost:8000/redoc
echo.
echo 🔑 Default Login Credentials:
echo    Username: admin
echo    Password: admin123
echo.
echo 📋 Management Commands:
echo    View Logs: type logs
echo    Stop All:  type stop  
echo    Restart:   type restart
echo.

:menu
set /p "action=Enter command (logs/stop/restart/exit): "

if /i "%action%"=="logs" (
    echo.
    echo === Backend Logs ===
    if exist "..\logs\backend.log" type "..\logs\backend.log"
    echo.
    echo === Frontend Logs ===
    if exist "..\logs\frontend.log" type "..\logs\frontend.log"
    echo.
    goto menu
)

if /i "%action%"=="stop" (
    echo [INFO] Stopping services...
    taskkill /F /IM python.exe >nul 2>&1
    taskkill /F /IM node.exe >nul 2>&1
    echo [INFO] Services stopped
    goto menu
)

if /i "%action%"=="restart" (
    echo [INFO] Restarting services...
    taskkill /F /IM python.exe >nul 2>&1
    taskkill /F /IM node.exe >nul 2>&1
    timeout /t 2 >nul
    goto backend_start
)

if /i "%action%"=="exit" (
    echo [INFO] Stopping services before exit...
    taskkill /F /IM python.exe >nul 2>&1
    taskkill /F /IM node.exe >nul 2>&1
    echo [INFO] Goodbye!
    exit /b 0
)

echo [ERROR] Invalid command. Use: logs, stop, restart, or exit
goto menu