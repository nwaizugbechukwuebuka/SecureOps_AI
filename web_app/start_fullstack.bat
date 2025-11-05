@echo off
echo.
echo 🚀 Starting SecureOps AI Full Stack
echo =====================================
echo.

REM Kill any existing processes on our ports
echo 📋 Cleaning up existing processes...
taskkill /F /IM node.exe 2>nul
taskkill /F /IM python.exe 2>nul
timeout /t 2 >nul

REM Check if backend is already running
netstat -ano | findstr :8000 >nul
if %errorlevel% equ 0 (
    echo ✅ Backend already running on port 8000
) else (
    echo 🔧 Starting Backend API on port 8000...
    start "SecureOps Backend" cmd /c "cd backend && python start.py"
    timeout /t 5 >nul
)

REM Check if frontend is already running
netstat -ano | findstr :3010 >nul
if %errorlevel% equ 0 (
    echo ✅ Frontend already running on port 3010
) else (
    echo 🌐 Starting Frontend on port 3010...
    start "SecureOps Frontend" cmd /c "cd frontend && npm run dev"
    timeout /t 5 >nul
)

echo.
echo ⏳ Waiting for services to start...
timeout /t 10 >nul

echo.
echo 🔍 Checking service status...

REM Test backend
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 10; Write-Host '✅ Backend: RUNNING (' $response.StatusCode ')' } catch { Write-Host '❌ Backend: NOT ACCESSIBLE' }"

REM Test frontend
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:3010' -TimeoutSec 10; Write-Host '✅ Frontend: RUNNING (' $response.StatusCode ')' } catch { Write-Host '❌ Frontend: NOT ACCESSIBLE' }"

echo.
echo 🎉 SecureOps AI is ready!
echo ========================
echo.
echo 🌐 Frontend: http://localhost:3010
echo 🔧 Backend API: http://localhost:8000
echo 📚 API Docs: http://localhost:8000/api/docs
echo.
echo 🔑 Default Login:
echo    Username: admin
echo    Password: admin123
echo.
echo Press any key to open the web application...
pause >nul

start http://localhost:3010

echo.
echo 📝 Useful Commands:
echo    - View backend logs: Check the Backend terminal window
echo    - View frontend logs: Check the Frontend terminal window
echo    - Stop services: Close both terminal windows or Ctrl+C
echo.
pause