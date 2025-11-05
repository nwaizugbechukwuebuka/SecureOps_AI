@echo off
echo 🚀 Starting SecureOps AI Full Stack Application...

REM Stop any running containers
echo 🛑 Stopping existing containers...
docker-compose down

REM Build and start services
echo 🔨 Building and starting services...
docker-compose up --build -d

REM Wait for services to start
echo ⏳ Waiting for services to start...
timeout /t 30 /nobreak > nul

REM Check service status
echo 📊 Service Status:
echo Backend (FastAPI): http://localhost:8001
echo Frontend (React): http://localhost:3010
echo Redis: localhost:6379
echo API Docs: http://localhost:8001/api/docs

REM Check if services are responding
echo 🔍 Checking service health...

curl -f -s http://localhost:8001/health > nul 2>&1
if %errorlevel%==0 (
    echo ✅ Backend is healthy
) else (
    echo ❌ Backend is not responding
)

curl -f -s http://localhost:3010 > nul 2>&1
if %errorlevel%==0 (
    echo ✅ Frontend is healthy
    echo 🌐 Opening application in browser...
    start http://localhost:3010
) else (
    echo ❌ Frontend is not responding
)

echo 📋 Useful commands:
echo   docker-compose logs -f        # View logs
echo   docker-compose down           # Stop all services
echo   docker-compose exec backend bash   # Access backend container
echo   docker-compose exec frontend sh    # Access frontend container

echo 🎉 SecureOps AI is running!
echo 🌐 Access the application at: http://localhost:3010
pause