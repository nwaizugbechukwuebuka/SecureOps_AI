@echo off
REM SecureOps AI - Windows Development Setup Script

echo.
echo 🚀 Setting up SecureOps AI Development Environment
echo =================================================
echo.

REM Check if Docker is installed and running
echo [INFO] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop and try again.
    pause
    exit /b 1
)

echo [SUCCESS] Docker is installed

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker daemon is not running. Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo [SUCCESS] Docker is running

REM Create necessary directories
echo [INFO] Creating necessary directories...
if not exist "backend\logs" mkdir backend\logs
if not exist "backend\data" mkdir backend\data
if not exist "backend\uploads" mkdir backend\uploads
if not exist "backend\backups" mkdir backend\backups
if not exist "backend\temp" mkdir backend\temp
if not exist "ssl" mkdir ssl
if not exist "logs" mkdir logs

echo [SUCCESS] Directories created

REM Setup environment file
echo [INFO] Setting up environment configuration...
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [SUCCESS] Environment file created from example
        echo [WARNING] Please review and update .env file with your specific configuration
    ) else (
        echo [INFO] Creating basic .env file...
        (
            echo # Basic development configuration
            echo DEBUG=true
            echo ENVIRONMENT=development
            echo JWT_SECRET_KEY=dev-secret-key-change-in-production
            echo DATABASE_URL=sqlite:///./data/secureops.db
            echo REDIS_URL=redis://localhost:6379/0
            echo FRONTEND_URL=http://localhost:3010
        ) > .env
        echo [SUCCESS] Basic .env file created
    )
) else (
    echo [SUCCESS] Environment file already exists
)

REM Build and start services
echo [INFO] Building and starting development services...
docker-compose build
if errorlevel 1 (
    echo [ERROR] Failed to build Docker images
    pause
    exit /b 1
)

docker-compose up -d
if errorlevel 1 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)

echo [SUCCESS] Development services started

REM Wait for services to be ready
echo [INFO] Waiting for services to be ready...
timeout /t 10 >nul

REM Check backend health
echo [INFO] Checking backend service...
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8000/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host '[SUCCESS] Backend is ready' } catch { Write-Host '[WARNING] Backend may still be starting up' }"

REM Check frontend
echo [INFO] Checking frontend service...
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:3010' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host '[SUCCESS] Frontend is ready' } catch { Write-Host '[WARNING] Frontend may still be starting up' }"

echo.
echo 🎉 SecureOps AI Development Environment is Ready!
echo ===============================================
echo.
echo 📊 Web Application: http://localhost:3010
echo 🔧 API Backend: http://localhost:8000
echo 📚 API Documentation: http://localhost:8000/docs
echo 📖 ReDoc: http://localhost:8000/redoc
echo.
echo 🛠️ Development Tools:
echo    📧 Mailhog (Email testing): http://localhost:8025
echo    🗄️ Redis Commander: http://localhost:8081
echo    🗃️ Adminer (Database): http://localhost:8082
echo.
echo 📈 Monitoring (if enabled):
echo    📊 Prometheus: http://localhost:9090
echo    📈 Grafana: http://localhost:3000
echo.
echo 🔑 Default Credentials:
echo    Admin User: admin / admin123
echo    Demo User: demo / demo123
echo    Grafana: admin / admin123
echo.
echo 📝 Useful Commands:
echo    🔍 View logs: docker-compose logs -f [service]
echo    🔄 Restart: docker-compose restart [service]
echo    ⏹️ Stop: docker-compose down
echo    🧹 Clean up: docker-compose down -v --remove-orphans
echo.

if "%1"=="nopause" goto :eof
pause