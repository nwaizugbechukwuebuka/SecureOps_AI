# 🐳 Docker Setup for SecureOps AI

This guide provides complete Docker configuration for running your SecureOps AI full-stack application with **Backend on port 8001** and **Frontend on port 3010**.

## 📋 Prerequisites

- Docker Desktop installed and running
- Docker Compose (included with Docker Desktop)
- At least 4GB RAM available for containers

## 🚀 Quick Start

### Option 1: Using Startup Scripts

**Windows:**
```bash
.\start-docker.bat
```

**Linux/macOS:**
```bash
chmod +x start-docker.sh
./start-docker.sh
```

### Option 2: Using npm scripts

```bash
# Build and start all services
npm run docker:up

# Start with logs visible
npm run docker:up-logs

# View logs after starting
npm run docker:logs
```

### Option 3: Direct Docker Compose

```bash
# Start all services
docker-compose up --build -d

# Start with logs
docker-compose up --build
```

## 🏗️ Architecture

The Docker setup includes:

| Service | Port | Description |
|---------|------|-------------|
| **frontend** | 3010 | React + Vite development server |
| **backend** | 8001 | FastAPI application server |
| **redis** | 6379 | Redis for caching and sessions |
| **postgres-dev** | 5433 | PostgreSQL (optional, for testing) |
| **celery-worker** | - | Background task processor |
| **mailhog** | 8025 | Email testing interface |
| **redis-commander** | 8081 | Redis management UI |
| **adminer** | 8082 | Database management UI |

## 🌐 Access Points

After running `docker-compose up`:

- **Main Application**: http://localhost:3010
- **API Documentation**: http://localhost:8001/api/docs
- **API Health**: http://localhost:8001/health
- **Redis Management**: http://localhost:8081
- **Email Testing**: http://localhost:8025
- **Database Admin**: http://localhost:8082

## 🔧 Configuration Details

### Frontend-Backend Communication

The frontend automatically proxies API requests to the backend:
- Frontend runs on `localhost:3010`
- Backend runs on `localhost:8001`
- All `/api/*` requests are proxied from frontend to backend
- WebSocket connections on `/ws` are also proxied

### Environment Variables

Key environment variables for Docker:

```env
# Frontend
VITE_API_BASE_URL=http://backend:8001
VITE_WS_BASE_URL=ws://backend:8001
VITE_APP_PORT=3010

# Backend  
HOST=0.0.0.0
PORT=8001
CORS_ORIGINS=http://localhost:3010,http://frontend:3010
```

### Network Configuration

- All services run on the `secureops-network` bridge network
- Frontend container can reach backend via `backend:8001`
- Backend can reach frontend via `frontend:3010`
- External access via `localhost:3010` (frontend) and `localhost:8001` (backend)

## 📊 Health Checks

All services include health checks:
- **Backend**: `GET /health` endpoint
- **Frontend**: HTTP check on port 3010
- **Redis**: `redis-cli ping`
- Services wait for dependencies to be healthy before starting

## 🛠️ Development Features

- **Live Reload**: Both frontend and backend auto-reload on file changes
- **Hot Module Replacement**: Frontend updates instantly
- **Debug Logging**: Detailed logs available via `docker-compose logs -f`
- **Volume Mounting**: Source code mounted for real-time development

## 🔄 Common Commands

```bash
# View all service logs
docker-compose logs -f

# View specific service logs  
docker-compose logs -f backend
docker-compose logs -f frontend

# Access container shell
docker-compose exec backend bash
docker-compose exec frontend sh

# Restart specific service
docker-compose restart backend

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Rebuild everything
docker-compose build --no-cache
docker-compose up --build -d
```

## 🐛 Troubleshooting

### Service won't start
```bash
# Check logs
docker-compose logs [service-name]

# Check container status
docker-compose ps

# Restart specific service
docker-compose restart [service-name]
```

### Port conflicts
```bash
# Check what's using the ports
netstat -tulpn | grep :3010
netstat -tulpn | grep :8001

# Stop conflicting services
docker-compose down
```

### Frontend can't reach backend
- Check network connectivity: `docker-compose exec frontend curl http://backend:8001/health`
- Verify environment variables: `docker-compose exec frontend env | grep VITE`
- Check proxy configuration in `vite.config.js`

### Database issues
```bash
# Reset database
docker-compose down -v
docker-compose up --build -d
```

## 📁 File Structure Impact

```
web_app/
├── docker-compose.yml          # Multi-service orchestration
├── Dockerfile                  # Multi-stage build (frontend + backend)
├── start-docker.bat           # Windows startup script
├── start-docker.sh            # Linux/macOS startup script
├── frontend/
│   ├── vite.config.js         # Proxy configuration for backend
│   └── src/...
├── backend/
│   ├── config.py              # Port configuration (8001)
│   ├── main.py                # FastAPI application
│   └── ...
└── .env                       # Environment variables
```

## 🎯 Production Notes

For production deployment:
1. Use `docker-compose.prod.yml` 
2. Set proper environment variables
3. Configure reverse proxy (nginx)
4. Enable SSL/TLS certificates
5. Use external databases instead of SQLite

## ✅ Verification

After starting with `docker-compose up`, verify:

1. **Frontend**: http://localhost:3010 shows the React app
2. **Backend**: http://localhost:8001/health returns `{"status": "healthy"}`
3. **API Docs**: http://localhost:8001/api/docs shows FastAPI documentation
4. **Proxy**: API calls from frontend are successfully reaching backend
5. **Live Reload**: Changes to source files trigger automatic reloads

The application should be fully functional with seamless frontend-backend communication through the Docker network.