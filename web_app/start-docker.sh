#!/bin/bash

echo "🚀 Starting SecureOps AI Full Stack Application..."

# Stop any running containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Build and start services
echo "🔨 Building and starting services..."
docker-compose up --build -d

# Wait for services to be healthy
echo "⏳ Waiting for services to start..."
sleep 30

# Check service status
echo "📊 Service Status:"
echo "Backend (FastAPI): http://localhost:8001"
echo "Frontend (React): http://localhost:3010" 
echo "Redis: localhost:6379"
echo "API Docs: http://localhost:8001/api/docs"

# Check if services are responding
echo "🔍 Checking service health..."

if curl -f -s http://localhost:8001/health > /dev/null; then
    echo "✅ Backend is healthy"
else
    echo "❌ Backend is not responding"
fi

if curl -f -s http://localhost:3010 > /dev/null; then
    echo "✅ Frontend is healthy"
    echo "🌐 Opening application in browser..."
    # Uncomment the line below for your OS:
    # open http://localhost:3010        # macOS
    # xdg-open http://localhost:3010    # Linux
    # start http://localhost:3010       # Windows (Git Bash)
else
    echo "❌ Frontend is not responding"
fi

echo "📋 Useful commands:"
echo "  docker-compose logs -f        # View logs"
echo "  docker-compose down           # Stop all services"
echo "  docker-compose exec backend bash   # Access backend container"
echo "  docker-compose exec frontend sh    # Access frontend container"

echo "🎉 SecureOps AI is running!"
echo "🌐 Access the application at: http://localhost:3010"