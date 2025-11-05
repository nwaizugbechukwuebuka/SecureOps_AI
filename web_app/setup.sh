#!/bin/bash

# SecureOps AI Setup Script
# Automated setup for Unix systems (Linux/macOS)

echo "🚀 Setting up SecureOps AI..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Setup Frontend
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
if [ $? -ne 0 ]; then
    echo "❌ Frontend dependency installation failed"
    exit 1
fi
echo "✅ Frontend dependencies installed"

# Setup Backend
echo "🐍 Installing backend dependencies..."
cd ../backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Backend dependency installation failed"
    exit 1
fi
echo "✅ Backend dependencies installed"

cd ..

echo "🎉 Setup complete!"
echo ""
echo "To start the development servers:"
echo "  Frontend: cd frontend && npm run dev"
echo "  Backend:  cd backend && source venv/bin/activate && python main.py"
echo ""
echo "Frontend will be available at: http://localhost:3010"
echo "Backend API will be available at: http://localhost:8010"
echo "API Documentation at: http://localhost:8010/docs"