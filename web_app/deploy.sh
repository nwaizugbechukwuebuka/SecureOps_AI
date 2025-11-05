#!/bin/bash
# Deployment script for SecureOps AI Backend

echo "🚀 Deploying SecureOps AI Backend..."

# Check if platform is specified
if [ -z "$1" ]; then
    echo "Usage: $0 [render|vercel|railway]"
    echo "Example: $0 render"
    exit 1
fi

PLATFORM=$1

case $PLATFORM in
    "render")
        echo "📦 Deploying to Render..."
        echo "1. Commit your changes to GitHub"
        echo "2. Go to https://dashboard.render.com"
        echo "3. Click 'New +' -> 'Web Service'"
        echo "4. Connect your GitHub repository"
        echo "5. Configure:"
        echo "   - Name: secureops-ai-backend"
        echo "   - Environment: Python"
        echo "   - Build Command: cd backend && pip install -r requirements.txt"
        echo "   - Start Command: cd backend && uvicorn main:app --host 0.0.0.0 --port \$PORT"
        echo "6. Set environment variables:"
        echo "   - SECRET_KEY=<generate-strong-key>"
        echo "   - ENVIRONMENT=production"
        echo "   - CORS_ORIGINS=https://nwaizugbechukwuebuka.github.io"
        ;;
        
    "vercel")
        echo "⚡ Deploying to Vercel..."
        echo "1. Install Vercel CLI: npm i -g vercel"
        echo "2. Run: vercel --prod"
        echo "3. Follow the prompts"
        echo "4. Set environment variables in Vercel dashboard"
        ;;
        
    "railway")
        echo "🚂 Deploying to Railway..."
        echo "1. Install Railway CLI: npm i -g @railway/cli"
        echo "2. Run: railway login"
        echo "3. Run: railway deploy"
        echo "4. Set environment variables in Railway dashboard"
        ;;
        
    *)
        echo "❌ Unsupported platform: $PLATFORM"
        echo "Supported platforms: render, vercel, railway"
        exit 1
        ;;
esac

echo ""
echo "📋 Remember to set these environment variables:"
echo "- SECRET_KEY (generate a strong random key)"
echo "- ENVIRONMENT=production"
echo "- DEBUG=false" 
echo "- CORS_ORIGINS=https://nwaizugbechukwuebuka.github.io"
echo "- DATABASE_URL (if using external database)"
echo ""
echo "✅ Backend deployment configuration ready for $PLATFORM!"