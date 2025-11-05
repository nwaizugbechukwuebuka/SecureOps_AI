#!/bin/bash

# SecureOps AI - Development Setup Script
# This script sets up the complete development environment

set -e

echo "🚀 Setting up SecureOps AI Development Environment"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed and running
check_docker() {
    print_status "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker and try again."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker and try again."
        exit 1
    fi
    
    print_success "Docker is installed and running"
}

# Check if Docker Compose is installed
check_docker_compose() {
    print_status "Checking Docker Compose installation..."
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
    
    print_success "Docker Compose is available"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p backend/logs
    mkdir -p backend/data
    mkdir -p backend/uploads
    mkdir -p backend/backups
    mkdir -p backend/temp
    mkdir -p ssl
    mkdir -p logs
    
    print_success "Directories created"
}

# Copy environment files
setup_environment() {
    print_status "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            print_success "Environment file created from example"
            print_warning "Please review and update .env file with your specific configuration"
        else
            print_error ".env.example file not found. Creating basic .env file..."
            cat > .env << EOF
# Basic development configuration
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=dev-secret-key-change-in-production
DATABASE_URL=sqlite:///./data/secureops.db
REDIS_URL=redis://localhost:6379/0
FRONTEND_URL=http://localhost:3010
EOF
            print_success "Basic .env file created"
        fi
    else
        print_success "Environment file already exists"
    fi
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    # Create SQLite database directory if it doesn't exist
    mkdir -p backend/data
    
    # If init_data.sql exists, note that it will be loaded
    if [ -f backend/data/init_data.sql ]; then
        print_success "Database initialization script found"
    else
        print_warning "No database initialization script found"
    fi
}

# Build and start development services
start_development() {
    print_status "Building and starting development services..."
    
    # Build images
    docker-compose build
    
    # Start services
    docker-compose up -d
    
    print_success "Development services started"
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for backend
    timeout=60
    counter=0
    while ! curl -f http://localhost:8000/health &> /dev/null; do
        if [ $counter -ge $timeout ]; then
            print_error "Backend service failed to start within $timeout seconds"
            docker-compose logs backend
            exit 1
        fi
        sleep 1
        counter=$((counter + 1))
        if [ $((counter % 10)) -eq 0 ]; then
            print_status "Still waiting for backend... ($counter/$timeout seconds)"
        fi
    done
    
    # Wait for frontend
    counter=0
    while ! curl -f http://localhost:3010 &> /dev/null; do
        if [ $counter -ge $timeout ]; then
            print_error "Frontend service failed to start within $timeout seconds"
            docker-compose logs frontend
            exit 1
        fi
        sleep 1
        counter=$((counter + 1))
        if [ $((counter % 10)) -eq 0 ]; then
            print_status "Still waiting for frontend... ($counter/$timeout seconds)"
        fi
    done
    
    print_success "All services are ready!"
}

# Show service information
show_services() {
    echo ""
    echo "🎉 SecureOps AI Development Environment is Ready!"
    echo "==============================================="
    echo ""
    echo "📊 Web Application: http://localhost:3010"
    echo "🔧 API Backend: http://localhost:8000"
    echo "📚 API Documentation: http://localhost:8000/docs"
    echo "📖 ReDoc: http://localhost:8000/redoc"
    echo ""
    echo "🛠️ Development Tools:"
    echo "   📧 Mailhog (Email testing): http://localhost:8025"
    echo "   🗄️ Redis Commander: http://localhost:8081"
    echo "   🗃️ Adminer (Database): http://localhost:8082"
    echo ""
    echo "📈 Monitoring (if enabled):"
    echo "   📊 Prometheus: http://localhost:9090"
    echo "   📈 Grafana: http://localhost:3000"
    echo ""
    echo "🔑 Default Credentials:"
    echo "   Admin User: admin / admin123"
    echo "   Demo User: demo / demo123"
    echo "   Grafana: admin / admin123"
    echo ""
    echo "📝 Useful Commands:"
    echo "   🔍 View logs: docker-compose logs -f [service]"
    echo "   🔄 Restart: docker-compose restart [service]"
    echo "   ⏹️ Stop: docker-compose down"
    echo "   🧹 Clean up: docker-compose down -v --remove-orphans"
    echo ""
}

# Main execution
main() {
    echo "Starting SecureOps AI setup..."
    
    check_docker
    check_docker_compose
    create_directories
    setup_environment
    init_database
    start_development
    wait_for_services
    show_services
    
    print_success "Setup complete! 🎉"
}

# Handle script arguments
case "${1:-}" in
    "clean")
        print_status "Cleaning up development environment..."
        docker-compose down -v --remove-orphans
        docker system prune -f
        print_success "Environment cleaned up"
        ;;
    "rebuild")
        print_status "Rebuilding development environment..."
        docker-compose down
        docker-compose build --no-cache
        docker-compose up -d
        wait_for_services
        show_services
        ;;
    "logs")
        docker-compose logs -f
        ;;
    "status")
        docker-compose ps
        ;;
    *)
        main
        ;;
esac