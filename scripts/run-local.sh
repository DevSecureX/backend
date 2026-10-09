#!/bin/bash
# DevSecureX Local Development Environment
# This script runs everything locally with Docker containers

set -e  # Exit on any error

echo "🏠 DevSecureX - Starting LOCAL Development Environment"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

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

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Check if docker-compose exists
if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose is not installed. Please install docker-compose first."
    exit 1
fi

print_status "🧹 Cleaning up any existing containers..."
docker-compose down --remove-orphans > /dev/null 2>&1 || true

print_status "🏗️  Building and starting LOCAL services..."
print_warning "This will use:"
echo "  • Local PostgreSQL database (port 6544)"
echo "  • Local Redis cache (port 6382)"  
echo "  • Backend API (port 8010)"
echo "  • NO production services (no costs)"
echo "  • Background workers: ENABLED (1 worker)"
echo ""

# Start services
docker-compose up --build -d

# Wait for services to be healthy
print_status "⏳ Waiting for services to be healthy..."
sleep 5

# Check health
BACKEND_HEALTH=$(docker-compose ps | grep devsecurex-backend | grep -o "healthy" || echo "unhealthy")
DB_HEALTH=$(docker-compose ps | grep devsecurex-db | grep -o "healthy" || echo "unhealthy")
REDIS_HEALTH=$(docker-compose ps | grep devsecurex-redis | grep -o "healthy" || echo "unhealthy")

echo ""
print_status "🏥 Health Check Results:"
echo "  • Database: $DB_HEALTH"
echo "  • Redis: $REDIS_HEALTH"
echo "  • Backend: $BACKEND_HEALTH"
echo ""

if [[ "$BACKEND_HEALTH" == "healthy" && "$DB_HEALTH" == "healthy" && "$REDIS_HEALTH" == "healthy" ]]; then
    print_success "🎉 LOCAL environment is running successfully!"
    echo ""
    echo "📍 Access Points:"
    echo "  • API Documentation: http://localhost:8010/docs"
    echo "  • API Health Check: http://localhost:8010/health"
    echo "  • Database: postgresql://devsecurex_user:devsecurex_pass@localhost:6544/devsecurex_db"
    echo "  • Redis: redis://localhost:6382"
    echo ""
    echo "🔧 Useful Commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop all: docker-compose down"
    echo "  • Restart: docker-compose restart"
    echo ""
    print_warning "💰 Cost: $0 (everything runs locally)"
    
    # Test the API
    print_status "🧪 Testing API connection..."
    if curl -s http://localhost:8010/health > /dev/null 2>&1; then
        print_success "✅ API is responding correctly"
    else
        print_warning "⚠️  API might still be starting up"
    fi
    
else
    print_error "❌ Some services are not healthy. Check logs with: docker-compose logs"
    echo ""
    print_status "📋 Container Status:"
    docker-compose ps
fi

echo ""
print_status "🛑 To stop the local environment, run: docker-compose down"