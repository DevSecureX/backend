#!/bin/bash

# DevSecureX Monitoring Stack - Simple Startup Script
# This script starts the essential monitoring services

set -e

echo "🚀 Starting DevSecureX Monitoring Stack (Simple Version)..."
echo "=========================================================="

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

print_success "Docker is running"

# Start the monitoring stack
print_status "Starting monitoring services..."
docker-compose -f docker-compose.simple.yml up -d

# Wait for services to be ready
print_status "Waiting for services to start..."
sleep 15

# Check service health
print_status "Checking service status..."
docker-compose -f docker-compose.simple.yml ps

echo
echo "🎉 DevSecureX Monitoring Stack is Ready!"
echo "========================================"
echo
echo "📊 Access Points:"
echo "   • Grafana Dashboard:  http://localhost:3000 (admin/admin)"
echo "   • Prometheus Metrics: http://localhost:9090"
echo "   • Jaeger Tracing:     http://localhost:16686"
echo "   • Node Exporter:      http://localhost:9100"
echo "   • Redis Monitoring:   localhost:6380"
echo
echo "🔧 Management Commands:"
echo "   • View logs:    docker-compose -f docker-compose.simple.yml logs -f [service]"
echo "   • Stop stack:   docker-compose -f docker-compose.simple.yml down"
echo "   • Restart:      docker-compose -f docker-compose.simple.yml restart"
echo "   • Status:       docker-compose -f docker-compose.simple.yml ps"
echo
echo "✅ Ready to monitor DevSecureX optimizations!"