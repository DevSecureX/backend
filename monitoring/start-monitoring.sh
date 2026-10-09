#!/bin/bash

# DevSecureX Monitoring Stack Startup Script
# Comprehensive monitoring setup for all 5 optimization phases

set -e

echo "🚀 Starting DevSecureX Monitoring Stack..."
echo "======================================="

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

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

print_success "Docker is running"

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose."
    exit 1
fi

print_success "Docker Compose is available"

# Create necessary directories
print_status "Creating monitoring directories..."
mkdir -p ./prometheus/data
mkdir -p ./grafana/data
mkdir -p ./elasticsearch/data
mkdir -p ./alertmanager/data
mkdir -p ./jaeger/data

print_success "Monitoring directories created"

# Set proper permissions
print_status "Setting directory permissions..."
chmod 777 ./prometheus/data
chmod 777 ./grafana/data  
chmod 777 ./elasticsearch/data
chmod 777 ./alertmanager/data
chmod 777 ./jaeger/data

print_success "Directory permissions set"

# Stop any existing monitoring stack
print_status "Stopping existing monitoring stack..."
docker-compose -f docker-compose.monitoring.yml down --remove-orphans || true

print_success "Existing stack stopped"

# Start the monitoring stack
print_status "Starting DevSecureX monitoring stack..."
docker-compose -f docker-compose.monitoring.yml up -d

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 30

# Check service health
print_status "Checking service health..."

services=(
    "prometheus:9090"
    "grafana:3000"
    "jaeger:16686"
    "elasticsearch:9200"
    "kibana:5601"
    "alertmanager:9093"
)

for service in "${services[@]}"; do
    name=$(echo $service | cut -d':' -f1)
    port=$(echo $service | cut -d':' -f2)
    
    if curl -s http://localhost:$port > /dev/null; then
        print_success "$name is running on port $port"
    else
        print_warning "$name may still be starting up on port $port"
    fi
done

echo
echo "🎉 DevSecureX Monitoring Stack Started!"
echo "======================================"
echo
echo "Access Points:"
echo "📊 Grafana Dashboard:     http://localhost:3000 (admin/admin)"
echo "📈 Prometheus Metrics:    http://localhost:9090"
echo "🔍 Jaeger Tracing:        http://localhost:16686"
echo "📋 Kibana Logs:           http://localhost:5601"
echo "🚨 Alertmanager:          http://localhost:9093"
echo "📊 cAdvisor:              http://localhost:8080"
echo "🖥️  Node Exporter:        http://localhost:9100"
echo "📤 Push Gateway:          http://localhost:9091"
echo
echo "Phase-Specific Dashboards:"
echo "🔹 System Overview:       http://localhost:3000/d/devsecurex-system-overview"
echo "🔹 Database (Phase 1):    http://localhost:3000/d/devsecurex-database-performance"  
echo "🔹 Redis (Phase 2):       http://localhost:3000/d/devsecurex-redis-caching"
echo "🔹 Security Scanning:     http://localhost:3000/d/devsecurex-security-scanning"
echo "🔹 Task System (Phase 4): http://localhost:3000/d/devsecurex-task-system"
echo "🔹 SLA (Phase 5):         http://localhost:3000/d/devsecurex-sla-compliance"
echo
echo "DevSecureX Metrics Endpoints:"
echo "🔗 Prometheus Metrics:    http://localhost:8010/monitoring/prometheus/metrics"
echo "🔗 Health Check:          http://localhost:8010/monitoring/health/detailed"
echo "🔗 Database Metrics:      http://localhost:8010/monitoring/database/metrics"
echo "🔗 Task Metrics:          http://localhost:8010/monitoring/tasks/metrics"
echo
echo "Useful Commands:"
echo "📜 View logs:             docker-compose -f docker-compose.monitoring.yml logs -f [service_name]"
echo "🔄 Restart stack:         docker-compose -f docker-compose.monitoring.yml restart"
echo "🛑 Stop stack:            docker-compose -f docker-compose.monitoring.yml down"
echo "📊 View status:           docker-compose -f docker-compose.monitoring.yml ps"
echo
print_success "Monitoring stack is ready to monitor all 5 optimization phases!"

# Optional: Check if DevSecureX backend is running
if curl -s http://localhost:8010/health > /dev/null; then
    print_success "DevSecureX backend is running and ready for monitoring"
else
    print_warning "DevSecureX backend is not running. Start it to see metrics in dashboards:"
    echo "  cd .. && python -m uvicorn app.main:app --host 0.0.0.0 --port 8010"
fi