#!/bin/bash

# DevSecureX - Restart Grafana with Working Dashboard
# This script restarts Grafana to apply the new simple working dashboard

echo "=== DevSecureX Grafana Dashboard Fix ==="
echo ""

# Navigate to monitoring directory
cd "$(dirname "$0")"

echo "1. Checking current setup..."
echo "   - DevSecureX Backend: http://localhost:8010/metrics"
echo "   - Prometheus: http://localhost:9090"
echo "   - Grafana: http://localhost:3000"
echo ""

echo "2. Testing metrics endpoint..."
if curl -s http://localhost:8010/metrics > /dev/null; then
    echo "   ✅ DevSecureX metrics endpoint is working"
else
    echo "   ❌ DevSecureX metrics endpoint is not accessible"
    echo "   Please start DevSecureX backend first"
    exit 1
fi

echo ""
echo "3. Testing Prometheus..."
if curl -s http://localhost:9090/-/healthy > /dev/null; then
    echo "   ✅ Prometheus is running"
else
    echo "   ❌ Prometheus is not accessible"
    echo "   Starting monitoring stack..."
fi

echo ""
echo "4. Restarting Grafana with new dashboard..."
echo "   This will apply the simple working dashboard with real data"

# Restart only Grafana to pick up new dashboard
docker-compose -f docker-compose.monitoring.yml restart grafana

echo ""
echo "5. Waiting for Grafana to start..."
sleep 10

echo ""
echo "6. Testing Grafana..."
if curl -s http://localhost:3000/api/health > /dev/null; then
    echo "   ✅ Grafana is running"
else
    echo "   ❌ Grafana startup failed"
    echo "   Check logs with: docker logs devsecurex-grafana"
    exit 1
fi

echo ""
echo "=== SUCCESS! ==="
echo ""
echo "🎉 Grafana has been restarted with the working dashboard!"
echo ""
echo "Next steps:"
echo "1. Open Grafana: http://localhost:3000"
echo "2. Login: admin / admin"
echo "3. Look for 'DevSecureX - Simple Working Dashboard'"
echo "4. You should see:"
echo "   - Backend Status: UP (green)"
echo "   - System Health Score: number value" 
echo "   - Active Database Queries: current count"
echo "   - Time series graphs with data points"
echo ""
echo "If you still see 'No Data':"
echo "1. Go to Explore tab in Grafana"
echo "2. Test query: up{job=\"devsecurex-backend\"}"
echo "3. Should return value of 1"
echo ""
echo "Dashboard file: ./grafana/dashboards/devsecurex/simple_working_dashboard.json"
echo "Troubleshooting guide: ./grafana_dashboard_troubleshooting.md"
echo ""

# Show current metrics for verification
echo "Current available metrics:"
curl -s http://localhost:8010/metrics | grep -E "^[a-zA-Z]" | head -5
echo "..."
echo ""

echo "✨ Your Grafana dashboards should now show REAL DATA! ✨"