#!/bin/bash

# DevSecureX Monitoring Setup Verification Script
# Validates all monitoring components and configurations

set -e

echo "🔍 DevSecureX Monitoring Setup Verification"
echo "==========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
passed=0
failed=0

# Function to print test results
test_result() {
    if [ $2 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC} - $1"
        ((passed++))
    else
        echo -e "${RED}❌ FAIL${NC} - $1"
        ((failed++))
    fi
}

echo -e "${BLUE}[INFO]${NC} Starting verification tests..."
echo

# Test 1: Check required directories exist
echo "📁 Testing directory structure..."
directories=(
    "./prometheus"
    "./prometheus/rules"
    "./grafana/provisioning/datasources"
    "./grafana/provisioning/dashboards"
    "./grafana/dashboards/devsecurex"
    "./alertmanager"
    "./logstash/config"
    "./logstash/pipeline"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        test_result "Directory exists: $dir" 0
    else
        test_result "Directory missing: $dir" 1
    fi
done

echo

# Test 2: Check configuration files exist
echo "📄 Testing configuration files..."
config_files=(
    "./docker-compose.monitoring.yml"
    "./prometheus/prometheus.yml"
    "./prometheus/rules/devsecurex_alerts.yml"
    "./grafana/provisioning/datasources/prometheus.yml"
    "./grafana/provisioning/dashboards/devsecurex.yml"
    "./alertmanager/alertmanager.yml"
    "./logstash/config/logstash.yml"
    "./logstash/pipeline/devsecurex-logs.conf"
)

for file in "${config_files[@]}"; do
    if [ -f "$file" ]; then
        test_result "Config file exists: $file" 0
    else
        test_result "Config file missing: $file" 1
    fi
done

echo

# Test 3: Check dashboard files exist
echo "📊 Testing Grafana dashboard files..."
dashboard_files=(
    "./grafana/dashboards/devsecurex/system_overview.json"
    "./grafana/dashboards/devsecurex/database_performance.json"
    "./grafana/dashboards/devsecurex/redis_caching.json"
    "./grafana/dashboards/devsecurex/security_scanning.json"
    "./grafana/dashboards/devsecurex/task_system.json"
    "./grafana/dashboards/devsecurex/sla_compliance.json"
)

for file in "${dashboard_files[@]}"; do
    if [ -f "$file" ]; then
        test_result "Dashboard exists: $(basename $file)" 0
    else
        test_result "Dashboard missing: $(basename $file)" 1
    fi
done

echo

# Test 4: Validate JSON dashboard syntax
echo "🔍 Validating dashboard JSON syntax..."
for file in "${dashboard_files[@]}"; do
    if [ -f "$file" ]; then
        if python3 -m json.tool "$file" > /dev/null 2>&1; then
            test_result "Valid JSON: $(basename $file)" 0
        else
            test_result "Invalid JSON: $(basename $file)" 1
        fi
    fi
done

echo

# Test 5: Check YAML configuration syntax
echo "🔍 Validating YAML configuration syntax..."
yaml_files=(
    "./prometheus/prometheus.yml"
    "./prometheus/rules/devsecurex_alerts.yml"
    "./grafana/provisioning/datasources/prometheus.yml"
    "./grafana/provisioning/dashboards/devsecurex.yml"
    "./alertmanager/alertmanager.yml"
    "./logstash/config/logstash.yml"
    "./docker-compose.monitoring.yml"
)

for file in "${yaml_files[@]}"; do
    if [ -f "$file" ]; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            test_result "Valid YAML: $(basename $file)" 0
        else
            test_result "Invalid YAML: $(basename $file)" 1
        fi
    fi
done

echo

# Test 6: Check startup script
echo "🚀 Testing startup script..."
if [ -f "./start-monitoring.sh" ] && [ -x "./start-monitoring.sh" ]; then
    test_result "Startup script exists and is executable" 0
else
    test_result "Startup script missing or not executable" 1
fi

echo

# Test 7: Check if Docker is available
echo "🐳 Testing Docker availability..."
if command -v docker &> /dev/null; then
    if docker info > /dev/null 2>&1; then
        test_result "Docker is running" 0
    else
        test_result "Docker is not running" 1
    fi
else
    test_result "Docker is not installed" 1
fi

# Test 8: Check if Docker Compose is available  
if command -v docker-compose &> /dev/null; then
    test_result "Docker Compose is available" 0
else
    test_result "Docker Compose is not installed" 1
fi

echo

# Test 9: Check dashboard UIDs are unique
echo "🆔 Testing dashboard UID uniqueness..."
uids_file="/tmp/dashboard_uids.txt"
> $uids_file

for file in "${dashboard_files[@]}"; do
    if [ -f "$file" ]; then
        uid=$(python3 -c "import json; print(json.load(open('$file')).get('uid', 'no-uid'))" 2>/dev/null || echo "no-uid")
        echo "$uid" >> $uids_file
    fi
done

unique_uids=$(sort $uids_file | uniq | wc -l)
total_uids=$(wc -l < $uids_file)

if [ "$unique_uids" -eq "$total_uids" ]; then
    test_result "All dashboard UIDs are unique" 0
else
    test_result "Duplicate dashboard UIDs found" 1
fi

rm -f $uids_file

echo

# Test 10: Check if DevSecureX backend is accessible
echo "🔌 Testing DevSecureX backend connectivity..."
if curl -s --connect-timeout 5 http://localhost:8010/health > /dev/null 2>&1; then
    test_result "DevSecureX backend is accessible" 0
    
    # Test monitoring endpoints
    endpoints=(
        "/monitoring/health/detailed"
        "/monitoring/prometheus/metrics"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -s --connect-timeout 5 http://localhost:8010$endpoint > /dev/null 2>&1; then
            test_result "Endpoint accessible: $endpoint" 0
        else
            test_result "Endpoint not accessible: $endpoint" 1
        fi
    done
else
    test_result "DevSecureX backend is not running (optional for setup validation)" 0
fi

echo

# Summary
echo "📋 Verification Summary"
echo "======================"
echo -e "✅ Passed: ${GREEN}$passed${NC}"
echo -e "❌ Failed: ${RED}$failed${NC}"
echo -e "📊 Total:  $(($passed + $failed))"
echo

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! Your monitoring setup is ready.${NC}"
    echo
    echo "Next steps:"
    echo "1. Start the monitoring stack: ./start-monitoring.sh"
    echo "2. Access Grafana: http://localhost:3000 (admin/admin)"
    echo "3. View dashboards and verify metrics collection"
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please fix the issues before proceeding.${NC}"
    exit 1
fi