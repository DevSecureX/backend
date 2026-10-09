# Grafana Dashboard Troubleshooting Guide

## Problem Diagnosis

The existing Grafana dashboards are showing "No Data" even though:
- ✅ Metrics endpoint is working: `http://localhost:8010/metrics`
- ✅ Prometheus is collecting data successfully
- ✅ Prometheus shows target is "up" with job="devsecurex-backend"

## Root Cause Analysis

The issue is that the existing dashboards are querying for metrics that **don't exist** in the current application. Here's what we found:

### Available Metrics (from /metrics endpoint):
```
- db_active_queries_current
- system_health_score  
- scaling_target_workers
- scaling_decision_time_seconds_*
- repository_size_bytes_*
- devsecurex_app_info_info
```

### Dashboard Queries Looking For (that don't exist):
```
- workers_active_current        ❌ NOT FOUND
- task_queue_size_current       ❌ NOT FOUND  
- active_scans_current          ❌ NOT FOUND
- http_requests_total           ❌ NOT FOUND
- http_request_duration_seconds ❌ NOT FOUND
- sla_compliance_percentage     ❌ NOT FOUND
```

## Solution: Simple Working Dashboard

Created `/monitoring/grafana/dashboards/devsecurex/simple_working_dashboard.json` with:

### Working Panels:
1. **Backend Status**: `up{job="devsecurex-backend"}` - Shows if backend is running
2. **System Health Score**: `system_health_score{job="devsecurex-backend"}` - Current health
3. **Active Database Queries**: `db_active_queries_current{job="devsecurex-backend"}` - DB activity
4. **Scaling Target Workers**: `scaling_target_workers{job="devsecurex-backend"}` - Worker scaling

## Manual Setup Steps

### 1. Access Grafana
```bash
# Open browser to: http://localhost:3000
# Login: admin / admin
```

### 2. Verify Data Source
```
Configuration → Data Sources → Prometheus
- URL should be: http://prometheus:9090
- Test connection should show: "Data source is working"
```

### 3. Test Queries in Explore
```
Go to Explore tab → Select Prometheus
Test these queries:
- up{job="devsecurex-backend"}           # Should show "1"
- system_health_score                    # Should show "0" or health score
- db_active_queries_current              # Should show current DB queries
```

### 4. Import Working Dashboard
```
+ Create → Import
- Copy content from simple_working_dashboard.json
- Or use dashboard provisioning (automatic)
```

## Restart Monitoring Stack

If dashboards still don't work:

```bash
# Stop monitoring stack
cd monitoring/
docker-compose -f docker-compose.monitoring.yml down

# Remove volumes to reset Grafana
docker volume rm monitoring_grafana_data

# Restart
docker-compose -f docker-compose.monitoring.yml up -d
```

## Verification Steps

1. **Backend Status Panel**: Should show "UP" in green
2. **System Health Score**: Should show a number (even if 0)
3. **Database Queries**: Should show 0 or current query count
4. **Time Series**: Should show data points over time

## Next Steps: Add More Metrics

To get the complex dashboards working, the backend application needs to expose more metrics:

```python
# In app/monitoring/metrics.py - add these metrics:
workers_active_current = Gauge('workers_active_current', 'Currently active workers')
task_queue_size_current = Gauge('task_queue_size_current', 'Current task queue size') 
active_scans_current = Gauge('active_scans_current', 'Currently running scans')
http_requests_total = Counter('http_requests_total', 'HTTP requests', ['method', 'endpoint', 'status_code'])
```

## Troubleshooting Commands

```bash
# Check if metrics endpoint works
curl http://localhost:8010/metrics | head -20

# Test Prometheus has data
curl -s "http://localhost:9090/api/v1/query?query=up" | jq '.data.result[] | select(.metric.job == "devsecurex-backend")'

# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job == "devsecurex-backend")'

# Check Grafana logs
docker logs devsecurex-grafana

# Check Prometheus logs  
docker logs devsecurex-prometheus
```

## Expected Working Result

After implementing the simple dashboard:
- ✅ "Backend Status" shows "UP" 
- ✅ "System Health Score" shows a number
- ✅ "Active Database Queries" shows current count
- ✅ Time series graphs display data points
- ✅ No more "No Data" messages