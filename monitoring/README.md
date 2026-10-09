# DevSecureX Monitoring Stack

Comprehensive visual monitoring UI with Grafana dashboards for all 5 optimization phases.

## 🎯 Overview

This monitoring stack provides complete observability for DevSecureX, featuring:

- **Real-time Dashboards**: Visual monitoring for all optimization phases
- **Comprehensive Metrics**: Database, cache, API, tasks, and SLA monitoring
- **Smart Alerting**: Phase-specific alert routing and notifications
- **Distributed Tracing**: End-to-end request tracking with Jaeger
- **Centralized Logging**: Structured log analysis with ELK Stack

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- DevSecureX backend running on port 8010
- At least 4GB RAM available for monitoring stack

### 1. Start the Monitoring Stack

```bash
cd monitoring
./start-monitoring.sh
```

### 2. Access the Dashboards

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Jaeger**: http://localhost:16686
- **Kibana**: http://localhost:5601

## 📊 Dashboard Overview

### System Overview Dashboard
**URL**: http://localhost:3000/d/devsecurex-system-overview

- System health score across all phases
- Real-time API performance metrics
- Active workers and queue status
- SLA compliance overview

### Phase-Specific Dashboards

#### 🔹 Database Performance (Phase 1)
**URL**: http://localhost:3000/d/devsecurex-database-performance

- Connection pool utilization and health
- Query performance percentiles
- Transaction monitoring
- Slow query detection

#### 🔹 Redis & Caching (Phase 2)  
**URL**: http://localhost:3000/d/devsecurex-redis-caching

- Cache hit/miss ratios
- L1/L2 cache performance
- Redis connection pool status
- Cache operation latency

#### 🔹 Security Scanning
**URL**: http://localhost:3000/d/devsecurex-security-scanning

- Active security scans
- Vulnerability detection rates
- Scan performance by tool
- Security compliance metrics

#### 🔹 Task System (Phase 4)
**URL**: http://localhost:3000/d/devsecurex-task-system

- Task queue sizes by priority
- Worker utilization and scaling
- Task processing rates
- Wait time analysis

#### 🔹 SLA Compliance (Phase 5)
**URL**: http://localhost:3000/d/devsecurex-sla-compliance

- Overall compliance tracking
- Service availability metrics
- Performance vs SLA targets
- Violation analysis

## 🚨 Alert Configuration

### Alert Levels
- **Critical**: Immediate attention required (1min - 1h repeat)
- **Warning**: Investigation needed (5min - 8h repeat) 
- **Info**: Awareness notifications (10min - 24h repeat)

### Phase-Specific Alert Routing
- **Phase 1**: Database team notifications
- **Phase 2**: Cache optimization alerts
- **Phase 3**: API performance team
- **Phase 4**: Task system monitoring
- **Phase 5**: SLA compliance team

### Alert Channels
- Email notifications (configured in alertmanager.yml)
- Webhook integrations for Slack/Teams
- Custom notification endpoints

## 📈 Key Metrics

### System Health Metrics
```prometheus
# System health score (0-100%)
system_health_score

# Active workers by type
workers_active_current

# Total queue size across all queues
sum(task_queue_size_current)
```

### Database Metrics (Phase 1)
```prometheus
# Connection pool utilization
db_pool_checked_out_connections / db_pool_size_total * 100

# Query performance percentiles
histogram_quantile(0.95, rate(db_query_duration_seconds_bucket[5m]))

# Transaction rates
rate(db_transactions_total[5m])
```

### Cache Metrics (Phase 2)
```prometheus
# Cache hit rate
cache_hit_rate_percentage

# Cache operation latency
histogram_quantile(0.95, rate(cache_operation_duration_seconds_bucket[5m]))

# L1/L2 cache entries
l1_cache_entries_current
l2_cache_entries_current
```

### API Metrics (Phase 3)
```prometheus
# Request rate
rate(http_requests_total[5m])

# Response time percentiles
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Error rate
rate(http_requests_total{status_code=~"4..|5.."}[5m]) / rate(http_requests_total[5m]) * 100
```

### Task System Metrics (Phase 4)
```prometheus
# Queue sizes by priority
task_queue_size_current

# Task processing rates
rate(tasks_processed_total[5m])

# Worker utilization
worker_utilization_percentage
```

### SLA Metrics (Phase 5)
```prometheus
# SLA compliance percentage
sla_compliance_percentage

# SLA violations
increase(sla_violations_total[24h])
```

## 🔧 Configuration

### Prometheus Configuration
- **Scrape Interval**: 15s (adjustable per job)
- **Retention**: 15 days (configurable)
- **Targets**: DevSecureX app, system metrics, containers

### Grafana Configuration
- **Refresh Rate**: 30s (system), 15s (performance)
- **Data Source**: Prometheus + Jaeger
- **Provisioning**: Automated dashboard deployment

### Alertmanager Configuration
- **Grouping**: By alertname, service, phase
- **Inhibition**: Critical alerts suppress warnings
- **Routing**: Phase-specific team notifications

## 🐛 Troubleshooting

### Common Issues

#### Dashboards Not Loading
```bash
# Check Grafana logs
docker-compose logs grafana

# Verify Prometheus connection
curl http://localhost:9090/api/v1/query?query=up
```

#### No Metrics Appearing
```bash
# Check if DevSecureX is exposing metrics
curl http://localhost:8010/monitoring/prometheus/metrics

# Verify Prometheus targets
curl http://localhost:9090/api/v1/targets
```

#### Alerts Not Firing
```bash
# Check Prometheus rules
curl http://localhost:9090/api/v1/rules

# Verify Alertmanager status
curl http://localhost:9093/api/v1/status
```

### Service Health Checks
```bash
# Check all services
docker-compose ps

# View service logs
docker-compose logs -f [service_name]

# Restart specific service
docker-compose restart [service_name]
```

## 📚 Advanced Usage

### Custom Dashboards
1. Access Grafana at http://localhost:3000
2. Create new dashboard or modify existing
3. Export JSON and save to `./grafana/dashboards/devsecurex/`
4. Restart Grafana to reload

### Custom Alerts
1. Edit `./prometheus/rules/devsecurex_alerts.yml`
2. Add new alert rules following existing patterns
3. Restart Prometheus: `docker-compose restart prometheus`

### Log Analysis
1. Access Kibana at http://localhost:5601
2. Create index patterns for `devsecurex-*`
3. Build custom visualizations and dashboards

## 🔒 Security Considerations

- Change default passwords (Grafana: admin/admin)
- Configure HTTPS for production deployments  
- Secure Elasticsearch cluster
- Set up proper authentication for Prometheus
- Configure firewall rules for monitoring ports

## 📊 Performance Tuning

### Resource Requirements
- **Minimum**: 4GB RAM, 2 CPU cores
- **Recommended**: 8GB RAM, 4 CPU cores
- **Storage**: 50GB for 30-day retention

### Optimization Tips
- Adjust scrape intervals based on needs
- Configure metric retention policies
- Use recording rules for expensive queries
- Implement proper cardinality limits

## 🤝 Support

For issues and questions:
1. Check service logs: `docker-compose logs [service]`
2. Review Prometheus targets: http://localhost:9090/targets
3. Validate Grafana data sources: http://localhost:3000/datasources
4. Consult alert rules: http://localhost:9090/rules

---

**🎉 Your DevSecureX monitoring stack is now ready to provide comprehensive visibility into all 5 optimization phases!**