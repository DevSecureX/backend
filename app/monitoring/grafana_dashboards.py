"""
Grafana Dashboards and Alerting Configuration for DevSecureX Backend

Comprehensive Grafana dashboard definitions and alert rules:
- System overview dashboard
- Database performance dashboard  
- Redis & caching dashboard
- Security scanning dashboard
- Task system monitoring dashboard
- SLA compliance dashboard
- Alert rule definitions
- Dashboard provisioning automation
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

from monitoring.structured_logging import get_logger

logger_instance = get_logger()
logger = logger_instance.get_logger()

class GrafanaDashboardGenerator:
    """Generate Grafana dashboards and alert rules for DevSecureX"""
    
    def __init__(self):
        self.datasource_name = "prometheus"
        self.refresh_interval = "30s"
        self.time_range = {"from": "now-1h", "to": "now"}
        
    def create_system_overview_dashboard(self) -> Dict[str, Any]:
        """Create comprehensive system overview dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - System Overview",
            "description": "Comprehensive system health and performance overview",
            "tags": ["devsecurex", "overview", "system"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": self.time_range,
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # Row 1: System Health Summary
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "System Health Score",
                "type": "stat",
                "targets": [{
                    "expr": "system_health_score",
                    "legendFormat": "Health Score"
                }],
                "fieldConfig": {
                    "defaults": {
                        "color": {
                            "mode": "thresholds"
                        },
                        "mappings": [],
                        "thresholds": {
                            "steps": [
                                {"color": "red", "value": 0},
                                {"color": "yellow", "value": 70},
                                {"color": "green", "value": 90}
                            ]
                        },
                        "unit": "percent"
                    }
                },
                "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Active Workers",
                "type": "stat",
                "targets": [{
                    "expr": "workers_active_current",
                    "legendFormat": "Active Workers"
                }],
                "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0}
            },
            {
                "id": 3,
                "title": "Queue Size",
                "type": "stat",
                "targets": [{
                    "expr": "sum(task_queue_size_current)",
                    "legendFormat": "Total Queue Size"
                }],
                "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0}
            },
            {
                "id": 4,
                "title": "Active Scans",
                "type": "stat",
                "targets": [{
                    "expr": "sum(active_scans_current)",
                    "legendFormat": "Active Security Scans"
                }],
                "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0}
            }
        ])
        
        # Row 2: Performance Metrics
        dashboard["panels"].extend([
            {
                "id": 5,
                "title": "HTTP Request Rate",
                "type": "graph",
                "targets": [{
                    "expr": "rate(http_requests_total[5m])",
                    "legendFormat": "{{method}} {{endpoint}}"
                }],
                "yAxes": [
                    {"label": "Requests/sec"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4}
            },
            {
                "id": 6,
                "title": "Response Time Percentiles",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "p50"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "p95"
                    },
                    {
                        "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "p99"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}
            }
        ])
        
        # Row 3: Error Rates and SLA
        dashboard["panels"].extend([
            {
                "id": 7,
                "title": "Error Rate by Service",
                "type": "graph",
                "targets": [{
                    "expr": "rate(http_requests_total{status_code=~\"4..|5..\"}[5m]) / rate(http_requests_total[5m]) * 100",
                    "legendFormat": "{{endpoint}}"
                }],
                "yAxes": [
                    {"label": "Error %", "max": 100},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12}
            },
            {
                "id": 8,
                "title": "SLA Compliance",
                "type": "graph",
                "targets": [
                    {
                        "expr": "sla_compliance_percentage{sla_type=\"availability\"}",
                        "legendFormat": "Availability"
                    },
                    {
                        "expr": "sla_compliance_percentage{sla_type=\"response_time\"}",
                        "legendFormat": "Response Time"
                    },
                    {
                        "expr": "sla_compliance_percentage{sla_type=\"error_rate\"}",
                        "legendFormat": "Error Rate"
                    }
                ],
                "yAxes": [
                    {"label": "Compliance %", "min": 0, "max": 100},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12}
            }
        ])
        
        return dashboard
    
    def create_database_performance_dashboard(self) -> Dict[str, Any]:
        """Create database performance monitoring dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - Database Performance",
            "description": "Database connection pools, query performance, and optimization metrics",
            "tags": ["devsecurex", "database", "performance"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": self.time_range,
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # Connection Pool Metrics
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "Database Connection Pool Status",
                "type": "graph",
                "targets": [
                    {
                        "expr": "db_pool_size_total",
                        "legendFormat": "Pool Size - {{pool_type}}"
                    },
                    {
                        "expr": "db_pool_checked_out_connections",
                        "legendFormat": "Checked Out - {{pool_name}}"
                    },
                    {
                        "expr": "db_pool_overflow_connections",
                        "legendFormat": "Overflow - {{pool_name}}"
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Connection Checkout Rate",
                "type": "graph",
                "targets": [{
                    "expr": "rate(db_pool_checkouts_total[5m])",
                    "legendFormat": "{{pool_name}} - {{status}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
            }
        ])
        
        # Query Performance Metrics
        dashboard["panels"].extend([
            {
                "id": 3,
                "title": "Database Query Duration",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(db_query_duration_seconds_bucket[5m]))",
                        "legendFormat": "p50"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(db_query_duration_seconds_bucket[5m]))",
                        "legendFormat": "p95"
                    },
                    {
                        "expr": "histogram_quantile(0.99, rate(db_query_duration_seconds_bucket[5m]))",
                        "legendFormat": "p99"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 4,
                "title": "Query Rate by Type",
                "type": "graph",
                "targets": [{
                    "expr": "rate(db_queries_total[5m])",
                    "legendFormat": "{{query_type}} - {{table}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
            }
        ])
        
        # Transaction Metrics
        dashboard["panels"].extend([
            {
                "id": 5,
                "title": "Database Transactions",
                "type": "graph",
                "targets": [{
                    "expr": "rate(db_transactions_total[5m])",
                    "legendFormat": "{{status}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
            },
            {
                "id": 6,
                "title": "Active Database Queries",
                "type": "graph",
                "targets": [{
                    "expr": "db_active_queries_current",
                    "legendFormat": "Active Queries"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
            }
        ])
        
        return dashboard
    
    def create_redis_caching_dashboard(self) -> Dict[str, Any]:
        """Create Redis and caching performance dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - Redis & Caching",
            "description": "Redis performance, cache hit rates, and multi-level cache metrics",
            "tags": ["devsecurex", "redis", "caching", "performance"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": self.time_range,
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # Cache Performance
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "Cache Hit Rate",
                "type": "stat",
                "targets": [{
                    "expr": "cache_hit_rate_percentage",
                    "legendFormat": "{{cache_type}}"
                }],
                "fieldConfig": {
                    "defaults": {
                        "color": {
                            "mode": "thresholds"
                        },
                        "thresholds": {
                            "steps": [
                                {"color": "red", "value": 0},
                                {"color": "yellow", "value": 70},
                                {"color": "green", "value": 90}
                            ]
                        },
                        "unit": "percent"
                    }
                },
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Cache Operations Rate",
                "type": "graph",
                "targets": [{
                    "expr": "rate(cache_operations_total[5m])",
                    "legendFormat": "{{cache_type}} - {{operation}} - {{result}}"
                }],
                "gridPos": {"h": 8, "w": 18, "x": 6, "y": 0}
            }
        ])
        
        # Redis Pool Status
        dashboard["panels"].extend([
            {
                "id": 3,
                "title": "Redis Connection Pools",
                "type": "graph",
                "targets": [{
                    "expr": "redis_pool_size_total",
                    "legendFormat": "{{pool_name}} - {{pool_type}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 4,
                "title": "Cache Operation Duration",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(cache_operation_duration_seconds_bucket[5m]))",
                        "legendFormat": "p50"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(cache_operation_duration_seconds_bucket[5m]))",
                        "legendFormat": "p95"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
            }
        ])
        
        # Multi-level Cache
        dashboard["panels"].extend([
            {
                "id": 5,
                "title": "L1 Cache Entries",
                "type": "graph",
                "targets": [{
                    "expr": "l1_cache_entries_current",
                    "legendFormat": "{{cache_name}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
            },
            {
                "id": 6,
                "title": "L2 Cache Entries",
                "type": "graph",
                "targets": [{
                    "expr": "l2_cache_entries_current",
                    "legendFormat": "{{cache_name}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
            }
        ])
        
        return dashboard
    
    def create_security_scanning_dashboard(self) -> Dict[str, Any]:
        """Create security scanning monitoring dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - Security Scanning",
            "description": "Security scan performance, vulnerability detection, and tool metrics",
            "tags": ["devsecurex", "security", "scanning", "vulnerabilities"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": self.time_range,
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # Scan Overview
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "Active Security Scans",
                "type": "stat",
                "targets": [{
                    "expr": "sum(active_scans_current)",
                    "legendFormat": "Active Scans"
                }],
                "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Scans Completed (24h)",
                "type": "stat",
                "targets": [{
                    "expr": "increase(security_scans_total{status=\"success\"}[24h])",
                    "legendFormat": "Completed Scans"
                }],
                "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0}
            },
            {
                "id": 3,
                "title": "Vulnerabilities Found (24h)",
                "type": "stat",
                "targets": [{
                    "expr": "increase(vulnerabilities_found_total[24h])",
                    "legendFormat": "Vulnerabilities"
                }],
                "fieldConfig": {
                    "defaults": {
                        "color": {
                            "mode": "thresholds"
                        },
                        "thresholds": {
                            "steps": [
                                {"color": "green", "value": 0},
                                {"color": "yellow", "value": 10},
                                {"color": "red", "value": 50}
                            ]
                        }
                    }
                },
                "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0}
            },
            {
                "id": 4,
                "title": "Scan Success Rate",
                "type": "stat",
                "targets": [{
                    "expr": "rate(security_scans_total{status=\"success\"}[1h]) / rate(security_scans_total[1h]) * 100",
                    "legendFormat": "Success Rate"
                }],
                "fieldConfig": {
                    "defaults": {
                        "unit": "percent",
                        "thresholds": {
                            "steps": [
                                {"color": "red", "value": 0},
                                {"color": "yellow", "value": 90},
                                {"color": "green", "value": 95}
                            ]
                        }
                    }
                },
                "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0}
            }
        ])
        
        # Scan Performance
        dashboard["panels"].extend([
            {
                "id": 5,
                "title": "Scan Duration by Tool",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(scan_duration_seconds_bucket[5m]))",
                        "legendFormat": "p50 - {{tool}}"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(scan_duration_seconds_bucket[5m]))",
                        "legendFormat": "p95 - {{tool}}"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4}
            },
            {
                "id": 6,
                "title": "Scan Rate by Type",
                "type": "graph",
                "targets": [{
                    "expr": "rate(security_scans_total[5m])",
                    "legendFormat": "{{scan_type}} - {{tool}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}
            }
        ])
        
        # Vulnerability Analysis
        dashboard["panels"].extend([
            {
                "id": 7,
                "title": "Vulnerabilities by Severity",
                "type": "piechart",
                "targets": [{
                    "expr": "sum by (severity) (increase(vulnerabilities_found_total[24h]))",
                    "legendFormat": "{{severity}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12}
            },
            {
                "id": 8,
                "title": "Files Scanned Rate",
                "type": "graph",
                "targets": [{
                    "expr": "rate(files_scanned_total[5m])",
                    "legendFormat": "{{file_type}} - {{tool}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12}
            }
        ])
        
        return dashboard
    
    def create_task_system_dashboard(self) -> Dict[str, Any]:
        """Create task system monitoring dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - Task System",
            "description": "Background task processing, worker scaling, and queue management",
            "tags": ["devsecurex", "tasks", "workers", "scaling"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": self.time_range,
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # Queue Status
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "Task Queue Size by Priority",
                "type": "graph",
                "targets": [{
                    "expr": "task_queue_size_current",
                    "legendFormat": "{{queue_name}} - {{priority}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Task Processing Rate",
                "type": "graph",
                "targets": [{
                    "expr": "rate(tasks_processed_total[5m])",
                    "legendFormat": "{{task_type}} - {{status}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
            }
        ])
        
        # Worker Metrics
        dashboard["panels"].extend([
            {
                "id": 3,
                "title": "Active Workers",
                "type": "graph",
                "targets": [{
                    "expr": "workers_active_current",
                    "legendFormat": "{{worker_type}}"
                }],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 4,
                "title": "Worker Utilization",
                "type": "graph",
                "targets": [{
                    "expr": "worker_utilization_percentage",
                    "legendFormat": "{{worker_id}}"
                }],
                "yAxes": [
                    {"label": "Utilization %", "min": 0, "max": 100},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
            }
        ])
        
        # Task Performance
        dashboard["panels"].extend([
            {
                "id": 5,
                "title": "Task Wait Time",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(task_wait_time_seconds_bucket[5m]))",
                        "legendFormat": "p50"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(task_wait_time_seconds_bucket[5m]))",
                        "legendFormat": "p95"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
            },
            {
                "id": 6,
                "title": "Task Execution Time",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.50, rate(task_execution_time_seconds_bucket[5m]))",
                        "legendFormat": "p50"
                    },
                    {
                        "expr": "histogram_quantile(0.95, rate(task_execution_time_seconds_bucket[5m]))",
                        "legendFormat": "p95"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
            }
        ])
        
        return dashboard
    
    def create_sla_compliance_dashboard(self) -> Dict[str, Any]:
        """Create SLA compliance monitoring dashboard"""
        
        dashboard = {
            "id": None,
            "title": "DevSecureX - SLA Compliance",
            "description": "Service level agreement monitoring and compliance tracking",
            "tags": ["devsecurex", "sla", "compliance", "performance"],
            "timezone": "browser",
            "refresh": self.refresh_interval,
            "time": {"from": "now-24h", "to": "now"},
            "version": 1,
            "editable": True,
            "graphTooltip": 1,
            "panels": []
        }
        
        # SLA Overview
        dashboard["panels"].extend([
            {
                "id": 1,
                "title": "Overall SLA Compliance",
                "type": "stat",
                "targets": [{
                    "expr": "min(sla_compliance_percentage)",
                    "legendFormat": "Overall Compliance"
                }],
                "fieldConfig": {
                    "defaults": {
                        "color": {
                            "mode": "thresholds"
                        },
                        "thresholds": {
                            "steps": [
                                {"color": "red", "value": 0},
                                {"color": "yellow", "value": 95},
                                {"color": "green", "value": 99}
                            ]
                        },
                        "unit": "percent"
                    }
                },
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "SLA Compliance by Service",
                "type": "graph",
                "targets": [{
                    "expr": "sla_compliance_percentage",
                    "legendFormat": "{{service}} - {{sla_type}}"
                }],
                "yAxes": [
                    {"label": "Compliance %", "min": 0, "max": 100},
                    {"show": False}
                ],
                "gridPos": {"h": 8, "w": 18, "x": 6, "y": 0}
            }
        ])
        
        # SLA Violations
        dashboard["panels"].extend([
            {
                "id": 3,
                "title": "SLA Violations (24h)",
                "type": "table",
                "targets": [{
                    "expr": "increase(sla_violations_total[24h])",
                    "legendFormat": "{{service}} - {{sla_type}} - {{severity}}"
                }],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {},
                            "indexByName": {},
                            "renameByName": {}
                        }
                    }
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
            }
        ])
        
        # Performance Trends
        dashboard["panels"].extend([
            {
                "id": 4,
                "title": "Response Time Trends",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "p95 Response Time"
                    }
                ],
                "yAxes": [
                    {"label": "Seconds"},
                    {"show": False}
                ],
                "thresholds": [
                    {
                        "value": 5.0,
                        "colorMode": "critical",
                        "op": "gt"
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
            },
            {
                "id": 5,
                "title": "Error Rate Trends",
                "type": "graph",
                "targets": [{
                    "expr": "rate(http_requests_total{status_code=~\"4..|5..\"}[5m]) / rate(http_requests_total[5m]) * 100",
                    "legendFormat": "Error Rate %"
                }],
                "yAxes": [
                    {"label": "Error %", "min": 0},
                    {"show": False}
                ],
                "thresholds": [
                    {
                        "value": 1.0,
                        "colorMode": "critical",
                        "op": "gt"
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
            }
        ])
        
        return dashboard
    
    def create_alert_rules(self) -> List[Dict[str, Any]]:
        """Create Grafana alert rules for DevSecureX"""
        
        alert_rules = [
            # System Health Alerts
            {
                "alert": {
                    "name": "SystemHealthCritical",
                    "message": "System health score is critically low",
                    "frequency": "30s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "last"
                            },
                            "evaluator": {
                                "params": [50],
                                "type": "lt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "2m"
                },
                "targets": [
                    {
                        "expr": "system_health_score",
                        "refId": "A"
                    }
                ]
            },
            
            # Database Alerts
            {
                "alert": {
                    "name": "DatabaseConnectionPoolHigh",
                    "message": "Database connection pool utilization is high",
                    "frequency": "30s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "last"
                            },
                            "evaluator": {
                                "params": [90],
                                "type": "gt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "1m"
                },
                "targets": [
                    {
                        "expr": "db_pool_checked_out_connections / db_pool_size_total * 100",
                        "refId": "A"
                    }
                ]
            },
            
            # Cache Alerts
            {
                "alert": {
                    "name": "CacheHitRateLow",
                    "message": "Cache hit rate is below acceptable threshold",
                    "frequency": "1m",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "avg"
                            },
                            "evaluator": {
                                "params": [80],
                                "type": "lt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "5m"
                },
                "targets": [
                    {
                        "expr": "cache_hit_rate_percentage",
                        "refId": "A"
                    }
                ]
            },
            
            # Task System Alerts
            {
                "alert": {
                    "name": "TaskQueueSizeHigh",
                    "message": "Task queue size is critically high",
                    "frequency": "30s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "last"
                            },
                            "evaluator": {
                                "params": [100],
                                "type": "gt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "2m"
                },
                "targets": [
                    {
                        "expr": "sum(task_queue_size_current)",
                        "refId": "A"
                    }
                ]
            },
            
            # Performance Alerts
            {
                "alert": {
                    "name": "HighResponseTime",
                    "message": "API response time is above SLA threshold",
                    "frequency": "30s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "avg"
                            },
                            "evaluator": {
                                "params": [5.0],
                                "type": "gt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "1m"
                },
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
                        "refId": "A"
                    }
                ]
            },
            
            # Error Rate Alerts
            {
                "alert": {
                    "name": "HighErrorRate",
                    "message": "HTTP error rate is above acceptable threshold",
                    "frequency": "30s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "params": [],
                                "type": "avg"
                            },
                            "evaluator": {
                                "params": [5.0],
                                "type": "gt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "2m"
                },
                "targets": [
                    {
                        "expr": "rate(http_requests_total{status_code=~\"4..|5..\"}[5m]) / rate(http_requests_total[5m]) * 100",
                        "refId": "A"
                    }
                ]
            }
        ]
        
        return alert_rules
    
    def export_dashboards_config(self, output_dir: str = "./grafana"):
        """Export all dashboards and alerts to JSON files"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Export dashboards
        dashboards = {
            "system_overview": self.create_system_overview_dashboard(),
            "database_performance": self.create_database_performance_dashboard(),
            "redis_caching": self.create_redis_caching_dashboard(),
            "security_scanning": self.create_security_scanning_dashboard(),
            "task_system": self.create_task_system_dashboard(),
            "sla_compliance": self.create_sla_compliance_dashboard()
        }
        
        for name, dashboard in dashboards.items():
            file_path = os.path.join(output_dir, f"{name}_dashboard.json")
            with open(file_path, 'w') as f:
                json.dump(dashboard, f, indent=2)
            logger.info(f"Exported dashboard: {file_path}")
        
        # Export alert rules
        alert_rules = self.create_alert_rules()
        alert_file = os.path.join(output_dir, "alert_rules.json")
        with open(alert_file, 'w') as f:
            json.dump(alert_rules, f, indent=2)
        logger.info(f"Exported alert rules: {alert_file}")
        
        # Create provisioning configuration
        self._create_provisioning_config(output_dir)
        
        logger.info(f"Grafana configuration exported to: {output_dir}")
    
    def _create_provisioning_config(self, output_dir: str):
        """Create Grafana provisioning configuration"""
        
        # Dashboard provisioning
        dashboard_config = {
            "apiVersion": 1,
            "providers": [
                {
                    "name": "devsecurex-dashboards",
                    "orgId": 1,
                    "folder": "DevSecureX",
                    "type": "file",
                    "disableDeletion": False,
                    "updateIntervalSeconds": 10,
                    "allowUiUpdates": True,
                    "options": {
                        "path": "/etc/grafana/provisioning/dashboards/devsecurex"
                    }
                }
            ]
        }
        
        dashboard_config_file = os.path.join(output_dir, "dashboard_provisioning.yaml")
        import yaml
        with open(dashboard_config_file, 'w') as f:
            yaml.dump(dashboard_config, f, default_flow_style=False)
        
        # Datasource provisioning
        datasource_config = {
            "apiVersion": 1,
            "datasources": [
                {
                    "name": "prometheus",
                    "type": "prometheus",
                    "access": "proxy",
                    "url": "http://prometheus:9090",
                    "isDefault": True,
                    "editable": True
                }
            ]
        }
        
        datasource_config_file = os.path.join(output_dir, "datasource_provisioning.yaml")
        with open(datasource_config_file, 'w') as f:
            yaml.dump(datasource_config, f, default_flow_style=False)

# Global dashboard generator instance
_dashboard_generator: Optional[GrafanaDashboardGenerator] = None

def get_dashboard_generator() -> GrafanaDashboardGenerator:
    """Get the global dashboard generator instance"""
    global _dashboard_generator
    
    if _dashboard_generator is None:
        _dashboard_generator = GrafanaDashboardGenerator()
    
    return _dashboard_generator

def generate_all_dashboards(output_dir: str = "./monitoring/grafana"):
    """Generate and export all Grafana dashboards"""
    generator = get_dashboard_generator()
    generator.export_dashboards_config(output_dir)
    logger.info("All Grafana dashboards and alerts generated successfully")

# Export dashboards on module import if requested
if os.getenv('EXPORT_GRAFANA_DASHBOARDS', 'false').lower() == 'true':
    try:
        generate_all_dashboards()
    except Exception as e:
        logger.error(f"Failed to export Grafana dashboards on import: {e}")