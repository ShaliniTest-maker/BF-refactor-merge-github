#!/bin/bash

# Monitoring and Metrics Collection Script
# Flask Application Observability Infrastructure
#
# This script configures and manages comprehensive observability infrastructure
# for the Flask application migration from Node.js, ensuring ≤10% performance 
# variance compliance and enterprise-grade monitoring capabilities.
#
# Components:
# - Prometheus metrics endpoints configuration
# - APM agent integration (Datadog/New Relic)
# - Database operation monitoring with PyMongo event listeners
# - Enterprise observability infrastructure with Grafana integration
# - Health check endpoints for Kubernetes orchestration
# - Structured logging with ELK/Splunk integration
# - Performance variance tracking and alerting

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/logs/monitoring.log"
MONITORING_CONFIG="${PROJECT_ROOT}/src/config/monitoring.py"
PROMETHEUS_PORT=${PROMETHEUS_PORT:-8000}
GRAFANA_URL=${GRAFANA_URL:-"http://localhost:3000"}
APM_ENVIRONMENT=${APM_ENVIRONMENT:-"production"}
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-30}
PERFORMANCE_VARIANCE_THRESHOLD=${PERFORMANCE_VARIANCE_THRESHOLD:-10}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() { log "INFO" "$*"; }
warn() { log "WARN" "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Create necessary directories
create_directories() {
    info "Creating monitoring infrastructure directories..."
    
    mkdir -p "${PROJECT_ROOT}/logs"
    mkdir -p "${PROJECT_ROOT}/metrics"
    mkdir -p "${PROJECT_ROOT}/grafana/dashboards"
    mkdir -p "${PROJECT_ROOT}/prometheus/rules"
    mkdir -p "/tmp/prometheus_multiproc_dir"
    
    # Set permissions for Prometheus multiprocess directory
    chmod 755 "/tmp/prometheus_multiproc_dir"
    
    success "Monitoring directories created successfully"
}

# Validate monitoring dependencies
validate_dependencies() {
    info "Validating monitoring infrastructure dependencies..."
    
    local python_cmd="python3"
    if ! command -v python3 &> /dev/null; then
        python_cmd="python"
    fi
    
    # Check Python version (minimum 3.8)
    local python_version=$($python_cmd -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    if [[ $(echo "$python_version >= 3.8" | bc -l) -eq 0 ]]; then
        error "Python 3.8+ required, found $python_version"
        return 1
    fi
    
    # Validate required Python packages
    local required_packages=(
        "prometheus_client>=0.17.0"
        "structlog>=23.1.0"
        "python-json-logger>=2.0.0"
        "flask>=2.3.0"
        "psutil>=5.9.0"
        "ddtrace>=2.1.0"
        "newrelic>=9.2.0"
        "pymongo>=4.5.0"
        "motor>=3.3.0"
        "redis>=5.0.0"
    )
    
    for package in "${required_packages[@]}"; do
        if ! $python_cmd -c "import pkg_resources; pkg_resources.require('$package')" &> /dev/null; then
            warn "Package $package not found or version mismatch"
        else
            info "✓ $package validated"
        fi
    done
    
    success "Dependency validation completed"
}

# Configure Prometheus metrics endpoint
configure_prometheus_metrics() {
    info "Configuring Prometheus metrics endpoint..."
    
    # Create Prometheus configuration
    cat > "${PROJECT_ROOT}/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'flask-app'
    static_configs:
      - targets: ['localhost:${PROMETHEUS_PORT}']
    scrape_interval: 15s
    metrics_path: '/metrics'
    
  - job_name: 'gunicorn-workers'
    static_configs:
      - targets: ['localhost:${PROMETHEUS_PORT}']
    scrape_interval: 10s
    metrics_path: '/metrics/workers'
    
  - job_name: 'database-metrics'
    static_configs:
      - targets: ['localhost:${PROMETHEUS_PORT}']
    scrape_interval: 30s
    metrics_path: '/metrics/database'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

    # Create alerting rules for performance variance monitoring
    cat > "${PROJECT_ROOT}/prometheus/rules/performance_alerts.yml" << EOF
groups:
  - name: flask_migration_performance
    rules:
      - alert: PerformanceVarianceExceeded
        expr: flask_response_time_variance_percentage > ${PERFORMANCE_VARIANCE_THRESHOLD}
        for: 2m
        labels:
          severity: critical
          team: performance-engineering
        annotations:
          summary: "Flask application performance variance exceeds ${PERFORMANCE_VARIANCE_THRESHOLD}%"
          description: "Response time variance: {{ \$value }}% (threshold: ${PERFORMANCE_VARIANCE_THRESHOLD}%)"
          
      - alert: HighCPUUtilization
        expr: process_cpu_usage_percent > 70
        for: 5m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "High CPU utilization detected"
          description: "CPU usage: {{ \$value }}% (sustained for 5+ minutes)"
          
      - alert: CriticalCPUUtilization
        expr: process_cpu_usage_percent > 90
        for: 2m
        labels:
          severity: critical
          team: performance-engineering
        annotations:
          summary: "Critical CPU utilization detected"
          description: "CPU usage: {{ \$value }}% (requires immediate action)"
          
      - alert: PythonGCPauseTimeHigh
        expr: python_gc_pause_time_milliseconds > 100
        for: 3m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "Python garbage collection pause time elevated"
          description: "GC pause time: {{ \$value }}ms (threshold: 100ms)"
          
      - alert: DatabaseResponseTimeSlow
        expr: mongodb_operation_duration_seconds > 0.5
        for: 2m
        labels:
          severity: warning
          team: database-team
        annotations:
          summary: "Database response time degraded"
          description: "MongoDB operation time: {{ \$value }}s (threshold: 0.5s)"
          
      - alert: CircuitBreakerOpen
        expr: pybreaker_circuit_breaker_state == 2
        for: 1m
        labels:
          severity: critical
          team: platform-engineering
        annotations:
          summary: "Circuit breaker opened for external service"
          description: "Service unavailable, fallback responses active"
EOF

    # Set environment variable for multiprocess metrics
    export prometheus_multiproc_dir="/tmp/prometheus_multiproc_dir"
    
    success "Prometheus metrics endpoint configured"
}

# Initialize APM agents
initialize_apm_agents() {
    info "Initializing APM agent integration..."
    
    # Configure Datadog APM if available
    if [[ -n "${DD_API_KEY:-}" ]]; then
        info "Configuring Datadog APM integration..."
        export DD_SERVICE="flask-migration-app"
        export DD_ENV="${APM_ENVIRONMENT}"
        export DD_VERSION="${APP_VERSION:-1.0.0}"
        export DD_TRACE_SAMPLE_RATE="${DD_SAMPLE_RATE:-0.1}"
        export DD_PROFILING_ENABLED="true"
        export DD_LOGS_INJECTION="true"
        success "Datadog APM configured"
    fi
    
    # Configure New Relic if available
    if [[ -n "${NEW_RELIC_LICENSE_KEY:-}" ]]; then
        info "Configuring New Relic APM integration..."
        export NEW_RELIC_APP_NAME="flask-migration-app"
        export NEW_RELIC_ENVIRONMENT="${APM_ENVIRONMENT}"
        export NEW_RELIC_DISTRIBUTED_TRACING_ENABLED="true"
        export NEW_RELIC_LOG_LEVEL="info"
        success "New Relic APM configured"
    fi
    
    # Validate APM configuration
    python3 -c "
import os
from src.monitoring.apm import configure_apm
try:
    configure_apm()
    print('APM agents initialized successfully')
except Exception as e:
    print(f'APM initialization warning: {e}')
" || warn "APM configuration validation failed"
    
    success "APM agent initialization completed"
}

# Configure database operation monitoring
configure_database_monitoring() {
    info "Configuring database operation monitoring..."
    
    # Create database monitoring configuration
    python3 -c "
import sys
sys.path.append('${PROJECT_ROOT}')

from src.monitoring.metrics import DatabaseMetrics
from src.data.connection import get_mongodb_client, get_redis_client
import pymongo.monitoring

try:
    # Initialize database metrics collector
    db_metrics = DatabaseMetrics()
    
    # Register PyMongo event listeners
    pymongo.monitoring.register(db_metrics.command_listener)
    pymongo.monitoring.register(db_metrics.connection_pool_listener)
    pymongo.monitoring.register(db_metrics.server_listener)
    
    print('Database monitoring configured successfully')
    
    # Test database connections with monitoring
    mongo_client = get_mongodb_client()
    redis_client = get_redis_client()
    
    # Perform health checks
    mongo_client.admin.command('ping')
    redis_client.ping()
    
    print('Database health checks passed')
    
except Exception as e:
    print(f'Database monitoring configuration error: {e}', file=sys.stderr)
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        success "Database operation monitoring configured"
    else
        error "Database monitoring configuration failed"
        return 1
    fi
}

# Setup health check endpoints
setup_health_checks() {
    info "Setting up health check endpoints..."
    
    # Create health check validation script
    cat > "${PROJECT_ROOT}/scripts/validate_health.py" << 'EOF'
#!/usr/bin/env python3
"""
Health check validation script for monitoring infrastructure
"""
import sys
import requests
import json
import time
from urllib.parse import urljoin

def validate_health_endpoint(base_url, endpoint, expected_status=200):
    """Validate a specific health check endpoint"""
    try:
        url = urljoin(base_url, endpoint)
        response = requests.get(url, timeout=10)
        
        if response.status_code == expected_status:
            print(f"✓ {endpoint}: {response.status_code}")
            return True
        else:
            print(f"✗ {endpoint}: {response.status_code} (expected: {expected_status})")
            return False
            
    except requests.RequestException as e:
        print(f"✗ {endpoint}: Connection error - {e}")
        return False

def main():
    """Main health check validation"""
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    endpoints = [
        ("/health", 200),           # Basic health check
        ("/health/live", 200),      # Kubernetes liveness probe
        ("/health/ready", 200),     # Kubernetes readiness probe
        ("/metrics", 200),          # Prometheus metrics endpoint
    ]
    
    print(f"Validating health endpoints for {base_url}...")
    
    all_passed = True
    for endpoint, expected_status in endpoints:
        if not validate_health_endpoint(base_url, endpoint, expected_status):
            all_passed = False
    
    if all_passed:
        print("\n✓ All health checks passed")
        sys.exit(0)
    else:
        print("\n✗ Some health checks failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

    chmod +x "${PROJECT_ROOT}/scripts/validate_health.py"
    
    success "Health check endpoints configured"
}

# Configure Grafana dashboards
configure_grafana_dashboards() {
    info "Configuring Grafana dashboard integration..."
    
    # Create Flask Application Performance Dashboard
    cat > "${PROJECT_ROOT}/grafana/dashboards/flask_performance.json" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Flask Migration Performance Dashboard",
    "tags": ["flask", "migration", "performance"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Response Time Variance from Node.js Baseline",
        "type": "stat",
        "targets": [
          {
            "expr": "flask_response_time_variance_percentage",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 5},
                {"color": "red", "value": 10}
              ]
            },
            "unit": "percent"
          }
        }
      },
      {
        "id": 2,
        "title": "Request Rate Comparison",
        "type": "timeseries",
        "targets": [
          {
            "expr": "rate(flask_migration_requests_total[5m])",
            "legendFormat": "Flask Requests/sec",
            "refId": "A"
          },
          {
            "expr": "rate(nodejs_baseline_requests_total[5m])",
            "legendFormat": "Node.js Baseline/sec",
            "refId": "B"
          }
        ]
      },
      {
        "id": 3,
        "title": "CPU Utilization",
        "type": "timeseries",
        "targets": [
          {
            "expr": "process_cpu_usage_percent",
            "legendFormat": "CPU Usage %",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 70},
                {"color": "red", "value": 90}
              ]
            }
          }
        }
      },
      {
        "id": 4,
        "title": "Database Operation Metrics",
        "type": "timeseries",
        "targets": [
          {
            "expr": "mongodb_operation_duration_seconds",
            "legendFormat": "MongoDB Response Time",
            "refId": "A"
          },
          {
            "expr": "redis_operation_duration_seconds",
            "legendFormat": "Redis Response Time",
            "refId": "B"
          }
        ]
      },
      {
        "id": 5,
        "title": "Python GC Pause Times",
        "type": "timeseries",
        "targets": [
          {
            "expr": "python_gc_pause_time_milliseconds",
            "legendFormat": "GC Pause Time (ms)",
            "refId": "A"
          }
        ]
      },
      {
        "id": 6,
        "title": "Circuit Breaker States",
        "type": "stat",
        "targets": [
          {
            "expr": "pybreaker_circuit_breaker_state",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {"value": 0, "text": "CLOSED"},
              {"value": 1, "text": "HALF_OPEN"},
              {"value": 2, "text": "OPEN"}
            ]
          }
        }
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "10s"
  }
}
EOF

    # Create database performance dashboard
    cat > "${PROJECT_ROOT}/grafana/dashboards/database_performance.json" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Database Performance Monitoring",
    "tags": ["database", "mongodb", "redis", "performance"],
    "panels": [
      {
        "id": 1,
        "title": "MongoDB Operations per Second",
        "type": "timeseries",
        "targets": [
          {
            "expr": "rate(mongodb_operations_total[5m])",
            "legendFormat": "Operations/sec",
            "refId": "A"
          }
        ]
      },
      {
        "id": 2,
        "title": "Connection Pool Utilization",
        "type": "timeseries",
        "targets": [
          {
            "expr": "mongodb_connection_pool_active_connections",
            "legendFormat": "Active Connections",
            "refId": "A"
          },
          {
            "expr": "mongodb_connection_pool_max_connections",
            "legendFormat": "Max Connections",
            "refId": "B"
          }
        ]
      },
      {
        "id": 3,
        "title": "Redis Cache Hit Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "redis_cache_hit_rate_percentage",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "thresholds": {
              "steps": [
                {"color": "red", "value": null},
                {"color": "yellow", "value": 80},
                {"color": "green", "value": 90}
              ]
            }
          }
        }
      }
    ]
  }
}
EOF

    success "Grafana dashboards configured"
}

# Setup structured logging
setup_structured_logging() {
    info "Setting up structured logging infrastructure..."
    
    # Create logging configuration validation
    python3 -c "
import sys
sys.path.append('${PROJECT_ROOT}')

try:
    from src.monitoring.logging import configure_structured_logging
    from src.config.monitoring import get_logging_config
    
    # Initialize structured logging
    configure_structured_logging()
    
    # Test logging functionality
    import structlog
    logger = structlog.get_logger()
    logger.info('Structured logging test', component='monitoring_script', test=True)
    
    print('Structured logging configured successfully')
    
except Exception as e:
    print(f'Structured logging configuration error: {e}', file=sys.stderr)
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        success "Structured logging infrastructure configured"
    else
        error "Structured logging configuration failed"
        return 1
    fi
}

# Validate monitoring infrastructure
validate_monitoring_infrastructure() {
    info "Validating monitoring infrastructure..."
    
    # Test Prometheus metrics endpoint
    if command -v curl &> /dev/null; then
        if curl -s "http://localhost:${PROMETHEUS_PORT}/metrics" &> /dev/null; then
            success "✓ Prometheus metrics endpoint accessible"
        else
            warn "Prometheus metrics endpoint not accessible (may start with Flask app)"
        fi
    fi
    
    # Validate monitoring configuration files
    local config_files=(
        "${PROJECT_ROOT}/src/monitoring/metrics.py"
        "${PROJECT_ROOT}/src/monitoring/apm.py"
        "${PROJECT_ROOT}/src/monitoring/health.py"
        "${PROJECT_ROOT}/src/monitoring/logging.py"
        "${PROJECT_ROOT}/src/config/monitoring.py"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            info "✓ $config_file exists"
        else
            error "✗ $config_file missing"
            return 1
        fi
    done
    
    # Validate directory structure
    local required_dirs=(
        "${PROJECT_ROOT}/logs"
        "${PROJECT_ROOT}/metrics"
        "${PROJECT_ROOT}/grafana/dashboards"
        "${PROJECT_ROOT}/prometheus/rules"
        "/tmp/prometheus_multiproc_dir"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            info "✓ Directory $dir exists"
        else
            warn "Directory $dir missing"
        fi
    done
    
    success "Monitoring infrastructure validation completed"
}

# Generate monitoring status report
generate_status_report() {
    info "Generating monitoring infrastructure status report..."
    
    local report_file="${PROJECT_ROOT}/logs/monitoring_status_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "monitoring_infrastructure": {
    "prometheus": {
      "endpoint": "http://localhost:${PROMETHEUS_PORT}/metrics",
      "multiproc_dir": "/tmp/prometheus_multiproc_dir",
      "alerts_configured": true
    },
    "apm": {
      "datadog_enabled": $([ -n "${DD_API_KEY:-}" ] && echo "true" || echo "false"),
      "newrelic_enabled": $([ -n "${NEW_RELIC_LICENSE_KEY:-}" ] && echo "true" || echo "false"),
      "environment": "${APM_ENVIRONMENT}"
    },
    "health_checks": {
      "endpoints": ["/health", "/health/live", "/health/ready"],
      "interval_seconds": ${HEALTH_CHECK_INTERVAL}
    },
    "database_monitoring": {
      "pymongo_listeners": true,
      "redis_monitoring": true,
      "connection_pool_metrics": true
    },
    "grafana": {
      "dashboards_configured": true,
      "url": "${GRAFANA_URL}"
    },
    "structured_logging": {
      "format": "json",
      "enterprise_integration": true
    },
    "performance_requirements": {
      "variance_threshold_percent": ${PERFORMANCE_VARIANCE_THRESHOLD},
      "baseline_comparison": "nodejs"
    }
  },
  "configuration_status": "$(date +%Y-%m-%d_%H:%M:%S) - Monitoring infrastructure configured successfully"
}
EOF

    info "Status report generated: $report_file"
    
    # Display summary
    echo
    echo "=================== MONITORING INFRASTRUCTURE SUMMARY ==================="
    echo "Configuration completed at: $(date)"
    echo "Prometheus endpoint: http://localhost:${PROMETHEUS_PORT}/metrics"
    echo "Health check endpoints: /health, /health/live, /health/ready"
    echo "Performance variance threshold: ≤${PERFORMANCE_VARIANCE_THRESHOLD}%"
    echo "APM environment: ${APM_ENVIRONMENT}"
    echo "Structured logging: Enabled with JSON format"
    echo "Database monitoring: PyMongo and Redis event listeners active"
    echo "Grafana dashboards: Configured for performance and database metrics"
    echo "=========================================================================="
    echo
}

# Main execution function
main() {
    info "Starting monitoring infrastructure configuration..."
    info "Project root: ${PROJECT_ROOT}"
    
    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    # Execute configuration steps
    create_directories
    validate_dependencies
    configure_prometheus_metrics
    initialize_apm_agents
    configure_database_monitoring
    setup_health_checks
    configure_grafana_dashboards
    setup_structured_logging
    validate_monitoring_infrastructure
    generate_status_report
    
    success "Monitoring infrastructure configuration completed successfully!"
    
    # Provide next steps
    echo
    echo "Next steps:"
    echo "1. Start the Flask application to activate monitoring endpoints"
    echo "2. Configure Prometheus server to scrape metrics"
    echo "3. Import Grafana dashboards for visualization"
    echo "4. Set up Alertmanager for notifications"
    echo "5. Validate health checks with: ./scripts/validate_health.py"
    echo
    echo "For detailed monitoring information, see: $LOG_FILE"
}

# Error handling
trap 'error "Script failed at line $LINENO"' ERR

# Execute main function
main "$@"