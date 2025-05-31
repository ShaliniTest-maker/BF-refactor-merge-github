#!/bin/bash

# ==============================================================================
# Flask Migration Application - Monitoring and Metrics Collection Script
# ==============================================================================
# 
# Comprehensive monitoring and observability infrastructure configuration script
# implementing enterprise-grade monitoring with Prometheus metrics endpoints,
# APM integration, and database operation monitoring for Flask application
# performance tracking and ≤10% variance compliance with Node.js baseline.
#
# Key Features:
# - Prometheus metrics endpoint configuration using prometheus-client 0.17+
# - APM agent integration (Datadog ddtrace 2.1+ / New Relic newrelic 9.2+)
# - Database operation monitoring with PyMongo event listeners
# - Enterprise observability infrastructure with Grafana dashboard integration
# - WSGI server instrumentation for Gunicorn/uWSGI performance monitoring
# - Container-level resource monitoring via cAdvisor integration
# - Health check endpoint validation for Kubernetes deployment
# - Performance variance tracking against Node.js baseline implementation
#
# Architecture Integration:
# - Section 6.5.1.1: Flask request/response hooks for request lifecycle monitoring
# - Section 6.5.4.1: Gunicorn prometheus_multiproc_dir configuration
# - Section 6.5.4.2: Container-level resource monitoring via cAdvisor integration
# - Section 6.5.4.3: Python APM agent initialization in Flask application factory
# - Section 6.5.4.4: Kubernetes health probe endpoints (/health/live, /health/ready)
# - Section 6.5.4.5: Custom migration performance metrics for Node.js baseline comparison
#
# Performance Requirements:
# - Response time variance monitoring: ≤10% from Node.js baseline (critical requirement)
# - CPU utilization monitoring: Warning >70%, Critical >90% with 5-minute response SLA
# - Memory usage tracking: Warning >80%, Critical >95% heap usage
# - GC pause time monitoring: Warning >10ms, Critical >20ms average pause
# - Container resource correlation for comprehensive performance analysis
#
# Usage:
#   ./scripts/monitoring.sh start      # Initialize monitoring infrastructure
#   ./scripts/monitoring.sh stop       # Stop monitoring services
#   ./scripts/monitoring.sh restart    # Restart monitoring components
#   ./scripts/monitoring.sh status     # Check monitoring service status
#   ./scripts/monitoring.sh validate   # Validate monitoring configuration
#   ./scripts/monitoring.sh dashboard  # Deploy Grafana dashboards
#
# Environment Variables:
#   FLASK_ENV                 - Environment (development, staging, production)
#   APM_PROVIDER             - APM provider (datadog, newrelic, disabled)
#   PROMETHEUS_ENABLED       - Enable Prometheus metrics collection
#   MONITORING_CONFIG_PATH   - Path to monitoring configuration files
#   GRAFANA_URL             - Grafana instance URL for dashboard deployment
#   ALERTMANAGER_URL        - Prometheus Alertmanager URL for alert routing
#
# References:
# - Section 0.1.1: Performance optimization to ensure ≤10% variance from Node.js baseline
# - Section 0.2.4: prometheus-client 0.17+ dependency decisions  
# - Section 6.5: Comprehensive monitoring and observability infrastructure
# - Section 3.6: Core monitoring technologies and enterprise integration requirements
# ==============================================================================

set -euo pipefail

# Script Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly MONITORING_CONFIG_DIR="${PROJECT_ROOT}/config/monitoring"
readonly LOG_FILE="${PROJECT_ROOT}/logs/monitoring.log"
readonly PID_FILE="${PROJECT_ROOT}/run/monitoring.pid"

# Environment Configuration
readonly FLASK_ENV="${FLASK_ENV:-development}"
readonly APM_PROVIDER="${APM_PROVIDER:-datadog}"
readonly PROMETHEUS_ENABLED="${PROMETHEUS_ENABLED:-true}"
readonly MONITORING_CONFIG_PATH="${MONITORING_CONFIG_PATH:-${MONITORING_CONFIG_DIR}}"
readonly GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
readonly ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"

# Monitoring Service Configuration
readonly PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
readonly PROMETHEUS_CONFIG_FILE="${MONITORING_CONFIG_PATH}/prometheus.yml"
readonly ALERTMANAGER_CONFIG_FILE="${MONITORING_CONFIG_PATH}/alertmanager.yml"
readonly GRAFANA_DASHBOARD_DIR="${MONITORING_CONFIG_PATH}/grafana/dashboards"
readonly GRAFANA_PROVISIONING_DIR="${MONITORING_CONFIG_PATH}/grafana/provisioning"

# Performance Monitoring Thresholds
readonly CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD:-70.0}"
readonly CPU_CRITICAL_THRESHOLD="${CPU_CRITICAL_THRESHOLD:-90.0}"
readonly MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD:-80.0}"
readonly MEMORY_CRITICAL_THRESHOLD="${MEMORY_CRITICAL_THRESHOLD:-95.0}"
readonly PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD:-10.0}"
readonly GC_PAUSE_WARNING_THRESHOLD="${GC_PAUSE_WARNING_THRESHOLD:-10.0}"
readonly GC_PAUSE_CRITICAL_THRESHOLD="${GC_PAUSE_CRITICAL_THRESHOLD:-20.0}"

# Docker Configuration for Container Monitoring
readonly CADVISOR_PORT="${CADVISOR_PORT:-8080}"
readonly NODE_EXPORTER_PORT="${NODE_EXPORTER_PORT:-9100}"
readonly PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus_multiproc}"

# Logging Configuration
setup_logging() {
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"
    
    # Create logs directory if it doesn't exist
    [[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}"
    
    # Configure structured logging for monitoring operations
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2> >(tee -a "${LOG_FILE}" >&2)
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Monitoring script initialized with environment: ${FLASK_ENV}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] APM Provider: ${APM_PROVIDER}, Prometheus: ${PROMETHEUS_ENABLED}"
}

# Color output for terminal display
log_info() {
    echo -e "\033[32m[INFO]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_warn() {
    echo -e "\033[33m[WARN]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "\033[31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "\033[32m[SUCCESS]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

# Dependency Validation
validate_dependencies() {
    log_info "Validating monitoring dependencies and configuration..."
    
    local dependencies=(
        "python3:Python 3.8+ runtime for Flask application"
        "pip:Python package manager for dependency installation"
        "docker:Container runtime for monitoring services"
        "curl:HTTP client for API validation"
        "jq:JSON processor for configuration parsing"
    )
    
    local missing_deps=()
    
    for dep_info in "${dependencies[@]}"; do
        local dep="${dep_info%%:*}"
        local desc="${dep_info#*:}"
        
        if ! command -v "${dep}" &>/dev/null; then
            log_error "Missing dependency: ${dep} (${desc})"
            missing_deps+=("${dep}")
        else
            log_info "✓ Found dependency: ${dep}"
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies before proceeding"
        return 1
    fi
    
    # Validate Python packages
    log_info "Validating Python monitoring packages..."
    local python_packages=(
        "prometheus_client:prometheus-client 0.17+ for metrics collection"
        "structlog:structlog 23.1+ for structured logging"
        "psutil:psutil 5.9+ for system resource monitoring"
        "flask:Flask 2.3+ web framework"
    )
    
    for pkg_info in "${python_packages[@]}"; do
        local pkg="${pkg_info%%:*}"
        local desc="${pkg_info#*:}"
        
        if python3 -c "import ${pkg}" 2>/dev/null; then
            log_info "✓ Found Python package: ${pkg}"
        else
            log_warn "Missing Python package: ${pkg} (${desc})"
        fi
    done
    
    log_success "Dependency validation completed"
    return 0
}

# Environment-Specific Configuration Setup
setup_environment_config() {
    log_info "Setting up environment-specific monitoring configuration for: ${FLASK_ENV}"
    
    # Create monitoring configuration directories
    local config_dirs=(
        "${MONITORING_CONFIG_PATH}"
        "${GRAFANA_DASHBOARD_DIR}"
        "${GRAFANA_PROVISIONING_DIR}/dashboards"
        "${GRAFANA_PROVISIONING_DIR}/datasources"
        "${PROMETHEUS_MULTIPROC_DIR}"
        "${PROJECT_ROOT}/run"
        "${PROJECT_ROOT}/logs"
    )
    
    for dir in "${config_dirs[@]}"; do
        [[ ! -d "${dir}" ]] && mkdir -p "${dir}"
        log_info "✓ Created directory: ${dir}"
    done
    
    # Set appropriate permissions for multiprocess directory
    chmod 755 "${PROMETHEUS_MULTIPROC_DIR}"
    
    # Environment-specific APM configuration
    configure_apm_integration
    
    # Environment-specific alert thresholds
    configure_alert_thresholds
    
    log_success "Environment configuration setup completed"
}

# APM Integration Configuration
configure_apm_integration() {
    log_info "Configuring APM integration for provider: ${APM_PROVIDER}"
    
    case "${APM_PROVIDER}" in
        "datadog")
            configure_datadog_apm
            ;;
        "newrelic")
            configure_newrelic_apm
            ;;
        "disabled")
            log_info "APM integration disabled by configuration"
            ;;
        *)
            log_warn "Unknown APM provider: ${APM_PROVIDER}, defaulting to disabled"
            ;;
    esac
}

# Datadog APM Configuration
configure_datadog_apm() {
    log_info "Configuring Datadog APM integration with ddtrace 2.1+"
    
    # Environment-specific sampling rates for cost optimization
    local sample_rate
    case "${FLASK_ENV}" in
        "production")
            sample_rate="0.1"  # Cost-optimized production sampling
            ;;
        "staging")
            sample_rate="0.5"  # Moderate staging sampling
            ;;
        "development")
            sample_rate="1.0"  # Full development sampling
            ;;
        *)
            sample_rate="0.1"
            ;;
    esac
    
    # Datadog APM environment variables
    export DD_SERVICE="flask-migration-app"
    export DD_ENV="${FLASK_ENV}"
    export DD_VERSION="${APP_VERSION:-1.0.0}"
    export DD_TRACE_SAMPLE_RATE="${sample_rate}"
    export DD_TRACE_ENABLED="true"
    export DD_RUNTIME_METRICS_ENABLED="true"
    export DD_LOGS_INJECTION="true"
    export DD_PROFILING_ENABLED="true"
    export DD_AGENT_HOST="${DD_AGENT_HOST:-localhost}"
    export DD_TRACE_AGENT_PORT="${DD_TRACE_AGENT_PORT:-8126}"
    
    log_info "✓ Datadog APM configured with sample rate: ${sample_rate}"
    
    # Validate Datadog agent connectivity
    if curl -s --max-time 5 "http://${DD_AGENT_HOST}:${DD_TRACE_AGENT_PORT}/info" >/dev/null 2>&1; then
        log_success "✓ Datadog agent connectivity validated"
    else
        log_warn "⚠ Unable to connect to Datadog agent at ${DD_AGENT_HOST}:${DD_TRACE_AGENT_PORT}"
    fi
}

# New Relic APM Configuration
configure_newrelic_apm() {
    log_info "Configuring New Relic APM integration with newrelic 9.2+"
    
    # Environment-specific sampling rates
    local sample_rate
    case "${FLASK_ENV}" in
        "production")
            sample_rate="0.1"
            ;;
        "staging")
            sample_rate="0.5"
            ;;
        "development")
            sample_rate="1.0"
            ;;
        *)
            sample_rate="0.1"
            ;;
    esac
    
    # New Relic environment variables
    export NEW_RELIC_APP_NAME="flask-migration-app-${FLASK_ENV}"
    export NEW_RELIC_LICENSE_KEY="${NEW_RELIC_LICENSE_KEY:-}"
    export NEW_RELIC_ENVIRONMENT="${FLASK_ENV}"
    export NEW_RELIC_DISTRIBUTED_TRACING_ENABLED="true"
    export NEW_RELIC_APPLICATION_LOGGING_ENABLED="true"
    export NEW_RELIC_APPLICATION_LOGGING_FORWARDING_ENABLED="true"
    
    log_info "✓ New Relic APM configured with sample rate: ${sample_rate}"
    
    if [[ -z "${NEW_RELIC_LICENSE_KEY}" ]]; then
        log_warn "⚠ NEW_RELIC_LICENSE_KEY not configured - APM integration will be limited"
    fi
}

# Alert Threshold Configuration
configure_alert_thresholds() {
    log_info "Configuring performance alert thresholds for ${FLASK_ENV} environment"
    
    # Export thresholds as environment variables for monitoring components
    export MONITORING_CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD}"
    export MONITORING_CPU_CRITICAL_THRESHOLD="${CPU_CRITICAL_THRESHOLD}"
    export MONITORING_MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD}"
    export MONITORING_MEMORY_CRITICAL_THRESHOLD="${MEMORY_CRITICAL_THRESHOLD}"
    export MONITORING_PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD}"
    export MONITORING_GC_PAUSE_WARNING_THRESHOLD="${GC_PAUSE_WARNING_THRESHOLD}"
    export MONITORING_GC_PAUSE_CRITICAL_THRESHOLD="${GC_PAUSE_CRITICAL_THRESHOLD}"
    
    log_info "✓ Alert thresholds configured:"
    log_info "  CPU: Warning >${CPU_WARNING_THRESHOLD}%, Critical >${CPU_CRITICAL_THRESHOLD}%"
    log_info "  Memory: Warning >${MEMORY_WARNING_THRESHOLD}%, Critical >${MEMORY_CRITICAL_THRESHOLD}%"
    log_info "  Performance Variance: ≤${PERFORMANCE_VARIANCE_THRESHOLD}% from Node.js baseline"
    log_info "  GC Pause Time: Warning >${GC_PAUSE_WARNING_THRESHOLD}ms, Critical >${GC_PAUSE_CRITICAL_THRESHOLD}ms"
}

# Prometheus Configuration
setup_prometheus_config() {
    if [[ "${PROMETHEUS_ENABLED}" != "true" ]]; then
        log_info "Prometheus metrics collection disabled"
        return 0
    fi
    
    log_info "Setting up Prometheus metrics collection configuration"
    
    # Create Prometheus configuration file
    cat > "${PROMETHEUS_CONFIG_FILE}" << 'EOF'
# Prometheus Configuration for Flask Migration Application
# Implementing comprehensive metrics collection for Node.js baseline comparison
# and enterprise-grade observability with ≤10% performance variance compliance

global:
  scrape_interval: 15s      # Set the scrape interval to every 15 seconds
  evaluation_interval: 15s  # Evaluate rules every 15 seconds
  external_labels:
    cluster: 'flask-migration'
    environment: '{{ .FLASK_ENV }}'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - "{{ .ALERTMANAGER_URL }}"

# Load rules once and periodically evaluate them according to the global 'evaluation_interval'
rule_files:
  - "alert_rules.yml"

# Scrape configuration
scrape_configs:
  # Flask Application Metrics
  - job_name: 'flask-migration-app'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
    scrape_timeout: 10s
    honor_labels: true

  # WSGI Server Metrics (Gunicorn)
  - job_name: 'gunicorn-wsgi'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'

  # System Resource Metrics
  - job_name: 'node-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:{{ .NODE_EXPORTER_PORT }}']
    
  # Container Metrics (cAdvisor)
  - job_name: 'cadvisor'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:{{ .CADVISOR_PORT }}']

  # Database Metrics (MongoDB Exporter)
  - job_name: 'mongodb-exporter'
    scrape_interval: 30s
    static_configs:
      - targets: ['localhost:9216']

  # Redis Metrics
  - job_name: 'redis-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9121']

  # Custom Migration Performance Metrics
  - job_name: 'migration-performance'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:8001']
    metrics_path: '/migration-metrics'
    honor_labels: true
EOF

    # Replace template variables in Prometheus configuration
    sed -i "s/{{ \.FLASK_ENV }}/${FLASK_ENV}/g" "${PROMETHEUS_CONFIG_FILE}"
    sed -i "s/{{ \.ALERTMANAGER_URL }}/${ALERTMANAGER_URL}/g" "${PROMETHEUS_CONFIG_FILE}"
    sed -i "s/{{ \.NODE_EXPORTER_PORT }}/${NODE_EXPORTER_PORT}/g" "${PROMETHEUS_CONFIG_FILE}"
    sed -i "s/{{ \.CADVISOR_PORT }}/${CADVISOR_PORT}/g" "${PROMETHEUS_CONFIG_FILE}"
    
    log_success "✓ Prometheus configuration created: ${PROMETHEUS_CONFIG_FILE}"
    
    # Create Prometheus alert rules for migration-specific monitoring
    create_prometheus_alert_rules
}

# Prometheus Alert Rules for Migration Performance Monitoring
create_prometheus_alert_rules() {
    log_info "Creating Prometheus alert rules for Flask migration monitoring"
    
    cat > "${MONITORING_CONFIG_PATH}/alert_rules.yml" << EOF
# Flask Migration Application Alert Rules
# Performance monitoring and Node.js baseline comparison alerts
# Ensuring ≤10% variance compliance and enterprise-grade observability

groups:
  - name: flask_migration_performance
    rules:
      # Critical Performance Variance Alert
      - alert: FlaskPerformanceVarianceCritical
        expr: abs(flask_performance_variance_percent) > ${PERFORMANCE_VARIANCE_THRESHOLD}
        for: 2m
        labels:
          severity: critical
          team: performance-engineering
          service: flask-migration-app
        annotations:
          summary: "Flask migration performance variance exceeds critical threshold"
          description: "Performance variance of {{ \$value }}% exceeds the ≤${PERFORMANCE_VARIANCE_THRESHOLD}% threshold for endpoint {{ \$labels.endpoint }}"
          runbook_url: "https://wiki.company.com/runbooks/flask-migration-performance"

      # CPU Utilization Alerts
      - alert: FlaskCPUUtilizationWarning
        expr: flask_cpu_utilization_percent > ${CPU_WARNING_THRESHOLD}
        for: 5m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "Flask application CPU utilization high"
          description: "CPU utilization is {{ \$value }}% which exceeds warning threshold of ${CPU_WARNING_THRESHOLD}%"

      - alert: FlaskCPUUtilizationCritical
        expr: flask_cpu_utilization_percent > ${CPU_CRITICAL_THRESHOLD}
        for: 2m
        labels:
          severity: critical
          team: performance-engineering
        annotations:
          summary: "Flask application CPU utilization critical"
          description: "CPU utilization is {{ \$value }}% which exceeds critical threshold of ${CPU_CRITICAL_THRESHOLD}%"

      # Memory Usage Alerts
      - alert: FlaskMemoryUsageWarning
        expr: (flask_memory_usage_bytes{type="rss"} / (1024*1024*1024)) > (${MEMORY_WARNING_THRESHOLD} / 100) * 4
        for: 5m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "Flask application memory usage high"
          description: "Memory usage exceeds warning threshold"

      # GC Pause Time Alerts
      - alert: FlaskGCPauseTimeWarning
        expr: flask_gc_pause_time_seconds > (${GC_PAUSE_WARNING_THRESHOLD} / 1000)
        for: 1m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "Python garbage collection pause time high"
          description: "GC pause time of {{ \$value }}s exceeds warning threshold"

      # Database Operation Performance
      - alert: FlaskDatabaseOperationSlow
        expr: flask_database_operation_duration_seconds > 0.5
        for: 1m
        labels:
          severity: warning
          team: database-engineering
        annotations:
          summary: "Database operation response time degraded"
          description: "Database {{ \$labels.operation }} on {{ \$labels.collection }} took {{ \$value }}s"

      # External Service Integration Alerts
      - alert: FlaskExternalServiceFailure
        expr: rate(flask_external_service_requests_total{status_code!~"2.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
          team: integration-engineering
        annotations:
          summary: "External service integration failure rate high"
          description: "Service {{ \$labels.service }} failure rate is {{ \$value }} errors/sec"

  - name: flask_migration_business_logic
    rules:
      # Business Logic Throughput Comparison
      - alert: FlaskBusinessLogicThroughputDegraded
        expr: rate(flask_migration_requests_total[5m]) < 0.9 * rate(nodejs_baseline_requests_total[5m])
        for: 3m
        labels:
          severity: warning
          team: business-logic-engineering
        annotations:
          summary: "Flask business logic throughput degraded compared to Node.js baseline"
          description: "Current throughput is {{ \$value }} req/sec vs Node.js baseline"

      # Endpoint Response Time Distribution
      - alert: FlaskEndpointResponseTimeP95High
        expr: histogram_quantile(0.95, rate(flask_http_request_duration_seconds_bucket[5m])) > 1.0
        for: 2m
        labels:
          severity: warning
          team: performance-engineering
        annotations:
          summary: "Flask endpoint 95th percentile response time high"
          description: "P95 response time for {{ \$labels.endpoint }} is {{ \$value }}s"

  - name: flask_migration_infrastructure
    rules:
      # Container Resource Utilization
      - alert: FlaskContainerCPUThrottling
        expr: rate(container_cpu_cfs_throttled_seconds_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
          team: infrastructure-engineering
        annotations:
          summary: "Flask container experiencing CPU throttling"
          description: "Container CPU is being throttled which may impact performance"

      # WSGI Worker Pool Saturation
      - alert: FlaskWSGIWorkersSaturated
        expr: flask_active_requests > 0.8 * flask_wsgi_workers_total
        for: 1m
        labels:
          severity: critical
          team: performance-engineering
        annotations:
          summary: "WSGI worker pool approaching saturation"
          description: "Active requests ({{ \$value }}) approaching worker limit"

      # Health Check Endpoint Failures
      - alert: FlaskHealthCheckFailing
        expr: up{job="flask-migration-app"} == 0
        for: 30s
        labels:
          severity: critical
          team: operations
        annotations:
          summary: "Flask application health check failing"
          description: "Application health check endpoint is not responding"
EOF

    log_success "✓ Prometheus alert rules created: ${MONITORING_CONFIG_PATH}/alert_rules.yml"
}

# Database Operation Monitoring Setup
setup_database_monitoring() {
    log_info "Setting up database operation monitoring with PyMongo event listeners"
    
    # Create PyMongo monitoring configuration
    cat > "${MONITORING_CONFIG_PATH}/database_monitoring.py" << 'EOF'
"""
Database Operation Monitoring Configuration
PyMongo Event Listeners for Performance Tracking and Node.js Baseline Comparison

Implements comprehensive MongoDB operation monitoring with performance metrics collection,
connection pool monitoring, and query performance analysis for ≤10% variance compliance.
"""

import time
import logging
import threading
from collections import defaultdict
from typing import Dict, Any

import pymongo
from pymongo import monitoring
from prometheus_client import Counter, Histogram, Gauge

# Initialize logger for database monitoring
logger = logging.getLogger(__name__)

class DatabasePerformanceMonitor:
    """
    Comprehensive database performance monitoring for Flask migration application.
    
    Implements PyMongo event listeners for operation timing, connection pool monitoring,
    and query performance analysis with Node.js baseline comparison capabilities.
    """
    
    def __init__(self):
        """Initialize database monitoring with performance metrics."""
        self._lock = threading.Lock()
        self._active_operations = {}
        
        # Database Operation Metrics
        self.db_operations_total = Counter(
            'mongodb_operations_total',
            'Total MongoDB operations',
            ['operation', 'collection', 'database']
        )
        
        self.db_operation_duration = Histogram(
            'mongodb_operation_duration_seconds',
            'MongoDB operation duration',
            ['operation', 'collection', 'database'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        self.db_connections_active = Gauge(
            'mongodb_connections_active',
            'Active MongoDB connections'
        )
        
        self.db_connections_pool_size = Gauge(
            'mongodb_connections_pool_size',
            'MongoDB connection pool size'
        )
        
        # Migration Performance Comparison Metrics
        self.nodejs_db_operations_total = Counter(
            'nodejs_mongodb_operations_total',
            'Node.js baseline MongoDB operations',
            ['operation', 'collection']
        )
        
        self.db_performance_variance = Gauge(
            'mongodb_performance_variance_percent',
            'Database performance variance from Node.js baseline',
            ['operation', 'collection']
        )

class CommandMonitor(monitoring.CommandListener):
    """MongoDB command monitoring for performance tracking."""
    
    def __init__(self, performance_monitor: DatabasePerformanceMonitor):
        """Initialize command monitor with performance metrics."""
        self.monitor = performance_monitor
        
    def started(self, event: monitoring.CommandStartedEvent) -> None:
        """Handle command start event."""
        with self.monitor._lock:
            self.monitor._active_operations[event.request_id] = {
                'start_time': time.time(),
                'operation': event.command_name,
                'database': event.database_name,
                'collection': self._extract_collection_name(event.command)
            }
    
    def succeeded(self, event: monitoring.CommandSucceededEvent) -> None:
        """Handle successful command completion."""
        self._complete_operation(event.request_id, 'success')
    
    def failed(self, event: monitoring.CommandFailedEvent) -> None:
        """Handle failed command completion."""
        self._complete_operation(event.request_id, 'failure')
        logger.warning(f"MongoDB operation failed: {event.failure}")
    
    def _complete_operation(self, request_id: int, status: str) -> None:
        """Complete operation tracking and record metrics."""
        with self.monitor._lock:
            operation_info = self.monitor._active_operations.pop(request_id, None)
            
            if operation_info:
                duration = time.time() - operation_info['start_time']
                
                # Record operation metrics
                self.monitor.db_operations_total.labels(
                    operation=operation_info['operation'],
                    collection=operation_info['collection'],
                    database=operation_info['database']
                ).inc()
                
                self.monitor.db_operation_duration.labels(
                    operation=operation_info['operation'],
                    collection=operation_info['collection'],
                    database=operation_info['database']
                ).observe(duration)
                
                # Log slow operations
                if duration > 0.5:  # 500ms threshold
                    logger.warning(
                        f"Slow MongoDB operation: {operation_info['operation']} "
                        f"on {operation_info['collection']} took {duration:.3f}s"
                    )
    
    def _extract_collection_name(self, command: Dict[str, Any]) -> str:
        """Extract collection name from MongoDB command."""
        # Handle different command types
        collection_keys = ['find', 'insert', 'update', 'delete', 'aggregate', 'count']
        
        for key in collection_keys:
            if key in command:
                return command[key]
        
        # Handle index operations
        if 'createIndexes' in command:
            return command['createIndexes']
        
        return 'unknown'

class ConnectionPoolMonitor(monitoring.ConnectionPoolListener):
    """MongoDB connection pool monitoring."""
    
    def __init__(self, performance_monitor: DatabasePerformanceMonitor):
        """Initialize connection pool monitor."""
        self.monitor = performance_monitor
    
    def pool_created(self, event: monitoring.PoolCreatedEvent) -> None:
        """Handle connection pool creation."""
        logger.info(f"MongoDB connection pool created for {event.address}")
    
    def connection_created(self, event: monitoring.ConnectionCreatedEvent) -> None:
        """Handle new connection creation."""
        self.monitor.db_connections_active.inc()
    
    def connection_closed(self, event: monitoring.ConnectionClosedEvent) -> None:
        """Handle connection closure."""
        self.monitor.db_connections_active.dec()

def initialize_database_monitoring() -> DatabasePerformanceMonitor:
    """
    Initialize comprehensive database monitoring with PyMongo event listeners.
    
    Returns:
        DatabasePerformanceMonitor: Configured monitoring instance
    """
    # Create performance monitor
    performance_monitor = DatabasePerformanceMonitor()
    
    # Register PyMongo event listeners
    monitoring.register(CommandMonitor(performance_monitor))
    monitoring.register(ConnectionPoolMonitor(performance_monitor))
    
    logger.info("Database monitoring initialized with PyMongo event listeners")
    return performance_monitor

# Export monitoring initialization function
__all__ = ['initialize_database_monitoring', 'DatabasePerformanceMonitor']
EOF

    log_success "✓ Database monitoring configuration created: ${MONITORING_CONFIG_PATH}/database_monitoring.py"
}

# Grafana Dashboard Configuration
setup_grafana_dashboards() {
    log_info "Setting up Grafana dashboard integration for Flask migration monitoring"
    
    # Create Grafana datasource configuration
    cat > "${GRAFANA_PROVISIONING_DIR}/datasources/prometheus.yml" << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:${PROMETHEUS_PORT}
    isDefault: true
    editable: true
    jsonData:
      httpMethod: POST
      timeInterval: '15s'
EOF

    # Create Flask Migration Performance Dashboard
    cat > "${GRAFANA_DASHBOARD_DIR}/flask_migration_performance.json" << 'EOF'
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "description": "Comprehensive Flask Migration Performance Dashboard - Node.js Baseline Comparison and ≤10% Variance Compliance Monitoring",
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 1,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "percentage": false,
      "pluginVersion": "7.0.0",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "abs(flask_performance_variance_percent)",
          "interval": "",
          "legendFormat": "Performance Variance %",
          "refId": "A"
        },
        {
          "expr": "10",
          "interval": "",
          "legendFormat": "Critical Threshold (10%)",
          "refId": "B"
        }
      ],
      "thresholds": [
        {
          "colorMode": "critical",
          "fill": true,
          "line": true,
          "op": "gt",
          "value": 10,
          "yAxis": "left"
        }
      ],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Performance Variance from Node.js Baseline",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xAxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yAxes": [
        {
          "decimals": 1,
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": 0,
          "show": true
        }
      ],
      "yAxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {
            "align": null
          },
          "mappings": [],
          "thresholds": {
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 10
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "values": false,
          "calcs": [
            "lastNotNull"
          ],
          "fields": ""
        }
      },
      "pluginVersion": "7.0.0",
      "targets": [
        {
          "expr": "flask_cpu_utilization_percent",
          "interval": "",
          "legendFormat": "CPU Utilization %",
          "refId": "A"
        }
      ],
      "title": "CPU Utilization",
      "type": "stat"
    }
  ],
  "refresh": "5s",
  "schemaVersion": 22,
  "style": "dark",
  "tags": [
    "flask",
    "migration",
    "performance",
    "nodejs-comparison"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "Flask Migration Performance Dashboard",
  "uid": "flask_migration_perf",
  "version": 1
}
EOF

    # Create Dashboard Provisioning Configuration
    cat > "${GRAFANA_PROVISIONING_DIR}/dashboards/dashboard.yml" << EOF
apiVersion: 1

providers:
  - name: 'Flask Migration Dashboards'
    orgId: 1
    folder: 'Flask Migration'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: ${GRAFANA_DASHBOARD_DIR}
EOF

    log_success "✓ Grafana dashboard configuration created"
}

# Container Monitoring Setup (cAdvisor and Node Exporter)
setup_container_monitoring() {
    log_info "Setting up container-level resource monitoring with cAdvisor and Node Exporter"
    
    # Create Docker Compose configuration for monitoring services
    cat > "${MONITORING_CONFIG_PATH}/docker-compose.monitoring.yml" << EOF
version: '3.8'

services:
  # Container Metrics Collection via cAdvisor
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.0
    container_name: cadvisor
    ports:
      - "${CADVISOR_PORT}:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    privileged: true
    devices:
      - /dev/kmsg
    restart: unless-stopped
    networks:
      - monitoring

  # System Metrics Collection via Node Exporter
  node-exporter:
    image: prom/node-exporter:v1.6.0
    container_name: node-exporter
    ports:
      - "${NODE_EXPORTER_PORT}:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped
    networks:
      - monitoring

  # Prometheus Server
  prometheus:
    image: prom/prometheus:v2.45.0
    container_name: prometheus
    ports:
      - "${PROMETHEUS_PORT}:9090"
    volumes:
      - ${PROMETHEUS_CONFIG_FILE}:/etc/prometheus/prometheus.yml:ro
      - ${MONITORING_CONFIG_PATH}/alert_rules.yml:/etc/prometheus/alert_rules.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped
    networks:
      - monitoring

  # Prometheus Alertmanager
  alertmanager:
    image: prom/alertmanager:v0.25.0
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ${ALERTMANAGER_CONFIG_FILE}:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://localhost:9093'
    restart: unless-stopped
    networks:
      - monitoring

  # Grafana Dashboard Server
  grafana:
    image: grafana/grafana:10.0.0
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ${GRAFANA_PROVISIONING_DIR}:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    restart: unless-stopped
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge

volumes:
  prometheus_data:
  alertmanager_data:
  grafana_data:
EOF

    log_success "✓ Container monitoring configuration created: docker-compose.monitoring.yml"
}

# Health Check Validation
validate_health_endpoints() {
    log_info "Validating Flask application health check endpoints"
    
    local flask_url="http://localhost:5000"
    local health_endpoints=("/health/live" "/health/ready")
    local validation_passed=true
    
    for endpoint in "${health_endpoints[@]}"; do
        log_info "Testing health endpoint: ${flask_url}${endpoint}"
        
        if curl -s --max-time 10 "${flask_url}${endpoint}" >/dev/null 2>&1; then
            local status_code
            status_code=$(curl -s -o /dev/null -w "%{http_code}" "${flask_url}${endpoint}")
            
            if [[ "${status_code}" == "200" ]]; then
                log_success "✓ Health endpoint ${endpoint} responding correctly (HTTP ${status_code})"
            else
                log_warn "⚠ Health endpoint ${endpoint} returned HTTP ${status_code}"
                validation_passed=false
            fi
        else
            log_error "✗ Health endpoint ${endpoint} not accessible"
            validation_passed=false
        fi
    done
    
    if [[ "${validation_passed}" == "true" ]]; then
        log_success "✓ All health check endpoints validated successfully"
        return 0
    else
        log_error "✗ Health check validation failed"
        return 1
    fi
}

# Monitoring Service Management
start_monitoring_services() {
    log_info "Starting comprehensive monitoring infrastructure..."
    
    # Start container monitoring services
    if [[ -f "${MONITORING_CONFIG_PATH}/docker-compose.monitoring.yml" ]]; then
        log_info "Starting monitoring services with Docker Compose..."
        
        cd "${MONITORING_CONFIG_PATH}"
        docker-compose -f docker-compose.monitoring.yml up -d
        
        # Wait for services to start
        sleep 10
        
        # Validate service health
        local services=("prometheus:${PROMETHEUS_PORT}" "grafana:3000" "cadvisor:${CADVISOR_PORT}" "node-exporter:${NODE_EXPORTER_PORT}")
        
        for service_port in "${services[@]}"; do
            local service="${service_port%%:*}"
            local port="${service_port##*:}"
            
            if curl -s --max-time 5 "http://localhost:${port}" >/dev/null 2>&1; then
                log_success "✓ ${service} service started successfully on port ${port}"
            else
                log_warn "⚠ ${service} service may not be responding on port ${port}"
            fi
        done
    else
        log_warn "Docker Compose configuration not found, skipping container services"
    fi
    
    # Create PID file
    echo $$ > "${PID_FILE}"
    
    log_success "Monitoring infrastructure startup completed"
}

stop_monitoring_services() {
    log_info "Stopping monitoring services..."
    
    if [[ -f "${MONITORING_CONFIG_PATH}/docker-compose.monitoring.yml" ]]; then
        cd "${MONITORING_CONFIG_PATH}"
        docker-compose -f docker-compose.monitoring.yml down
        log_success "✓ Docker Compose monitoring services stopped"
    fi
    
    # Remove PID file
    [[ -f "${PID_FILE}" ]] && rm -f "${PID_FILE}"
    
    log_success "Monitoring services stopped successfully"
}

restart_monitoring_services() {
    log_info "Restarting monitoring services..."
    stop_monitoring_services
    sleep 5
    start_monitoring_services
}

# Monitoring Status Check
check_monitoring_status() {
    log_info "Checking monitoring infrastructure status..."
    
    # Check if monitoring process is running
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid=$(cat "${PID_FILE}")
        
        if ps -p "${pid}" > /dev/null 2>&1; then
            log_success "✓ Monitoring process is running (PID: ${pid})"
        else
            log_warn "⚠ Monitoring PID file exists but process not found"
            rm -f "${PID_FILE}"
        fi
    else
        log_info "Monitoring process not running (no PID file)"
    fi
    
    # Check monitoring services
    local services=(
        "prometheus:${PROMETHEUS_PORT}:Prometheus Metrics Server"
        "grafana:3000:Grafana Dashboard Server"
        "cadvisor:${CADVISOR_PORT}:Container Metrics (cAdvisor)"
        "node-exporter:${NODE_EXPORTER_PORT}:System Metrics (Node Exporter)"
    )
    
    for service_info in "${services[@]}"; do
        local service="${service_info%%:*}"
        local port="${service_info#*:}"
        port="${port%%:*}"
        local description="${service_info##*:}"
        
        if curl -s --max-time 3 "http://localhost:${port}" >/dev/null 2>&1; then
            log_success "✓ ${description} (port ${port})"
        else
            log_warn "⚠ ${description} not responding (port ${port})"
        fi
    done
    
    # Check Flask application metrics endpoint
    if curl -s --max-time 5 "http://localhost:5000/metrics" >/dev/null 2>&1; then
        log_success "✓ Flask application metrics endpoint accessible"
    else
        log_warn "⚠ Flask application metrics endpoint not accessible"
    fi
}

# Configuration Validation
validate_monitoring_config() {
    log_info "Validating monitoring configuration..."
    
    local validation_passed=true
    
    # Validate configuration files
    local required_configs=(
        "${PROMETHEUS_CONFIG_FILE}:Prometheus configuration"
        "${MONITORING_CONFIG_PATH}/alert_rules.yml:Prometheus alert rules"
        "${MONITORING_CONFIG_PATH}/database_monitoring.py:Database monitoring configuration"
    )
    
    for config_info in "${required_configs[@]}"; do
        local config_file="${config_info%%:*}"
        local description="${config_info##*:}"
        
        if [[ -f "${config_file}" ]]; then
            log_success "✓ ${description} exists: ${config_file}"
        else
            log_error "✗ Missing ${description}: ${config_file}"
            validation_passed=false
        fi
    done
    
    # Validate environment variables
    local required_env_vars=(
        "FLASK_ENV:Flask environment"
        "APM_PROVIDER:APM provider configuration"
        "PROMETHEUS_ENABLED:Prometheus metrics enablement"
    )
    
    for env_info in "${required_env_vars[@]}"; do
        local env_var="${env_info%%:*}"
        local description="${env_info##*:}"
        
        if [[ -n "${!env_var:-}" ]]; then
            log_success "✓ ${description}: ${!env_var}"
        else
            log_warn "⚠ Missing ${description} (${env_var})"
        fi
    done
    
    if [[ "${validation_passed}" == "true" ]]; then
        log_success "✓ Monitoring configuration validation passed"
        return 0
    else
        log_error "✗ Monitoring configuration validation failed"
        return 1
    fi
}

# Deploy Grafana Dashboards
deploy_grafana_dashboards() {
    log_info "Deploying Grafana dashboards for Flask migration monitoring..."
    
    # Check if Grafana is accessible
    local grafana_url="${GRAFANA_URL:-http://localhost:3000}"
    
    if ! curl -s --max-time 5 "${grafana_url}/api/health" >/dev/null 2>&1; then
        log_error "Grafana server not accessible at ${grafana_url}"
        return 1
    fi
    
    log_success "✓ Grafana server accessible at ${grafana_url}"
    
    # Dashboard deployment is handled via provisioning
    log_info "Dashboards will be automatically provisioned via Grafana configuration"
    log_info "Access dashboards at: ${grafana_url}/dashboards"
    log_info "Default credentials: admin/admin"
    
    log_success "✓ Grafana dashboard deployment completed"
}

# Main Script Logic
main() {
    local command="${1:-}"
    
    # Setup logging
    setup_logging
    
    case "${command}" in
        "start")
            log_info "Starting Flask migration monitoring infrastructure..."
            validate_dependencies || exit 1
            setup_environment_config
            setup_prometheus_config
            setup_database_monitoring
            setup_grafana_dashboards
            setup_container_monitoring
            start_monitoring_services
            log_success "Monitoring infrastructure started successfully"
            ;;
            
        "stop")
            log_info "Stopping Flask migration monitoring infrastructure..."
            stop_monitoring_services
            log_success "Monitoring infrastructure stopped successfully"
            ;;
            
        "restart")
            log_info "Restarting Flask migration monitoring infrastructure..."
            restart_monitoring_services
            log_success "Monitoring infrastructure restarted successfully"
            ;;
            
        "status")
            log_info "Checking Flask migration monitoring status..."
            check_monitoring_status
            ;;
            
        "validate")
            log_info "Validating Flask migration monitoring configuration..."
            validate_dependencies || exit 1
            validate_monitoring_config || exit 1
            validate_health_endpoints || exit 1
            log_success "Monitoring validation completed successfully"
            ;;
            
        "dashboard")
            log_info "Deploying Grafana dashboards..."
            deploy_grafana_dashboards
            ;;
            
        "help"|"--help"|"-h")
            cat << EOF

Flask Migration Monitoring Script
================================

Comprehensive monitoring and observability infrastructure for Flask migration application
with Node.js baseline comparison and ≤10% performance variance compliance.

Usage:
  ${0} <command>

Commands:
  start      Initialize complete monitoring infrastructure
  stop       Stop all monitoring services
  restart    Restart monitoring components
  status     Check monitoring service status
  validate   Validate monitoring configuration and health
  dashboard  Deploy Grafana dashboards
  help       Show this help message

Environment Variables:
  FLASK_ENV                 Environment (development, staging, production)
  APM_PROVIDER             APM provider (datadog, newrelic, disabled)
  PROMETHEUS_ENABLED       Enable Prometheus metrics collection
  MONITORING_CONFIG_PATH   Path to monitoring configuration files
  GRAFANA_URL             Grafana instance URL for dashboard deployment
  ALERTMANAGER_URL        Prometheus Alertmanager URL for alert routing

Features:
  ✓ Prometheus metrics collection with custom migration metrics
  ✓ APM integration (Datadog ddtrace 2.1+ / New Relic newrelic 9.2+)
  ✓ Database operation monitoring with PyMongo event listeners
  ✓ Container-level resource monitoring via cAdvisor
  ✓ Grafana dashboard integration with performance comparison
  ✓ Health check endpoint validation for Kubernetes deployment
  ✓ Performance variance tracking against Node.js baseline

Monitoring Endpoints:
  http://localhost:5000/metrics      Flask application metrics
  http://localhost:5000/health/live  Kubernetes liveness probe
  http://localhost:5000/health/ready Kubernetes readiness probe
  http://localhost:9090              Prometheus server
  http://localhost:3000              Grafana dashboards
  http://localhost:8080              cAdvisor container metrics
  http://localhost:9100              Node Exporter system metrics

EOF
            ;;
            
        "")
            log_error "No command specified. Use '${0} help' for usage information."
            exit 1
            ;;
            
        *)
            log_error "Unknown command: ${command}. Use '${0} help' for usage information."
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"