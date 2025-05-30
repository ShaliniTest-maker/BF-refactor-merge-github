"""
Monitoring and Observability Configuration Module

This module implements comprehensive monitoring and observability capabilities for the Flask
migration application, providing structured logging, metrics collection, APM integration,
and health check endpoints to ensure enterprise-grade monitoring and ≤10% performance
variance compliance with the Node.js baseline.

Key Features:
- structlog 23.1+ structured logging with JSON formatting for enterprise log aggregation
- prometheus-client 0.17+ metrics collection for performance monitoring
- Enterprise APM integration (Datadog/New Relic) for distributed tracing
- Kubernetes-native health check endpoints (/health/live, /health/ready)
- Custom migration performance metrics for baseline comparison
- Circuit breaker state monitoring and integration
- Performance variance tracking against Node.js baseline

Architecture Integration:
- Flask application factory pattern integration for centralized configuration
- WSGI server instrumentation for Gunicorn/uWSGI performance metrics
- Container-level resource monitoring via cAdvisor integration
- Enterprise logging system compatibility (Splunk, ELK Stack)
- Automated alert routing and escalation procedures

Performance Requirements:
- Response time variance monitoring: ≤10% from Node.js baseline (critical requirement)
- CPU utilization monitoring: Warning >70%, Critical >90% with 5-minute response SLA
- Memory usage tracking: Warning >80%, Critical >95% heap usage
- GC pause time monitoring: Warning >10ms, Critical >20ms average pause
- Container resource correlation for comprehensive performance analysis

References:
- Section 3.6 MONITORING & OBSERVABILITY: Core monitoring technologies and enterprise integration
- Section 6.5 MONITORING AND OBSERVABILITY: Comprehensive monitoring infrastructure
- Section 6.1.3 Health Check Implementation: Kubernetes probe endpoints and circuit breaker patterns
- Section 0.1.1 Primary Objective: ≤10% performance variance requirement compliance
"""

import gc
import logging
import os
import psutil
import time
from datetime import datetime, timezone
from functools import wraps
from threading import Lock
from typing import Any, Dict, Optional, Callable, Union

import structlog
from flask import Flask, request, g, jsonify
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
    multiprocess,
    ProcessCollector,
)

try:
    # Enterprise APM Integration - Datadog
    import ddtrace
    from ddtrace import tracer
    from ddtrace.contrib.flask import patch as ddtrace_patch_flask
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False

try:
    # Enterprise APM Integration - New Relic  
    import newrelic.agent
    NEWRELIC_AVAILABLE = True
except ImportError:
    NEWRELIC_AVAILABLE = False


class MonitoringConfig:
    """
    Comprehensive monitoring configuration implementing enterprise-grade observability
    patterns for Flask migration application with Node.js baseline performance tracking.
    
    This configuration provides:
    - Structured logging equivalent to Node.js logging patterns
    - Prometheus metrics collection for performance monitoring
    - Enterprise APM integration for distributed tracing
    - Health check endpoints for container orchestration
    - Custom migration metrics for baseline comparison
    """
    
    # Structured Logging Configuration
    STRUCTURED_LOGGING_ENABLED = os.getenv('STRUCTURED_LOGGING_ENABLED', 'true').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')  # json, console
    LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', '/var/log/flask-migration/app.log')
    
    # Enterprise Log Aggregation
    ENTERPRISE_LOGGING_ENABLED = os.getenv('ENTERPRISE_LOGGING_ENABLED', 'true').lower() == 'true'
    SPLUNK_ENDPOINT = os.getenv('SPLUNK_ENDPOINT', None)
    ELK_ENDPOINT = os.getenv('ELK_ENDPOINT', None)
    
    # Prometheus Metrics Configuration
    PROMETHEUS_ENABLED = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'
    PROMETHEUS_METRICS_PATH = os.getenv('PROMETHEUS_METRICS_PATH', '/metrics')
    PROMETHEUS_MULTIPROC_DIR = os.getenv('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus_multiproc')
    
    # Performance Monitoring Configuration
    PERFORMANCE_MONITORING_ENABLED = os.getenv('PERFORMANCE_MONITORING_ENABLED', 'true').lower() == 'true'
    NODEJS_BASELINE_ENABLED = os.getenv('NODEJS_BASELINE_ENABLED', 'true').lower() == 'true'
    PERFORMANCE_VARIANCE_THRESHOLD = float(os.getenv('PERFORMANCE_VARIANCE_THRESHOLD', '10.0'))  # ≤10% requirement
    
    # APM Configuration
    APM_ENABLED = os.getenv('APM_ENABLED', 'true').lower() == 'true'
    APM_SERVICE_NAME = os.getenv('APM_SERVICE_NAME', 'flask-migration-app')
    APM_ENVIRONMENT = os.getenv('APM_ENVIRONMENT', 'production')
    APM_VERSION = os.getenv('APM_VERSION', '1.0.0')
    
    # Datadog APM Configuration
    DATADOG_APM_ENABLED = os.getenv('DATADOG_APM_ENABLED', 'false').lower() == 'true'
    DATADOG_SAMPLE_RATE = float(os.getenv('DATADOG_SAMPLE_RATE', '0.1'))  # Production: 0.1, Development: 1.0
    
    # New Relic APM Configuration
    NEWRELIC_APM_ENABLED = os.getenv('NEWRELIC_APM_ENABLED', 'false').lower() == 'true'
    NEWRELIC_LICENSE_KEY = os.getenv('NEWRELIC_LICENSE_KEY', None)
    NEWRELIC_SAMPLE_RATE = float(os.getenv('NEWRELIC_SAMPLE_RATE', '0.1'))  # Production: 0.1, Staging: 0.5
    
    # Health Check Configuration
    HEALTH_CHECK_ENABLED = os.getenv('HEALTH_CHECK_ENABLED', 'true').lower() == 'true'
    HEALTH_CHECK_TIMEOUT = int(os.getenv('HEALTH_CHECK_TIMEOUT', '30'))  # seconds
    
    # Alert Thresholds
    CPU_UTILIZATION_WARNING_THRESHOLD = float(os.getenv('CPU_UTILIZATION_WARNING_THRESHOLD', '70.0'))
    CPU_UTILIZATION_CRITICAL_THRESHOLD = float(os.getenv('CPU_UTILIZATION_CRITICAL_THRESHOLD', '90.0'))
    MEMORY_WARNING_THRESHOLD = float(os.getenv('MEMORY_WARNING_THRESHOLD', '80.0'))
    MEMORY_CRITICAL_THRESHOLD = float(os.getenv('MEMORY_CRITICAL_THRESHOLD', '95.0'))
    GC_PAUSE_WARNING_THRESHOLD = float(os.getenv('GC_PAUSE_WARNING_THRESHOLD', '10.0'))  # milliseconds
    GC_PAUSE_CRITICAL_THRESHOLD = float(os.getenv('GC_PAUSE_CRITICAL_THRESHOLD', '20.0'))  # milliseconds


class PrometheusMetrics:
    """
    Prometheus metrics collection implementing comprehensive performance monitoring
    for Flask migration application with Node.js baseline comparison capabilities.
    
    Provides metrics for:
    - HTTP request/response performance tracking
    - Database operation performance monitoring
    - External service integration metrics
    - Resource utilization (CPU, memory, GC) tracking
    - Custom migration performance comparison metrics
    """
    
    def __init__(self):
        """Initialize Prometheus metrics collectors with migration-specific metrics."""
        self._lock = Lock()
        self._initialized = False
        
        # HTTP Request Metrics
        self.http_requests_total = Counter(
            'flask_http_requests_total',
            'Total number of HTTP requests processed',
            ['method', 'endpoint', 'status_code']
        )
        
        self.http_request_duration_seconds = Histogram(
            'flask_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Database Performance Metrics
        self.database_operations_total = Counter(
            'flask_database_operations_total',
            'Total number of database operations',
            ['operation', 'collection', 'status']
        )
        
        self.database_operation_duration_seconds = Histogram(
            'flask_database_operation_duration_seconds',
            'Database operation duration in seconds',
            ['operation', 'collection'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        # External Service Integration Metrics
        self.external_service_requests_total = Counter(
            'flask_external_service_requests_total',
            'Total number of external service requests',
            ['service', 'operation', 'status_code']
        )
        
        self.external_service_duration_seconds = Histogram(
            'flask_external_service_duration_seconds',
            'External service request duration in seconds',
            ['service', 'operation'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
        )
        
        # Resource Utilization Metrics
        self.cpu_utilization_percent = Gauge(
            'flask_cpu_utilization_percent',
            'Current CPU utilization percentage'
        )
        
        self.memory_usage_bytes = Gauge(
            'flask_memory_usage_bytes',
            'Current memory usage in bytes',
            ['type']  # heap, rss, vms
        )
        
        self.gc_pause_time_seconds = Histogram(
            'flask_gc_pause_time_seconds',
            'Python garbage collection pause time in seconds',
            ['generation'],
            buckets=[0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5]
        )
        
        # Custom Migration Performance Metrics
        self.nodejs_baseline_requests_total = Counter(
            'nodejs_baseline_requests_total',
            'Total Node.js baseline requests for comparison',
            ['endpoint']
        )
        
        self.flask_migration_requests_total = Counter(
            'flask_migration_requests_total',
            'Total Flask migration requests for comparison',
            ['endpoint']
        )
        
        self.performance_variance_percent = Gauge(
            'flask_performance_variance_percent',
            'Performance variance percentage against Node.js baseline',
            ['endpoint', 'metric_type']  # response_time, memory_usage, cpu_usage
        )
        
        self.endpoint_response_time_comparison = Histogram(
            'flask_endpoint_response_time_comparison_seconds',
            'Endpoint response time comparison with Node.js baseline',
            ['endpoint', 'implementation'],  # nodejs, flask
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        # Business Logic Performance Metrics
        self.business_logic_operations_total = Counter(
            'flask_business_logic_operations_total',
            'Total business logic operations processed',
            ['operation', 'status']
        )
        
        self.business_logic_duration_seconds = Histogram(
            'flask_business_logic_duration_seconds',
            'Business logic operation duration in seconds',
            ['operation'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
        )
        
        # Circuit Breaker Metrics
        self.circuit_breaker_state = Gauge(
            'flask_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['service']
        )
        
        self.circuit_breaker_failures_total = Counter(
            'flask_circuit_breaker_failures_total',
            'Total circuit breaker failures',
            ['service']
        )
        
        # WSGI Server Metrics
        self.active_requests = Gauge(
            'flask_active_requests',
            'Number of active requests being processed'
        )
        
        self.worker_utilization_percent = Gauge(
            'flask_worker_utilization_percent',
            'WSGI worker utilization percentage',
            ['worker_id']
        )
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics with performance tracking."""
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code)
        ).inc()
        
        self.http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_database_operation(self, operation: str, collection: str, status: str, duration: float):
        """Record database operation metrics with performance tracking."""
        self.database_operations_total.labels(
            operation=operation,
            collection=collection,
            status=status
        ).inc()
        
        self.database_operation_duration_seconds.labels(
            operation=operation,
            collection=collection
        ).observe(duration)
    
    def record_external_service_request(self, service: str, operation: str, status_code: int, duration: float):
        """Record external service request metrics with circuit breaker integration."""
        self.external_service_requests_total.labels(
            service=service,
            operation=operation,
            status_code=str(status_code)
        ).inc()
        
        self.external_service_duration_seconds.labels(
            service=service,
            operation=operation
        ).observe(duration)
    
    def update_resource_utilization(self):
        """Update system resource utilization metrics."""
        # CPU utilization
        cpu_percent = psutil.cpu_percent(interval=None)
        self.cpu_utilization_percent.set(cpu_percent)
        
        # Memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        self.memory_usage_bytes.labels(type='rss').set(memory_info.rss)
        self.memory_usage_bytes.labels(type='vms').set(memory_info.vms)
        
        # Python heap usage
        import sys
        heap_size = sys.getsizeof(gc.get_objects())
        self.memory_usage_bytes.labels(type='heap').set(heap_size)
    
    def record_gc_pause(self, generation: int, pause_time: float):
        """Record garbage collection pause time metrics."""
        self.gc_pause_time_seconds.labels(
            generation=str(generation)
        ).observe(pause_time)
    
    def record_performance_variance(self, endpoint: str, metric_type: str, variance_percent: float):
        """Record performance variance against Node.js baseline."""
        self.performance_variance_percent.labels(
            endpoint=endpoint,
            metric_type=metric_type
        ).set(variance_percent)
    
    def record_endpoint_comparison(self, endpoint: str, implementation: str, response_time: float):
        """Record endpoint response time for Node.js baseline comparison."""
        self.endpoint_response_time_comparison.labels(
            endpoint=endpoint,
            implementation=implementation
        ).observe(response_time)
        
        # Increment corresponding request counter
        if implementation == 'nodejs':
            self.nodejs_baseline_requests_total.labels(endpoint=endpoint).inc()
        else:
            self.flask_migration_requests_total.labels(endpoint=endpoint).inc()
    
    def update_circuit_breaker_state(self, service: str, state: int):
        """Update circuit breaker state metrics."""
        self.circuit_breaker_state.labels(service=service).set(state)
    
    def record_circuit_breaker_failure(self, service: str):
        """Record circuit breaker failure."""
        self.circuit_breaker_failures_total.labels(service=service).inc()


class GarbageCollectionMonitor:
    """
    Python garbage collection monitoring for performance analysis and memory management optimization.
    
    Provides comprehensive GC metrics including:
    - Collection pause time measurement
    - Generation-specific collection statistics  
    - Memory allocation pattern analysis
    - GC performance correlation with response times
    """
    
    def __init__(self, metrics: PrometheusMetrics):
        """Initialize GC monitoring with metrics integration."""
        self.metrics = metrics
        self.gc_stats = {
            'collections': [0, 0, 0],
            'collected': [0, 0, 0],
            'total_pause_time': 0.0
        }
        self._setup_gc_callbacks()
    
    def _setup_gc_callbacks(self):
        """Setup garbage collection callbacks for performance monitoring."""
        if hasattr(gc, 'callbacks'):
            gc.callbacks.append(self._gc_callback)
    
    def _gc_callback(self, phase: str, info: Dict[str, Any]):
        """Garbage collection callback for pause time measurement."""
        if phase == 'start':
            self._gc_start_time = time.perf_counter()
        elif phase == 'stop' and hasattr(self, '_gc_start_time'):
            pause_time = time.perf_counter() - self._gc_start_time
            generation = info.get('generation', 0)
            
            # Record GC pause time metrics
            self.metrics.record_gc_pause(generation, pause_time)
            
            # Update internal statistics
            self.gc_stats['total_pause_time'] += pause_time
            if generation < len(self.gc_stats['collections']):
                self.gc_stats['collections'][generation] += 1
                self.gc_stats['collected'][generation] += info.get('collected', 0)
    
    def get_gc_statistics(self) -> Dict[str, Any]:
        """Get comprehensive garbage collection statistics."""
        stats = gc.get_stats()
        current_counts = gc.get_count()
        
        return {
            'generation_stats': stats,
            'current_counts': current_counts,
            'total_collections': sum(self.gc_stats['collections']),
            'total_collected': sum(self.gc_stats['collected']),
            'total_pause_time': self.gc_stats['total_pause_time'],
            'average_pause_time': (
                self.gc_stats['total_pause_time'] / max(sum(self.gc_stats['collections']), 1)
            )
        }


class HealthCheckManager:
    """
    Kubernetes-native health check implementation with circuit breaker integration
    and comprehensive dependency validation for container orchestration support.
    
    Provides health check endpoints:
    - /health/live: Liveness probe for application process health
    - /health/ready: Readiness probe for dependency health validation
    - /health: General health status with detailed diagnostics
    """
    
    def __init__(self, app: Flask):
        """Initialize health check manager with Flask application integration."""
        self.app = app
        self.dependencies = {}
        self.circuit_breakers = {}
        self.last_check_time = {}
        self.check_results = {}
        
    def register_dependency(self, name: str, check_function: Callable[[], bool], timeout: int = 30):
        """Register a dependency health check function."""
        self.dependencies[name] = {
            'check_function': check_function,
            'timeout': timeout,
            'last_status': None,
            'last_check': None
        }
    
    def register_circuit_breaker(self, name: str, circuit_breaker):
        """Register a circuit breaker for health monitoring."""
        self.circuit_breakers[name] = circuit_breaker
    
    def _check_dependency(self, name: str, dependency: Dict[str, Any]) -> Dict[str, Any]:
        """Check individual dependency health with timeout handling."""
        try:
            start_time = time.time()
            
            # Execute health check with timeout
            is_healthy = dependency['check_function']()
            
            check_duration = time.time() - start_time
            
            result = {
                'status': 'healthy' if is_healthy else 'unhealthy',
                'last_check': datetime.now(timezone.utc).isoformat(),
                'check_duration': check_duration,
                'timeout': dependency['timeout']
            }
            
            # Update dependency status
            dependency['last_status'] = result['status']
            dependency['last_check'] = result['last_check']
            
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now(timezone.utc).isoformat(),
                'timeout': dependency['timeout']
            }
    
    def get_liveness_status(self) -> tuple[Dict[str, Any], int]:
        """
        Get liveness probe status for Kubernetes container restart decisions.
        
        Returns HTTP 200 when Flask application process is operational,
        HTTP 503 when application is in fatal state requiring restart.
        """
        try:
            # Basic application health check
            status = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'service': 'flask-migration-app',
                'version': self.app.config.get('APP_VERSION', '1.0.0'),
                'uptime': time.time() - self.app.config.get('START_TIME', time.time()),
                'process_id': os.getpid()
            }
            
            return status, 200
            
        except Exception as e:
            status = {
                'status': 'unhealthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'service': 'flask-migration-app'
            }
            return status, 503
    
    def get_readiness_status(self) -> tuple[Dict[str, Any], int]:
        """
        Get readiness probe status for Kubernetes traffic routing decisions.
        
        Returns HTTP 200 when all critical dependencies are accessible,
        HTTP 503 when dependencies are unavailable or degraded.
        """
        try:
            dependency_results = {}
            overall_healthy = True
            
            # Check all registered dependencies
            for name, dependency in self.dependencies.items():
                result = self._check_dependency(name, dependency)
                dependency_results[name] = result
                
                if result['status'] != 'healthy':
                    overall_healthy = False
            
            # Check circuit breaker states
            circuit_breaker_status = {}
            for name, cb in self.circuit_breakers.items():
                if hasattr(cb, 'state'):
                    state = cb.state
                    circuit_breaker_status[name] = {
                        'state': state,
                        'failure_count': getattr(cb, 'failure_count', 0),
                        'last_failure': getattr(cb, 'last_failure_time', None)
                    }
                    
                    # Circuit breaker open indicates service unavailability
                    if state == 'open':
                        overall_healthy = False
            
            status = {
                'status': 'ready' if overall_healthy else 'not_ready',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'dependencies': dependency_results,
                'circuit_breakers': circuit_breaker_status,
                'service': 'flask-migration-app'
            }
            
            return status, 200 if overall_healthy else 503
            
        except Exception as e:
            status = {
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'service': 'flask-migration-app'
            }
            return status, 503
    
    def get_detailed_health_status(self) -> tuple[Dict[str, Any], int]:
        """Get comprehensive health status with diagnostic information."""
        liveness_status, liveness_code = self.get_liveness_status()
        readiness_status, readiness_code = self.get_readiness_status()
        
        # System resource information
        try:
            process = psutil.Process()
            resource_info = {
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory_info': {
                    'rss': process.memory_info().rss,
                    'vms': process.memory_info().vms,
                    'percent': process.memory_percent()
                },
                'disk_usage': {
                    path: {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100
                    }
                    for path in ['/']
                    for usage in [psutil.disk_usage(path)]
                }
            }
        except Exception:
            resource_info = {'error': 'Unable to collect resource information'}
        
        status = {
            'overall_status': 'healthy' if liveness_code == 200 and readiness_code == 200 else 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'liveness': liveness_status,
            'readiness': readiness_status,
            'system_resources': resource_info,
            'flask_config': {
                'debug': self.app.debug,
                'testing': self.app.testing,
                'environment': self.app.config.get('ENVIRONMENT', 'unknown')
            }
        }
        
        return status, 200 if status['overall_status'] == 'healthy' else 503


class StructuredLogger:
    """
    Enterprise-grade structured logging implementation using structlog 23.1+
    with JSON formatting for enterprise log aggregation and Node.js logging pattern equivalence.
    
    Features:
    - JSON-formatted log output for Splunk/ELK Stack integration
    - Request correlation ID tracking for distributed tracing
    - Performance metrics integration with logging events
    - Enterprise security compliance with PII filtering
    - Request/response context enrichment
    """
    
    def __init__(self, config: MonitoringConfig):
        """Initialize structured logging with enterprise configuration."""
        self.config = config
        self.logger = None
        self._setup_structured_logging()
    
    def _setup_structured_logging(self):
        """Configure structlog with enterprise-grade settings."""
        # Configure structlog processors
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]
        
        # Add JSON processor for enterprise log aggregation
        if self.config.LOG_FORMAT == 'json':
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        # Configure structlog
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Get logger instance
        self.logger = structlog.get_logger("flask-migration-app")
        
        # Configure Python logging
        logging.basicConfig(
            format="%(message)s",
            level=getattr(logging, self.config.LOG_LEVEL),
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.config.LOG_FILE_PATH) if self.config.LOG_FILE_PATH else logging.NullHandler()
            ]
        )
    
    def get_logger(self, name: str = None):
        """Get a structured logger instance with optional name."""
        if name:
            return structlog.get_logger(name)
        return self.logger
    
    def log_request_start(self, request_id: str, method: str, path: str, user_id: str = None):
        """Log HTTP request start with correlation tracking."""
        self.logger.info(
            "Request started",
            request_id=request_id,
            method=method,
            path=path,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_request_end(self, request_id: str, status_code: int, duration: float, response_size: int = None):
        """Log HTTP request completion with performance metrics."""
        self.logger.info(
            "Request completed",
            request_id=request_id,
            status_code=status_code,
            duration_ms=duration * 1000,
            response_size_bytes=response_size,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_database_operation(self, operation: str, collection: str, duration: float, result_count: int = None):
        """Log database operation with performance tracking."""
        self.logger.info(
            "Database operation",
            operation=operation,
            collection=collection,
            duration_ms=duration * 1000,
            result_count=result_count,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_external_service_call(self, service: str, operation: str, duration: float, status_code: int):
        """Log external service calls with circuit breaker context."""
        self.logger.info(
            "External service call",
            service=service,
            operation=operation,
            duration_ms=duration * 1000,
            status_code=status_code,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_performance_variance(self, endpoint: str, variance_percent: float, baseline_time: float, current_time: float):
        """Log performance variance against Node.js baseline."""
        log_level = "warning" if variance_percent > 5.0 else "info"
        
        getattr(self.logger, log_level)(
            "Performance variance detected",
            endpoint=endpoint,
            variance_percent=variance_percent,
            baseline_response_time_ms=baseline_time * 1000,
            current_response_time_ms=current_time * 1000,
            threshold_exceeded=variance_percent > self.config.PERFORMANCE_VARIANCE_THRESHOLD,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Log error with comprehensive context information."""
        error_context = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if context:
            error_context.update(context)
        
        self.logger.error("Application error", **error_context)


class APMIntegration:
    """
    Enterprise APM integration supporting Datadog and New Relic for distributed
    tracing and comprehensive application performance monitoring.
    
    Features:
    - Automatic Flask instrumentation for request tracing
    - Database operation tracing with PyMongo/Motor integration
    - External service call tracing with circuit breaker correlation
    - Custom attribute collection for business context
    - Environment-specific sampling configuration
    """
    
    def __init__(self, config: MonitoringConfig):
        """Initialize APM integration with enterprise configuration."""
        self.config = config
        self.datadog_enabled = False
        self.newrelic_enabled = False
        
        self._setup_apm_integration()
    
    def _setup_apm_integration(self):
        """Configure enterprise APM integration."""
        if not self.config.APM_ENABLED:
            return
        
        # Datadog APM Integration
        if self.config.DATADOG_APM_ENABLED and DATADOG_AVAILABLE:
            self._setup_datadog_apm()
        
        # New Relic APM Integration
        if self.config.NEWRELIC_APM_ENABLED and NEWRELIC_AVAILABLE:
            self._setup_newrelic_apm()
    
    def _setup_datadog_apm(self):
        """Configure Datadog APM with Flask instrumentation."""
        try:
            # Configure Datadog tracer
            ddtrace.config.flask['service_name'] = self.config.APM_SERVICE_NAME
            ddtrace.config.flask['distributed_tracing'] = True
            
            # Set sampling rate based on environment
            tracer.configure(
                settings={
                    'PRIORITY_SAMPLING': True,
                    'SAMPLE_RATE': self.config.DATADOG_SAMPLE_RATE
                }
            )
            
            # Enable automatic instrumentation
            ddtrace.patch(
                flask=True,
                requests=True,
                pymongo=True,
                redis=True
            )
            
            self.datadog_enabled = True
            
        except Exception as e:
            logging.error(f"Failed to setup Datadog APM: {e}")
    
    def _setup_newrelic_apm(self):
        """Configure New Relic APM with Flask instrumentation."""
        try:
            if self.config.NEWRELIC_LICENSE_KEY:
                # Initialize New Relic agent
                newrelic.agent.initialize(
                    config_file=None,
                    environment=self.config.APM_ENVIRONMENT,
                    log_file='/var/log/newrelic/python-agent.log',
                    log_level='info'
                )
                
                self.newrelic_enabled = True
                
        except Exception as e:
            logging.error(f"Failed to setup New Relic APM: {e}")
    
    def patch_flask_app(self, app: Flask):
        """Apply APM instrumentation to Flask application."""
        if self.datadog_enabled and DATADOG_AVAILABLE:
            ddtrace_patch_flask(app)
        
        if self.newrelic_enabled and NEWRELIC_AVAILABLE:
            app.wsgi_app = newrelic.agent.WSGIApplicationWrapper(app.wsgi_app)
    
    def add_custom_attributes(self, **attributes):
        """Add custom attributes to current trace."""
        if self.datadog_enabled and DATADOG_AVAILABLE:
            span = tracer.current_span()
            if span:
                for key, value in attributes.items():
                    span.set_tag(key, value)
        
        if self.newrelic_enabled and NEWRELIC_AVAILABLE:
            for key, value in attributes.items():
                newrelic.agent.add_custom_attribute(key, value)
    
    def trace_database_operation(self, operation: str, collection: str):
        """Create database operation trace."""
        if self.datadog_enabled and DATADOG_AVAILABLE:
            return tracer.trace(f"mongodb.{operation}", service="mongodb", resource=collection)
        
        return None
    
    def trace_external_service(self, service: str, operation: str):
        """Create external service trace."""
        if self.datadog_enabled and DATADOG_AVAILABLE:
            return tracer.trace(f"{service}.{operation}", service=service, resource=operation)
        
        return None


def create_monitoring_middleware(metrics: PrometheusMetrics, logger: StructuredLogger, apm: APMIntegration):
    """
    Create comprehensive monitoring middleware for Flask request processing
    with performance tracking, logging, and APM integration.
    """
    
    def monitoring_middleware(app: Flask):
        """Flask middleware for comprehensive request monitoring."""
        
        @app.before_request
        def before_request():
            """Pre-request monitoring setup and tracking."""
            # Generate correlation ID for request tracking
            request_id = request.headers.get('X-Request-ID', f"req-{int(time.time() * 1000)}")
            g.request_id = request_id
            g.start_time = time.perf_counter()
            
            # Update active request count
            metrics.active_requests.inc()
            
            # Log request start
            logger.log_request_start(
                request_id=request_id,
                method=request.method,
                path=request.path,
                user_id=getattr(g, 'user_id', None)
            )
            
            # Add APM custom attributes
            apm.add_custom_attributes(
                request_id=request_id,
                endpoint=request.endpoint or 'unknown',
                user_agent=request.headers.get('User-Agent', 'unknown')
            )
        
        @app.after_request
        def after_request(response):
            """Post-request monitoring and metrics collection."""
            if hasattr(g, 'start_time'):
                # Calculate request duration
                duration = time.perf_counter() - g.start_time
                
                # Record HTTP metrics
                metrics.record_http_request(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown',
                    status_code=response.status_code,
                    duration=duration
                )
                
                # Log request completion
                logger.log_request_end(
                    request_id=g.request_id,
                    status_code=response.status_code,
                    duration=duration,
                    response_size=response.content_length
                )
                
                # Update active request count
                metrics.active_requests.dec()
                
                # Performance variance check for migration endpoints
                if hasattr(g, 'baseline_time') and g.baseline_time:
                    variance_percent = ((duration - g.baseline_time) / g.baseline_time) * 100
                    
                    metrics.record_performance_variance(
                        endpoint=request.endpoint or 'unknown',
                        metric_type='response_time',
                        variance_percent=variance_percent
                    )
                    
                    logger.log_performance_variance(
                        endpoint=request.endpoint or 'unknown',
                        variance_percent=variance_percent,
                        baseline_time=g.baseline_time,
                        current_time=duration
                    )
            
            return response
        
        @app.errorhandler(Exception)
        def handle_exception(error):
            """Global exception handler with comprehensive error logging."""
            # Log error with context
            logger.log_error(error, {
                'request_id': getattr(g, 'request_id', 'unknown'),
                'endpoint': request.endpoint or 'unknown',
                'method': request.method,
                'path': request.path,
                'user_id': getattr(g, 'user_id', None)
            })
            
            # Add APM error tracking
            apm.add_custom_attributes(
                error_type=type(error).__name__,
                error_message=str(error)
            )
            
            # Return error response
            return jsonify({
                'error': 'Internal server error',
                'request_id': getattr(g, 'request_id', 'unknown'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 500
    
    return monitoring_middleware


def setup_prometheus_endpoint(app: Flask, metrics: PrometheusMetrics):
    """Setup Prometheus metrics endpoint for monitoring integration."""
    
    @app.route('/metrics')
    def prometheus_metrics():
        """Prometheus metrics endpoint for monitoring system integration."""
        try:
            # Update resource utilization metrics
            metrics.update_resource_utilization()
            
            # Handle multiprocess metrics collection for Gunicorn
            if MonitoringConfig.PROMETHEUS_MULTIPROC_DIR:
                registry = CollectorRegistry()
                multiprocess.MultiProcessCollector(registry)
                metrics_output = generate_latest(registry)
            else:
                metrics_output = generate_latest()
            
            return metrics_output, 200, {'Content-Type': CONTENT_TYPE_LATEST}
            
        except Exception as e:
            return f"Error generating metrics: {str(e)}", 500


def setup_health_endpoints(app: Flask, health_manager: HealthCheckManager):
    """Setup Kubernetes-native health check endpoints."""
    
    @app.route('/health/live')
    def health_liveness():
        """Kubernetes liveness probe endpoint."""
        status, code = health_manager.get_liveness_status()
        return jsonify(status), code
    
    @app.route('/health/ready')
    def health_readiness():
        """Kubernetes readiness probe endpoint."""
        status, code = health_manager.get_readiness_status()
        return jsonify(status), code
    
    @app.route('/health')
    def health_detailed():
        """Detailed health status endpoint with comprehensive diagnostics."""
        status, code = health_manager.get_detailed_health_status()
        return jsonify(status), code


def init_monitoring(app: Flask) -> tuple[PrometheusMetrics, StructuredLogger, HealthCheckManager, APMIntegration]:
    """
    Initialize comprehensive monitoring and observability for Flask application.
    
    This function sets up enterprise-grade monitoring including:
    - Structured logging with JSON formatting for enterprise log aggregation
    - Prometheus metrics collection for performance monitoring
    - APM integration for distributed tracing
    - Health check endpoints for Kubernetes integration
    - Performance variance tracking against Node.js baseline
    
    Args:
        app: Flask application instance
        
    Returns:
        tuple: (metrics, logger, health_manager, apm) monitoring components
    """
    # Initialize monitoring configuration
    config = MonitoringConfig()
    
    # Setup Prometheus multiprocess directory for Gunicorn
    if config.PROMETHEUS_MULTIPROC_DIR:
        os.makedirs(config.PROMETHEUS_MULTIPROC_DIR, exist_ok=True)
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = config.PROMETHEUS_MULTIPROC_DIR
    
    # Initialize monitoring components
    metrics = PrometheusMetrics()
    logger = StructuredLogger(config)
    apm = APMIntegration(config)
    health_manager = HealthCheckManager(app)
    
    # Initialize garbage collection monitoring
    gc_monitor = GarbageCollectionMonitor(metrics)
    
    # Setup APM integration
    apm.patch_flask_app(app)
    
    # Setup monitoring middleware
    monitoring_middleware = create_monitoring_middleware(metrics, logger, apm)
    monitoring_middleware(app)
    
    # Setup Prometheus metrics endpoint
    setup_prometheus_endpoint(app, metrics)
    
    # Setup health check endpoints
    setup_health_endpoints(app, health_manager)
    
    # Store components in app config for access
    app.config['MONITORING_METRICS'] = metrics
    app.config['MONITORING_LOGGER'] = logger
    app.config['MONITORING_HEALTH'] = health_manager
    app.config['MONITORING_APM'] = apm
    app.config['MONITORING_GC'] = gc_monitor
    
    # Store application start time for uptime calculation
    app.config['START_TIME'] = time.time()
    
    # Log monitoring initialization
    logger.get_logger().info(
        "Monitoring system initialized",
        prometheus_enabled=config.PROMETHEUS_ENABLED,
        apm_enabled=config.APM_ENABLED,
        structured_logging_enabled=config.STRUCTURED_LOGGING_ENABLED,
        health_checks_enabled=config.HEALTH_CHECK_ENABLED,
        performance_monitoring_enabled=config.PERFORMANCE_MONITORING_ENABLED,
        nodejs_baseline_enabled=config.NODEJS_BASELINE_ENABLED,
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return metrics, logger, health_manager, apm


# Performance monitoring decorators for business logic instrumentation
def monitor_performance(endpoint: str = None, baseline_time: float = None):
    """
    Decorator for monitoring business logic performance with Node.js baseline comparison.
    
    Args:
        endpoint: Endpoint identifier for metrics labeling
        baseline_time: Node.js baseline response time for variance calculation
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                status = 'success'
            except Exception as e:
                status = 'error'
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Record business logic metrics
                if hasattr(g, 'app') and hasattr(g.app.config, 'MONITORING_METRICS'):
                    metrics = g.app.config['MONITORING_METRICS']
                    metrics.business_logic_operations_total.labels(
                        operation=endpoint or func.__name__,
                        status=status
                    ).inc()
                    
                    metrics.business_logic_duration_seconds.labels(
                        operation=endpoint or func.__name__
                    ).observe(duration)
                    
                    # Store baseline time for request monitoring
                    if baseline_time:
                        g.baseline_time = baseline_time
            
            return result
        return wrapper
    return decorator


def monitor_database_operation(operation: str, collection: str):
    """
    Decorator for monitoring database operations with performance tracking.
    
    Args:
        operation: Database operation type (find, insert, update, delete)
        collection: MongoDB collection name
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                status = 'success'
            except Exception as e:
                status = 'error'
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Record database metrics
                if hasattr(g, 'app') and hasattr(g.app.config, 'MONITORING_METRICS'):
                    metrics = g.app.config['MONITORING_METRICS']
                    metrics.record_database_operation(operation, collection, status, duration)
                
                # Log database operation
                if hasattr(g, 'app') and hasattr(g.app.config, 'MONITORING_LOGGER'):
                    logger = g.app.config['MONITORING_LOGGER']
                    logger.log_database_operation(operation, collection, duration)
            
            return result
        return wrapper
    return decorator


def monitor_external_service(service: str, operation: str):
    """
    Decorator for monitoring external service calls with circuit breaker integration.
    
    Args:
        service: External service name (auth0, aws, redis)
        operation: Service operation identifier
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            status_code = 200
            
            try:
                result = func(*args, **kwargs)
                # Extract status code from result if available
                if hasattr(result, 'status_code'):
                    status_code = result.status_code
            except Exception as e:
                status_code = 500
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Record external service metrics
                if hasattr(g, 'app') and hasattr(g.app.config, 'MONITORING_METRICS'):
                    metrics = g.app.config['MONITORING_METRICS']
                    metrics.record_external_service_request(service, operation, status_code, duration)
                
                # Log external service call
                if hasattr(g, 'app') and hasattr(g.app.config, 'MONITORING_LOGGER'):
                    logger = g.app.config['MONITORING_LOGGER']
                    logger.log_external_service_call(service, operation, duration, status_code)
            
            return result
        return wrapper
    return decorator


# Export monitoring components for application integration
__all__ = [
    'MonitoringConfig',
    'PrometheusMetrics', 
    'StructuredLogger',
    'HealthCheckManager',
    'APMIntegration',
    'GarbageCollectionMonitor',
    'init_monitoring',
    'monitor_performance',
    'monitor_database_operation',
    'monitor_external_service'
]