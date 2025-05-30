"""
Monitoring and observability configuration module implementing Prometheus metrics collection,
APM integration, performance monitoring, and health check endpoints.

This module supports the ≤10% performance variance monitoring requirement for the Node.js to Flask migration project.
Provides enterprise-grade observability through comprehensive metrics collection, distributed tracing,
and automated health monitoring capabilities.

Features:
- Prometheus metrics collection and export
- APM integration (Datadog, New Relic)
- Flask-Monitoring-Dashboard real-time monitoring
- Kubernetes health check endpoints
- WSGI server instrumentation
- Container resource monitoring
- Circuit breaker state tracking
- Performance variance monitoring against Node.js baseline
"""

import os
import time
import logging
import threading
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from functools import wraps

# Core monitoring libraries
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info, Enum,
    CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest,
    multiprocess, values
)
import psutil
import gc

# Flask monitoring extensions
from flask import Flask, request, Response, jsonify, g
from flask_monitoring import MonitoringDashboard

# APM integrations
try:
    import ddtrace
    from ddtrace import tracer, patch_all
    from ddtrace.contrib.flask import TraceMiddleware
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False

try:
    import newrelic.agent
    NEWRELIC_AVAILABLE = True
except ImportError:
    NEWRELIC_AVAILABLE = False

# Circuit breaker integration
try:
    from pybreaker import CircuitBreaker
    PYBREAKER_AVAILABLE = True
except ImportError:
    PYBREAKER_AVAILABLE = False

# Configuration base
from config.settings import BaseConfig


class MonitoringConfig:
    """
    Monitoring and observability configuration for Flask application.
    
    Implements comprehensive monitoring stack including:
    - Prometheus metrics collection
    - APM integration (Datadog/New Relic)
    - Health check endpoints
    - Performance monitoring
    - Circuit breaker integration
    """
    
    # Prometheus configuration
    PROMETHEUS_ENABLED = True
    PROMETHEUS_MULTIPROC_DIR = os.environ.get('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus_multiproc')
    PROMETHEUS_METRICS_PATH = '/metrics'
    
    # APM configuration
    APM_ENABLED = True
    APM_SERVICE_NAME = 'flask-migration-app'
    APM_ENVIRONMENT = os.environ.get('FLASK_ENV', 'development')
    APM_VERSION = os.environ.get('APP_VERSION', '1.0.0')
    
    # Datadog APM configuration
    DATADOG_APM_ENABLED = DATADOG_AVAILABLE and os.environ.get('DATADOG_APM_ENABLED', 'false').lower() == 'true'
    DATADOG_SERVICE_NAME = APM_SERVICE_NAME
    DATADOG_ENV = APM_ENVIRONMENT
    DATADOG_VERSION = APM_VERSION
    DATADOG_SAMPLE_RATE = float(os.environ.get('DATADOG_SAMPLE_RATE', '0.1' if APM_ENVIRONMENT == 'production' else '1.0'))
    
    # New Relic APM configuration
    NEWRELIC_APM_ENABLED = NEWRELIC_AVAILABLE and os.environ.get('NEW_RELIC_LICENSE_KEY') is not None
    NEWRELIC_APP_NAME = APM_SERVICE_NAME
    NEWRELIC_ENVIRONMENT = APM_ENVIRONMENT
    NEWRELIC_SAMPLE_RATE = float(os.environ.get('NEWRELIC_SAMPLE_RATE', '0.1' if APM_ENVIRONMENT == 'production' else '1.0'))
    
    # Health check configuration
    HEALTH_CHECK_ENABLED = True
    HEALTH_CHECK_TIMEOUT = 5.0  # seconds
    HEALTH_ENDPOINT_PREFIX = '/health'
    
    # Performance monitoring configuration
    PERFORMANCE_MONITORING_ENABLED = True
    PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement
    PERFORMANCE_BASELINE_TRACKING = True
    NODEJS_BASELINE_METRICS_ENABLED = True
    
    # Flask monitoring dashboard configuration
    FLASK_MONITORING_DASHBOARD_ENABLED = True
    FLASK_MONITORING_CONFIG = {
        'SECURITY_TOKEN': os.environ.get('MONITORING_DASHBOARD_TOKEN', 'dev-token-change-in-production'),
        'MONITOR_LEVEL': 3,  # Detailed monitoring
        'OUTLIER_DETECTION_CONSTANT': 2.5,
        'SAMPLING_PERIOD': 20,  # seconds
        'ENABLE_LOGGING': True
    }
    
    # System resource monitoring configuration
    SYSTEM_RESOURCE_MONITORING_ENABLED = True
    CPU_MONITORING_INTERVAL = 15  # seconds
    MEMORY_MONITORING_INTERVAL = 30  # seconds
    GC_MONITORING_ENABLED = True
    
    # Container monitoring configuration (cAdvisor integration)
    CONTAINER_MONITORING_ENABLED = os.environ.get('CONTAINER_MONITORING_ENABLED', 'true').lower() == 'true'
    CADVISOR_ENDPOINT = os.environ.get('CADVISOR_ENDPOINT', 'http://cadvisor:8080')
    
    # WSGI server monitoring configuration
    WSGI_MONITORING_ENABLED = True
    GUNICORN_METRICS_ENABLED = True
    WORKER_MONITORING_ENABLED = True
    
    # Alert thresholds
    ALERT_THRESHOLDS = {
        'response_time_variance_warning': 5.0,  # %
        'response_time_variance_critical': 10.0,  # %
        'cpu_utilization_warning': 70.0,  # %
        'cpu_utilization_critical': 90.0,  # %
        'memory_usage_warning': 80.0,  # %
        'memory_usage_critical': 95.0,  # %
        'gc_pause_warning': 100.0,  # ms
        'gc_pause_critical': 300.0,  # ms
        'worker_utilization_warning': 70.0,  # %
        'worker_utilization_critical': 90.0,  # %
        'request_queue_warning': 10,  # requests
        'request_queue_critical': 20,  # requests
    }
    
    # Circuit breaker configuration
    CIRCUIT_BREAKER_ENABLED = PYBREAKER_AVAILABLE
    CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60
    CIRCUIT_BREAKER_EXPECTED_EXCEPTION = Exception


class PrometheusMetrics:
    """
    Prometheus metrics collection and management for Flask application.
    
    Implements comprehensive metrics including:
    - Request/response metrics
    - Performance variance tracking
    - System resource utilization
    - Business logic throughput
    - Migration-specific metrics
    """
    
    def __init__(self):
        """Initialize Prometheus metrics collectors."""
        self.registry = CollectorRegistry()
        self._setup_metrics()
        self._setup_system_metrics()
        self._setup_migration_metrics()
        
    def _setup_metrics(self):
        """Set up core application metrics."""
        # Request metrics
        self.request_count = Counter(
            'flask_requests_total',
            'Total number of HTTP requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'flask_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            registry=self.registry,
            buckets=[0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
        )
        
        self.request_size = Histogram(
            'flask_request_size_bytes',
            'HTTP request size in bytes',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.response_size = Histogram(
            'flask_response_size_bytes',
            'HTTP response size in bytes',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        # Error metrics
        self.error_count = Counter(
            'flask_errors_total',
            'Total number of application errors',
            ['error_type', 'endpoint'],
            registry=self.registry
        )
        
        self.exception_count = Counter(
            'flask_exceptions_total',
            'Total number of unhandled exceptions',
            ['exception_type', 'endpoint'],
            registry=self.registry
        )
        
    def _setup_system_metrics(self):
        """Set up system resource monitoring metrics."""
        # CPU metrics
        self.cpu_usage = Gauge(
            'system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.process_cpu_usage = Gauge(
            'process_cpu_usage_percent',
            'Process CPU usage percentage',
            registry=self.registry
        )
        
        # Memory metrics
        self.memory_usage = Gauge(
            'system_memory_usage_bytes',
            'System memory usage in bytes',
            registry=self.registry
        )
        
        self.process_memory_usage = Gauge(
            'process_memory_usage_bytes',
            'Process memory usage in bytes',
            registry=self.registry
        )
        
        self.memory_usage_percent = Gauge(
            'process_memory_usage_percent',
            'Process memory usage percentage',
            registry=self.registry
        )
        
        # Python GC metrics
        self.gc_collections = Counter(
            'python_gc_collections_total',
            'Total number of garbage collections',
            ['generation'],
            registry=self.registry
        )
        
        self.gc_objects_collected = Counter(
            'python_gc_objects_collected_total',
            'Total number of objects collected by GC',
            ['generation'],
            registry=self.registry
        )
        
        self.gc_pause_time = Histogram(
            'python_gc_pause_time_seconds',
            'Time spent in garbage collection',
            ['generation'],
            registry=self.registry
        )
        
        # WSGI worker metrics
        self.active_workers = Gauge(
            'wsgi_active_workers',
            'Number of active WSGI workers',
            registry=self.registry
        )
        
        self.worker_utilization = Gauge(
            'wsgi_worker_utilization_percent',
            'WSGI worker utilization percentage',
            registry=self.registry
        )
        
        self.request_queue_depth = Gauge(
            'wsgi_request_queue_depth',
            'WSGI request queue depth',
            registry=self.registry
        )
        
    def _setup_migration_metrics(self):
        """Set up migration-specific performance metrics."""
        # Performance variance tracking
        self.performance_variance = Gauge(
            'migration_performance_variance_percent',
            'Performance variance percentage against Node.js baseline',
            ['endpoint'],
            registry=self.registry
        )
        
        # Endpoint comparison metrics
        self.nodejs_baseline_requests = Counter(
            'nodejs_baseline_requests_total',
            'Node.js baseline request count for comparison',
            ['endpoint'],
            registry=self.registry
        )
        
        self.flask_migration_requests = Counter(
            'flask_migration_requests_total',
            'Flask migration request count for comparison',
            ['endpoint'],
            registry=self.registry
        )
        
        # Business logic throughput
        self.business_logic_throughput = Gauge(
            'business_logic_throughput_operations_per_second',
            'Business logic processing throughput',
            ['operation_type'],
            registry=self.registry
        )
        
        # Database operation metrics
        self.database_operation_duration = Histogram(
            'database_operation_duration_seconds',
            'Database operation duration in seconds',
            ['operation_type', 'collection'],
            registry=self.registry
        )
        
        self.database_connection_pool = Gauge(
            'database_connection_pool_size',
            'Database connection pool size',
            ['pool_type'],
            registry=self.registry
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_state = Enum(
            'circuit_breaker_state',
            'Circuit breaker state',
            ['service'],
            states=['closed', 'open', 'half_open'],
            registry=self.registry
        )
        
        self.circuit_breaker_failures = Counter(
            'circuit_breaker_failures_total',
            'Total circuit breaker failures',
            ['service'],
            registry=self.registry
        )
        
        self.circuit_breaker_successes = Counter(
            'circuit_breaker_successes_total',
            'Total circuit breaker successes',
            ['service'],
            registry=self.registry
        )


class SystemResourceMonitor:
    """
    System resource monitoring for CPU, memory, and Python GC metrics.
    
    Provides real-time system resource utilization tracking with
    integration into Prometheus metrics collection.
    """
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
        self.process = psutil.Process()
        self._monitoring_active = False
        self._monitor_thread = None
        
    def start_monitoring(self):
        """Start system resource monitoring in background thread."""
        if self._monitoring_active:
            return
            
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name='SystemResourceMonitor'
        )
        self._monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop system resource monitoring."""
        self._monitoring_active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
            
    def _monitor_loop(self):
        """Main monitoring loop for system resources."""
        while self._monitoring_active:
            try:
                self._update_cpu_metrics()
                self._update_memory_metrics()
                self._update_gc_metrics()
                
                # Sleep for monitoring interval
                time.sleep(MonitoringConfig.CPU_MONITORING_INTERVAL)
                
            except Exception as e:
                logging.error(f"Error in system resource monitoring: {e}")
                time.sleep(5.0)  # Brief pause before retry
                
    def _update_cpu_metrics(self):
        """Update CPU utilization metrics."""
        try:
            # System CPU usage
            system_cpu = psutil.cpu_percent(interval=1.0)
            self.metrics.cpu_usage.set(system_cpu)
            
            # Process CPU usage
            process_cpu = self.process.cpu_percent()
            self.metrics.process_cpu_usage.set(process_cpu)
            
        except Exception as e:
            logging.error(f"Error updating CPU metrics: {e}")
            
    def _update_memory_metrics(self):
        """Update memory utilization metrics."""
        try:
            # System memory
            system_memory = psutil.virtual_memory()
            self.metrics.memory_usage.set(system_memory.used)
            
            # Process memory
            process_memory = self.process.memory_info()
            self.metrics.process_memory_usage.set(process_memory.rss)
            
            # Memory usage percentage
            memory_percent = (process_memory.rss / system_memory.total) * 100
            self.metrics.memory_usage_percent.set(memory_percent)
            
        except Exception as e:
            logging.error(f"Error updating memory metrics: {e}")
            
    def _update_gc_metrics(self):
        """Update Python garbage collection metrics."""
        try:
            if not MonitoringConfig.GC_MONITORING_ENABLED:
                return
                
            # Get GC stats for each generation
            gc_stats = gc.get_stats()
            for generation, stats in enumerate(gc_stats):
                self.metrics.gc_collections.labels(generation=str(generation)).inc(
                    stats.get('collections', 0)
                )
                self.metrics.gc_objects_collected.labels(generation=str(generation)).inc(
                    stats.get('collected', 0)
                )
                
        except Exception as e:
            logging.error(f"Error updating GC metrics: {e}")


class HealthCheckManager:
    """
    Health check management for Kubernetes probes and load balancer integration.
    
    Implements comprehensive health checking including:
    - Liveness probes for container restart decisions
    - Readiness probes for traffic routing decisions
    - Dependency health validation
    - Circuit breaker state monitoring
    """
    
    def __init__(self, app: Flask):
        self.app = app
        self.health_checks: Dict[str, Callable] = {}
        self.dependency_checks: Dict[str, Callable] = {}
        self._last_health_status = {}
        
    def register_health_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function."""
        self.health_checks[name] = check_func
        
    def register_dependency_check(self, name: str, check_func: Callable) -> None:
        """Register a dependency health check function."""
        self.dependency_checks[name] = check_func
        
    def setup_health_endpoints(self):
        """Set up health check endpoints for Kubernetes probes."""
        
        @self.app.route(f"{MonitoringConfig.HEALTH_ENDPOINT_PREFIX}/live")
        def liveness_probe():
            """
            Kubernetes liveness probe endpoint.
            
            Returns HTTP 200 when Flask application is operational,
            HTTP 503 when application is in fatal state requiring restart.
            """
            try:
                # Basic application health check
                app_status = self._check_application_health()
                
                if app_status['healthy']:
                    return jsonify({
                        'status': 'healthy',
                        'timestamp': datetime.utcnow().isoformat(),
                        'checks': app_status['checks']
                    }), 200
                else:
                    return jsonify({
                        'status': 'unhealthy',
                        'timestamp': datetime.utcnow().isoformat(),
                        'checks': app_status['checks']
                    }), 503
                    
            except Exception as e:
                logging.error(f"Liveness probe error: {e}")
                return jsonify({
                    'status': 'error',
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e)
                }), 503
                
        @self.app.route(f"{MonitoringConfig.HEALTH_ENDPOINT_PREFIX}/ready")
        def readiness_probe():
            """
            Kubernetes readiness probe endpoint.
            
            Returns HTTP 200 when all dependencies are healthy,
            HTTP 503 when dependencies are unavailable or degraded.
            """
            try:
                # Comprehensive dependency health check
                dependency_status = self._check_dependencies_health()
                
                if dependency_status['ready']:
                    return jsonify({
                        'status': 'ready',
                        'timestamp': datetime.utcnow().isoformat(),
                        'dependencies': dependency_status['dependencies']
                    }), 200
                else:
                    return jsonify({
                        'status': 'not_ready',
                        'timestamp': datetime.utcnow().isoformat(),
                        'dependencies': dependency_status['dependencies']
                    }), 503
                    
            except Exception as e:
                logging.error(f"Readiness probe error: {e}")
                return jsonify({
                    'status': 'error',
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e)
                }), 503
                
        @self.app.route(f"{MonitoringConfig.HEALTH_ENDPOINT_PREFIX}")
        def health_summary():
            """
            Comprehensive health summary endpoint for load balancers.
            
            Provides detailed health information for enterprise monitoring.
            """
            try:
                app_status = self._check_application_health()
                dependency_status = self._check_dependencies_health()
                
                overall_healthy = app_status['healthy'] and dependency_status['ready']
                
                return jsonify({
                    'status': 'healthy' if overall_healthy else 'degraded',
                    'timestamp': datetime.utcnow().isoformat(),
                    'application': app_status,
                    'dependencies': dependency_status,
                    'uptime': self._get_uptime(),
                    'version': MonitoringConfig.APM_VERSION
                }), 200 if overall_healthy else 503
                
            except Exception as e:
                logging.error(f"Health summary error: {e}")
                return jsonify({
                    'status': 'error',
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e)
                }), 503
                
    def _check_application_health(self) -> Dict[str, Any]:
        """Check basic application health."""
        checks = {}
        healthy = True
        
        try:
            # Run registered health checks
            for name, check_func in self.health_checks.items():
                try:
                    start_time = time.time()
                    result = check_func()
                    duration = time.time() - start_time
                    
                    checks[name] = {
                        'healthy': bool(result),
                        'duration_ms': round(duration * 1000, 2),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    if not result:
                        healthy = False
                        
                except Exception as e:
                    checks[name] = {
                        'healthy': False,
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    healthy = False
                    
        except Exception as e:
            logging.error(f"Error in application health check: {e}")
            healthy = False
            
        return {
            'healthy': healthy,
            'checks': checks
        }
        
    def _check_dependencies_health(self) -> Dict[str, Any]:
        """Check dependency health for readiness probe."""
        dependencies = {}
        ready = True
        
        try:
            # Run registered dependency checks
            for name, check_func in self.dependency_checks.items():
                try:
                    start_time = time.time()
                    result = check_func()
                    duration = time.time() - start_time
                    
                    dependencies[name] = {
                        'healthy': bool(result),
                        'duration_ms': round(duration * 1000, 2),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    if not result:
                        ready = False
                        
                except Exception as e:
                    dependencies[name] = {
                        'healthy': False,
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    ready = False
                    
        except Exception as e:
            logging.error(f"Error in dependency health check: {e}")
            ready = False
            
        return {
            'ready': ready,
            'dependencies': dependencies
        }
        
    def _get_uptime(self) -> str:
        """Get application uptime."""
        try:
            uptime_seconds = time.time() - self.app.config.get('START_TIME', time.time())
            uptime_timedelta = timedelta(seconds=int(uptime_seconds))
            return str(uptime_timedelta)
        except Exception:
            return "unknown"


class PerformanceMonitor:
    """
    Performance monitoring for ≤10% variance requirement compliance.
    
    Tracks performance metrics against Node.js baseline and provides
    real-time variance analysis for migration success validation.
    """
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
        self.baseline_metrics: Dict[str, Dict] = {}
        self.current_metrics: Dict[str, Dict] = {}
        self.variance_threshold = MonitoringConfig.PERFORMANCE_VARIANCE_THRESHOLD
        
    def record_request_performance(self, endpoint: str, duration: float, method: str = 'GET'):
        """Record request performance for variance analysis."""
        try:
            # Update current metrics
            if endpoint not in self.current_metrics:
                self.current_metrics[endpoint] = {
                    'durations': [],
                    'count': 0,
                    'total_time': 0.0
                }
                
            self.current_metrics[endpoint]['durations'].append(duration)
            self.current_metrics[endpoint]['count'] += 1
            self.current_metrics[endpoint]['total_time'] += duration
            
            # Keep only recent measurements (sliding window)
            if len(self.current_metrics[endpoint]['durations']) > 100:
                old_duration = self.current_metrics[endpoint]['durations'].pop(0)
                self.current_metrics[endpoint]['total_time'] -= old_duration
                self.current_metrics[endpoint]['count'] = len(self.current_metrics[endpoint]['durations'])
                
            # Calculate variance if baseline exists
            if endpoint in self.baseline_metrics:
                variance = self._calculate_variance(endpoint)
                self.metrics.performance_variance.labels(endpoint=endpoint).set(variance)
                
                # Check for threshold violations
                if abs(variance) > self.variance_threshold:
                    logging.warning(
                        f"Performance variance threshold exceeded for {endpoint}: "
                        f"{variance:.2f}% (threshold: ±{self.variance_threshold}%)"
                    )
                    
        except Exception as e:
            logging.error(f"Error recording performance: {e}")
            
    def set_baseline_metrics(self, endpoint: str, baseline_data: Dict):
        """Set Node.js baseline metrics for comparison."""
        self.baseline_metrics[endpoint] = baseline_data
        
    def _calculate_variance(self, endpoint: str) -> float:
        """Calculate performance variance percentage against baseline."""
        try:
            current = self.current_metrics.get(endpoint, {})
            baseline = self.baseline_metrics.get(endpoint, {})
            
            if not current.get('count') or not baseline.get('avg_duration'):
                return 0.0
                
            current_avg = current['total_time'] / current['count']
            baseline_avg = baseline['avg_duration']
            
            variance = ((current_avg - baseline_avg) / baseline_avg) * 100
            return variance
            
        except Exception as e:
            logging.error(f"Error calculating variance: {e}")
            return 0.0
            
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        summary = {
            'endpoints': {},
            'overall_compliance': True,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        for endpoint in self.current_metrics:
            if endpoint in self.baseline_metrics:
                variance = self._calculate_variance(endpoint)
                compliant = abs(variance) <= self.variance_threshold
                
                summary['endpoints'][endpoint] = {
                    'variance_percent': variance,
                    'compliant': compliant,
                    'current_avg_ms': (
                        self.current_metrics[endpoint]['total_time'] / 
                        self.current_metrics[endpoint]['count'] * 1000
                    ) if self.current_metrics[endpoint]['count'] > 0 else 0,
                    'baseline_avg_ms': self.baseline_metrics[endpoint].get('avg_duration', 0) * 1000,
                    'request_count': self.current_metrics[endpoint]['count']
                }
                
                if not compliant:
                    summary['overall_compliance'] = False
                    
        return summary


class MonitoringMiddleware:
    """
    Flask middleware for comprehensive request monitoring and metrics collection.
    
    Integrates with Prometheus metrics, APM tracing, and performance monitoring
    to provide end-to-end observability for the Flask application.
    """
    
    def __init__(self, app: Flask, metrics: PrometheusMetrics, performance_monitor: PerformanceMonitor):
        self.app = app
        self.metrics = metrics
        self.performance_monitor = performance_monitor
        self._setup_middleware()
        
    def _setup_middleware(self):
        """Set up Flask request/response middleware."""
        
        @self.app.before_request
        def before_request():
            """Before request processing - start timing and set up context."""
            g.start_time = time.time()
            g.request_size = request.content_length or 0
            
            # Record request metrics
            endpoint = request.endpoint or 'unknown'
            method = request.method
            
            self.metrics.request_size.labels(
                method=method,
                endpoint=endpoint
            ).observe(g.request_size)
            
        @self.app.after_request
        def after_request(response):
            """After request processing - record metrics and performance data."""
            try:
                # Calculate request duration
                duration = time.time() - getattr(g, 'start_time', time.time())
                
                # Get request context
                endpoint = request.endpoint or 'unknown'
                method = request.method
                status_code = str(response.status_code)
                
                # Record Prometheus metrics
                self.metrics.request_count.labels(
                    method=method,
                    endpoint=endpoint,
                    status_code=status_code
                ).inc()
                
                self.metrics.request_duration.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(duration)
                
                # Record response size
                response_size = len(response.get_data())
                self.metrics.response_size.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(response_size)
                
                # Record performance data for variance analysis
                if MonitoringConfig.PERFORMANCE_BASELINE_TRACKING:
                    self.performance_monitor.record_request_performance(
                        endpoint=endpoint,
                        duration=duration,
                        method=method
                    )
                    
                # Update migration-specific metrics
                self.metrics.flask_migration_requests.labels(endpoint=endpoint).inc()
                
            except Exception as e:
                logging.error(f"Error in after_request middleware: {e}")
                
            return response
            
        @self.app.errorhandler(Exception)
        def handle_exception(e):
            """Handle unhandled exceptions and record error metrics."""
            try:
                endpoint = request.endpoint or 'unknown'
                exception_type = type(e).__name__
                
                self.metrics.exception_count.labels(
                    exception_type=exception_type,
                    endpoint=endpoint
                ).inc()
                
                logging.error(f"Unhandled exception in {endpoint}: {e}")
                
            except Exception as log_error:
                logging.error(f"Error in exception handler: {log_error}")
                
            # Re-raise the original exception
            raise e


def setup_prometheus_metrics(app: Flask) -> PrometheusMetrics:
    """
    Set up Prometheus metrics collection for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        PrometheusMetrics: Configured metrics collector
    """
    if not MonitoringConfig.PROMETHEUS_ENABLED:
        return None
        
    try:
        # Initialize metrics collector
        metrics = PrometheusMetrics()
        
        # Set up metrics endpoint
        @app.route(MonitoringConfig.PROMETHEUS_METRICS_PATH)
        def metrics_endpoint():
            """Prometheus metrics export endpoint."""
            try:
                # Handle multiprocess mode
                if MonitoringConfig.PROMETHEUS_MULTIPROC_DIR:
                    registry = CollectorRegistry()
                    multiprocess.MultiProcessCollector(registry)
                    return Response(
                        generate_latest(registry),
                        mimetype=CONTENT_TYPE_LATEST
                    )
                else:
                    return Response(
                        generate_latest(metrics.registry),
                        mimetype=CONTENT_TYPE_LATEST
                    )
            except Exception as e:
                logging.error(f"Error generating metrics: {e}")
                return Response("Error generating metrics", status=500)
                
        logging.info("Prometheus metrics collection initialized")
        return metrics
        
    except Exception as e:
        logging.error(f"Error setting up Prometheus metrics: {e}")
        return None


def setup_apm_integration(app: Flask) -> bool:
    """
    Set up APM integration for distributed tracing and performance monitoring.
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if APM integration was successful
    """
    if not MonitoringConfig.APM_ENABLED:
        return False
        
    apm_initialized = False
    
    # Datadog APM integration
    if MonitoringConfig.DATADOG_APM_ENABLED and DATADOG_AVAILABLE:
        try:
            # Configure Datadog tracer
            ddtrace.config.flask['service_name'] = MonitoringConfig.DATADOG_SERVICE_NAME
            ddtrace.config.flask['analytics_enabled'] = True
            ddtrace.config.flask['analytics_sample_rate'] = MonitoringConfig.DATADOG_SAMPLE_RATE
            
            # Patch Flask and other libraries
            patch_all()
            
            # Initialize trace middleware
            TraceMiddleware(app, tracer, service=MonitoringConfig.DATADOG_SERVICE_NAME)
            
            # Set global tags
            tracer.set_tags({
                'service': MonitoringConfig.DATADOG_SERVICE_NAME,
                'env': MonitoringConfig.DATADOG_ENV,
                'version': MonitoringConfig.DATADOG_VERSION
            })
            
            logging.info("Datadog APM integration initialized")
            apm_initialized = True
            
        except Exception as e:
            logging.error(f"Error setting up Datadog APM: {e}")
            
    # New Relic APM integration
    if MonitoringConfig.NEWRELIC_APM_ENABLED and NEWRELIC_AVAILABLE:
        try:
            # Initialize New Relic agent
            newrelic.agent.initialize()
            
            # Set application info
            newrelic.agent.set_application_name(
                MonitoringConfig.NEWRELIC_APP_NAME,
                MonitoringConfig.NEWRELIC_ENVIRONMENT
            )
            
            logging.info("New Relic APM integration initialized")
            apm_initialized = True
            
        except Exception as e:
            logging.error(f"Error setting up New Relic APM: {e}")
            
    return apm_initialized


def setup_flask_monitoring_dashboard(app: Flask) -> bool:
    """
    Set up Flask monitoring dashboard for real-time performance monitoring.
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if dashboard setup was successful
    """
    if not MonitoringConfig.FLASK_MONITORING_DASHBOARD_ENABLED:
        return False
        
    try:
        # Configure monitoring dashboard
        for key, value in MonitoringConfig.FLASK_MONITORING_CONFIG.items():
            app.config[key] = value
            
        # Initialize monitoring dashboard
        MonitoringDashboard(app)
        
        logging.info("Flask monitoring dashboard initialized")
        return True
        
    except Exception as e:
        logging.error(f"Error setting up Flask monitoring dashboard: {e}")
        return False


def configure_monitoring(app: Flask) -> Dict[str, Any]:
    """
    Configure comprehensive monitoring and observability for Flask application.
    
    This is the main entry point for setting up all monitoring components
    including Prometheus metrics, APM integration, health checks, and
    performance monitoring.
    
    Args:
        app: Flask application instance
        
    Returns:
        Dict[str, Any]: Configuration summary and monitoring component references
    """
    monitoring_components = {}
    
    try:
        # Record application start time for uptime calculation
        app.config['START_TIME'] = time.time()
        
        # Set up Prometheus metrics
        metrics = setup_prometheus_metrics(app)
        if metrics:
            monitoring_components['metrics'] = metrics
            
        # Set up APM integration
        apm_configured = setup_apm_integration(app)
        monitoring_components['apm_enabled'] = apm_configured
        
        # Set up Flask monitoring dashboard
        dashboard_configured = setup_flask_monitoring_dashboard(app)
        monitoring_components['dashboard_enabled'] = dashboard_configured
        
        # Set up performance monitoring
        if metrics and MonitoringConfig.PERFORMANCE_MONITORING_ENABLED:
            performance_monitor = PerformanceMonitor(metrics)
            monitoring_components['performance_monitor'] = performance_monitor
            
            # Set up monitoring middleware
            middleware = MonitoringMiddleware(app, metrics, performance_monitor)
            monitoring_components['middleware'] = middleware
            
        # Set up health check manager
        if MonitoringConfig.HEALTH_CHECK_ENABLED:
            health_manager = HealthCheckManager(app)
            health_manager.setup_health_endpoints()
            monitoring_components['health_manager'] = health_manager
            
        # Set up system resource monitoring
        if metrics and MonitoringConfig.SYSTEM_RESOURCE_MONITORING_ENABLED:
            resource_monitor = SystemResourceMonitor(metrics)
            resource_monitor.start_monitoring()
            monitoring_components['resource_monitor'] = resource_monitor
            
        # Configure cleanup on app teardown
        @app.teardown_appcontext
        def cleanup_monitoring(exception):
            """Clean up monitoring resources on app teardown."""
            try:
                if 'resource_monitor' in monitoring_components:
                    monitoring_components['resource_monitor'].stop_monitoring()
            except Exception as e:
                logging.error(f"Error cleaning up monitoring: {e}")
                
        logging.info("Monitoring configuration completed successfully")
        
        return {
            'status': 'configured',
            'components': list(monitoring_components.keys()),
            'prometheus_enabled': 'metrics' in monitoring_components,
            'apm_enabled': apm_configured,
            'dashboard_enabled': dashboard_configured,
            'health_checks_enabled': 'health_manager' in monitoring_components,
            'performance_monitoring_enabled': 'performance_monitor' in monitoring_components,
            'system_monitoring_enabled': 'resource_monitor' in monitoring_components,
            'config': {
                'variance_threshold': MonitoringConfig.PERFORMANCE_VARIANCE_THRESHOLD,
                'apm_service_name': MonitoringConfig.APM_SERVICE_NAME,
                'apm_environment': MonitoringConfig.APM_ENVIRONMENT,
                'health_endpoint_prefix': MonitoringConfig.HEALTH_ENDPOINT_PREFIX
            }
        }
        
    except Exception as e:
        logging.error(f"Error configuring monitoring: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'components': list(monitoring_components.keys())
        }


# Export main configuration function and classes
__all__ = [
    'MonitoringConfig',
    'PrometheusMetrics',
    'SystemResourceMonitor',
    'HealthCheckManager',
    'PerformanceMonitor',
    'MonitoringMiddleware',
    'configure_monitoring',
    'setup_prometheus_metrics',
    'setup_apm_integration',
    'setup_flask_monitoring_dashboard'
]