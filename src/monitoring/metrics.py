#!/usr/bin/env python3
"""
Prometheus Metrics Collection Module

Comprehensive application performance monitoring using prometheus-client 0.17+ providing
WSGI server instrumentation, custom migration metrics, and business logic throughput tracking.
Implements specialized metrics for ≤10% performance variance compliance and enterprise monitoring integration.

Key Features:
- WSGI server instrumentation with Gunicorn prometheus_multiproc_dir
- Custom migration performance metrics for Node.js baseline comparison
- Flask request/response hooks for comprehensive request lifecycle monitoring
- Performance variance tracking with Prometheus Gauge metrics
- Endpoint-specific histogram metrics for response time distribution analysis
- Business logic throughput counters for migration quality assurance

Compliance:
- Section 0.1.1: Performance monitoring to ensure ≤10% variance from Node.js baseline
- Section 0.2.4: prometheus-client 0.17+ dependency decisions
- Section 6.5.4.1: WSGI server instrumentation for enterprise monitoring
- Section 6.5.4.5: Custom migration performance metrics implementation
"""

import os
import time
import functools
import threading
from typing import Dict, List, Optional, Callable, Any, Union
from collections import defaultdict
import logging

import psutil
import gc
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info, Enum,
    CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest,
    multiprocess, start_http_server
)
from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST as OPENMETRICS_CONTENT_TYPE
from flask import Flask, request, g, jsonify, Response
from werkzeug.exceptions import HTTPException

from src.config.monitoring import MonitoringConfig

# Initialize logger for metrics collection
logger = logging.getLogger(__name__)

# Global metrics registry for multiprocess support
METRICS_REGISTRY = CollectorRegistry()

class FlaskMetricsCollector:
    """
    Comprehensive Flask application metrics collector implementing enterprise-grade
    monitoring with specialized migration performance tracking.
    
    Provides WSGI server instrumentation, custom performance variance metrics,
    and business logic throughput analysis for Node.js baseline comparison.
    """
    
    def __init__(self, app: Optional[Flask] = None, registry: Optional[CollectorRegistry] = None):
        """
        Initialize Flask metrics collector with comprehensive monitoring capabilities.
        
        Args:
            app: Flask application instance for initialization
            registry: Prometheus metrics registry (defaults to global multiprocess registry)
        """
        self.app = app
        self.registry = registry or METRICS_REGISTRY
        self.config = MonitoringConfig()
        
        # Thread-local storage for request metrics
        self._local = threading.local()
        
        # Performance baseline tracking
        self._nodejs_baseline: Dict[str, float] = {}
        self._performance_cache: Dict[str, List[float]] = defaultdict(list)
        self._performance_lock = threading.Lock()
        
        # Initialize core metrics collections
        self._init_request_metrics()
        self._init_performance_metrics()
        self._init_system_metrics()
        self._init_migration_metrics()
        self._init_business_metrics()
        
        if app:
            self.init_app(app)
    
    def _init_request_metrics(self) -> None:
        """
        Initialize comprehensive request lifecycle metrics for Flask application monitoring.
        
        Implements Section 6.5.1.1 Flask request/response hooks for request lifecycle monitoring.
        """
        # Request duration histogram with detailed percentile tracking
        self.request_duration = Histogram(
            'flask_request_duration_seconds',
            'Time spent processing Flask requests by endpoint and method',
            ['method', 'endpoint', 'status_code'],
            buckets=[
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
                1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float('inf')
            ],
            registry=self.registry
        )
        
        # Request count counter with comprehensive labeling
        self.request_count = Counter(
            'flask_requests_total',
            'Total number of Flask requests processed',
            ['method', 'endpoint', 'status_code', 'client_type'],
            registry=self.registry
        )
        
        # Request size tracking for performance analysis
        self.request_size = Histogram(
            'flask_request_size_bytes',
            'Size of Flask request payloads in bytes',
            ['method', 'endpoint'],
            buckets=[64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float('inf')],
            registry=self.registry
        )
        
        # Response size tracking for bandwidth analysis
        self.response_size = Histogram(
            'flask_response_size_bytes',
            'Size of Flask response payloads in bytes',
            ['method', 'endpoint', 'status_code'],
            buckets=[64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float('inf')],
            registry=self.registry
        )
        
        # Active request gauge for concurrent load monitoring
        self.active_requests = Gauge(
            'flask_active_requests',
            'Number of requests currently being processed',
            registry=self.registry
        )
        
        # Request processing stages for detailed timing analysis
        self.request_stages = Histogram(
            'flask_request_stage_duration_seconds',
            'Time spent in different request processing stages',
            ['stage', 'endpoint'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, float('inf')],
            registry=self.registry
        )
    
    def _init_performance_metrics(self) -> None:
        """
        Initialize performance monitoring metrics for Node.js baseline comparison.
        
        Implements Section 6.5.4.5 performance variance tracking with Prometheus Gauge metrics.
        """
        # Real-time performance variance tracking against Node.js baseline
        self.performance_variance = Gauge(
            'flask_performance_variance_percentage',
            'Performance variance percentage from Node.js baseline by endpoint',
            ['endpoint', 'metric_type'],
            registry=self.registry
        )
        
        # Response time comparison metrics
        self.baseline_comparison = Histogram(
            'flask_baseline_response_comparison_seconds',
            'Response time comparison between Flask and Node.js baseline',
            ['endpoint', 'comparison_type'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, float('inf')],
            registry=self.registry
        )
        
        # Performance threshold violation tracking
        self.variance_violations = Counter(
            'flask_performance_variance_violations_total',
            'Count of performance variance threshold violations',
            ['endpoint', 'threshold_type', 'severity'],
            registry=self.registry
        )
        
        # Performance trend analysis
        self.performance_trend = Gauge(
            'flask_performance_trend_score',
            'Performance trend score indicating improvement or degradation',
            ['endpoint', 'time_window'],
            registry=self.registry
        )
        
        # Memory usage correlation with performance
        self.memory_performance_correlation = Gauge(
            'flask_memory_performance_correlation',
            'Correlation between memory usage and response time performance',
            ['endpoint'],
            registry=self.registry
        )
    
    def _init_system_metrics(self) -> None:
        """
        Initialize comprehensive system resource monitoring metrics.
        
        Implements Section 6.5.1.1 CPU utilization monitoring with psutil integration.
        """
        # Process-level CPU utilization tracking
        self.cpu_usage = Gauge(
            'flask_process_cpu_usage_percentage',
            'CPU utilization percentage for Flask process',
            ['cpu_type'],
            registry=self.registry
        )
        
        # Memory usage comprehensive tracking
        self.memory_usage = Gauge(
            'flask_process_memory_bytes',
            'Memory usage in bytes for Flask process',
            ['memory_type'],
            registry=self.registry
        )
        
        # Python garbage collection metrics
        self.gc_collections = Counter(
            'flask_gc_collections_total',
            'Total number of garbage collection cycles by generation',
            ['generation'],
            registry=self.registry
        )
        
        # GC pause time tracking for performance impact analysis
        self.gc_pause_time = Histogram(
            'flask_gc_pause_seconds',
            'Garbage collection pause time in seconds',
            ['generation'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, float('inf')],
            registry=self.registry
        )
        
        # Thread and connection pool monitoring
        self.thread_count = Gauge(
            'flask_active_threads',
            'Number of active threads in Flask application',
            registry=self.registry
        )
        
        # WSGI worker process metrics
        self.worker_metrics = Gauge(
            'flask_wsgi_worker_status',
            'WSGI worker process status and utilization',
            ['worker_id', 'status'],
            registry=self.registry
        )
        
        # File descriptor usage tracking
        self.fd_usage = Gauge(
            'flask_file_descriptors_used',
            'Number of file descriptors currently in use',
            registry=self.registry
        )
    
    def _init_migration_metrics(self) -> None:
        """
        Initialize specialized migration-specific performance metrics.
        
        Implements Section 6.5.4.5 custom migration performance metrics for Node.js baseline comparison.
        """
        # Business logic throughput comparison counters
        self.nodejs_baseline_requests = Counter(
            'nodejs_baseline_requests_total',
            'Total requests processed by Node.js baseline implementation',
            ['endpoint', 'operation_type'],
            registry=self.registry
        )
        
        self.flask_migration_requests = Counter(
            'flask_migration_requests_total',
            'Total requests processed by Flask migration implementation',
            ['endpoint', 'operation_type'],
            registry=self.registry
        )
        
        # Migration quality assurance metrics
        self.migration_compliance = Gauge(
            'flask_migration_compliance_score',
            'Migration compliance score based on performance and functionality',
            ['compliance_type'],
            registry=self.registry
        )
        
        # Feature parity tracking
        self.feature_parity = Gauge(
            'flask_feature_parity_percentage',
            'Percentage of Node.js features successfully migrated',
            ['feature_category'],
            registry=self.registry
        )
        
        # Migration rollback metrics
        self.rollback_triggers = Counter(
            'flask_migration_rollback_triggers_total',
            'Count of migration rollback triggers by cause',
            ['trigger_cause', 'severity'],
            registry=self.registry
        )
        
        # Performance improvement tracking
        self.performance_improvements = Counter(
            'flask_performance_improvements_total',
            'Count of performance improvements over Node.js baseline',
            ['improvement_type', 'endpoint'],
            registry=self.registry
        )
    
    def _init_business_metrics(self) -> None:
        """
        Initialize business logic and application-specific metrics.
        
        Provides comprehensive tracking of business operations and user interactions.
        """
        # API endpoint performance by business function
        self.business_operation_duration = Histogram(
            'flask_business_operation_duration_seconds',
            'Time spent processing specific business operations',
            ['operation', 'module', 'success'],
            buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, float('inf')],
            registry=self.registry
        )
        
        # Database operation metrics
        self.db_operation_duration = Histogram(
            'flask_database_operation_duration_seconds',
            'Database operation execution time',
            ['operation_type', 'collection', 'status'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, float('inf')],
            registry=self.registry
        )
        
        # External service integration metrics
        self.external_service_calls = Counter(
            'flask_external_service_calls_total',
            'Total external service API calls',
            ['service', 'method', 'status_code'],
            registry=self.registry
        )
        
        self.external_service_duration = Histogram(
            'flask_external_service_duration_seconds',
            'External service call duration',
            ['service', 'endpoint'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, float('inf')],
            registry=self.registry
        )
        
        # User session and authentication metrics
        self.auth_operations = Counter(
            'flask_auth_operations_total',
            'Authentication and authorization operations',
            ['operation_type', 'result', 'provider'],
            registry=self.registry
        )
        
        # Cache performance metrics
        self.cache_operations = Counter(
            'flask_cache_operations_total',
            'Cache operations count',
            ['operation', 'result', 'cache_type'],
            registry=self.registry
        )
        
        self.cache_hit_ratio = Gauge(
            'flask_cache_hit_ratio',
            'Cache hit ratio percentage',
            ['cache_type'],
            registry=self.registry
        )
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize metrics collection for Flask application with comprehensive hooks.
        
        Args:
            app: Flask application instance to instrument
        """
        self.app = app
        
        # Configure multiprocess metrics support for WSGI deployment
        self._configure_multiprocess_metrics()
        
        # Register Flask request/response hooks
        self._register_flask_hooks(app)
        
        # Initialize system resource monitoring
        self._start_system_monitoring()
        
        # Register metrics endpoint
        self._register_metrics_endpoint(app)
        
        logger.info("Flask metrics collection initialized with enterprise monitoring support")
    
    def _configure_multiprocess_metrics(self) -> None:
        """
        Configure Prometheus multiprocess metrics for WSGI server deployment.
        
        Implements Section 6.5.4.1 Gunicorn prometheus_multiproc_dir configuration.
        """
        # Set up multiprocess metrics directory for Gunicorn workers
        multiprocess_dir = os.environ.get('prometheus_multiproc_dir')
        if multiprocess_dir:
            # Configure multiprocess registry for worker aggregation
            self.registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(self.registry)
            logger.info(f"Configured multiprocess metrics with directory: {multiprocess_dir}")
        else:
            logger.warning("prometheus_multiproc_dir not configured - multiprocess metrics unavailable")
    
    def _register_flask_hooks(self, app: Flask) -> None:
        """
        Register comprehensive Flask request/response hooks for monitoring.
        
        Implements Section 6.5.1.1 Flask request/response hooks for request lifecycle monitoring.
        """
        @app.before_request
        def before_request():
            """Track request start time and initialize monitoring context."""
            g.start_time = time.time()
            g.request_id = request.headers.get('X-Request-ID', f"req_{int(time.time() * 1000)}")
            
            # Increment active request counter
            self.active_requests.inc()
            
            # Track request size for performance analysis
            if request.content_length:
                self.request_size.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown'
                ).observe(request.content_length)
        
        @app.after_request
        def after_request(response):
            """Collect comprehensive request metrics after processing."""
            try:
                request_duration = time.time() - g.start_time
                endpoint = request.endpoint or 'unknown'
                status_code = str(response.status_code)
                
                # Record request duration with detailed labeling
                self.request_duration.labels(
                    method=request.method,
                    endpoint=endpoint,
                    status_code=status_code
                ).observe(request_duration)
                
                # Count requests with client type detection
                client_type = self._detect_client_type(request)
                self.request_count.labels(
                    method=request.method,
                    endpoint=endpoint,
                    status_code=status_code,
                    client_type=client_type
                ).inc()
                
                # Track response size
                if response.content_length:
                    self.response_size.labels(
                        method=request.method,
                        endpoint=endpoint,
                        status_code=status_code
                    ).observe(response.content_length)
                
                # Update performance variance tracking
                self._update_performance_variance(endpoint, request_duration)
                
                # Track migration-specific metrics
                self._track_migration_metrics(endpoint, request_duration, status_code)
                
                # Decrement active request counter
                self.active_requests.dec()
                
            except Exception as e:
                logger.error(f"Error collecting request metrics: {e}")
            
            return response
        
        @app.teardown_request
        def teardown_request(exception):
            """Clean up request-specific monitoring context."""
            if exception:
                # Track request exceptions for error analysis
                endpoint = request.endpoint or 'unknown'
                self.request_count.labels(
                    method=request.method,
                    endpoint=endpoint,
                    status_code='500',
                    client_type='error'
                ).inc()
    
    def _detect_client_type(self, request) -> str:
        """
        Detect client type from request headers for detailed analytics.
        
        Args:
            request: Flask request object
            
        Returns:
            Client type classification string
        """
        user_agent = request.headers.get('User-Agent', '').lower()
        
        if 'postman' in user_agent or 'insomnia' in user_agent:
            return 'api_client'
        elif 'curl' in user_agent or 'wget' in user_agent:
            return 'cli_tool'
        elif 'python' in user_agent or 'requests' in user_agent:
            return 'python_client'
        elif 'monitoring' in user_agent or 'probe' in user_agent:
            return 'health_check'
        elif 'bot' in user_agent or 'crawler' in user_agent:
            return 'bot'
        else:
            return 'browser'
    
    def _update_performance_variance(self, endpoint: str, duration: float) -> None:
        """
        Update performance variance metrics against Node.js baseline.
        
        Implements Section 6.5.4.5 performance variance tracking for compliance monitoring.
        
        Args:
            endpoint: API endpoint name
            duration: Request duration in seconds
        """
        with self._performance_lock:
            # Add current measurement to performance cache
            self._performance_cache[endpoint].append(duration)
            
            # Maintain rolling window of last 100 measurements
            if len(self._performance_cache[endpoint]) > 100:
                self._performance_cache[endpoint] = self._performance_cache[endpoint][-100:]
            
            # Calculate performance variance if baseline exists
            if endpoint in self._nodejs_baseline:
                baseline_duration = self._nodejs_baseline[endpoint]
                current_avg = sum(self._performance_cache[endpoint]) / len(self._performance_cache[endpoint])
                
                # Calculate variance percentage
                variance_pct = ((current_avg - baseline_duration) / baseline_duration) * 100
                
                # Update variance gauge
                self.performance_variance.labels(
                    endpoint=endpoint,
                    metric_type='response_time'
                ).set(variance_pct)
                
                # Track variance violations
                if abs(variance_pct) > 5.0:  # Warning threshold
                    severity = 'critical' if abs(variance_pct) > 10.0 else 'warning'
                    threshold_type = 'performance_degradation' if variance_pct > 0 else 'performance_improvement'
                    
                    self.variance_violations.labels(
                        endpoint=endpoint,
                        threshold_type=threshold_type,
                        severity=severity
                    ).inc()
                    
                    if severity == 'critical':
                        logger.warning(f"Critical performance variance detected for {endpoint}: {variance_pct:.2f}%")
                
                # Record baseline comparison
                comparison_type = 'flask_current' if variance_pct >= 0 else 'flask_improved'
                self.baseline_comparison.labels(
                    endpoint=endpoint,
                    comparison_type=comparison_type
                ).observe(current_avg)
    
    def _track_migration_metrics(self, endpoint: str, duration: float, status_code: str) -> None:
        """
        Track migration-specific metrics for quality assurance.
        
        Args:
            endpoint: API endpoint name
            duration: Request duration in seconds
            status_code: HTTP response status code
        """
        # Increment Flask migration request counter
        operation_type = 'read' if request.method == 'GET' else 'write'
        self.flask_migration_requests.labels(
            endpoint=endpoint,
            operation_type=operation_type
        ).inc()
        
        # Update migration compliance score
        compliance_score = self._calculate_compliance_score(endpoint, duration, status_code)
        self.migration_compliance.labels(
            compliance_type='overall'
        ).set(compliance_score)
    
    def _calculate_compliance_score(self, endpoint: str, duration: float, status_code: str) -> float:
        """
        Calculate migration compliance score based on performance and functionality.
        
        Args:
            endpoint: API endpoint name
            duration: Request duration in seconds
            status_code: HTTP response status code
            
        Returns:
            Compliance score between 0.0 and 1.0
        """
        score = 1.0
        
        # Performance compliance factor
        if endpoint in self._nodejs_baseline:
            baseline_duration = self._nodejs_baseline[endpoint]
            variance_pct = ((duration - baseline_duration) / baseline_duration) * 100
            
            if abs(variance_pct) <= 5.0:
                performance_factor = 1.0
            elif abs(variance_pct) <= 10.0:
                performance_factor = 0.8
            else:
                performance_factor = 0.5
            
            score *= performance_factor
        
        # Functionality compliance factor
        if status_code.startswith('2'):
            functionality_factor = 1.0
        elif status_code.startswith('4'):
            functionality_factor = 0.9
        else:
            functionality_factor = 0.7
        
        score *= functionality_factor
        
        return max(0.0, min(1.0, score))
    
    def _start_system_monitoring(self) -> None:
        """
        Start background system resource monitoring thread.
        
        Implements Section 6.5.1.1 CPU utilization monitoring with psutil integration.
        """
        def monitor_system_resources():
            """Background thread for continuous system resource monitoring."""
            while True:
                try:
                    # CPU utilization monitoring
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.cpu_usage.labels(cpu_type='total').set(cpu_percent)
                    
                    process = psutil.Process()
                    process_cpu = process.cpu_percent()
                    self.cpu_usage.labels(cpu_type='process').set(process_cpu)
                    
                    # Memory usage monitoring
                    memory_info = process.memory_info()
                    self.memory_usage.labels(memory_type='rss').set(memory_info.rss)
                    self.memory_usage.labels(memory_type='vms').set(memory_info.vms)
                    
                    # Memory percentage
                    memory_percent = process.memory_percent()
                    self.memory_usage.labels(memory_type='percent').set(memory_percent)
                    
                    # Thread count monitoring
                    thread_count = threading.active_count()
                    self.thread_count.set(thread_count)
                    
                    # File descriptor usage
                    try:
                        fd_count = process.num_fds()
                        self.fd_usage.set(fd_count)
                    except AttributeError:
                        # Windows doesn't support num_fds
                        pass
                    
                    # Garbage collection metrics
                    gc_stats = gc.get_stats()
                    for generation, stats in enumerate(gc_stats):
                        self.gc_collections.labels(generation=str(generation)).inc(stats.get('collections', 0))
                    
                    time.sleep(15)  # Monitor every 15 seconds
                    
                except Exception as e:
                    logger.error(f"Error monitoring system resources: {e}")
                    time.sleep(30)  # Wait longer on error
        
        # Start monitoring thread as daemon
        monitor_thread = threading.Thread(target=monitor_system_resources, daemon=True)
        monitor_thread.start()
        logger.info("Started background system resource monitoring")
    
    def _register_metrics_endpoint(self, app: Flask) -> None:
        """
        Register Prometheus metrics endpoint for scraping.
        
        Args:
            app: Flask application instance
        """
        @app.route('/metrics')
        def metrics():
            """Prometheus metrics endpoint supporting OpenMetrics format."""
            try:
                # Support both Prometheus and OpenMetrics formats
                accept_header = request.headers.get('Accept', '')
                
                if 'application/openmetrics-text' in accept_header:
                    content_type = OPENMETRICS_CONTENT_TYPE
                else:
                    content_type = CONTENT_TYPE_LATEST
                
                # Generate metrics data
                metrics_data = generate_latest(self.registry)
                
                return Response(
                    metrics_data,
                    mimetype=content_type,
                    headers={'Cache-Control': 'no-cache, no-store, must-revalidate'}
                )
                
            except Exception as e:
                logger.error(f"Error generating metrics: {e}")
                return jsonify({'error': 'Metrics generation failed'}), 500
    
    def set_nodejs_baseline(self, endpoint: str, baseline_duration: float) -> None:
        """
        Set Node.js baseline performance for comparison tracking.
        
        Args:
            endpoint: API endpoint name
            baseline_duration: Baseline duration in seconds from Node.js implementation
        """
        self._nodejs_baseline[endpoint] = baseline_duration
        logger.info(f"Set Node.js baseline for {endpoint}: {baseline_duration:.3f}s")
    
    def track_business_operation(self, operation: str, module: str = 'unknown') -> Callable:
        """
        Decorator for tracking business operation metrics.
        
        Args:
            operation: Business operation name
            module: Module or component name
            
        Returns:
            Decorator function for business operation tracking
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                success = True
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    success = False
                    raise
                finally:
                    duration = time.time() - start_time
                    self.business_operation_duration.labels(
                        operation=operation,
                        module=module,
                        success=str(success).lower()
                    ).observe(duration)
            
            return wrapper
        return decorator
    
    def track_external_service_call(self, service: str, endpoint: str = 'unknown') -> Callable:
        """
        Decorator for tracking external service call metrics.
        
        Args:
            service: External service name
            endpoint: Service endpoint name
            
        Returns:
            Decorator function for external service tracking
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    # Track successful call
                    self.external_service_calls.labels(
                        service=service,
                        method='unknown',
                        status_code='200'
                    ).inc()
                    
                    return result
                except Exception as e:
                    # Track failed call
                    self.external_service_calls.labels(
                        service=service,
                        method='unknown',
                        status_code='error'
                    ).inc()
                    raise
                finally:
                    duration = time.time() - start_time
                    self.external_service_duration.labels(
                        service=service,
                        endpoint=endpoint
                    ).observe(duration)
            
            return wrapper
        return decorator
    
    def track_database_operation(self, operation_type: str, collection: str = 'unknown') -> Callable:
        """
        Decorator for tracking database operation metrics.
        
        Args:
            operation_type: Database operation type (find, insert, update, delete)
            collection: MongoDB collection name
            
        Returns:
            Decorator function for database operation tracking
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                status = 'success'
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    status = 'error'
                    raise
                finally:
                    duration = time.time() - start_time
                    self.db_operation_duration.labels(
                        operation_type=operation_type,
                        collection=collection,
                        status=status
                    ).observe(duration)
            
            return wrapper
        return decorator
    
    def update_cache_metrics(self, operation: str, result: str, cache_type: str = 'redis') -> None:
        """
        Update cache operation metrics.
        
        Args:
            operation: Cache operation (get, set, delete, etc.)
            result: Operation result (hit, miss, success, error)
            cache_type: Type of cache system
        """
        self.cache_operations.labels(
            operation=operation,
            result=result,
            cache_type=cache_type
        ).inc()
    
    def update_auth_metrics(self, operation_type: str, result: str, provider: str = 'local') -> None:
        """
        Update authentication operation metrics.
        
        Args:
            operation_type: Authentication operation (login, logout, validate, etc.)
            result: Operation result (success, failure, error)
            provider: Authentication provider (local, auth0, etc.)
        """
        self.auth_operations.labels(
            operation_type=operation_type,
            result=result,
            provider=provider
        ).inc()
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance summary for monitoring dashboards.
        
        Returns:
            Dictionary containing performance metrics summary
        """
        summary = {
            'endpoints_monitored': len(self._performance_cache),
            'nodejs_baselines_set': len(self._nodejs_baseline),
            'performance_compliance': {},
            'system_health': {}
        }
        
        # Calculate performance compliance for each endpoint
        for endpoint in self._nodejs_baseline:
            if endpoint in self._performance_cache and self._performance_cache[endpoint]:
                baseline = self._nodejs_baseline[endpoint]
                current_avg = sum(self._performance_cache[endpoint]) / len(self._performance_cache[endpoint])
                variance_pct = ((current_avg - baseline) / baseline) * 100
                
                summary['performance_compliance'][endpoint] = {
                    'variance_percentage': round(variance_pct, 2),
                    'compliant': abs(variance_pct) <= 10.0,
                    'current_avg_ms': round(current_avg * 1000, 2),
                    'baseline_ms': round(baseline * 1000, 2)
                }
        
        # Add system health indicators
        try:
            process = psutil.Process()
            summary['system_health'] = {
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'thread_count': threading.active_count(),
                'gc_generation_0': gc.get_count()[0],
                'gc_generation_1': gc.get_count()[1],
                'gc_generation_2': gc.get_count()[2]
            }
        except Exception as e:
            logger.error(f"Error gathering system health metrics: {e}")
        
        return summary


# Global metrics collector instance for application-wide use
metrics_collector = FlaskMetricsCollector(registry=METRICS_REGISTRY)

# Convenience decorators for common operations
track_business_operation = metrics_collector.track_business_operation
track_external_service_call = metrics_collector.track_external_service_call
track_database_operation = metrics_collector.track_database_operation

# Metrics update functions
update_cache_metrics = metrics_collector.update_cache_metrics
update_auth_metrics = metrics_collector.update_auth_metrics

# Performance management functions
set_nodejs_baseline = metrics_collector.set_nodejs_baseline
get_performance_summary = metrics_collector.get_performance_summary

def init_metrics(app: Flask) -> FlaskMetricsCollector:
    """
    Initialize metrics collection for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured metrics collector instance
    """
    metrics_collector.init_app(app)
    return metrics_collector

def start_metrics_server(port: int = 8000) -> None:
    """
    Start standalone Prometheus metrics server.
    
    Args:
        port: Port number for metrics server
    """
    try:
        start_http_server(port, registry=METRICS_REGISTRY)
        logger.info(f"Started Prometheus metrics server on port {port}")
    except Exception as e:
        logger.error(f"Failed to start metrics server: {e}")

# Export key components for external use
__all__ = [
    'FlaskMetricsCollector',
    'metrics_collector',
    'init_metrics',
    'start_metrics_server',
    'track_business_operation',
    'track_external_service_call', 
    'track_database_operation',
    'update_cache_metrics',
    'update_auth_metrics',
    'set_nodejs_baseline',
    'get_performance_summary',
    'METRICS_REGISTRY'
]