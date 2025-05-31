"""
Prometheus Metrics Collection Implementation

This module implements comprehensive Prometheus metrics collection for the Flask migration
application using prometheus-client 0.17+, providing enterprise-grade monitoring, WSGI server
instrumentation, custom migration performance tracking, and business logic throughput analysis.

Key Features:
- prometheus-client 0.17+ metrics collection for enterprise Prometheus integration
- WSGI server instrumentation with Gunicorn prometheus_multiproc_dir support
- Custom migration performance metrics for Node.js baseline comparison (≤10% variance)
- Flask request/response hooks for comprehensive request lifecycle monitoring
- Performance variance tracking with real-time Prometheus Gauge metrics
- Endpoint-specific histogram metrics for response time distribution analysis
- Business logic throughput counters for migration quality assurance
- Container resource correlation and system performance monitoring

Architecture Integration:
- Flask application factory pattern integration for centralized metrics collection
- Prometheus Alertmanager integration for automated threshold-based alerting
- Enterprise APM correlation for comprehensive performance monitoring
- Container orchestration integration via /metrics endpoint for Kubernetes monitoring
- WSGI worker-level metrics aggregation for horizontal scaling decision support

Performance Requirements:
- Real-time performance variance tracking: ≤10% from Node.js baseline (critical requirement)
- Response time distribution analysis: P50, P95, P99 percentile tracking with histogram buckets
- CPU utilization monitoring: Warning >70%, Critical >90% with 15-second collection intervals
- Memory usage tracking: Warning >80%, Critical >95% heap usage with Python GC correlation
- Business logic throughput comparison: Direct Flask vs Node.js request rate analysis

References:
- Section 3.6.2 Performance Monitoring: prometheus-client 0.17+ requirements
- Section 6.5.1.1 Metrics Collection: WSGI server instrumentation and enterprise integration
- Section 6.5.4.5 Custom Migration Performance Metrics: Node.js baseline comparison framework
- Section 0.1.1 Primary Objective: ≤10% performance variance requirement compliance
- Section 6.5.4.1 Enhanced WSGI Server Monitoring: Gunicorn metrics collection implementation
"""

import gc
import os
import time
import threading
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Callable, Union

import psutil
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Info,
    Summary,
    CollectorRegistry,
    multiprocess,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
    start_http_server,
)
from flask import Flask, g, request, Response

from src.config.monitoring import MonitoringConfig


class PrometheusMetricsCollector:
    """
    Comprehensive Prometheus metrics collector implementing enterprise-grade performance
    monitoring for Flask migration application with Node.js baseline comparison capabilities.
    
    This collector provides:
    - HTTP request/response performance tracking with P50/P95/P99 percentiles
    - Database operation performance monitoring with query-level granularity
    - External service integration metrics with circuit breaker correlation
    - Resource utilization (CPU, memory, GC) tracking with container integration
    - Custom migration performance comparison metrics for baseline compliance
    - Business logic throughput analysis for migration quality assurance
    - WSGI server instrumentation for worker-level performance monitoring
    """
    
    def __init__(self, config: MonitoringConfig = None):
        """
        Initialize Prometheus metrics collector with enterprise configuration.
        
        Args:
            config: MonitoringConfig instance with enterprise monitoring settings
        """
        self.config = config or MonitoringConfig()
        self._lock = threading.Lock()
        self._initialized = False
        
        # Setup multiprocess metrics collection for Gunicorn
        self._setup_multiprocess_registry()
        
        # Initialize core HTTP metrics
        self._init_http_metrics()
        
        # Initialize database performance metrics
        self._init_database_metrics()
        
        # Initialize external service metrics
        self._init_external_service_metrics()
        
        # Initialize system resource metrics
        self._init_resource_metrics()
        
        # Initialize custom migration metrics
        self._init_migration_metrics()
        
        # Initialize business logic metrics
        self._init_business_logic_metrics()
        
        # Initialize WSGI server metrics
        self._init_wsgi_server_metrics()
        
        # Initialize circuit breaker metrics
        self._init_circuit_breaker_metrics()
        
        # Setup garbage collection monitoring
        self._init_garbage_collection_metrics()
        
        self._initialized = True
    
    def _setup_multiprocess_registry(self):
        """Setup multiprocess metrics registry for Gunicorn worker coordination."""
        if self.config.PROMETHEUS_MULTIPROC_DIR:
            # Ensure multiprocess directory exists
            os.makedirs(self.config.PROMETHEUS_MULTIPROC_DIR, exist_ok=True)
            
            # Set environment variable for prometheus_client
            os.environ['PROMETHEUS_MULTIPROC_DIR'] = self.config.PROMETHEUS_MULTIPROC_DIR
    
    def _init_http_metrics(self):
        """Initialize HTTP request/response performance metrics."""
        # HTTP request counter with comprehensive labels
        self.http_requests_total = Counter(
            'flask_http_requests_total',
            'Total number of HTTP requests processed by Flask application',
            ['method', 'endpoint', 'status_code', 'user_type'],
            registry=REGISTRY
        )
        
        # HTTP request duration histogram with optimized buckets for web applications
        self.http_request_duration_seconds = Histogram(
            'flask_http_request_duration_seconds',
            'HTTP request processing duration in seconds',
            ['method', 'endpoint', 'status_class'],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float('inf')],
            registry=REGISTRY
        )
        
        # HTTP request size histogram for bandwidth analysis
        self.http_request_size_bytes = Histogram(
            'flask_http_request_size_bytes',
            'Size of HTTP request in bytes',
            ['method', 'endpoint'],
            buckets=[64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float('inf')],
            registry=REGISTRY
        )
        
        # HTTP response size histogram for response optimization
        self.http_response_size_bytes = Histogram(
            'flask_http_response_size_bytes',
            'Size of HTTP response in bytes',
            ['method', 'endpoint', 'status_class'],
            buckets=[64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float('inf')],
            registry=REGISTRY
        )
        
        # Active HTTP requests gauge for concurrency monitoring
        self.http_requests_active = Gauge(
            'flask_http_requests_active',
            'Number of HTTP requests currently being processed',
            registry=REGISTRY
        )
        
        # HTTP request rate summary for throughput analysis
        self.http_request_rate = Summary(
            'flask_http_request_rate_per_second',
            'Rate of HTTP requests per second',
            registry=REGISTRY
        )
    
    def _init_database_metrics(self):
        """Initialize database operation performance metrics."""
        # Database operation counter with operation granularity
        self.database_operations_total = Counter(
            'flask_database_operations_total',
            'Total number of database operations executed',
            ['operation', 'collection', 'status', 'connection_pool'],
            registry=REGISTRY
        )
        
        # Database operation duration histogram for query performance analysis
        self.database_operation_duration_seconds = Histogram(
            'flask_database_operation_duration_seconds',
            'Database operation execution duration in seconds',
            ['operation', 'collection', 'index_used'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, float('inf')],
            registry=REGISTRY
        )
        
        # Database connection pool metrics
        self.database_connections_active = Gauge(
            'flask_database_connections_active',
            'Number of active database connections',
            ['pool_name', 'database'],
            registry=REGISTRY
        )
        
        self.database_connections_pool_size = Gauge(
            'flask_database_connections_pool_size',
            'Total database connection pool size',
            ['pool_name', 'database'],
            registry=REGISTRY
        )
        
        # Database query result size for optimization analysis
        self.database_query_result_size = Histogram(
            'flask_database_query_result_size_documents',
            'Number of documents returned by database queries',
            ['operation', 'collection'],
            buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, float('inf')],
            registry=REGISTRY
        )
    
    def _init_external_service_metrics(self):
        """Initialize external service integration performance metrics."""
        # External service request counter with service identification
        self.external_service_requests_total = Counter(
            'flask_external_service_requests_total',
            'Total number of external service requests made',
            ['service', 'operation', 'status_code', 'circuit_breaker_state'],
            registry=REGISTRY
        )
        
        # External service request duration histogram
        self.external_service_duration_seconds = Histogram(
            'flask_external_service_duration_seconds',
            'External service request duration in seconds',
            ['service', 'operation', 'endpoint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float('inf')],
            registry=REGISTRY
        )
        
        # External service timeout counter for reliability analysis
        self.external_service_timeouts_total = Counter(
            'flask_external_service_timeouts_total',
            'Total number of external service request timeouts',
            ['service', 'operation'],
            registry=REGISTRY
        )
        
        # External service retry attempts for resilience tracking
        self.external_service_retries_total = Counter(
            'flask_external_service_retries_total',
            'Total number of external service retry attempts',
            ['service', 'operation', 'retry_reason'],
            registry=REGISTRY
        )
    
    def _init_resource_metrics(self):
        """Initialize system resource utilization metrics."""
        # CPU utilization gauge with process-level granularity
        self.cpu_utilization_percent = Gauge(
            'flask_cpu_utilization_percent',
            'Current CPU utilization percentage of Flask application process',
            ['process_type'],  # main, worker
            registry=REGISTRY
        )
        
        # Memory usage gauges with detailed breakdown
        self.memory_usage_bytes = Gauge(
            'flask_memory_usage_bytes',
            'Current memory usage in bytes',
            ['memory_type'],  # rss, vms, heap, shared
            registry=REGISTRY
        )
        
        # Memory usage percentage for alerting
        self.memory_utilization_percent = Gauge(
            'flask_memory_utilization_percent',
            'Current memory utilization percentage of available memory',
            ['memory_type'],
            registry=REGISTRY
        )
        
        # Disk I/O metrics for performance correlation
        self.disk_io_bytes_total = Counter(
            'flask_disk_io_bytes_total',
            'Total disk I/O bytes processed',
            ['operation'],  # read, write
            registry=REGISTRY
        )
        
        # Network I/O metrics for bandwidth analysis
        self.network_io_bytes_total = Counter(
            'flask_network_io_bytes_total',
            'Total network I/O bytes processed',
            ['direction'],  # sent, received
            registry=REGISTRY
        )
        
        # File descriptor usage for resource leak detection
        self.file_descriptors_open = Gauge(
            'flask_file_descriptors_open',
            'Number of open file descriptors',
            registry=REGISTRY
        )
    
    def _init_migration_metrics(self):
        """Initialize custom migration performance comparison metrics."""
        # Node.js baseline request counter for comparison
        self.nodejs_baseline_requests_total = Counter(
            'nodejs_baseline_requests_total',
            'Total Node.js baseline requests for performance comparison',
            ['endpoint', 'status_code'],
            registry=REGISTRY
        )
        
        # Flask migration request counter for comparison
        self.flask_migration_requests_total = Counter(
            'flask_migration_requests_total',
            'Total Flask migration requests for performance comparison',
            ['endpoint', 'status_code'],
            registry=REGISTRY
        )
        
        # Performance variance gauge (critical ≤10% requirement)
        self.performance_variance_percent = Gauge(
            'flask_performance_variance_percent',
            'Performance variance percentage against Node.js baseline',
            ['endpoint', 'metric_type', 'variance_direction'],  # response_time, memory_usage, cpu_usage; positive, negative
            registry=REGISTRY
        )
        
        # Endpoint response time comparison histogram
        self.endpoint_response_time_comparison_seconds = Histogram(
            'flask_endpoint_response_time_comparison_seconds',
            'Endpoint response time comparison between implementations',
            ['endpoint', 'implementation', 'percentile'],  # nodejs, flask; p50, p95, p99
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float('inf')],
            registry=REGISTRY
        )
        
        # Migration baseline compliance gauge
        self.migration_baseline_compliance = Gauge(
            'flask_migration_baseline_compliance',
            'Migration baseline compliance score (1.0 = full compliance)',
            ['compliance_category'],  # performance, functionality, security
            registry=REGISTRY
        )
        
        # Performance regression detection counter
        self.performance_regressions_total = Counter(
            'flask_performance_regressions_total',
            'Total number of performance regressions detected',
            ['endpoint', 'regression_type', 'severity'],  # response_time, memory_leak, cpu_spike; warning, critical
            registry=REGISTRY
        )
    
    def _init_business_logic_metrics(self):
        """Initialize business logic performance and throughput metrics."""
        # Business logic operation counter for throughput analysis
        self.business_logic_operations_total = Counter(
            'flask_business_logic_operations_total',
            'Total business logic operations processed',
            ['operation', 'module', 'status', 'complexity'],  # simple, moderate, complex
            registry=REGISTRY
        )
        
        # Business logic operation duration histogram
        self.business_logic_duration_seconds = Histogram(
            'flask_business_logic_duration_seconds',
            'Business logic operation execution duration in seconds',
            ['operation', 'module', 'optimization_level'],  # baseline, optimized, cached
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, float('inf')],
            registry=REGISTRY
        )
        
        # Business logic cache hit ratio for optimization tracking
        self.business_logic_cache_hits_total = Counter(
            'flask_business_logic_cache_hits_total',
            'Total business logic cache hits',
            ['cache_type', 'operation'],  # memory, redis, database
            registry=REGISTRY
        )
        
        self.business_logic_cache_misses_total = Counter(
            'flask_business_logic_cache_misses_total',
            'Total business logic cache misses',
            ['cache_type', 'operation'],
            registry=REGISTRY
        )
        
        # Data processing throughput for migration validation
        self.data_processing_throughput_records_per_second = Gauge(
            'flask_data_processing_throughput_records_per_second',
            'Current data processing throughput in records per second',
            ['processor_type', 'data_type'],
            registry=REGISTRY
        )
        
        # Business rule execution metrics
        self.business_rules_executed_total = Counter(
            'flask_business_rules_executed_total',
            'Total number of business rules executed',
            ['rule_type', 'rule_category', 'execution_result'],  # validation, transformation, enrichment; success, failure, skipped
            registry=REGISTRY
        )
    
    def _init_wsgi_server_metrics(self):
        """Initialize WSGI server instrumentation metrics."""
        # Worker process metrics for Gunicorn monitoring
        self.wsgi_workers_active = Gauge(
            'flask_wsgi_workers_active',
            'Number of active WSGI worker processes',
            registry=REGISTRY
        )
        
        self.wsgi_workers_total = Gauge(
            'flask_wsgi_workers_total',
            'Total number of configured WSGI worker processes',
            registry=REGISTRY
        )
        
        # Worker utilization percentage for scaling decisions
        self.wsgi_worker_utilization_percent = Gauge(
            'flask_wsgi_worker_utilization_percent',
            'WSGI worker utilization percentage',
            ['worker_id', 'worker_type'],  # sync, async
            registry=REGISTRY
        )
        
        # Request queue depth for performance analysis
        self.wsgi_request_queue_depth = Gauge(
            'flask_wsgi_request_queue_depth',
            'Number of requests waiting in WSGI queue',
            registry=REGISTRY
        )
        
        # Worker request processing rate
        self.wsgi_worker_requests_per_second = Gauge(
            'flask_wsgi_worker_requests_per_second',
            'Requests processed per second by WSGI workers',
            ['worker_id'],
            registry=REGISTRY
        )
        
        # Worker lifecycle events
        self.wsgi_worker_lifecycle_events_total = Counter(
            'flask_wsgi_worker_lifecycle_events_total',
            'Total WSGI worker lifecycle events',
            ['event_type', 'worker_id'],  # started, stopped, restarted, crashed
            registry=REGISTRY
        )
        
        # Connection handling metrics
        self.wsgi_connections_active = Gauge(
            'flask_wsgi_connections_active',
            'Number of active WSGI connections',
            ['connection_type'],  # keep_alive, new
            registry=REGISTRY
        )
    
    def _init_circuit_breaker_metrics(self):
        """Initialize circuit breaker pattern monitoring metrics."""
        # Circuit breaker state gauge
        self.circuit_breaker_state = Gauge(
            'flask_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half_open)',
            ['service', 'operation'],
            registry=REGISTRY
        )
        
        # Circuit breaker state transition counter
        self.circuit_breaker_state_transitions_total = Counter(
            'flask_circuit_breaker_state_transitions_total',
            'Total circuit breaker state transitions',
            ['service', 'operation', 'from_state', 'to_state'],
            registry=REGISTRY
        )
        
        # Circuit breaker failure counter
        self.circuit_breaker_failures_total = Counter(
            'flask_circuit_breaker_failures_total',
            'Total circuit breaker failures',
            ['service', 'operation', 'failure_type'],  # timeout, error, threshold_exceeded
            registry=REGISTRY
        )
        
        # Circuit breaker recovery attempts
        self.circuit_breaker_recovery_attempts_total = Counter(
            'flask_circuit_breaker_recovery_attempts_total',
            'Total circuit breaker recovery attempts',
            ['service', 'operation', 'recovery_result'],  # success, failure
            registry=REGISTRY
        )
    
    def _init_garbage_collection_metrics(self):
        """Initialize Python garbage collection performance metrics."""
        # GC collection counter by generation
        self.gc_collections_total = Counter(
            'flask_gc_collections_total',
            'Total number of garbage collection cycles',
            ['generation'],  # 0, 1, 2
            registry=REGISTRY
        )
        
        # GC pause time histogram for performance impact analysis
        self.gc_pause_time_seconds = Histogram(
            'flask_gc_pause_time_seconds',
            'Python garbage collection pause time in seconds',
            ['generation', 'collection_type'],  # full, incremental
            buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, float('inf')],
            registry=REGISTRY
        )
        
        # GC object count gauges for memory analysis
        self.gc_objects_tracked = Gauge(
            'flask_gc_objects_tracked',
            'Number of objects tracked by garbage collector',
            ['object_type'],  # dict, list, tuple, custom
            registry=REGISTRY
        )
        
        # GC memory recovered histogram
        self.gc_memory_recovered_bytes = Histogram(
            'flask_gc_memory_recovered_bytes',
            'Memory recovered by garbage collection in bytes',
            ['generation'],
            buckets=[1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, float('inf')],
            registry=REGISTRY
        )
        
        # GC efficiency metrics
        self.gc_efficiency_ratio = Gauge(
            'flask_gc_efficiency_ratio',
            'Garbage collection efficiency ratio (objects_collected / objects_examined)',
            ['generation'],
            registry=REGISTRY
        )
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, 
                           duration: float, request_size: int = None, response_size: int = None,
                           user_type: str = 'anonymous'):
        """
        Record HTTP request metrics with comprehensive tracking.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: Flask endpoint name or route pattern
            status_code: HTTP response status code
            duration: Request processing duration in seconds
            request_size: Size of request body in bytes
            response_size: Size of response body in bytes
            user_type: Type of user making request (authenticated, anonymous, service)
        """
        status_class = f"{status_code // 100}xx"
        
        # Record request counter
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code),
            user_type=user_type
        ).inc()
        
        # Record request duration
        self.http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint,
            status_class=status_class
        ).observe(duration)
        
        # Record request size if provided
        if request_size is not None:
            self.http_request_size_bytes.labels(
                method=method,
                endpoint=endpoint
            ).observe(request_size)
        
        # Record response size if provided
        if response_size is not None:
            self.http_response_size_bytes.labels(
                method=method,
                endpoint=endpoint,
                status_class=status_class
            ).observe(response_size)
        
        # Update request rate
        self.http_request_rate.observe(1.0)
    
    def record_database_operation(self, operation: str, collection: str, duration: float,
                                 status: str = 'success', connection_pool: str = 'default',
                                 result_count: int = None, index_used: bool = True):
        """
        Record database operation metrics with performance tracking.
        
        Args:
            operation: Database operation type (find, insert, update, delete, aggregate)
            collection: MongoDB collection name
            duration: Operation execution duration in seconds
            status: Operation status (success, error, timeout)
            connection_pool: Connection pool identifier
            result_count: Number of documents returned/affected
            index_used: Whether database index was used for the operation
        """
        # Record operation counter
        self.database_operations_total.labels(
            operation=operation,
            collection=collection,
            status=status,
            connection_pool=connection_pool
        ).inc()
        
        # Record operation duration
        self.database_operation_duration_seconds.labels(
            operation=operation,
            collection=collection,
            index_used='yes' if index_used else 'no'
        ).observe(duration)
        
        # Record query result size if provided
        if result_count is not None:
            self.database_query_result_size.labels(
                operation=operation,
                collection=collection
            ).observe(result_count)
    
    def record_external_service_request(self, service: str, operation: str, duration: float,
                                       status_code: int, endpoint: str = 'default',
                                       circuit_breaker_state: str = 'closed',
                                       timeout_occurred: bool = False,
                                       retry_count: int = 0):
        """
        Record external service request metrics with resilience tracking.
        
        Args:
            service: External service name (auth0, aws_s3, redis)
            operation: Service operation identifier
            duration: Request duration in seconds
            status_code: HTTP status code or equivalent
            endpoint: Specific endpoint or resource accessed
            circuit_breaker_state: Current circuit breaker state
            timeout_occurred: Whether request timed out
            retry_count: Number of retry attempts made
        """
        # Record service request counter
        self.external_service_requests_total.labels(
            service=service,
            operation=operation,
            status_code=str(status_code),
            circuit_breaker_state=circuit_breaker_state
        ).inc()
        
        # Record service request duration
        self.external_service_duration_seconds.labels(
            service=service,
            operation=operation,
            endpoint=endpoint
        ).observe(duration)
        
        # Record timeout if occurred
        if timeout_occurred:
            self.external_service_timeouts_total.labels(
                service=service,
                operation=operation
            ).inc()
        
        # Record retry attempts
        if retry_count > 0:
            for _ in range(retry_count):
                self.external_service_retries_total.labels(
                    service=service,
                    operation=operation,
                    retry_reason='timeout' if timeout_occurred else 'error'
                ).inc()
    
    def update_resource_utilization(self):
        """Update system resource utilization metrics."""
        try:
            # Get current process
            process = psutil.Process()
            
            # CPU utilization
            cpu_percent = process.cpu_percent(interval=None)
            self.cpu_utilization_percent.labels(process_type='main').set(cpu_percent)
            
            # Memory information
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            self.memory_usage_bytes.labels(memory_type='rss').set(memory_info.rss)
            self.memory_usage_bytes.labels(memory_type='vms').set(memory_info.vms)
            
            # Get shared memory if available
            if hasattr(memory_info, 'shared'):
                self.memory_usage_bytes.labels(memory_type='shared').set(memory_info.shared)
            
            # Memory utilization percentage
            self.memory_utilization_percent.labels(memory_type='total').set(memory_percent)
            
            # Python heap size estimation
            gc.collect()  # Force garbage collection for accurate measurement
            heap_size = sum(len(obj) if hasattr(obj, '__len__') else 1 for obj in gc.get_objects())
            self.memory_usage_bytes.labels(memory_type='heap').set(heap_size)
            
            # Disk I/O counters
            io_counters = process.io_counters()
            self.disk_io_bytes_total.labels(operation='read')._value._value = io_counters.read_bytes
            self.disk_io_bytes_total.labels(operation='write')._value._value = io_counters.write_bytes
            
            # Network I/O counters (system-wide)
            net_io = psutil.net_io_counters()
            if net_io:
                self.network_io_bytes_total.labels(direction='sent')._value._value = net_io.bytes_sent
                self.network_io_bytes_total.labels(direction='received')._value._value = net_io.bytes_recv
            
            # File descriptors
            try:
                num_fds = process.num_fds()
                self.file_descriptors_open.set(num_fds)
            except AttributeError:
                # Windows doesn't support num_fds
                pass
            
        except Exception as e:
            # Log error but don't fail metrics collection
            print(f"Error updating resource utilization metrics: {e}")
    
    def record_performance_variance(self, endpoint: str, metric_type: str, 
                                   flask_value: float, nodejs_baseline: float):
        """
        Record performance variance against Node.js baseline (critical ≤10% requirement).
        
        Args:
            endpoint: API endpoint identifier
            metric_type: Type of metric being compared (response_time, memory_usage, cpu_usage)
            flask_value: Current Flask implementation metric value
            nodejs_baseline: Node.js baseline metric value for comparison
        """
        if nodejs_baseline == 0:
            variance_percent = 0.0
        else:
            variance_percent = ((flask_value - nodejs_baseline) / nodejs_baseline) * 100
        
        variance_direction = 'positive' if variance_percent >= 0 else 'negative'
        
        # Record performance variance gauge
        self.performance_variance_percent.labels(
            endpoint=endpoint,
            metric_type=metric_type,
            variance_direction=variance_direction
        ).set(variance_percent)
        
        # Check for performance regression (>10% variance)
        if abs(variance_percent) > 10.0:
            severity = 'critical' if abs(variance_percent) > 20.0 else 'warning'
            
            self.performance_regressions_total.labels(
                endpoint=endpoint,
                regression_type=metric_type,
                severity=severity
            ).inc()
        
        # Update migration baseline compliance
        compliance_score = max(0.0, 1.0 - (abs(variance_percent) / 100.0))
        self.migration_baseline_compliance.labels(
            compliance_category='performance'
        ).set(compliance_score)
    
    def record_endpoint_comparison(self, endpoint: str, implementation: str, 
                                  response_time: float, percentile: str = 'p50'):
        """
        Record endpoint response time for Node.js baseline comparison.
        
        Args:
            endpoint: API endpoint identifier
            implementation: Implementation type (nodejs, flask)
            response_time: Response time in seconds
            percentile: Percentile category (p50, p95, p99)
        """
        self.endpoint_response_time_comparison_seconds.labels(
            endpoint=endpoint,
            implementation=implementation,
            percentile=percentile
        ).observe(response_time)
        
        # Increment corresponding request counter
        if implementation == 'nodejs':
            self.nodejs_baseline_requests_total.labels(
                endpoint=endpoint,
                status_code='200'  # Assume success for baseline
            ).inc()
        else:
            self.flask_migration_requests_total.labels(
                endpoint=endpoint,
                status_code='200'  # Will be updated with actual status
            ).inc()
    
    def record_business_logic_operation(self, operation: str, module: str, duration: float,
                                      status: str = 'success', complexity: str = 'moderate',
                                      optimization_level: str = 'baseline'):
        """
        Record business logic operation metrics for throughput analysis.
        
        Args:
            operation: Business operation identifier
            module: Business module name
            duration: Operation execution duration in seconds
            status: Operation status (success, error, skipped)
            complexity: Operation complexity level (simple, moderate, complex)
            optimization_level: Optimization level applied (baseline, optimized, cached)
        """
        # Record operation counter
        self.business_logic_operations_total.labels(
            operation=operation,
            module=module,
            status=status,
            complexity=complexity
        ).inc()
        
        # Record operation duration
        self.business_logic_duration_seconds.labels(
            operation=operation,
            module=module,
            optimization_level=optimization_level
        ).observe(duration)
    
    def record_cache_hit(self, cache_type: str, operation: str, hit: bool = True):
        """
        Record cache hit/miss for optimization tracking.
        
        Args:
            cache_type: Type of cache (memory, redis, database)
            operation: Operation that accessed cache
            hit: Whether cache hit (True) or miss (False) occurred
        """
        if hit:
            self.business_logic_cache_hits_total.labels(
                cache_type=cache_type,
                operation=operation
            ).inc()
        else:
            self.business_logic_cache_misses_total.labels(
                cache_type=cache_type,
                operation=operation
            ).inc()
    
    def update_wsgi_worker_metrics(self, worker_id: str = None, worker_type: str = 'sync',
                                  utilization: float = None, queue_depth: int = None,
                                  requests_per_second: float = None):
        """
        Update WSGI worker performance metrics.
        
        Args:
            worker_id: Worker process identifier
            worker_type: Worker type (sync, async)
            utilization: Worker utilization percentage (0-100)
            queue_depth: Current request queue depth
            requests_per_second: Requests processed per second by worker
        """
        if worker_id and utilization is not None:
            self.wsgi_worker_utilization_percent.labels(
                worker_id=worker_id,
                worker_type=worker_type
            ).set(utilization)
        
        if queue_depth is not None:
            self.wsgi_request_queue_depth.set(queue_depth)
        
        if worker_id and requests_per_second is not None:
            self.wsgi_worker_requests_per_second.labels(
                worker_id=worker_id
            ).set(requests_per_second)
    
    def record_circuit_breaker_event(self, service: str, operation: str, 
                                    state: str, event_type: str = 'state_change',
                                    failure_type: str = None):
        """
        Record circuit breaker state and events.
        
        Args:
            service: External service name
            operation: Service operation
            state: Current circuit breaker state (closed, open, half_open)
            event_type: Type of event (state_change, failure, recovery_attempt)
            failure_type: Type of failure if applicable (timeout, error, threshold_exceeded)
        """
        # Map state to numeric value
        state_values = {'closed': 0, 'open': 1, 'half_open': 2}
        state_value = state_values.get(state, 0)
        
        self.circuit_breaker_state.labels(
            service=service,
            operation=operation
        ).set(state_value)
        
        if event_type == 'failure' and failure_type:
            self.circuit_breaker_failures_total.labels(
                service=service,
                operation=operation,
                failure_type=failure_type
            ).inc()
    
    def record_gc_event(self, generation: int, pause_time: float, 
                       objects_collected: int = None, memory_recovered: int = None,
                       collection_type: str = 'incremental'):
        """
        Record garbage collection event metrics.
        
        Args:
            generation: GC generation (0, 1, 2)
            pause_time: GC pause time in seconds
            objects_collected: Number of objects collected
            memory_recovered: Memory recovered in bytes
            collection_type: Collection type (incremental, full)
        """
        generation_str = str(generation)
        
        # Record GC collection
        self.gc_collections_total.labels(generation=generation_str).inc()
        
        # Record pause time
        self.gc_pause_time_seconds.labels(
            generation=generation_str,
            collection_type=collection_type
        ).observe(pause_time)
        
        # Record memory recovered if provided
        if memory_recovered is not None:
            self.gc_memory_recovered_bytes.labels(
                generation=generation_str
            ).observe(memory_recovered)
        
        # Update GC efficiency if data available
        if objects_collected is not None and objects_collected > 0:
            # This is a simplified efficiency calculation
            efficiency_ratio = min(1.0, objects_collected / 1000.0)  # Normalized example
            self.gc_efficiency_ratio.labels(generation=generation_str).set(efficiency_ratio)
    
    def get_metrics_registry(self) -> CollectorRegistry:
        """
        Get the Prometheus metrics registry.
        
        Returns:
            CollectorRegistry: The metrics registry instance
        """
        if self.config.PROMETHEUS_MULTIPROC_DIR:
            # Create new registry for multiprocess collection
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            return registry
        else:
            return REGISTRY
    
    def generate_metrics_output(self) -> str:
        """
        Generate Prometheus metrics output in text format.
        
        Returns:
            str: Prometheus metrics in text exposition format
        """
        # Update resource metrics before generating output
        self.update_resource_utilization()
        
        # Get appropriate registry
        registry = self.get_metrics_registry()
        
        # Generate metrics output
        return generate_latest(registry)


class MetricsMiddleware:
    """
    Flask middleware for automatic HTTP request metrics collection with comprehensive
    performance tracking and Node.js baseline comparison integration.
    """
    
    def __init__(self, metrics_collector: PrometheusMetricsCollector):
        """
        Initialize metrics middleware.
        
        Args:
            metrics_collector: PrometheusMetricsCollector instance
        """
        self.metrics = metrics_collector
    
    def init_app(self, app: Flask):
        """
        Initialize middleware with Flask application.
        
        Args:
            app: Flask application instance
        """
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_appcontext(self._teardown_request)
    
    def _before_request(self):
        """Pre-request metrics collection setup."""
        # Store request start time
        g.metrics_start_time = time.perf_counter()
        
        # Increment active requests counter
        self.metrics.http_requests_active.inc()
        
        # Store request size if available
        g.metrics_request_size = request.content_length or 0
    
    def _after_request(self, response: Response) -> Response:
        """Post-request metrics collection and recording."""
        if hasattr(g, 'metrics_start_time'):
            # Calculate request duration
            duration = time.perf_counter() - g.metrics_start_time
            
            # Get request information
            method = request.method
            endpoint = request.endpoint or 'unknown'
            status_code = response.status_code
            request_size = getattr(g, 'metrics_request_size', 0)
            response_size = response.content_length or 0
            
            # Determine user type
            user_type = 'authenticated' if hasattr(g, 'current_user') else 'anonymous'
            
            # Record HTTP request metrics
            self.metrics.record_http_request(
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                duration=duration,
                request_size=request_size,
                response_size=response_size,
                user_type=user_type
            )
            
            # Record endpoint comparison for migration tracking
            self.metrics.record_endpoint_comparison(
                endpoint=endpoint,
                implementation='flask',
                response_time=duration
            )
            
            # Check for performance variance if baseline available
            if hasattr(g, 'nodejs_baseline_time'):
                self.metrics.record_performance_variance(
                    endpoint=endpoint,
                    metric_type='response_time',
                    flask_value=duration,
                    nodejs_baseline=g.nodejs_baseline_time
                )
        
        return response
    
    def _teardown_request(self, exception=None):
        """Request teardown metrics cleanup."""
        # Decrement active requests counter
        self.metrics.http_requests_active.dec()


def create_metrics_endpoint(app: Flask, metrics_collector: PrometheusMetricsCollector, 
                          endpoint_path: str = '/metrics'):
    """
    Create Prometheus metrics endpoint for monitoring system integration.
    
    Args:
        app: Flask application instance
        metrics_collector: PrometheusMetricsCollector instance
        endpoint_path: URL path for metrics endpoint (default: /metrics)
    """
    @app.route(endpoint_path, methods=['GET'])
    def prometheus_metrics():
        """
        Prometheus metrics endpoint for monitoring system integration.
        
        Returns:
            Response: Prometheus metrics in text exposition format with appropriate headers
        """
        try:
            # Generate metrics output
            metrics_output = metrics_collector.generate_metrics_output()
            
            # Return metrics with appropriate content type
            return Response(
                metrics_output,
                mimetype=CONTENT_TYPE_LATEST,
                status=200
            )
            
        except Exception as e:
            # Log error and return error response
            error_message = f"Error generating Prometheus metrics: {str(e)}"
            return Response(
                error_message,
                mimetype='text/plain',
                status=500
            )


def setup_metrics_collection(app: Flask, config: MonitoringConfig = None) -> PrometheusMetricsCollector:
    """
    Setup comprehensive Prometheus metrics collection for Flask application.
    
    This function initializes enterprise-grade metrics collection including:
    - HTTP request/response performance tracking
    - Database operation monitoring
    - External service integration metrics
    - System resource utilization tracking
    - Custom migration performance comparison
    - Business logic throughput analysis
    - WSGI server instrumentation
    - Garbage collection monitoring
    
    Args:
        app: Flask application instance
        config: MonitoringConfig instance with enterprise settings
        
    Returns:
        PrometheusMetricsCollector: Configured metrics collector instance
    """
    # Initialize configuration
    if config is None:
        config = MonitoringConfig()
    
    # Create metrics collector
    metrics_collector = PrometheusMetricsCollector(config)
    
    # Setup metrics middleware
    metrics_middleware = MetricsMiddleware(metrics_collector)
    metrics_middleware.init_app(app)
    
    # Create metrics endpoint
    create_metrics_endpoint(app, metrics_collector, config.PROMETHEUS_METRICS_PATH)
    
    # Store metrics collector in app config for access by other components
    app.config['PROMETHEUS_METRICS'] = metrics_collector
    
    # Setup periodic resource metrics updates
    if config.PERFORMANCE_MONITORING_ENABLED:
        import threading
        import time
        
        def update_resource_metrics():
            """Background thread for periodic resource metrics updates."""
            while True:
                try:
                    metrics_collector.update_resource_utilization()
                    time.sleep(15)  # Update every 15 seconds
                except Exception as e:
                    print(f"Error in resource metrics update: {e}")
                    time.sleep(60)  # Wait longer on error
        
        # Start background thread for resource monitoring
        resource_thread = threading.Thread(target=update_resource_metrics, daemon=True)
        resource_thread.start()
    
    return metrics_collector


# Performance monitoring decorators for business logic instrumentation
def monitor_performance(endpoint: str = None, nodejs_baseline: float = None):
    """
    Decorator for monitoring business logic performance with Node.js baseline comparison.
    
    Args:
        endpoint: Endpoint identifier for metrics labeling
        nodejs_baseline: Node.js baseline response time for variance calculation
        
    Returns:
        Callable: Decorated function with performance monitoring
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
                
                # Get metrics collector from Flask app config
                if hasattr(g, 'app') and 'PROMETHEUS_METRICS' in g.app.config:
                    metrics = g.app.config['PROMETHEUS_METRICS']
                    
                    # Record business logic operation
                    metrics.record_business_logic_operation(
                        operation=endpoint or func.__name__,
                        module=func.__module__ or 'unknown',
                        duration=duration,
                        status=status
                    )
                    
                    # Store baseline time for request monitoring if provided
                    if nodejs_baseline:
                        g.nodejs_baseline_time = nodejs_baseline
            
            return result
        return wrapper
    return decorator


def monitor_database_operation(operation: str, collection: str):
    """
    Decorator for monitoring database operations with performance tracking.
    
    Args:
        operation: Database operation type (find, insert, update, delete)
        collection: MongoDB collection name
        
    Returns:
        Callable: Decorated function with database monitoring
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                status = 'success'
                
                # Try to extract result count from result
                result_count = None
                if hasattr(result, 'count'):
                    result_count = result.count()
                elif isinstance(result, (list, tuple)):
                    result_count = len(result)
                
            except Exception as e:
                status = 'error'
                result_count = None
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Get metrics collector from Flask app config
                if hasattr(g, 'app') and 'PROMETHEUS_METRICS' in g.app.config:
                    metrics = g.app.config['PROMETHEUS_METRICS']
                    
                    # Record database operation
                    metrics.record_database_operation(
                        operation=operation,
                        collection=collection,
                        duration=duration,
                        status=status,
                        result_count=result_count
                    )
            
            return result
        return wrapper
    return decorator


def monitor_external_service(service: str, operation: str):
    """
    Decorator for monitoring external service calls with circuit breaker integration.
    
    Args:
        service: External service name (auth0, aws_s3, redis)
        operation: Service operation identifier
        
    Returns:
        Callable: Decorated function with external service monitoring
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            status_code = 200
            timeout_occurred = False
            retry_count = 0
            
            try:
                result = func(*args, **kwargs)
                
                # Extract status code from result if available
                if hasattr(result, 'status_code'):
                    status_code = result.status_code
                elif hasattr(result, 'status'):
                    status_code = result.status
                
                # Extract retry information if available
                if hasattr(result, 'retry_count'):
                    retry_count = result.retry_count
                
            except TimeoutError:
                status_code = 408
                timeout_occurred = True
                raise
            except Exception as e:
                status_code = 500
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Get metrics collector from Flask app config
                if hasattr(g, 'app') and 'PROMETHEUS_METRICS' in g.app.config:
                    metrics = g.app.config['PROMETHEUS_METRICS']
                    
                    # Record external service request
                    metrics.record_external_service_request(
                        service=service,
                        operation=operation,
                        duration=duration,
                        status_code=status_code,
                        timeout_occurred=timeout_occurred,
                        retry_count=retry_count
                    )
            
            return result
        return wrapper
    return decorator


def monitor_cache_operation(cache_type: str, operation: str):
    """
    Decorator for monitoring cache operations with hit/miss tracking.
    
    Args:
        cache_type: Type of cache (memory, redis, database)
        operation: Cache operation identifier
        
    Returns:
        Callable: Decorated function with cache monitoring
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                
                # Determine if cache hit or miss occurred
                cache_hit = result is not None and result != False
                
                # Get metrics collector from Flask app config
                if hasattr(g, 'app') and 'PROMETHEUS_METRICS' in g.app.config:
                    metrics = g.app.config['PROMETHEUS_METRICS']
                    
                    # Record cache hit/miss
                    metrics.record_cache_hit(
                        cache_type=cache_type,
                        operation=operation,
                        hit=cache_hit
                    )
                
                return result
            
            except Exception as e:
                # Record cache miss on exception
                if hasattr(g, 'app') and 'PROMETHEUS_METRICS' in g.app.config:
                    metrics = g.app.config['PROMETHEUS_METRICS']
                    metrics.record_cache_hit(
                        cache_type=cache_type,
                        operation=operation,
                        hit=False
                    )
                raise
        
        return wrapper
    return decorator


# Export monitoring components for application integration
__all__ = [
    'PrometheusMetricsCollector',
    'MetricsMiddleware',
    'setup_metrics_collection',
    'create_metrics_endpoint',
    'monitor_performance',
    'monitor_database_operation',
    'monitor_external_service',
    'monitor_cache_operation',
]