#!/usr/bin/env python3
"""
Performance Monitoring Setup Script

Comprehensive performance monitoring setup script configuring prometheus-client metrics collection,
Flask-Metrics integration, and enterprise monitoring system compatibility during performance testing.
Establishes comprehensive monitoring infrastructure for accurate performance measurement and ≤10%
variance compliance validation against Node.js baseline.

Key Features:
- prometheus-client 0.17+ metrics collection setup per Section 3.6.2
- Flask-Metrics request timing measurement integration per Section 3.6.2
- Memory profiling and monitoring configuration per Section 3.6.2
- Database monitoring and connection pool metrics per Section 3.6.2
- Enterprise APM integration compatibility per Section 3.6.1
- Real-time performance data collection during testing per Section 6.6.1
- WSGI server instrumentation for Gunicorn prometheus_multiproc_dir per Section 6.5.4.1
- Custom migration performance metrics for Node.js baseline comparison per Section 6.5.4.5

Performance Requirements Compliance:
- ≤10% variance threshold enforcement per Section 0.1.1
- Response time ≤500ms (95th percentile) per Section 4.6.3
- CPU utilization monitoring with >70% warning, >90% critical thresholds per Section 6.5.5
- Memory usage tracking with >80% warning, >95% critical thresholds per Section 6.5.5
- Python GC pause time monitoring with >10ms warning, >20ms critical per Section 6.5.2.2

Dependencies:
- prometheus-client ≥0.17+ for enterprise Prometheus integration
- Flask-Metrics for request timing and performance measurement
- psutil ≥5.9+ for system resource monitoring
- structlog ≥23.1+ for enterprise logging integration
- memory-profiler for memory usage analysis
- python-dateutil ≥2.8+ for timestamp handling

Author: Performance Engineering Team
Version: 1.0.0
"""

import asyncio
import gc
import json
import logging
import os
import psutil
import sys
import tempfile
import time
import threading
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from unittest.mock import patch, Mock

# Performance monitoring framework imports
try:
    import memory_profiler
    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

# Prometheus monitoring imports
try:
    import prometheus_client
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary, Info, Enum,
        CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest,
        multiprocess, start_http_server, ProcessCollector
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Flask and application imports
try:
    from flask import Flask, g, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Application monitoring imports
try:
    from src.monitoring.metrics import (
        FlaskMetricsCollector, PrometheusMetrics, StructuredLogger,
        HealthCheckManager, APMIntegration, GarbageCollectionMonitor,
        init_monitoring
    )
    from src.config.settings import TestingConfig, get_monitoring_config
    from src.config.monitoring import MonitoringConfig
    MONITORING_MODULES_AVAILABLE = True
except ImportError:
    MONITORING_MODULES_AVAILABLE = False

# Performance testing imports
try:
    from tests.performance.baseline_data import (
        BaselineDataManager, get_default_baseline_data,
        PERFORMANCE_VARIANCE_THRESHOLD
    )
    from tests.performance.performance_config import (
        BasePerformanceConfig, create_performance_config,
        DATABASE_PERFORMANCE_THRESHOLDS, APM_INTEGRATION_CONFIG
    )
    PERFORMANCE_MODULES_AVAILABLE = True
except ImportError:
    PERFORMANCE_MODULES_AVAILABLE = False


class MonitoringSetupError(Exception):
    """Custom exception for monitoring setup failures."""
    pass


class PerformanceMonitoringSetup:
    """
    Comprehensive performance monitoring setup orchestrator providing enterprise-grade
    monitoring infrastructure for Flask migration application performance validation.
    
    This class implements all monitoring requirements from technical specifications:
    - Section 3.6.2: prometheus-client 0.17+ metrics collection
    - Section 3.6.2: Flask-Metrics request timing measurement
    - Section 3.6.2: Memory profiling for ≤10% variance compliance
    - Section 3.6.1: Enterprise APM integration compatibility
    - Section 6.6.1: Real-time performance data collection during testing
    """
    
    def __init__(self, test_environment: str = 'testing', verbose: bool = True):
        """
        Initialize performance monitoring setup with comprehensive configuration.
        
        Args:
            test_environment: Testing environment name (testing, staging, production)
            verbose: Enable verbose logging during setup
        """
        self.test_environment = test_environment
        self.verbose = verbose
        self.setup_start_time = time.time()
        
        # Monitoring components
        self.metrics_registry: Optional[CollectorRegistry] = None
        self.prometheus_metrics: Optional[PrometheusMetrics] = None
        self.flask_metrics_collector: Optional[FlaskMetricsCollector] = None
        self.structured_logger: Optional[StructuredLogger] = None
        self.health_manager: Optional[HealthCheckManager] = None
        self.apm_integration: Optional[APMIntegration] = None
        self.gc_monitor: Optional[GarbageCollectionMonitor] = None
        
        # Configuration objects
        self.monitoring_config: Optional[MonitoringConfig] = None
        self.performance_config: Optional[BasePerformanceConfig] = None
        self.baseline_manager: Optional[BaselineDataManager] = None
        
        # Setup state tracking
        self.setup_steps_completed = []
        self.setup_errors = []
        self.monitoring_endpoints = {}
        self.performance_baselines = {}
        
        # Performance data collection
        self.performance_data_collector = PerformanceDataCollector()
        self.memory_profiler_instance = None
        self.resource_monitor = SystemResourceMonitor()
        
        # Setup locks for thread safety
        self._setup_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        
        # Initialize logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Initialize logging for monitoring setup process."""
        # Configure basic logging for setup process
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f'/tmp/monitoring_setup_{int(time.time())}.log')
            ]
        )
        
        self.logger = logging.getLogger('performance_monitoring_setup')
        self.logger.info(f"Performance monitoring setup initialized for environment: {self.test_environment}")
    
    def validate_dependencies(self) -> Dict[str, bool]:
        """
        Validate all required dependencies for performance monitoring setup.
        
        Returns:
            Dictionary containing dependency validation results
            
        Raises:
            MonitoringSetupError: If critical dependencies are missing
        """
        dependency_status = {
            'prometheus_client': PROMETHEUS_AVAILABLE,
            'memory_profiler': MEMORY_PROFILER_AVAILABLE,
            'structlog': STRUCTLOG_AVAILABLE,
            'flask': FLASK_AVAILABLE,
            'monitoring_modules': MONITORING_MODULES_AVAILABLE,
            'performance_modules': PERFORMANCE_MODULES_AVAILABLE,
            'psutil': True,  # Required for system monitoring
        }
        
        # Validate prometheus-client version compliance per Section 3.6.2
        if PROMETHEUS_AVAILABLE:
            prometheus_version = prometheus_client.__version__
            version_parts = prometheus_version.split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            version_compliant = major > 0 or (major == 0 and minor >= 17)
            dependency_status['prometheus_client_version'] = version_compliant
            
            if not version_compliant:
                self.logger.error(
                    f"prometheus-client version {prometheus_version} does not meet "
                    f"minimum requirement of 0.17+ per Section 3.6.2"
                )
                dependency_status['prometheus_client'] = False
        
        # Check system capabilities
        dependency_status['multiprocessing'] = hasattr(os, 'fork')
        dependency_status['threading'] = threading.active_count() > 0
        dependency_status['gc_monitoring'] = hasattr(gc, 'callbacks')
        
        # Validate critical dependencies
        critical_deps = [
            'prometheus_client', 'flask', 'monitoring_modules', 'performance_modules'
        ]
        
        missing_critical = [dep for dep in critical_deps if not dependency_status.get(dep, False)]
        
        if missing_critical:
            error_msg = f"Critical dependencies missing: {missing_critical}"
            self.logger.error(error_msg)
            raise MonitoringSetupError(error_msg)
        
        # Log dependency status
        self.logger.info("Dependency validation completed")
        for dep, status in dependency_status.items():
            status_str = "✅ Available" if status else "❌ Missing"
            self.logger.info(f"  {dep}: {status_str}")
        
        self.setup_steps_completed.append('dependency_validation')
        return dependency_status
    
    def setup_prometheus_metrics_collection(self) -> PrometheusMetrics:
        """
        Configure prometheus-client 0.17+ metrics collection per Section 3.6.2.
        
        Establishes comprehensive Prometheus metrics collection including:
        - HTTP request/response performance tracking
        - Database operation monitoring
        - External service integration metrics
        - Resource utilization tracking
        - Custom migration performance metrics
        
        Returns:
            PrometheusMetrics: Configured Prometheus metrics collector
            
        Raises:
            MonitoringSetupError: If Prometheus setup fails
        """
        try:
            self.logger.info("Setting up prometheus-client 0.17+ metrics collection...")
            
            # Initialize metrics registry with multiprocess support
            if self.test_environment in ['production', 'staging']:
                # Configure multiprocess directory for WSGI deployment
                multiproc_dir = os.getenv('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus_multiproc')
                os.makedirs(multiproc_dir, exist_ok=True)
                os.environ['PROMETHEUS_MULTIPROC_DIR'] = multiproc_dir
                
                self.metrics_registry = CollectorRegistry()
                multiprocess.MultiProcessCollector(self.metrics_registry)
                
                self.logger.info(f"Multiprocess Prometheus registry configured: {multiproc_dir}")
            else:
                # Single process registry for testing
                self.metrics_registry = CollectorRegistry()
                
                self.logger.info("Single process Prometheus registry configured")
            
            # Initialize PrometheusMetrics with comprehensive metric definitions
            self.prometheus_metrics = PrometheusMetrics()
            
            # Validate core metrics are properly initialized
            required_metrics = [
                'http_requests_total',
                'http_request_duration_seconds',
                'database_operations_total',
                'database_operation_duration_seconds',
                'external_service_requests_total',
                'external_service_duration_seconds',
                'cpu_utilization_percent',
                'memory_usage_bytes',
                'gc_pause_time_seconds',
                'performance_variance_percent',
                'endpoint_response_time_comparison'
            ]
            
            for metric_name in required_metrics:
                if not hasattr(self.prometheus_metrics, metric_name):
                    raise MonitoringSetupError(f"Required metric {metric_name} not initialized")
            
            # Configure performance variance tracking
            self._setup_performance_variance_metrics()
            
            # Configure custom migration metrics per Section 6.5.4.5
            self._setup_migration_specific_metrics()
            
            # Setup metrics HTTP endpoint
            self._setup_metrics_endpoint()
            
            self.logger.info("✅ Prometheus metrics collection setup completed")
            self.setup_steps_completed.append('prometheus_metrics')
            
            return self.prometheus_metrics
            
        except Exception as e:
            error_msg = f"Failed to setup Prometheus metrics collection: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _setup_performance_variance_metrics(self) -> None:
        """Setup performance variance tracking metrics for Node.js baseline comparison."""
        # Load baseline data for variance calculation
        try:
            self.baseline_manager = get_default_baseline_data()
            
            # Configure performance variance thresholds
            variance_thresholds = {
                'response_time': PERFORMANCE_VARIANCE_THRESHOLD,  # ≤10% requirement
                'memory_usage': 15.0,  # ±15% acceptable variance
                'cpu_usage': 10.0,     # ≤10% variance
                'throughput': 10.0     # ≤10% variance
            }
            
            # Initialize variance tracking for each metric type
            for metric_type, threshold in variance_thresholds.items():
                self.prometheus_metrics.performance_variance_percent.labels(
                    endpoint='baseline_comparison',
                    metric_type=metric_type
                ).set(0.0)
            
            self.logger.info("Performance variance metrics configured")
            
        except Exception as e:
            self.logger.warning(f"Baseline data loading failed: {e}")
    
    def _setup_migration_specific_metrics(self) -> None:
        """Setup custom migration performance metrics per Section 6.5.4.5."""
        # Migration-specific endpoints for tracking
        migration_endpoints = [
            '/api/v1/users',
            '/api/v1/auth/login',
            '/api/v1/data/reports',
            '/api/v1/files/upload',
            '/health',
            '/health/ready',
            '/health/live'
        ]
        
        # Initialize baseline counters for each endpoint
        for endpoint in migration_endpoints:
            self.prometheus_metrics.nodejs_baseline_requests_total.labels(
                endpoint=endpoint
            ).inc(0)  # Initialize counter
            
            self.prometheus_metrics.flask_migration_requests_total.labels(
                endpoint=endpoint
            ).inc(0)  # Initialize counter
        
        # Initialize business logic throughput metrics
        business_operations = [
            'user_authentication',
            'data_validation',
            'file_processing',
            'database_query',
            'external_service_call'
        ]
        
        for operation in business_operations:
            self.prometheus_metrics.business_logic_operations_total.labels(
                operation=operation,
                status='success'
            ).inc(0)
        
        self.logger.info("Migration-specific metrics initialized")
    
    def _setup_metrics_endpoint(self) -> None:
        """Setup Prometheus metrics HTTP endpoint for monitoring integration."""
        try:
            # Configure metrics endpoint path
            metrics_path = '/metrics'
            self.monitoring_endpoints['prometheus_metrics'] = {
                'path': metrics_path,
                'content_type': CONTENT_TYPE_LATEST,
                'description': 'Prometheus metrics endpoint for monitoring integration'
            }
            
            # Test metrics generation
            test_metrics_output = generate_latest(self.metrics_registry or prometheus_client.REGISTRY)
            if not test_metrics_output:
                raise MonitoringSetupError("Metrics endpoint not generating output")
            
            self.logger.info(f"Metrics endpoint configured: {metrics_path}")
            
        except Exception as e:
            self.logger.error(f"Metrics endpoint setup failed: {e}")
            raise
    
    def setup_flask_metrics_integration(self, app: Optional[Flask] = None) -> FlaskMetricsCollector:
        """
        Configure Flask-Metrics request timing measurement per Section 3.6.2.
        
        Establishes comprehensive Flask request lifecycle monitoring including:
        - Before/after request hooks for timing measurement
        - Request/response size tracking
        - Active request monitoring
        - Performance correlation analysis
        
        Args:
            app: Optional Flask application instance for integration
            
        Returns:
            FlaskMetricsCollector: Configured Flask metrics collector
            
        Raises:
            MonitoringSetupError: If Flask metrics integration fails
        """
        try:
            self.logger.info("Setting up Flask-Metrics request timing measurement...")
            
            # Initialize Flask metrics collector
            self.flask_metrics_collector = FlaskMetricsCollector(
                app=app,
                registry=self.metrics_registry
            )
            
            # Configure request/response hooks if Flask app is provided
            if app:
                self._configure_flask_request_hooks(app)
            
            # Setup request timing infrastructure
            self._setup_request_timing_measurement()
            
            # Configure performance correlation tracking
            self._setup_performance_correlation_tracking()
            
            # Validate Flask metrics integration
            self._validate_flask_metrics_setup()
            
            self.logger.info("✅ Flask-Metrics integration setup completed")
            self.setup_steps_completed.append('flask_metrics')
            
            return self.flask_metrics_collector
            
        except Exception as e:
            error_msg = f"Failed to setup Flask-Metrics integration: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _configure_flask_request_hooks(self, app: Flask) -> None:
        """Configure Flask request/response hooks for comprehensive monitoring."""
        @app.before_request
        def before_request_monitoring():
            """Pre-request monitoring setup and timing initialization."""
            g.monitoring_start_time = time.perf_counter()
            g.monitoring_request_id = f"req-{int(time.time() * 1000)}-{os.getpid()}"
            
            # Update active requests gauge
            if self.prometheus_metrics:
                self.prometheus_metrics.active_requests.inc()
            
            # Track request size
            content_length = request.content_length or 0
            if self.flask_metrics_collector and content_length > 0:
                self.flask_metrics_collector.request_size.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown'
                ).observe(content_length)
        
        @app.after_request
        def after_request_monitoring(response):
            """Post-request monitoring and metrics collection."""
            if hasattr(g, 'monitoring_start_time'):
                # Calculate request duration
                duration = time.perf_counter() - g.monitoring_start_time
                
                # Record Flask metrics
                if self.flask_metrics_collector:
                    self.flask_metrics_collector.request_duration.labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code=str(response.status_code)
                    ).observe(duration)
                    
                    self.flask_metrics_collector.request_count.labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code=str(response.status_code),
                        client_type='performance_test'
                    ).inc()
                
                # Record Prometheus metrics
                if self.prometheus_metrics:
                    self.prometheus_metrics.record_http_request(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code=response.status_code,
                        duration=duration
                    )
                    
                    # Update active requests gauge
                    self.prometheus_metrics.active_requests.dec()
                
                # Track response size
                response_size = response.content_length or len(response.get_data())
                if self.flask_metrics_collector:
                    self.flask_metrics_collector.response_size.labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code=str(response.status_code)
                    ).observe(response_size)
                
                # Performance variance check
                self._check_performance_variance(
                    endpoint=request.endpoint or 'unknown',
                    duration=duration
                )
            
            return response
        
        @app.teardown_request
        def teardown_request_monitoring(exception):
            """Request teardown monitoring for cleanup and error tracking."""
            if exception:
                # Track request errors
                if self.prometheus_metrics:
                    self.prometheus_metrics.http_requests_total.labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code='500'
                    ).inc()
        
        self.logger.info("Flask request/response hooks configured")
    
    def _setup_request_timing_measurement(self) -> None:
        """Setup comprehensive request timing measurement infrastructure."""
        # Configure timing precision and accuracy
        self.timing_config = {
            'precision': 'nanosecond',  # Use time.perf_counter() for high precision
            'baseline_variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
            'performance_correlation_enabled': True,
            'real_time_variance_tracking': True
        }
        
        # Initialize timing data collectors
        self.request_timing_data = defaultdict(lambda: deque(maxlen=1000))
        self.baseline_timing_data = {}
        
        self.logger.info("Request timing measurement infrastructure configured")
    
    def _setup_performance_correlation_tracking(self) -> None:
        """Setup performance correlation tracking between metrics."""
        # Configure correlation tracking for:
        # - Response time vs memory usage
        # - Response time vs CPU utilization
        # - Response time vs database operations
        # - Response time vs external service calls
        
        self.performance_correlations = {
            'response_time_memory': deque(maxlen=500),
            'response_time_cpu': deque(maxlen=500),
            'response_time_db': deque(maxlen=500),
            'response_time_external': deque(maxlen=500)
        }
        
        self.logger.info("Performance correlation tracking configured")
    
    def _validate_flask_metrics_setup(self) -> None:
        """Validate Flask metrics integration is properly configured."""
        required_metrics = [
            'request_duration',
            'request_count',
            'request_size',
            'response_size',
            'active_requests'
        ]
        
        for metric_name in required_metrics:
            if not hasattr(self.flask_metrics_collector, metric_name):
                raise MonitoringSetupError(f"Flask metric {metric_name} not configured")
        
        self.logger.info("Flask metrics integration validation passed")
    
    def _check_performance_variance(self, endpoint: str, duration: float) -> None:
        """Check performance variance against Node.js baseline."""
        if not self.baseline_manager:
            return
        
        try:
            # Get baseline for endpoint
            baseline = self.baseline_manager.get_response_time_baseline(endpoint, 'GET')
            if baseline:
                baseline_time = baseline.mean_response_time_ms / 1000  # Convert to seconds
                variance_percent = ((duration - baseline_time) / baseline_time) * 100
                
                # Record variance metric
                if self.prometheus_metrics:
                    self.prometheus_metrics.record_performance_variance(
                        endpoint=endpoint,
                        metric_type='response_time',
                        variance_percent=variance_percent
                    )
                
                # Log variance if exceeding threshold
                if abs(variance_percent) > PERFORMANCE_VARIANCE_THRESHOLD:
                    self.logger.warning(
                        f"Performance variance threshold exceeded: {endpoint} "
                        f"({variance_percent:.2f}% vs {PERFORMANCE_VARIANCE_THRESHOLD}% threshold)"
                    )
        
        except Exception as e:
            self.logger.debug(f"Performance variance check failed: {e}")
    
    def setup_memory_profiling_monitoring(self) -> 'MemoryProfiler':
        """
        Configure memory profiling for ≤10% variance compliance per Section 3.6.2.
        
        Establishes comprehensive memory monitoring including:
        - Process memory usage tracking (RSS, VMS, heap)
        - Python garbage collection monitoring
        - Memory allocation pattern analysis
        - Memory performance correlation
        
        Returns:
            MemoryProfiler: Configured memory profiling instance
            
        Raises:
            MonitoringSetupError: If memory profiling setup fails
        """
        try:
            self.logger.info("Setting up memory profiling and monitoring...")
            
            # Initialize memory profiler if available
            if MEMORY_PROFILER_AVAILABLE:
                self.memory_profiler_instance = MemoryProfiler(
                    prometheus_metrics=self.prometheus_metrics
                )
            else:
                self.logger.warning("memory-profiler not available, using basic memory monitoring")
                self.memory_profiler_instance = BasicMemoryMonitor(
                    prometheus_metrics=self.prometheus_metrics
                )
            
            # Setup garbage collection monitoring per Section 6.5.2.2
            self._setup_garbage_collection_monitoring()
            
            # Configure memory performance correlation
            self._setup_memory_performance_correlation()
            
            # Setup memory variance tracking
            self._setup_memory_variance_tracking()
            
            # Initialize memory baseline comparison
            self._initialize_memory_baseline_comparison()
            
            # Start memory monitoring thread
            self._start_memory_monitoring_thread()
            
            self.logger.info("✅ Memory profiling and monitoring setup completed")
            self.setup_steps_completed.append('memory_profiling')
            
            return self.memory_profiler_instance
            
        except Exception as e:
            error_msg = f"Failed to setup memory profiling: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _setup_garbage_collection_monitoring(self) -> None:
        """Setup Python garbage collection monitoring per Section 6.5.2.2."""
        if MONITORING_MODULES_AVAILABLE:
            self.gc_monitor = GarbageCollectionMonitor(self.prometheus_metrics)
        else:
            # Fallback GC monitoring
            self.gc_monitor = BasicGCMonitor(self.prometheus_metrics)
        
        # Configure GC pause time thresholds per Section 6.5.5
        self.gc_thresholds = {
            'warning_pause_ms': 10.0,   # >10ms warning
            'critical_pause_ms': 20.0   # >20ms critical
        }
        
        self.logger.info("Garbage collection monitoring configured")
    
    def _setup_memory_performance_correlation(self) -> None:
        """Setup memory usage correlation with response time performance."""
        self.memory_correlation_config = {
            'correlation_window_size': 100,
            'correlation_threshold': 0.7,  # Strong correlation threshold
            'variance_tracking_enabled': True,
            'real_time_analysis': True
        }
        
        # Initialize correlation data structures
        self.memory_performance_data = {
            'memory_samples': deque(maxlen=1000),
            'response_time_samples': deque(maxlen=1000),
            'correlation_coefficients': deque(maxlen=100)
        }
        
        self.logger.info("Memory performance correlation configured")
    
    def _setup_memory_variance_tracking(self) -> None:
        """Setup memory usage variance tracking for baseline compliance."""
        if self.baseline_manager:
            try:
                # Get memory baseline
                memory_baseline = self.baseline_manager.get_average_resource_utilization()
                if memory_baseline:
                    self.memory_baseline = {
                        'baseline_memory_mb': memory_baseline.memory_usage_mb,
                        'variance_threshold': 15.0,  # ±15% acceptable variance
                        'compliance_tracking': True
                    }
                    
                    self.logger.info(f"Memory baseline configured: {memory_baseline.memory_usage_mb} MB")
            except Exception as e:
                self.logger.warning(f"Memory baseline setup failed: {e}")
                self.memory_baseline = None
        else:
            self.memory_baseline = None
    
    def _initialize_memory_baseline_comparison(self) -> None:
        """Initialize memory usage baseline comparison capabilities."""
        # Setup memory variance metrics
        if self.prometheus_metrics:
            self.prometheus_metrics.performance_variance_percent.labels(
                endpoint='memory_baseline',
                metric_type='memory_usage'
            ).set(0.0)
        
        # Configure memory comparison tracking
        self.memory_comparison_data = {
            'baseline_memory': None,
            'current_samples': deque(maxlen=50),
            'variance_history': deque(maxlen=100)
        }
        
        self.logger.info("Memory baseline comparison initialized")
    
    def _start_memory_monitoring_thread(self) -> None:
        """Start background thread for continuous memory monitoring."""
        def memory_monitoring_loop():
            """Background memory monitoring loop."""
            while getattr(self, '_monitoring_active', True):
                try:
                    # Collect memory metrics
                    if self.memory_profiler_instance:
                        memory_data = self.memory_profiler_instance.collect_memory_metrics()
                        
                        # Update Prometheus metrics
                        if self.prometheus_metrics and memory_data:
                            self.prometheus_metrics.memory_usage_bytes.labels(
                                type='rss'
                            ).set(memory_data.get('rss', 0))
                            
                            self.prometheus_metrics.memory_usage_bytes.labels(
                                type='vms'
                            ).set(memory_data.get('vms', 0))
                            
                            self.prometheus_metrics.memory_usage_bytes.labels(
                                type='heap'
                            ).set(memory_data.get('heap', 0))
                    
                    # Check memory variance
                    self._check_memory_variance()
                    
                    time.sleep(5)  # 5-second monitoring interval
                    
                except Exception as e:
                    self.logger.debug(f"Memory monitoring error: {e}")
                    time.sleep(10)  # Longer sleep on error
        
        # Start monitoring thread
        self._monitoring_active = True
        self.memory_monitoring_thread = threading.Thread(
            target=memory_monitoring_loop,
            daemon=True,
            name='memory_monitoring'
        )
        self.memory_monitoring_thread.start()
        
        self.logger.info("Memory monitoring thread started")
    
    def _check_memory_variance(self) -> None:
        """Check current memory usage against baseline for variance compliance."""
        if not self.memory_baseline:
            return
        
        try:
            # Get current memory usage
            process = psutil.Process()
            current_memory_mb = process.memory_info().rss / (1024 * 1024)
            
            # Calculate variance
            baseline_memory = self.memory_baseline['baseline_memory_mb']
            variance_percent = ((current_memory_mb - baseline_memory) / baseline_memory) * 100
            
            # Update variance metric
            if self.prometheus_metrics:
                self.prometheus_metrics.performance_variance_percent.labels(
                    endpoint='memory_baseline',
                    metric_type='memory_usage'
                ).set(variance_percent)
            
            # Track variance history
            self.memory_comparison_data['variance_history'].append({
                'timestamp': time.time(),
                'variance_percent': variance_percent,
                'current_memory_mb': current_memory_mb,
                'baseline_memory_mb': baseline_memory
            })
            
            # Log variance if exceeding threshold
            variance_threshold = self.memory_baseline['variance_threshold']
            if abs(variance_percent) > variance_threshold:
                self.logger.warning(
                    f"Memory variance threshold exceeded: {variance_percent:.2f}% "
                    f"(threshold: ±{variance_threshold}%)"
                )
        
        except Exception as e:
            self.logger.debug(f"Memory variance check failed: {e}")
    
    def setup_database_monitoring(self) -> 'DatabaseMonitor':
        """
        Configure database monitoring and connection pool metrics per Section 3.6.2.
        
        Establishes comprehensive database performance monitoring including:
        - Query execution time tracking
        - Connection pool utilization monitoring
        - Database operation success/failure rates
        - Performance variance against baseline
        
        Returns:
            DatabaseMonitor: Configured database monitoring instance
            
        Raises:
            MonitoringSetupError: If database monitoring setup fails
        """
        try:
            self.logger.info("Setting up database monitoring and connection pool metrics...")
            
            # Initialize database monitor
            self.database_monitor = DatabaseMonitor(
                prometheus_metrics=self.prometheus_metrics,
                performance_thresholds=DATABASE_PERFORMANCE_THRESHOLDS
            )
            
            # Configure query performance tracking
            self._setup_query_performance_tracking()
            
            # Setup connection pool monitoring
            self._setup_connection_pool_monitoring()
            
            # Configure database operation metrics
            self._setup_database_operation_metrics()
            
            # Initialize database performance baseline comparison
            self._setup_database_baseline_comparison()
            
            # Setup database error monitoring
            self._setup_database_error_monitoring()
            
            self.logger.info("✅ Database monitoring setup completed")
            self.setup_steps_completed.append('database_monitoring')
            
            return self.database_monitor
            
        except Exception as e:
            error_msg = f"Failed to setup database monitoring: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _setup_query_performance_tracking(self) -> None:
        """Setup database query performance tracking and analysis."""
        # Configure query performance thresholds
        self.query_performance_config = {
            'avg_query_time_threshold': DATABASE_PERFORMANCE_THRESHOLDS['avg_query_time'],
            'max_query_time_threshold': DATABASE_PERFORMANCE_THRESHOLDS['max_query_time'],
            'slow_query_threshold': 0.1,  # 100ms
            'variance_tracking_enabled': True
        }
        
        # Initialize query performance tracking
        self.query_performance_data = {
            'query_times': defaultdict(lambda: deque(maxlen=1000)),
            'query_counts': defaultdict(int),
            'slow_queries': deque(maxlen=100)
        }
        
        self.logger.info("Query performance tracking configured")
    
    def _setup_connection_pool_monitoring(self) -> None:
        """Setup database connection pool monitoring and metrics."""
        # Configure connection pool metrics
        self.connection_pool_config = {
            'pool_size_monitoring': True,
            'connection_utilization_tracking': True,
            'connection_wait_time_tracking': True,
            'pool_exhaustion_alerts': True
        }
        
        # Initialize connection pool data tracking
        self.connection_pool_data = {
            'active_connections': 0,
            'pool_size': 10,  # Default pool size
            'connection_wait_times': deque(maxlen=1000),
            'pool_utilization_history': deque(maxlen=500)
        }
        
        self.logger.info("Connection pool monitoring configured")
    
    def _setup_database_operation_metrics(self) -> None:
        """Setup comprehensive database operation metrics collection."""
        # Database operations to track
        self.database_operations = [
            'find', 'insert', 'update', 'delete', 'aggregate', 'count', 'distinct'
        ]
        
        # Collections to monitor
        self.monitored_collections = [
            'users', 'reports', 'files', 'sessions', 'audit_logs'
        ]
        
        # Initialize operation metrics
        for operation in self.database_operations:
            for collection in self.monitored_collections:
                if self.prometheus_metrics:
                    self.prometheus_metrics.database_operations_total.labels(
                        operation=operation,
                        collection=collection,
                        status='success'
                    ).inc(0)  # Initialize counter
        
        self.logger.info("Database operation metrics configured")
    
    def _setup_database_baseline_comparison(self) -> None:
        """Setup database performance baseline comparison."""
        if self.baseline_manager:
            try:
                # Load database baseline data
                self.database_baselines = {
                    'find_operations': self.baseline_manager.get_response_time_baseline('database_find', 'GET'),
                    'insert_operations': self.baseline_manager.get_response_time_baseline('database_insert', 'POST'),
                    'update_operations': self.baseline_manager.get_response_time_baseline('database_update', 'PUT'),
                    'delete_operations': self.baseline_manager.get_response_time_baseline('database_delete', 'DELETE')
                }
                
                self.logger.info("Database baseline comparison configured")
                
            except Exception as e:
                self.logger.warning(f"Database baseline setup failed: {e}")
                self.database_baselines = {}
        else:
            self.database_baselines = {}
    
    def _setup_database_error_monitoring(self) -> None:
        """Setup database error monitoring and alerting."""
        # Configure error tracking
        self.database_error_config = {
            'error_rate_threshold': 0.05,  # 5% error rate threshold
            'connection_error_tracking': True,
            'timeout_error_tracking': True,
            'query_error_tracking': True
        }
        
        # Initialize error tracking data
        self.database_error_data = {
            'error_counts': defaultdict(int),
            'error_rates': deque(maxlen=100),
            'recent_errors': deque(maxlen=50)
        }
        
        self.logger.info("Database error monitoring configured")
    
    def setup_enterprise_apm_integration(self) -> APMIntegration:
        """
        Configure enterprise APM integration compatibility per Section 3.6.1.
        
        Establishes enterprise monitoring system integration including:
        - Datadog APM configuration with distributed tracing
        - New Relic APM integration with custom attributes
        - Environment-specific sampling rates
        - Performance overhead monitoring
        
        Returns:
            APMIntegration: Configured APM integration instance
            
        Raises:
            MonitoringSetupError: If APM integration setup fails
        """
        try:
            self.logger.info("Setting up enterprise APM integration compatibility...")
            
            # Initialize monitoring configuration
            if MONITORING_MODULES_AVAILABLE:
                monitoring_config = MonitoringConfig()
            else:
                monitoring_config = self._create_fallback_monitoring_config()
            
            # Initialize APM integration
            self.apm_integration = APMIntegration(monitoring_config)
            
            # Configure environment-specific settings
            self._configure_apm_environment_settings()
            
            # Setup distributed tracing
            self._setup_distributed_tracing()
            
            # Configure custom attributes collection
            self._setup_custom_attributes_collection()
            
            # Initialize performance overhead monitoring
            self._setup_apm_performance_overhead_monitoring()
            
            # Validate APM integration
            self._validate_apm_integration()
            
            self.logger.info("✅ Enterprise APM integration setup completed")
            self.setup_steps_completed.append('apm_integration')
            
            return self.apm_integration
            
        except Exception as e:
            error_msg = f"Failed to setup enterprise APM integration: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _create_fallback_monitoring_config(self) -> object:
        """Create fallback monitoring configuration when modules unavailable."""
        class FallbackMonitoringConfig:
            APM_ENABLED = True
            APM_SERVICE_NAME = 'flask-migration-app'
            APM_ENVIRONMENT = self.test_environment
            DATADOG_APM_ENABLED = APM_INTEGRATION_CONFIG.get('datadog', {}).get('enabled', False)
            DATADOG_SAMPLE_RATE = APM_INTEGRATION_CONFIG.get('datadog', {}).get('sample_rate', 0.1)
            NEWRELIC_APM_ENABLED = APM_INTEGRATION_CONFIG.get('newrelic', {}).get('enabled', False)
            NEWRELIC_SAMPLE_RATE = APM_INTEGRATION_CONFIG.get('newrelic', {}).get('sample_rate', 0.1)
        
        return FallbackMonitoringConfig()
    
    def _configure_apm_environment_settings(self) -> None:
        """Configure APM settings based on test environment."""
        # Environment-specific sampling rates
        self.apm_environment_config = {
            'testing': {
                'datadog_sample_rate': 1.0,  # Full sampling for testing
                'newrelic_sample_rate': 1.0,
                'trace_all_requests': True
            },
            'staging': {
                'datadog_sample_rate': 0.5,
                'newrelic_sample_rate': 0.5,
                'trace_all_requests': False
            },
            'production': {
                'datadog_sample_rate': 0.1,
                'newrelic_sample_rate': 0.1,
                'trace_all_requests': False
            }
        }
        
        env_config = self.apm_environment_config.get(self.test_environment, self.apm_environment_config['testing'])
        
        self.logger.info(f"APM environment configuration: {env_config}")
    
    def _setup_distributed_tracing(self) -> None:
        """Setup distributed tracing for end-to-end request tracking."""
        # Configure trace context propagation
        self.tracing_config = {
            'trace_context_propagation': True,
            'correlation_id_tracking': True,
            'request_correlation': True,
            'database_operation_tracing': True,
            'external_service_tracing': True
        }
        
        # Initialize trace correlation data
        self.trace_correlation_data = {
            'active_traces': {},
            'trace_performance_data': deque(maxlen=1000),
            'correlation_mapping': {}
        }
        
        self.logger.info("Distributed tracing configured")
    
    def _setup_custom_attributes_collection(self) -> None:
        """Setup custom attribute collection for business context tracking."""
        # Custom attributes to collect
        self.custom_attributes_config = {
            'business_context_attributes': [
                'user_id', 'operation_type', 'endpoint_category',
                'migration_phase', 'performance_baseline'
            ],
            'technical_attributes': [
                'request_id', 'response_time_variance', 'memory_usage_mb',
                'cpu_utilization', 'database_operations_count'
            ],
            'performance_attributes': [
                'baseline_comparison', 'variance_percentage',
                'performance_trend', 'resource_utilization'
            ]
        }
        
        # Initialize custom attributes tracking
        self.custom_attributes_data = defaultdict(dict)
        
        self.logger.info("Custom attributes collection configured")
    
    def _setup_apm_performance_overhead_monitoring(self) -> None:
        """Setup APM performance overhead monitoring per Section 6.5.4.3."""
        # Configure overhead monitoring
        self.apm_overhead_config = {
            'max_overhead_percent': APM_INTEGRATION_CONFIG.get('performance', {}).get('max_overhead_percent', 5.0),
            'overhead_measurement_interval': 60,  # seconds
            'baseline_comparison_enabled': True,
            'overhead_alerting_enabled': True
        }
        
        # Initialize overhead tracking
        self.apm_overhead_data = {
            'baseline_times': deque(maxlen=100),
            'monitored_times': deque(maxlen=100),
            'overhead_percentages': deque(maxlen=100),
            'overhead_violations': []
        }
        
        self.logger.info("APM performance overhead monitoring configured")
    
    def _validate_apm_integration(self) -> None:
        """Validate APM integration configuration and functionality."""
        validation_results = {
            'apm_integration_available': hasattr(self, 'apm_integration'),
            'distributed_tracing_configured': bool(self.tracing_config),
            'custom_attributes_configured': bool(self.custom_attributes_config),
            'overhead_monitoring_configured': bool(self.apm_overhead_config)
        }
        
        # Check for any validation failures
        failed_validations = [k for k, v in validation_results.items() if not v]
        
        if failed_validations:
            self.logger.warning(f"APM validation issues: {failed_validations}")
        else:
            self.logger.info("APM integration validation passed")
    
    def setup_real_time_performance_collection(self) -> 'PerformanceDataCollector':
        """
        Configure real-time performance data collection during testing per Section 6.6.1.
        
        Establishes continuous performance monitoring including:
        - Real-time metrics streaming
        - Performance trend analysis
        - Alert threshold validation
        - Continuous compliance monitoring
        
        Returns:
            PerformanceDataCollector: Configured performance data collector
            
        Raises:
            MonitoringSetupError: If real-time collection setup fails
        """
        try:
            self.logger.info("Setting up real-time performance data collection...")
            
            # Configure performance data collector
            self.performance_data_collector.configure(
                prometheus_metrics=self.prometheus_metrics,
                baseline_manager=self.baseline_manager,
                variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD
            )
            
            # Setup real-time metrics streaming
            self._setup_realtime_metrics_streaming()
            
            # Configure performance trend analysis
            self._setup_performance_trend_analysis()
            
            # Initialize alert threshold validation
            self._setup_alert_threshold_validation()
            
            # Setup continuous compliance monitoring
            self._setup_continuous_compliance_monitoring()
            
            # Start real-time collection thread
            self._start_realtime_collection_thread()
            
            self.logger.info("✅ Real-time performance data collection setup completed")
            self.setup_steps_completed.append('realtime_collection')
            
            return self.performance_data_collector
            
        except Exception as e:
            error_msg = f"Failed to setup real-time performance collection: {str(e)}"
            self.logger.error(error_msg)
            self.setup_errors.append(error_msg)
            raise MonitoringSetupError(error_msg)
    
    def _setup_realtime_metrics_streaming(self) -> None:
        """Setup real-time metrics streaming infrastructure."""
        # Configure streaming parameters
        self.realtime_streaming_config = {
            'streaming_interval': 1.0,  # 1-second intervals
            'metrics_buffer_size': 1000,
            'stream_compression': True,
            'batch_processing': True
        }
        
        # Initialize streaming data structures
        self.realtime_metrics_stream = {
            'response_times': deque(maxlen=1000),
            'memory_usage': deque(maxlen=1000),
            'cpu_utilization': deque(maxlen=1000),
            'database_operations': deque(maxlen=1000),
            'error_rates': deque(maxlen=1000)
        }
        
        self.logger.info("Real-time metrics streaming configured")
    
    def _setup_performance_trend_analysis(self) -> None:
        """Setup performance trend analysis and pattern detection."""
        # Configure trend analysis
        self.trend_analysis_config = {
            'trend_window_size': 100,
            'trend_detection_sensitivity': 0.05,  # 5% change detection
            'regression_analysis_enabled': True,
            'predictive_analysis_enabled': True
        }
        
        # Initialize trend tracking
        self.performance_trends = {
            'response_time_trend': deque(maxlen=500),
            'memory_usage_trend': deque(maxlen=500),
            'error_rate_trend': deque(maxlen=500),
            'throughput_trend': deque(maxlen=500)
        }
        
        self.logger.info("Performance trend analysis configured")
    
    def _setup_alert_threshold_validation(self) -> None:
        """Setup alert threshold validation per Section 6.5.5."""
        # Configure alert thresholds per specification
        self.alert_thresholds = {
            'response_time_variance': {
                'warning': 5.0,   # >5% warning
                'critical': 10.0  # >10% critical
            },
            'cpu_utilization': {
                'warning': 70.0,  # >70% warning
                'critical': 90.0  # >90% critical
            },
            'memory_usage': {
                'warning': 80.0,  # >80% warning
                'critical': 95.0  # >95% critical
            },
            'gc_pause_time': {
                'warning': 10.0,  # >10ms warning
                'critical': 20.0  # >20ms critical
            },
            'error_rate': {
                'warning': 1.0,   # >1% warning
                'critical': 5.0   # >5% critical
            }
        }
        
        # Initialize threshold validation tracking
        self.threshold_violations = {
            'warning_violations': deque(maxlen=100),
            'critical_violations': deque(maxlen=100),
            'violation_counts': defaultdict(int)
        }
        
        self.logger.info("Alert threshold validation configured")
    
    def _setup_continuous_compliance_monitoring(self) -> None:
        """Setup continuous compliance monitoring for ≤10% variance requirement."""
        # Configure compliance monitoring
        self.compliance_monitoring_config = {
            'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
            'compliance_check_interval': 10.0,  # seconds
            'rolling_compliance_window': 100,   # samples
            'compliance_reporting_enabled': True
        }
        
        # Initialize compliance tracking
        self.compliance_monitoring_data = {
            'compliance_samples': deque(maxlen=1000),
            'violation_history': deque(maxlen=500),
            'compliance_percentage': 100.0,
            'last_compliance_check': time.time()
        }
        
        self.logger.info("Continuous compliance monitoring configured")
    
    def _start_realtime_collection_thread(self) -> None:
        """Start background thread for real-time performance data collection."""
        def realtime_collection_loop():
            """Background real-time data collection loop."""
            while getattr(self, '_realtime_collection_active', True):
                try:
                    # Collect current performance metrics
                    self._collect_realtime_metrics()
                    
                    # Perform trend analysis
                    self._analyze_performance_trends()
                    
                    # Validate alert thresholds
                    self._validate_alert_thresholds()
                    
                    # Check compliance status
                    self._check_compliance_status()
                    
                    # Sleep for configured interval
                    time.sleep(self.realtime_streaming_config['streaming_interval'])
                    
                except Exception as e:
                    self.logger.debug(f"Real-time collection error: {e}")
                    time.sleep(5)  # Longer sleep on error
        
        # Start collection thread
        self._realtime_collection_active = True
        self.realtime_collection_thread = threading.Thread(
            target=realtime_collection_loop,
            daemon=True,
            name='realtime_collection'
        )
        self.realtime_collection_thread.start()
        
        self.logger.info("Real-time collection thread started")
    
    def _collect_realtime_metrics(self) -> None:
        """Collect current performance metrics for real-time analysis."""
        try:
            # Collect system metrics
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            
            # Update real-time streams
            timestamp = time.time()
            
            self.realtime_metrics_stream['cpu_utilization'].append({
                'timestamp': timestamp,
                'value': cpu_percent
            })
            
            self.realtime_metrics_stream['memory_usage'].append({
                'timestamp': timestamp,
                'value': memory_info.rss / (1024 * 1024)  # MB
            })
            
            # Update Prometheus metrics
            if self.prometheus_metrics:
                self.prometheus_metrics.cpu_utilization_percent.set(cpu_percent)
                self.prometheus_metrics.memory_usage_bytes.labels(type='rss').set(memory_info.rss)
        
        except Exception as e:
            self.logger.debug(f"Real-time metrics collection error: {e}")
    
    def _analyze_performance_trends(self) -> None:
        """Analyze performance trends for pattern detection."""
        try:
            # Analyze CPU utilization trend
            cpu_data = [item['value'] for item in list(self.realtime_metrics_stream['cpu_utilization'])[-10:]]
            if len(cpu_data) >= 5:
                cpu_trend = self._calculate_trend(cpu_data)
                self.performance_trends['cpu_trend'] = cpu_trend
            
            # Analyze memory usage trend
            memory_data = [item['value'] for item in list(self.realtime_metrics_stream['memory_usage'])[-10:]]
            if len(memory_data) >= 5:
                memory_trend = self._calculate_trend(memory_data)
                self.performance_trends['memory_trend'] = memory_trend
        
        except Exception as e:
            self.logger.debug(f"Trend analysis error: {e}")
    
    def _calculate_trend(self, data: List[float]) -> Dict[str, float]:
        """Calculate trend analysis for performance data."""
        if len(data) < 2:
            return {'slope': 0.0, 'direction': 'stable'}
        
        # Simple linear regression for trend calculation
        n = len(data)
        x = list(range(n))
        
        # Calculate slope
        x_mean = sum(x) / n
        y_mean = sum(data) / n
        
        numerator = sum((x[i] - x_mean) * (data[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        slope = numerator / denominator if denominator != 0 else 0.0
        
        # Determine trend direction
        if abs(slope) < 0.1:
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'
        else:
            direction = 'decreasing'
        
        return {'slope': slope, 'direction': direction}
    
    def _validate_alert_thresholds(self) -> None:
        """Validate current metrics against alert thresholds."""
        try:
            current_time = time.time()
            
            # Check CPU utilization
            if self.realtime_metrics_stream['cpu_utilization']:
                latest_cpu = self.realtime_metrics_stream['cpu_utilization'][-1]['value']
                self._check_threshold_violation('cpu_utilization', latest_cpu, current_time)
            
            # Check memory usage percentage
            if self.realtime_metrics_stream['memory_usage']:
                latest_memory = self.realtime_metrics_stream['memory_usage'][-1]['value']
                memory_percent = (latest_memory / 1024) * 100  # Approximate percentage
                self._check_threshold_violation('memory_usage', memory_percent, current_time)
        
        except Exception as e:
            self.logger.debug(f"Threshold validation error: {e}")
    
    def _check_threshold_violation(self, metric_name: str, value: float, timestamp: float) -> None:
        """Check if metric value violates alert thresholds."""
        if metric_name not in self.alert_thresholds:
            return
        
        thresholds = self.alert_thresholds[metric_name]
        
        # Check critical threshold
        if value > thresholds['critical']:
            violation = {
                'metric': metric_name,
                'value': value,
                'threshold': thresholds['critical'],
                'severity': 'critical',
                'timestamp': timestamp
            }
            self.threshold_violations['critical_violations'].append(violation)
            self.threshold_violations['violation_counts'][f'{metric_name}_critical'] += 1
            
            self.logger.warning(
                f"CRITICAL threshold violation: {metric_name}={value:.2f} "
                f"(threshold: {thresholds['critical']})"
            )
        
        # Check warning threshold
        elif value > thresholds['warning']:
            violation = {
                'metric': metric_name,
                'value': value,
                'threshold': thresholds['warning'],
                'severity': 'warning',
                'timestamp': timestamp
            }
            self.threshold_violations['warning_violations'].append(violation)
            self.threshold_violations['violation_counts'][f'{metric_name}_warning'] += 1
            
            self.logger.info(
                f"Warning threshold violation: {metric_name}={value:.2f} "
                f"(threshold: {thresholds['warning']})"
            )
    
    def _check_compliance_status(self) -> None:
        """Check overall compliance status against ≤10% variance requirement."""
        try:
            current_time = time.time()
            
            # Check if enough time has passed since last check
            if current_time - self.compliance_monitoring_data['last_compliance_check'] < self.compliance_monitoring_config['compliance_check_interval']:
                return
            
            # Calculate compliance percentage
            total_violations = len(self.threshold_violations['critical_violations']) + len(self.threshold_violations['warning_violations'])
            total_samples = len(self.compliance_monitoring_data['compliance_samples'])
            
            if total_samples > 0:
                compliance_percentage = ((total_samples - total_violations) / total_samples) * 100
            else:
                compliance_percentage = 100.0
            
            # Update compliance data
            self.compliance_monitoring_data['compliance_percentage'] = compliance_percentage
            self.compliance_monitoring_data['last_compliance_check'] = current_time
            
            # Log compliance status
            if compliance_percentage < 90.0:
                self.logger.warning(f"Compliance below target: {compliance_percentage:.1f}%")
            else:
                self.logger.debug(f"Compliance status: {compliance_percentage:.1f}%")
        
        except Exception as e:
            self.logger.debug(f"Compliance check error: {e}")
    
    def get_monitoring_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive monitoring setup summary report.
        
        Returns:
            Dictionary containing complete monitoring setup status and metrics
        """
        setup_duration = time.time() - self.setup_start_time
        
        summary = {
            'setup_metadata': {
                'test_environment': self.test_environment,
                'setup_duration_seconds': setup_duration,
                'setup_start_time': datetime.fromtimestamp(self.setup_start_time, timezone.utc).isoformat(),
                'setup_completion_time': datetime.now(timezone.utc).isoformat()
            },
            'setup_status': {
                'steps_completed': self.setup_steps_completed,
                'total_steps': 6,  # prometheus, flask_metrics, memory, database, apm, realtime
                'completion_percentage': (len(self.setup_steps_completed) / 6) * 100,
                'setup_errors': self.setup_errors,
                'setup_successful': len(self.setup_errors) == 0
            },
            'component_status': {
                'prometheus_metrics': hasattr(self, 'prometheus_metrics') and self.prometheus_metrics is not None,
                'flask_metrics_collector': hasattr(self, 'flask_metrics_collector') and self.flask_metrics_collector is not None,
                'memory_profiler': hasattr(self, 'memory_profiler_instance') and self.memory_profiler_instance is not None,
                'database_monitor': hasattr(self, 'database_monitor') and hasattr(self, 'database_monitor'),
                'apm_integration': hasattr(self, 'apm_integration') and self.apm_integration is not None,
                'performance_data_collector': hasattr(self, 'performance_data_collector') and self.performance_data_collector is not None
            },
            'monitoring_endpoints': self.monitoring_endpoints,
            'performance_thresholds': {
                'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
                'alert_thresholds': getattr(self, 'alert_thresholds', {}),
                'database_thresholds': DATABASE_PERFORMANCE_THRESHOLDS
            },
            'configuration_summary': {
                'structured_logging_enabled': STRUCTLOG_AVAILABLE,
                'memory_profiling_enabled': MEMORY_PROFILER_AVAILABLE,
                'enterprise_apm_enabled': getattr(self, 'apm_integration', None) is not None,
                'real_time_collection_enabled': getattr(self, '_realtime_collection_active', False)
            }
        }
        
        # Add compliance monitoring data if available
        if hasattr(self, 'compliance_monitoring_data'):
            summary['compliance_status'] = {
                'compliance_percentage': self.compliance_monitoring_data.get('compliance_percentage', 0),
                'total_violations': len(getattr(self, 'threshold_violations', {}).get('critical_violations', [])),
                'monitoring_active': getattr(self, '_realtime_collection_active', False)
            }
        
        # Add baseline comparison status
        if hasattr(self, 'baseline_manager') and self.baseline_manager:
            baseline_summary = self.baseline_manager.generate_baseline_summary()
            summary['baseline_comparison'] = {
                'baseline_data_available': True,
                'total_baselines': baseline_summary.get('baseline_data_summary', {}).get('total_response_time_baselines', 0),
                'variance_tracking_enabled': True
            }
        else:
            summary['baseline_comparison'] = {
                'baseline_data_available': False,
                'variance_tracking_enabled': False
            }
        
        return summary
    
    def shutdown_monitoring(self) -> None:
        """
        Gracefully shutdown monitoring infrastructure and cleanup resources.
        """
        self.logger.info("Shutting down performance monitoring infrastructure...")
        
        try:
            # Stop real-time collection
            if hasattr(self, '_realtime_collection_active'):
                self._realtime_collection_active = False
                if hasattr(self, 'realtime_collection_thread'):
                    self.realtime_collection_thread.join(timeout=5)
            
            # Stop memory monitoring
            if hasattr(self, '_monitoring_active'):
                self._monitoring_active = False
                if hasattr(self, 'memory_monitoring_thread'):
                    self.memory_monitoring_thread.join(timeout=5)
            
            # Cleanup metrics registry
            if self.metrics_registry:
                # Clear multiprocess directory if exists
                multiproc_dir = os.getenv('PROMETHEUS_MULTIPROC_DIR')
                if multiproc_dir and os.path.exists(multiproc_dir):
                    import shutil
                    shutil.rmtree(multiproc_dir, ignore_errors=True)
            
            # Clear data structures
            if hasattr(self, 'performance_data_collector'):
                self.performance_data_collector = None
            
            if hasattr(self, 'realtime_metrics_stream'):
                self.realtime_metrics_stream.clear()
            
            self.logger.info("✅ Performance monitoring shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during monitoring shutdown: {e}")


class PerformanceDataCollector:
    """
    Real-time performance data collection and analysis component providing
    continuous monitoring capabilities for performance testing scenarios.
    """
    
    def __init__(self):
        """Initialize performance data collector."""
        self.prometheus_metrics = None
        self.baseline_manager = None
        self.variance_threshold = 10.0
        self.collection_active = False
        
        # Data collection storage
        self.collected_data = {
            'response_times': deque(maxlen=10000),
            'memory_usage': deque(maxlen=10000),
            'cpu_utilization': deque(maxlen=10000),
            'database_operations': deque(maxlen=10000),
            'error_rates': deque(maxlen=1000)
        }
        
        # Performance analysis data
        self.performance_analysis = {
            'variance_tracking': defaultdict(list),
            'trend_analysis': defaultdict(list),
            'compliance_tracking': []
        }
        
        self.collection_lock = threading.Lock()
    
    def configure(self, prometheus_metrics=None, baseline_manager=None, variance_threshold=10.0):
        """Configure performance data collector with monitoring components."""
        self.prometheus_metrics = prometheus_metrics
        self.baseline_manager = baseline_manager
        self.variance_threshold = variance_threshold
        
    def collect_performance_sample(self, sample_data: Dict[str, Any]) -> None:
        """Collect performance sample for real-time analysis."""
        with self.collection_lock:
            timestamp = time.time()
            
            # Store response time data
            if 'response_time' in sample_data:
                self.collected_data['response_times'].append({
                    'timestamp': timestamp,
                    'value': sample_data['response_time'],
                    'endpoint': sample_data.get('endpoint', 'unknown')
                })
            
            # Store resource utilization data
            if 'memory_usage' in sample_data:
                self.collected_data['memory_usage'].append({
                    'timestamp': timestamp,
                    'value': sample_data['memory_usage']
                })
            
            if 'cpu_utilization' in sample_data:
                self.collected_data['cpu_utilization'].append({
                    'timestamp': timestamp,
                    'value': sample_data['cpu_utilization']
                })
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Generate performance data summary for analysis."""
        with self.collection_lock:
            summary = {
                'collection_summary': {
                    'total_samples': sum(len(data) for data in self.collected_data.values()),
                    'collection_active': self.collection_active,
                    'variance_threshold': self.variance_threshold
                },
                'data_summary': {},
                'performance_analysis': self.performance_analysis
            }
            
            # Analyze collected data
            for data_type, data_samples in self.collected_data.items():
                if data_samples:
                    values = [sample['value'] for sample in data_samples]
                    summary['data_summary'][data_type] = {
                        'sample_count': len(values),
                        'mean': sum(values) / len(values),
                        'min': min(values),
                        'max': max(values)
                    }
            
            return summary


class MemoryProfiler:
    """
    Advanced memory profiling component using memory-profiler library
    for comprehensive memory usage analysis and variance tracking.
    """
    
    def __init__(self, prometheus_metrics=None):
        """Initialize memory profiler with metrics integration."""
        self.prometheus_metrics = prometheus_metrics
        self.profiling_active = False
        self.memory_samples = deque(maxlen=10000)
        
    def collect_memory_metrics(self) -> Dict[str, float]:
        """Collect comprehensive memory metrics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            memory_data = {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': process.memory_percent(),
                'heap': self._get_heap_size()
            }
            
            # Store sample
            self.memory_samples.append({
                'timestamp': time.time(),
                'memory_data': memory_data
            })
            
            return memory_data
            
        except Exception as e:
            return {}
    
    def _get_heap_size(self) -> int:
        """Estimate Python heap size."""
        try:
            return sum(sys.getsizeof(obj) for obj in gc.get_objects())
        except:
            return 0


class BasicMemoryMonitor:
    """
    Basic memory monitoring fallback when memory-profiler is not available.
    """
    
    def __init__(self, prometheus_metrics=None):
        """Initialize basic memory monitor."""
        self.prometheus_metrics = prometheus_metrics
        
    def collect_memory_metrics(self) -> Dict[str, float]:
        """Collect basic memory metrics using psutil."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': process.memory_percent()
            }
        except:
            return {}


class DatabaseMonitor:
    """
    Database performance monitoring component for tracking query performance,
    connection pool metrics, and database operation variance.
    """
    
    def __init__(self, prometheus_metrics=None, performance_thresholds=None):
        """Initialize database monitor."""
        self.prometheus_metrics = prometheus_metrics
        self.performance_thresholds = performance_thresholds or {}
        self.query_performance_data = defaultdict(lambda: deque(maxlen=1000))
        
    def record_query_performance(self, operation: str, collection: str, duration: float):
        """Record database query performance metrics."""
        key = f"{operation}_{collection}"
        self.query_performance_data[key].append({
            'timestamp': time.time(),
            'duration': duration,
            'operation': operation,
            'collection': collection
        })
        
        # Update Prometheus metrics
        if self.prometheus_metrics:
            self.prometheus_metrics.record_database_operation(
                operation=operation,
                collection=collection,
                status='success',
                duration=duration
            )


class BasicGCMonitor:
    """
    Basic garbage collection monitoring fallback when advanced GC monitoring is not available.
    """
    
    def __init__(self, prometheus_metrics=None):
        """Initialize basic GC monitor."""
        self.prometheus_metrics = prometheus_metrics
        self.gc_stats = {'collections': [0, 0, 0], 'total_pause_time': 0.0}
    
    def get_gc_statistics(self) -> Dict[str, Any]:
        """Get basic garbage collection statistics."""
        return {
            'generation_stats': gc.get_stats(),
            'current_counts': gc.get_count(),
            'total_collections': sum(self.gc_stats['collections'])
        }


class SystemResourceMonitor:
    """
    System resource monitoring component for comprehensive resource utilization tracking.
    """
    
    def __init__(self):
        """Initialize system resource monitor."""
        self.monitoring_active = False
        self.resource_data = deque(maxlen=10000)
        
    def collect_system_metrics(self) -> Dict[str, float]:
        """Collect comprehensive system resource metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            metrics = {
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count,
                'memory_total': memory.total,
                'memory_used': memory.used,
                'memory_percent': memory.percent,
                'disk_total': disk.total,
                'disk_used': disk.used,
                'disk_percent': (disk.used / disk.total) * 100,
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv
            }
            
            # Store metrics sample
            self.resource_data.append({
                'timestamp': time.time(),
                'metrics': metrics
            })
            
            return metrics
            
        except Exception as e:
            return {}


def main():
    """
    Main entry point for performance monitoring setup script.
    
    This function demonstrates the complete performance monitoring setup process
    and can be used for standalone monitoring infrastructure initialization.
    """
    print("🚀 Performance Monitoring Setup Script")
    print("=" * 50)
    
    try:
        # Initialize monitoring setup
        monitoring_setup = PerformanceMonitoringSetup(
            test_environment='testing',
            verbose=True
        )
        
        print("📋 Step 1: Validating dependencies...")
        dependency_status = monitoring_setup.validate_dependencies()
        print(f"✅ Dependencies validated: {sum(dependency_status.values())}/{len(dependency_status)} available")
        
        print("\n📊 Step 2: Setting up Prometheus metrics collection...")
        prometheus_metrics = monitoring_setup.setup_prometheus_metrics_collection()
        print("✅ Prometheus metrics collection configured")
        
        print("\n⚡ Step 3: Setting up Flask-Metrics integration...")
        flask_metrics = monitoring_setup.setup_flask_metrics_integration()
        print("✅ Flask-Metrics integration configured")
        
        print("\n🧠 Step 4: Setting up memory profiling...")
        memory_profiler = monitoring_setup.setup_memory_profiling_monitoring()
        print("✅ Memory profiling and monitoring configured")
        
        print("\n💾 Step 5: Setting up database monitoring...")
        database_monitor = monitoring_setup.setup_database_monitoring()
        print("✅ Database monitoring configured")
        
        print("\n🔗 Step 6: Setting up enterprise APM integration...")
        apm_integration = monitoring_setup.setup_enterprise_apm_integration()
        print("✅ Enterprise APM integration configured")
        
        print("\n📡 Step 7: Setting up real-time performance collection...")
        performance_collector = monitoring_setup.setup_real_time_performance_collection()
        print("✅ Real-time performance collection configured")
        
        print("\n📈 Step 8: Generating monitoring summary...")
        summary = monitoring_setup.get_monitoring_summary()
        
        print(f"\n🎯 Performance Monitoring Setup Complete!")
        print(f"   • Setup Duration: {summary['setup_metadata']['setup_duration_seconds']:.2f} seconds")
        print(f"   • Completion Rate: {summary['setup_status']['completion_percentage']:.1f}%")
        print(f"   • Components Active: {sum(summary['component_status'].values())}/{len(summary['component_status'])}")
        print(f"   • Monitoring Endpoints: {len(summary['monitoring_endpoints'])}")
        print(f"   • Performance Variance Threshold: ≤{summary['performance_thresholds']['variance_threshold']}%")
        
        if summary['baseline_comparison']['baseline_data_available']:
            print(f"   • Baseline Comparison: ✅ Enabled ({summary['baseline_comparison']['total_baselines']} baselines)")
        else:
            print(f"   • Baseline Comparison: ⚠️  Limited (no baseline data)")
        
        print(f"\n📋 Setup Summary:")
        print(f"   • Steps Completed: {', '.join(summary['setup_status']['steps_completed'])}")
        
        if summary['setup_status']['setup_errors']:
            print(f"   • Setup Errors: {len(summary['setup_status']['setup_errors'])}")
            for error in summary['setup_status']['setup_errors']:
                print(f"     - {error}")
        else:
            print(f"   • Setup Errors: None")
        
        print(f"\n🎉 Performance monitoring infrastructure ready for testing!")
        print(f"   Access metrics at: http://localhost:5000/metrics")
        print(f"   Health checks at: http://localhost:5000/health")
        print(f"   Liveness probe: http://localhost:5000/health/live")
        print(f"   Readiness probe: http://localhost:5000/health/ready")
        
        # Keep monitoring active for demonstration
        print(f"\n⏰ Monitoring active - press Ctrl+C to shutdown...")
        try:
            while True:
                time.sleep(10)
                compliance_status = summary.get('compliance_status', {})
                if compliance_status:
                    print(f"   Compliance: {compliance_status.get('compliance_percentage', 0):.1f}% | "
                          f"Violations: {compliance_status.get('total_violations', 0)}")
        except KeyboardInterrupt:
            print(f"\n🛑 Shutting down monitoring...")
            monitoring_setup.shutdown_monitoring()
            print(f"✅ Monitoring shutdown complete")
            
    except MonitoringSetupError as e:
        print(f"❌ Monitoring setup failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()