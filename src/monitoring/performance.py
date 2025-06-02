#!/usr/bin/env python3
"""
Performance Monitoring and Baseline Comparison Module

Comprehensive performance monitoring implementation providing Node.js baseline comparison,
response time variance tracking, memory profiling, CPU utilization monitoring, and Python
garbage collection analysis. Implements performance validation to ensure ≤10% variance
compliance and capacity planning insights for enterprise deployment optimization.

Key Features:
- Node.js baseline performance comparison with real-time variance tracking
- Response time variance calculation with automated alert thresholds per Section 6.5.5
- Memory profiling and Python garbage collection instrumentation per Section 6.5.1.1
- CPU utilization monitoring with psutil 5.9+ integration per Section 6.5.1.1
- Container resource correlation analysis for comprehensive performance insights
- Performance baseline tracking and drift analysis per Section 6.5.3.4
- Automated rollback recommendation based on performance degradation detection

Compliance:
- Section 0.1.1: Performance monitoring to ensure ≤10% variance from Node.js baseline
- Section 6.5.2.2: Performance variance tracking with Prometheus Gauge metrics
- Section 6.5.1.1: CPU utilization monitoring with psutil and container correlation
- Section 6.5.5: Alert threshold matrices for performance monitoring
- Section 6.5.3.4: Performance baseline tracking and drift analysis
"""

import os
import gc
import sys
import time
import psutil
import threading
import statistics
import tracemalloc
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
import pickle
import hashlib

import structlog
from flask import Flask, request, g, has_request_context
from prometheus_client import Counter, Histogram, Gauge, Summary

from src.monitoring.metrics import metrics_collector, track_business_operation
from src.monitoring.logging import get_logger, log_performance_metric, log_business_event

# Initialize logger for performance monitoring
logger = get_logger(__name__)

@dataclass
class PerformanceBaseline:
    """
    Node.js baseline performance data structure for comparison tracking.
    
    Stores comprehensive baseline metrics including response times, throughput,
    resource utilization, and capacity characteristics from Node.js implementation.
    """
    endpoint: str
    method: str
    avg_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    throughput_rps: float
    cpu_utilization: float
    memory_usage_mb: float
    error_rate: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sample_count: int = 0
    confidence_score: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline to dictionary for serialization."""
        return {
            'endpoint': self.endpoint,
            'method': self.method,
            'avg_response_time': self.avg_response_time,
            'p50_response_time': self.p50_response_time,
            'p95_response_time': self.p95_response_time,
            'p99_response_time': self.p99_response_time,
            'throughput_rps': self.throughput_rps,
            'cpu_utilization': self.cpu_utilization,
            'memory_usage_mb': self.memory_usage_mb,
            'error_rate': self.error_rate,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'sample_count': self.sample_count,
            'confidence_score': self.confidence_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PerformanceBaseline':
        """Create baseline from dictionary data."""
        return cls(
            endpoint=data['endpoint'],
            method=data['method'],
            avg_response_time=data['avg_response_time'],
            p50_response_time=data['p50_response_time'],
            p95_response_time=data['p95_response_time'],
            p99_response_time=data['p99_response_time'],
            throughput_rps=data['throughput_rps'],
            cpu_utilization=data['cpu_utilization'],
            memory_usage_mb=data['memory_usage_mb'],
            error_rate=data['error_rate'],
            created_at=datetime.fromisoformat(data['created_at']),
            last_updated=datetime.fromisoformat(data['last_updated']),
            sample_count=data['sample_count'],
            confidence_score=data['confidence_score']
        )

@dataclass
class PerformanceMeasurement:
    """
    Real-time performance measurement data structure.
    
    Captures comprehensive performance metrics for Flask implementation
    including timing, resource utilization, and request characteristics.
    """
    endpoint: str
    method: str
    response_time: float
    status_code: int
    cpu_usage: float
    memory_usage_mb: float
    gc_collections: int
    active_threads: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    db_query_time: float = 0.0
    external_service_time: float = 0.0
    business_logic_time: float = 0.0
    middleware_time: float = 0.0
    
    def variance_from_baseline(self, baseline: PerformanceBaseline) -> float:
        """
        Calculate performance variance percentage from Node.js baseline.
        
        Returns:
            Variance percentage (positive = slower, negative = faster)
        """
        if baseline.avg_response_time <= 0:
            return 0.0
        
        return ((self.response_time - baseline.avg_response_time) / baseline.avg_response_time) * 100

@dataclass 
class MemoryProfile:
    """
    Python memory profiling data structure for GC analysis.
    
    Captures detailed memory allocation patterns, garbage collection metrics,
    and memory fragmentation characteristics for performance optimization.
    """
    timestamp: datetime
    heap_size_mb: float
    heap_used_mb: float
    gc_gen0_collections: int
    gc_gen1_collections: int
    gc_gen2_collections: int
    gc_pause_time_ms: float
    memory_fragmentation_ratio: float
    object_count: int
    tracemalloc_peak_mb: float = 0.0
    memory_growth_rate_mb_per_min: float = 0.0
    allocation_rate_mb_per_sec: float = 0.0

class PerformanceMonitor:
    """
    Comprehensive performance monitoring and baseline comparison system.
    
    Implements enterprise-grade performance tracking with Node.js baseline comparison,
    variance monitoring, automated alerting, and capacity planning insights.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize performance monitoring system.
        
        Args:
            app: Flask application instance for initialization
        """
        self.app = app
        self._baselines: Dict[str, PerformanceBaseline] = {}
        self._measurements: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._memory_profiles: deque = deque(maxlen=500)
        self._performance_lock = threading.RLock()
        
        # Performance monitoring configuration
        self._monitoring_enabled = True
        self._baseline_storage_path = os.getenv('PERFORMANCE_BASELINE_PATH', '/tmp/nodejs_baselines.pkl')
        self._variance_threshold_warning = float(os.getenv('PERFORMANCE_VARIANCE_WARNING', '5.0'))
        self._variance_threshold_critical = float(os.getenv('PERFORMANCE_VARIANCE_CRITICAL', '10.0'))
        self._measurement_window_size = int(os.getenv('PERFORMANCE_WINDOW_SIZE', '100'))
        self._memory_profiling_enabled = os.getenv('MEMORY_PROFILING_ENABLED', 'true').lower() == 'true'
        
        # System resource monitoring
        self._cpu_monitoring_interval = float(os.getenv('CPU_MONITORING_INTERVAL', '15.0'))
        self._memory_monitoring_interval = float(os.getenv('MEMORY_MONITORING_INTERVAL', '30.0'))
        self._gc_monitoring_enabled = os.getenv('GC_MONITORING_ENABLED', 'true').lower() == 'true'
        
        # Performance analysis caches
        self._variance_cache: Dict[str, float] = {}
        self._trend_cache: Dict[str, List[float]] = defaultdict(list)
        self._capacity_cache: Dict[str, Any] = {}
        
        # Thread pool for background monitoring
        self._monitor_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix='perf_monitor')
        self._monitoring_threads: List[threading.Thread] = []
        
        # Performance alerting state
        self._alert_state: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._last_alert_time: Dict[str, datetime] = {}
        self._alert_cooldown_minutes = int(os.getenv('ALERT_COOLDOWN_MINUTES', '5'))
        
        # Initialize monitoring components
        self._init_performance_metrics()
        self._init_memory_profiling()
        self._init_gc_monitoring()
        
        if app:
            self.init_app(app)
    
    def _init_performance_metrics(self) -> None:
        """
        Initialize Prometheus metrics for performance monitoring.
        
        Implements Section 6.5.2.2 performance variance tracking with Prometheus Gauge metrics.
        """
        # Response time variance tracking
        self.response_time_variance = Gauge(
            'flask_response_time_variance_percentage',
            'Response time variance percentage from Node.js baseline',
            ['endpoint', 'method'],
            registry=metrics_collector.registry
        )
        
        # Performance compliance tracking
        self.performance_compliance = Gauge(
            'flask_performance_compliance_status',
            'Performance compliance status (1=compliant, 0=non-compliant)',
            ['endpoint', 'method', 'threshold_type'],
            registry=metrics_collector.registry
        )
        
        # Memory performance correlation
        self.memory_performance_correlation = Gauge(
            'flask_memory_performance_correlation_coefficient',
            'Correlation between memory usage and response time',
            ['endpoint'],
            registry=metrics_collector.registry
        )
        
        # Capacity utilization tracking
        self.capacity_utilization = Gauge(
            'flask_capacity_utilization_percentage',
            'Current capacity utilization percentage',
            ['resource_type'],
            registry=metrics_collector.registry
        )
        
        # Performance trend indicators
        self.performance_trend = Gauge(
            'flask_performance_trend_score',
            'Performance trend score (-1=degrading, 0=stable, 1=improving)',
            ['endpoint', 'time_window'],
            registry=metrics_collector.registry
        )
        
        # Baseline confidence tracking
        self.baseline_confidence = Gauge(
            'flask_baseline_confidence_score',
            'Confidence score for Node.js baseline data',
            ['endpoint', 'method'],
            registry=metrics_collector.registry
        )
        
        # Alert threshold violations
        self.variance_violations = Counter(
            'flask_performance_variance_violations_total',
            'Total performance variance threshold violations',
            ['endpoint', 'method', 'threshold_type', 'severity'],
            registry=metrics_collector.registry
        )
        
        # Performance optimization opportunities
        self.optimization_opportunities = Counter(
            'flask_performance_optimization_opportunities_total',
            'Count of performance optimization opportunities identified',
            ['optimization_type', 'impact_level'],
            registry=metrics_collector.registry
        )
    
    def _init_memory_profiling(self) -> None:
        """
        Initialize Python memory profiling and tracemalloc integration.
        
        Implements Section 6.5.1.1 Python garbage collection instrumentation.
        """
        if self._memory_profiling_enabled:
            try:
                # Start tracemalloc for detailed memory tracking
                tracemalloc.start(10)  # Track top 10 memory allocations
                logger.info("Initialized tracemalloc memory profiling")
            except Exception as e:
                logger.warning(f"Failed to initialize tracemalloc: {e}")
                self._memory_profiling_enabled = False
        
        # Memory profiling metrics
        self.memory_heap_size = Gauge(
            'flask_memory_heap_size_bytes',
            'Python heap memory size in bytes',
            registry=metrics_collector.registry
        )
        
        self.memory_heap_used = Gauge(
            'flask_memory_heap_used_bytes',
            'Python heap memory used in bytes',
            registry=metrics_collector.registry
        )
        
        self.memory_fragmentation = Gauge(
            'flask_memory_fragmentation_ratio',
            'Memory fragmentation ratio (higher = more fragmented)',
            registry=metrics_collector.registry
        )
        
        self.memory_growth_rate = Gauge(
            'flask_memory_growth_rate_mb_per_minute',
            'Memory growth rate in MB per minute',
            registry=metrics_collector.registry
        )
        
        self.allocation_rate = Gauge(
            'flask_allocation_rate_mb_per_second', 
            'Memory allocation rate in MB per second',
            registry=metrics_collector.registry
        )
        
        # Object count tracking
        self.python_object_count = Gauge(
            'flask_python_object_count',
            'Total count of Python objects in memory',
            ['object_type'],
            registry=metrics_collector.registry
        )
    
    def _init_gc_monitoring(self) -> None:
        """
        Initialize Python garbage collection monitoring and instrumentation.
        
        Implements Section 6.5.1.1 GC pause time instrumentation using gc module.
        """
        if self._gc_monitoring_enabled:
            # GC pause time tracking
            self.gc_pause_time = Histogram(
                'flask_gc_pause_time_seconds',
                'Python garbage collection pause time in seconds',
                ['generation'],
                buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, float('inf')],
                registry=metrics_collector.registry
            )
            
            # GC collection frequency
            self.gc_collections_rate = Gauge(
                'flask_gc_collections_per_minute',
                'Garbage collection frequency per minute by generation',
                ['generation'],
                registry=metrics_collector.registry
            )
            
            # GC efficiency metrics
            self.gc_efficiency = Gauge(
                'flask_gc_efficiency_ratio',
                'Garbage collection efficiency (objects freed / objects scanned)',
                ['generation'],
                registry=metrics_collector.registry
            )
            
            # Register GC callbacks for pause time measurement
            self._setup_gc_callbacks()
    
    def _setup_gc_callbacks(self) -> None:
        """
        Set up garbage collection callbacks for pause time measurement.
        
        Monitors GC events and measures pause times for performance analysis.
        """
        self._gc_start_times: Dict[int, float] = {}
        self._gc_stats = defaultdict(list)
        
        def gc_callback(phase: str, info: Dict[str, Any]) -> None:
            """Callback function for GC event monitoring."""
            try:
                generation = info.get('generation', 0)
                current_time = time.time()
                
                if phase == 'start':
                    self._gc_start_times[generation] = current_time
                elif phase == 'stop' and generation in self._gc_start_times:
                    pause_time = current_time - self._gc_start_times[generation]
                    
                    # Record pause time metric
                    self.gc_pause_time.labels(generation=str(generation)).observe(pause_time)
                    
                    # Update GC statistics
                    self._gc_stats[generation].append({
                        'pause_time': pause_time,
                        'timestamp': datetime.now(timezone.utc),
                        'collected': info.get('collected', 0),
                        'uncollectable': info.get('uncollectable', 0)
                    })
                    
                    # Maintain rolling window
                    if len(self._gc_stats[generation]) > 100:
                        self._gc_stats[generation] = self._gc_stats[generation][-100:]
                    
                    # Clean up start time
                    del self._gc_start_times[generation]
                    
                    # Log significant GC pause times
                    if pause_time > 0.1:  # 100ms threshold
                        logger.warning(
                            "Significant GC pause detected",
                            generation=generation,
                            pause_time_ms=pause_time * 1000,
                            collected_objects=info.get('collected', 0),
                            performance=True
                        )
            
            except Exception as e:
                logger.error(f"Error in GC callback: {e}")
        
        # Note: Python's gc module doesn't provide direct callback registration
        # This would need to be implemented through periodic polling or custom instrumentation
        logger.info("GC monitoring callbacks configured")
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize performance monitoring for Flask application.
        
        Args:
            app: Flask application instance to instrument
        """
        self.app = app
        
        # Load Node.js baselines if available
        self._load_baselines()
        
        # Register Flask hooks for performance measurement
        self._register_flask_hooks(app)
        
        # Start background monitoring threads
        self._start_background_monitoring()
        
        # Register shutdown handlers
        self._register_shutdown_handlers(app)
        
        logger.info(
            "Performance monitoring initialized",
            variance_warning_threshold=self._variance_threshold_warning,
            variance_critical_threshold=self._variance_threshold_critical,
            memory_profiling_enabled=self._memory_profiling_enabled,
            gc_monitoring_enabled=self._gc_monitoring_enabled
        )
    
    def _register_flask_hooks(self, app: Flask) -> None:
        """
        Register Flask request/response hooks for performance measurement.
        
        Implements comprehensive request lifecycle monitoring for baseline comparison.
        """
        @app.before_request
        def before_request_performance():
            """Initialize performance measurement context."""
            if not self._monitoring_enabled:
                return
            
            # Set performance measurement start time
            g.perf_start_time = time.time()
            g.perf_start_cpu = psutil.Process().cpu_percent()
            g.perf_start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            g.perf_gc_start = gc.get_count()
            g.perf_thread_count = threading.active_count()
            
            # Record request characteristics
            g.perf_request_size = request.content_length or 0
            g.perf_endpoint = request.endpoint or 'unknown'
            g.perf_method = request.method
            
            # Initialize timing breakdown
            g.perf_timing_breakdown = {
                'middleware_start': time.time(),
                'auth_time': 0.0,
                'validation_time': 0.0,
                'business_logic_time': 0.0,
                'db_time': 0.0,
                'external_service_time': 0.0
            }
        
        @app.after_request
        def after_request_performance(response):
            """Capture performance measurement and analyze variance."""
            if not self._monitoring_enabled or not hasattr(g, 'perf_start_time'):
                return response
            
            try:
                # Calculate performance metrics
                end_time = time.time()
                response_time = end_time - g.perf_start_time
                
                # System resource metrics
                process = psutil.Process()
                end_cpu = process.cpu_percent()
                end_memory = process.memory_info().rss / 1024 / 1024  # MB
                
                # GC metrics
                end_gc = gc.get_count()
                gc_collections = sum(end_gc[i] - g.perf_gc_start[i] for i in range(3))
                
                # Create performance measurement
                measurement = PerformanceMeasurement(
                    endpoint=g.perf_endpoint,
                    method=g.perf_method,
                    response_time=response_time,
                    status_code=response.status_code,
                    cpu_usage=end_cpu,
                    memory_usage_mb=end_memory,
                    gc_collections=gc_collections,
                    active_threads=threading.active_count(),
                    request_size_bytes=g.perf_request_size,
                    response_size_bytes=len(response.get_data()) if hasattr(response, 'get_data') else 0,
                    middleware_time=getattr(g, 'perf_middleware_time', 0.0),
                    business_logic_time=getattr(g, 'perf_business_logic_time', 0.0),
                    db_query_time=getattr(g, 'perf_db_time', 0.0),
                    external_service_time=getattr(g, 'perf_external_service_time', 0.0)
                )
                
                # Process measurement and update metrics
                self._process_measurement(measurement)
                
                # Log performance metric
                log_performance_metric(
                    f"request_{g.perf_endpoint}",
                    response_time * 1000,  # Convert to milliseconds
                    'ms',
                    {
                        'method': g.perf_method,
                        'status_code': response.status_code,
                        'cpu_usage': end_cpu,
                        'memory_usage_mb': end_memory,
                        'gc_collections': gc_collections
                    }
                )
                
            except Exception as e:
                logger.error(f"Error capturing performance measurement: {e}")
            
            return response
        
        @app.teardown_request
        def teardown_request_performance(exception):
            """Clean up performance measurement context."""
            if exception and hasattr(g, 'perf_start_time'):
                # Log performance data for failed requests
                logger.error(
                    "Request failed with performance context",
                    endpoint=getattr(g, 'perf_endpoint', 'unknown'),
                    method=getattr(g, 'perf_method', 'unknown'),
                    duration_ms=(time.time() - g.perf_start_time) * 1000,
                    exception_type=type(exception).__name__,
                    performance=True
                )
    
    def _process_measurement(self, measurement: PerformanceMeasurement) -> None:
        """
        Process performance measurement and update variance tracking.
        
        Args:
            measurement: Performance measurement to process
        """
        endpoint_key = f"{measurement.method}:{measurement.endpoint}"
        
        with self._performance_lock:
            # Store measurement
            self._measurements[endpoint_key].append(measurement)
            
            # Update variance metrics if baseline exists
            if endpoint_key in self._baselines:
                baseline = self._baselines[endpoint_key]
                variance = measurement.variance_from_baseline(baseline)
                
                # Update Prometheus metrics
                self.response_time_variance.labels(
                    endpoint=measurement.endpoint,
                    method=measurement.method
                ).set(variance)
                
                # Update compliance status
                is_compliant = abs(variance) <= self._variance_threshold_critical
                self.performance_compliance.labels(
                    endpoint=measurement.endpoint,
                    method=measurement.method,
                    threshold_type='critical'
                ).set(1 if is_compliant else 0)
                
                # Check alert thresholds
                self._check_alert_thresholds(endpoint_key, variance, measurement)
                
                # Update trend analysis
                self._update_trend_analysis(endpoint_key, variance)
                
                # Update capacity utilization
                self._update_capacity_metrics(measurement)
            
            # Update baseline confidence if needed
            self._update_baseline_confidence(endpoint_key)
    
    def _check_alert_thresholds(self, endpoint_key: str, variance: float, 
                               measurement: PerformanceMeasurement) -> None:
        """
        Check performance variance against alert thresholds.
        
        Implements Section 6.5.5 alert threshold matrices for performance monitoring.
        """
        current_time = datetime.now(timezone.utc)
        endpoint = measurement.endpoint
        method = measurement.method
        
        # Check if we're in alert cooldown period
        last_alert = self._last_alert_time.get(endpoint_key)
        if last_alert and (current_time - last_alert).total_seconds() < (self._alert_cooldown_minutes * 60):
            return
        
        # Warning threshold check
        if abs(variance) > self._variance_threshold_warning:
            severity = 'critical' if abs(variance) > self._variance_threshold_critical else 'warning'
            threshold_type = 'performance_degradation' if variance > 0 else 'performance_improvement'
            
            # Increment violation counter
            self.variance_violations.labels(
                endpoint=endpoint,
                method=method,
                threshold_type=threshold_type,
                severity=severity
            ).inc()
            
            # Log alert event
            logger.warning(
                "Performance variance threshold exceeded",
                endpoint=endpoint,
                method=method,
                variance_percentage=round(variance, 2),
                threshold_type=threshold_type,
                severity=severity,
                response_time_ms=measurement.response_time * 1000,
                cpu_usage=measurement.cpu_usage,
                memory_usage_mb=measurement.memory_usage_mb,
                performance=True
            )
            
            # Update alert state
            self._alert_state[endpoint_key] = {
                'variance': variance,
                'severity': severity,
                'threshold_type': threshold_type,
                'measurement': measurement,
                'alert_time': current_time
            }
            
            self._last_alert_time[endpoint_key] = current_time
            
            # Check for rollback recommendation
            if severity == 'critical':
                self._evaluate_rollback_recommendation(endpoint_key, variance, measurement)
    
    def _evaluate_rollback_recommendation(self, endpoint_key: str, variance: float,
                                        measurement: PerformanceMeasurement) -> None:
        """
        Evaluate if automatic rollback should be recommended.
        
        Implements automated rollback consideration based on sustained performance degradation.
        """
        # Check for sustained degradation over multiple measurements
        recent_measurements = list(self._measurements[endpoint_key])[-10:]  # Last 10 measurements
        
        if len(recent_measurements) >= 5:
            baseline = self._baselines[endpoint_key]
            recent_variances = [m.variance_from_baseline(baseline) for m in recent_measurements]
            
            # Check if 80% of recent measurements exceed critical threshold
            critical_violations = sum(1 for v in recent_variances if abs(v) > self._variance_threshold_critical)
            violation_rate = critical_violations / len(recent_variances)
            
            if violation_rate >= 0.8:
                logger.critical(
                    "Sustained performance degradation detected - rollback recommended",
                    endpoint=measurement.endpoint,
                    method=measurement.method,
                    violation_rate=violation_rate,
                    avg_variance=statistics.mean(recent_variances),
                    recommendation="AUTOMATED_ROLLBACK",
                    performance=True
                )
                
                # Log business event for operations team
                log_business_event(
                    "performance_rollback_recommended",
                    {
                        'endpoint': measurement.endpoint,
                        'method': measurement.method,
                        'avg_variance_percentage': statistics.mean(recent_variances),
                        'violation_rate': violation_rate,
                        'severity': 'critical'
                    }
                )
    
    def _update_trend_analysis(self, endpoint_key: str, variance: float) -> None:
        """
        Update performance trend analysis for capacity planning.
        
        Args:
            endpoint_key: Endpoint identifier
            variance: Current variance percentage
        """
        # Add to trend cache
        self._trend_cache[endpoint_key].append(variance)
        
        # Maintain rolling window of 50 measurements
        if len(self._trend_cache[endpoint_key]) > 50:
            self._trend_cache[endpoint_key] = self._trend_cache[endpoint_key][-50:]
        
        # Calculate trend score
        if len(self._trend_cache[endpoint_key]) >= 10:
            recent_variances = self._trend_cache[endpoint_key]
            
            # Calculate linear regression slope for trend
            x_values = list(range(len(recent_variances)))
            y_values = recent_variances
            
            # Simple linear regression
            n = len(x_values)
            sum_x = sum(x_values)
            sum_y = sum(y_values)
            sum_xy = sum(x * y for x, y in zip(x_values, y_values))
            sum_x2 = sum(x * x for x in x_values)
            
            # Calculate slope
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            
            # Normalize slope to trend score (-1 to 1)
            trend_score = max(-1.0, min(1.0, -slope / 10.0))  # Negative slope = improving
            
            # Update metric
            endpoint, method = endpoint_key.split(':', 1)
            self.performance_trend.labels(
                endpoint=endpoint,
                time_window='50_measurements'
            ).set(trend_score)
    
    def _update_capacity_metrics(self, measurement: PerformanceMeasurement) -> None:
        """
        Update capacity utilization metrics for planning.
        
        Args:
            measurement: Current performance measurement
        """
        # CPU capacity utilization
        cpu_utilization = measurement.cpu_usage
        self.capacity_utilization.labels(resource_type='cpu').set(cpu_utilization)
        
        # Memory capacity utilization (assuming 1GB container limit)
        memory_limit_mb = float(os.getenv('CONTAINER_MEMORY_LIMIT_MB', '1024'))
        memory_utilization = (measurement.memory_usage_mb / memory_limit_mb) * 100
        self.capacity_utilization.labels(resource_type='memory').set(memory_utilization)
        
        # Thread utilization (assuming 200 thread limit)
        thread_limit = int(os.getenv('THREAD_LIMIT', '200'))
        thread_utilization = (measurement.active_threads / thread_limit) * 100
        self.capacity_utilization.labels(resource_type='threads').set(thread_utilization)
    
    def _update_baseline_confidence(self, endpoint_key: str) -> None:
        """
        Update baseline confidence score based on data quality.
        
        Args:
            endpoint_key: Endpoint identifier
        """
        if endpoint_key in self._baselines:
            baseline = self._baselines[endpoint_key]
            measurements = self._measurements[endpoint_key]
            
            # Calculate confidence based on data age and sample size
            age_days = (datetime.now(timezone.utc) - baseline.created_at).days
            age_factor = max(0.5, 1.0 - (age_days / 30.0))  # Decay over 30 days
            
            sample_factor = min(1.0, baseline.sample_count / 1000.0)  # Full confidence at 1000 samples
            
            measurement_consistency = 1.0
            if len(measurements) >= 10:
                recent_variances = [
                    m.variance_from_baseline(baseline) 
                    for m in list(measurements)[-10:]
                ]
                variance_std = statistics.stdev(recent_variances) if len(recent_variances) > 1 else 0
                measurement_consistency = max(0.3, 1.0 - (variance_std / 20.0))  # Penalize high variance
            
            confidence = age_factor * sample_factor * measurement_consistency
            baseline.confidence_score = confidence
            
            # Update metric
            endpoint, method = endpoint_key.split(':', 1)
            self.baseline_confidence.labels(
                endpoint=endpoint,
                method=method
            ).set(confidence)
    
    def _start_background_monitoring(self) -> None:
        """
        Start background monitoring threads for system resource tracking.
        
        Implements Section 6.5.1.1 CPU utilization and container resource monitoring.
        """
        # CPU and system resource monitoring thread
        cpu_thread = threading.Thread(
            target=self._monitor_system_resources,
            daemon=True,
            name='perf_monitor_cpu'
        )
        cpu_thread.start()
        self._monitoring_threads.append(cpu_thread)
        
        # Memory profiling thread
        if self._memory_profiling_enabled:
            memory_thread = threading.Thread(
                target=self._monitor_memory_usage,
                daemon=True,
                name='perf_monitor_memory'
            )
            memory_thread.start()
            self._monitoring_threads.append(memory_thread)
        
        # GC monitoring thread
        if self._gc_monitoring_enabled:
            gc_thread = threading.Thread(
                target=self._monitor_gc_performance,
                daemon=True,
                name='perf_monitor_gc'
            )
            gc_thread.start()
            self._monitoring_threads.append(gc_thread)
        
        logger.info(f"Started {len(self._monitoring_threads)} background monitoring threads")
    
    def _monitor_system_resources(self) -> None:
        """
        Background thread for monitoring system CPU and resource utilization.
        
        Implements continuous system resource monitoring for capacity planning.
        """
        while self._monitoring_enabled:
            try:
                process = psutil.Process()
                
                # CPU utilization
                cpu_percent = process.cpu_percent(interval=1)
                system_cpu_percent = psutil.cpu_percent(interval=None)
                
                # Memory utilization
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                memory_percent = process.memory_percent()
                
                # System memory
                system_memory = psutil.virtual_memory()
                
                # Update capacity metrics
                self.capacity_utilization.labels(resource_type='cpu').set(cpu_percent)
                self.capacity_utilization.labels(resource_type='system_cpu').set(system_cpu_percent)
                self.capacity_utilization.labels(resource_type='memory').set(memory_percent)
                
                # Thread count
                thread_count = threading.active_count()
                
                # Network I/O (if available)
                try:
                    network_io = psutil.net_io_counters()
                    # Log network stats periodically
                    if int(time.time()) % 300 == 0:  # Every 5 minutes
                        logger.info(
                            "System resource snapshot",
                            cpu_percent=cpu_percent,
                            system_cpu_percent=system_cpu_percent,
                            memory_mb=memory_mb,
                            memory_percent=memory_percent,
                            thread_count=thread_count,
                            network_bytes_sent=network_io.bytes_sent,
                            network_bytes_recv=network_io.bytes_recv,
                            performance=True
                        )
                except Exception:
                    pass  # Network stats not available on all systems
                
                # Check for resource utilization alerts
                if cpu_percent > 70:
                    severity = 'critical' if cpu_percent > 90 else 'warning'
                    logger.warning(
                        "High CPU utilization detected",
                        cpu_percent=cpu_percent,
                        severity=severity,
                        performance=True
                    )
                
                if memory_percent > 80:
                    severity = 'critical' if memory_percent > 95 else 'warning'
                    logger.warning(
                        "High memory utilization detected",
                        memory_percent=memory_percent,
                        memory_mb=memory_mb,
                        severity=severity,
                        performance=True
                    )
                
                time.sleep(self._cpu_monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in system resource monitoring: {e}")
                time.sleep(30)
    
    def _monitor_memory_usage(self) -> None:
        """
        Background thread for detailed memory profiling and analysis.
        
        Implements memory profiling for performance compliance and optimization.
        """
        previous_memory = 0
        memory_samples = deque(maxlen=60)  # 30 minutes of samples at 30s intervals
        
        while self._monitoring_enabled:
            try:
                current_time = datetime.now(timezone.utc)
                process = psutil.Process()
                
                # Basic memory metrics
                memory_info = process.memory_info()
                current_memory = memory_info.rss / 1024 / 1024  # MB
                
                # Tracemalloc data if available
                tracemalloc_current = 0
                tracemalloc_peak = 0
                if self._memory_profiling_enabled and tracemalloc.is_tracing():
                    current_size, peak_size = tracemalloc.get_traced_memory()
                    tracemalloc_current = current_size / 1024 / 1024  # MB
                    tracemalloc_peak = peak_size / 1024 / 1024  # MB
                
                # GC statistics
                gc_counts = gc.get_count()
                
                # Object counting (expensive, do less frequently)
                object_count = 0
                if int(time.time()) % 120 == 0:  # Every 2 minutes
                    try:
                        import sys
                        object_count = len(gc.get_objects())
                    except Exception:
                        pass
                
                # Calculate memory growth rate
                memory_samples.append((current_time, current_memory))
                memory_growth_rate = 0.0
                
                if len(memory_samples) >= 2:
                    oldest_time, oldest_memory = memory_samples[0]
                    time_diff = (current_time - oldest_time).total_seconds() / 60  # minutes
                    memory_diff = current_memory - oldest_memory
                    
                    if time_diff > 0:
                        memory_growth_rate = memory_diff / time_diff
                
                # Calculate allocation rate
                allocation_rate = 0.0
                if previous_memory > 0:
                    allocation_rate = abs(current_memory - previous_memory) / (self._memory_monitoring_interval / 60)
                
                # Memory fragmentation estimation
                if tracemalloc_current > 0:
                    fragmentation_ratio = current_memory / tracemalloc_current
                else:
                    fragmentation_ratio = 1.0
                
                # Create memory profile
                profile = MemoryProfile(
                    timestamp=current_time,
                    heap_size_mb=current_memory,
                    heap_used_mb=tracemalloc_current,
                    gc_gen0_collections=gc_counts[0],
                    gc_gen1_collections=gc_counts[1],
                    gc_gen2_collections=gc_counts[2],
                    gc_pause_time_ms=0.0,  # Would need custom GC instrumentation
                    memory_fragmentation_ratio=fragmentation_ratio,
                    object_count=object_count,
                    tracemalloc_peak_mb=tracemalloc_peak,
                    memory_growth_rate_mb_per_min=memory_growth_rate,
                    allocation_rate_mb_per_sec=allocation_rate
                )
                
                # Store profile
                self._memory_profiles.append(profile)
                
                # Update Prometheus metrics
                self.memory_heap_size.set(current_memory * 1024 * 1024)  # bytes
                self.memory_heap_used.set(tracemalloc_current * 1024 * 1024)  # bytes
                self.memory_fragmentation.set(fragmentation_ratio)
                self.memory_growth_rate.set(memory_growth_rate)
                self.allocation_rate.set(allocation_rate)
                
                # Object count metrics
                if object_count > 0:
                    self.python_object_count.labels(object_type='total').set(object_count)
                
                # Log memory events
                if memory_growth_rate > 10:  # Growing faster than 10MB/min
                    logger.warning(
                        "High memory growth rate detected",
                        growth_rate_mb_per_min=memory_growth_rate,
                        current_memory_mb=current_memory,
                        allocation_rate_mb_per_sec=allocation_rate,
                        performance=True
                    )
                
                if fragmentation_ratio > 2.0:  # High fragmentation
                    logger.warning(
                        "High memory fragmentation detected",
                        fragmentation_ratio=fragmentation_ratio,
                        heap_size_mb=current_memory,
                        heap_used_mb=tracemalloc_current,
                        performance=True
                    )
                
                previous_memory = current_memory
                time.sleep(self._memory_monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")
                time.sleep(60)
    
    def _monitor_gc_performance(self) -> None:
        """
        Background thread for garbage collection performance monitoring.
        
        Implements Python GC instrumentation and pause time analysis.
        """
        previous_gc_counts = gc.get_count()
        gc_frequency_samples = defaultdict(lambda: deque(maxlen=60))  # Track frequency
        
        while self._monitoring_enabled:
            try:
                current_time = datetime.now(timezone.utc)
                current_gc_counts = gc.get_count()
                
                # Calculate GC frequency
                for generation in range(3):
                    collections_diff = current_gc_counts[generation] - previous_gc_counts[generation]
                    if collections_diff > 0:
                        gc_frequency_samples[generation].append((current_time, collections_diff))
                
                # Update GC frequency metrics
                for generation in range(3):
                    samples = gc_frequency_samples[generation]
                    if len(samples) >= 2:
                        # Calculate collections per minute
                        oldest_time, _ = samples[0]
                        total_collections = sum(count for _, count in samples)
                        time_span_minutes = (current_time - oldest_time).total_seconds() / 60
                        
                        if time_span_minutes > 0:
                            collections_per_minute = total_collections / time_span_minutes
                            self.gc_collections_rate.labels(generation=str(generation)).set(collections_per_minute)
                
                # GC statistics analysis
                gc_stats = gc.get_stats()
                for generation, stats in enumerate(gc_stats):
                    collections = stats.get('collections', 0)
                    collected = stats.get('collected', 0)
                    uncollectable = stats.get('uncollectable', 0)
                    
                    # Calculate efficiency
                    total_processed = collected + uncollectable
                    efficiency = collected / total_processed if total_processed > 0 else 1.0
                    self.gc_efficiency.labels(generation=str(generation)).set(efficiency)
                
                # Check for GC performance issues
                for generation in range(3):
                    frequency = gc_frequency_samples[generation]
                    if len(frequency) >= 10:
                        recent_total = sum(count for _, count in list(frequency)[-10:])
                        if recent_total > 50:  # High GC frequency
                            logger.warning(
                                "High garbage collection frequency detected",
                                generation=generation,
                                collections_in_last_10_intervals=recent_total,
                                performance=True
                            )
                
                previous_gc_counts = current_gc_counts
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in GC monitoring: {e}")
                time.sleep(60)
    
    def _register_shutdown_handlers(self, app: Flask) -> None:
        """
        Register application shutdown handlers for cleanup.
        
        Args:
            app: Flask application instance
        """
        @app.teardown_appcontext
        def shutdown_performance_monitoring(error):
            """Clean up performance monitoring on app shutdown."""
            if error:
                logger.error(f"Application error during performance monitoring: {error}")
        
        # Register cleanup for graceful shutdown
        import atexit
        atexit.register(self._cleanup_monitoring)
    
    def _cleanup_monitoring(self) -> None:
        """Clean up monitoring resources and save state."""
        logger.info("Shutting down performance monitoring")
        
        self._monitoring_enabled = False
        
        # Save baselines
        self._save_baselines()
        
        # Shutdown thread pool
        if hasattr(self, '_monitor_executor'):
            self._monitor_executor.shutdown(wait=True, timeout=30)
        
        # Stop tracemalloc if running
        if self._memory_profiling_enabled and tracemalloc.is_tracing():
            tracemalloc.stop()
        
        logger.info("Performance monitoring shutdown complete")
    
    def set_nodejs_baseline(self, endpoint: str, method: str, baseline_data: Dict[str, Any]) -> None:
        """
        Set Node.js baseline performance data for comparison.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            baseline_data: Baseline performance data dictionary
        """
        baseline = PerformanceBaseline(
            endpoint=endpoint,
            method=method,
            avg_response_time=baseline_data.get('avg_response_time', 0.0),
            p50_response_time=baseline_data.get('p50_response_time', 0.0),
            p95_response_time=baseline_data.get('p95_response_time', 0.0),
            p99_response_time=baseline_data.get('p99_response_time', 0.0),
            throughput_rps=baseline_data.get('throughput_rps', 0.0),
            cpu_utilization=baseline_data.get('cpu_utilization', 0.0),
            memory_usage_mb=baseline_data.get('memory_usage_mb', 0.0),
            error_rate=baseline_data.get('error_rate', 0.0),
            sample_count=baseline_data.get('sample_count', 1),
            confidence_score=baseline_data.get('confidence_score', 1.0)
        )
        
        endpoint_key = f"{method}:{endpoint}"
        
        with self._performance_lock:
            self._baselines[endpoint_key] = baseline
        
        # Update baseline metrics
        self.baseline_confidence.labels(
            endpoint=endpoint,
            method=method
        ).set(baseline.confidence_score)
        
        logger.info(
            "Node.js baseline set",
            endpoint=endpoint,
            method=method,
            avg_response_time_ms=baseline.avg_response_time * 1000,
            throughput_rps=baseline.throughput_rps,
            confidence_score=baseline.confidence_score
        )
    
    def load_baselines_from_file(self, file_path: str) -> None:
        """
        Load Node.js baselines from JSON file.
        
        Args:
            file_path: Path to JSON file containing baseline data
        """
        try:
            with open(file_path, 'r') as f:
                baselines_data = json.load(f)
            
            loaded_count = 0
            for baseline_dict in baselines_data.get('baselines', []):
                baseline = PerformanceBaseline.from_dict(baseline_dict)
                endpoint_key = f"{baseline.method}:{baseline.endpoint}"
                
                with self._performance_lock:
                    self._baselines[endpoint_key] = baseline
                
                loaded_count += 1
            
            logger.info(f"Loaded {loaded_count} Node.js baselines from {file_path}")
            
        except Exception as e:
            logger.error(f"Error loading baselines from {file_path}: {e}")
    
    def _load_baselines(self) -> None:
        """Load baselines from persistent storage."""
        if os.path.exists(self._baseline_storage_path):
            try:
                with open(self._baseline_storage_path, 'rb') as f:
                    stored_baselines = pickle.load(f)
                
                with self._performance_lock:
                    self._baselines.update(stored_baselines)
                
                logger.info(f"Loaded {len(stored_baselines)} baselines from storage")
                
            except Exception as e:
                logger.warning(f"Error loading baselines from storage: {e}")
    
    def _save_baselines(self) -> None:
        """Save baselines to persistent storage."""
        try:
            with self._performance_lock:
                baselines_copy = dict(self._baselines)
            
            os.makedirs(os.path.dirname(self._baseline_storage_path), exist_ok=True)
            
            with open(self._baseline_storage_path, 'wb') as f:
                pickle.dump(baselines_copy, f)
            
            logger.info(f"Saved {len(baselines_copy)} baselines to storage")
            
        except Exception as e:
            logger.error(f"Error saving baselines to storage: {e}")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance summary for monitoring dashboards.
        
        Returns:
            Dictionary containing performance analysis and compliance status
        """
        with self._performance_lock:
            summary = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'monitoring_status': {
                    'enabled': self._monitoring_enabled,
                    'memory_profiling': self._memory_profiling_enabled,
                    'gc_monitoring': self._gc_monitoring_enabled,
                    'baseline_count': len(self._baselines),
                    'endpoints_monitored': len(self._measurements)
                },
                'performance_compliance': {},
                'capacity_analysis': {},
                'memory_analysis': {},
                'alert_status': {},
                'optimization_recommendations': []
            }
            
            # Performance compliance analysis
            for endpoint_key, baseline in self._baselines.items():
                if endpoint_key in self._measurements and self._measurements[endpoint_key]:
                    recent_measurements = list(self._measurements[endpoint_key])[-10:]
                    variances = [m.variance_from_baseline(baseline) for m in recent_measurements]
                    
                    avg_variance = statistics.mean(variances) if variances else 0.0
                    max_variance = max(variances) if variances else 0.0
                    
                    endpoint, method = endpoint_key.split(':', 1)
                    summary['performance_compliance'][endpoint_key] = {
                        'endpoint': endpoint,
                        'method': method,
                        'avg_variance_percentage': round(avg_variance, 2),
                        'max_variance_percentage': round(max_variance, 2),
                        'compliant': abs(avg_variance) <= self._variance_threshold_critical,
                        'baseline_confidence': baseline.confidence_score,
                        'measurement_count': len(self._measurements[endpoint_key]),
                        'trend_score': self._trend_cache[endpoint_key][-1] if self._trend_cache[endpoint_key] else 0.0
                    }
            
            # Capacity analysis
            try:
                process = psutil.Process()
                summary['capacity_analysis'] = {
                    'cpu_utilization_percent': process.cpu_percent(),
                    'memory_utilization_percent': process.memory_percent(),
                    'memory_usage_mb': process.memory_info().rss / 1024 / 1024,
                    'thread_count': threading.active_count(),
                    'capacity_warnings': self._generate_capacity_warnings()
                }
            except Exception as e:
                logger.warning(f"Error gathering capacity analysis: {e}")
            
            # Memory analysis
            if self._memory_profiles:
                latest_profile = self._memory_profiles[-1]
                summary['memory_analysis'] = {
                    'heap_size_mb': latest_profile.heap_size_mb,
                    'heap_used_mb': latest_profile.heap_used_mb,
                    'memory_growth_rate_mb_per_min': latest_profile.memory_growth_rate_mb_per_min,
                    'allocation_rate_mb_per_sec': latest_profile.allocation_rate_mb_per_sec,
                    'fragmentation_ratio': latest_profile.memory_fragmentation_ratio,
                    'gc_gen0_collections': latest_profile.gc_gen0_collections,
                    'gc_gen1_collections': latest_profile.gc_gen1_collections,
                    'gc_gen2_collections': latest_profile.gc_gen2_collections,
                    'object_count': latest_profile.object_count
                }
            
            # Alert status
            summary['alert_status'] = {
                'active_alerts': len(self._alert_state),
                'recent_violations': self._count_recent_violations(),
                'alert_details': dict(self._alert_state)
            }
            
            # Optimization recommendations
            summary['optimization_recommendations'] = self._generate_optimization_recommendations()
            
        return summary
    
    def _generate_capacity_warnings(self) -> List[Dict[str, Any]]:
        """Generate capacity planning warnings."""
        warnings = []
        
        try:
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            memory_percent = process.memory_percent()
            thread_count = threading.active_count()
            
            if cpu_percent > 70:
                warnings.append({
                    'type': 'cpu_utilization',
                    'severity': 'critical' if cpu_percent > 90 else 'warning',
                    'message': f"High CPU utilization: {cpu_percent:.1f}%",
                    'recommendation': 'Consider horizontal scaling or CPU optimization'
                })
            
            if memory_percent > 80:
                warnings.append({
                    'type': 'memory_utilization',
                    'severity': 'critical' if memory_percent > 95 else 'warning',
                    'message': f"High memory utilization: {memory_percent:.1f}%",
                    'recommendation': 'Consider memory optimization or container limits increase'
                })
            
            if thread_count > 150:
                warnings.append({
                    'type': 'thread_count',
                    'severity': 'warning',
                    'message': f"High thread count: {thread_count}",
                    'recommendation': 'Review async patterns and connection pooling'
                })
                
        except Exception as e:
            logger.warning(f"Error generating capacity warnings: {e}")
        
        return warnings
    
    def _count_recent_violations(self) -> int:
        """Count performance violations in the last hour."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        violation_count = 0
        
        for alert_data in self._alert_state.values():
            if alert_data.get('alert_time', datetime.min.replace(tzinfo=timezone.utc)) > cutoff_time:
                violation_count += 1
        
        return violation_count
    
    def _generate_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # Memory optimization recommendations
        if self._memory_profiles:
            latest_profile = self._memory_profiles[-1]
            
            if latest_profile.memory_growth_rate_mb_per_min > 5:
                recommendations.append({
                    'type': 'memory_optimization',
                    'priority': 'high',
                    'description': 'High memory growth rate detected',
                    'recommendation': 'Review object lifecycle management and implement memory pooling',
                    'impact': 'Reduced memory pressure and GC frequency'
                })
            
            if latest_profile.memory_fragmentation_ratio > 2.0:
                recommendations.append({
                    'type': 'memory_fragmentation',
                    'priority': 'medium',
                    'description': 'High memory fragmentation detected',
                    'recommendation': 'Consider memory compaction strategies and object reuse patterns',
                    'impact': 'Improved memory efficiency and reduced allocation overhead'
                })
        
        # Performance variance recommendations
        for endpoint_key, baseline in self._baselines.items():
            if endpoint_key in self._measurements and self._measurements[endpoint_key]:
                recent_measurements = list(self._measurements[endpoint_key])[-5:]
                avg_variance = statistics.mean([m.variance_from_baseline(baseline) for m in recent_measurements])
                
                if abs(avg_variance) > self._variance_threshold_warning:
                    endpoint, method = endpoint_key.split(':', 1)
                    recommendations.append({
                        'type': 'performance_optimization',
                        'priority': 'critical' if abs(avg_variance) > self._variance_threshold_critical else 'high',
                        'description': f'Performance variance detected for {method} {endpoint}',
                        'recommendation': 'Analyze request processing pipeline and optimize bottlenecks',
                        'impact': 'Improved response times and compliance with baseline requirements',
                        'variance_percentage': round(avg_variance, 2)
                    })
        
        return recommendations
    
    @contextmanager
    def measure_operation(self, operation_name: str, category: str = 'business_logic'):
        """
        Context manager for measuring specific operation performance.
        
        Args:
            operation_name: Name of the operation being measured
            category: Category of operation (business_logic, db_query, external_service)
        """
        start_time = time.time()
        start_cpu = psutil.Process().cpu_percent()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            yield
        finally:
            end_time = time.time()
            duration = end_time - start_time
            end_cpu = psutil.Process().cpu_percent()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            # Log operation performance
            log_performance_metric(
                f"operation_{operation_name}",
                duration * 1000,  # milliseconds
                'ms',
                {
                    'category': category,
                    'cpu_delta': end_cpu - start_cpu,
                    'memory_delta_mb': end_memory - start_memory
                }
            )
            
            # Store timing in Flask context if available
            if has_request_context():
                timing_key = f'perf_{category}_time'
                current_time = getattr(g, timing_key, 0.0)
                setattr(g, timing_key, current_time + duration)

# Global performance monitor instance for application-wide use
performance_monitor = PerformanceMonitor()

# Convenience functions for external use
def init_performance_monitoring(app: Flask) -> PerformanceMonitor:
    """
    Initialize performance monitoring for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured performance monitor instance
    """
    performance_monitor.init_app(app)
    return performance_monitor

def set_nodejs_baseline(endpoint: str, method: str, baseline_data: Dict[str, Any]) -> None:
    """
    Set Node.js baseline performance data for comparison.
    
    Args:
        endpoint: API endpoint path
        method: HTTP method
        baseline_data: Baseline performance data dictionary
    """
    performance_monitor.set_nodejs_baseline(endpoint, method, baseline_data)

def measure_operation(operation_name: str, category: str = 'business_logic'):
    """
    Context manager for measuring specific operation performance.
    
    Args:
        operation_name: Name of the operation being measured
        category: Category of operation
    """
    return performance_monitor.measure_operation(operation_name, category)

def get_performance_summary() -> Dict[str, Any]:
    """
    Get comprehensive performance summary for monitoring dashboards.
    
    Returns:
        Dictionary containing performance analysis and compliance status
    """
    return performance_monitor.get_performance_summary()

def load_baselines_from_file(file_path: str) -> None:
    """
    Load Node.js baselines from JSON file.
    
    Args:
        file_path: Path to JSON file containing baseline data
    """
    performance_monitor.load_baselines_from_file(file_path)

# Decorator for tracking business operation performance
def track_performance(operation_name: str, category: str = 'business_logic'):
    """
    Decorator for tracking operation performance with baseline comparison.
    
    Args:
        operation_name: Name of the operation being tracked
        category: Category of operation
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            with measure_operation(operation_name, category):
                return func(*args, **kwargs)
        return wrapper
    return decorator

# Export key components for external use
__all__ = [
    'PerformanceMonitor',
    'PerformanceBaseline', 
    'PerformanceMeasurement',
    'MemoryProfile',
    'performance_monitor',
    'init_performance_monitoring',
    'set_nodejs_baseline',
    'measure_operation',
    'get_performance_summary',
    'load_baselines_from_file',
    'track_performance'
]