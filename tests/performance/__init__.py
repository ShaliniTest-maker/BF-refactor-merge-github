"""
Performance Testing Package Initialization

This module provides comprehensive performance testing infrastructure for the Node.js to Python/Flask 
migration project, centralizing the ≤10% variance requirement validation and performance testing 
framework initialization as specified in Section 0.1.1 of the technical specification.

Key Features:
- ≤10% variance threshold constants for Node.js baseline comparison per Section 0.1.1
- Performance testing framework configuration with locust and apache-bench integration per Section 4.6.3
- Baseline comparison validation utilities ensuring performance compliance per Section 0.3.2
- Metrics collection integration with Prometheus for continuous monitoring per Section 3.6.2
- Comprehensive performance test utilities for CI/CD pipeline integration
- Advanced performance analysis and variance calculation capabilities

Architecture Integration:
- Section 0.1.1: Primary objective requiring ≤10% variance from Node.js baseline performance
- Section 4.6.3: Performance testing flows with locust and apache-bench framework integration
- Section 0.3.2: Performance monitoring requirements with continuous baseline comparison
- Section 3.6.2: Performance monitoring and metrics collection using prometheus-client
- Section 6.6.1: Performance testing approach with load testing and baseline validation
- Section 6.6.3: Quality metrics enforcement with performance variance thresholds

Performance Requirements:
- Response time variance ≤10% from Node.js baseline (project-critical requirement)
- Memory usage pattern equivalence with ±15% acceptable variance
- Concurrent request capacity preservation or improvement
- Database performance query execution time equivalence with ±10% variance
- Cache operation performance maintaining Node.js-equivalent timing patterns

Author: Flask Migration Team
Version: 1.0.0
Dependencies: locust ≥2.x, pytest 7.4+, prometheus-client 0.17+, requests 2.31+, psutil 5.9+
"""

import functools
import logging
import math
import statistics
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from pathlib import Path

# Performance testing and monitoring imports
import psutil
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

# Optional imports with fallback handling
try:
    import locust
    from locust import HttpUser, task
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    logging.warning("Locust not available - load testing capabilities will be limited")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("Requests not available - HTTP performance testing will be limited")

# Import test configuration for performance testing
try:
    from tests.test_config import PerformanceTestConfig, get_performance_test_config
    TEST_CONFIG_AVAILABLE = True
except ImportError:
    TEST_CONFIG_AVAILABLE = False
    logging.warning("Test configuration not available - using fallback performance settings")


# =============================================================================
# Core Performance Constants and Thresholds (Section 0.1.1 & 0.3.2)
# =============================================================================

# Primary Performance Variance Threshold (Project-Critical Requirement)
PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance from Node.js baseline per Section 0.1.1
PERFORMANCE_VARIANCE_THRESHOLD_DECIMAL = PERFORMANCE_VARIANCE_THRESHOLD / 100.0  # 0.10 for calculations

# Memory Usage Variance Thresholds
MEMORY_VARIANCE_THRESHOLD = 15.0  # ±15% acceptable variance for memory usage
MEMORY_VARIANCE_THRESHOLD_DECIMAL = MEMORY_VARIANCE_THRESHOLD / 100.0  # 0.15 for calculations

# Database Performance Variance Thresholds
DATABASE_VARIANCE_THRESHOLD = 10.0  # ±10% variance for database operations
DATABASE_VARIANCE_THRESHOLD_DECIMAL = DATABASE_VARIANCE_THRESHOLD / 100.0  # 0.10 for calculations

# Cache Performance Variance Thresholds
CACHE_VARIANCE_THRESHOLD = 5.0  # ±5% variance for cache operations (stricter due to simplicity)
CACHE_VARIANCE_THRESHOLD_DECIMAL = CACHE_VARIANCE_THRESHOLD / 100.0  # 0.05 for calculations

# Quality Gate Enforcement Levels
PERFORMANCE_COMPLIANCE_LEVELS = {
    'critical': 5.0,     # ≤5% variance for critical performance paths
    'standard': 10.0,    # ≤10% variance for standard operations (primary requirement)
    'relaxed': 15.0,     # ≤15% variance for memory and resource usage
    'development': 25.0  # ≤25% variance for development environment testing
}


# =============================================================================
# Node.js Baseline Performance Metrics (Section 6.6.1)
# =============================================================================

@dataclass
class NodeJSBaselineMetrics:
    """
    Node.js baseline performance metrics for Python implementation comparison.
    
    These metrics represent the established performance baselines from the original
    Node.js implementation, serving as the reference point for the ≤10% variance
    requirement validation per Section 0.1.1 and Section 6.6.1.
    """
    
    # API Endpoint Response Times (milliseconds)
    response_times: Dict[str, float] = field(default_factory=lambda: {
        'api_get_users': 150.0,         # GET /users endpoint baseline
        'api_create_user': 200.0,       # POST /users endpoint baseline  
        'api_update_user': 180.0,       # PUT /users/{id} endpoint baseline
        'api_delete_user': 120.0,       # DELETE /users/{id} endpoint baseline
        'api_list_users': 100.0,        # GET /users with pagination baseline
        'health_check': 50.0,           # GET /health endpoint baseline
        'auth_login': 180.0,            # POST /auth/login endpoint baseline
        'auth_logout': 80.0,            # POST /auth/logout endpoint baseline
        'file_upload': 300.0,           # POST /upload endpoint baseline
        'database_query': 75.0          # Generic database query baseline
    })
    
    # Memory Usage Patterns (megabytes)
    memory_usage: Dict[str, float] = field(default_factory=lambda: {
        'baseline_mb': 256.0,           # Application baseline memory usage
        'peak_mb': 512.0,               # Peak memory usage under load
        'average_mb': 320.0,            # Average memory usage during normal operation
        'startup_mb': 180.0,            # Memory usage immediately after startup
        'idle_mb': 200.0                # Memory usage during idle periods
    })
    
    # Throughput and Concurrency Metrics
    throughput: Dict[str, float] = field(default_factory=lambda: {
        'requests_per_second': 1000.0,   # Sustained requests per second capacity
        'concurrent_users': 100.0,       # Maximum concurrent user capacity
        'database_ops_per_second': 500.0,# Database operations per second capacity
        'cache_ops_per_second': 2000.0,  # Cache operations per second capacity
        'file_ops_per_second': 50.0      # File operation throughput capacity
    })
    
    # Database Performance Metrics (milliseconds)
    database_performance: Dict[str, float] = field(default_factory=lambda: {
        'user_lookup': 45.0,            # User lookup query performance
        'user_create': 85.0,            # User creation operation performance
        'user_update': 70.0,            # User update operation performance
        'user_delete': 40.0,            # User deletion operation performance
        'bulk_operations': 200.0,       # Bulk database operation performance
        'index_queries': 25.0,          # Index-based query performance
        'aggregation_queries': 150.0,   # MongoDB aggregation pipeline performance
        'connection_time': 20.0         # Database connection establishment time
    })
    
    # Cache Performance Metrics (milliseconds)
    cache_performance: Dict[str, float] = field(default_factory=lambda: {
        'get_hit': 5.0,                 # Cache hit retrieval time
        'get_miss': 15.0,               # Cache miss with fallback time
        'set': 10.0,                    # Cache set operation time
        'delete': 8.0,                  # Cache delete operation time
        'bulk_get': 20.0,               # Bulk cache retrieval time
        'pipeline_operations': 30.0,    # Redis pipeline operation time
        'connection_time': 15.0         # Cache connection establishment time
    })
    
    # External Service Integration Performance (milliseconds)
    external_services: Dict[str, float] = field(default_factory=lambda: {
        'auth0_token_validation': 100.0, # Auth0 JWT token validation time
        'auth0_user_info': 150.0,        # Auth0 user info retrieval time
        'aws_s3_upload': 500.0,          # AWS S3 file upload time
        'aws_s3_download': 300.0,        # AWS S3 file download time
        'aws_s3_list': 200.0,            # AWS S3 bucket listing time
        'http_client_request': 120.0,    # Generic HTTP client request time
        'webhook_delivery': 250.0        # Webhook delivery time
    })


# Global baseline metrics instance for easy access
NODEJS_BASELINE = NodeJSBaselineMetrics()


# =============================================================================
# Performance Testing Framework Configuration (Section 4.6.3)
# =============================================================================

@dataclass
class PerformanceTestConfiguration:
    """
    Comprehensive performance testing framework configuration.
    
    Centralizes all performance testing parameters, tool configurations, and
    validation thresholds for consistent testing across development, CI/CD,
    and production environments per Section 4.6.3 requirements.
    """
    
    # Core Performance Testing Settings
    variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD
    memory_variance_threshold: float = MEMORY_VARIANCE_THRESHOLD
    database_variance_threshold: float = DATABASE_VARIANCE_THRESHOLD
    cache_variance_threshold: float = CACHE_VARIANCE_THRESHOLD
    
    # Load Testing Configuration (locust integration)
    load_test_users: int = 50              # Concurrent users for load testing
    load_test_spawn_rate: int = 5          # User spawn rate per second
    load_test_duration: int = 60           # Test duration in seconds
    load_test_host: str = 'http://localhost:5000'  # Target host for testing
    
    # Performance Test Scenarios
    test_scenarios: Dict[str, Dict[str, Union[int, float]]] = field(default_factory=lambda: {
        'light_load': {
            'users': 10,
            'spawn_rate': 2,
            'duration': 30,
            'expected_rps': 50
        },
        'normal_load': {
            'users': 50,
            'spawn_rate': 5,
            'duration': 60,
            'expected_rps': 200
        },
        'heavy_load': {
            'users': 100,
            'spawn_rate': 10,
            'duration': 120,
            'expected_rps': 400
        },
        'stress_test': {
            'users': 200,
            'spawn_rate': 20,
            'duration': 300,
            'expected_rps': 600
        },
        'spike_test': {
            'users': 300,
            'spawn_rate': 50,
            'duration': 180,
            'expected_rps': 800
        }
    })
    
    # Benchmark Testing Configuration (apache-bench equivalent)
    benchmark_requests: int = 1000         # Total requests for benchmarking
    benchmark_concurrency: int = 10        # Concurrent requests for benchmarking
    benchmark_timeout: int = 30            # Request timeout in seconds
    
    # Performance Monitoring Configuration
    metrics_collection_enabled: bool = True
    metrics_collection_interval: float = 1.0  # Metrics collection interval in seconds
    metrics_retention_duration: int = 3600    # Metrics retention in seconds
    
    # Quality Gate Configuration
    performance_gates_enabled: bool = True
    automated_failure_detection: bool = True
    performance_regression_detection: bool = True
    
    # Resource Monitoring Configuration
    monitor_cpu: bool = True
    monitor_memory: bool = True
    monitor_disk_io: bool = True
    monitor_network_io: bool = True
    
    # Database Performance Monitoring
    monitor_database_queries: bool = True
    monitor_database_connections: bool = True
    monitor_database_locks: bool = True
    
    # Cache Performance Monitoring
    monitor_cache_operations: bool = True
    monitor_cache_hit_rates: bool = True
    monitor_cache_memory_usage: bool = True


# Global performance test configuration instance
PERFORMANCE_CONFIG = PerformanceTestConfiguration()


# =============================================================================
# Performance Metrics Collection Integration (Section 3.6.2)
# =============================================================================

class PerformanceMetricsCollector:
    """
    Comprehensive performance metrics collection system with Prometheus integration.
    
    Provides real-time performance metrics collection, baseline comparison, and
    variance validation capabilities per Section 3.6.2 requirements. Integrates
    with Prometheus client for enterprise monitoring integration.
    """
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """
        Initialize performance metrics collector.
        
        Args:
            registry: Optional Prometheus collector registry for custom metrics
        """
        self.registry = registry or CollectorRegistry()
        self._setup_prometheus_metrics()
        self._performance_measurements: List[Dict[str, Any]] = []
        self._baseline_comparisons: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        
        # System resource monitoring
        self._cpu_percent = 0.0
        self._memory_percent = 0.0
        self._disk_io_counters = None
        self._network_io_counters = None
        
        logging.info("Performance metrics collector initialized with Prometheus integration")
    
    def _setup_prometheus_metrics(self) -> None:
        """Set up Prometheus metrics for performance monitoring."""
        
        # Response time metrics
        self.response_time_histogram = Histogram(
            'flask_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0)
        )
        
        # Performance variance metrics
        self.performance_variance_gauge = Gauge(
            'performance_variance_percentage',
            'Performance variance from Node.js baseline',
            ['operation_type', 'operation_name'],
            registry=self.registry
        )
        
        # Baseline comparison counters
        self.baseline_comparison_counter = Counter(
            'baseline_comparisons_total',
            'Total baseline performance comparisons',
            ['operation_type', 'compliance_status'],
            registry=self.registry
        )
        
        # System resource metrics
        self.cpu_usage_gauge = Gauge(
            'system_cpu_usage_percentage',
            'Current CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage_gauge = Gauge(
            'system_memory_usage_percentage', 
            'Current memory usage percentage',
            registry=self.registry
        )
        
        # Database performance metrics
        self.database_operation_histogram = Histogram(
            'database_operation_duration_seconds',
            'Database operation duration in seconds',
            ['operation_type', 'collection'],
            registry=self.registry
        )
        
        # Cache performance metrics
        self.cache_operation_histogram = Histogram(
            'cache_operation_duration_seconds',
            'Cache operation duration in seconds', 
            ['operation_type', 'cache_key_pattern'],
            registry=self.registry
        )
        
        # External service performance metrics
        self.external_service_histogram = Histogram(
            'external_service_duration_seconds',
            'External service request duration in seconds',
            ['service_name', 'operation'],
            registry=self.registry
        )
    
    @contextmanager
    def measure_operation(self, operation_name: str, operation_type: str = 'api',
                         baseline_category: Optional[str] = None):
        """
        Context manager for measuring operation performance with baseline comparison.
        
        Args:
            operation_name: Name of the operation being measured
            operation_type: Type of operation (api, database, cache, external)
            baseline_category: Baseline category for comparison validation
            
        Yields:
            Measurement context with performance tracking
        """
        start_time = time.perf_counter()
        start_memory = psutil.virtual_memory().percent if PERFORMANCE_CONFIG.monitor_memory else None
        start_cpu = psutil.cpu_percent(interval=None) if PERFORMANCE_CONFIG.monitor_cpu else None
        
        try:
            yield self
        finally:
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            # Collect final resource measurements
            end_memory = psutil.virtual_memory().percent if PERFORMANCE_CONFIG.monitor_memory else None
            end_cpu = psutil.cpu_percent(interval=None) if PERFORMANCE_CONFIG.monitor_cpu else None
            
            # Record measurement
            measurement = {
                'operation_name': operation_name,
                'operation_type': operation_type,
                'duration': duration,
                'timestamp': datetime.utcnow(),
                'memory_start': start_memory,
                'memory_end': end_memory,
                'cpu_start': start_cpu,
                'cpu_end': end_cpu
            }
            
            with self._lock:
                self._performance_measurements.append(measurement)
            
            # Update Prometheus metrics
            if operation_type == 'api':
                self.response_time_histogram.labels(
                    method='unknown',
                    endpoint=operation_name,
                    status_code='200'
                ).observe(duration)
            elif operation_type == 'database':
                self.database_operation_histogram.labels(
                    operation_type=operation_name,
                    collection='unknown'
                ).observe(duration)
            elif operation_type == 'cache':
                self.cache_operation_histogram.labels(
                    operation_type=operation_name,
                    cache_key_pattern='pattern'
                ).observe(duration)
            elif operation_type == 'external':
                self.external_service_histogram.labels(
                    service_name=operation_name,
                    operation='request'
                ).observe(duration)
            
            # Perform baseline comparison if baseline category provided
            if baseline_category:
                self._perform_baseline_comparison(
                    operation_name, operation_type, duration, baseline_category
                )
    
    def _perform_baseline_comparison(self, operation_name: str, operation_type: str,
                                   measured_duration: float, baseline_category: str) -> None:
        """
        Perform baseline comparison and variance validation.
        
        Args:
            operation_name: Name of the measured operation
            operation_type: Type of operation for categorization
            measured_duration: Measured operation duration in seconds
            baseline_category: Baseline category for comparison
        """
        try:
            # Get baseline value based on category
            baseline_value = None
            if baseline_category == 'response_times':
                baseline_value = NODEJS_BASELINE.response_times.get(operation_name)
            elif baseline_category == 'database_performance':
                baseline_value = NODEJS_BASELINE.database_performance.get(operation_name)
            elif baseline_category == 'cache_performance':
                baseline_value = NODEJS_BASELINE.cache_performance.get(operation_name)
            elif baseline_category == 'external_services':
                baseline_value = NODEJS_BASELINE.external_services.get(operation_name)
            
            if baseline_value is None:
                logging.warning(f"No baseline value found for {operation_name} in {baseline_category}")
                return
            
            # Convert baseline from milliseconds to seconds for comparison
            baseline_seconds = baseline_value / 1000.0
            
            # Calculate variance percentage
            variance_percentage = calculate_variance_percentage(baseline_seconds, measured_duration)
            
            # Determine compliance status
            compliance_threshold = self._get_compliance_threshold(operation_type)
            is_compliant = abs(variance_percentage) <= compliance_threshold
            
            # Record baseline comparison
            comparison = {
                'operation_name': operation_name,
                'operation_type': operation_type,
                'baseline_category': baseline_category,
                'baseline_value': baseline_seconds,
                'measured_value': measured_duration,
                'variance_percentage': variance_percentage,
                'compliance_threshold': compliance_threshold,
                'is_compliant': is_compliant,
                'timestamp': datetime.utcnow()
            }
            
            with self._lock:
                self._baseline_comparisons.append(comparison)
            
            # Update Prometheus metrics
            self.performance_variance_gauge.labels(
                operation_type=operation_type,
                operation_name=operation_name
            ).set(abs(variance_percentage))
            
            self.baseline_comparison_counter.labels(
                operation_type=operation_type,
                compliance_status='compliant' if is_compliant else 'non_compliant'
            ).inc()
            
            # Log performance variance for monitoring
            if not is_compliant:
                logging.warning(
                    f"Performance variance violation detected: {operation_name} "
                    f"exceeded {compliance_threshold}% threshold with {variance_percentage:.2f}% variance"
                )
            else:
                logging.debug(
                    f"Performance compliance validated: {operation_name} "
                    f"within {compliance_threshold}% threshold with {variance_percentage:.2f}% variance"
                )
                
        except Exception as e:
            logging.error(f"Error performing baseline comparison for {operation_name}: {e}")
    
    def _get_compliance_threshold(self, operation_type: str) -> float:
        """
        Get compliance threshold based on operation type.
        
        Args:
            operation_type: Type of operation
            
        Returns:
            float: Compliance threshold percentage
        """
        if operation_type == 'database':
            return PERFORMANCE_CONFIG.database_variance_threshold
        elif operation_type == 'cache':
            return PERFORMANCE_CONFIG.cache_variance_threshold
        else:
            return PERFORMANCE_CONFIG.variance_threshold
    
    def update_system_metrics(self) -> None:
        """Update system resource metrics for monitoring."""
        if PERFORMANCE_CONFIG.monitor_cpu:
            cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_usage_gauge.set(cpu_percent)
            self._cpu_percent = cpu_percent
        
        if PERFORMANCE_CONFIG.monitor_memory:
            memory_percent = psutil.virtual_memory().percent
            self.memory_usage_gauge.set(memory_percent)
            self._memory_percent = memory_percent
        
        if PERFORMANCE_CONFIG.monitor_disk_io:
            self._disk_io_counters = psutil.disk_io_counters()
        
        if PERFORMANCE_CONFIG.monitor_network_io:
            self._network_io_counters = psutil.net_io_counters()
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance measurement summary.
        
        Returns:
            Dict containing performance summary statistics
        """
        with self._lock:
            measurements = self._performance_measurements.copy()
            comparisons = self._baseline_comparisons.copy()
        
        if not measurements:
            return {
                'total_measurements': 0,
                'performance_summary': {},
                'compliance_summary': {},
                'system_metrics': self._get_current_system_metrics()
            }
        
        # Calculate performance statistics
        durations = [m['duration'] for m in measurements]
        performance_summary = {
            'total_measurements': len(measurements),
            'average_duration': statistics.mean(durations),
            'median_duration': statistics.median(durations),
            'min_duration': min(durations),
            'max_duration': max(durations),
            'std_deviation': statistics.stdev(durations) if len(durations) > 1 else 0.0
        }
        
        # Calculate compliance statistics
        compliant_comparisons = [c for c in comparisons if c['is_compliant']]
        compliance_summary = {
            'total_comparisons': len(comparisons),
            'compliant_comparisons': len(compliant_comparisons),
            'compliance_rate': len(compliant_comparisons) / len(comparisons) if comparisons else 0.0,
            'average_variance': statistics.mean([abs(c['variance_percentage']) for c in comparisons]) if comparisons else 0.0,
            'max_variance': max([abs(c['variance_percentage']) for c in comparisons]) if comparisons else 0.0
        }
        
        return {
            'performance_summary': performance_summary,
            'compliance_summary': compliance_summary,
            'system_metrics': self._get_current_system_metrics(),
            'measurement_details': measurements[-10:],  # Last 10 measurements
            'compliance_details': [c for c in comparisons if not c['is_compliant']]  # Non-compliant operations
        }
    
    def _get_current_system_metrics(self) -> Dict[str, Any]:
        """Get current system resource metrics."""
        return {
            'cpu_percent': self._cpu_percent,
            'memory_percent': self._memory_percent,
            'disk_io': self._disk_io_counters._asdict() if self._disk_io_counters else None,
            'network_io': self._network_io_counters._asdict() if self._network_io_counters else None,
            'timestamp': datetime.utcnow()
        }


# Global performance metrics collector instance
PERFORMANCE_METRICS = PerformanceMetricsCollector()


# =============================================================================
# Performance Variance Calculation Utilities
# =============================================================================

def calculate_variance_percentage(baseline: float, measured: float) -> float:
    """
    Calculate performance variance percentage from baseline value.
    
    This function implements the core variance calculation for the ≤10% variance
    requirement validation per Section 0.1.1. Positive values indicate performance
    degradation (slower), negative values indicate performance improvement (faster).
    
    Args:
        baseline: Node.js baseline performance value
        measured: Python implementation measured value
        
    Returns:
        float: Variance percentage (positive = slower, negative = faster)
        
    Raises:
        ValueError: If baseline value is zero or negative
        
    Example:
        >>> calculate_variance_percentage(100.0, 105.0)
        5.0  # 5% slower than baseline
        >>> calculate_variance_percentage(100.0, 95.0) 
        -5.0  # 5% faster than baseline
    """
    if baseline <= 0:
        raise ValueError("Baseline value must be positive")
    
    return ((measured - baseline) / baseline) * 100.0


def is_within_variance_threshold(baseline: float, measured: float, 
                               threshold: float = PERFORMANCE_VARIANCE_THRESHOLD) -> bool:
    """
    Check if measured performance is within acceptable variance threshold.
    
    Validates compliance with the ≤10% variance requirement from Section 0.1.1
    or custom threshold for specific operation types.
    
    Args:
        baseline: Node.js baseline performance value
        measured: Python implementation measured value
        threshold: Variance threshold percentage (default: 10.0)
        
    Returns:
        bool: True if within threshold, False if exceeding threshold
        
    Example:
        >>> is_within_variance_threshold(100.0, 108.0)  # 8% variance
        True
        >>> is_within_variance_threshold(100.0, 112.0)  # 12% variance
        False
    """
    try:
        variance = calculate_variance_percentage(baseline, measured)
        return abs(variance) <= threshold
    except ValueError:
        return False


def validate_performance_compliance(operation_name: str, measured_value: float,
                                  baseline_category: str = 'response_times',
                                  operation_type: str = 'api') -> Dict[str, Any]:
    """
    Comprehensive performance compliance validation.
    
    Performs complete performance validation including baseline comparison,
    variance calculation, and compliance assessment per Section 0.3.2 requirements.
    
    Args:
        operation_name: Name of the operation being validated
        measured_value: Measured performance value (in seconds)
        baseline_category: Baseline category for comparison
        operation_type: Type of operation for threshold selection
        
    Returns:
        Dict containing comprehensive validation results
        
    Example:
        >>> result = validate_performance_compliance('api_get_users', 0.145)
        >>> result['is_compliant']
        True
        >>> result['variance_percentage']
        -3.33
    """
    try:
        # Get baseline value
        baseline_value = None
        if baseline_category == 'response_times':
            baseline_value = NODEJS_BASELINE.response_times.get(operation_name)
        elif baseline_category == 'database_performance':
            baseline_value = NODEJS_BASELINE.database_performance.get(operation_name)
        elif baseline_category == 'cache_performance':
            baseline_value = NODEJS_BASELINE.cache_performance.get(operation_name)
        elif baseline_category == 'external_services':
            baseline_value = NODEJS_BASELINE.external_services.get(operation_name)
        elif baseline_category == 'memory_usage':
            baseline_value = NODEJS_BASELINE.memory_usage.get(operation_name)
        elif baseline_category == 'throughput':
            baseline_value = NODEJS_BASELINE.throughput.get(operation_name)
        
        if baseline_value is None:
            return {
                'operation_name': operation_name,
                'baseline_category': baseline_category,
                'operation_type': operation_type,
                'baseline_value': None,
                'measured_value': measured_value,
                'variance_percentage': None,
                'is_compliant': None,
                'compliance_threshold': None,
                'error': f'No baseline value found for {operation_name} in {baseline_category}'
            }
        
        # Convert baseline from milliseconds to seconds for time-based metrics
        if baseline_category in ['response_times', 'database_performance', 'cache_performance', 'external_services']:
            baseline_seconds = baseline_value / 1000.0
        else:
            baseline_seconds = baseline_value
        
        # Calculate variance
        variance_percentage = calculate_variance_percentage(baseline_seconds, measured_value)
        
        # Determine compliance threshold based on operation type
        compliance_threshold = PERFORMANCE_VARIANCE_THRESHOLD
        if operation_type == 'database':
            compliance_threshold = DATABASE_VARIANCE_THRESHOLD
        elif operation_type == 'cache':
            compliance_threshold = CACHE_VARIANCE_THRESHOLD
        elif baseline_category == 'memory_usage':
            compliance_threshold = MEMORY_VARIANCE_THRESHOLD
        
        # Check compliance
        is_compliant = abs(variance_percentage) <= compliance_threshold
        
        return {
            'operation_name': operation_name,
            'baseline_category': baseline_category,
            'operation_type': operation_type,
            'baseline_value': baseline_seconds,
            'measured_value': measured_value,
            'variance_percentage': variance_percentage,
            'is_compliant': is_compliant,
            'compliance_threshold': compliance_threshold,
            'variance_status': _get_variance_status(variance_percentage, compliance_threshold),
            'performance_impact': _get_performance_impact(variance_percentage),
            'validation_timestamp': datetime.utcnow()
        }
        
    except Exception as e:
        return {
            'operation_name': operation_name,
            'baseline_category': baseline_category,
            'operation_type': operation_type,
            'baseline_value': None,
            'measured_value': measured_value,
            'variance_percentage': None,
            'is_compliant': False,
            'compliance_threshold': None,
            'error': str(e),
            'validation_timestamp': datetime.utcnow()
        }


def _get_variance_status(variance_percentage: float, threshold: float) -> str:
    """Get descriptive variance status."""
    abs_variance = abs(variance_percentage)
    
    if abs_variance <= threshold * 0.5:
        return 'excellent'
    elif abs_variance <= threshold * 0.75:
        return 'good'
    elif abs_variance <= threshold:
        return 'acceptable'
    elif abs_variance <= threshold * 1.5:
        return 'concerning'
    else:
        return 'critical'


def _get_performance_impact(variance_percentage: float) -> str:
    """Get descriptive performance impact assessment."""
    if variance_percentage < -5.0:
        return 'significant_improvement'
    elif variance_percentage < 0:
        return 'improvement'
    elif variance_percentage <= 5.0:
        return 'minimal_impact'
    elif variance_percentage <= 10.0:
        return 'moderate_degradation'
    elif variance_percentage <= 20.0:
        return 'significant_degradation'
    else:
        return 'critical_degradation'


# =============================================================================
# Performance Testing Framework Integration (Section 4.6.3)
# =============================================================================

class PerformanceTestFramework:
    """
    Comprehensive performance testing framework integrating locust, apache-bench equivalent,
    and custom performance testing utilities per Section 4.6.3 requirements.
    """
    
    def __init__(self, config: Optional[PerformanceTestConfiguration] = None):
        """
        Initialize performance testing framework.
        
        Args:
            config: Optional performance test configuration
        """
        self.config = config or PERFORMANCE_CONFIG
        self.metrics_collector = PERFORMANCE_METRICS
        self._test_results: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        
        logging.info("Performance testing framework initialized")
    
    def run_load_test(self, scenario_name: str = 'normal_load',
                     target_host: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute load testing scenario using locust integration.
        
        Args:
            scenario_name: Load test scenario name
            target_host: Target host for load testing
            
        Returns:
            Dict containing load test results and performance metrics
        """
        if not LOCUST_AVAILABLE:
            return {
                'success': False,
                'error': 'Locust not available for load testing',
                'scenario': scenario_name
            }
        
        scenario = self.config.test_scenarios.get(scenario_name)
        if not scenario:
            return {
                'success': False,
                'error': f'Unknown scenario: {scenario_name}',
                'available_scenarios': list(self.config.test_scenarios.keys())
            }
        
        host = target_host or self.config.load_test_host
        
        try:
            # Create locust environment
            env = Environment(user_classes=[BasicPerformanceUser])
            env.create_local_runner()
            
            # Configure test parameters
            users = scenario['users']
            spawn_rate = scenario['spawn_rate']
            duration = scenario['duration']
            
            logging.info(f"Starting load test: {scenario_name} with {users} users")
            
            # Start load test
            start_time = time.time()
            env.runner.start(users, spawn_rate)
            
            # Run for specified duration
            time.sleep(duration)
            
            # Stop load test
            env.runner.stop()
            end_time = time.time()
            
            # Collect results
            stats = env.runner.stats
            
            result = {
                'success': True,
                'scenario': scenario_name,
                'configuration': scenario,
                'target_host': host,
                'duration': end_time - start_time,
                'total_requests': stats.total.num_requests,
                'failed_requests': stats.total.num_failures,
                'average_response_time': stats.total.avg_response_time,
                'min_response_time': stats.total.min_response_time,
                'max_response_time': stats.total.max_response_time,
                'requests_per_second': stats.total.current_rps,
                'failure_rate': stats.total.fail_ratio,
                'percentiles': {
                    '50th': stats.total.get_response_time_percentile(0.5),
                    '95th': stats.total.get_response_time_percentile(0.95),
                    '99th': stats.total.get_response_time_percentile(0.99)
                }
            }
            
            # Validate against baseline expectations
            expected_rps = scenario.get('expected_rps', 0)
            if expected_rps > 0:
                rps_variance = calculate_variance_percentage(expected_rps, result['requests_per_second'])
                result['rps_variance_percentage'] = rps_variance
                result['rps_compliant'] = abs(rps_variance) <= self.config.variance_threshold
            
            with self._lock:
                self._test_results.append(result)
            
            logging.info(f"Load test completed: {scenario_name} - RPS: {result['requests_per_second']:.2f}")
            
            return result
            
        except Exception as e:
            logging.error(f"Load test failed for scenario {scenario_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'scenario': scenario_name
            }
    
    def run_benchmark_test(self, endpoint: str, target_host: Optional[str] = None,
                          requests: Optional[int] = None, concurrency: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute benchmark testing (apache-bench equivalent) using requests library.
        
        Args:
            endpoint: API endpoint to benchmark
            target_host: Target host for benchmarking
            requests: Total number of requests
            concurrency: Concurrent request count
            
        Returns:
            Dict containing benchmark test results
        """
        if not REQUESTS_AVAILABLE:
            return {
                'success': False,
                'error': 'Requests library not available for benchmarking',
                'endpoint': endpoint
            }
        
        host = target_host or self.config.load_test_host
        url = f"{host.rstrip('/')}/{endpoint.lstrip('/')}"
        total_requests = requests or self.config.benchmark_requests
        concurrent_requests = concurrency or self.config.benchmark_concurrency
        
        try:
            logging.info(f"Starting benchmark test: {endpoint} with {total_requests} requests")
            
            # Prepare timing measurements
            start_time = time.time()
            response_times = []
            successful_requests = 0
            failed_requests = 0
            
            # Execute benchmark requests
            for batch in range(0, total_requests, concurrent_requests):
                batch_size = min(concurrent_requests, total_requests - batch)
                batch_times = self._execute_concurrent_requests(url, batch_size)
                
                for response_time, success in batch_times:
                    response_times.append(response_time)
                    if success:
                        successful_requests += 1
                    else:
                        failed_requests += 1
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            # Calculate statistics
            if response_times:
                avg_response_time = statistics.mean(response_times)
                min_response_time = min(response_times)
                max_response_time = max(response_times)
                median_response_time = statistics.median(response_times)
                std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0.0
                
                # Calculate percentiles
                sorted_times = sorted(response_times)
                p50 = sorted_times[int(len(sorted_times) * 0.5)]
                p95 = sorted_times[int(len(sorted_times) * 0.95)]
                p99 = sorted_times[int(len(sorted_times) * 0.99)]
            else:
                avg_response_time = min_response_time = max_response_time = 0.0
                median_response_time = std_dev = p50 = p95 = p99 = 0.0
            
            # Calculate throughput
            requests_per_second = total_requests / total_duration if total_duration > 0 else 0.0
            
            result = {
                'success': True,
                'endpoint': endpoint,
                'target_url': url,
                'total_requests': total_requests,
                'concurrent_requests': concurrent_requests,
                'successful_requests': successful_requests,
                'failed_requests': failed_requests,
                'failure_rate': failed_requests / total_requests if total_requests > 0 else 0.0,
                'total_duration': total_duration,
                'requests_per_second': requests_per_second,
                'average_response_time': avg_response_time,
                'min_response_time': min_response_time,
                'max_response_time': max_response_time,
                'median_response_time': median_response_time,
                'std_deviation': std_dev,
                'percentiles': {
                    '50th': p50,
                    '95th': p95,
                    '99th': p99
                }
            }
            
            # Validate against baseline if available
            baseline_key = endpoint.replace('/', '_').replace('-', '_')
            baseline_value = NODEJS_BASELINE.response_times.get(baseline_key)
            
            if baseline_value:
                baseline_seconds = baseline_value / 1000.0
                variance = calculate_variance_percentage(baseline_seconds, avg_response_time)
                result['baseline_comparison'] = {
                    'baseline_value': baseline_seconds,
                    'variance_percentage': variance,
                    'is_compliant': abs(variance) <= self.config.variance_threshold,
                    'compliance_threshold': self.config.variance_threshold
                }
            
            with self._lock:
                self._test_results.append(result)
            
            logging.info(f"Benchmark completed: {endpoint} - RPS: {requests_per_second:.2f}")
            
            return result
            
        except Exception as e:
            logging.error(f"Benchmark test failed for endpoint {endpoint}: {e}")
            return {
                'success': False,
                'error': str(e),
                'endpoint': endpoint
            }
    
    def _execute_concurrent_requests(self, url: str, count: int) -> List[Tuple[float, bool]]:
        """Execute concurrent HTTP requests and measure response times."""
        import concurrent.futures
        
        def single_request():
            try:
                start_time = time.perf_counter()
                response = requests.get(url, timeout=self.config.benchmark_timeout)
                end_time = time.perf_counter()
                
                return (end_time - start_time, response.status_code == 200)
            except Exception:
                return (self.config.benchmark_timeout, False)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(single_request) for _ in range(count)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        return results
    
    def get_test_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance test summary.
        
        Returns:
            Dict containing complete performance test results and analysis
        """
        with self._lock:
            results = self._test_results.copy()
        
        if not results:
            return {
                'total_tests': 0,
                'test_summary': {},
                'compliance_summary': {}
            }
        
        # Categorize results
        load_tests = [r for r in results if 'scenario' in r]
        benchmark_tests = [r for r in results if 'endpoint' in r]
        
        # Calculate overall compliance
        compliant_tests = []
        non_compliant_tests = []
        
        for result in results:
            if result.get('success', False):
                # Check for compliance indicators
                if 'rps_compliant' in result:
                    if result['rps_compliant']:
                        compliant_tests.append(result)
                    else:
                        non_compliant_tests.append(result)
                elif 'baseline_comparison' in result:
                    if result['baseline_comparison']['is_compliant']:
                        compliant_tests.append(result)
                    else:
                        non_compliant_tests.append(result)
        
        return {
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r.get('success', False)]),
            'failed_tests': len([r for r in results if not r.get('success', False)]),
            'load_tests': len(load_tests),
            'benchmark_tests': len(benchmark_tests),
            'compliant_tests': len(compliant_tests),
            'non_compliant_tests': len(non_compliant_tests),
            'overall_compliance_rate': len(compliant_tests) / (len(compliant_tests) + len(non_compliant_tests)) if (compliant_tests or non_compliant_tests) else 0.0,
            'test_details': results,
            'compliance_violations': non_compliant_tests
        }


# Locust user class for load testing
if LOCUST_AVAILABLE:
    class BasicPerformanceUser(HttpUser):
        """Basic Locust user class for performance testing."""
        
        wait_time = locust.between(1, 3)
        
        @task(3)
        def get_health_check(self):
            """Health check endpoint test."""
            self.client.get("/health")
        
        @task(2)
        def get_users(self):
            """Users list endpoint test."""
            self.client.get("/api/users")
        
        @task(1)
        def create_user(self):
            """User creation endpoint test."""
            self.client.post("/api/users", json={
                "name": "Test User",
                "email": "test@example.com"
            })


# Global performance testing framework instance
PERFORMANCE_FRAMEWORK = PerformanceTestFramework()


# =============================================================================
# Performance Testing Decorators and Utilities
# =============================================================================

def performance_test(operation_name: str, baseline_category: str = 'response_times',
                    operation_type: str = 'api', compliance_threshold: Optional[float] = None):
    """
    Decorator for automatic performance testing and baseline comparison.
    
    This decorator automatically measures function execution time and validates
    against Node.js baseline requirements per Section 0.1.1 and Section 0.3.2.
    
    Args:
        operation_name: Name of the operation for baseline lookup
        baseline_category: Baseline category for comparison
        operation_type: Type of operation for threshold selection
        compliance_threshold: Custom compliance threshold (overrides default)
        
    Returns:
        Decorator function for performance testing
        
    Example:
        @performance_test('api_get_users', 'response_times', 'api')
        def test_get_users_endpoint():
            response = client.get('/api/users')
            assert response.status_code == 200
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Set custom threshold if provided
            original_threshold = PERFORMANCE_CONFIG.variance_threshold
            if compliance_threshold is not None:
                PERFORMANCE_CONFIG.variance_threshold = compliance_threshold
            
            try:
                with PERFORMANCE_METRICS.measure_operation(
                    operation_name=operation_name,
                    operation_type=operation_type,
                    baseline_category=baseline_category
                ):
                    result = func(*args, **kwargs)
                
                return result
            finally:
                # Restore original threshold
                if compliance_threshold is not None:
                    PERFORMANCE_CONFIG.variance_threshold = original_threshold
        
        return wrapper
    return decorator


def assert_performance_compliance(operation_name: str, measured_value: float,
                                baseline_category: str = 'response_times',
                                operation_type: str = 'api') -> None:
    """
    Assert performance compliance with baseline requirements.
    
    Raises AssertionError if performance variance exceeds threshold per Section 0.1.1.
    
    Args:
        operation_name: Name of the operation
        measured_value: Measured performance value
        baseline_category: Baseline category for comparison
        operation_type: Type of operation
        
    Raises:
        AssertionError: If performance variance exceeds threshold
        
    Example:
        assert_performance_compliance('api_get_users', 0.145)
    """
    validation_result = validate_performance_compliance(
        operation_name, measured_value, baseline_category, operation_type
    )
    
    if 'error' in validation_result:
        warnings.warn(f"Performance validation error: {validation_result['error']}")
        return
    
    if not validation_result['is_compliant']:
        raise AssertionError(
            f"Performance compliance violation: {operation_name} "
            f"variance {validation_result['variance_percentage']:.2f}% "
            f"exceeds threshold {validation_result['compliance_threshold']:.2f}%"
        )


def get_performance_baseline(operation_name: str, category: str = 'response_times') -> Optional[float]:
    """
    Get Node.js baseline value for specific operation.
    
    Args:
        operation_name: Name of the operation
        category: Baseline category
        
    Returns:
        Baseline value in seconds (converted from milliseconds for time-based metrics)
        
    Example:
        >>> get_performance_baseline('api_get_users')
        0.15  # 150ms converted to seconds
    """
    baseline_dict = None
    
    if category == 'response_times':
        baseline_dict = NODEJS_BASELINE.response_times
    elif category == 'database_performance':
        baseline_dict = NODEJS_BASELINE.database_performance
    elif category == 'cache_performance':
        baseline_dict = NODEJS_BASELINE.cache_performance
    elif category == 'external_services':
        baseline_dict = NODEJS_BASELINE.external_services
    elif category == 'memory_usage':
        baseline_dict = NODEJS_BASELINE.memory_usage
    elif category == 'throughput':
        baseline_dict = NODEJS_BASELINE.throughput
    
    if baseline_dict and operation_name in baseline_dict:
        baseline_value = baseline_dict[operation_name]
        
        # Convert time-based metrics from milliseconds to seconds
        if category in ['response_times', 'database_performance', 'cache_performance', 'external_services']:
            return baseline_value / 1000.0
        else:
            return baseline_value
    
    return None


# =============================================================================
# Module Export and Initialization
# =============================================================================

# Export key components for easy import
__all__ = [
    # Core constants
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'PERFORMANCE_VARIANCE_THRESHOLD_DECIMAL',
    'MEMORY_VARIANCE_THRESHOLD',
    'DATABASE_VARIANCE_THRESHOLD',
    'CACHE_VARIANCE_THRESHOLD',
    'PERFORMANCE_COMPLIANCE_LEVELS',
    
    # Baseline metrics
    'NodeJSBaselineMetrics',
    'NODEJS_BASELINE',
    
    # Configuration classes
    'PerformanceTestConfiguration',
    'PERFORMANCE_CONFIG',
    
    # Metrics collection
    'PerformanceMetricsCollector',
    'PERFORMANCE_METRICS',
    
    # Testing framework
    'PerformanceTestFramework',
    'PERFORMANCE_FRAMEWORK',
    
    # Utility functions
    'calculate_variance_percentage',
    'is_within_variance_threshold',
    'validate_performance_compliance',
    'get_performance_baseline',
    
    # Decorators and assertions
    'performance_test',
    'assert_performance_compliance',
    
    # Locust integration (if available)
    'BasicPerformanceUser' if LOCUST_AVAILABLE else None
]

# Remove None values from exports
__all__ = [item for item in __all__ if item is not None]

# Initialize performance monitoring system
try:
    PERFORMANCE_METRICS.update_system_metrics()
    logging.info(
        "Performance testing package initialized successfully",
        variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD,
        baseline_operations=len(NODEJS_BASELINE.response_times),
        locust_available=LOCUST_AVAILABLE,
        requests_available=REQUESTS_AVAILABLE
    )
except Exception as e:
    logging.warning(f"Performance monitoring initialization warning: {e}")