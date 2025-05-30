"""
Performance testing package initialization providing module-level constants, baseline thresholds, 
and performance test configuration for the Flask application migration from Node.js.

This module centralizes the ≤10% variance requirement validation per Section 0.1.1 primary objective
and performance testing framework initialization per Section 4.6.3 performance testing flows.

Key Features:
- ≤10% variance threshold constant per Section 0.1.1 primary objective
- Performance testing framework configuration per Section 4.6.3 performance testing flows  
- Baseline comparison constants per Section 0.3.2 performance monitoring requirements
- Performance metrics collection configuration per Section 3.6.2 performance monitoring
- Node.js baseline data for comprehensive performance validation
- Load testing configuration for Locust/Gatling integration per Section 4.6.3
- Prometheus metrics integration for enterprise monitoring per Section 3.6.2

Dependencies:
- pytest 7.4+ for performance test execution and reporting
- prometheus-client 0.17+ for metrics collection and baseline comparison
- locust for load testing and user behavior simulation per Section 4.6.3
- pytest-benchmark for performance measurement and regression detection
- structlog 23.1+ for structured performance logging per Section 3.6.1
"""

import os
import sys
import time
import logging
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Any, List, Optional, Union, NamedTuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import warnings

# Performance testing framework imports
try:
    import pytest
    import pytest_benchmark
except ImportError:
    # Graceful handling if pytest modules not available
    pytest = None
    pytest_benchmark = None

# Metrics collection imports
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    from prometheus_client import start_http_server, CONTENT_TYPE_LATEST
except ImportError:
    # Mock Prometheus classes if not available
    class MockMetric:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def time(self): return self
        def __enter__(self): return self
        def __exit__(self, *args): pass
    
    Counter = Histogram = Gauge = Summary = MockMetric
    start_http_server = lambda *args, **kwargs: None
    CONTENT_TYPE_LATEST = "text/plain"

# Structured logging import
try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

# Application imports with fallback handling
try:
    from tests.test_config import PerformanceTestConfig
    from tests.conftest import performance_baseline
except ImportError:
    # Fallback configurations if modules don't exist yet
    class PerformanceTestConfig:
        PERFORMANCE_VARIANCE_THRESHOLD = 0.10
        BENCHMARK_ITERATIONS = 100
        LOAD_TEST_USERS = 50
        NODEJS_BASELINE_RESPONSE_TIME = 100
        NODEJS_BASELINE_MEMORY_USAGE = 256
        NODEJS_BASELINE_CPU_USAGE = 15


# =============================================================================
# CORE PERFORMANCE CONSTANTS - Section 0.1.1 Primary Objective
# =============================================================================

# ≤10% variance requirement from Node.js baseline per Section 0.1.1
PERFORMANCE_VARIANCE_THRESHOLD = 0.10
"""
Critical performance variance threshold constant per Section 0.1.1 primary objective.

This constant defines the maximum allowable performance degradation from the 
Node.js baseline implementation. Any performance metrics exceeding this threshold
indicate migration compliance failure.

Value: 0.10 (10% maximum variance)
Source: Section 0.1.1 "Performance optimization to ensure ≤10% variance from Node.js baseline"
"""

PERFORMANCE_VARIANCE_THRESHOLD_PERCENT = PERFORMANCE_VARIANCE_THRESHOLD * 100
"""Performance variance threshold expressed as percentage for reporting."""

# Baseline tolerance for performance measurements
BASELINE_TOLERANCE_STRICT = 0.05   # 5% for critical performance metrics
BASELINE_TOLERANCE_STANDARD = 0.10  # 10% for standard performance metrics  
BASELINE_TOLERANCE_RELAXED = 0.15   # 15% for non-critical performance metrics

# Performance test execution parameters
PERFORMANCE_TEST_ITERATIONS = 100
"""Number of iterations for performance benchmark tests."""

PERFORMANCE_TEST_WARMUP_ITERATIONS = 10
"""Number of warmup iterations before performance measurement."""

PERFORMANCE_TEST_TIMEOUT_SECONDS = 300
"""Maximum timeout for individual performance tests in seconds."""


# =============================================================================
# NODE.JS BASELINE CONSTANTS - Section 0.3.2 Performance Monitoring
# =============================================================================

class NodeJSBaseline:
    """
    Node.js baseline performance constants per Section 0.3.2 performance monitoring requirements.
    
    These constants represent the established performance baseline from the original 
    Node.js implementation that the Flask migration must not exceed by more than 10%.
    """
    
    # Response Time Baselines (milliseconds)
    API_RESPONSE_TIMES = {
        'health_check': 50,
        'api_get_users': 150,
        'api_create_user': 200,
        'api_update_user': 180,
        'api_delete_user': 120,
        'api_authenticate': 100,
        'api_search_users': 250,
        'api_upload_file': 300,
        'api_download_file': 200,
        'api_batch_operations': 500,
    }
    
    # Memory Usage Baselines (MB)
    MEMORY_USAGE = {
        'baseline_mb': 256,
        'peak_mb': 512,
        'average_mb': 320,
        'startup_mb': 180,
        'idle_mb': 200,
    }
    
    # CPU Utilization Baselines (percentage)
    CPU_UTILIZATION = {
        'baseline_percent': 15,
        'peak_percent': 45,
        'average_percent': 25,
        'idle_percent': 5,
        'load_test_percent': 65,
    }
    
    # Database Operation Baselines (milliseconds)
    DATABASE_OPERATIONS = {
        'user_lookup': 45,
        'user_create': 85,
        'user_update': 70,
        'user_delete': 40,
        'batch_insert': 150,
        'complex_query': 200,
        'index_scan': 25,
        'full_table_scan': 800,
    }
    
    # Cache Operation Baselines (milliseconds)
    CACHE_OPERATIONS = {
        'get_hit': 5,
        'get_miss': 15,
        'set': 10,
        'delete': 8,
        'flush': 50,
        'keys_scan': 30,
    }
    
    # Throughput Baselines (requests/second)
    THROUGHPUT = {
        'sustained_rps': 100,
        'peak_rps': 250,
        'concurrent_users': 50,
        'max_concurrent_users': 200,
    }


# =============================================================================
# PERFORMANCE METRICS CONFIGURATION - Section 3.6.2 Performance Monitoring
# =============================================================================

# Prometheus metrics for performance monitoring per Section 3.6.2
performance_request_duration = Histogram(
    'flask_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint', 'status_code'],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

performance_request_count = Counter(
    'flask_request_total',
    'Total number of requests',
    ['method', 'endpoint', 'status_code']
)

performance_memory_usage = Gauge(
    'flask_memory_usage_bytes',
    'Current memory usage in bytes'
)

performance_cpu_usage = Gauge(
    'flask_cpu_usage_percent',
    'Current CPU usage percentage'
)

performance_database_duration = Histogram(
    'flask_database_operation_duration_seconds',
    'Database operation duration in seconds',
    ['operation', 'collection', 'result'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

performance_cache_duration = Histogram(
    'flask_cache_operation_duration_seconds',
    'Cache operation duration in seconds',
    ['operation', 'result'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1)
)

performance_external_service_duration = Histogram(
    'flask_external_service_duration_seconds',
    'External service call duration in seconds',
    ['service', 'operation', 'status'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
)


# =============================================================================
# PERFORMANCE TEST CONFIGURATION - Section 4.6.3 Performance Testing Flows
# =============================================================================

@dataclass
class LoadTestConfig:
    """
    Load testing configuration per Section 4.6.3 performance testing flows.
    
    Defines parameters for Locust/Gatling load testing to validate performance
    characteristics against Node.js baseline with progressive scaling.
    """
    
    # User simulation parameters
    min_users: int = 10
    max_users: int = 1000
    spawn_rate: int = 10
    test_duration: int = 1800  # 30 minutes
    
    # Geographic distribution simulation
    regions: List[str] = field(default_factory=lambda: ['us-east-1', 'us-west-2', 'eu-west-1'])
    
    # Request patterns
    user_behavior_weights: Dict[str, float] = field(default_factory=lambda: {
        'browse_users': 0.4,
        'create_user': 0.2,
        'update_user': 0.2,
        'delete_user': 0.1,
        'search_users': 0.1
    })
    
    # Performance targets
    target_rps: int = 100
    max_response_time_ms: int = 500
    max_error_rate_percent: float = 0.1
    
    # Resource limits
    max_cpu_percent: float = 70.0
    max_memory_percent: float = 80.0


@dataclass
class BenchmarkConfig:
    """
    Benchmark testing configuration for pytest-benchmark integration.
    
    Provides configuration for automated performance regression testing
    with baseline comparison and variance validation.
    """
    
    # Benchmark execution parameters
    min_rounds: int = 5
    max_time: float = 10.0
    min_time: float = 0.1
    timer: str = 'time.perf_counter'
    
    # Statistical analysis
    warmup: bool = True
    warmup_iterations: int = 3
    disable_gc: bool = True
    
    # Baseline comparison
    compare_baselines: bool = True
    baseline_tolerance: float = PERFORMANCE_VARIANCE_THRESHOLD
    
    # Reporting
    sort_by: str = 'mean'
    histogram: bool = True
    save_data: bool = True


class PerformanceTestType(Enum):
    """Performance test type enumeration for test categorization."""
    
    UNIT_BENCHMARK = "unit_benchmark"
    INTEGRATION_PERFORMANCE = "integration_performance"
    LOAD_TEST = "load_test"
    STRESS_TEST = "stress_test"
    ENDURANCE_TEST = "endurance_test"
    BASELINE_COMPARISON = "baseline_comparison"


# =============================================================================
# PERFORMANCE VALIDATION UTILITIES
# =============================================================================

class PerformanceValidator:
    """
    Performance validation utilities for baseline comparison and variance checking.
    
    Provides comprehensive validation against Node.js baseline metrics ensuring
    compliance with ≤10% variance requirement per Section 0.1.1.
    """
    
    @staticmethod
    def calculate_variance(current_value: float, baseline_value: float) -> float:
        """
        Calculate performance variance percentage between current and baseline values.
        
        Args:
            current_value: Current measured performance value
            baseline_value: Node.js baseline performance value
            
        Returns:
            Variance percentage (positive for degradation, negative for improvement)
            
        Raises:
            ValueError: If baseline_value is zero or negative
        """
        if baseline_value <= 0:
            raise ValueError(f"Baseline value must be positive, got: {baseline_value}")
        
        variance = ((current_value - baseline_value) / baseline_value) * 100
        return round(variance, 2)
    
    @staticmethod
    def is_within_threshold(current_value: float, baseline_value: float, 
                          threshold: float = PERFORMANCE_VARIANCE_THRESHOLD) -> bool:
        """
        Check if current performance value is within acceptable variance threshold.
        
        Args:
            current_value: Current measured performance value
            baseline_value: Node.js baseline performance value
            threshold: Variance threshold (default: 10%)
            
        Returns:
            True if within threshold, False if exceeds threshold
        """
        try:
            variance = abs(PerformanceValidator.calculate_variance(current_value, baseline_value))
            return variance <= (threshold * 100)
        except ValueError:
            return False
    
    @staticmethod
    def validate_response_time(endpoint: str, current_ms: float) -> Dict[str, Any]:
        """
        Validate API response time against Node.js baseline.
        
        Args:
            endpoint: API endpoint name
            current_ms: Current response time in milliseconds
            
        Returns:
            Validation result dictionary with pass/fail status and metrics
        """
        baseline_ms = NodeJSBaseline.API_RESPONSE_TIMES.get(endpoint)
        if baseline_ms is None:
            return {
                'endpoint': endpoint,
                'status': 'unknown_endpoint',
                'current_ms': current_ms,
                'baseline_ms': None,
                'variance_percent': None,
                'within_threshold': False,
                'message': f"No baseline defined for endpoint: {endpoint}"
            }
        
        variance = PerformanceValidator.calculate_variance(current_ms, baseline_ms)
        within_threshold = PerformanceValidator.is_within_threshold(current_ms, baseline_ms)
        
        return {
            'endpoint': endpoint,
            'status': 'pass' if within_threshold else 'fail',
            'current_ms': current_ms,
            'baseline_ms': baseline_ms,
            'variance_percent': variance,
            'within_threshold': within_threshold,
            'message': f"Response time variance: {variance}% ({'PASS' if within_threshold else 'FAIL'})"
        }
    
    @staticmethod
    def validate_memory_usage(current_mb: float) -> Dict[str, Any]:
        """
        Validate memory usage against Node.js baseline.
        
        Args:
            current_mb: Current memory usage in MB
            
        Returns:
            Validation result dictionary with pass/fail status and metrics
        """
        baseline_mb = NodeJSBaseline.MEMORY_USAGE['average_mb']
        variance = PerformanceValidator.calculate_variance(current_mb, baseline_mb)
        within_threshold = PerformanceValidator.is_within_threshold(current_mb, baseline_mb)
        
        return {
            'metric': 'memory_usage',
            'status': 'pass' if within_threshold else 'fail',
            'current_mb': current_mb,
            'baseline_mb': baseline_mb,
            'variance_percent': variance,
            'within_threshold': within_threshold,
            'message': f"Memory usage variance: {variance}% ({'PASS' if within_threshold else 'FAIL'})"
        }
    
    @staticmethod
    def validate_database_operation(operation: str, current_ms: float) -> Dict[str, Any]:
        """
        Validate database operation performance against Node.js baseline.
        
        Args:
            operation: Database operation name
            current_ms: Current operation time in milliseconds
            
        Returns:
            Validation result dictionary with pass/fail status and metrics
        """
        baseline_ms = NodeJSBaseline.DATABASE_OPERATIONS.get(operation)
        if baseline_ms is None:
            return {
                'operation': operation,
                'status': 'unknown_operation',
                'current_ms': current_ms,
                'baseline_ms': None,
                'variance_percent': None,
                'within_threshold': False,
                'message': f"No baseline defined for operation: {operation}"
            }
        
        variance = PerformanceValidator.calculate_variance(current_ms, baseline_ms)
        within_threshold = PerformanceValidator.is_within_threshold(current_ms, baseline_ms)
        
        return {
            'operation': operation,
            'status': 'pass' if within_threshold else 'fail',
            'current_ms': current_ms,
            'baseline_ms': baseline_ms,
            'variance_percent': variance,
            'within_threshold': within_threshold,
            'message': f"Database operation variance: {variance}% ({'PASS' if within_threshold else 'FAIL'})"
        }


# =============================================================================
# PERFORMANCE TEST DECORATORS AND UTILITIES
# =============================================================================

def performance_test(test_type: PerformanceTestType = PerformanceTestType.UNIT_BENCHMARK,
                    baseline_key: Optional[str] = None,
                    timeout: int = PERFORMANCE_TEST_TIMEOUT_SECONDS):
    """
    Decorator for marking performance tests with configuration and baseline validation.
    
    Args:
        test_type: Type of performance test being executed
        baseline_key: Key for baseline comparison (if applicable)
        timeout: Test timeout in seconds
        
    Returns:
        Decorated test function with performance monitoring
    """
    def decorator(func: Callable) -> Callable:
        # Add performance test markers
        func = pytest.mark.performance(func) if pytest else func
        func = pytest.mark.timeout(timeout)(func) if pytest else func
        
        # Store performance test metadata
        func._performance_test_type = test_type
        func._baseline_key = baseline_key
        func._performance_timeout = timeout
        
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                # Execute the test
                result = func(*args, **kwargs)
                
                # Record performance metrics
                end_time = time.perf_counter()
                execution_time = end_time - start_time
                
                # Log performance data
                logger.info(
                    "Performance test completed",
                    test_name=func.__name__,
                    test_type=test_type.value,
                    execution_time_ms=execution_time * 1000,
                    baseline_key=baseline_key
                )
                
                return result
                
            except Exception as e:
                # Log performance test failure
                logger.error(
                    "Performance test failed",
                    test_name=func.__name__,
                    test_type=test_type.value,
                    error=str(e),
                    baseline_key=baseline_key
                )
                raise
        
        return wrapper
    return decorator


def benchmark_against_baseline(baseline_key: str, tolerance: float = PERFORMANCE_VARIANCE_THRESHOLD):
    """
    Decorator for benchmarking test functions against Node.js baseline values.
    
    Args:
        baseline_key: Key to lookup baseline value in NodeJSBaseline
        tolerance: Variance tolerance threshold
        
    Returns:
        Decorated test function with baseline validation
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            # Execute the function
            result = func(*args, **kwargs)
            
            # Measure execution time
            end_time = time.perf_counter()
            execution_time_ms = (end_time - start_time) * 1000
            
            # Validate against baseline
            validation_result = None
            if baseline_key in NodeJSBaseline.API_RESPONSE_TIMES:
                validation_result = PerformanceValidator.validate_response_time(
                    baseline_key, execution_time_ms
                )
            elif baseline_key in NodeJSBaseline.DATABASE_OPERATIONS:
                validation_result = PerformanceValidator.validate_database_operation(
                    baseline_key, execution_time_ms
                )
            
            # Log validation result
            if validation_result:
                logger.info(
                    "Baseline validation completed",
                    test_name=func.__name__,
                    baseline_key=baseline_key,
                    validation_result=validation_result
                )
                
                # Fail test if performance exceeds threshold
                if not validation_result['within_threshold']:
                    raise AssertionError(
                        f"Performance test failed baseline validation: {validation_result['message']}"
                    )
            
            return result
        
        return wrapper
    return decorator


# =============================================================================
# PERFORMANCE TESTING FRAMEWORK INITIALIZATION
# =============================================================================

class PerformanceTestFramework:
    """
    Performance testing framework initialization per Section 4.6.3 performance testing flows.
    
    Provides centralized configuration and setup for all performance testing components
    including metrics collection, baseline validation, and load testing integration.
    """
    
    def __init__(self):
        self.config = LoadTestConfig()
        self.benchmark_config = BenchmarkConfig()
        self.metrics_server_port = 8000
        self.metrics_server_started = False
        
        # Initialize structured logging
        self._setup_logging()
        
        # Initialize performance metrics
        self._setup_metrics()
    
    def _setup_logging(self):
        """Configure structured logging for performance testing."""
        try:
            if structlog:
                structlog.configure(
                    processors=[
                        structlog.stdlib.filter_by_level,
                        structlog.stdlib.add_logger_name,
                        structlog.stdlib.add_log_level,
                        structlog.stdlib.PositionalArgumentsFormatter(),
                        structlog.processors.StackInfoRenderer(),
                        structlog.processors.format_exc_info,
                        structlog.processors.UnicodeDecoder(),
                        structlog.processors.JSONRenderer()
                    ],
                    context_class=dict,
                    logger_factory=structlog.stdlib.LoggerFactory(),
                    wrapper_class=structlog.stdlib.BoundLogger,
                    cache_logger_on_first_use=True,
                )
        except Exception as e:
            warnings.warn(f"Failed to configure structured logging: {e}")
    
    def _setup_metrics(self):
        """Initialize Prometheus metrics for performance monitoring."""
        try:
            # Initialize all performance metrics
            self.metrics = {
                'request_duration': performance_request_duration,
                'request_count': performance_request_count,
                'memory_usage': performance_memory_usage,
                'cpu_usage': performance_cpu_usage,
                'database_duration': performance_database_duration,
                'cache_duration': performance_cache_duration,
                'external_service_duration': performance_external_service_duration,
            }
            logger.info("Performance metrics initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize performance metrics: {e}")
    
    def start_metrics_server(self, port: int = 8000):
        """
        Start Prometheus metrics server for performance monitoring.
        
        Args:
            port: Port number for metrics server
        """
        if not self.metrics_server_started:
            try:
                start_http_server(port)
                self.metrics_server_port = port
                self.metrics_server_started = True
                logger.info(f"Performance metrics server started on port {port}")
            except Exception as e:
                logger.error(f"Failed to start metrics server: {e}")
    
    def get_baseline_for_endpoint(self, endpoint: str) -> Optional[float]:
        """
        Get Node.js baseline value for API endpoint.
        
        Args:
            endpoint: API endpoint name
            
        Returns:
            Baseline response time in milliseconds or None if not found
        """
        return NodeJSBaseline.API_RESPONSE_TIMES.get(endpoint)
    
    def validate_performance_metrics(self, metrics: Dict[str, float]) -> Dict[str, Any]:
        """
        Validate multiple performance metrics against Node.js baselines.
        
        Args:
            metrics: Dictionary of metric names and current values
            
        Returns:
            Validation results for all metrics
        """
        results = {
            'overall_status': 'pass',
            'failed_metrics': [],
            'metric_results': {}
        }
        
        for metric_name, current_value in metrics.items():
            if metric_name in NodeJSBaseline.API_RESPONSE_TIMES:
                validation = PerformanceValidator.validate_response_time(metric_name, current_value)
            elif metric_name in NodeJSBaseline.DATABASE_OPERATIONS:
                validation = PerformanceValidator.validate_database_operation(metric_name, current_value)
            elif metric_name == 'memory_usage':
                validation = PerformanceValidator.validate_memory_usage(current_value)
            else:
                continue
            
            results['metric_results'][metric_name] = validation
            
            if not validation['within_threshold']:
                results['overall_status'] = 'fail'
                results['failed_metrics'].append(metric_name)
        
        return results


# =============================================================================
# MODULE INITIALIZATION AND EXPORTS
# =============================================================================

# Initialize the performance testing framework
performance_framework = PerformanceTestFramework()

# Configure pytest integration if available
if pytest:
    # Register performance test markers
    pytest.mark.performance = pytest.mark.performance or pytest.mark.marker('performance')
    pytest.mark.baseline_comparison = pytest.mark.marker('baseline_comparison')
    pytest.mark.load_test = pytest.mark.marker('load_test')
    
    # Configure pytest-benchmark if available
    if pytest_benchmark:
        try:
            # Configure benchmark defaults
            benchmark_config = BenchmarkConfig()
            os.environ.setdefault('PYTEST_BENCHMARK_DISABLE_GC', str(benchmark_config.disable_gc))
            os.environ.setdefault('PYTEST_BENCHMARK_MIN_ROUNDS', str(benchmark_config.min_rounds))
            os.environ.setdefault('PYTEST_BENCHMARK_MAX_TIME', str(benchmark_config.max_time))
        except Exception as e:
            logger.warning(f"Failed to configure pytest-benchmark: {e}")

# Export public interface
__all__ = [
    # Core constants
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'PERFORMANCE_VARIANCE_THRESHOLD_PERCENT',
    'BASELINE_TOLERANCE_STRICT',
    'BASELINE_TOLERANCE_STANDARD', 
    'BASELINE_TOLERANCE_RELAXED',
    'PERFORMANCE_TEST_ITERATIONS',
    'PERFORMANCE_TEST_WARMUP_ITERATIONS',
    'PERFORMANCE_TEST_TIMEOUT_SECONDS',
    
    # Baseline data
    'NodeJSBaseline',
    
    # Configuration classes
    'LoadTestConfig',
    'BenchmarkConfig',
    'PerformanceTestType',
    
    # Validation utilities
    'PerformanceValidator',
    
    # Decorators
    'performance_test',
    'benchmark_against_baseline',
    
    # Framework
    'PerformanceTestFramework',
    'performance_framework',
    
    # Prometheus metrics
    'performance_request_duration',
    'performance_request_count',
    'performance_memory_usage',
    'performance_cpu_usage',
    'performance_database_duration',
    'performance_cache_duration',
    'performance_external_service_duration',
]

# Log initialization success
logger.info(
    "Performance testing package initialized",
    variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD,
    baseline_endpoints=len(NodeJSBaseline.API_RESPONSE_TIMES),
    framework_ready=True
)