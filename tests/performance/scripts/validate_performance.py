#!/usr/bin/env python3
"""
Automated Performance Validation Script for Flask Migration

This comprehensive performance validation script implements automated variance calculation
logic, regression detection, and performance compliance verification to enforce the
critical ≤10% variance requirement per Section 0.1.1 of the technical specification.
Provides automated pass/fail determination with comprehensive metrics analysis and
CI/CD pipeline integration for the Node.js to Flask migration project.

Key Features:
- ≤10% performance variance enforcement per Section 0.1.1 primary objective
- Automated regression detection and validation per Section 0.3.2
- Response time ≤500ms and throughput ≥100 req/sec validation per Section 4.6.3
- Database query performance compliance checking per Section 0.3.2
- Comprehensive memory usage, CPU utilization validation per Section 4.6.3
- Automated performance failure alerting and reporting per Section 6.6.2
- CI/CD pipeline integration with GitHub Actions per Section 6.6.2

Architecture Compliance:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 4.6.3: Performance testing flows with automated variance calculation
- Section 6.6.1: Performance monitoring with automated regression detection
- Section 6.6.2: CI/CD integration with automated performance gates

Usage:
    python validate_performance.py --environment testing --config performance_config.json
    python validate_performance.py --baseline-only --output-format json
    python validate_performance.py --run-load-test --concurrent-users 500 --duration 1800

Dependencies:
    - tests.performance.baseline_data: Node.js baseline performance metrics
    - tests.performance.performance_config: Environment-specific configuration
    - tests.performance.test_baseline_comparison: Baseline comparison test suite
    - locust ≥2.x: Load testing framework for throughput validation
    - apache-bench: HTTP performance measurement tool
    - prometheus-client ≥0.17+: Performance metrics collection

Author: Flask Migration Team
Version: 1.0.0
"""

import argparse
import asyncio
import json
import logging
import os
import statistics
import subprocess
import sys
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, NamedTuple
from dataclasses import dataclass, asdict
import uuid
import signal
import tempfile

# Performance testing framework imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

# Import project performance modules
from tests.performance.baseline_data import (
    BaselineDataManager,
    ResponseTimeBaseline,
    ResourceUtilizationBaseline,
    DatabasePerformanceBaseline,
    ThroughputBaseline,
    get_default_baseline_data,
    validate_flask_performance_against_baseline,
    PERFORMANCE_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    CRITICAL_VARIANCE_THRESHOLD
)

from tests.performance.performance_config import (
    BasePerformanceConfig,
    PerformanceConfigFactory,
    LoadTestConfiguration,
    BaselineMetrics,
    PerformanceThreshold,
    PerformanceTestType,
    create_performance_config,
    get_performance_baseline_comparison,
    generate_performance_report
)

from tests.performance.test_baseline_comparison import (
    BaselineComparisonTestSuite,
    PerformanceComparisonResult,
    PerformanceTrendAnalyzer
)

# Configure logging
if STRUCTLOG_AVAILABLE:
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
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
    logger = structlog.get_logger(__name__)
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

# Performance validation constants per Section 0.1.1 and Section 4.6.3
PERFORMANCE_VARIANCE_LIMIT = 10.0        # ≤10% variance requirement per Section 0.1.1
RESPONSE_TIME_THRESHOLD_MS = 500.0       # ≤500ms response time per Section 4.6.3
THROUGHPUT_THRESHOLD_RPS = 100.0         # ≥100 req/sec throughput per Section 4.6.3
ERROR_RATE_THRESHOLD_PERCENT = 0.1       # ≤0.1% error rate per Section 4.6.3
CPU_UTILIZATION_THRESHOLD = 70.0         # ≤70% CPU utilization
MEMORY_UTILIZATION_THRESHOLD = 80.0      # ≤80% memory utilization

# Test execution constants
VALIDATION_TIMEOUT = 3600                # 60-minute maximum validation time
DEFAULT_LOAD_TEST_DURATION = 1800        # 30-minute default load test per Section 4.6.3
DEFAULT_CONCURRENT_USERS = 100           # Default concurrent users for load testing
BASELINE_SAMPLE_SIZE = 100              # Minimum samples for statistical validity
PERFORMANCE_REPORT_RETENTION_DAYS = 30   # Performance report retention period


class ValidationResult(NamedTuple):
    """Structured validation result for performance metrics."""
    
    metric_name: str
    baseline_value: float
    current_value: float
    variance_percent: float
    within_threshold: bool
    status: str
    test_category: str
    timestamp: datetime
    
    @property
    def is_critical_failure(self) -> bool:
        """Check if result indicates critical performance failure."""
        return not self.within_threshold and abs(self.variance_percent) > PERFORMANCE_VARIANCE_LIMIT
    
    @property
    def variance_severity(self) -> str:
        """Get variance severity classification."""
        abs_variance = abs(self.variance_percent)
        if abs_variance <= WARNING_VARIANCE_THRESHOLD:
            return "excellent"
        elif abs_variance <= PERFORMANCE_VARIANCE_LIMIT:
            return "warning"
        elif abs_variance <= CRITICAL_VARIANCE_THRESHOLD:
            return "critical"
        else:
            return "failure"


@dataclass
class PerformanceValidationConfig:
    """Configuration for performance validation execution."""
    
    environment: str = "testing"
    baseline_comparison_enabled: bool = True
    load_testing_enabled: bool = True
    regression_detection_enabled: bool = True
    automated_alerting_enabled: bool = True
    
    # Load testing parameters per Section 4.6.3
    concurrent_users: int = DEFAULT_CONCURRENT_USERS
    test_duration_seconds: int = DEFAULT_LOAD_TEST_DURATION
    ramp_up_time_seconds: int = 300
    target_request_rate: int = int(THROUGHPUT_THRESHOLD_RPS)
    
    # Validation thresholds per Section 0.1.1 and Section 4.6.3
    variance_threshold_percent: float = PERFORMANCE_VARIANCE_LIMIT
    response_time_threshold_ms: float = RESPONSE_TIME_THRESHOLD_MS
    throughput_threshold_rps: float = THROUGHPUT_THRESHOLD_RPS
    error_rate_threshold_percent: float = ERROR_RATE_THRESHOLD_PERCENT
    
    # Output configuration
    output_format: str = "json"  # json, markdown, html
    report_file_path: Optional[str] = None
    metrics_export_enabled: bool = True
    
    # CI/CD integration per Section 6.6.2
    ci_cd_mode: bool = False
    fail_on_regression: bool = True
    notification_webhook_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)


class PerformanceValidationError(Exception):
    """Custom exception for performance validation failures."""
    pass


class RegressionDetectionError(Exception):
    """Custom exception for regression detection failures."""
    pass


class PerformanceValidator:
    """
    Comprehensive performance validator implementing automated variance calculation,
    regression detection, and compliance verification per technical specification
    requirements for the Flask migration project.
    """
    
    def __init__(self, config: PerformanceValidationConfig):
        """
        Initialize performance validator with configuration.
        
        Args:
            config: Performance validation configuration
        """
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.start_time = datetime.now(timezone.utc)
        self.validation_results: List[ValidationResult] = []
        self.performance_metrics: Dict[str, Any] = {}
        self.regression_analysis: Dict[str, Any] = {}
        
        # Initialize performance components
        self.baseline_manager = get_default_baseline_data()
        self.performance_config = create_performance_config(config.environment)
        self.comparison_suite = BaselineComparisonTestSuite(self.baseline_manager)
        self.comparison_suite.setup_baseline_comparison(config.environment)
        self.trend_analyzer = PerformanceTrendAnalyzer()
        
        # Initialize metrics registry if Prometheus available
        if PROMETHEUS_AVAILABLE:
            self.metrics_registry = CollectorRegistry()
            self._setup_prometheus_metrics()
        else:
            self.metrics_registry = None
            logger.warning("Prometheus client not available - metrics export disabled")
        
        # Validation state tracking
        self.validation_errors: List[str] = []
        self.critical_failures: List[str] = []
        self.performance_warnings: List[str] = []
        
        logger.info(
            "Performance validator initialized",
            session_id=self.session_id,
            environment=config.environment,
            variance_threshold=config.variance_threshold_percent,
            ci_cd_mode=config.ci_cd_mode
        )
    
    def _setup_prometheus_metrics(self) -> None:
        """Setup Prometheus metrics for performance monitoring."""
        self.response_time_histogram = Histogram(
            'performance_response_time_seconds',
            'Response time distribution',
            ['endpoint', 'method'],
            buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry=self.metrics_registry
        )
        
        self.variance_gauge = Gauge(
            'performance_variance_percent',
            'Performance variance from baseline',
            ['metric_name', 'endpoint'],
            registry=self.metrics_registry
        )
        
        self.throughput_gauge = Gauge(
            'performance_throughput_rps',
            'Current throughput in requests per second',
            registry=self.metrics_registry
        )
        
        self.compliance_gauge = Gauge(
            'performance_compliance_status',
            'Performance compliance status (1=compliant, 0=non-compliant)',
            ['validation_type'],
            registry=self.metrics_registry
        )
        
        logger.info("Prometheus metrics configured for performance monitoring")
    
    def validate_response_time_performance(
        self, 
        endpoint: str, 
        method: str, 
        response_times_ms: List[float],
        test_category: str = "api_performance"
    ) -> ValidationResult:
        """
        Validate response time performance against Node.js baseline per Section 4.6.3.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            response_times_ms: List of measured response times in milliseconds
            test_category: Category of performance test
            
        Returns:
            ValidationResult with response time analysis
            
        Raises:
            PerformanceValidationError: If validation fails or insufficient data
        """
        if not response_times_ms:
            raise PerformanceValidationError("No response time data provided for validation")
        
        if len(response_times_ms) < 10:
            logger.warning(
                "Limited response time samples for statistical validity",
                endpoint=endpoint,
                method=method,
                sample_count=len(response_times_ms)
            )
        
        try:
            # Get baseline for comparison
            baseline = self.baseline_manager.get_response_time_baseline(endpoint, method)
            if not baseline:
                logger.warning(
                    "No baseline available for endpoint - using general threshold validation",
                    endpoint=endpoint,
                    method=method
                )
                
                # Use general response time threshold validation
                mean_response_time = statistics.mean(response_times_ms)
                p95_response_time = statistics.quantiles(response_times_ms, n=20)[18] if len(response_times_ms) >= 20 else max(response_times_ms)
                
                within_threshold = p95_response_time <= self.config.response_time_threshold_ms
                status = f"Response time validation: {p95_response_time:.2f}ms vs threshold {self.config.response_time_threshold_ms}ms"
                
                result = ValidationResult(
                    metric_name=f"response_time_{method.lower()}_{endpoint.replace('/', '_')}",
                    baseline_value=self.config.response_time_threshold_ms,
                    current_value=p95_response_time,
                    variance_percent=(p95_response_time - self.config.response_time_threshold_ms) / self.config.response_time_threshold_ms * 100,
                    within_threshold=within_threshold,
                    status=status,
                    test_category=test_category,
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                # Perform baseline comparison using test suite
                comparison_result = self.comparison_suite.compare_response_time_performance(
                    endpoint, method, response_times_ms
                )
                
                result = ValidationResult(
                    metric_name=comparison_result.metric_name,
                    baseline_value=comparison_result.baseline_value,
                    current_value=comparison_result.current_value,
                    variance_percent=comparison_result.variance_percent,
                    within_threshold=comparison_result.within_threshold,
                    status=comparison_result.status,
                    test_category=test_category,
                    timestamp=comparison_result.timestamp
                )
            
            # Update Prometheus metrics if available
            if self.metrics_registry and PROMETHEUS_AVAILABLE:
                self.response_time_histogram.labels(endpoint=endpoint, method=method).observe(
                    statistics.mean(response_times_ms) / 1000.0  # Convert to seconds
                )
                self.variance_gauge.labels(metric_name=result.metric_name, endpoint=endpoint).set(
                    abs(result.variance_percent)
                )
            
            # Add to trend analysis
            self.trend_analyzer.add_measurement(
                result.metric_name, 
                result.current_value, 
                result.baseline_value
            )
            
            # Record validation result
            self.validation_results.append(result)
            
            # Log validation outcome
            if result.within_threshold:
                logger.info(
                    "Response time validation passed",
                    endpoint=endpoint,
                    method=method,
                    current_value=result.current_value,
                    baseline_value=result.baseline_value,
                    variance_percent=result.variance_percent
                )
            else:
                logger.warning(
                    "Response time validation failed",
                    endpoint=endpoint,
                    method=method,
                    current_value=result.current_value,
                    baseline_value=result.baseline_value,
                    variance_percent=result.variance_percent,
                    severity=result.variance_severity
                )
                
                if result.is_critical_failure:
                    self.critical_failures.append(result.status)
                else:
                    self.performance_warnings.append(result.status)
            
            return result
            
        except Exception as e:
            error_msg = f"Response time validation error for {method} {endpoint}: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def validate_resource_utilization_performance(
        self,
        cpu_percent: float,
        memory_mb: float,
        test_category: str = "resource_performance"
    ) -> List[ValidationResult]:
        """
        Validate CPU and memory utilization against Node.js baseline per Section 0.3.2.
        
        Args:
            cpu_percent: Measured CPU utilization percentage
            memory_mb: Measured memory usage in megabytes
            test_category: Category of performance test
            
        Returns:
            List of ValidationResult for CPU and memory metrics
            
        Raises:
            PerformanceValidationError: If validation fails
        """
        try:
            # Perform baseline comparison using test suite
            comparison_results = self.comparison_suite.compare_resource_utilization_performance(
                cpu_percent, memory_mb
            )
            
            validation_results = []
            
            for comparison_result in comparison_results:
                result = ValidationResult(
                    metric_name=comparison_result.metric_name,
                    baseline_value=comparison_result.baseline_value,
                    current_value=comparison_result.current_value,
                    variance_percent=comparison_result.variance_percent,
                    within_threshold=comparison_result.within_threshold,
                    status=comparison_result.status,
                    test_category=test_category,
                    timestamp=comparison_result.timestamp
                )
                
                validation_results.append(result)
                
                # Add to trend analysis
                self.trend_analyzer.add_measurement(
                    result.metric_name,
                    result.current_value,
                    result.baseline_value
                )
                
                # Log validation outcome
                if result.within_threshold:
                    logger.info(
                        "Resource utilization validation passed",
                        metric=result.metric_name,
                        current_value=result.current_value,
                        baseline_value=result.baseline_value,
                        variance_percent=result.variance_percent
                    )
                else:
                    logger.warning(
                        "Resource utilization validation failed",
                        metric=result.metric_name,
                        current_value=result.current_value,
                        baseline_value=result.baseline_value,
                        variance_percent=result.variance_percent,
                        severity=result.variance_severity
                    )
                    
                    if result.is_critical_failure:
                        self.critical_failures.append(result.status)
                    else:
                        self.performance_warnings.append(result.status)
            
            # Record validation results
            self.validation_results.extend(validation_results)
            return validation_results
            
        except Exception as e:
            error_msg = f"Resource utilization validation error: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def validate_database_performance(
        self,
        operation_type: str,
        collection: str,
        query_times_ms: List[float],
        test_category: str = "database_performance"
    ) -> ValidationResult:
        """
        Validate database query performance against Node.js baseline per Section 0.3.2.
        
        Args:
            operation_type: Database operation type ('find', 'insert', 'update', etc.)
            collection: Database collection name
            query_times_ms: List of measured query times in milliseconds
            test_category: Category of performance test
            
        Returns:
            ValidationResult with database performance analysis
            
        Raises:
            PerformanceValidationError: If validation fails
        """
        if not query_times_ms:
            raise PerformanceValidationError("No database query time data provided for validation")
        
        try:
            # Perform baseline comparison using test suite
            comparison_result = self.comparison_suite.compare_database_performance(
                operation_type, collection, query_times_ms
            )
            
            result = ValidationResult(
                metric_name=comparison_result.metric_name,
                baseline_value=comparison_result.baseline_value,
                current_value=comparison_result.current_value,
                variance_percent=comparison_result.variance_percent,
                within_threshold=comparison_result.within_threshold,
                status=comparison_result.status,
                test_category=test_category,
                timestamp=comparison_result.timestamp
            )
            
            # Add to trend analysis
            self.trend_analyzer.add_measurement(
                result.metric_name,
                result.current_value,
                result.baseline_value
            )
            
            # Record validation result
            self.validation_results.append(result)
            
            # Log validation outcome
            if result.within_threshold:
                logger.info(
                    "Database performance validation passed",
                    operation=operation_type,
                    collection=collection,
                    current_value=result.current_value,
                    baseline_value=result.baseline_value,
                    variance_percent=result.variance_percent
                )
            else:
                logger.warning(
                    "Database performance validation failed",
                    operation=operation_type,
                    collection=collection,
                    current_value=result.current_value,
                    baseline_value=result.baseline_value,
                    variance_percent=result.variance_percent,
                    severity=result.variance_severity
                )
                
                if result.is_critical_failure:
                    self.critical_failures.append(result.status)
                else:
                    self.performance_warnings.append(result.status)
            
            return result
            
        except Exception as e:
            error_msg = f"Database performance validation error for {operation_type} on {collection}: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def validate_throughput_performance(
        self,
        requests_per_second: float,
        concurrent_users: int,
        error_rate_percent: float,
        test_category: str = "throughput_performance"
    ) -> List[ValidationResult]:
        """
        Validate throughput and error rate performance per Section 4.6.3.
        
        Args:
            requests_per_second: Measured throughput in requests per second
            concurrent_users: Number of concurrent users during test
            error_rate_percent: Error rate percentage during test
            test_category: Category of performance test
            
        Returns:
            List of ValidationResult for throughput and error rate metrics
            
        Raises:
            PerformanceValidationError: If validation fails
        """
        try:
            # Perform baseline comparison using test suite
            comparison_results = self.comparison_suite.compare_throughput_performance(
                requests_per_second, concurrent_users, error_rate_percent
            )
            
            validation_results = []
            
            for comparison_result in comparison_results:
                result = ValidationResult(
                    metric_name=comparison_result.metric_name,
                    baseline_value=comparison_result.baseline_value,
                    current_value=comparison_result.current_value,
                    variance_percent=comparison_result.variance_percent,
                    within_threshold=comparison_result.within_threshold,
                    status=comparison_result.status,
                    test_category=test_category,
                    timestamp=comparison_result.timestamp
                )
                
                validation_results.append(result)
                
                # Update Prometheus metrics if available
                if self.metrics_registry and PROMETHEUS_AVAILABLE:
                    if result.metric_name == "requests_per_second":
                        self.throughput_gauge.set(result.current_value)
                
                # Add to trend analysis
                self.trend_analyzer.add_measurement(
                    result.metric_name,
                    result.current_value,
                    result.baseline_value
                )
                
                # Log validation outcome
                if result.within_threshold:
                    logger.info(
                        "Throughput validation passed",
                        metric=result.metric_name,
                        current_value=result.current_value,
                        baseline_value=result.baseline_value,
                        variance_percent=result.variance_percent
                    )
                else:
                    logger.warning(
                        "Throughput validation failed",
                        metric=result.metric_name,
                        current_value=result.current_value,
                        baseline_value=result.baseline_value,
                        variance_percent=result.variance_percent,
                        severity=result.variance_severity
                    )
                    
                    if result.is_critical_failure:
                        self.critical_failures.append(result.status)
                    else:
                        self.performance_warnings.append(result.status)
            
            # Record validation results
            self.validation_results.extend(validation_results)
            return validation_results
            
        except Exception as e:
            error_msg = f"Throughput validation error: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def detect_performance_regressions(self) -> Dict[str, Any]:
        """
        Detect performance regressions using trend analysis per Section 0.3.2.
        
        Returns:
            Dictionary containing regression analysis results
            
        Raises:
            RegressionDetectionError: If regression detection fails
        """
        try:
            regression_summary = {
                "regressions_detected": 0,
                "metrics_analyzed": 0,
                "regression_details": {},
                "trend_analysis": {},
                "overall_regression_status": "no_regressions_detected"
            }
            
            # Analyze each performance metric for regressions
            unique_metrics = set(result.metric_name for result in self.validation_results)
            regression_summary["metrics_analyzed"] = len(unique_metrics)
            
            for metric_name in unique_metrics:
                # Generate trend report for metric
                trend_report = self.trend_analyzer.generate_trend_report(metric_name)
                regression_analysis = self.trend_analyzer.detect_regression(metric_name)
                
                regression_summary["trend_analysis"][metric_name] = trend_report
                
                if regression_analysis["regression_detected"]:
                    regression_summary["regressions_detected"] += 1
                    regression_summary["regression_details"][metric_name] = {
                        "confidence": regression_analysis["confidence"],
                        "z_score": regression_analysis["z_score"],
                        "trend_slope": regression_analysis["trend_slope"],
                        "message": regression_analysis["message"],
                        "sample_size": regression_analysis["sample_size"]
                    }
                    
                    logger.warning(
                        "Performance regression detected",
                        metric=metric_name,
                        confidence=regression_analysis["confidence"],
                        message=regression_analysis["message"]
                    )
            
            # Determine overall regression status
            if regression_summary["regressions_detected"] > 0:
                critical_regressions = sum(
                    1 for details in regression_summary["regression_details"].values()
                    if details["confidence"] > 0.8
                )
                
                if critical_regressions > 0:
                    regression_summary["overall_regression_status"] = "critical_regressions_detected"
                else:
                    regression_summary["overall_regression_status"] = "minor_regressions_detected"
            
            # Store regression analysis results
            self.regression_analysis = regression_summary
            
            logger.info(
                "Regression detection completed",
                metrics_analyzed=regression_summary["metrics_analyzed"],
                regressions_detected=regression_summary["regressions_detected"],
                overall_status=regression_summary["overall_regression_status"]
            )
            
            return regression_summary
            
        except Exception as e:
            error_msg = f"Regression detection error: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise RegressionDetectionError(error_msg) from e
    
    def run_automated_load_test(
        self,
        base_url: str = "http://localhost:5000",
        endpoints: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run automated load test using Apache Bench per Section 4.6.3.
        
        Args:
            base_url: Base URL for load testing
            endpoints: List of endpoints to test (defaults to common endpoints)
            
        Returns:
            Dictionary containing load test results
            
        Raises:
            PerformanceValidationError: If load test execution fails
        """
        if endpoints is None:
            endpoints = [
                "/health",
                "/api/v1/users",
                "/api/v1/auth/login",
                "/api/v1/data/reports"
            ]
        
        load_test_results = {
            "test_configuration": {
                "base_url": base_url,
                "endpoints": endpoints,
                "concurrent_users": self.config.concurrent_users,
                "test_duration": self.config.test_duration_seconds,
                "target_rps": self.config.target_request_rate
            },
            "endpoint_results": {},
            "overall_metrics": {},
            "compliance_status": True
        }
        
        try:
            logger.info(
                "Starting automated load test",
                base_url=base_url,
                concurrent_users=self.config.concurrent_users,
                duration=self.config.test_duration_seconds
            )
            
            # Check if Apache Bench is available
            try:
                subprocess.run(["ab", "-V"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.warning("Apache Bench not available - skipping load test")
                load_test_results["error"] = "Apache Bench not available"
                return load_test_results
            
            # Test each endpoint
            total_requests = 0
            total_response_time = 0
            total_errors = 0
            
            for endpoint in endpoints:
                try:
                    logger.info(f"Load testing endpoint: {endpoint}")
                    
                    # Calculate requests per endpoint
                    requests_per_endpoint = min(1000, self.config.target_request_rate * 10)
                    
                    # Execute Apache Bench command
                    test_url = f"{base_url}{endpoint}"
                    cmd = [
                        "ab",
                        "-n", str(requests_per_endpoint),
                        "-c", str(min(self.config.concurrent_users, 50)),
                        "-s", "30",  # 30-second timeout
                        test_url
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5-minute timeout per endpoint
                    )
                    
                    if result.returncode == 0:
                        # Parse Apache Bench output
                        parsed_results = self._parse_apache_bench_output(result.stdout)
                        load_test_results["endpoint_results"][endpoint] = parsed_results
                        
                        # Extract response times for validation
                        if "response_time_mean" in parsed_results:
                            response_times = [parsed_results["response_time_mean"]] * requests_per_endpoint
                            
                            # Validate response time performance
                            method = "POST" if "login" in endpoint else "GET"
                            try:
                                self.validate_response_time_performance(
                                    endpoint, method, response_times, "load_test"
                                )
                            except PerformanceValidationError:
                                load_test_results["compliance_status"] = False
                        
                        # Accumulate overall metrics
                        total_requests += requests_per_endpoint
                        if "response_time_mean" in parsed_results:
                            total_response_time += parsed_results["response_time_mean"]
                        if "failed_requests" in parsed_results:
                            total_errors += parsed_results["failed_requests"]
                    
                    else:
                        logger.error(
                            "Apache Bench test failed for endpoint",
                            endpoint=endpoint,
                            error=result.stderr
                        )
                        load_test_results["endpoint_results"][endpoint] = {
                            "error": result.stderr,
                            "status": "failed"
                        }
                        load_test_results["compliance_status"] = False
                
                except subprocess.TimeoutExpired:
                    logger.error(f"Load test timeout for endpoint: {endpoint}")
                    load_test_results["endpoint_results"][endpoint] = {
                        "error": "Test timeout",
                        "status": "timeout"
                    }
                    load_test_results["compliance_status"] = False
                
                except Exception as e:
                    logger.error(f"Load test error for endpoint {endpoint}: {str(e)}")
                    load_test_results["endpoint_results"][endpoint] = {
                        "error": str(e),
                        "status": "error"
                    }
                    load_test_results["compliance_status"] = False
            
            # Calculate overall metrics
            if total_requests > 0:
                avg_response_time = total_response_time / len(endpoints)
                error_rate = (total_errors / total_requests) * 100
                estimated_rps = total_requests / (self.config.test_duration_seconds / len(endpoints))
                
                load_test_results["overall_metrics"] = {
                    "total_requests": total_requests,
                    "average_response_time_ms": avg_response_time,
                    "error_rate_percent": error_rate,
                    "estimated_rps": estimated_rps,
                    "endpoints_tested": len(endpoints)
                }
                
                # Validate overall throughput and error rate
                try:
                    self.validate_throughput_performance(
                        estimated_rps, self.config.concurrent_users, error_rate, "load_test"
                    )
                except PerformanceValidationError:
                    load_test_results["compliance_status"] = False
            
            logger.info(
                "Automated load test completed",
                endpoints_tested=len(endpoints),
                total_requests=total_requests,
                compliance_status=load_test_results["compliance_status"]
            )
            
            return load_test_results
            
        except Exception as e:
            error_msg = f"Automated load test error: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def _parse_apache_bench_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Apache Bench output to extract performance metrics.
        
        Args:
            output: Raw Apache Bench stdout output
            
        Returns:
            Dictionary containing parsed performance metrics
        """
        results = {}
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if "Requests per second:" in line:
                    parts = line.split()
                    results["requests_per_second"] = float(parts[3])
                    
                elif "Time per request:" in line and "mean" in line:
                    parts = line.split()
                    results["response_time_mean"] = float(parts[3])
                    
                elif "Complete requests:" in line:
                    parts = line.split()
                    results["total_requests"] = int(parts[2])
                    
                elif "Failed requests:" in line:
                    parts = line.split()
                    results["failed_requests"] = int(parts[2])
                    
                elif "%" in line and "ms" in line:
                    # Parse percentile data
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            percentile = int(parts[0].replace('%', ''))
                            time_ms = float(parts[1])
                            if "percentiles" not in results:
                                results["percentiles"] = {}
                            results["percentiles"][percentile] = time_ms
                        except (ValueError, IndexError):
                            continue
        
        except Exception as e:
            logger.warning(f"Error parsing Apache Bench output: {str(e)}")
        
        return results
    
    def collect_system_metrics(self) -> Dict[str, float]:
        """
        Collect current system resource metrics using psutil.
        
        Returns:
            Dictionary containing current system metrics
        """
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - cannot collect system metrics")
            return {}
        
        try:
            # Collect CPU and memory metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            memory_mb = memory_info.used / (1024 * 1024)
            memory_percent = memory_info.percent
            
            # Collect additional system metrics
            disk_usage = psutil.disk_usage('/')
            network_io = psutil.net_io_counters()
            
            system_metrics = {
                "cpu_utilization_percent": cpu_percent,
                "memory_usage_mb": memory_mb,
                "memory_utilization_percent": memory_percent,
                "disk_usage_percent": (disk_usage.used / disk_usage.total) * 100,
                "network_bytes_sent": network_io.bytes_sent,
                "network_bytes_recv": network_io.bytes_recv
            }
            
            logger.info(
                "System metrics collected",
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                memory_percent=memory_percent
            )
            
            return system_metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {str(e)}")
            return {}
    
    def validate_overall_performance_compliance(self) -> Dict[str, Any]:
        """
        Validate overall performance compliance per Section 0.1.1 and Section 4.6.3.
        
        Returns:
            Dictionary containing comprehensive compliance analysis
            
        Raises:
            PerformanceValidationError: If compliance validation fails
        """
        try:
            # Use baseline comparison suite for overall validation
            overall_compliance = self.comparison_suite.validate_overall_performance_compliance()
            
            # Enhance with validator-specific metrics
            enhanced_compliance = {
                "session_metadata": {
                    "session_id": self.session_id,
                    "validation_start_time": self.start_time.isoformat(),
                    "validation_duration_seconds": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
                    "environment": self.config.environment,
                    "variance_threshold_percent": self.config.variance_threshold_percent
                },
                "validation_summary": {
                    "total_validations": len(self.validation_results),
                    "passed_validations": len([r for r in self.validation_results if r.within_threshold]),
                    "failed_validations": len([r for r in self.validation_results if not r.within_threshold]),
                    "critical_failures": len(self.critical_failures),
                    "performance_warnings": len(self.performance_warnings),
                    "validation_errors": len(self.validation_errors)
                },
                "compliance_analysis": overall_compliance,
                "regression_analysis": self.regression_analysis,
                "performance_categories": self._analyze_performance_by_category(),
                "recommendations": self._generate_performance_recommendations()
            }
            
            # Determine final compliance status
            final_compliance = (
                overall_compliance.get("overall_compliant", False) and
                len(self.critical_failures) == 0 and
                len(self.validation_errors) == 0 and
                self.regression_analysis.get("overall_regression_status", "") != "critical_regressions_detected"
            )
            
            enhanced_compliance["final_compliance_status"] = final_compliance
            enhanced_compliance["deployment_recommendation"] = "APPROVED" if final_compliance else "BLOCKED"
            
            # Update Prometheus compliance metrics if available
            if self.metrics_registry and PROMETHEUS_AVAILABLE:
                self.compliance_gauge.labels(validation_type="overall").set(1.0 if final_compliance else 0.0)
                self.compliance_gauge.labels(validation_type="baseline_comparison").set(
                    1.0 if overall_compliance.get("overall_compliant", False) else 0.0
                )
                self.compliance_gauge.labels(validation_type="regression_detection").set(
                    1.0 if self.regression_analysis.get("regressions_detected", 0) == 0 else 0.0
                )
            
            logger.info(
                "Overall performance compliance validation completed",
                final_compliance=final_compliance,
                total_validations=enhanced_compliance["validation_summary"]["total_validations"],
                critical_failures=enhanced_compliance["validation_summary"]["critical_failures"],
                deployment_recommendation=enhanced_compliance["deployment_recommendation"]
            )
            
            return enhanced_compliance
            
        except Exception as e:
            error_msg = f"Overall compliance validation error: {str(e)}"
            logger.error(error_msg, error=str(e))
            self.validation_errors.append(error_msg)
            raise PerformanceValidationError(error_msg) from e
    
    def _analyze_performance_by_category(self) -> Dict[str, Any]:
        """Analyze performance results by test category."""
        categories = {}
        
        for result in self.validation_results:
            category = result.test_category
            if category not in categories:
                categories[category] = {
                    "total_tests": 0,
                    "passed_tests": 0,
                    "failed_tests": 0,
                    "average_variance": 0.0,
                    "max_variance": 0.0,
                    "critical_failures": 0
                }
            
            cat_data = categories[category]
            cat_data["total_tests"] += 1
            
            if result.within_threshold:
                cat_data["passed_tests"] += 1
            else:
                cat_data["failed_tests"] += 1
                if result.is_critical_failure:
                    cat_data["critical_failures"] += 1
            
            cat_data["max_variance"] = max(cat_data["max_variance"], abs(result.variance_percent))
        
        # Calculate average variances
        for category, data in categories.items():
            category_results = [r for r in self.validation_results if r.test_category == category]
            if category_results:
                data["average_variance"] = statistics.mean([abs(r.variance_percent) for r in category_results])
        
        return categories
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # Critical failures require immediate attention
        if self.critical_failures:
            recommendations.append("CRITICAL: Immediate performance optimization required - migration blocked")
            recommendations.append("Review critical performance failures and implement fixes before deployment")
        
        # Regression-specific recommendations
        if self.regression_analysis.get("regressions_detected", 0) > 0:
            recommendations.append("Performance regressions detected - investigate root causes")
            recommendations.append("Consider performance optimization or baseline recalibration")
        
        # Category-specific recommendations
        performance_categories = self._analyze_performance_by_category()
        for category, data in performance_categories.items():
            if data["failed_tests"] > 0:
                recommendations.append(f"Optimize {category.replace('_', ' ')} - {data['failed_tests']} failures detected")
        
        # General recommendations
        if len(self.performance_warnings) > len(self.critical_failures):
            recommendations.append("Monitor performance trends closely - multiple warnings detected")
        
        if not recommendations:
            recommendations.append("Performance validation successful - deployment approved")
        
        return recommendations
    
    def send_performance_alerts(self, compliance_results: Dict[str, Any]) -> None:
        """
        Send automated performance alerts per Section 6.6.2.
        
        Args:
            compliance_results: Performance compliance analysis results
        """
        if not self.config.automated_alerting_enabled:
            logger.info("Automated alerting disabled - skipping notifications")
            return
        
        try:
            alert_data = {
                "session_id": self.session_id,
                "environment": self.config.environment,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "compliance_status": compliance_results["final_compliance_status"],
                "deployment_recommendation": compliance_results["deployment_recommendation"],
                "critical_failures": len(self.critical_failures),
                "performance_warnings": len(self.performance_warnings),
                "validation_errors": len(self.validation_errors),
                "regressions_detected": self.regression_analysis.get("regressions_detected", 0),
                "summary": {
                    "total_validations": compliance_results["validation_summary"]["total_validations"],
                    "passed_validations": compliance_results["validation_summary"]["passed_validations"],
                    "failed_validations": compliance_results["validation_summary"]["failed_validations"]
                }
            }
            
            # Send webhook notification if configured
            if self.config.notification_webhook_url and REQUESTS_AVAILABLE:
                try:
                    response = requests.post(
                        self.config.notification_webhook_url,
                        json=alert_data,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        logger.info("Performance alert sent successfully via webhook")
                    else:
                        logger.warning(
                            "Webhook notification failed",
                            status_code=response.status_code,
                            response=response.text
                        )
                
                except Exception as e:
                    logger.error(f"Webhook notification error: {str(e)}")
            
            # Log alert for CI/CD integration
            if self.config.ci_cd_mode:
                if not compliance_results["final_compliance_status"]:
                    logger.error(
                        "PERFORMANCE VALIDATION FAILED - DEPLOYMENT BLOCKED",
                        **alert_data
                    )
                else:
                    logger.info(
                        "PERFORMANCE VALIDATION PASSED - DEPLOYMENT APPROVED",
                        **alert_data
                    )
            
            logger.info(
                "Performance alert processing completed",
                compliance_status=compliance_results["final_compliance_status"],
                webhook_configured=bool(self.config.notification_webhook_url)
            )
            
        except Exception as e:
            logger.error(f"Performance alerting error: {str(e)}")
    
    def generate_validation_report(self, compliance_results: Dict[str, Any]) -> str:
        """
        Generate comprehensive performance validation report.
        
        Args:
            compliance_results: Performance compliance analysis results
            
        Returns:
            Formatted performance validation report
        """
        try:
            if self.config.output_format.lower() == "json":
                return self._generate_json_report(compliance_results)
            elif self.config.output_format.lower() == "markdown":
                return self._generate_markdown_report(compliance_results)
            elif self.config.output_format.lower() == "html":
                return self._generate_html_report(compliance_results)
            else:
                logger.warning(f"Unsupported output format: {self.config.output_format}")
                return self._generate_json_report(compliance_results)
        
        except Exception as e:
            logger.error(f"Report generation error: {str(e)}")
            return json.dumps({"error": f"Report generation failed: {str(e)}"}, indent=2)
    
    def _generate_json_report(self, compliance_results: Dict[str, Any]) -> str:
        """Generate JSON format performance validation report."""
        report_data = {
            "performance_validation_report": {
                "metadata": compliance_results["session_metadata"],
                "validation_summary": compliance_results["validation_summary"],
                "compliance_analysis": compliance_results["compliance_analysis"],
                "regression_analysis": compliance_results["regression_analysis"],
                "performance_categories": compliance_results["performance_categories"],
                "recommendations": compliance_results["recommendations"],
                "final_status": {
                    "compliance_status": compliance_results["final_compliance_status"],
                    "deployment_recommendation": compliance_results["deployment_recommendation"]
                },
                "detailed_results": [
                    {
                        "metric_name": result.metric_name,
                        "baseline_value": result.baseline_value,
                        "current_value": result.current_value,
                        "variance_percent": result.variance_percent,
                        "within_threshold": result.within_threshold,
                        "status": result.status,
                        "test_category": result.test_category,
                        "timestamp": result.timestamp.isoformat(),
                        "variance_severity": result.variance_severity
                    }
                    for result in self.validation_results
                ]
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_markdown_report(self, compliance_results: Dict[str, Any]) -> str:
        """Generate Markdown format performance validation report."""
        report = f"""# Performance Validation Report

**Session ID:** {self.session_id}  
**Environment:** {self.config.environment}  
**Validation Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Duration:** {(datetime.now(timezone.utc) - self.start_time).total_seconds():.1f} seconds  

## Executive Summary

- **Final Status:** {'✅ PASSED' if compliance_results['final_compliance_status'] else '❌ FAILED'}
- **Deployment Recommendation:** {compliance_results['deployment_recommendation']}
- **Total Validations:** {compliance_results['validation_summary']['total_validations']}
- **Passed/Failed:** {compliance_results['validation_summary']['passed_validations']}/{compliance_results['validation_summary']['failed_validations']}
- **Critical Failures:** {compliance_results['validation_summary']['critical_failures']}

## Performance Variance Analysis

| Metric | Baseline | Current | Variance | Status |
|--------|----------|---------|----------|--------|
"""
        
        for result in self.validation_results:
            status_icon = "✅" if result.within_threshold else "❌"
            report += f"| {result.metric_name} | {result.baseline_value:.2f} | {result.current_value:.2f} | {result.variance_percent:.2f}% | {status_icon} |\n"
        
        report += f"""
## Regression Analysis

- **Metrics Analyzed:** {self.regression_analysis.get('metrics_analyzed', 0)}
- **Regressions Detected:** {self.regression_analysis.get('regressions_detected', 0)}
- **Overall Status:** {self.regression_analysis.get('overall_regression_status', 'unknown')}

## Recommendations

"""
        
        for recommendation in compliance_results['recommendations']:
            report += f"- {recommendation}\n"
        
        return report
    
    def _generate_html_report(self, compliance_results: Dict[str, Any]) -> str:
        """Generate HTML format performance validation report."""
        status_color = "green" if compliance_results['final_compliance_status'] else "red"
        
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Performance Validation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .status-pass {{ color: green; font-weight: bold; }}
        .status-fail {{ color: red; font-weight: bold; }}
        .status-warning {{ color: orange; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .metric-pass {{ background-color: #e8f5e9; }}
        .metric-fail {{ background-color: #ffebee; }}
        .recommendations {{ background-color: #fff3e0; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Performance Validation Report</h1>
        <p><strong>Session ID:</strong> {self.session_id}</p>
        <p><strong>Environment:</strong> {self.config.environment}</p>
        <p><strong>Status:</strong> <span class="status-{'pass' if compliance_results['final_compliance_status'] else 'fail'}">{compliance_results['deployment_recommendation']}</span></p>
    </div>
    
    <h2>Validation Summary</h2>
    <ul>
        <li>Total Validations: {compliance_results['validation_summary']['total_validations']}</li>
        <li>Passed: {compliance_results['validation_summary']['passed_validations']}</li>
        <li>Failed: {compliance_results['validation_summary']['failed_validations']}</li>
        <li>Critical Failures: {compliance_results['validation_summary']['critical_failures']}</li>
    </ul>
    
    <h2>Performance Results</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Baseline</th>
            <th>Current</th>
            <th>Variance</th>
            <th>Status</th>
        </tr>
"""
        
        for result in self.validation_results:
            row_class = "metric-pass" if result.within_threshold else "metric-fail"
            html_report += f"""
        <tr class="{row_class}">
            <td>{result.metric_name}</td>
            <td>{result.baseline_value:.2f}</td>
            <td>{result.current_value:.2f}</td>
            <td>{result.variance_percent:.2f}%</td>
            <td>{'PASS' if result.within_threshold else 'FAIL'}</td>
        </tr>
"""
        
        html_report += """
    </table>
    
    <h2>Recommendations</h2>
    <div class="recommendations">
        <ul>
"""
        
        for recommendation in compliance_results['recommendations']:
            html_report += f"<li>{recommendation}</li>\n"
        
        html_report += """
        </ul>
    </div>
</body>
</html>
"""
        
        return html_report
    
    def export_prometheus_metrics(self, file_path: Optional[str] = None) -> Optional[str]:
        """
        Export Prometheus metrics for monitoring integration.
        
        Args:
            file_path: Optional file path for metrics export
            
        Returns:
            Prometheus metrics data or file path if exported
        """
        if not self.metrics_registry or not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus metrics not available for export")
            return None
        
        try:
            metrics_data = generate_latest(self.metrics_registry)
            
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(metrics_data)
                logger.info(f"Prometheus metrics exported to: {file_path}")
                return file_path
            else:
                return metrics_data.decode('utf-8')
        
        except Exception as e:
            logger.error(f"Prometheus metrics export error: {str(e)}")
            return None


def parse_command_line_arguments() -> argparse.Namespace:
    """Parse command line arguments for performance validation script."""
    parser = argparse.ArgumentParser(
        description="Automated Performance Validation Script for Flask Migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python validate_performance.py --environment testing
    python validate_performance.py --baseline-only --output-format json
    python validate_performance.py --run-load-test --concurrent-users 500
    python validate_performance.py --ci-cd-mode --fail-on-regression
        """
    )
    
    # Environment and configuration
    parser.add_argument(
        "--environment", "-e",
        default="testing",
        choices=["development", "testing", "staging", "production", "ci_cd"],
        help="Target environment for performance validation"
    )
    
    parser.add_argument(
        "--config-file", "-c",
        help="Path to JSON configuration file"
    )
    
    # Validation modes
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Only perform baseline comparison validation"
    )
    
    parser.add_argument(
        "--run-load-test",
        action="store_true",
        help="Execute automated load testing with Apache Bench"
    )
    
    parser.add_argument(
        "--collect-system-metrics",
        action="store_true",
        help="Collect and validate current system resource metrics"
    )
    
    # Load testing parameters
    parser.add_argument(
        "--concurrent-users",
        type=int,
        default=DEFAULT_CONCURRENT_USERS,
        help=f"Number of concurrent users for load testing (default: {DEFAULT_CONCURRENT_USERS})"
    )
    
    parser.add_argument(
        "--test-duration",
        type=int,
        default=DEFAULT_LOAD_TEST_DURATION,
        help=f"Load test duration in seconds (default: {DEFAULT_LOAD_TEST_DURATION})"
    )
    
    parser.add_argument(
        "--base-url",
        default="http://localhost:5000",
        help="Base URL for load testing (default: http://localhost:5000)"
    )
    
    # Validation thresholds
    parser.add_argument(
        "--variance-threshold",
        type=float,
        default=PERFORMANCE_VARIANCE_LIMIT,
        help=f"Performance variance threshold percentage (default: {PERFORMANCE_VARIANCE_LIMIT})"
    )
    
    parser.add_argument(
        "--response-time-threshold",
        type=float,
        default=RESPONSE_TIME_THRESHOLD_MS,
        help=f"Response time threshold in milliseconds (default: {RESPONSE_TIME_THRESHOLD_MS})"
    )
    
    # Output configuration
    parser.add_argument(
        "--output-format",
        choices=["json", "markdown", "html"],
        default="json",
        help="Output format for validation report (default: json)"
    )
    
    parser.add_argument(
        "--output-file", "-o",
        help="Output file path for validation report"
    )
    
    parser.add_argument(
        "--export-metrics",
        help="Export Prometheus metrics to file path"
    )
    
    # CI/CD integration
    parser.add_argument(
        "--ci-cd-mode",
        action="store_true",
        help="Enable CI/CD mode with automated failure handling"
    )
    
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Fail validation if performance regressions detected"
    )
    
    parser.add_argument(
        "--notification-webhook",
        help="Webhook URL for automated performance alerts"
    )
    
    # Debugging and verbose output
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode with detailed logging"
    )
    
    return parser.parse_args()


def load_configuration_from_file(file_path: str) -> Dict[str, Any]:
    """Load performance validation configuration from JSON file."""
    try:
        with open(file_path, 'r') as f:
            config_data = json.load(f)
        logger.info(f"Configuration loaded from: {file_path}")
        return config_data
    except Exception as e:
        logger.error(f"Error loading configuration file: {str(e)}")
        return {}


def create_validation_config(args: argparse.Namespace) -> PerformanceValidationConfig:
    """Create performance validation configuration from command line arguments."""
    config_data = {}
    
    # Load configuration file if specified
    if args.config_file:
        config_data = load_configuration_from_file(args.config_file)
    
    # Override with command line arguments
    config = PerformanceValidationConfig(
        environment=args.environment,
        baseline_comparison_enabled=not args.baseline_only or config_data.get("baseline_comparison_enabled", True),
        load_testing_enabled=args.run_load_test or config_data.get("load_testing_enabled", False),
        regression_detection_enabled=config_data.get("regression_detection_enabled", True),
        automated_alerting_enabled=config_data.get("automated_alerting_enabled", True),
        concurrent_users=args.concurrent_users,
        test_duration_seconds=args.test_duration,
        variance_threshold_percent=args.variance_threshold,
        response_time_threshold_ms=args.response_time_threshold,
        output_format=args.output_format,
        report_file_path=args.output_file,
        ci_cd_mode=args.ci_cd_mode,
        fail_on_regression=args.fail_on_regression,
        notification_webhook_url=args.notification_webhook
    )
    
    return config


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum} - initiating graceful shutdown")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main execution function for performance validation script."""
    setup_signal_handlers()
    
    try:
        # Parse command line arguments
        args = parse_command_line_arguments()
        
        # Configure logging
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)
        else:
            logging.getLogger().setLevel(logging.WARNING)
        
        # Create validation configuration
        config = create_validation_config(args)
        
        logger.info(
            "Performance validation starting",
            environment=config.environment,
            ci_cd_mode=config.ci_cd_mode,
            baseline_comparison=config.baseline_comparison_enabled,
            load_testing=config.load_testing_enabled
        )
        
        # Initialize performance validator
        validator = PerformanceValidator(config)
        
        # Collect system metrics if requested
        if args.collect_system_metrics:
            logger.info("Collecting system performance metrics")
            system_metrics = validator.collect_system_metrics()
            
            if system_metrics:
                # Validate resource utilization
                validator.validate_resource_utilization_performance(
                    system_metrics.get("cpu_utilization_percent", 0),
                    system_metrics.get("memory_usage_mb", 0),
                    "system_metrics"
                )
        
        # Run load testing if enabled
        load_test_results = {}
        if config.load_testing_enabled:
            logger.info("Executing automated load testing")
            load_test_results = validator.run_automated_load_test(args.base_url)
        
        # Detect performance regressions
        logger.info("Performing regression detection analysis")
        validator.detect_performance_regressions()
        
        # Validate overall performance compliance
        logger.info("Validating overall performance compliance")
        compliance_results = validator.validate_overall_performance_compliance()
        
        # Send automated alerts
        validator.send_performance_alerts(compliance_results)
        
        # Generate validation report
        logger.info("Generating performance validation report")
        report = validator.generate_validation_report(compliance_results)
        
        # Output report
        if config.report_file_path:
            with open(config.report_file_path, 'w') as f:
                f.write(report)
            logger.info(f"Validation report saved to: {config.report_file_path}")
        else:
            print(report)
        
        # Export Prometheus metrics if requested
        if args.export_metrics:
            validator.export_prometheus_metrics(args.export_metrics)
        
        # Determine exit status
        if config.ci_cd_mode:
            if not compliance_results["final_compliance_status"]:
                logger.error("Performance validation failed - exiting with error code")
                sys.exit(1)
            elif config.fail_on_regression and compliance_results.get("regression_analysis", {}).get("regressions_detected", 0) > 0:
                logger.error("Performance regressions detected - exiting with error code")
                sys.exit(1)
        
        logger.info(
            "Performance validation completed successfully",
            final_status=compliance_results["final_compliance_status"],
            deployment_recommendation=compliance_results["deployment_recommendation"]
        )
        
        sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Performance validation interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Performance validation failed with error: {str(e)}")
        if args.debug:
            logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()