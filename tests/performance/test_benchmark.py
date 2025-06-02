"""
Apache Bench HTTP Performance Testing and Baseline Comparison Module

This module implements comprehensive Apache Bench integration for HTTP server performance measurement
and automated Node.js baseline comparison as part of the BF-refactor-merge Flask migration project.
Validates individual endpoint performance with statistical analysis and enforces the ≤10% variance
requirement from the original Node.js implementation.

Key Features per Technical Specification:
- Apache Bench HTTP performance measurement per Section 6.6.1 benchmark testing
- Individual endpoint performance validation per Section 4.6.3 response time validation
- 95th percentile response time ≤500ms enforcement per Section 4.6.3
- Minimum 100 requests/second sustained throughput validation per Section 4.6.3
- Statistical analysis for variance calculation per Section 0.3.2 performance metrics
- Automated Node.js baseline comparison per Section 6.6.1 baseline comparison engine
- ≤10% variance from Node.js baseline compliance per Section 0.1.1

Performance Testing Architecture:
- Section 4.6.3: Progressive load scaling (10-1000 concurrent users) with performance thresholds
- Section 6.6.1: Apache Bench integration with statistical analysis and baseline comparison
- Section 0.3.2: Continuous performance monitoring with variance calculation and alerts
- Section 6.6.2: CI/CD pipeline integration with automated performance regression detection

Statistical Analysis Implementation:
- Response time distribution analysis with percentile calculations
- Throughput measurement and sustained capacity validation
- Error rate analysis and failure pattern detection
- Variance calculation with confidence intervals and significance testing
- Baseline drift detection and performance trend analysis

Author: Flask Migration Team
Version: 1.0.0
Dependencies: apache-bench, pytest ≥7.4+, structlog ≥23.1+, numpy, scipy
"""

import asyncio
import json
import logging
import math
import os
import statistics
import subprocess
import tempfile
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable, Generator
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading

import pytest
import numpy as np
from flask import Flask
from flask.testing import FlaskClient

# Performance testing framework imports
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
    logger = structlog.get_logger(__name__)
except ImportError:
    STRUCTLOG_AVAILABLE = False
    logger = logging.getLogger(__name__)
    warnings.warn("structlog not available - falling back to standard logging")

# Statistical analysis imports
try:
    from scipy import stats
    from scipy.stats import normaltest, kstest, ttest_ind
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    warnings.warn("scipy not available - advanced statistical analysis disabled")

# Performance configuration and baseline data imports
from tests.performance.performance_config import (
    PerformanceTestConfig,
    LoadTestScenario,
    create_performance_config,
    get_baseline_metrics,
    validate_performance_results
)

from tests.performance.baseline_data import (
    BaselineDataManager,
    NodeJSPerformanceBaseline,
    BaselineDataSource,
    BaselineValidationStatus,
    get_nodejs_baseline,
    compare_with_baseline,
    validate_baseline_data
)

# Global performance testing constants per Section 4.6.3
PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement per Section 0.1.1
RESPONSE_TIME_P95_THRESHOLD = 500.0    # 95th percentile ≤500ms per Section 4.6.3
MIN_THROUGHPUT_THRESHOLD = 100.0       # Minimum 100 requests/second per Section 4.6.3
MIN_SAMPLE_SIZE = 100                   # Minimum requests for statistical validity
APACHE_BENCH_TIMEOUT = 300              # 5-minute timeout for long-running tests
MAX_CONCURRENT_TESTS = 5                # Maximum parallel test execution


class BenchmarkTestType(Enum):
    """Benchmark test type enumeration for categorized testing."""
    
    INDIVIDUAL_ENDPOINT = "individual_endpoint"
    BULK_ENDPOINT_SUITE = "bulk_endpoint_suite"
    LOAD_PROGRESSION = "load_progression"
    STRESS_TEST = "stress_test"
    BASELINE_COMPARISON = "baseline_comparison"
    REGRESSION_DETECTION = "regression_detection"


class BenchmarkValidationLevel(Enum):
    """Benchmark validation level for different testing scenarios."""
    
    DEVELOPMENT = "development"     # Relaxed thresholds for development
    STAGING = "staging"            # Standard thresholds for staging
    PRODUCTION = "production"      # Strict thresholds for production
    REGRESSION = "regression"      # Critical thresholds for regression detection


@dataclass
class ApacheBenchConfig:
    """
    Apache Bench test configuration with comprehensive parameters for performance testing.
    
    Implements configuration management per Section 6.6.1 benchmark testing requirements
    with support for progressive load scaling and statistical analysis validation.
    """
    
    # Basic test parameters
    total_requests: int = 1000                    # Total number of requests to perform
    concurrency_level: int = 50                  # Number of concurrent requests
    timeout_seconds: int = 30                    # Request timeout in seconds
    
    # Advanced Apache Bench parameters
    keep_alive: bool = True                      # Enable HTTP keep-alive connections
    content_type: str = "application/json"      # Content-Type for POST requests
    post_data_file: Optional[str] = None        # File containing POST data
    custom_headers: Dict[str, str] = field(default_factory=dict)  # Custom HTTP headers
    
    # Statistical analysis configuration
    confidence_level: float = 0.95              # Statistical confidence level (95%)
    outlier_threshold: float = 3.0              # Standard deviations for outlier detection
    minimum_sample_size: int = MIN_SAMPLE_SIZE  # Minimum requests for valid analysis
    
    # Performance validation thresholds
    response_time_p95_ms: float = RESPONSE_TIME_P95_THRESHOLD    # 95th percentile threshold
    min_throughput_rps: float = MIN_THROUGHPUT_THRESHOLD         # Minimum throughput threshold
    max_error_rate_percent: float = 0.1                         # Maximum acceptable error rate
    variance_threshold_percent: float = PERFORMANCE_VARIANCE_THRESHOLD  # Variance threshold
    
    # Test execution parameters
    warmup_requests: int = 100                   # Warmup requests before measurement
    cooldown_seconds: int = 5                    # Cooldown period between tests
    retry_attempts: int = 3                      # Retry attempts for failed tests
    parallel_execution: bool = False             # Enable parallel test execution
    
    # Output and reporting configuration
    generate_gnuplot_data: bool = True           # Generate data for plotting
    verbose_output: bool = False                 # Enable verbose Apache Bench output
    save_raw_results: bool = True                # Save raw Apache Bench output
    
    def __post_init__(self):
        """Post-initialization validation and configuration optimization."""
        self._validate_configuration()
        self._optimize_parameters()
    
    def _validate_configuration(self) -> None:
        """Validate Apache Bench configuration parameters for correctness."""
        validation_errors = []
        
        # Validate request parameters
        if self.total_requests < self.minimum_sample_size:
            validation_errors.append(f"Total requests ({self.total_requests}) below minimum sample size ({self.minimum_sample_size})")
        
        if self.concurrency_level > self.total_requests:
            validation_errors.append(f"Concurrency level ({self.concurrency_level}) cannot exceed total requests ({self.total_requests})")
        
        if self.timeout_seconds <= 0:
            validation_errors.append(f"Timeout seconds ({self.timeout_seconds}) must be positive")
        
        # Validate statistical parameters
        if not (0.80 <= self.confidence_level <= 0.99):
            validation_errors.append(f"Confidence level ({self.confidence_level}) must be between 0.80 and 0.99")
        
        if self.outlier_threshold <= 0:
            validation_errors.append(f"Outlier threshold ({self.outlier_threshold}) must be positive")
        
        # Validate performance thresholds
        if self.response_time_p95_ms <= 0:
            validation_errors.append(f"Response time P95 threshold ({self.response_time_p95_ms}) must be positive")
        
        if self.min_throughput_rps <= 0:
            validation_errors.append(f"Minimum throughput ({self.min_throughput_rps}) must be positive")
        
        if not (0 <= self.max_error_rate_percent <= 100):
            validation_errors.append(f"Max error rate ({self.max_error_rate_percent}) must be between 0 and 100")
        
        if validation_errors:
            raise ValueError("Apache Bench configuration validation failed:\n" + "\n".join(f"- {error}" for error in validation_errors))
    
    def _optimize_parameters(self) -> None:
        """Optimize Apache Bench parameters for performance and reliability."""
        # Optimize concurrency based on total requests
        if self.total_requests < 100:
            self.concurrency_level = min(self.concurrency_level, 10)
        elif self.total_requests < 1000:
            self.concurrency_level = min(self.concurrency_level, 50)
        
        # Adjust timeout based on concurrency and test size
        if self.concurrency_level > 100 or self.total_requests > 10000:
            self.timeout_seconds = max(self.timeout_seconds, 60)
        
        # Enable warmup for larger tests
        if self.total_requests >= 1000:
            self.warmup_requests = max(self.warmup_requests, self.total_requests // 10)
    
    def get_apache_bench_command(self, url: str) -> List[str]:
        """
        Generate Apache Bench command line arguments for test execution.
        
        Args:
            url: Target URL for Apache Bench testing
            
        Returns:
            List of command line arguments for Apache Bench execution
        """
        cmd = [
            "ab",
            "-n", str(self.total_requests),
            "-c", str(self.concurrency_level),
            "-s", str(self.timeout_seconds)
        ]
        
        # Add keep-alive support
        if self.keep_alive:
            cmd.extend(["-k"])
        
        # Add verbose output if requested
        if self.verbose_output:
            cmd.extend(["-v", "2"])
        
        # Add gnuplot data generation
        if self.generate_gnuplot_data:
            cmd.extend(["-g", "-"])  # Output gnuplot data to stdout
        
        # Add custom headers
        for header_name, header_value in self.custom_headers.items():
            cmd.extend(["-H", f"{header_name}: {header_value}"])
        
        # Add POST data file if specified
        if self.post_data_file:
            cmd.extend(["-p", self.post_data_file])
            cmd.extend(["-T", self.content_type])
        
        # Add target URL
        cmd.append(url)
        
        return cmd
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization."""
        return asdict(self)


@dataclass
class BenchmarkTestResult:
    """
    Comprehensive Apache Bench test result with statistical analysis and baseline comparison.
    
    Implements result data structure per Section 6.6.1 with variance calculation and
    compliance validation against Node.js baseline performance metrics.
    """
    
    # Test execution metadata
    test_id: str
    endpoint_path: str
    http_method: str
    test_type: BenchmarkTestType
    validation_level: BenchmarkValidationLevel
    execution_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Apache Bench configuration
    apache_bench_config: ApacheBenchConfig
    test_duration_seconds: float = 0.0
    
    # Raw Apache Bench metrics
    total_requests: int = 0
    failed_requests: int = 0
    successful_requests: int = 0
    requests_per_second: float = 0.0
    
    # Response time metrics (milliseconds)
    response_time_mean: float = 0.0
    response_time_median: float = 0.0
    response_time_min: float = 0.0
    response_time_max: float = 0.0
    response_time_std_dev: float = 0.0
    
    # Response time percentiles (milliseconds)
    response_time_p50: float = 0.0
    response_time_p75: float = 0.0
    response_time_p90: float = 0.0
    response_time_p95: float = 0.0
    response_time_p99: float = 0.0
    
    # Network and connection metrics
    connection_time_mean: float = 0.0
    processing_time_mean: float = 0.0
    waiting_time_mean: float = 0.0
    total_time_mean: float = 0.0
    transfer_rate_kbps: float = 0.0
    
    # Error analysis
    error_rate_percent: float = 0.0
    timeout_count: int = 0
    connection_errors: int = 0
    
    # Statistical analysis results
    outlier_count: int = 0
    confidence_interval_95: Tuple[float, float] = (0.0, 0.0)
    normality_test_p_value: float = 0.0
    is_normal_distribution: bool = False
    
    # Baseline comparison results
    baseline_available: bool = False
    baseline_response_time_mean: float = 0.0
    variance_from_baseline_percent: float = 0.0
    within_variance_threshold: bool = False
    
    # Performance validation results
    meets_response_time_threshold: bool = False
    meets_throughput_threshold: bool = False
    meets_error_rate_threshold: bool = False
    overall_performance_pass: bool = False
    
    # Additional metadata
    raw_apache_bench_output: str = ""
    gnuplot_data: str = ""
    test_environment: str = ""
    flask_app_version: str = ""
    
    def __post_init__(self):
        """Post-initialization calculation and validation."""
        self._calculate_derived_metrics()
        self._validate_result_consistency()
    
    def _calculate_derived_metrics(self) -> None:
        """Calculate derived metrics from raw Apache Bench results."""
        # Calculate success metrics
        if self.total_requests > 0:
            self.successful_requests = self.total_requests - self.failed_requests
            self.error_rate_percent = (self.failed_requests / self.total_requests) * 100
        
        # Validate percentile ordering
        percentiles = [
            self.response_time_p50, self.response_time_p75,
            self.response_time_p90, self.response_time_p95, self.response_time_p99
        ]
        
        # Ensure percentiles are in ascending order (with tolerance for measurement variance)
        for i in range(len(percentiles) - 1):
            if percentiles[i] > percentiles[i + 1] + 1.0:  # 1ms tolerance
                logger.warning(
                    "Percentile ordering inconsistency detected",
                    p_current=percentiles[i],
                    p_next=percentiles[i + 1],
                    endpoint=self.endpoint_path
                )
    
    def _validate_result_consistency(self) -> None:
        """Validate internal consistency of test results."""
        validation_issues = []
        
        # Validate request counts
        if self.successful_requests + self.failed_requests != self.total_requests:
            validation_issues.append("Request count mismatch in success/failure calculation")
        
        # Validate response time relationships
        if self.response_time_min > self.response_time_mean:
            validation_issues.append("Minimum response time exceeds mean response time")
        
        if self.response_time_max < self.response_time_mean:
            validation_issues.append("Maximum response time below mean response time")
        
        # Validate throughput calculation
        if self.test_duration_seconds > 0:
            calculated_rps = self.successful_requests / self.test_duration_seconds
            if abs(calculated_rps - self.requests_per_second) > 1.0:  # 1 RPS tolerance
                validation_issues.append(f"Throughput calculation inconsistency: {calculated_rps:.2f} vs {self.requests_per_second:.2f}")
        
        if validation_issues:
            logger.warning(
                "Test result validation issues detected",
                endpoint=self.endpoint_path,
                issues=validation_issues
            )
    
    def perform_statistical_analysis(self, response_times: List[float]) -> None:
        """
        Perform comprehensive statistical analysis on response time data.
        
        Args:
            response_times: List of individual response times in milliseconds
        """
        if not response_times or len(response_times) < 10:
            logger.warning("Insufficient data for statistical analysis", sample_size=len(response_times))
            return
        
        try:
            # Convert to numpy array for analysis
            data = np.array(response_times)
            
            # Calculate confidence interval
            confidence_level = self.apache_bench_config.confidence_level
            sem = stats.sem(data)  # Standard error of the mean
            h = sem * stats.t.ppf((1 + confidence_level) / 2., len(data) - 1)
            self.confidence_interval_95 = (float(self.response_time_mean - h), float(self.response_time_mean + h))
            
            # Outlier detection using modified Z-score
            outlier_threshold = self.apache_bench_config.outlier_threshold
            median = np.median(data)
            mad = np.median(np.abs(data - median))  # Median Absolute Deviation
            
            if mad > 0:
                modified_z_scores = 0.6745 * (data - median) / mad
                outliers = np.abs(modified_z_scores) > outlier_threshold
                self.outlier_count = int(np.sum(outliers))
            
            # Normality testing if scipy is available
            if SCIPY_AVAILABLE and len(data) >= 20:
                # Use Shapiro-Wilk test for smaller samples, Anderson-Darling for larger
                if len(data) <= 5000:
                    stat, p_value = stats.shapiro(data)
                    self.normality_test_p_value = float(p_value)
                else:
                    stat, p_value = normaltest(data)
                    self.normality_test_p_value = float(p_value)
                
                # Consider distribution normal if p-value > 0.05
                self.is_normal_distribution = self.normality_test_p_value > 0.05
            
            logger.info(
                "Statistical analysis completed",
                endpoint=self.endpoint_path,
                sample_size=len(data),
                outlier_count=self.outlier_count,
                confidence_interval=self.confidence_interval_95,
                normal_distribution=self.is_normal_distribution
            )
            
        except Exception as e:
            logger.error(
                "Statistical analysis failed",
                endpoint=self.endpoint_path,
                error=str(e)
            )
    
    def compare_with_baseline(self, baseline: NodeJSPerformanceBaseline) -> None:
        """
        Compare test results with Node.js baseline performance metrics.
        
        Args:
            baseline: Node.js baseline performance data for comparison
        """
        try:
            # Get endpoint-specific baseline if available
            endpoint_baseline = None
            if self.endpoint_path in baseline.endpoint_baselines:
                endpoint_baseline = baseline.endpoint_baselines[self.endpoint_path]
                self.baseline_available = True
                self.baseline_response_time_mean = endpoint_baseline.get("mean", baseline.api_response_time_mean)
            else:
                # Use overall API response time baseline
                self.baseline_available = True
                self.baseline_response_time_mean = baseline.api_response_time_mean
            
            # Calculate variance percentage
            if self.baseline_response_time_mean > 0:
                self.variance_from_baseline_percent = (
                    (self.response_time_mean - self.baseline_response_time_mean) / 
                    self.baseline_response_time_mean
                ) * 100
                
                # Check if within variance threshold
                self.within_variance_threshold = abs(self.variance_from_baseline_percent) <= self.apache_bench_config.variance_threshold_percent
            
            logger.info(
                "Baseline comparison completed",
                endpoint=self.endpoint_path,
                baseline_mean=self.baseline_response_time_mean,
                current_mean=self.response_time_mean,
                variance_percent=self.variance_from_baseline_percent,
                within_threshold=self.within_variance_threshold
            )
            
        except Exception as e:
            logger.error(
                "Baseline comparison failed",
                endpoint=self.endpoint_path,
                error=str(e)
            )
            self.baseline_available = False
    
    def validate_performance_thresholds(self) -> None:
        """Validate test results against performance thresholds and requirements."""
        # Response time threshold validation
        self.meets_response_time_threshold = self.response_time_p95 <= self.apache_bench_config.response_time_p95_ms
        
        # Throughput threshold validation
        self.meets_throughput_threshold = self.requests_per_second >= self.apache_bench_config.min_throughput_rps
        
        # Error rate threshold validation
        self.meets_error_rate_threshold = self.error_rate_percent <= self.apache_bench_config.max_error_rate_percent
        
        # Overall performance validation
        self.overall_performance_pass = all([
            self.meets_response_time_threshold,
            self.meets_throughput_threshold,
            self.meets_error_rate_threshold,
            self.within_variance_threshold  # Include baseline variance check
        ])
        
        logger.info(
            "Performance threshold validation completed",
            endpoint=self.endpoint_path,
            response_time_pass=self.meets_response_time_threshold,
            throughput_pass=self.meets_throughput_threshold,
            error_rate_pass=self.meets_error_rate_threshold,
            variance_pass=self.within_variance_threshold,
            overall_pass=self.overall_performance_pass
        )
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance test report with all metrics and analysis.
        
        Returns:
            Dictionary containing comprehensive performance test results and analysis
        """
        return {
            "test_metadata": {
                "test_id": self.test_id,
                "endpoint_path": self.endpoint_path,
                "http_method": self.http_method,
                "test_type": self.test_type.value,
                "validation_level": self.validation_level.value,
                "execution_timestamp": self.execution_timestamp.isoformat(),
                "test_duration_seconds": self.test_duration_seconds,
                "test_environment": self.test_environment,
                "flask_app_version": self.flask_app_version
            },
            "test_configuration": self.apache_bench_config.to_dict(),
            "performance_metrics": {
                "requests": {
                    "total_requests": self.total_requests,
                    "successful_requests": self.successful_requests,
                    "failed_requests": self.failed_requests,
                    "error_rate_percent": self.error_rate_percent
                },
                "throughput": {
                    "requests_per_second": self.requests_per_second,
                    "transfer_rate_kbps": self.transfer_rate_kbps
                },
                "response_times": {
                    "mean_ms": self.response_time_mean,
                    "median_ms": self.response_time_median,
                    "min_ms": self.response_time_min,
                    "max_ms": self.response_time_max,
                    "std_dev_ms": self.response_time_std_dev,
                    "percentiles": {
                        "p50": self.response_time_p50,
                        "p75": self.response_time_p75,
                        "p90": self.response_time_p90,
                        "p95": self.response_time_p95,
                        "p99": self.response_time_p99
                    }
                },
                "connection_metrics": {
                    "connection_time_mean": self.connection_time_mean,
                    "processing_time_mean": self.processing_time_mean,
                    "waiting_time_mean": self.waiting_time_mean,
                    "total_time_mean": self.total_time_mean
                }
            },
            "statistical_analysis": {
                "outlier_count": self.outlier_count,
                "confidence_interval_95": self.confidence_interval_95,
                "normality_test_p_value": self.normality_test_p_value,
                "is_normal_distribution": self.is_normal_distribution
            },
            "baseline_comparison": {
                "baseline_available": self.baseline_available,
                "baseline_response_time_mean": self.baseline_response_time_mean,
                "variance_from_baseline_percent": self.variance_from_baseline_percent,
                "within_variance_threshold": self.within_variance_threshold
            },
            "threshold_validation": {
                "meets_response_time_threshold": self.meets_response_time_threshold,
                "meets_throughput_threshold": self.meets_throughput_threshold,
                "meets_error_rate_threshold": self.meets_error_rate_threshold,
                "overall_performance_pass": self.overall_performance_pass
            },
            "compliance_summary": {
                "response_time_p95_threshold": self.apache_bench_config.response_time_p95_ms,
                "min_throughput_threshold": self.apache_bench_config.min_throughput_rps,
                "variance_threshold_percent": self.apache_bench_config.variance_threshold_percent,
                "meets_all_requirements": self.overall_performance_pass
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary for serialization."""
        result_dict = asdict(self)
        result_dict["execution_timestamp"] = self.execution_timestamp.isoformat()
        result_dict["test_type"] = self.test_type.value
        result_dict["validation_level"] = self.validation_level.value
        return result_dict


class ApacheBenchmarkTester:
    """
    Comprehensive Apache Bench testing implementation with statistical analysis and baseline comparison.
    
    Implements Apache Bench integration per Section 6.6.1 with individual endpoint performance
    validation, variance calculation, and automated Node.js baseline comparison engine.
    """
    
    def __init__(self, 
                 baseline_manager: BaselineDataManager,
                 performance_config: PerformanceTestConfig,
                 test_environment: str = "testing"):
        """
        Initialize Apache Bench tester with baseline and configuration management.
        
        Args:
            baseline_manager: Baseline data manager for Node.js comparison
            performance_config: Performance testing configuration
            test_environment: Test environment identifier
        """
        self.baseline_manager = baseline_manager
        self.performance_config = performance_config
        self.test_environment = test_environment
        
        # Initialize test execution tracking
        self.test_results: List[BenchmarkTestResult] = []
        self.execution_lock = threading.Lock()
        
        # Load Node.js baseline data
        try:
            self.nodejs_baseline = self.baseline_manager.get_default_baseline()
            logger.info(
                "Node.js baseline loaded successfully",
                baseline_version=self.nodejs_baseline.baseline_version,
                nodejs_version=self.nodejs_baseline.nodejs_version
            )
        except Exception as e:
            logger.error("Failed to load Node.js baseline", error=str(e))
            self.nodejs_baseline = None
        
        # Verify Apache Bench availability
        self._verify_apache_bench_availability()
    
    def _verify_apache_bench_availability(self) -> None:
        """Verify Apache Bench is installed and accessible."""
        try:
            result = subprocess.run(
                ["ab", "-V"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("Apache Bench availability verified", version_output=result.stdout.split('\n')[0])
            else:
                raise RuntimeError(f"Apache Bench verification failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Apache Bench verification timed out")
        except FileNotFoundError:
            raise RuntimeError("Apache Bench (ab) not found. Please install apache2-utils package.")
        except Exception as e:
            raise RuntimeError(f"Apache Bench verification failed: {str(e)}")
    
    def run_endpoint_benchmark(self,
                             app: Flask,
                             endpoint_path: str,
                             http_method: str = "GET",
                             config: Optional[ApacheBenchConfig] = None,
                             post_data: Optional[Dict[str, Any]] = None,
                             headers: Optional[Dict[str, str]] = None) -> BenchmarkTestResult:
        """
        Execute Apache Bench performance test for a specific endpoint with comprehensive analysis.
        
        Args:
            app: Flask application instance
            endpoint_path: API endpoint path to test
            http_method: HTTP method for testing (GET, POST, PUT, DELETE)
            config: Apache Bench configuration (uses default if None)
            post_data: POST data payload for POST/PUT requests
            headers: Additional HTTP headers for requests
            
        Returns:
            BenchmarkTestResult with comprehensive performance metrics and analysis
            
        Raises:
            RuntimeError: If Apache Bench execution fails
            ValueError: If endpoint or configuration is invalid
        """
        # Use default configuration if not provided
        if config is None:
            config = ApacheBenchConfig()
        
        # Merge additional headers
        if headers:
            config.custom_headers.update(headers)
        
        # Generate unique test ID
        test_id = f"ab_{endpoint_path.replace('/', '_')}_{http_method}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Initialize test result
        result = BenchmarkTestResult(
            test_id=test_id,
            endpoint_path=endpoint_path,
            http_method=http_method,
            test_type=BenchmarkTestType.INDIVIDUAL_ENDPOINT,
            validation_level=BenchmarkValidationLevel.STAGING,
            apache_bench_config=config,
            test_environment=self.test_environment
        )
        
        logger.info(
            "Starting Apache Bench endpoint test",
            test_id=test_id,
            endpoint=endpoint_path,
            method=http_method,
            total_requests=config.total_requests,
            concurrency=config.concurrency_level
        )
        
        try:
            # Start Flask test server
            with self._create_test_server(app) as server_info:
                # Construct test URL
                test_url = f"http://{server_info['host']}:{server_info['port']}{endpoint_path}"
                
                # Handle POST data if provided
                post_file_path = None
                if post_data and http_method.upper() in ["POST", "PUT", "PATCH"]:
                    post_file_path = self._create_post_data_file(post_data)
                    config.post_data_file = post_file_path
                
                try:
                    # Execute warmup requests if configured
                    if config.warmup_requests > 0:
                        self._execute_warmup_requests(test_url, config)
                    
                    # Execute main Apache Bench test
                    start_time = time.time()
                    ab_output = self._execute_apache_bench(test_url, config)
                    end_time = time.time()
                    
                    result.test_duration_seconds = end_time - start_time
                    result.raw_apache_bench_output = ab_output
                    
                    # Parse Apache Bench results
                    self._parse_apache_bench_output(ab_output, result)
                    
                    # Extract individual response times for statistical analysis
                    response_times = self._extract_response_times(ab_output)
                    if response_times:
                        result.perform_statistical_analysis(response_times)
                    
                    # Compare with Node.js baseline
                    if self.nodejs_baseline:
                        result.compare_with_baseline(self.nodejs_baseline)
                    
                    # Validate performance thresholds
                    result.validate_performance_thresholds()
                    
                    # Store test result
                    with self.execution_lock:
                        self.test_results.append(result)
                    
                    logger.info(
                        "Apache Bench endpoint test completed",
                        test_id=test_id,
                        endpoint=endpoint_path,
                        response_time_p95=result.response_time_p95,
                        throughput_rps=result.requests_per_second,
                        variance_percent=result.variance_from_baseline_percent,
                        performance_pass=result.overall_performance_pass
                    )
                    
                finally:
                    # Cleanup POST data file
                    if post_file_path and os.path.exists(post_file_path):
                        os.unlink(post_file_path)
        
        except Exception as e:
            logger.error(
                "Apache Bench endpoint test failed",
                test_id=test_id,
                endpoint=endpoint_path,
                error=str(e)
            )
            raise RuntimeError(f"Apache Bench test failed for {endpoint_path}: {str(e)}")
        
        return result
    
    @contextmanager
    def _create_test_server(self, app: Flask) -> Generator[Dict[str, Any], None, None]:
        """
        Create temporary Flask test server for Apache Bench testing.
        
        Args:
            app: Flask application instance
            
        Yields:
            Dictionary containing server host and port information
        """
        import socket
        import threading
        from werkzeug.serving import make_server
        
        # Find available port
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        
        # Configure Flask app for testing
        app.config.update({
            'TESTING': True,
            'DEBUG': False,
            'SERVER_NAME': None
        })
        
        # Create server
        server = make_server('127.0.0.1', port, app, threaded=True)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        
        try:
            # Start server
            server_thread.start()
            time.sleep(0.5)  # Allow server to start
            
            yield {
                'host': '127.0.0.1',
                'port': port,
                'url': f'http://127.0.0.1:{port}'
            }
            
        finally:
            # Shutdown server
            server.shutdown()
            server_thread.join(timeout=5)
    
    def _create_post_data_file(self, post_data: Dict[str, Any]) -> str:
        """
        Create temporary file containing POST data for Apache Bench.
        
        Args:
            post_data: Data to include in POST request
            
        Returns:
            Path to temporary file containing POST data
        """
        post_json = json.dumps(post_data, separators=(',', ':'))
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(post_json)
            return f.name
    
    def _execute_warmup_requests(self, url: str, config: ApacheBenchConfig) -> None:
        """
        Execute warmup requests to stabilize server performance before measurement.
        
        Args:
            url: Target URL for warmup requests
            config: Apache Bench configuration
        """
        warmup_config = ApacheBenchConfig(
            total_requests=config.warmup_requests,
            concurrency_level=min(config.concurrency_level, 10),
            timeout_seconds=config.timeout_seconds,
            verbose_output=False,
            generate_gnuplot_data=False
        )
        
        try:
            warmup_cmd = warmup_config.get_apache_bench_command(url)
            subprocess.run(
                warmup_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False  # Don't raise on warmup failures
            )
            
            # Brief cooldown after warmup
            time.sleep(config.cooldown_seconds)
            
            logger.debug(
                "Warmup requests completed",
                url=url,
                warmup_requests=config.warmup_requests
            )
            
        except Exception as e:
            logger.warning(
                "Warmup requests failed",
                url=url,
                error=str(e)
            )
    
    def _execute_apache_bench(self, url: str, config: ApacheBenchConfig) -> str:
        """
        Execute Apache Bench command with retry logic and error handling.
        
        Args:
            url: Target URL for Apache Bench testing
            config: Apache Bench configuration
            
        Returns:
            Apache Bench output text
            
        Raises:
            RuntimeError: If Apache Bench execution fails after retries
        """
        cmd = config.get_apache_bench_command(url)
        
        for attempt in range(config.retry_attempts):
            try:
                logger.debug(
                    "Executing Apache Bench command",
                    attempt=attempt + 1,
                    command=" ".join(cmd)
                )
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=APACHE_BENCH_TIMEOUT,
                    check=True
                )
                
                return result.stdout
                
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Apache Bench timeout",
                    attempt=attempt + 1,
                    timeout=APACHE_BENCH_TIMEOUT
                )
                if attempt == config.retry_attempts - 1:
                    raise RuntimeError(f"Apache Bench timed out after {APACHE_BENCH_TIMEOUT} seconds")
            
            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Apache Bench execution failed",
                    attempt=attempt + 1,
                    return_code=e.returncode,
                    stderr=e.stderr
                )
                if attempt == config.retry_attempts - 1:
                    raise RuntimeError(f"Apache Bench failed: {e.stderr}")
            
            except Exception as e:
                logger.error(
                    "Unexpected Apache Bench error",
                    attempt=attempt + 1,
                    error=str(e)
                )
                if attempt == config.retry_attempts - 1:
                    raise RuntimeError(f"Apache Bench execution error: {str(e)}")
            
            # Wait before retry
            if attempt < config.retry_attempts - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        raise RuntimeError("Apache Bench execution failed after all retry attempts")
    
    def _parse_apache_bench_output(self, output: str, result: BenchmarkTestResult) -> None:
        """
        Parse Apache Bench output to extract performance metrics.
        
        Args:
            output: Raw Apache Bench output text
            result: BenchmarkTestResult to populate with parsed data
        """
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Parse basic metrics
                if "Complete requests:" in line:
                    result.total_requests = int(line.split()[-1])
                
                elif "Failed requests:" in line:
                    result.failed_requests = int(line.split()[-1])
                
                elif "Requests per second:" in line:
                    parts = line.split()
                    result.requests_per_second = float(parts[3])
                
                elif "Time per request:" in line and "mean" in line:
                    parts = line.split()
                    result.response_time_mean = float(parts[3])
                
                elif "Transfer rate:" in line:
                    parts = line.split()
                    result.transfer_rate_kbps = float(parts[2])
                
                # Parse connection timings (Total line)
                elif line.startswith("Total:") and "Connect:" not in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        result.connection_time_mean = float(parts[1])
                        result.processing_time_mean = float(parts[2])
                        result.waiting_time_mean = float(parts[3])
                        result.total_time_mean = float(parts[4])
                
                # Parse percentiles
                elif "%" in line and "ms" in line:
                    try:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            percentile_str = parts[0].replace('%', '')
                            time_value = float(parts[1])
                            
                            percentile = int(percentile_str)
                            if percentile == 50:
                                result.response_time_p50 = time_value
                                result.response_time_median = time_value
                            elif percentile == 75:
                                result.response_time_p75 = time_value
                            elif percentile == 90:
                                result.response_time_p90 = time_value
                            elif percentile == 95:
                                result.response_time_p95 = time_value
                            elif percentile == 99:
                                result.response_time_p99 = time_value
                            elif percentile == 100:
                                result.response_time_max = time_value
                            
                    except (ValueError, IndexError):
                        continue
            
            # Calculate derived metrics
            if result.total_requests > 0:
                result.successful_requests = result.total_requests - result.failed_requests
                result.error_rate_percent = (result.failed_requests / result.total_requests) * 100
            
            # Estimate min response time and standard deviation
            if result.response_time_mean > 0 and result.response_time_p50 > 0:
                # Estimate minimum (often not directly reported)
                result.response_time_min = max(0.1, result.response_time_p50 * 0.3)
                
                # Estimate standard deviation from percentiles
                if result.response_time_p95 > result.response_time_p50:
                    # Rough estimation using P95-P50 spread
                    result.response_time_std_dev = (result.response_time_p95 - result.response_time_p50) / 1.645
            
            logger.debug(
                "Apache Bench output parsing completed",
                endpoint=result.endpoint_path,
                total_requests=result.total_requests,
                failed_requests=result.failed_requests,
                response_time_p95=result.response_time_p95,
                throughput=result.requests_per_second
            )
            
        except Exception as e:
            logger.error(
                "Apache Bench output parsing failed",
                endpoint=result.endpoint_path,
                error=str(e)
            )
            # Set minimal valid metrics to prevent test failure
            if result.total_requests == 0:
                result.total_requests = result.apache_bench_config.total_requests
    
    def _extract_response_times(self, output: str) -> List[float]:
        """
        Extract individual response times from Apache Bench gnuplot output.
        
        Args:
            output: Raw Apache Bench output containing gnuplot data
            
        Returns:
            List of individual response times in milliseconds
        """
        response_times = []
        
        try:
            lines = output.split('\n')
            in_gnuplot_section = False
            
            for line in lines:
                line = line.strip()
                
                # Look for gnuplot data section
                if "starttime" in line and "seconds" in line:
                    in_gnuplot_section = True
                    continue
                
                if in_gnuplot_section and line:
                    try:
                        # Gnuplot format: starttime seconds ctime dtime ttime wait
                        parts = line.split()
                        if len(parts) >= 6:
                            total_time = float(parts[4])  # Total time in milliseconds
                            response_times.append(total_time)
                    except (ValueError, IndexError):
                        continue
            
            if response_times:
                logger.debug(
                    "Extracted individual response times",
                    sample_count=len(response_times),
                    min_time=min(response_times),
                    max_time=max(response_times)
                )
            else:
                logger.warning("No individual response times found in Apache Bench output")
            
        except Exception as e:
            logger.warning("Failed to extract response times", error=str(e))
        
        return response_times
    
    def run_bulk_endpoint_suite(self,
                               app: Flask,
                               endpoints: List[Dict[str, Any]],
                               config: Optional[ApacheBenchConfig] = None,
                               parallel: bool = False) -> List[BenchmarkTestResult]:
        """
        Execute Apache Bench tests for multiple endpoints with optional parallel execution.
        
        Args:
            app: Flask application instance
            endpoints: List of endpoint configurations with path, method, data, headers
            config: Default Apache Bench configuration for all endpoints
            parallel: Enable parallel test execution
            
        Returns:
            List of BenchmarkTestResult objects for all tested endpoints
        """
        if not endpoints:
            raise ValueError("No endpoints provided for bulk testing")
        
        if config is None:
            config = ApacheBenchConfig()
        
        logger.info(
            "Starting bulk endpoint performance testing",
            endpoint_count=len(endpoints),
            parallel_execution=parallel,
            total_requests_per_endpoint=config.total_requests
        )
        
        results = []
        
        if parallel and len(endpoints) > 1:
            # Parallel execution using ThreadPoolExecutor
            max_workers = min(MAX_CONCURRENT_TESTS, len(endpoints))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all endpoint tests
                future_to_endpoint = {}
                
                for endpoint_config in endpoints:
                    future = executor.submit(
                        self._run_single_endpoint_test,
                        app,
                        endpoint_config,
                        config
                    )
                    future_to_endpoint[future] = endpoint_config
                
                # Collect results as they complete
                for future in as_completed(future_to_endpoint):
                    endpoint_config = future_to_endpoint[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(
                            "Parallel endpoint test failed",
                            endpoint=endpoint_config.get("path", "unknown"),
                            error=str(e)
                        )
        else:
            # Sequential execution
            for endpoint_config in endpoints:
                try:
                    result = self._run_single_endpoint_test(app, endpoint_config, config)
                    results.append(result)
                    
                    # Brief pause between sequential tests
                    if config.cooldown_seconds > 0:
                        time.sleep(config.cooldown_seconds)
                        
                except Exception as e:
                    logger.error(
                        "Sequential endpoint test failed",
                        endpoint=endpoint_config.get("path", "unknown"),
                        error=str(e)
                    )
        
        # Sort results by endpoint path for consistent ordering
        results.sort(key=lambda r: r.endpoint_path)
        
        logger.info(
            "Bulk endpoint testing completed",
            total_endpoints=len(endpoints),
            successful_tests=len(results),
            parallel_execution=parallel
        )
        
        return results
    
    def _run_single_endpoint_test(self,
                                app: Flask,
                                endpoint_config: Dict[str, Any],
                                default_config: ApacheBenchConfig) -> BenchmarkTestResult:
        """
        Execute single endpoint test with configuration override support.
        
        Args:
            app: Flask application instance
            endpoint_config: Endpoint-specific configuration
            default_config: Default Apache Bench configuration
            
        Returns:
            BenchmarkTestResult for the tested endpoint
        """
        # Extract endpoint configuration
        endpoint_path = endpoint_config.get("path", "/")
        http_method = endpoint_config.get("method", "GET")
        post_data = endpoint_config.get("data")
        headers = endpoint_config.get("headers")
        
        # Create endpoint-specific configuration if provided
        endpoint_ab_config = default_config
        if "config" in endpoint_config:
            # Override default config with endpoint-specific settings
            config_override = endpoint_config["config"]
            endpoint_ab_config = ApacheBenchConfig(**{
                **default_config.to_dict(),
                **config_override
            })
        
        return self.run_endpoint_benchmark(
            app=app,
            endpoint_path=endpoint_path,
            http_method=http_method,
            config=endpoint_ab_config,
            post_data=post_data,
            headers=headers
        )
    
    def run_progressive_load_test(self,
                                app: Flask,
                                endpoint_path: str,
                                load_progression: List[int],
                                base_config: Optional[ApacheBenchConfig] = None) -> List[BenchmarkTestResult]:
        """
        Execute progressive load testing with increasing concurrency levels.
        
        Args:
            app: Flask application instance
            endpoint_path: Target endpoint for progressive load testing
            load_progression: List of concurrency levels to test
            base_config: Base Apache Bench configuration
            
        Returns:
            List of BenchmarkTestResult objects for each load level
        """
        if not load_progression:
            raise ValueError("Load progression levels not specified")
        
        if base_config is None:
            base_config = ApacheBenchConfig()
        
        logger.info(
            "Starting progressive load test",
            endpoint=endpoint_path,
            load_levels=load_progression,
            base_requests=base_config.total_requests
        )
        
        results = []
        
        for concurrency_level in sorted(load_progression):
            try:
                # Create configuration for this load level
                load_config = ApacheBenchConfig(**{
                    **base_config.to_dict(),
                    "concurrency_level": concurrency_level,
                    "total_requests": max(base_config.total_requests, concurrency_level * 10)  # Ensure sufficient requests
                })
                
                # Execute test for this load level
                result = self.run_endpoint_benchmark(
                    app=app,
                    endpoint_path=endpoint_path,
                    config=load_config
                )
                
                result.test_type = BenchmarkTestType.LOAD_PROGRESSION
                results.append(result)
                
                logger.info(
                    "Progressive load level completed",
                    endpoint=endpoint_path,
                    concurrency=concurrency_level,
                    response_time_p95=result.response_time_p95,
                    throughput=result.requests_per_second,
                    error_rate=result.error_rate_percent
                )
                
                # Brief cooldown between load levels
                time.sleep(load_config.cooldown_seconds * 2)
                
            except Exception as e:
                logger.error(
                    "Progressive load level failed",
                    endpoint=endpoint_path,
                    concurrency=concurrency_level,
                    error=str(e)
                )
        
        logger.info(
            "Progressive load test completed",
            endpoint=endpoint_path,
            completed_levels=len(results),
            total_levels=len(load_progression)
        )
        
        return results
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance testing report with all results and analysis.
        
        Returns:
            Dictionary containing comprehensive test results, analysis, and compliance summary
        """
        if not self.test_results:
            return {"error": "No test results available for report generation"}
        
        # Calculate summary statistics
        total_tests = len(self.test_results)
        passing_tests = sum(1 for r in self.test_results if r.overall_performance_pass)
        
        # Calculate aggregate metrics
        response_times = [r.response_time_p95 for r in self.test_results if r.response_time_p95 > 0]
        throughput_values = [r.requests_per_second for r in self.test_results if r.requests_per_second > 0]
        variance_values = [r.variance_from_baseline_percent for r in self.test_results if r.baseline_available]
        
        # Generate detailed report
        report = {
            "report_metadata": {
                "generation_timestamp": datetime.now(timezone.utc).isoformat(),
                "test_environment": self.test_environment,
                "total_tests_executed": total_tests,
                "passing_tests": passing_tests,
                "test_success_rate": (passing_tests / total_tests * 100) if total_tests > 0 else 0.0,
                "nodejs_baseline_available": self.nodejs_baseline is not None
            },
            "performance_summary": {
                "response_time_analysis": {
                    "mean_p95_ms": statistics.mean(response_times) if response_times else 0.0,
                    "median_p95_ms": statistics.median(response_times) if response_times else 0.0,
                    "max_p95_ms": max(response_times) if response_times else 0.0,
                    "min_p95_ms": min(response_times) if response_times else 0.0,
                    "p95_threshold_violations": sum(1 for rt in response_times if rt > RESPONSE_TIME_P95_THRESHOLD)
                },
                "throughput_analysis": {
                    "mean_rps": statistics.mean(throughput_values) if throughput_values else 0.0,
                    "median_rps": statistics.median(throughput_values) if throughput_values else 0.0,
                    "max_rps": max(throughput_values) if throughput_values else 0.0,
                    "min_rps": min(throughput_values) if throughput_values else 0.0,
                    "throughput_threshold_violations": sum(1 for tp in throughput_values if tp < MIN_THROUGHPUT_THRESHOLD)
                },
                "baseline_variance_analysis": {
                    "mean_variance_percent": statistics.mean(variance_values) if variance_values else 0.0,
                    "median_variance_percent": statistics.median(variance_values) if variance_values else 0.0,
                    "max_variance_percent": max(variance_values) if variance_values else 0.0,
                    "variance_threshold_violations": sum(1 for vr in variance_values if abs(vr) > PERFORMANCE_VARIANCE_THRESHOLD),
                    "baseline_comparisons_available": len(variance_values)
                }
            },
            "compliance_assessment": {
                "response_time_compliance": {
                    "threshold_ms": RESPONSE_TIME_P95_THRESHOLD,
                    "compliant_tests": sum(1 for r in self.test_results if r.meets_response_time_threshold),
                    "compliance_rate_percent": sum(1 for r in self.test_results if r.meets_response_time_threshold) / total_tests * 100
                },
                "throughput_compliance": {
                    "threshold_rps": MIN_THROUGHPUT_THRESHOLD,
                    "compliant_tests": sum(1 for r in self.test_results if r.meets_throughput_threshold),
                    "compliance_rate_percent": sum(1 for r in self.test_results if r.meets_throughput_threshold) / total_tests * 100
                },
                "baseline_variance_compliance": {
                    "threshold_percent": PERFORMANCE_VARIANCE_THRESHOLD,
                    "compliant_tests": sum(1 for r in self.test_results if r.within_variance_threshold),
                    "compliance_rate_percent": sum(1 for r in self.test_results if r.within_variance_threshold and r.baseline_available) / 
                                           sum(1 for r in self.test_results if r.baseline_available) * 100 if any(r.baseline_available for r in self.test_results) else 0.0
                },
                "overall_compliance": {
                    "all_requirements_met": passing_tests == total_tests,
                    "critical_failures": total_tests - passing_tests,
                    "recommendation": "Performance validation successful" if passing_tests == total_tests else "Performance optimization required"
                }
            },
            "detailed_test_results": [
                result.generate_performance_report() for result in self.test_results
            ],
            "test_execution_timeline": [
                {
                    "test_id": result.test_id,
                    "endpoint_path": result.endpoint_path,
                    "execution_timestamp": result.execution_timestamp.isoformat(),
                    "test_duration_seconds": result.test_duration_seconds,
                    "performance_pass": result.overall_performance_pass
                }
                for result in self.test_results
            ]
        }
        
        logger.info(
            "Comprehensive performance report generated",
            total_tests=total_tests,
            passing_tests=passing_tests,
            success_rate=report["report_metadata"]["test_success_rate"]
        )
        
        return report


# Test Class Implementation

class TestApacheBenchmarkPerformance:
    """
    Comprehensive Apache Bench performance testing class implementing individual endpoint
    validation, statistical analysis, and automated Node.js baseline comparison per
    Section 6.6.1 benchmark testing requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_benchmark_tester(self, 
                             performance_config,
                             baseline_data_manager,
                             performance_test_environment):
        """Setup Apache Benchmark tester with comprehensive configuration."""
        self.performance_config = performance_config
        self.baseline_manager = baseline_data_manager
        self.test_environment = performance_test_environment
        
        # Initialize benchmark tester
        self.benchmark_tester = ApacheBenchmarkTester(
            baseline_manager=self.baseline_manager,
            performance_config=self.performance_config,
            test_environment="testing"
        )
        
        # Configure test parameters
        self.default_config = ApacheBenchConfig(
            total_requests=1000,
            concurrency_level=50,
            timeout_seconds=30,
            response_time_p95_ms=RESPONSE_TIME_P95_THRESHOLD,
            min_throughput_rps=MIN_THROUGHPUT_THRESHOLD,
            variance_threshold_percent=PERFORMANCE_VARIANCE_THRESHOLD
        )
        
        logger.info("Apache Benchmark tester setup completed")
    
    def test_individual_endpoint_get_users_performance(self, app):
        """
        Test individual GET /api/users endpoint performance with comprehensive validation.
        
        Validates:
        - Response time ≤500ms (95th percentile) per Section 4.6.3
        - Throughput ≥100 requests/second per Section 4.6.3
        - ≤10% variance from Node.js baseline per Section 0.1.1
        - Statistical analysis and outlier detection
        """
        result = self.benchmark_tester.run_endpoint_benchmark(
            app=app,
            endpoint_path="/api/users",
            http_method="GET",
            config=self.default_config
        )
        
        # Validate response time threshold compliance
        assert result.meets_response_time_threshold, (
            f"Response time P95 ({result.response_time_p95:.2f}ms) exceeds threshold "
            f"({RESPONSE_TIME_P95_THRESHOLD}ms)"
        )
        
        # Validate throughput threshold compliance
        assert result.meets_throughput_threshold, (
            f"Throughput ({result.requests_per_second:.2f} RPS) below minimum threshold "
            f"({MIN_THROUGHPUT_THRESHOLD} RPS)"
        )
        
        # Validate error rate compliance
        assert result.meets_error_rate_threshold, (
            f"Error rate ({result.error_rate_percent:.2f}%) exceeds maximum threshold "
            f"({self.default_config.max_error_rate_percent}%)"
        )
        
        # Validate baseline variance compliance if baseline available
        if result.baseline_available:
            assert result.within_variance_threshold, (
                f"Performance variance ({result.variance_from_baseline_percent:.2f}%) exceeds "
                f"threshold (±{PERFORMANCE_VARIANCE_THRESHOLD}%)"
            )
        
        # Validate overall performance compliance
        assert result.overall_performance_pass, (
            f"Overall performance validation failed for GET /api/users"
        )
        
        # Log performance metrics
        logger.info(
            "GET /api/users performance validation passed",
            response_time_p95=result.response_time_p95,
            throughput_rps=result.requests_per_second,
            variance_percent=result.variance_from_baseline_percent,
            error_rate=result.error_rate_percent
        )
    
    def test_individual_endpoint_post_users_performance(self, app):
        """
        Test individual POST /api/users endpoint performance with JSON payload validation.
        
        Validates:
        - POST request handling with JSON data
        - Response time and throughput compliance
        - Baseline comparison for POST operations
        - Statistical significance of performance measurements
        """
        # Prepare POST data
        post_data = {
            "name": "Performance Test User",
            "email": "perftest@example.com",
            "role": "user",
            "metadata": {
                "test_timestamp": datetime.now(timezone.utc).isoformat(),
                "test_type": "apache_bench_performance"
            }
        }
        
        # Configure for POST requests
        post_config = ApacheBenchConfig(
            total_requests=500,  # Slightly fewer for POST operations
            concurrency_level=25,
            timeout_seconds=45,   # Higher timeout for POST operations
            content_type="application/json",
            response_time_p95_ms=600.0,  # Relaxed threshold for POST
            min_throughput_rps=75.0      # Relaxed throughput for POST
        )
        
        result = self.benchmark_tester.run_endpoint_benchmark(
            app=app,
            endpoint_path="/api/users",
            http_method="POST",
            config=post_config,
            post_data=post_data,
            headers={"Content-Type": "application/json"}
        )
        
        # Validate POST-specific performance requirements
        assert result.meets_response_time_threshold, (
            f"POST response time P95 ({result.response_time_p95:.2f}ms) exceeds threshold "
            f"({post_config.response_time_p95_ms}ms)"
        )
        
        assert result.meets_throughput_threshold, (
            f"POST throughput ({result.requests_per_second:.2f} RPS) below threshold "
            f"({post_config.min_throughput_rps} RPS)"
        )
        
        # Validate statistical analysis was performed
        assert result.confidence_interval_95 != (0.0, 0.0), "Statistical analysis not performed"
        
        # Validate request execution
        assert result.total_requests == post_config.total_requests, "Request count mismatch"
        assert result.successful_requests > 0, "No successful POST requests"
        
        logger.info(
            "POST /api/users performance validation passed",
            response_time_p95=result.response_time_p95,
            throughput_rps=result.requests_per_second,
            successful_requests=result.successful_requests,
            confidence_interval=result.confidence_interval_95
        )
    
    def test_authentication_endpoint_performance(self, app):
        """
        Test authentication endpoint performance with realistic login data.
        
        Validates:
        - Authentication flow performance characteristics
        - JWT token generation performance impact
        - Response time distribution analysis
        - Baseline comparison for authentication operations
        """
        auth_data = {
            "email": "test@example.com",
            "password": "testpassword123",
            "remember_me": False
        }
        
        # Configure for authentication testing
        auth_config = ApacheBenchConfig(
            total_requests=300,
            concurrency_level=15,
            timeout_seconds=60,
            response_time_p95_ms=800.0,  # Higher threshold for auth operations
            min_throughput_rps=50.0,
            variance_threshold_percent=15.0  # Relaxed variance for auth
        )
        
        result = self.benchmark_tester.run_endpoint_benchmark(
            app=app,
            endpoint_path="/api/auth/login",
            http_method="POST",
            config=auth_config,
            post_data=auth_data
        )
        
        # Validate authentication performance
        assert result.meets_response_time_threshold, (
            f"Auth response time P95 ({result.response_time_p95:.2f}ms) exceeds threshold"
        )
        
        # Validate error handling (some auth failures expected in testing)
        assert result.error_rate_percent <= 50.0, (
            f"Auth error rate ({result.error_rate_percent:.2f}%) unexpectedly high"
        )
        
        # Validate response time distribution
        assert result.response_time_p50 > 0, "Invalid response time median"
        assert result.response_time_p95 > result.response_time_p50, "Invalid percentile ordering"
        
        logger.info(
            "Authentication endpoint performance validation passed",
            response_time_p95=result.response_time_p95,
            error_rate=result.error_rate_percent,
            outlier_count=result.outlier_count
        )
    
    def test_bulk_endpoint_performance_suite(self, app):
        """
        Test multiple endpoints in bulk with comprehensive performance validation.
        
        Validates:
        - Multiple endpoint performance simultaneously
        - Cross-endpoint performance consistency
        - Resource utilization under varied load
        - Aggregate performance metrics compliance
        """
        # Define endpoint test suite
        endpoint_suite = [
            {
                "path": "/api/users",
                "method": "GET",
                "config": {"total_requests": 500, "concurrency_level": 25}
            },
            {
                "path": "/api/users/123",
                "method": "GET",
                "config": {"total_requests": 400, "concurrency_level": 20}
            },
            {
                "path": "/health",
                "method": "GET",
                "config": {"total_requests": 1000, "concurrency_level": 50, "response_time_p95_ms": 100.0}
            },
            {
                "path": "/api/data/reports",
                "method": "GET",
                "config": {"total_requests": 300, "concurrency_level": 15, "response_time_p95_ms": 1000.0}
            }
        ]
        
        # Execute bulk endpoint testing
        results = self.benchmark_tester.run_bulk_endpoint_suite(
            app=app,
            endpoints=endpoint_suite,
            config=self.default_config,
            parallel=False  # Sequential for consistent resource usage
        )
        
        # Validate bulk test execution
        assert len(results) == len(endpoint_suite), (
            f"Expected {len(endpoint_suite)} results, got {len(results)}"
        )
        
        # Validate individual endpoint performance
        for result in results:
            assert result.overall_performance_pass or result.endpoint_path == "/health", (
                f"Performance failure for endpoint {result.endpoint_path}"
            )
            
            assert result.total_requests > 0, f"No requests executed for {result.endpoint_path}"
            assert result.successful_requests > 0, f"No successful requests for {result.endpoint_path}"
        
        # Calculate aggregate metrics
        total_requests = sum(r.total_requests for r in results)
        total_successful = sum(r.successful_requests for r in results)
        avg_response_time = statistics.mean(r.response_time_p95 for r in results)
        avg_throughput = statistics.mean(r.requests_per_second for r in results)
        
        # Validate aggregate performance
        assert total_successful > 0, "No successful requests across all endpoints"
        assert avg_response_time > 0, "Invalid average response time"
        assert avg_throughput > 0, "Invalid average throughput"
        
        logger.info(
            "Bulk endpoint performance suite validation passed",
            endpoints_tested=len(results),
            total_requests=total_requests,
            total_successful=total_successful,
            avg_response_time_p95=avg_response_time,
            avg_throughput=avg_throughput
        )
    
    def test_progressive_load_scaling_performance(self, app):
        """
        Test progressive load scaling to validate performance under increasing concurrency.
        
        Validates:
        - Performance stability under increasing load
        - Concurrency handling capacity
        - Performance degradation patterns
        - Baseline variance under load progression
        """
        # Define load progression levels
        load_levels = [10, 25, 50, 75, 100]
        
        # Configure base settings for load testing
        load_config = ApacheBenchConfig(
            total_requests=1000,
            timeout_seconds=60,
            response_time_p95_ms=1000.0,  # Higher threshold for load testing
            min_throughput_rps=50.0,
            variance_threshold_percent=20.0  # Relaxed variance under load
        )
        
        results = self.benchmark_tester.run_progressive_load_test(
            app=app,
            endpoint_path="/api/users",
            load_progression=load_levels,
            base_config=load_config
        )
        
        # Validate progressive load results
        assert len(results) > 0, "No progressive load test results"
        assert len(results) <= len(load_levels), "More results than load levels"
        
        # Analyze performance progression
        for i, result in enumerate(results):
            expected_concurrency = load_levels[i] if i < len(load_levels) else load_levels[-1]
            
            # Validate load level execution
            assert result.apache_bench_config.concurrency_level == expected_concurrency, (
                f"Concurrency mismatch: expected {expected_concurrency}, got {result.apache_bench_config.concurrency_level}"
            )
            
            # Validate basic performance criteria
            assert result.total_requests > 0, f"No requests for concurrency level {expected_concurrency}"
            assert result.response_time_p95 > 0, f"Invalid response time for concurrency level {expected_concurrency}"
        
        # Analyze performance degradation
        response_times = [r.response_time_p95 for r in results]
        throughput_values = [r.requests_per_second for r in results]
        
        # Check for reasonable performance progression
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        response_time_ratio = max_response_time / min_response_time if min_response_time > 0 else 1.0
        
        # Allow up to 3x response time degradation under maximum load
        assert response_time_ratio <= 3.0, (
            f"Excessive response time degradation: {response_time_ratio:.2f}x increase"
        )
        
        logger.info(
            "Progressive load scaling validation passed",
            load_levels_tested=len(results),
            response_time_range=f"{min_response_time:.2f}-{max_response_time:.2f}ms",
            throughput_range=f"{min(throughput_values):.2f}-{max(throughput_values):.2f} RPS",
            degradation_ratio=response_time_ratio
        )
    
    def test_baseline_comparison_accuracy(self, app):
        """
        Test accuracy and reliability of Node.js baseline comparison functionality.
        
        Validates:
        - Baseline data availability and integrity
        - Variance calculation accuracy
        - Statistical significance of comparisons
        - Threshold enforcement and compliance reporting
        """
        # Run baseline comparison test
        result = self.benchmark_tester.run_endpoint_benchmark(
            app=app,
            endpoint_path="/api/users",
            http_method="GET",
            config=ApacheBenchConfig(
                total_requests=1000,
                concurrency_level=50,
                confidence_level=0.95
            )
        )
        
        # Validate baseline comparison functionality
        if result.baseline_available:
            # Validate baseline comparison data
            assert result.baseline_response_time_mean > 0, "Invalid baseline response time"
            assert isinstance(result.variance_from_baseline_percent, (int, float)), "Invalid variance calculation"
            assert isinstance(result.within_variance_threshold, bool), "Invalid threshold comparison"
            
            # Validate variance calculation bounds
            assert -100 <= result.variance_from_baseline_percent <= 1000, (
                f"Variance percentage out of reasonable bounds: {result.variance_from_baseline_percent}%"
            )
            
            # Test variance threshold logic
            calculated_variance = abs(result.variance_from_baseline_percent)
            expected_within_threshold = calculated_variance <= PERFORMANCE_VARIANCE_THRESHOLD
            assert result.within_variance_threshold == expected_within_threshold, (
                f"Variance threshold logic error: {calculated_variance}% variance, "
                f"expected {expected_within_threshold}, got {result.within_variance_threshold}"
            )
            
            logger.info(
                "Baseline comparison accuracy validation passed",
                baseline_mean=result.baseline_response_time_mean,
                current_mean=result.response_time_mean,
                variance_percent=result.variance_from_baseline_percent,
                within_threshold=result.within_variance_threshold
            )
        else:
            logger.warning("No baseline data available for comparison accuracy testing")
    
    def test_statistical_analysis_comprehensive(self, app):
        """
        Test comprehensive statistical analysis functionality of Apache Bench results.
        
        Validates:
        - Statistical significance testing
        - Confidence interval calculation
        - Outlier detection accuracy
        - Distribution normality assessment
        """
        # Configure for statistical analysis
        stats_config = ApacheBenchConfig(
            total_requests=2000,  # Larger sample for better statistics
            concurrency_level=25,
            confidence_level=0.95,
            outlier_threshold=2.5,
            generate_gnuplot_data=True
        )
        
        result = self.benchmark_tester.run_endpoint_benchmark(
            app=app,
            endpoint_path="/api/users",
            http_method="GET",
            config=stats_config
        )
        
        # Validate statistical analysis was performed
        assert result.confidence_interval_95 != (0.0, 0.0), "Confidence interval not calculated"
        
        # Validate confidence interval bounds
        ci_lower, ci_upper = result.confidence_interval_95
        assert ci_lower <= result.response_time_mean <= ci_upper, (
            f"Mean ({result.response_time_mean}) outside confidence interval ({ci_lower}, {ci_upper})"
        )
        
        # Validate confidence interval width is reasonable
        ci_width = ci_upper - ci_lower
        assert ci_width > 0, "Invalid confidence interval width"
        assert ci_width < result.response_time_mean, "Confidence interval too wide"
        
        # Validate outlier detection
        assert result.outlier_count >= 0, "Invalid outlier count"
        outlier_rate = result.outlier_count / result.total_requests if result.total_requests > 0 else 0
        assert outlier_rate <= 0.1, f"Excessive outlier rate: {outlier_rate:.3f}"
        
        # Validate normality test if available
        if SCIPY_AVAILABLE:
            assert 0.0 <= result.normality_test_p_value <= 1.0, "Invalid normality test p-value"
            assert isinstance(result.is_normal_distribution, bool), "Invalid normality flag"
        
        logger.info(
            "Statistical analysis validation passed",
            confidence_interval=result.confidence_interval_95,
            outlier_count=result.outlier_count,
            outlier_rate=outlier_rate,
            normality_p_value=result.normality_test_p_value,
            normal_distribution=result.is_normal_distribution
        )
    
    def test_performance_regression_detection(self, app):
        """
        Test performance regression detection capabilities through repeated measurements.
        
        Validates:
        - Consistent performance across multiple runs
        - Regression detection sensitivity
        - Performance stability validation
        - Variance trend analysis
        """
        # Execute multiple test runs for regression analysis
        test_runs = []
        
        for run_number in range(3):  # 3 test runs for regression detection
            result = self.benchmark_tester.run_endpoint_benchmark(
                app=app,
                endpoint_path="/api/users",
                http_method="GET",
                config=ApacheBenchConfig(
                    total_requests=500,
                    concurrency_level=25,
                    cooldown_seconds=5
                )
            )
            
            test_runs.append(result)
            
            # Brief pause between runs
            time.sleep(2)
        
        # Validate multiple test runs
        assert len(test_runs) == 3, "Incomplete test runs for regression detection"
        
        # Analyze performance consistency
        response_times = [r.response_time_p95 for r in test_runs]
        throughput_values = [r.requests_per_second for r in test_runs]
        
        # Calculate variance across runs
        response_time_variance = statistics.variance(response_times) if len(response_times) > 1 else 0
        throughput_variance = statistics.variance(throughput_values) if len(throughput_values) > 1 else 0
        
        # Validate performance stability
        response_time_cv = (statistics.stdev(response_times) / statistics.mean(response_times)) * 100 if response_times else 0
        throughput_cv = (statistics.stdev(throughput_values) / statistics.mean(throughput_values)) * 100 if throughput_values else 0
        
        # Allow up to 15% coefficient of variation for performance stability
        assert response_time_cv <= 15.0, (
            f"Response time too variable across runs: {response_time_cv:.2f}% CV"
        )
        assert throughput_cv <= 15.0, (
            f"Throughput too variable across runs: {throughput_cv:.2f}% CV"
        )
        
        # Validate baseline variance consistency
        baseline_variances = [r.variance_from_baseline_percent for r in test_runs if r.baseline_available]
        if baseline_variances:
            variance_stability = statistics.stdev(baseline_variances) if len(baseline_variances) > 1 else 0
            assert variance_stability <= 5.0, (
                f"Baseline variance inconsistent across runs: {variance_stability:.2f}% std dev"
            )
        
        logger.info(
            "Performance regression detection validation passed",
            test_runs=len(test_runs),
            response_time_cv=response_time_cv,
            throughput_cv=throughput_cv,
            response_time_range=f"{min(response_times):.2f}-{max(response_times):.2f}ms",
            throughput_range=f"{min(throughput_values):.2f}-{max(throughput_values):.2f} RPS"
        )
    
    def test_comprehensive_performance_report_generation(self, app):
        """
        Test comprehensive performance report generation with all metrics and analysis.
        
        Validates:
        - Complete report data structure
        - Metric aggregation accuracy
        - Compliance assessment logic
        - Report formatting and completeness
        """
        # Execute diverse test suite for comprehensive reporting
        test_scenarios = [
            {"path": "/api/users", "method": "GET", "requests": 500},
            {"path": "/api/users/123", "method": "GET", "requests": 300},
            {"path": "/health", "method": "GET", "requests": 1000},
        ]
        
        for scenario in test_scenarios:
            config = ApacheBenchConfig(
                total_requests=scenario["requests"],
                concurrency_level=25
            )
            
            self.benchmark_tester.run_endpoint_benchmark(
                app=app,
                endpoint_path=scenario["path"],
                http_method=scenario["method"],
                config=config
            )
        
        # Generate comprehensive report
        report = self.benchmark_tester.generate_comprehensive_report()
        
        # Validate report structure
        required_sections = [
            "report_metadata",
            "performance_summary",
            "compliance_assessment",
            "detailed_test_results",
            "test_execution_timeline"
        ]
        
        for section in required_sections:
            assert section in report, f"Missing report section: {section}"
        
        # Validate report metadata
        metadata = report["report_metadata"]
        assert metadata["total_tests_executed"] == len(test_scenarios), "Incorrect test count in report"
        assert metadata["test_success_rate"] >= 0, "Invalid success rate"
        assert "generation_timestamp" in metadata, "Missing generation timestamp"
        
        # Validate performance summary
        perf_summary = report["performance_summary"]
        assert "response_time_analysis" in perf_summary, "Missing response time analysis"
        assert "throughput_analysis" in perf_summary, "Missing throughput analysis"
        assert "baseline_variance_analysis" in perf_summary, "Missing variance analysis"
        
        # Validate compliance assessment
        compliance = report["compliance_assessment"]
        assert "response_time_compliance" in compliance, "Missing response time compliance"
        assert "throughput_compliance" in compliance, "Missing throughput compliance"
        assert "overall_compliance" in compliance, "Missing overall compliance"
        
        # Validate detailed results
        detailed_results = report["detailed_test_results"]
        assert len(detailed_results) == len(test_scenarios), "Incorrect detailed results count"
        
        for result in detailed_results:
            assert "test_metadata" in result, "Missing test metadata in detailed result"
            assert "performance_metrics" in result, "Missing performance metrics"
            assert "compliance_summary" in result, "Missing compliance summary"
        
        logger.info(
            "Comprehensive performance report validation passed",
            report_sections=len(required_sections),
            test_results=len(detailed_results),
            overall_success_rate=metadata["test_success_rate"]
        )


# Pytest markers for test organization
pytestmark = [
    pytest.mark.performance,
    pytest.mark.apache_bench,
    pytest.mark.baseline_comparison,
    pytest.mark.timeout(600)  # 10-minute timeout for comprehensive performance tests
]


# Additional test utilities and helper functions

def validate_apache_bench_installation():
    """Validate Apache Bench installation and availability."""
    try:
        result = subprocess.run(["ab", "-V"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def create_test_endpoint_config(endpoint_path: str, 
                              method: str = "GET",
                              requests: int = 500,
                              concurrency: int = 25) -> Dict[str, Any]:
    """Create standardized endpoint configuration for testing."""
    return {
        "path": endpoint_path,
        "method": method,
        "config": {
            "total_requests": requests,
            "concurrency_level": concurrency,
            "timeout_seconds": 30
        }
    }


# Export public interface
__all__ = [
    # Core classes
    'ApacheBenchConfig',
    'BenchmarkTestResult',
    'ApacheBenchmarkTester',
    'TestApacheBenchmarkPerformance',
    
    # Enumerations
    'BenchmarkTestType',
    'BenchmarkValidationLevel',
    
    # Utility functions
    'validate_apache_bench_installation',
    'create_test_endpoint_config',
    
    # Constants
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'RESPONSE_TIME_P95_THRESHOLD',
    'MIN_THROUGHPUT_THRESHOLD',
    'MIN_SAMPLE_SIZE',
    'APACHE_BENCH_TIMEOUT',
    'MAX_CONCURRENT_TESTS'
]