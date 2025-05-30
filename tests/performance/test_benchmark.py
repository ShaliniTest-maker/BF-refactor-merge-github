"""
Apache Bench Integration for HTTP Server Performance Measurement

This module implements comprehensive Apache Bench (ab) integration for HTTP server
performance measurement and automated Node.js baseline comparison. Validates individual
endpoint performance with statistical analysis and enforces the critical ≤10% variance
requirement per Section 0.1.1 of the technical specification.

Key Features:
- Apache Bench HTTP performance measurement per Section 6.6.1 benchmark testing
- Individual endpoint performance validation per Section 4.6.3 response time validation  
- Statistical analysis for variance calculation per Section 0.3.2 performance metrics
- Automated Node.js baseline comparison per Section 6.6.1 baseline comparison engine
- 95th percentile response time validation ≤500ms per Section 4.6.3
- Minimum 100 requests/second sustained throughput validation per Section 4.6.3

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 4.6.3: Performance testing specifications with response time and throughput thresholds
- Section 6.6.1: Apache Bench integration for benchmark testing and baseline comparison
- Section 0.3.2: Continuous performance monitoring with statistical variance analysis

Author: Flask Migration Team
Version: 1.0.0
Dependencies: subprocess, pytest ≥7.4+, requests ≥2.31+, statistics, numpy (optional)
"""

import subprocess
import json
import time
import statistics
import re
import logging
import tempfile
import concurrent.futures
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, NamedTuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import os

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# Import performance testing dependencies
from tests.performance.performance_config import (
    BasePerformanceConfig,
    PerformanceConfigFactory,
    PerformanceThreshold,
    LoadTestConfiguration,
    BaselineMetrics
)
from tests.performance.baseline_data import (
    BaselineDataManager,
    ResponseTimeBaseline,
    ThroughputBaseline,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD
)

# Configure logging for benchmark testing
logger = logging.getLogger(__name__)


@dataclass
class ApacheBenchResult:
    """
    Apache Bench test result data structure with comprehensive metrics.
    
    Contains complete performance measurement data from Apache Bench execution
    including response times, throughput, error rates, and statistical analysis.
    """
    endpoint: str
    method: str = "GET"
    
    # Request configuration
    total_requests: int = 0
    concurrency_level: int = 0
    test_duration_seconds: float = 0.0
    
    # Response time metrics (milliseconds)
    mean_response_time_ms: float = 0.0
    median_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    std_deviation_ms: float = 0.0
    
    # Percentile response times (milliseconds)
    p50_response_time_ms: float = 0.0
    p90_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    
    # Throughput metrics
    requests_per_second: float = 0.0
    time_per_request_ms: float = 0.0
    transfer_rate_kb_per_sec: float = 0.0
    
    # Error and reliability metrics
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate_percent: float = 0.0
    connect_errors: int = 0
    read_errors: int = 0
    length_errors: int = 0
    
    # HTTP response statistics
    response_codes: Dict[int, int] = field(default_factory=dict)
    content_length_bytes: int = 0
    
    # Performance validation
    baseline_comparison: Optional[Dict[str, Any]] = None
    variance_analysis: Optional[Dict[str, float]] = None
    performance_compliance: bool = False
    
    # Test execution metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    server_info: str = ""
    ab_version: str = ""
    raw_output: str = ""
    
    def __post_init__(self):
        """Validate Apache Bench result data integrity."""
        if self.total_requests > 0 and self.successful_requests + self.failed_requests != self.total_requests:
            logger.warning(f"Request count mismatch: total={self.total_requests}, success={self.successful_requests}, failed={self.failed_requests}")
        
        # Calculate error rate if not set
        if self.total_requests > 0 and self.error_rate_percent == 0.0:
            self.error_rate_percent = (self.failed_requests / self.total_requests) * 100.0
    
    def calculate_variance_from_baseline(self, baseline: ResponseTimeBaseline) -> Dict[str, float]:
        """
        Calculate performance variance from Node.js baseline per Section 0.3.2.
        
        Args:
            baseline: Node.js baseline response time data
            
        Returns:
            Dictionary containing variance percentages for key metrics
        """
        variance_results = {}
        
        # Response time variance calculation
        if baseline.mean_response_time_ms > 0:
            variance_results['mean_response_time'] = (
                (self.mean_response_time_ms - baseline.mean_response_time_ms) / baseline.mean_response_time_ms
            ) * 100.0
        
        if baseline.p95_response_time_ms > 0:
            variance_results['p95_response_time'] = (
                (self.p95_response_time_ms - baseline.p95_response_time_ms) / baseline.p95_response_time_ms
            ) * 100.0
        
        # Store variance analysis for reporting
        self.variance_analysis = variance_results
        return variance_results
    
    def validate_performance_thresholds(self, config: BasePerformanceConfig) -> Dict[str, bool]:
        """
        Validate performance metrics against configured thresholds per Section 4.6.3.
        
        Args:
            config: Performance configuration with threshold definitions
            
        Returns:
            Dictionary of threshold validation results
        """
        validation_results = {}
        
        # Validate 95th percentile response time ≤500ms per Section 4.6.3
        validation_results['p95_response_time_threshold'] = self.p95_response_time_ms <= config.RESPONSE_TIME_P95_THRESHOLD
        
        # Validate minimum 100 requests/second sustained throughput per Section 4.6.3
        validation_results['throughput_threshold'] = self.requests_per_second >= config.TARGET_THROUGHPUT_RPS
        
        # Validate error rate ≤0.1% per Section 4.6.3
        validation_results['error_rate_threshold'] = self.error_rate_percent <= config.ERROR_RATE_THRESHOLD
        
        # Validate ≤10% variance from baseline per Section 0.1.1
        if self.variance_analysis:
            variance_within_threshold = all(
                abs(variance) <= PERFORMANCE_VARIANCE_THRESHOLD 
                for variance in self.variance_analysis.values()
            )
            validation_results['variance_threshold'] = variance_within_threshold
        
        # Overall compliance validation
        self.performance_compliance = all(validation_results.values())
        
        return validation_results
    
    def generate_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance summary for reporting.
        
        Returns:
            Dictionary containing performance metrics and compliance status
        """
        return {
            'endpoint_info': {
                'endpoint': self.endpoint,
                'method': self.method,
                'test_timestamp': self.timestamp.isoformat()
            },
            'response_time_metrics': {
                'mean_ms': self.mean_response_time_ms,
                'median_ms': self.median_response_time_ms,
                'p95_ms': self.p95_response_time_ms,
                'p99_ms': self.p99_response_time_ms,
                'std_deviation_ms': self.std_deviation_ms
            },
            'throughput_metrics': {
                'requests_per_second': self.requests_per_second,
                'time_per_request_ms': self.time_per_request_ms,
                'transfer_rate_kb_sec': self.transfer_rate_kb_per_sec
            },
            'reliability_metrics': {
                'error_rate_percent': self.error_rate_percent,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests
            },
            'variance_analysis': self.variance_analysis or {},
            'performance_compliance': self.performance_compliance
        }


class ApacheBenchExecutor:
    """
    Apache Bench execution engine with comprehensive configuration and analysis.
    
    Provides robust Apache Bench test execution with error handling, result parsing,
    statistical analysis, and automated baseline comparison per Section 6.6.1.
    """
    
    def __init__(self, config: Optional[BasePerformanceConfig] = None):
        """
        Initialize Apache Bench executor with performance configuration.
        
        Args:
            config: Performance configuration (defaults to environment-based config)
        """
        self.config = config or PerformanceConfigFactory.get_config()
        self.baseline_manager = default_baseline_manager
        self.session = self._create_http_session()
        
        # Apache Bench executable validation
        self.ab_executable = self._find_apache_bench_executable()
        if not self.ab_executable:
            raise RuntimeError("Apache Bench (ab) executable not found. Install apache2-utils or httpd-tools package.")
        
        # Execution settings
        self.default_requests = 1000
        self.default_concurrency = 10
        self.timeout_seconds = 300
        self.max_retries = 3
        
        logger.info(f"Apache Bench executor initialized with {self.ab_executable}")
    
    def _find_apache_bench_executable(self) -> Optional[str]:
        """
        Locate Apache Bench executable in system PATH.
        
        Returns:
            Path to Apache Bench executable or None if not found
        """
        for executable in ['ab', '/usr/bin/ab', '/usr/local/bin/ab']:
            try:
                result = subprocess.run([executable, '-V'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and 'Apache Bench' in result.stderr:
                    return executable
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None
    
    def _create_http_session(self) -> requests.Session:
        """
        Create HTTP session with optimized configuration for testing.
        
        Returns:
            Configured requests.Session for HTTP operations
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set reasonable timeout
        session.timeout = 30
        
        return session
    
    def execute_benchmark(self, 
                         url: str, 
                         requests: int = None,
                         concurrency: int = None,
                         method: str = "GET",
                         headers: Optional[Dict[str, str]] = None,
                         post_data: Optional[str] = None,
                         content_type: Optional[str] = None) -> ApacheBenchResult:
        """
        Execute Apache Bench performance test with comprehensive analysis.
        
        Args:
            url: Target URL for performance testing
            requests: Total number of requests (defaults to config value)
            concurrency: Concurrent requests (defaults to config value)
            method: HTTP method (GET, POST, PUT, DELETE)
            headers: Optional HTTP headers dictionary
            post_data: Optional POST data for request body
            content_type: Optional content type for POST requests
            
        Returns:
            ApacheBenchResult with comprehensive performance metrics
            
        Raises:
            RuntimeError: If Apache Bench execution fails
            ValueError: If invalid parameters provided
        """
        # Validate inputs
        if not url:
            raise ValueError("URL is required for benchmark execution")
        
        requests = requests or self.default_requests
        concurrency = concurrency or self.default_concurrency
        
        if concurrency > requests:
            concurrency = requests
            logger.warning(f"Adjusted concurrency to {concurrency} (cannot exceed total requests)")
        
        # Build Apache Bench command
        ab_command = self._build_ab_command(
            url=url,
            requests=requests,
            concurrency=concurrency,
            method=method,
            headers=headers,
            post_data=post_data,
            content_type=content_type
        )
        
        logger.info(f"Executing Apache Bench: {' '.join(ab_command[:5])}... (total {len(ab_command)} args)")
        
        # Execute Apache Bench with timeout and error handling
        start_time = time.time()
        try:
            result = subprocess.run(
                ab_command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False
            )
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = f"Apache Bench failed with return code {result.returncode}: {result.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Parse Apache Bench output
            ab_result = self._parse_ab_output(result.stdout, url, method)
            ab_result.test_duration_seconds = execution_time
            ab_result.raw_output = result.stdout
            
            logger.info(f"Apache Bench completed in {execution_time:.2f}s: {ab_result.requests_per_second:.1f} RPS")
            
            return ab_result
            
        except subprocess.TimeoutExpired:
            error_msg = f"Apache Bench timed out after {self.timeout_seconds} seconds"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"Apache Bench execution error: {str(e)}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
    
    def _build_ab_command(self, 
                         url: str,
                         requests: int,
                         concurrency: int,
                         method: str,
                         headers: Optional[Dict[str, str]],
                         post_data: Optional[str],
                         content_type: Optional[str]) -> List[str]:
        """
        Build Apache Bench command with all specified parameters.
        
        Args:
            url: Target URL
            requests: Total requests
            concurrency: Concurrent requests
            method: HTTP method
            headers: HTTP headers
            post_data: POST data
            content_type: Content type
            
        Returns:
            List of command arguments for subprocess execution
        """
        command = [
            self.ab_executable,
            '-n', str(requests),           # Total requests
            '-c', str(concurrency),        # Concurrency level
            '-g', '/dev/null',             # Disable gnuplot output
            '-e', '/dev/null',             # Disable CSV output
            '-k',                          # Enable keep-alive
            '-r',                          # Don't exit on socket receive errors
            '-s', '60',                    # Socket timeout (seconds)
            '-w',                          # Print results in HTML table format
        ]
        
        # Add HTTP headers
        if headers:
            for header_name, header_value in headers.items():
                command.extend(['-H', f"{header_name}: {header_value}"])
        
        # Add POST data and content type for non-GET methods
        if method.upper() in ['POST', 'PUT', 'PATCH'] and post_data:
            if content_type:
                command.extend(['-T', content_type])
            
            # Write POST data to temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(post_data)
                temp_file_path = temp_file.name
            
            command.extend(['-p', temp_file_path])
        
        # Add custom HTTP method
        if method.upper() != 'GET':
            command.extend(['-m', method.upper()])
        
        # Add target URL
        command.append(url)
        
        return command
    
    def _parse_ab_output(self, output: str, url: str, method: str) -> ApacheBenchResult:
        """
        Parse Apache Bench output into structured performance metrics.
        
        Args:
            output: Raw Apache Bench stdout output
            url: Target URL being tested
            method: HTTP method used
            
        Returns:
            ApacheBenchResult with parsed performance metrics
        """
        result = ApacheBenchResult(endpoint=url, method=method)
        
        try:
            # Extract server information
            server_match = re.search(r'Server Software:\s*(.+)', output)
            if server_match:
                result.server_info = server_match.group(1).strip()
            
            # Extract Apache Bench version
            version_match = re.search(r'This is ApacheBench, Version (.+)', output)
            if version_match:
                result.ab_version = version_match.group(1).strip()
            
            # Extract basic metrics
            result.total_requests = self._extract_metric(output, r'Complete requests:\s*(\d+)')
            result.failed_requests = self._extract_metric(output, r'Failed requests:\s*(\d+)')
            result.successful_requests = result.total_requests - result.failed_requests
            
            # Extract response time metrics
            result.time_per_request_ms = self._extract_metric(output, r'Time per request:\s*([\d.]+)\s*\[ms\]')
            result.mean_response_time_ms = result.time_per_request_ms
            
            # Extract throughput metrics
            result.requests_per_second = self._extract_metric(output, r'Requests per second:\s*([\d.]+)')
            result.transfer_rate_kb_per_sec = self._extract_metric(output, r'Transfer rate:\s*([\d.]+)')
            
            # Extract percentile response times
            result.p50_response_time_ms = self._extract_percentile(output, 50)
            result.p90_response_time_ms = self._extract_percentile(output, 90)
            result.p95_response_time_ms = self._extract_percentile(output, 95)
            result.p99_response_time_ms = self._extract_percentile(output, 99)
            
            # Use p50 as median if available
            if result.p50_response_time_ms > 0:
                result.median_response_time_ms = result.p50_response_time_ms
            
            # Extract min/max response times
            result.min_response_time_ms = self._extract_metric(output, r'min\)\s*([\d.]+)')
            result.max_response_time_ms = self._extract_metric(output, r'max\)\s*([\d.]+)')
            
            # Calculate derived metrics
            if result.total_requests > 0:
                result.error_rate_percent = (result.failed_requests / result.total_requests) * 100.0
            
            # Extract response codes
            result.response_codes = self._extract_response_codes(output)
            
            # Extract concurrency level
            result.concurrency_level = self._extract_metric(output, r'Concurrency Level:\s*(\d+)')
            
            logger.debug(f"Parsed AB result: {result.requests_per_second:.1f} RPS, {result.p95_response_time_ms:.1f}ms P95")
            
        except Exception as e:
            logger.error(f"Error parsing Apache Bench output: {str(e)}")
            logger.debug(f"Raw Apache Bench output:\n{output}")
            
        return result
    
    def _extract_metric(self, output: str, pattern: str) -> float:
        """
        Extract numeric metric from Apache Bench output using regex pattern.
        
        Args:
            output: Apache Bench output text
            pattern: Regex pattern to match metric
            
        Returns:
            Extracted numeric value or 0.0 if not found
        """
        match = re.search(pattern, output)
        if match:
            try:
                return float(match.group(1))
            except (ValueError, IndexError):
                pass
        return 0.0
    
    def _extract_percentile(self, output: str, percentile: int) -> float:
        """
        Extract percentile response time from Apache Bench output.
        
        Args:
            output: Apache Bench output text
            percentile: Percentile value (50, 90, 95, 99)
            
        Returns:
            Percentile response time in milliseconds
        """
        # Look for percentile table
        pattern = rf'{percentile}%\s*([\d.]+)'
        match = re.search(pattern, output)
        if match:
            try:
                return float(match.group(1))
            except (ValueError, IndexError):
                pass
        return 0.0
    
    def _extract_response_codes(self, output: str) -> Dict[int, int]:
        """
        Extract HTTP response code distribution from Apache Bench output.
        
        Args:
            output: Apache Bench output text
            
        Returns:
            Dictionary mapping status codes to counts
        """
        response_codes = {}
        
        # Look for "Non-2xx responses" line
        non_2xx_match = re.search(r'Non-2xx responses:\s*(\d+)', output)
        if non_2xx_match:
            # If there are non-2xx responses, we have mixed status codes
            # AB doesn't break them down, so we just note there were some
            response_codes[0] = int(non_2xx_match.group(1))  # Use 0 as placeholder
        
        return response_codes
    
    def benchmark_endpoint(self, 
                          base_url: str,
                          endpoint: str,
                          method: str = "GET",
                          requests: int = None,
                          concurrency: int = None,
                          compare_to_baseline: bool = True) -> ApacheBenchResult:
        """
        Benchmark specific endpoint with baseline comparison per Section 6.6.1.
        
        Args:
            base_url: Base URL of the Flask application
            endpoint: API endpoint path to test
            method: HTTP method for the endpoint
            requests: Total requests for the test
            concurrency: Concurrent request level
            compare_to_baseline: Whether to compare against Node.js baseline
            
        Returns:
            ApacheBenchResult with endpoint performance metrics and baseline comparison
        """
        # Construct full URL
        full_url = urljoin(base_url.rstrip('/') + '/', endpoint.lstrip('/'))
        
        logger.info(f"Benchmarking endpoint: {method} {endpoint}")
        
        # Execute Apache Bench test
        result = self.execute_benchmark(
            url=full_url,
            requests=requests,
            concurrency=concurrency,
            method=method
        )
        
        # Perform baseline comparison if requested
        if compare_to_baseline:
            baseline = self.baseline_manager.get_response_time_baseline(endpoint, method)
            if baseline:
                # Calculate variance from baseline
                variance_analysis = result.calculate_variance_from_baseline(baseline)
                
                # Store baseline comparison data
                result.baseline_comparison = {
                    'baseline_mean_response_time_ms': baseline.mean_response_time_ms,
                    'baseline_p95_response_time_ms': baseline.p95_response_time_ms,
                    'current_mean_response_time_ms': result.mean_response_time_ms,
                    'current_p95_response_time_ms': result.p95_response_time_ms,
                    'variance_analysis': variance_analysis
                }
                
                logger.info(f"Baseline comparison completed for {method} {endpoint}")
                for metric, variance in variance_analysis.items():
                    logger.info(f"  {metric}: {variance:+.2f}% variance from baseline")
            else:
                logger.warning(f"No baseline data available for {method} {endpoint}")
        
        # Validate performance thresholds
        threshold_validation = result.validate_performance_thresholds(self.config)
        
        logger.info(f"Performance validation for {method} {endpoint}:")
        logger.info(f"  Response time P95: {result.p95_response_time_ms:.1f}ms ({'✓' if threshold_validation.get('p95_response_time_threshold', False) else '✗'})")
        logger.info(f"  Throughput: {result.requests_per_second:.1f} RPS ({'✓' if threshold_validation.get('throughput_threshold', False) else '✗'})")
        logger.info(f"  Error rate: {result.error_rate_percent:.3f}% ({'✓' if threshold_validation.get('error_rate_threshold', False) else '✗'})")
        logger.info(f"  Overall compliance: {'✓' if result.performance_compliance else '✗'}")
        
        return result
    
    def benchmark_multiple_endpoints(self, 
                                   base_url: str,
                                   endpoints: List[Tuple[str, str]],
                                   requests_per_endpoint: int = None,
                                   concurrency: int = None,
                                   parallel_execution: bool = False) -> Dict[str, ApacheBenchResult]:
        """
        Benchmark multiple endpoints with optional parallel execution.
        
        Args:
            base_url: Base URL of the Flask application
            endpoints: List of (endpoint_path, method) tuples
            requests_per_endpoint: Requests per endpoint test
            concurrency: Concurrent request level
            parallel_execution: Whether to run tests in parallel
            
        Returns:
            Dictionary mapping endpoint keys to ApacheBenchResult objects
        """
        results = {}
        
        if parallel_execution and len(endpoints) > 1:
            # Execute tests in parallel using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(endpoints), 4)) as executor:
                future_to_endpoint = {
                    executor.submit(
                        self.benchmark_endpoint,
                        base_url,
                        endpoint,
                        method,
                        requests_per_endpoint,
                        concurrency
                    ): f"{method} {endpoint}"
                    for endpoint, method in endpoints
                }
                
                for future in concurrent.futures.as_completed(future_to_endpoint):
                    endpoint_key = future_to_endpoint[future]
                    try:
                        result = future.result()
                        results[endpoint_key] = result
                        logger.info(f"Completed parallel benchmark: {endpoint_key}")
                    except Exception as e:
                        logger.error(f"Parallel benchmark failed for {endpoint_key}: {str(e)}")
                        
        else:
            # Execute tests sequentially
            for endpoint, method in endpoints:
                endpoint_key = f"{method} {endpoint}"
                try:
                    result = self.benchmark_endpoint(
                        base_url=base_url,
                        endpoint=endpoint,
                        method=method,
                        requests=requests_per_endpoint,
                        concurrency=concurrency
                    )
                    results[endpoint_key] = result
                    logger.info(f"Completed sequential benchmark: {endpoint_key}")
                except Exception as e:
                    logger.error(f"Sequential benchmark failed for {endpoint_key}: {str(e)}")
        
        return results


class PerformanceBenchmarkValidator:
    """
    Performance benchmark validation engine with comprehensive analysis.
    
    Provides statistical analysis, variance calculation, and compliance validation
    for Apache Bench results against Node.js baselines per Section 0.3.2.
    """
    
    def __init__(self, config: Optional[BasePerformanceConfig] = None):
        """
        Initialize performance benchmark validator.
        
        Args:
            config: Performance configuration for threshold validation
        """
        self.config = config or PerformanceConfigFactory.get_config()
        self.baseline_manager = default_baseline_manager
    
    def validate_benchmark_result(self, result: ApacheBenchResult) -> Dict[str, Any]:
        """
        Comprehensive validation of Apache Bench result against all thresholds.
        
        Args:
            result: Apache Bench test result to validate
            
        Returns:
            Dictionary containing comprehensive validation analysis
        """
        validation_report = {
            'endpoint': result.endpoint,
            'method': result.method,
            'timestamp': result.timestamp.isoformat(),
            'performance_metrics': result.generate_performance_summary(),
            'threshold_validation': {},
            'baseline_comparison': {},
            'statistical_analysis': {},
            'compliance_status': {},
            'recommendations': []
        }
        
        # Validate against performance thresholds
        threshold_results = result.validate_performance_thresholds(self.config)
        validation_report['threshold_validation'] = threshold_results
        
        # Baseline comparison validation
        if result.baseline_comparison:
            baseline_validation = self._validate_baseline_comparison(result)
            validation_report['baseline_comparison'] = baseline_validation
        
        # Statistical analysis
        statistical_analysis = self._perform_statistical_analysis(result)
        validation_report['statistical_analysis'] = statistical_analysis
        
        # Overall compliance assessment
        compliance_status = self._assess_compliance_status(result, threshold_results)
        validation_report['compliance_status'] = compliance_status
        
        # Generate recommendations
        recommendations = self._generate_recommendations(result, validation_report)
        validation_report['recommendations'] = recommendations
        
        return validation_report
    
    def _validate_baseline_comparison(self, result: ApacheBenchResult) -> Dict[str, Any]:
        """
        Validate performance against Node.js baseline with variance analysis.
        
        Args:
            result: Apache Bench result with baseline comparison data
            
        Returns:
            Dictionary containing baseline validation results
        """
        baseline_validation = {
            'baseline_available': result.baseline_comparison is not None,
            'variance_within_threshold': False,
            'variance_analysis': {},
            'performance_trend': 'unknown'
        }
        
        if not result.baseline_comparison:
            return baseline_validation
        
        variance_analysis = result.variance_analysis or {}
        baseline_validation['variance_analysis'] = variance_analysis
        
        # Check if all variances are within ≤10% threshold
        variances_within_threshold = []
        for metric, variance in variance_analysis.items():
            abs_variance = abs(variance)
            within_threshold = abs_variance <= PERFORMANCE_VARIANCE_THRESHOLD
            variances_within_threshold.append(within_threshold)
            
            baseline_validation['variance_analysis'][f"{metric}_within_threshold"] = within_threshold
            baseline_validation['variance_analysis'][f"{metric}_variance_percent"] = variance
        
        baseline_validation['variance_within_threshold'] = all(variances_within_threshold)
        
        # Determine performance trend
        if variance_analysis:
            avg_variance = statistics.mean(variance_analysis.values())
            if avg_variance < -5:
                baseline_validation['performance_trend'] = 'significant_improvement'
            elif avg_variance < 0:
                baseline_validation['performance_trend'] = 'improvement'
            elif avg_variance > PERFORMANCE_VARIANCE_THRESHOLD:
                baseline_validation['performance_trend'] = 'significant_degradation'
            elif avg_variance > 5:
                baseline_validation['performance_trend'] = 'degradation'
            else:
                baseline_validation['performance_trend'] = 'stable'
        
        return baseline_validation
    
    def _perform_statistical_analysis(self, result: ApacheBenchResult) -> Dict[str, Any]:
        """
        Perform statistical analysis on benchmark results.
        
        Args:
            result: Apache Bench result for analysis
            
        Returns:
            Dictionary containing statistical analysis results
        """
        analysis = {
            'response_time_analysis': {},
            'throughput_analysis': {},
            'reliability_analysis': {},
            'performance_score': 0.0
        }
        
        # Response time analysis
        response_times = [result.p50_response_time_ms, result.p90_response_time_ms, 
                         result.p95_response_time_ms, result.p99_response_time_ms]
        response_times = [rt for rt in response_times if rt > 0]
        
        if response_times:
            analysis['response_time_analysis'] = {
                'mean_percentile_response_time': statistics.mean(response_times),
                'response_time_spread': max(response_times) - min(response_times),
                'response_time_consistency': result.std_deviation_ms / result.mean_response_time_ms if result.mean_response_time_ms > 0 else 0,
                'p95_threshold_compliance': result.p95_response_time_ms <= self.config.RESPONSE_TIME_P95_THRESHOLD
            }
        
        # Throughput analysis
        analysis['throughput_analysis'] = {
            'throughput_rps': result.requests_per_second,
            'throughput_threshold_compliance': result.requests_per_second >= self.config.TARGET_THROUGHPUT_RPS,
            'throughput_efficiency': (result.requests_per_second / self.config.PEAK_THROUGHPUT_RPS) * 100 if self.config.PEAK_THROUGHPUT_RPS > 0 else 0,
            'concurrent_capacity_utilization': (result.concurrency_level / 100) * 100  # Assuming max 100 concurrent
        }
        
        # Reliability analysis
        analysis['reliability_analysis'] = {
            'error_rate_percent': result.error_rate_percent,
            'error_rate_compliance': result.error_rate_percent <= self.config.ERROR_RATE_THRESHOLD,
            'success_rate_percent': 100.0 - result.error_rate_percent,
            'reliability_score': max(0, 100 - (result.error_rate_percent * 10))  # Penalize errors heavily
        }
        
        # Calculate overall performance score (0-100)
        score_components = []
        
        # Response time score (30% weight)
        if result.p95_response_time_ms <= self.config.RESPONSE_TIME_P95_THRESHOLD:
            response_score = max(0, 100 - (result.p95_response_time_ms / self.config.RESPONSE_TIME_P95_THRESHOLD * 50))
        else:
            response_score = max(0, 50 - ((result.p95_response_time_ms - self.config.RESPONSE_TIME_P95_THRESHOLD) / self.config.RESPONSE_TIME_P95_THRESHOLD * 50))
        score_components.append(response_score * 0.3)
        
        # Throughput score (30% weight)
        throughput_score = min(100, (result.requests_per_second / self.config.TARGET_THROUGHPUT_RPS) * 100)
        score_components.append(throughput_score * 0.3)
        
        # Reliability score (40% weight)
        reliability_score = analysis['reliability_analysis']['reliability_score']
        score_components.append(reliability_score * 0.4)
        
        analysis['performance_score'] = sum(score_components)
        
        return analysis
    
    def _assess_compliance_status(self, result: ApacheBenchResult, threshold_results: Dict[str, bool]) -> Dict[str, Any]:
        """
        Assess overall compliance status with detailed breakdown.
        
        Args:
            result: Apache Bench result
            threshold_results: Threshold validation results
            
        Returns:
            Dictionary containing compliance status assessment
        """
        compliance_status = {
            'overall_compliant': result.performance_compliance,
            'threshold_compliance': threshold_results,
            'critical_issues': [],
            'warning_issues': [],
            'compliance_score': 0.0,
            'deployment_recommendation': 'unknown'
        }
        
        # Identify critical issues
        if not threshold_results.get('p95_response_time_threshold', True):
            compliance_status['critical_issues'].append(
                f"P95 response time {result.p95_response_time_ms:.1f}ms exceeds {self.config.RESPONSE_TIME_P95_THRESHOLD}ms threshold"
            )
        
        if not threshold_results.get('throughput_threshold', True):
            compliance_status['critical_issues'].append(
                f"Throughput {result.requests_per_second:.1f} RPS below {self.config.TARGET_THROUGHPUT_RPS} RPS minimum"
            )
        
        if not threshold_results.get('variance_threshold', True) and result.variance_analysis:
            for metric, variance in result.variance_analysis.items():
                if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                    compliance_status['critical_issues'].append(
                        f"{metric} variance {variance:+.2f}% exceeds ±{PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
                    )
        
        # Identify warning issues
        if result.error_rate_percent > 0.05:  # Warning at 0.05%
            compliance_status['warning_issues'].append(
                f"Error rate {result.error_rate_percent:.3f}% approaching {self.config.ERROR_RATE_THRESHOLD}% threshold"
            )
        
        if result.p95_response_time_ms > (self.config.RESPONSE_TIME_P95_THRESHOLD * 0.8):  # Warning at 80% of threshold
            compliance_status['warning_issues'].append(
                f"P95 response time {result.p95_response_time_ms:.1f}ms approaching {self.config.RESPONSE_TIME_P95_THRESHOLD}ms threshold"
            )
        
        # Calculate compliance score
        passed_thresholds = sum(1 for passed in threshold_results.values() if passed)
        total_thresholds = len(threshold_results)
        compliance_status['compliance_score'] = (passed_thresholds / total_thresholds) * 100 if total_thresholds > 0 else 0
        
        # Generate deployment recommendation
        if not compliance_status['critical_issues']:
            if not compliance_status['warning_issues']:
                compliance_status['deployment_recommendation'] = 'approved'
            else:
                compliance_status['deployment_recommendation'] = 'approved_with_monitoring'
        else:
            compliance_status['deployment_recommendation'] = 'rejected'
        
        return compliance_status
    
    def _generate_recommendations(self, result: ApacheBenchResult, validation_report: Dict[str, Any]) -> List[str]:
        """
        Generate actionable recommendations based on performance analysis.
        
        Args:
            result: Apache Bench result
            validation_report: Comprehensive validation report
            
        Returns:
            List of actionable recommendations
        """
        recommendations = []
        
        compliance_status = validation_report.get('compliance_status', {})
        statistical_analysis = validation_report.get('statistical_analysis', {})
        
        # Critical issue recommendations
        if compliance_status.get('critical_issues'):
            recommendations.append("CRITICAL: Address performance issues before deployment")
            
            if result.p95_response_time_ms > self.config.RESPONSE_TIME_P95_THRESHOLD:
                recommendations.extend([
                    "Optimize database queries and caching strategy",
                    "Review application bottlenecks and resource allocation",
                    "Consider horizontal scaling or load balancing"
                ])
            
            if result.requests_per_second < self.config.TARGET_THROUGHPUT_RPS:
                recommendations.extend([
                    "Analyze thread pool configuration and connection pooling",
                    "Optimize request processing pipeline",
                    "Consider asynchronous processing for heavy operations"
                ])
        
        # Warning issue recommendations
        elif compliance_status.get('warning_issues'):
            recommendations.append("Monitor performance closely during deployment")
            recommendations.extend([
                "Implement proactive monitoring and alerting",
                "Consider pre-emptive optimization measures",
                "Plan for capacity scaling if load increases"
            ])
        
        # Performance optimization recommendations
        performance_score = statistical_analysis.get('performance_score', 0)
        if performance_score < 80:
            recommendations.extend([
                "Consider performance profiling to identify bottlenecks",
                "Review memory usage patterns and garbage collection",
                "Optimize database connection pooling and query patterns"
            ])
        
        # Baseline comparison recommendations
        baseline_comparison = validation_report.get('baseline_comparison', {})
        if baseline_comparison.get('performance_trend') in ['degradation', 'significant_degradation']:
            recommendations.extend([
                "Investigate performance regression causes",
                "Compare resource utilization with Node.js baseline",
                "Review recent code changes for performance impact"
            ])
        
        # Default recommendation for passing tests
        if not recommendations:
            recommendations.append("Performance validation successful - deployment approved")
        
        return recommendations


# Test Classes and Fixtures for pytest Integration

@pytest.mark.performance
class TestApacheBenchmarkIntegration:
    """
    Apache Benchmark integration test suite with comprehensive endpoint validation.
    
    Implements performance testing per Section 6.6.1 with Apache Bench integration,
    baseline comparison, and ≤10% variance enforcement per Section 0.1.1.
    """
    
    @pytest.fixture(scope="class")
    def ab_executor(self, performance_config):
        """Apache Bench executor fixture with performance configuration."""
        return ApacheBenchExecutor(performance_config)
    
    @pytest.fixture(scope="class")
    def performance_validator(self, performance_config):
        """Performance validator fixture for result validation."""
        return PerformanceBenchmarkValidator(performance_config)
    
    @pytest.fixture(scope="class")
    def test_endpoints(self):
        """Standard test endpoints for performance validation."""
        return [
            ("/api/v1/health", "GET"),
            ("/api/v1/auth/login", "POST"),
            ("/api/v1/users", "GET"),
            ("/api/v1/users", "POST"),
            ("/api/v1/data/reports", "GET")
        ]
    
    def test_apache_bench_availability(self, ab_executor):
        """
        Test Apache Bench availability and version validation.
        
        Ensures Apache Bench is properly installed and accessible for testing.
        """
        assert ab_executor.ab_executable is not None, "Apache Bench executable not found"
        
        # Test Apache Bench version execution
        try:
            result = subprocess.run([ab_executor.ab_executable, '-V'], capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, f"Apache Bench version check failed: {result.stderr}"
            assert 'Apache Bench' in result.stderr, "Invalid Apache Bench version output"
            
            logger.info(f"Apache Bench available: {ab_executor.ab_executable}")
        except Exception as e:
            pytest.fail(f"Apache Bench availability test failed: {str(e)}")
    
    def test_health_endpoint_benchmark(self, ab_executor, performance_validator, test_client, app_context):
        """
        Test health endpoint performance with Apache Bench per Section 4.6.3.
        
        Validates 95th percentile response time ≤500ms and minimum 100 RPS throughput.
        """
        base_url = "http://localhost:5000"  # Test server URL
        
        # Execute Apache Bench test
        result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/health",
            method="GET",
            requests=500,
            concurrency=10
        )
        
        # Validate performance metrics
        assert result.requests_per_second >= 100, f"Throughput {result.requests_per_second:.1f} RPS below 100 RPS minimum"
        assert result.p95_response_time_ms <= 500, f"P95 response time {result.p95_response_time_ms:.1f}ms exceeds 500ms threshold"
        assert result.error_rate_percent <= 0.1, f"Error rate {result.error_rate_percent:.3f}% exceeds 0.1% threshold"
        
        # Comprehensive validation
        validation_report = performance_validator.validate_benchmark_result(result)
        
        assert validation_report['compliance_status']['overall_compliant'], \
            f"Health endpoint performance validation failed: {validation_report['compliance_status']['critical_issues']}"
        
        logger.info(f"Health endpoint benchmark: {result.requests_per_second:.1f} RPS, {result.p95_response_time_ms:.1f}ms P95")
    
    def test_authentication_endpoint_benchmark(self, ab_executor, performance_validator):
        """
        Test authentication endpoint performance with baseline comparison.
        
        Validates authentication flow performance against Node.js baseline
        with ≤10% variance enforcement per Section 0.1.1.
        """
        base_url = "http://localhost:5000"
        
        # Execute Apache Bench test for authentication endpoint
        result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/auth/login",
            method="POST",
            requests=200,
            concurrency=5,
            compare_to_baseline=True
        )
        
        # Validate baseline comparison
        if result.baseline_comparison and result.variance_analysis:
            for metric, variance in result.variance_analysis.items():
                assert abs(variance) <= PERFORMANCE_VARIANCE_THRESHOLD, \
                    f"Authentication {metric} variance {variance:+.2f}% exceeds ±{PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
        
        # Comprehensive validation
        validation_report = performance_validator.validate_benchmark_result(result)
        
        assert validation_report['compliance_status']['overall_compliant'], \
            f"Authentication endpoint validation failed: {validation_report['compliance_status']['critical_issues']}"
        
        logger.info(f"Authentication benchmark: {result.requests_per_second:.1f} RPS, {result.p95_response_time_ms:.1f}ms P95")
    
    def test_users_api_endpoint_benchmark(self, ab_executor, performance_validator):
        """
        Test users API endpoint performance with comprehensive analysis.
        
        Validates both GET and POST operations for the users API endpoint
        with statistical analysis and performance scoring.
        """
        base_url = "http://localhost:5000"
        
        # Test GET /api/v1/users
        get_result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/users",
            method="GET",
            requests=1000,
            concurrency=20
        )
        
        # Test POST /api/v1/users
        post_result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/users",
            method="POST",
            requests=500,
            concurrency=10
        )
        
        # Validate both results
        for result in [get_result, post_result]:
            validation_report = performance_validator.validate_benchmark_result(result)
            
            assert validation_report['compliance_status']['overall_compliant'], \
                f"Users API {result.method} validation failed: {validation_report['compliance_status']['critical_issues']}"
            
            # Check performance score
            performance_score = validation_report['statistical_analysis']['performance_score']
            assert performance_score >= 70, f"Performance score {performance_score:.1f} below acceptable threshold"
        
        logger.info(f"Users API GET benchmark: {get_result.requests_per_second:.1f} RPS")
        logger.info(f"Users API POST benchmark: {post_result.requests_per_second:.1f} RPS")
    
    def test_data_reports_endpoint_benchmark(self, ab_executor, performance_validator):
        """
        Test data reports endpoint performance with heavy load simulation.
        
        Validates performance under higher load scenarios typical for
        data-intensive operations per Section 4.6.3 load testing.
        """
        base_url = "http://localhost:5000"
        
        # Execute high-load test for data reports endpoint
        result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/data/reports",
            method="GET",
            requests=2000,
            concurrency=50
        )
        
        # Validate performance under load
        assert result.requests_per_second >= 50, f"Data reports throughput {result.requests_per_second:.1f} RPS insufficient under load"
        assert result.p95_response_time_ms <= 1000, f"Data reports P95 response time {result.p95_response_time_ms:.1f}ms excessive under load"
        assert result.error_rate_percent <= 1.0, f"Data reports error rate {result.error_rate_percent:.3f}% too high under load"
        
        # Comprehensive validation
        validation_report = performance_validator.validate_benchmark_result(result)
        
        # Allow slightly relaxed standards for heavy load scenarios
        if not validation_report['compliance_status']['overall_compliant']:
            critical_issues = validation_report['compliance_status']['critical_issues']
            # Ensure no critical performance failures
            assert len(critical_issues) <= 1, f"Multiple critical issues under load: {critical_issues}"
        
        logger.info(f"Data reports benchmark under load: {result.requests_per_second:.1f} RPS, {result.p95_response_time_ms:.1f}ms P95")
    
    def test_multiple_endpoints_parallel_benchmark(self, ab_executor, performance_validator, test_endpoints):
        """
        Test multiple endpoints with parallel benchmark execution.
        
        Validates system performance under concurrent testing of multiple
        endpoints simulating realistic mixed workload scenarios.
        """
        base_url = "http://localhost:5000"
        
        # Execute parallel benchmarks
        results = ab_executor.benchmark_multiple_endpoints(
            base_url=base_url,
            endpoints=test_endpoints,
            requests_per_endpoint=300,
            concurrency=10,
            parallel_execution=True
        )
        
        # Validate all endpoint results
        overall_compliance = True
        overall_performance_scores = []
        
        for endpoint_key, result in results.items():
            validation_report = performance_validator.validate_benchmark_result(result)
            
            endpoint_compliant = validation_report['compliance_status']['overall_compliant']
            if not endpoint_compliant:
                logger.warning(f"Endpoint {endpoint_key} failed compliance: {validation_report['compliance_status']['critical_issues']}")
                overall_compliance = False
            
            performance_score = validation_report['statistical_analysis']['performance_score']
            overall_performance_scores.append(performance_score)
            
            logger.info(f"Parallel benchmark {endpoint_key}: {result.requests_per_second:.1f} RPS, score: {performance_score:.1f}")
        
        # System-wide validation
        avg_performance_score = statistics.mean(overall_performance_scores)
        assert avg_performance_score >= 60, f"Average system performance score {avg_performance_score:.1f} below acceptable threshold"
        
        # At least 80% of endpoints should be compliant
        compliant_count = sum(1 for endpoint_key, result in results.items() 
                             if performance_validator.validate_benchmark_result(result)['compliance_status']['overall_compliant'])
        compliance_rate = (compliant_count / len(results)) * 100
        assert compliance_rate >= 80, f"System compliance rate {compliance_rate:.1f}% below 80% threshold"
        
        logger.info(f"Parallel benchmark completed: {len(results)} endpoints, {compliance_rate:.1f}% compliance rate")
    
    def test_baseline_variance_enforcement(self, ab_executor, performance_validator):
        """
        Test enforcement of ≤10% variance requirement per Section 0.1.1.
        
        Validates that the system properly enforces the critical ≤10% variance
        requirement from Node.js baseline across all performance metrics.
        """
        base_url = "http://localhost:5000"
        
        # Test endpoints with known baselines
        baseline_endpoints = [
            ("/api/v1/auth/login", "POST"),
            ("/api/v1/users", "GET"),
            ("/api/v1/data/reports", "GET")
        ]
        
        variance_violations = []
        
        for endpoint, method in baseline_endpoints:
            result = ab_executor.benchmark_endpoint(
                base_url=base_url,
                endpoint=endpoint,
                method=method,
                requests=1000,
                concurrency=20,
                compare_to_baseline=True
            )
            
            if result.variance_analysis:
                for metric, variance in result.variance_analysis.items():
                    if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                        variance_violations.append({
                            'endpoint': f"{method} {endpoint}",
                            'metric': metric,
                            'variance_percent': variance,
                            'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                        })
        
        # Report variance violations
        if variance_violations:
            violation_summary = "\n".join([
                f"  {v['endpoint']} - {v['metric']}: {v['variance_percent']:+.2f}% (threshold: ±{v['threshold']}%)"
                for v in variance_violations
            ])
            pytest.fail(f"Baseline variance violations detected:\n{violation_summary}")
        
        logger.info(f"Baseline variance enforcement validated for {len(baseline_endpoints)} endpoints")
    
    def test_performance_regression_detection(self, ab_executor, performance_validator):
        """
        Test performance regression detection capabilities.
        
        Validates the system's ability to detect and report performance
        regressions through statistical analysis and trend monitoring.
        """
        base_url = "http://localhost:5000"
        
        # Execute baseline measurement
        baseline_result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/users",
            method="GET",
            requests=1000,
            concurrency=10
        )
        
        # Simulate potential regression by testing under higher load
        regression_result = ab_executor.benchmark_endpoint(
            base_url=base_url,
            endpoint="/api/v1/users",
            method="GET",
            requests=2000,
            concurrency=50
        )
        
        # Compare results for regression detection
        response_time_regression = (regression_result.p95_response_time_ms - baseline_result.p95_response_time_ms) / baseline_result.p95_response_time_ms * 100
        throughput_regression = (baseline_result.requests_per_second - regression_result.requests_per_second) / baseline_result.requests_per_second * 100
        
        logger.info(f"Regression analysis:")
        logger.info(f"  Response time change: {response_time_regression:+.2f}%")
        logger.info(f"  Throughput change: {throughput_regression:+.2f}%")
        
        # Validate regression detection (allow reasonable degradation under higher load)
        assert response_time_regression <= 50, f"Excessive response time regression: {response_time_regression:.2f}%"
        assert throughput_regression <= 30, f"Excessive throughput regression: {throughput_regression:.2f}%"
        
        # Validate comprehensive regression analysis
        validation_report = performance_validator.validate_benchmark_result(regression_result)
        
        # Should still maintain minimum performance standards
        assert validation_report['statistical_analysis']['performance_score'] >= 50, \
            "Performance regression detection failed - system performance critically degraded"
        
        logger.info("Performance regression detection validated successfully")


# Utility Functions for Apache Bench Integration

def validate_system_performance_against_baseline(base_url: str,
                                               endpoints: List[Tuple[str, str]] = None,
                                               config: Optional[BasePerformanceConfig] = None) -> Dict[str, Any]:
    """
    Comprehensive system performance validation against Node.js baseline.
    
    Executes Apache Bench tests across specified endpoints and validates
    performance against Node.js baseline with ≤10% variance enforcement.
    
    Args:
        base_url: Base URL of the Flask application
        endpoints: List of (endpoint, method) tuples to test
        config: Performance configuration (defaults to environment config)
        
    Returns:
        Dictionary containing comprehensive system performance validation results
    """
    config = config or PerformanceConfigFactory.get_config()
    ab_executor = ApacheBenchExecutor(config)
    validator = PerformanceBenchmarkValidator(config)
    
    # Default endpoints if not specified
    if not endpoints:
        endpoints = [
            ("/api/v1/health", "GET"),
            ("/api/v1/auth/login", "POST"),
            ("/api/v1/users", "GET"),
            ("/api/v1/users", "POST"),
            ("/api/v1/data/reports", "GET")
        ]
    
    system_validation = {
        'validation_timestamp': datetime.utcnow().isoformat(),
        'base_url': base_url,
        'endpoints_tested': len(endpoints),
        'endpoint_results': {},
        'system_metrics': {
            'avg_response_time_ms': 0.0,
            'avg_throughput_rps': 0.0,
            'overall_error_rate_percent': 0.0,
            'performance_score': 0.0
        },
        'compliance_summary': {
            'compliant_endpoints': 0,
            'total_endpoints': len(endpoints),
            'compliance_rate_percent': 0.0,
            'variance_violations': [],
            'critical_issues': []
        },
        'recommendation': 'unknown'
    }
    
    # Execute benchmarks for all endpoints
    endpoint_metrics = []
    variance_violations = []
    critical_issues = []
    
    for endpoint, method in endpoints:
        try:
            result = ab_executor.benchmark_endpoint(
                base_url=base_url,
                endpoint=endpoint,
                method=method,
                requests=1000,
                concurrency=20,
                compare_to_baseline=True
            )
            
            validation_report = validator.validate_benchmark_result(result)
            
            endpoint_key = f"{method} {endpoint}"
            system_validation['endpoint_results'][endpoint_key] = validation_report
            
            # Collect metrics for system-wide analysis
            endpoint_metrics.append({
                'response_time_ms': result.p95_response_time_ms,
                'throughput_rps': result.requests_per_second,
                'error_rate_percent': result.error_rate_percent,
                'performance_score': validation_report['statistical_analysis']['performance_score']
            })
            
            # Track compliance
            if validation_report['compliance_status']['overall_compliant']:
                system_validation['compliance_summary']['compliant_endpoints'] += 1
            else:
                critical_issues.extend(validation_report['compliance_status']['critical_issues'])
            
            # Track variance violations
            if result.variance_analysis:
                for metric, variance in result.variance_analysis.items():
                    if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                        variance_violations.append({
                            'endpoint': endpoint_key,
                            'metric': metric,
                            'variance_percent': variance
                        })
            
        except Exception as e:
            logger.error(f"Benchmark failed for {method} {endpoint}: {str(e)}")
            critical_issues.append(f"Benchmark execution failed for {method} {endpoint}: {str(e)}")
    
    # Calculate system-wide metrics
    if endpoint_metrics:
        system_validation['system_metrics'] = {
            'avg_response_time_ms': statistics.mean([m['response_time_ms'] for m in endpoint_metrics]),
            'avg_throughput_rps': statistics.mean([m['throughput_rps'] for m in endpoint_metrics]),
            'overall_error_rate_percent': statistics.mean([m['error_rate_percent'] for m in endpoint_metrics]),
            'performance_score': statistics.mean([m['performance_score'] for m in endpoint_metrics])
        }
    
    # Update compliance summary
    compliance_rate = (system_validation['compliance_summary']['compliant_endpoints'] / 
                      system_validation['compliance_summary']['total_endpoints']) * 100
    system_validation['compliance_summary']['compliance_rate_percent'] = compliance_rate
    system_validation['compliance_summary']['variance_violations'] = variance_violations
    system_validation['compliance_summary']['critical_issues'] = critical_issues
    
    # Generate system recommendation
    if compliance_rate >= 90 and not variance_violations:
        system_validation['recommendation'] = 'deployment_approved'
    elif compliance_rate >= 80 and len(variance_violations) <= 2:
        system_validation['recommendation'] = 'deployment_approved_with_monitoring'
    elif compliance_rate >= 60:
        system_validation['recommendation'] = 'deployment_requires_optimization'
    else:
        system_validation['recommendation'] = 'deployment_rejected'
    
    return system_validation


def generate_performance_benchmark_report(validation_results: Dict[str, Any],
                                         output_file: Optional[str] = None) -> str:
    """
    Generate comprehensive performance benchmark report.
    
    Creates detailed performance testing report in markdown format with
    statistical analysis, baseline comparison, and recommendations.
    
    Args:
        validation_results: System performance validation results
        output_file: Optional file path to save the report
        
    Returns:
        Markdown formatted performance report
    """
    timestamp = validation_results.get('validation_timestamp', datetime.utcnow().isoformat())
    
    report = f"""# Apache Bench Performance Validation Report

**Generated:** {timestamp}  
**System:** {validation_results.get('base_url', 'Unknown')}  
**Endpoints Tested:** {validation_results.get('endpoints_tested', 0)}

## Executive Summary

**Overall Compliance Rate:** {validation_results['compliance_summary']['compliance_rate_percent']:.1f}%  
**Compliant Endpoints:** {validation_results['compliance_summary']['compliant_endpoints']}/{validation_results['compliance_summary']['total_endpoints']}  
**Deployment Recommendation:** {validation_results['recommendation'].replace('_', ' ').title()}

## System Performance Metrics

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Average Response Time (P95) | {validation_results['system_metrics']['avg_response_time_ms']:.1f}ms | ≤500ms | {'✓' if validation_results['system_metrics']['avg_response_time_ms'] <= 500 else '✗'} |
| Average Throughput | {validation_results['system_metrics']['avg_throughput_rps']:.1f} RPS | ≥100 RPS | {'✓' if validation_results['system_metrics']['avg_throughput_rps'] >= 100 else '✗'} |
| Overall Error Rate | {validation_results['system_metrics']['overall_error_rate_percent']:.3f}% | ≤0.1% | {'✓' if validation_results['system_metrics']['overall_error_rate_percent'] <= 0.1 else '✗'} |
| Performance Score | {validation_results['system_metrics']['performance_score']:.1f}/100 | ≥70 | {'✓' if validation_results['system_metrics']['performance_score'] >= 70 else '✗'} |

## Endpoint Performance Details

"""
    
    # Add endpoint-specific results
    for endpoint_key, endpoint_result in validation_results['endpoint_results'].items():
        metrics = endpoint_result['performance_metrics']
        compliance = endpoint_result['compliance_status']
        
        report += f"""### {endpoint_key}

**Compliance Status:** {'✓ PASSED' if compliance['overall_compliant'] else '✗ FAILED'}  
**Performance Score:** {endpoint_result['statistical_analysis']['performance_score']:.1f}/100

**Response Time Metrics:**
- Mean: {metrics['response_time_metrics']['mean_ms']:.1f}ms
- P95: {metrics['response_time_metrics']['p95_ms']:.1f}ms
- P99: {metrics['response_time_metrics']['p99_ms']:.1f}ms

**Throughput Metrics:**
- Requests/Second: {metrics['throughput_metrics']['requests_per_second']:.1f}
- Transfer Rate: {metrics['throughput_metrics']['transfer_rate_kb_sec']:.1f} KB/s

**Reliability Metrics:**
- Error Rate: {metrics['reliability_metrics']['error_rate_percent']:.3f}%
- Success Rate: {metrics['reliability_metrics']['success_rate_percent']:.1f}%

"""
        
        if compliance['critical_issues']:
            report += "**Critical Issues:**\n"
            for issue in compliance['critical_issues']:
                report += f"- {issue}\n"
            report += "\n"
    
    # Add variance analysis
    if validation_results['compliance_summary']['variance_violations']:
        report += "## Baseline Variance Violations\n\n"
        report += "| Endpoint | Metric | Variance | Threshold |\n"
        report += "|----------|--------|----------|----------|\n"
        
        for violation in validation_results['compliance_summary']['variance_violations']:
            report += f"| {violation['endpoint']} | {violation['metric']} | {violation['variance_percent']:+.2f}% | ±{PERFORMANCE_VARIANCE_THRESHOLD}% |\n"
        
        report += "\n"
    
    # Add recommendations
    report += "## Recommendations\n\n"
    
    recommendation = validation_results['recommendation']
    if recommendation == 'deployment_approved':
        report += "✅ **Deployment Approved** - All performance criteria met\n"
    elif recommendation == 'deployment_approved_with_monitoring':
        report += "⚠️ **Deployment Approved with Monitoring** - Minor issues detected, monitor closely\n"
    elif recommendation == 'deployment_requires_optimization':
        report += "🔧 **Optimization Required** - Performance issues need attention before deployment\n"
    else:
        report += "❌ **Deployment Rejected** - Critical performance issues must be resolved\n"
    
    report += "\n"
    
    # Add general recommendations based on issues
    if validation_results['compliance_summary']['critical_issues']:
        report += "**Critical Actions Required:**\n"
        for issue in set(validation_results['compliance_summary']['critical_issues']):  # Remove duplicates
            report += f"- {issue}\n"
        report += "\n"
    
    # Save report to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        logger.info(f"Performance benchmark report saved to {output_file}")
    
    return report


# Export public interface
__all__ = [
    'ApacheBenchResult',
    'ApacheBenchExecutor', 
    'PerformanceBenchmarkValidator',
    'TestApacheBenchmarkIntegration',
    'validate_system_performance_against_baseline',
    'generate_performance_benchmark_report'
]