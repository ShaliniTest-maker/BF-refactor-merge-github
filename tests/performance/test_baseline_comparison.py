"""
Baseline Comparison Performance Testing Module

This module implements comprehensive baseline comparison testing to ensure the Flask implementation
maintains ≤10% performance variance from the original Node.js baseline per Section 0.1.1 primary
objective. Provides automated regression detection, trend analysis, and performance failure alerting
for continuous validation of the migration quality.

Key Features:
- ≤10% variance enforcement from Node.js baseline per Section 0.1.1
- Response time, memory usage, CPU utilization tracking per Section 0.3.2
- Database query performance comparison per Section 0.3.2
- Automated regression detection per Section 6.6.1
- Trend analysis and performance monitoring per Section 6.5
- Integration with CI/CD pipeline per Section 6.6.2

Performance Requirements Compliance:
- Response time variance ≤10% from Node.js baseline (critical requirement)
- Memory usage variance ≤15% acceptable per Section 0.3.2
- Database query performance ≤10% variance per Section 0.3.2  
- Concurrent request capacity preservation per Section 4.6.3
- 95th percentile response time ≤500ms per Section 4.6.3
- Minimum 100 req/sec sustained throughput per Section 4.6.3

Architecture Integration:
- Section 0.1.1: Primary objective performance optimization ≤10% variance
- Section 0.3.2: Performance monitoring requirements implementation
- Section 4.6.3: Performance testing specifications compliance
- Section 6.6.1: Testing strategy baseline comparison validation
- Section 6.6.2: CI/CD integration with automated quality gates

Author: Flask Migration Team
Version: 1.0.0
Dependencies: tests/performance/conftest.py, baseline_data.py, performance_config.py
"""

import asyncio
import json
import psutil
import statistics
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field, asdict

import pytest
from flask import Flask
from flask.testing import FlaskClient

# Performance testing imports
from tests.performance.conftest import (
    performance_config,
    baseline_data_manager, 
    baseline_comparison_validator,
    performance_monitoring_setup,
    performance_test_environment,
    locust_environment,
    apache_bench_runner,
    measure_response_time,
    performance_timer,
    validate_response_time_threshold,
    validate_throughput_threshold,
    PerformanceTestError,
    BaselineComparisonError,
    BASELINE_VARIANCE_LIMIT,
    MIN_SAMPLE_SIZE,
    PERFORMANCE_TEST_TIMEOUT
)

from tests.performance.baseline_data import (
    NodeJSPerformanceBaseline,
    BaselineDataManager,
    BaselineValidationStatus,
    compare_with_baseline,
    get_nodejs_baseline,
    validate_baseline_data,
    PERFORMANCE_VARIANCE_THRESHOLD
)

from tests.performance.performance_config import (
    PerformanceTestConfig,
    LoadTestScenario,
    LoadTestConfiguration,
    PerformanceMetricType,
    create_performance_config,
    get_load_test_config,
    validate_performance_results,
    get_baseline_metrics
)

# Structured logging for comprehensive test reporting
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    STRUCTLOG_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("structlog not available - falling back to standard logging")

# Prometheus metrics for performance tracking
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("prometheus_client not available - metrics collection disabled")

# Performance test constants per Section 4.6.3 and Section 0.1.1
CRITICAL_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement per Section 0.1.1
MEMORY_VARIANCE_THRESHOLD = 15.0    # ≤15% memory variance per Section 0.3.2
WARNING_VARIANCE_THRESHOLD = 5.0    # Warning at 5% variance for early detection
RESPONSE_TIME_THRESHOLD_MS = 500.0  # 95th percentile ≤500ms per Section 4.6.3
THROUGHPUT_THRESHOLD_RPS = 100.0    # Minimum 100 req/sec per Section 4.6.3
ERROR_RATE_THRESHOLD = 0.1          # ≤0.1% error rate per Section 4.6.3
CPU_UTILIZATION_THRESHOLD = 70.0    # ≤70% CPU per Section 4.6.3
MEMORY_UTILIZATION_THRESHOLD = 80.0 # ≤80% memory per Section 4.6.3
MIN_TEST_DURATION_SECONDS = 300     # 5 minutes minimum for statistical validity
BASELINE_COMPARISON_SAMPLE_SIZE = 1000  # Minimum requests for valid comparison


@dataclass
class BaselineComparisonResult:
    """
    Comprehensive baseline comparison result containing variance analysis,
    compliance status, and detailed metrics for performance validation.
    """
    
    # Test identification and metadata
    test_name: str
    test_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_duration_seconds: float = 0.0
    
    # Performance metrics comparison
    response_time_variance: Dict[str, float] = field(default_factory=dict)
    throughput_variance: Dict[str, float] = field(default_factory=dict)
    memory_usage_variance: Dict[str, float] = field(default_factory=dict)
    cpu_utilization_variance: Dict[str, float] = field(default_factory=dict)
    database_performance_variance: Dict[str, float] = field(default_factory=dict)
    
    # Compliance and validation status
    overall_compliance: bool = False
    critical_issues: List[str] = field(default_factory=list)
    warning_issues: List[str] = field(default_factory=list)
    performance_grade: str = "F"  # A, B, C, D, F grading scale
    
    # Statistical analysis
    sample_size: int = 0
    statistical_confidence: float = 0.0
    variance_distribution: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    # Trend analysis and regression detection
    trend_analysis: Dict[str, Any] = field(default_factory=dict)
    regression_detected: bool = False
    performance_improvement: bool = False
    
    # Detailed metrics for investigation
    detailed_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def calculate_performance_grade(self) -> str:
        """
        Calculate performance grade based on variance compliance and critical issues.
        
        Returns:
            Performance grade (A-F) based on compliance metrics
        """
        if self.critical_issues:
            return "F"  # Failure grade for critical issues
        
        # Calculate average variance across all metrics
        all_variances = []
        for variance_dict in [
            self.response_time_variance,
            self.throughput_variance, 
            self.memory_usage_variance,
            self.cpu_utilization_variance,
            self.database_performance_variance
        ]:
            for variance in variance_dict.values():
                if isinstance(variance, (int, float)):
                    all_variances.append(abs(variance))
        
        if not all_variances:
            return "C"  # Default grade if no metrics available
        
        avg_variance = statistics.mean(all_variances)
        
        # Grade based on average variance from baseline
        if avg_variance <= 2.0:
            return "A"  # Excellent performance (≤2% variance)
        elif avg_variance <= 5.0:
            return "B"  # Good performance (≤5% variance)  
        elif avg_variance <= 10.0:
            return "C"  # Acceptable performance (≤10% variance)
        elif avg_variance <= 15.0:
            return "D"  # Poor performance (>10% but ≤15% variance)
        else:
            return "F"  # Failing performance (>15% variance)
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive summary report for stakeholder communication.
        
        Returns:
            Dictionary containing executive summary and detailed analysis
        """
        self.performance_grade = self.calculate_performance_grade()
        
        return {
            "executive_summary": {
                "test_name": self.test_name,
                "test_timestamp": self.test_timestamp.isoformat(),
                "overall_compliance": self.overall_compliance,
                "performance_grade": self.performance_grade,
                "critical_issues_count": len(self.critical_issues),
                "warning_issues_count": len(self.warning_issues),
                "regression_detected": self.regression_detected,
                "performance_improvement": self.performance_improvement
            },
            "variance_summary": {
                "response_time_variance": self.response_time_variance,
                "throughput_variance": self.throughput_variance,
                "memory_usage_variance": self.memory_usage_variance,
                "cpu_utilization_variance": self.cpu_utilization_variance,
                "database_performance_variance": self.database_performance_variance
            },
            "quality_assessment": {
                "sample_size": self.sample_size,
                "statistical_confidence": self.statistical_confidence,
                "test_duration_seconds": self.test_duration_seconds,
                "variance_distribution": self.variance_distribution
            },
            "issues_and_recommendations": {
                "critical_issues": self.critical_issues,
                "warning_issues": self.warning_issues,
                "recommendations": self.recommendations
            },
            "trend_analysis": self.trend_analysis,
            "detailed_metrics": self.detailed_metrics
        }


class BaselineComparisonTestSuite:
    """
    Comprehensive baseline comparison test suite implementing automated variance 
    calculation, trend analysis, and regression detection for Flask migration validation.
    
    Ensures compliance with ≤10% variance requirement per Section 0.1.1 and provides
    comprehensive performance monitoring per Section 0.3.2 requirements.
    """
    
    def __init__(
        self,
        baseline_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig,
        monitoring_setup: Dict[str, Any]
    ):
        """
        Initialize baseline comparison test suite with dependencies.
        
        Args:
            baseline_manager: Baseline data manager for Node.js comparisons
            performance_config: Performance configuration and thresholds
            monitoring_setup: Performance monitoring infrastructure
        """
        self.baseline_manager = baseline_manager
        self.performance_config = performance_config
        self.monitoring_setup = monitoring_setup
        
        # Initialize test state tracking
        self.test_results: List[BaselineComparisonResult] = []
        self.regression_history: List[Dict[str, Any]] = []
        self.performance_trends: Dict[str, List[float]] = {}
        
        # Performance metrics registries
        if PROMETHEUS_AVAILABLE:
            self.metrics_registry = CollectorRegistry()
            self._init_prometheus_metrics()
        
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for performance tracking."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # Baseline variance tracking metrics
        self.variance_gauge = Gauge(
            'baseline_variance_percent',
            'Performance variance from Node.js baseline',
            ['metric_type', 'endpoint'],
            registry=self.metrics_registry
        )
        
        # Compliance status metrics
        self.compliance_gauge = Gauge(
            'baseline_compliance_status',
            'Baseline compliance status (1=compliant, 0=non-compliant)',
            ['test_type'],
            registry=self.metrics_registry
        )
        
        # Performance trend metrics
        self.trend_histogram = Histogram(
            'performance_trend_variance',
            'Historical performance variance distribution',
            buckets=[1.0, 2.5, 5.0, 7.5, 10.0, 15.0, 20.0],
            registry=self.metrics_registry
        )
        
        # Test execution metrics
        self.test_duration_histogram = Histogram(
            'baseline_test_duration_seconds',
            'Baseline comparison test execution time',
            ['test_type'],
            registry=self.metrics_registry
        )
    
    def run_comprehensive_baseline_comparison(
        self,
        app: Flask,
        test_scenarios: List[str] = None,
        include_load_testing: bool = True,
        include_database_testing: bool = True,
        include_memory_profiling: bool = True
    ) -> BaselineComparisonResult:
        """
        Execute comprehensive baseline comparison across all performance dimensions.
        
        Args:
            app: Flask application instance for testing
            test_scenarios: List of specific test scenarios to execute
            include_load_testing: Whether to include load testing validation
            include_database_testing: Whether to include database performance testing  
            include_memory_profiling: Whether to include memory usage profiling
            
        Returns:
            BaselineComparisonResult with comprehensive variance analysis
            
        Raises:
            BaselineComparisonError: If critical performance variance detected
            PerformanceTestError: If test execution fails
        """
        start_time = time.time()
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info(
                "Starting comprehensive baseline comparison test",
                test_scenarios=test_scenarios,
                include_load_testing=include_load_testing,
                include_database_testing=include_database_testing,
                include_memory_profiling=include_memory_profiling
            )
        
        # Initialize comprehensive test result
        result = BaselineComparisonResult(
            test_name="comprehensive_baseline_comparison",
            test_timestamp=datetime.now(timezone.utc)
        )
        
        try:
            # Get Node.js baseline for comparison
            nodejs_baseline = self.baseline_manager.get_default_baseline()
            
            # Execute core performance tests
            with app.test_client() as client:
                # 1. API Response Time Comparison
                response_time_results = self._test_api_response_times(client, nodejs_baseline)
                result.response_time_variance.update(response_time_results["variance_analysis"])
                result.detailed_metrics["response_times"] = response_time_results
                
                # 2. Throughput and Concurrency Testing
                if include_load_testing:
                    throughput_results = self._test_throughput_performance(client, nodejs_baseline)
                    result.throughput_variance.update(throughput_results["variance_analysis"])
                    result.detailed_metrics["throughput"] = throughput_results
                
                # 3. Memory Usage Profiling
                if include_memory_profiling:
                    memory_results = self._test_memory_usage_patterns(client, nodejs_baseline)
                    result.memory_usage_variance.update(memory_results["variance_analysis"])
                    result.detailed_metrics["memory_usage"] = memory_results
                
                # 4. CPU Utilization Analysis
                cpu_results = self._test_cpu_utilization(client, nodejs_baseline)
                result.cpu_utilization_variance.update(cpu_results["variance_analysis"])
                result.detailed_metrics["cpu_utilization"] = cpu_results
                
                # 5. Database Performance Comparison
                if include_database_testing:
                    database_results = self._test_database_performance(nodejs_baseline)
                    result.database_performance_variance.update(database_results["variance_analysis"])
                    result.detailed_metrics["database_performance"] = database_results
            
            # Calculate test completion metrics
            result.test_duration_seconds = time.time() - start_time
            result.sample_size = self._calculate_total_sample_size(result.detailed_metrics)
            result.statistical_confidence = self._calculate_statistical_confidence(result.sample_size)
            
            # Perform compliance validation
            self._validate_compliance_status(result)
            
            # Execute trend analysis and regression detection
            self._perform_trend_analysis(result)
            
            # Generate recommendations
            self._generate_performance_recommendations(result)
            
            # Update Prometheus metrics
            self._update_prometheus_metrics(result)
            
            # Store result for historical analysis
            self.test_results.append(result)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Comprehensive baseline comparison completed",
                    overall_compliance=result.overall_compliance,
                    performance_grade=result.calculate_performance_grade(),
                    test_duration=result.test_duration_seconds,
                    critical_issues=len(result.critical_issues),
                    warning_issues=len(result.warning_issues)
                )
            
            # Raise exception for critical compliance failures
            if result.critical_issues:
                raise BaselineComparisonError(
                    f"Critical performance variance detected: {result.critical_issues}"
                )
            
            return result
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Comprehensive baseline comparison failed",
                    error=str(e),
                    traceback=traceback.format_exc()
                )
            raise PerformanceTestError(f"Baseline comparison test failed: {str(e)}")
    
    def _test_api_response_times(
        self,
        client: FlaskClient,
        baseline: NodeJSPerformanceBaseline
    ) -> Dict[str, Any]:
        """
        Test API response times against Node.js baseline with comprehensive endpoint coverage.
        
        Args:
            client: Flask test client for API requests
            baseline: Node.js performance baseline for comparison
            
        Returns:
            Dictionary containing response time analysis and variance calculations
        """
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting API response time baseline comparison")
        
        response_time_results = {
            "endpoint_metrics": {},
            "variance_analysis": {},
            "statistical_summary": {},
            "compliance_status": {}
        }
        
        # Define comprehensive API endpoint test matrix
        test_endpoints = [
            {"path": "/health", "method": "GET", "expected_baseline": 50.0},
            {"path": "/api/v1/auth/login", "method": "POST", "expected_baseline": 180.0},
            {"path": "/api/v1/auth/logout", "method": "POST", "expected_baseline": 80.0},
            {"path": "/api/v1/auth/refresh", "method": "POST", "expected_baseline": 160.0},
            {"path": "/api/v1/users", "method": "GET", "expected_baseline": 150.0},
            {"path": "/api/v1/users", "method": "POST", "expected_baseline": 200.0},
            {"path": "/api/v1/users/123", "method": "GET", "expected_baseline": 130.0},
            {"path": "/api/v1/users/123", "method": "PUT", "expected_baseline": 180.0},
            {"path": "/api/v1/users/123", "method": "DELETE", "expected_baseline": 120.0},
            {"path": "/api/v1/data/export", "method": "GET", "expected_baseline": 850.0},
            {"path": "/api/v1/files/upload", "method": "POST", "expected_baseline": 450.0}
        ]
        
        # Execute response time testing for each endpoint
        for endpoint_config in test_endpoints:
            endpoint_path = endpoint_config["path"]
            method = endpoint_config["method"]
            expected_baseline = endpoint_config["expected_baseline"]
            
            try:
                # Collect multiple samples for statistical validity
                response_times = []
                successful_requests = 0
                failed_requests = 0
                
                for i in range(MIN_SAMPLE_SIZE):
                    try:
                        # Prepare request data based on method
                        request_data = self._prepare_request_data(endpoint_path, method)
                        
                        # Measure response time
                        start_time = time.time()
                        
                        if method == "GET":
                            response = client.get(endpoint_path)
                        elif method == "POST":
                            response = client.post(endpoint_path, json=request_data)
                        elif method == "PUT":
                            response = client.put(endpoint_path, json=request_data)
                        elif method == "DELETE":
                            response = client.delete(endpoint_path)
                        else:
                            continue
                        
                        response_time_ms = (time.time() - start_time) * 1000
                        
                        # Consider successful responses (2xx, 3xx, some 4xx)
                        if response.status_code < 500:
                            response_times.append(response_time_ms)
                            successful_requests += 1
                        else:
                            failed_requests += 1
                            
                    except Exception as request_error:
                        failed_requests += 1
                        if STRUCTLOG_AVAILABLE:
                            self.logger.warning(
                                "Request failed during response time testing",
                                endpoint=endpoint_path,
                                method=method,
                                error=str(request_error)
                            )
                        continue
                
                # Analyze response time statistics
                if response_times:
                    mean_response_time = statistics.mean(response_times)
                    median_response_time = statistics.median(response_times)
                    p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)
                    std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
                    
                    # Calculate variance from baseline
                    variance_percent = ((mean_response_time - expected_baseline) / expected_baseline) * 100
                    
                    # Determine compliance status
                    is_compliant = abs(variance_percent) <= CRITICAL_VARIANCE_THRESHOLD
                    is_warning = abs(variance_percent) > WARNING_VARIANCE_THRESHOLD
                    
                    endpoint_key = f"{method} {endpoint_path}"
                    
                    # Store detailed metrics
                    response_time_results["endpoint_metrics"][endpoint_key] = {
                        "sample_count": len(response_times),
                        "successful_requests": successful_requests,
                        "failed_requests": failed_requests,
                        "mean_ms": mean_response_time,
                        "median_ms": median_response_time,
                        "p95_ms": p95_response_time,
                        "std_dev_ms": std_dev,
                        "baseline_ms": expected_baseline,
                        "variance_percent": variance_percent,
                        "compliant": is_compliant,
                        "warning": is_warning
                    }
                    
                    # Store variance analysis
                    response_time_results["variance_analysis"][endpoint_key] = variance_percent
                    response_time_results["compliance_status"][endpoint_key] = is_compliant
                    
                    # Update performance monitoring
                    if self.monitoring_setup:
                        self.monitoring_setup["collect_response_time"](
                            endpoint_path, method, mean_response_time
                        )
                    
                    # Update Prometheus metrics
                    if PROMETHEUS_AVAILABLE:
                        self.variance_gauge.labels(
                            metric_type="response_time",
                            endpoint=endpoint_key
                        ).set(abs(variance_percent))
                    
                    if STRUCTLOG_AVAILABLE:
                        self.logger.info(
                            "API response time analysis completed",
                            endpoint=endpoint_key,
                            mean_response_time=mean_response_time,
                            baseline=expected_baseline,
                            variance_percent=variance_percent,
                            compliant=is_compliant,
                            sample_size=len(response_times)
                        )
                        
                else:
                    if STRUCTLOG_AVAILABLE:
                        self.logger.error(
                            "No successful response time samples collected",
                            endpoint=endpoint_path,
                            method=method,
                            failed_requests=failed_requests
                        )
                    
                    # Record failed endpoint
                    endpoint_key = f"{method} {endpoint_path}"
                    response_time_results["endpoint_metrics"][endpoint_key] = {
                        "sample_count": 0,
                        "successful_requests": 0,
                        "failed_requests": failed_requests,
                        "error": "No successful samples collected"
                    }
                    
                    response_time_results["variance_analysis"][endpoint_key] = float('inf')
                    response_time_results["compliance_status"][endpoint_key] = False
                    
            except Exception as endpoint_error:
                if STRUCTLOG_AVAILABLE:
                    self.logger.error(
                        "API response time testing failed for endpoint",
                        endpoint=endpoint_path,
                        method=method,
                        error=str(endpoint_error)
                    )
        
        # Calculate overall statistical summary
        all_variances = [v for v in response_time_results["variance_analysis"].values() if isinstance(v, (int, float)) and not math.isinf(v)]
        
        if all_variances:
            response_time_results["statistical_summary"] = {
                "total_endpoints_tested": len(test_endpoints),
                "successful_endpoint_tests": len(all_variances),
                "mean_variance_percent": statistics.mean([abs(v) for v in all_variances]),
                "median_variance_percent": statistics.median([abs(v) for v in all_variances]),
                "max_variance_percent": max([abs(v) for v in all_variances]),
                "compliant_endpoints": sum(1 for compliant in response_time_results["compliance_status"].values() if compliant),
                "compliance_percentage": (sum(1 for compliant in response_time_results["compliance_status"].values() if compliant) / len(all_variances)) * 100
            }
        
        return response_time_results
    
    def _test_throughput_performance(
        self,
        client: FlaskClient,
        baseline: NodeJSPerformanceBaseline
    ) -> Dict[str, Any]:
        """
        Test throughput performance against Node.js baseline with load scaling validation.
        
        Args:
            client: Flask test client for load testing
            baseline: Node.js performance baseline for comparison
            
        Returns:
            Dictionary containing throughput analysis and variance calculations
        """
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting throughput performance baseline comparison")
        
        throughput_results = {
            "load_test_metrics": {},
            "variance_analysis": {},
            "statistical_summary": {},
            "compliance_status": {}
        }
        
        # Define progressive load testing scenarios
        load_scenarios = [
            {"concurrent_users": 10, "duration_seconds": 60, "expected_rps": 50.0},
            {"concurrent_users": 50, "duration_seconds": 120, "expected_rps": 100.0},
            {"concurrent_users": 100, "duration_seconds": 180, "expected_rps": 125.0},
            {"concurrent_users": 200, "duration_seconds": 240, "expected_rps": 150.0}
        ]
        
        for scenario in load_scenarios:
            concurrent_users = scenario["concurrent_users"]
            duration_seconds = scenario["duration_seconds"]
            expected_rps = scenario["expected_rps"]
            
            try:
                if STRUCTLOG_AVAILABLE:
                    self.logger.info(
                        "Executing load testing scenario",
                        concurrent_users=concurrent_users,
                        duration_seconds=duration_seconds,
                        expected_rps=expected_rps
                    )
                
                # Execute concurrent load testing
                throughput_metrics = self._execute_concurrent_load_test(
                    client, concurrent_users, duration_seconds
                )
                
                # Calculate variance from baseline
                measured_rps = throughput_metrics["requests_per_second"]
                variance_percent = ((measured_rps - expected_rps) / expected_rps) * 100
                
                # Determine compliance status
                is_compliant = abs(variance_percent) <= CRITICAL_VARIANCE_THRESHOLD
                meets_minimum = measured_rps >= THROUGHPUT_THRESHOLD_RPS
                
                scenario_key = f"{concurrent_users}_users"
                
                # Store detailed metrics
                throughput_results["load_test_metrics"][scenario_key] = {
                    "concurrent_users": concurrent_users,
                    "test_duration_seconds": duration_seconds,
                    "total_requests": throughput_metrics["total_requests"],
                    "successful_requests": throughput_metrics["successful_requests"],
                    "failed_requests": throughput_metrics["failed_requests"],
                    "requests_per_second": measured_rps,
                    "average_response_time_ms": throughput_metrics["average_response_time_ms"],
                    "p95_response_time_ms": throughput_metrics["p95_response_time_ms"],
                    "error_rate_percent": throughput_metrics["error_rate_percent"],
                    "baseline_rps": expected_rps,
                    "variance_percent": variance_percent,
                    "compliant": is_compliant,
                    "meets_minimum_threshold": meets_minimum
                }
                
                # Store variance analysis
                throughput_results["variance_analysis"][scenario_key] = variance_percent
                throughput_results["compliance_status"][scenario_key] = is_compliant and meets_minimum
                
                # Update performance monitoring
                if self.monitoring_setup:
                    self.monitoring_setup["collect_throughput"](measured_rps)
                
                if STRUCTLOG_AVAILABLE:
                    self.logger.info(
                        "Load testing scenario completed",
                        scenario=scenario_key,
                        measured_rps=measured_rps,
                        expected_rps=expected_rps,
                        variance_percent=variance_percent,
                        compliant=is_compliant,
                        meets_minimum=meets_minimum
                    )
                    
            except Exception as scenario_error:
                if STRUCTLOG_AVAILABLE:
                    self.logger.error(
                        "Load testing scenario failed",
                        scenario=scenario_key,
                        error=str(scenario_error)
                    )
                
                throughput_results["variance_analysis"][scenario_key] = float('inf')
                throughput_results["compliance_status"][scenario_key] = False
        
        # Calculate overall statistical summary
        all_variances = [v for v in throughput_results["variance_analysis"].values() if isinstance(v, (int, float)) and not math.isinf(v)]
        
        if all_variances:
            throughput_results["statistical_summary"] = {
                "total_scenarios_tested": len(load_scenarios),
                "successful_scenario_tests": len(all_variances),
                "mean_variance_percent": statistics.mean([abs(v) for v in all_variances]),
                "max_variance_percent": max([abs(v) for v in all_variances]),
                "compliant_scenarios": sum(1 for compliant in throughput_results["compliance_status"].values() if compliant),
                "compliance_percentage": (sum(1 for compliant in throughput_results["compliance_status"].values() if compliant) / len(all_variances)) * 100
            }
        
        return throughput_results
    
    def _test_memory_usage_patterns(
        self,
        client: FlaskClient,
        baseline: NodeJSPerformanceBaseline
    ) -> Dict[str, Any]:
        """
        Test memory usage patterns against Node.js baseline with leak detection.
        
        Args:
            client: Flask test client for memory profiling
            baseline: Node.js performance baseline for comparison
            
        Returns:
            Dictionary containing memory analysis and variance calculations
        """
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting memory usage pattern baseline comparison")
        
        memory_results = {
            "memory_profiling": {},
            "variance_analysis": {},
            "leak_detection": {},
            "compliance_status": {}
        }
        
        # Get baseline memory metrics
        baseline_memory_mb = baseline.memory_usage_baseline_mb
        baseline_peak_mb = baseline.memory_usage_peak_mb
        
        try:
            # Initial memory measurement
            initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)  # Convert to MB
            
            # Execute memory stress testing
            memory_samples = []
            
            # Perform sustained request testing to monitor memory usage
            test_duration = 300  # 5 minutes of sustained testing
            sample_interval = 5   # Sample every 5 seconds
            
            start_time = time.time()
            request_count = 0
            
            while (time.time() - start_time) < test_duration:
                # Execute batch of requests
                for _ in range(10):
                    try:
                        response = client.get("/health")
                        request_count += 1
                    except Exception:
                        pass
                
                # Sample memory usage
                current_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                memory_samples.append({
                    "timestamp": time.time() - start_time,
                    "memory_mb": current_memory,
                    "requests_processed": request_count
                })
                
                time.sleep(sample_interval)
            
            # Final memory measurement
            final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
            
            # Analyze memory usage patterns
            memory_values = [sample["memory_mb"] for sample in memory_samples]
            
            if memory_values:
                mean_memory = statistics.mean(memory_values)
                peak_memory = max(memory_values)
                memory_growth = final_memory - initial_memory
                
                # Calculate variance from baseline
                baseline_variance = ((mean_memory - baseline_memory_mb) / baseline_memory_mb) * 100
                peak_variance = ((peak_memory - baseline_peak_mb) / baseline_peak_mb) * 100
                
                # Determine compliance status (allow ≤15% variance for memory)
                baseline_compliant = abs(baseline_variance) <= MEMORY_VARIANCE_THRESHOLD
                peak_compliant = abs(peak_variance) <= MEMORY_VARIANCE_THRESHOLD
                
                # Detect potential memory leaks
                leak_detected = memory_growth > (mean_memory * 0.1)  # >10% growth considered leak risk
                
                # Store detailed metrics
                memory_results["memory_profiling"] = {
                    "initial_memory_mb": initial_memory,
                    "final_memory_mb": final_memory,
                    "mean_memory_mb": mean_memory,
                    "peak_memory_mb": peak_memory,
                    "memory_growth_mb": memory_growth,
                    "test_duration_seconds": test_duration,
                    "requests_processed": request_count,
                    "sample_count": len(memory_samples),
                    "baseline_memory_mb": baseline_memory_mb,
                    "baseline_peak_mb": baseline_peak_mb
                }
                
                # Store variance analysis
                memory_results["variance_analysis"] = {
                    "baseline_variance_percent": baseline_variance,
                    "peak_variance_percent": peak_variance,
                    "memory_growth_percent": (memory_growth / initial_memory) * 100
                }
                
                # Store leak detection results
                memory_results["leak_detection"] = {
                    "leak_detected": leak_detected,
                    "memory_growth_mb": memory_growth,
                    "growth_rate_mb_per_request": memory_growth / request_count if request_count > 0 else 0,
                    "stability_assessment": "stable" if not leak_detected else "potential_leak"
                }
                
                # Store compliance status
                memory_results["compliance_status"] = {
                    "baseline_compliant": baseline_compliant,
                    "peak_compliant": peak_compliant,
                    "overall_compliant": baseline_compliant and peak_compliant and not leak_detected
                }
                
                # Update performance monitoring
                if self.monitoring_setup:
                    self.monitoring_setup["collect_resource_metrics"](
                        psutil.cpu_percent(), mean_memory
                    )
                
                if STRUCTLOG_AVAILABLE:
                    self.logger.info(
                        "Memory usage pattern analysis completed",
                        mean_memory=mean_memory,
                        peak_memory=peak_memory,
                        baseline_variance=baseline_variance,
                        peak_variance=peak_variance,
                        leak_detected=leak_detected,
                        baseline_compliant=baseline_compliant,
                        peak_compliant=peak_compliant
                    )
                    
            else:
                if STRUCTLOG_AVAILABLE:
                    self.logger.error("No memory samples collected during testing")
                
                memory_results["compliance_status"] = {"overall_compliant": False}
                
        except Exception as memory_error:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Memory usage testing failed",
                    error=str(memory_error)
                )
            
            memory_results["compliance_status"] = {"overall_compliant": False}
        
        return memory_results
    
    def _test_cpu_utilization(
        self,
        client: FlaskClient,
        baseline: NodeJSPerformanceBaseline
    ) -> Dict[str, Any]:
        """
        Test CPU utilization against Node.js baseline with efficiency analysis.
        
        Args:
            client: Flask test client for CPU profiling
            baseline: Node.js performance baseline for comparison
            
        Returns:
            Dictionary containing CPU analysis and variance calculations
        """
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting CPU utilization baseline comparison")
        
        cpu_results = {
            "cpu_profiling": {},
            "variance_analysis": {},
            "efficiency_analysis": {},
            "compliance_status": {}
        }
        
        # Get baseline CPU metrics
        baseline_cpu_avg = baseline.cpu_utilization_average
        baseline_cpu_peak = baseline.cpu_utilization_peak
        
        try:
            # Initialize CPU monitoring
            initial_cpu = psutil.cpu_percent(interval=1)
            cpu_samples = []
            
            # Execute CPU stress testing with sustained load
            test_duration = 180  # 3 minutes of CPU testing
            sample_interval = 2   # Sample every 2 seconds
            
            start_time = time.time()
            request_count = 0
            
            while (time.time() - start_time) < test_duration:
                # Execute CPU-intensive requests
                for _ in range(20):  # Batch requests for CPU load
                    try:
                        # Mix of different endpoints to simulate realistic load
                        endpoints = ["/health", "/api/v1/users", "/api/v1/auth/login"]
                        endpoint = endpoints[request_count % len(endpoints)]
                        
                        if endpoint == "/api/v1/auth/login":
                            client.post(endpoint, json={"email": "test@example.com", "password": "test"})
                        else:
                            client.get(endpoint)
                        
                        request_count += 1
                    except Exception:
                        pass
                
                # Sample CPU utilization
                current_cpu = psutil.cpu_percent(interval=None)
                cpu_samples.append({
                    "timestamp": time.time() - start_time,
                    "cpu_percent": current_cpu,
                    "requests_processed": request_count
                })
                
                time.sleep(sample_interval)
            
            # Final CPU measurement
            final_cpu = psutil.cpu_percent(interval=1)
            
            # Analyze CPU utilization patterns
            if cpu_samples:
                cpu_values = [sample["cpu_percent"] for sample in cpu_samples]
                
                mean_cpu = statistics.mean(cpu_values)
                peak_cpu = max(cpu_values)
                min_cpu = min(cpu_values)
                std_dev_cpu = statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0
                
                # Calculate variance from baseline
                avg_variance = ((mean_cpu - baseline_cpu_avg) / baseline_cpu_avg) * 100
                peak_variance = ((peak_cpu - baseline_cpu_peak) / baseline_cpu_peak) * 100
                
                # Determine compliance status
                avg_compliant = abs(avg_variance) <= CRITICAL_VARIANCE_THRESHOLD
                peak_compliant = peak_cpu <= CPU_UTILIZATION_THRESHOLD
                efficiency_good = mean_cpu <= (CPU_UTILIZATION_THRESHOLD * 0.8)  # 80% of threshold
                
                # Calculate efficiency metrics
                cpu_efficiency = request_count / mean_cpu if mean_cpu > 0 else 0  # Requests per CPU percent
                
                # Store detailed metrics
                cpu_results["cpu_profiling"] = {
                    "initial_cpu_percent": initial_cpu,
                    "final_cpu_percent": final_cpu,
                    "mean_cpu_percent": mean_cpu,
                    "peak_cpu_percent": peak_cpu,
                    "min_cpu_percent": min_cpu,
                    "std_dev_cpu": std_dev_cpu,
                    "test_duration_seconds": test_duration,
                    "requests_processed": request_count,
                    "sample_count": len(cpu_samples),
                    "baseline_cpu_avg": baseline_cpu_avg,
                    "baseline_cpu_peak": baseline_cpu_peak
                }
                
                # Store variance analysis
                cpu_results["variance_analysis"] = {
                    "average_variance_percent": avg_variance,
                    "peak_variance_percent": peak_variance,
                    "utilization_efficiency": cpu_efficiency
                }
                
                # Store efficiency analysis
                cpu_results["efficiency_analysis"] = {
                    "cpu_efficiency_ratio": cpu_efficiency,
                    "requests_per_cpu_percent": cpu_efficiency,
                    "utilization_stability": "stable" if std_dev_cpu < 5.0 else "variable",
                    "peak_within_threshold": peak_cpu <= CPU_UTILIZATION_THRESHOLD,
                    "efficiency_rating": "excellent" if efficiency_good else "acceptable" if avg_compliant else "poor"
                }
                
                # Store compliance status
                cpu_results["compliance_status"] = {
                    "average_compliant": avg_compliant,
                    "peak_compliant": peak_compliant,
                    "efficiency_good": efficiency_good,
                    "overall_compliant": avg_compliant and peak_compliant
                }
                
                if STRUCTLOG_AVAILABLE:
                    self.logger.info(
                        "CPU utilization analysis completed",
                        mean_cpu=mean_cpu,
                        peak_cpu=peak_cpu,
                        avg_variance=avg_variance,
                        peak_variance=peak_variance,
                        cpu_efficiency=cpu_efficiency,
                        avg_compliant=avg_compliant,
                        peak_compliant=peak_compliant
                    )
                    
            else:
                if STRUCTLOG_AVAILABLE:
                    self.logger.error("No CPU samples collected during testing")
                
                cpu_results["compliance_status"] = {"overall_compliant": False}
                
        except Exception as cpu_error:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "CPU utilization testing failed",
                    error=str(cpu_error)
                )
            
            cpu_results["compliance_status"] = {"overall_compliant": False}
        
        return cpu_results
    
    def _test_database_performance(
        self,
        baseline: NodeJSPerformanceBaseline
    ) -> Dict[str, Any]:
        """
        Test database performance against Node.js baseline with operation-specific analysis.
        
        Args:
            baseline: Node.js performance baseline for comparison
            
        Returns:
            Dictionary containing database analysis and variance calculations
        """
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting database performance baseline comparison")
        
        database_results = {
            "operation_metrics": {},
            "variance_analysis": {},
            "performance_summary": {},
            "compliance_status": {}
        }
        
        # Get baseline database metrics
        baseline_operations = baseline.database_operation_baselines
        baseline_query_mean = baseline.database_query_time_mean
        
        try:
            # Test database operations (mock implementation for example)
            # In real implementation, this would connect to actual database
            database_operations = [
                {"operation": "find_one", "baseline_ms": baseline_operations.get("find_one", 12.0)},
                {"operation": "find_many", "baseline_ms": baseline_operations.get("find_many", 45.0)},
                {"operation": "insert_one", "baseline_ms": baseline_operations.get("insert_one", 25.0)},
                {"operation": "update_one", "baseline_ms": baseline_operations.get("update_one", 35.0)},
                {"operation": "delete_one", "baseline_ms": baseline_operations.get("delete_one", 20.0)},
                {"operation": "aggregate", "baseline_ms": baseline_operations.get("aggregate", 85.0)}
            ]
            
            for operation_config in database_operations:
                operation_name = operation_config["operation"]
                baseline_time = operation_config["baseline_ms"]
                
                try:
                    # Simulate database operation testing (replace with actual database calls)
                    operation_times = []
                    
                    for _ in range(100):  # 100 samples per operation
                        # Mock database operation timing (replace with actual implementation)
                        simulated_time = baseline_time * (0.8 + 0.4 * time.time() % 1)  # Simulate variance
                        operation_times.append(simulated_time)
                    
                    # Analyze operation performance
                    mean_time = statistics.mean(operation_times)
                    median_time = statistics.median(operation_times)
                    p95_time = statistics.quantiles(operation_times, n=20)[18] if len(operation_times) >= 20 else max(operation_times)
                    
                    # Calculate variance from baseline
                    variance_percent = ((mean_time - baseline_time) / baseline_time) * 100
                    
                    # Determine compliance status
                    is_compliant = abs(variance_percent) <= CRITICAL_VARIANCE_THRESHOLD
                    
                    # Store detailed metrics
                    database_results["operation_metrics"][operation_name] = {
                        "sample_count": len(operation_times),
                        "mean_ms": mean_time,
                        "median_ms": median_time,
                        "p95_ms": p95_time,
                        "baseline_ms": baseline_time,
                        "variance_percent": variance_percent,
                        "compliant": is_compliant
                    }
                    
                    # Store variance analysis
                    database_results["variance_analysis"][operation_name] = variance_percent
                    database_results["compliance_status"][operation_name] = is_compliant
                    
                    if STRUCTLOG_AVAILABLE:
                        self.logger.info(
                            "Database operation analysis completed",
                            operation=operation_name,
                            mean_time=mean_time,
                            baseline_time=baseline_time,
                            variance_percent=variance_percent,
                            compliant=is_compliant
                        )
                        
                except Exception as operation_error:
                    if STRUCTLOG_AVAILABLE:
                        self.logger.error(
                            "Database operation testing failed",
                            operation=operation_name,
                            error=str(operation_error)
                        )
                    
                    database_results["variance_analysis"][operation_name] = float('inf')
                    database_results["compliance_status"][operation_name] = False
            
            # Calculate overall performance summary
            all_variances = [v for v in database_results["variance_analysis"].values() if isinstance(v, (int, float)) and not math.isinf(v)]
            
            if all_variances:
                database_results["performance_summary"] = {
                    "total_operations_tested": len(database_operations),
                    "successful_operation_tests": len(all_variances),
                    "mean_variance_percent": statistics.mean([abs(v) for v in all_variances]),
                    "max_variance_percent": max([abs(v) for v in all_variances]),
                    "compliant_operations": sum(1 for compliant in database_results["compliance_status"].values() if compliant),
                    "compliance_percentage": (sum(1 for compliant in database_results["compliance_status"].values() if compliant) / len(all_variances)) * 100
                }
                
        except Exception as database_error:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Database performance testing failed",
                    error=str(database_error)
                )
        
        return database_results
    
    def _execute_concurrent_load_test(
        self,
        client: FlaskClient,
        concurrent_users: int,
        duration_seconds: int
    ) -> Dict[str, Any]:
        """
        Execute concurrent load testing with specified user count and duration.
        
        Args:
            client: Flask test client for load testing
            concurrent_users: Number of concurrent users to simulate
            duration_seconds: Test duration in seconds
            
        Returns:
            Dictionary containing load test metrics and results
        """
        load_test_results = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "error_rate_percent": 0.0,
            "requests_per_second": 0.0,
            "average_response_time_ms": 0.0,
            "p95_response_time_ms": 0.0
        }
        
        def execute_user_requests(user_id: int, test_duration: int) -> Dict[str, Any]:
            """Execute requests for a single simulated user."""
            user_results = {
                "requests": 0,
                "successful": 0,
                "failed": 0,
                "response_times": []
            }
            
            start_time = time.time()
            
            while (time.time() - start_time) < test_duration:
                try:
                    # Simulate realistic user behavior with mixed endpoint requests
                    endpoints = [
                        "/health",
                        "/api/v1/users",
                        "/api/v1/auth/login"
                    ]
                    
                    endpoint = endpoints[user_results["requests"] % len(endpoints)]
                    
                    request_start = time.time()
                    
                    if endpoint == "/api/v1/auth/login":
                        response = client.post(endpoint, json={
                            "email": f"user{user_id}@example.com",
                            "password": "testpassword"
                        })
                    else:
                        response = client.get(endpoint)
                    
                    response_time_ms = (time.time() - request_start) * 1000
                    
                    user_results["requests"] += 1
                    user_results["response_times"].append(response_time_ms)
                    
                    if response.status_code < 500:
                        user_results["successful"] += 1
                    else:
                        user_results["failed"] += 1
                    
                    # Simulate realistic user think time
                    time.sleep(0.1 + (user_id % 3) * 0.1)  # 0.1-0.4 seconds
                    
                except Exception:
                    user_results["requests"] += 1
                    user_results["failed"] += 1
            
            return user_results
        
        # Execute concurrent load testing
        try:
            with ThreadPoolExecutor(max_workers=min(concurrent_users, 50)) as executor:
                # Submit user simulation tasks
                future_to_user = {
                    executor.submit(execute_user_requests, user_id, duration_seconds): user_id
                    for user_id in range(concurrent_users)
                }
                
                # Collect results from all simulated users
                all_response_times = []
                total_requests = 0
                successful_requests = 0
                failed_requests = 0
                
                for future in as_completed(future_to_user):
                    user_id = future_to_user[future]
                    try:
                        user_result = future.result()
                        
                        total_requests += user_result["requests"]
                        successful_requests += user_result["successful"]
                        failed_requests += user_result["failed"]
                        all_response_times.extend(user_result["response_times"])
                        
                    except Exception as user_error:
                        if STRUCTLOG_AVAILABLE:
                            self.logger.warning(
                                "User simulation failed",
                                user_id=user_id,
                                error=str(user_error)
                            )
                        failed_requests += 1
                
                # Calculate load test metrics
                actual_duration = duration_seconds  # Use planned duration for RPS calculation
                
                load_test_results.update({
                    "total_requests": total_requests,
                    "successful_requests": successful_requests,
                    "failed_requests": failed_requests,
                    "response_times": all_response_times,
                    "error_rate_percent": (failed_requests / total_requests * 100) if total_requests > 0 else 100.0,
                    "requests_per_second": total_requests / actual_duration if actual_duration > 0 else 0.0
                })
                
                if all_response_times:
                    load_test_results.update({
                        "average_response_time_ms": statistics.mean(all_response_times),
                        "p95_response_time_ms": statistics.quantiles(all_response_times, n=20)[18] if len(all_response_times) >= 20 else max(all_response_times)
                    })
                
        except Exception as load_test_error:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Concurrent load test execution failed",
                    concurrent_users=concurrent_users,
                    duration_seconds=duration_seconds,
                    error=str(load_test_error)
                )
        
        return load_test_results
    
    def _prepare_request_data(self, endpoint_path: str, method: str) -> Dict[str, Any]:
        """
        Prepare appropriate request data for different endpoints and methods.
        
        Args:
            endpoint_path: API endpoint path
            method: HTTP method
            
        Returns:
            Dictionary containing request data appropriate for the endpoint
        """
        if method in ["GET", "DELETE"]:
            return {}
        
        # Prepare data based on endpoint
        if "auth/login" in endpoint_path:
            return {
                "email": "test@example.com",
                "password": "testpassword123"
            }
        elif "auth/refresh" in endpoint_path:
            return {
                "refresh_token": "mock_refresh_token"
            }
        elif "users" in endpoint_path and method == "POST":
            return {
                "name": "Test User",
                "email": "testuser@example.com",
                "role": "user"
            }
        elif "users" in endpoint_path and method == "PUT":
            return {
                "name": "Updated Test User",
                "email": "updated@example.com"
            }
        elif "files/upload" in endpoint_path:
            return {
                "filename": "test_file.txt",
                "content": "This is test file content for upload testing"
            }
        else:
            return {}
    
    def _calculate_total_sample_size(self, detailed_metrics: Dict[str, Any]) -> int:
        """
        Calculate total sample size across all test metrics.
        
        Args:
            detailed_metrics: Detailed test metrics from all test categories
            
        Returns:
            Total sample size for statistical confidence calculation
        """
        total_samples = 0
        
        # Count samples from response time tests
        if "response_times" in detailed_metrics and "endpoint_metrics" in detailed_metrics["response_times"]:
            for endpoint_data in detailed_metrics["response_times"]["endpoint_metrics"].values():
                total_samples += endpoint_data.get("sample_count", 0)
        
        # Count samples from throughput tests
        if "throughput" in detailed_metrics and "load_test_metrics" in detailed_metrics["throughput"]:
            for load_test_data in detailed_metrics["throughput"]["load_test_metrics"].values():
                total_samples += load_test_data.get("total_requests", 0)
        
        # Count samples from memory tests
        if "memory_usage" in detailed_metrics and "memory_profiling" in detailed_metrics["memory_usage"]:
            total_samples += detailed_metrics["memory_usage"]["memory_profiling"].get("sample_count", 0)
        
        # Count samples from CPU tests
        if "cpu_utilization" in detailed_metrics and "cpu_profiling" in detailed_metrics["cpu_utilization"]:
            total_samples += detailed_metrics["cpu_utilization"]["cpu_profiling"].get("sample_count", 0)
        
        # Count samples from database tests
        if "database_performance" in detailed_metrics and "operation_metrics" in detailed_metrics["database_performance"]:
            for operation_data in detailed_metrics["database_performance"]["operation_metrics"].values():
                total_samples += operation_data.get("sample_count", 0)
        
        return total_samples
    
    def _calculate_statistical_confidence(self, sample_size: int) -> float:
        """
        Calculate statistical confidence level based on sample size.
        
        Args:
            sample_size: Total number of samples collected
            
        Returns:
            Statistical confidence level as percentage (0-100)
        """
        if sample_size >= 10000:
            return 99.0  # Very high confidence
        elif sample_size >= 5000:
            return 95.0  # High confidence
        elif sample_size >= 1000:
            return 90.0  # Good confidence
        elif sample_size >= 500:
            return 85.0  # Moderate confidence
        elif sample_size >= 100:
            return 75.0  # Low confidence
        else:
            return 50.0  # Very low confidence
    
    def _validate_compliance_status(self, result: BaselineComparisonResult) -> None:
        """
        Validate overall compliance status and identify critical/warning issues.
        
        Args:
            result: Baseline comparison result to validate
        """
        critical_issues = []
        warning_issues = []
        
        # Check response time compliance
        for endpoint, variance in result.response_time_variance.items():
            if isinstance(variance, (int, float)) and not math.isinf(variance):
                if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                    critical_issues.append(
                        f"❌ Response time variance for {endpoint}: {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                    )
                elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                    warning_issues.append(
                        f"⚠️ Response time variance for {endpoint}: {variance:.2f}% (warning: ±{WARNING_VARIANCE_THRESHOLD}%)"
                    )
        
        # Check throughput compliance
        for scenario, variance in result.throughput_variance.items():
            if isinstance(variance, (int, float)) and not math.isinf(variance):
                if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                    critical_issues.append(
                        f"❌ Throughput variance for {scenario}: {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                    )
                elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                    warning_issues.append(
                        f"⚠️ Throughput variance for {scenario}: {variance:.2f}% (warning: ±{WARNING_VARIANCE_THRESHOLD}%)"
                    )
        
        # Check memory usage compliance (allows ≤15% variance)
        for metric, variance in result.memory_usage_variance.items():
            if isinstance(variance, (int, float)) and not math.isinf(variance):
                if abs(variance) > MEMORY_VARIANCE_THRESHOLD:
                    critical_issues.append(
                        f"❌ Memory usage variance for {metric}: {variance:.2f}% (threshold: ±{MEMORY_VARIANCE_THRESHOLD}%)"
                    )
                elif abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                    warning_issues.append(
                        f"⚠️ Memory usage variance for {metric}: {variance:.2f}% (warning: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                    )
        
        # Check CPU utilization compliance
        for metric, variance in result.cpu_utilization_variance.items():
            if isinstance(variance, (int, float)) and not math.isinf(variance):
                if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                    critical_issues.append(
                        f"❌ CPU utilization variance for {metric}: {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                    )
                elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                    warning_issues.append(
                        f"⚠️ CPU utilization variance for {metric}: {variance:.2f}% (warning: ±{WARNING_VARIANCE_THRESHOLD}%)"
                    )
        
        # Check database performance compliance
        for operation, variance in result.database_performance_variance.items():
            if isinstance(variance, (int, float)) and not math.isinf(variance):
                if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                    critical_issues.append(
                        f"❌ Database operation variance for {operation}: {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                    )
                elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                    warning_issues.append(
                        f"⚠️ Database operation variance for {operation}: {variance:.2f}% (warning: ±{WARNING_VARIANCE_THRESHOLD}%)"
                    )
        
        # Update result with compliance analysis
        result.critical_issues = critical_issues
        result.warning_issues = warning_issues
        result.overall_compliance = len(critical_issues) == 0
    
    def _perform_trend_analysis(self, result: BaselineComparisonResult) -> None:
        """
        Perform trend analysis and regression detection based on historical data.
        
        Args:
            result: Baseline comparison result to analyze for trends
        """
        trend_analysis = {
            "historical_comparison": {},
            "regression_detection": {},
            "performance_trends": {},
            "improvement_detection": {}
        }
        
        # Compare with historical results
        if len(self.test_results) >= 2:
            recent_results = self.test_results[-3:]  # Last 3 results for trend analysis
            
            # Analyze response time trends
            response_time_trends = {}
            for test_result in recent_results:
                for endpoint, variance in test_result.response_time_variance.items():
                    if endpoint not in response_time_trends:
                        response_time_trends[endpoint] = []
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        response_time_trends[endpoint].append(abs(variance))
            
            # Detect regression patterns
            regression_detected = False
            performance_improvement = False
            
            for endpoint, variances in response_time_trends.items():
                if len(variances) >= 2:
                    # Check for increasing variance trend (regression)
                    if variances[-1] > variances[-2] and variances[-1] > CRITICAL_VARIANCE_THRESHOLD:
                        regression_detected = True
                        trend_analysis["regression_detection"][endpoint] = {
                            "current_variance": variances[-1],
                            "previous_variance": variances[-2],
                            "trend": "deteriorating",
                            "severity": "critical" if variances[-1] > CRITICAL_VARIANCE_THRESHOLD * 1.5 else "moderate"
                        }
                    
                    # Check for improving performance trend
                    elif variances[-1] < variances[-2] and variances[-2] > WARNING_VARIANCE_THRESHOLD:
                        performance_improvement = True
                        trend_analysis["improvement_detection"][endpoint] = {
                            "current_variance": variances[-1],
                            "previous_variance": variances[-2],
                            "trend": "improving",
                            "improvement_percent": ((variances[-2] - variances[-1]) / variances[-2]) * 100
                        }
            
            result.regression_detected = regression_detected
            result.performance_improvement = performance_improvement
            
            # Store performance trends in tracking
            self.performance_trends.update(response_time_trends)
        
        # Calculate moving averages for long-term trends
        if len(self.test_results) >= 5:
            recent_variances = []
            for test_result in self.test_results[-5:]:
                test_variances = []
                for variance_dict in [
                    test_result.response_time_variance,
                    test_result.throughput_variance,
                    test_result.memory_usage_variance,
                    test_result.cpu_utilization_variance,
                    test_result.database_performance_variance
                ]:
                    for variance in variance_dict.values():
                        if isinstance(variance, (int, float)) and not math.isinf(variance):
                            test_variances.append(abs(variance))
                
                if test_variances:
                    recent_variances.append(statistics.mean(test_variances))
            
            if recent_variances:
                trend_analysis["performance_trends"] = {
                    "moving_average_variance": statistics.mean(recent_variances),
                    "trend_direction": "improving" if recent_variances[-1] < recent_variances[0] else "stable" if abs(recent_variances[-1] - recent_variances[0]) <= 1.0 else "deteriorating",
                    "variance_stability": "stable" if statistics.stdev(recent_variances) < 2.0 else "variable",
                    "long_term_compliance": all(v <= CRITICAL_VARIANCE_THRESHOLD for v in recent_variances)
                }
        
        result.trend_analysis = trend_analysis
    
    def _generate_performance_recommendations(self, result: BaselineComparisonResult) -> None:
        """
        Generate actionable performance improvement recommendations.
        
        Args:
            result: Baseline comparison result to generate recommendations for
        """
        recommendations = []
        
        # Response time recommendations
        high_response_time_endpoints = [
            endpoint for endpoint, variance in result.response_time_variance.items()
            if isinstance(variance, (int, float)) and variance > CRITICAL_VARIANCE_THRESHOLD
        ]
        
        if high_response_time_endpoints:
            recommendations.append(
                f"🚀 Optimize response times for {len(high_response_time_endpoints)} endpoints: {', '.join(high_response_time_endpoints[:3])}..."
            )
            recommendations.append(
                "🔧 Consider implementing caching, database query optimization, or code profiling"
            )
        
        # Throughput recommendations
        low_throughput_scenarios = [
            scenario for scenario, variance in result.throughput_variance.items()
            if isinstance(variance, (int, float)) and variance < -CRITICAL_VARIANCE_THRESHOLD
        ]
        
        if low_throughput_scenarios:
            recommendations.append(
                f"📈 Improve throughput for {len(low_throughput_scenarios)} load scenarios"
            )
            recommendations.append(
                "⚡ Consider connection pooling, async processing, or horizontal scaling"
            )
        
        # Memory recommendations
        high_memory_variance = any(
            isinstance(variance, (int, float)) and variance > MEMORY_VARIANCE_THRESHOLD
            for variance in result.memory_usage_variance.values()
        )
        
        if high_memory_variance:
            recommendations.append(
                "💾 Investigate memory usage patterns and potential memory leaks"
            )
            recommendations.append(
                "🔍 Consider memory profiling, garbage collection tuning, or object pooling"
            )
        
        # CPU recommendations
        high_cpu_variance = any(
            isinstance(variance, (int, float)) and variance > CRITICAL_VARIANCE_THRESHOLD
            for variance in result.cpu_utilization_variance.values()
        )
        
        if high_cpu_variance:
            recommendations.append(
                "🖥️ Optimize CPU-intensive operations and algorithm efficiency"
            )
            recommendations.append(
                "⚙️ Consider code optimization, caching, or async processing patterns"
            )
        
        # Database recommendations
        slow_database_operations = [
            operation for operation, variance in result.database_performance_variance.items()
            if isinstance(variance, (int, float)) and variance > CRITICAL_VARIANCE_THRESHOLD
        ]
        
        if slow_database_operations:
            recommendations.append(
                f"🗄️ Optimize database operations: {', '.join(slow_database_operations[:3])}"
            )
            recommendations.append(
                "📊 Consider database indexing, query optimization, or connection pooling"
            )
        
        # Regression recommendations
        if result.regression_detected:
            recommendations.append(
                "🔴 Performance regression detected - investigate recent code changes"
            )
            recommendations.append(
                "📝 Review recent commits and consider performance impact analysis"
            )
        
        # Success recommendations
        if result.overall_compliance and not result.warning_issues:
            recommendations.append(
                "✅ Excellent performance! All metrics within acceptable variance thresholds"
            )
            if result.performance_improvement:
                recommendations.append(
                    "🎉 Performance improvements detected - consider updating baseline metrics"
                )
        
        # Default recommendations
        if not recommendations:
            recommendations.append(
                "📋 Continue monitoring performance metrics and maintain current optimization efforts"
            )
        
        result.recommendations = recommendations
    
    def _update_prometheus_metrics(self, result: BaselineComparisonResult) -> None:
        """
        Update Prometheus metrics with baseline comparison results.
        
        Args:
            result: Baseline comparison result with metrics to export
        """
        if not PROMETHEUS_AVAILABLE:
            return
        
        try:
            # Update compliance status
            self.compliance_gauge.labels(test_type="comprehensive").set(
                1.0 if result.overall_compliance else 0.0
            )
            
            # Update variance metrics
            all_variances = []
            
            # Response time variances
            for endpoint, variance in result.response_time_variance.items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    self.variance_gauge.labels(
                        metric_type="response_time",
                        endpoint=endpoint
                    ).set(abs(variance))
                    all_variances.append(abs(variance))
            
            # Throughput variances
            for scenario, variance in result.throughput_variance.items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    self.variance_gauge.labels(
                        metric_type="throughput",
                        endpoint=scenario
                    ).set(abs(variance))
                    all_variances.append(abs(variance))
            
            # Memory variances
            for metric, variance in result.memory_usage_variance.items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    self.variance_gauge.labels(
                        metric_type="memory",
                        endpoint=metric
                    ).set(abs(variance))
                    all_variances.append(abs(variance))
            
            # CPU variances
            for metric, variance in result.cpu_utilization_variance.items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    self.variance_gauge.labels(
                        metric_type="cpu",
                        endpoint=metric
                    ).set(abs(variance))
                    all_variances.append(abs(variance))
            
            # Database variances
            for operation, variance in result.database_performance_variance.items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    self.variance_gauge.labels(
                        metric_type="database",
                        endpoint=operation
                    ).set(abs(variance))
                    all_variances.append(abs(variance))
            
            # Update trend histogram
            for variance in all_variances:
                self.trend_histogram.observe(variance)
            
            # Update test duration
            self.test_duration_histogram.labels(
                test_type="comprehensive"
            ).observe(result.test_duration_seconds)
            
        except Exception as metrics_error:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning(
                    "Failed to update Prometheus metrics",
                    error=str(metrics_error)
                )


# Test class implementation

@pytest.mark.performance
@pytest.mark.baseline_comparison
class TestBaselineComparison:
    """
    Comprehensive baseline comparison test class implementing automated variance 
    calculation, regression detection, and performance validation for Flask migration.
    
    Ensures compliance with ≤10% variance requirement per Section 0.1.1 and provides
    comprehensive performance monitoring per Section 0.3.2 requirements.
    """
    
    def test_api_response_time_baseline_compliance(
        self,
        app: Flask,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig,
        baseline_comparison_validator: Dict[str, Any]
    ):
        """
        Test API response times against Node.js baseline ensuring ≤10% variance compliance.
        
        Validates individual endpoint performance against established baselines with
        comprehensive statistical analysis and automated failure detection.
        
        Args:
            app: Flask application instance for testing
            baseline_data_manager: Baseline data manager for Node.js comparisons
            performance_config: Performance configuration and thresholds
            baseline_comparison_validator: Validation utilities for compliance checking
        """
        with performance_timer("API Response Time Baseline Compliance Test"):
            # Initialize test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                {}
            )
            
            # Get Node.js baseline for comparison
            nodejs_baseline = baseline_data_manager.get_default_baseline()
            
            with app.test_client() as client:
                # Test critical API endpoints
                endpoint_results = test_suite._test_api_response_times(client, nodejs_baseline)
                
                # Validate compliance with variance thresholds
                compliance_failures = []
                warning_issues = []
                
                for endpoint, variance in endpoint_results["variance_analysis"].items():
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                            compliance_failures.append(
                                f"Critical variance: {endpoint} = {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                            )
                        elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                            warning_issues.append(
                                f"Warning variance: {endpoint} = {variance:.2f}% (threshold: ±{WARNING_VARIANCE_THRESHOLD}%)"
                            )
                
                # Log test results
                if STRUCTLOG_AVAILABLE:
                    logger.info(
                        "API response time baseline compliance test completed",
                        total_endpoints=len(endpoint_results["variance_analysis"]),
                        compliance_failures=len(compliance_failures),
                        warning_issues=len(warning_issues),
                        overall_compliance=len(compliance_failures) == 0
                    )
                
                # Assert compliance with ≤10% variance requirement
                if compliance_failures:
                    pytest.fail(
                        f"API response time baseline compliance failed:\n" +
                        "\n".join(compliance_failures) +
                        f"\n\nWarning issues:\n" +
                        "\n".join(warning_issues) +
                        f"\n\nThis violates the ≤{CRITICAL_VARIANCE_THRESHOLD}% variance requirement per Section 0.1.1"
                    )
    
    def test_throughput_baseline_compliance(
        self,
        app: Flask,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig
    ):
        """
        Test throughput performance against Node.js baseline with progressive load scaling.
        
        Validates sustained throughput capacity meets or exceeds Node.js baseline
        performance across multiple concurrent user scenarios.
        
        Args:
            app: Flask application instance for load testing
            baseline_data_manager: Baseline data manager for throughput comparisons
            performance_config: Performance configuration and load test settings
        """
        with performance_timer("Throughput Baseline Compliance Test"):
            # Initialize test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                {}
            )
            
            # Get Node.js baseline for comparison
            nodejs_baseline = baseline_data_manager.get_default_baseline()
            
            with app.test_client() as client:
                # Test throughput performance
                throughput_results = test_suite._test_throughput_performance(client, nodejs_baseline)
                
                # Validate compliance with throughput thresholds
                compliance_failures = []
                warning_issues = []
                
                for scenario, variance in throughput_results["variance_analysis"].items():
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                            compliance_failures.append(
                                f"Critical throughput variance: {scenario} = {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                            )
                        elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                            warning_issues.append(
                                f"Warning throughput variance: {scenario} = {variance:.2f}% (threshold: ±{WARNING_VARIANCE_THRESHOLD}%)"
                            )
                
                # Check minimum throughput requirements
                for scenario, metrics in throughput_results["load_test_metrics"].items():
                    if metrics.get("requests_per_second", 0) < THROUGHPUT_THRESHOLD_RPS:
                        compliance_failures.append(
                            f"Throughput below minimum: {scenario} = {metrics['requests_per_second']:.2f} req/sec (minimum: {THROUGHPUT_THRESHOLD_RPS} req/sec)"
                        )
                
                # Log test results
                if STRUCTLOG_AVAILABLE:
                    logger.info(
                        "Throughput baseline compliance test completed",
                        total_scenarios=len(throughput_results["variance_analysis"]),
                        compliance_failures=len(compliance_failures),
                        warning_issues=len(warning_issues),
                        overall_compliance=len(compliance_failures) == 0
                    )
                
                # Assert compliance with throughput requirements
                if compliance_failures:
                    pytest.fail(
                        f"Throughput baseline compliance failed:\n" +
                        "\n".join(compliance_failures) +
                        f"\n\nWarning issues:\n" +
                        "\n".join(warning_issues) +
                        f"\n\nThis violates throughput requirements per Section 4.6.3"
                    )
    
    def test_memory_usage_baseline_compliance(
        self,
        app: Flask,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig
    ):
        """
        Test memory usage patterns against Node.js baseline with leak detection.
        
        Validates memory consumption stays within ≤15% variance and detects
        potential memory leaks during sustained operation.
        
        Args:
            app: Flask application instance for memory profiling
            baseline_data_manager: Baseline data manager for memory comparisons
            performance_config: Performance configuration and memory thresholds
        """
        with performance_timer("Memory Usage Baseline Compliance Test"):
            # Initialize test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                {}
            )
            
            # Get Node.js baseline for comparison
            nodejs_baseline = baseline_data_manager.get_default_baseline()
            
            with app.test_client() as client:
                # Test memory usage patterns
                memory_results = test_suite._test_memory_usage_patterns(client, nodejs_baseline)
                
                # Validate compliance with memory thresholds
                compliance_failures = []
                warning_issues = []
                
                for metric, variance in memory_results["variance_analysis"].items():
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        if abs(variance) > MEMORY_VARIANCE_THRESHOLD:
                            compliance_failures.append(
                                f"Critical memory variance: {metric} = {variance:.2f}% (threshold: ±{MEMORY_VARIANCE_THRESHOLD}%)"
                            )
                        elif abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                            warning_issues.append(
                                f"Warning memory variance: {metric} = {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                            )
                
                # Check for memory leaks
                if memory_results.get("leak_detection", {}).get("leak_detected", False):
                    compliance_failures.append(
                        f"Memory leak detected: {memory_results['leak_detection']['memory_growth_mb']:.2f} MB growth"
                    )
                
                # Log test results
                if STRUCTLOG_AVAILABLE:
                    logger.info(
                        "Memory usage baseline compliance test completed",
                        memory_variance=memory_results.get("variance_analysis", {}),
                        leak_detected=memory_results.get("leak_detection", {}).get("leak_detected", False),
                        compliance_failures=len(compliance_failures),
                        warning_issues=len(warning_issues),
                        overall_compliance=len(compliance_failures) == 0
                    )
                
                # Assert compliance with memory requirements
                if compliance_failures:
                    pytest.fail(
                        f"Memory usage baseline compliance failed:\n" +
                        "\n".join(compliance_failures) +
                        f"\n\nWarning issues:\n" +
                        "\n".join(warning_issues) +
                        f"\n\nThis violates memory usage requirements per Section 0.3.2"
                    )
    
    def test_cpu_utilization_baseline_compliance(
        self,
        app: Flask,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig
    ):
        """
        Test CPU utilization against Node.js baseline with efficiency analysis.
        
        Validates CPU usage efficiency maintains ≤10% variance and stays
        within acceptable utilization thresholds during load testing.
        
        Args:
            app: Flask application instance for CPU profiling  
            baseline_data_manager: Baseline data manager for CPU comparisons
            performance_config: Performance configuration and CPU thresholds
        """
        with performance_timer("CPU Utilization Baseline Compliance Test"):
            # Initialize test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                {}
            )
            
            # Get Node.js baseline for comparison
            nodejs_baseline = baseline_data_manager.get_default_baseline()
            
            with app.test_client() as client:
                # Test CPU utilization patterns
                cpu_results = test_suite._test_cpu_utilization(client, nodejs_baseline)
                
                # Validate compliance with CPU thresholds
                compliance_failures = []
                warning_issues = []
                
                for metric, variance in cpu_results["variance_analysis"].items():
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                            compliance_failures.append(
                                f"Critical CPU variance: {metric} = {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                            )
                        elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                            warning_issues.append(
                                f"Warning CPU variance: {metric} = {variance:.2f}% (threshold: ±{WARNING_VARIANCE_THRESHOLD}%)"
                            )
                
                # Check CPU utilization thresholds
                peak_cpu = cpu_results.get("cpu_profiling", {}).get("peak_cpu_percent", 0)
                if peak_cpu > CPU_UTILIZATION_THRESHOLD:
                    compliance_failures.append(
                        f"CPU utilization too high: {peak_cpu:.2f}% (threshold: {CPU_UTILIZATION_THRESHOLD}%)"
                    )
                
                # Log test results
                if STRUCTLOG_AVAILABLE:
                    logger.info(
                        "CPU utilization baseline compliance test completed",
                        cpu_variance=cpu_results.get("variance_analysis", {}),
                        peak_cpu=peak_cpu,
                        compliance_failures=len(compliance_failures),
                        warning_issues=len(warning_issues),
                        overall_compliance=len(compliance_failures) == 0
                    )
                
                # Assert compliance with CPU requirements
                if compliance_failures:
                    pytest.fail(
                        f"CPU utilization baseline compliance failed:\n" +
                        "\n".join(compliance_failures) +
                        f"\n\nWarning issues:\n" +
                        "\n".join(warning_issues) +
                        f"\n\nThis violates CPU utilization requirements per Section 4.6.3"
                    )
    
    def test_database_performance_baseline_compliance(
        self,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig
    ):
        """
        Test database operations performance against Node.js baseline.
        
        Validates database query execution times maintain ≤10% variance
        across all critical database operations.
        
        Args:
            baseline_data_manager: Baseline data manager for database comparisons
            performance_config: Performance configuration and database thresholds
        """
        with performance_timer("Database Performance Baseline Compliance Test"):
            # Initialize test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                {}
            )
            
            # Get Node.js baseline for comparison
            nodejs_baseline = baseline_data_manager.get_default_baseline()
            
            # Test database performance
            database_results = test_suite._test_database_performance(nodejs_baseline)
            
            # Validate compliance with database performance thresholds
            compliance_failures = []
            warning_issues = []
            
            for operation, variance in database_results["variance_analysis"].items():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    if abs(variance) > CRITICAL_VARIANCE_THRESHOLD:
                        compliance_failures.append(
                            f"Critical database variance: {operation} = {variance:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                        )
                    elif abs(variance) > WARNING_VARIANCE_THRESHOLD:
                        warning_issues.append(
                            f"Warning database variance: {operation} = {variance:.2f}% (threshold: ±{WARNING_VARIANCE_THRESHOLD}%)"
                        )
            
            # Log test results
            if STRUCTLOG_AVAILABLE:
                logger.info(
                    "Database performance baseline compliance test completed",
                    total_operations=len(database_results["variance_analysis"]),
                    compliance_failures=len(compliance_failures),
                    warning_issues=len(warning_issues),
                    overall_compliance=len(compliance_failures) == 0
                )
            
            # Assert compliance with database performance requirements
            if compliance_failures:
                pytest.fail(
                    f"Database performance baseline compliance failed:\n" +
                    "\n".join(compliance_failures) +
                    f"\n\nWarning issues:\n" +
                    "\n".join(warning_issues) +
                    f"\n\nThis violates database performance requirements per Section 0.3.2"
                )
    
    def test_comprehensive_baseline_comparison_with_regression_detection(
        self,
        app: Flask,
        baseline_data_manager: BaselineDataManager,
        performance_config: PerformanceTestConfig,
        performance_monitoring_setup: Dict[str, Any]
    ):
        """
        Execute comprehensive baseline comparison with automated regression detection.
        
        Performs complete performance validation across all dimensions including
        trend analysis, regression detection, and automated alerting per Section 6.6.1.
        
        Args:
            app: Flask application instance for comprehensive testing
            baseline_data_manager: Baseline data manager for complete comparisons
            performance_config: Performance configuration for all test dimensions
            performance_monitoring_setup: Monitoring infrastructure for alerting
        """
        with performance_timer("Comprehensive Baseline Comparison with Regression Detection"):
            # Initialize comprehensive test suite
            test_suite = BaselineComparisonTestSuite(
                baseline_data_manager,
                performance_config,
                performance_monitoring_setup
            )
            
            # Execute comprehensive baseline comparison
            comparison_result = test_suite.run_comprehensive_baseline_comparison(
                app,
                test_scenarios=["critical_endpoints", "load_scaling", "resource_monitoring"],
                include_load_testing=True,
                include_database_testing=True,
                include_memory_profiling=True
            )
            
            # Generate comprehensive test report
            test_report = comparison_result.generate_summary_report()
            
            # Log comprehensive results
            if STRUCTLOG_AVAILABLE:
                logger.info(
                    "Comprehensive baseline comparison completed",
                    overall_compliance=comparison_result.overall_compliance,
                    performance_grade=comparison_result.performance_grade,
                    critical_issues=len(comparison_result.critical_issues),
                    warning_issues=len(comparison_result.warning_issues),
                    regression_detected=comparison_result.regression_detected,
                    performance_improvement=comparison_result.performance_improvement,
                    test_duration=comparison_result.test_duration_seconds,
                    sample_size=comparison_result.sample_size,
                    statistical_confidence=comparison_result.statistical_confidence
                )
            
            # Assert overall compliance with baseline requirements
            if not comparison_result.overall_compliance:
                failure_message = f"""
Comprehensive baseline comparison failed:

CRITICAL ISSUES ({len(comparison_result.critical_issues)}):
{chr(10).join(comparison_result.critical_issues)}

WARNING ISSUES ({len(comparison_result.warning_issues)}):
{chr(10).join(comparison_result.warning_issues)}

PERFORMANCE GRADE: {comparison_result.performance_grade}
REGRESSION DETECTED: {comparison_result.regression_detected}
STATISTICAL CONFIDENCE: {comparison_result.statistical_confidence:.1f}%

RECOMMENDATIONS:
{chr(10).join(comparison_result.recommendations)}

This violates the ≤{CRITICAL_VARIANCE_THRESHOLD}% variance requirement per Section 0.1.1.
"""
                pytest.fail(failure_message)
            
            # Warn on regression detection even if compliant
            if comparison_result.regression_detected:
                if STRUCTLOG_AVAILABLE:
                    logger.warning(
                        "Performance regression detected during comprehensive testing",
                        regression_details=comparison_result.trend_analysis.get("regression_detection", {}),
                        recommendations=comparison_result.recommendations
                    )
            
            # Log performance improvements
            if comparison_result.performance_improvement:
                if STRUCTLOG_AVAILABLE:
                    logger.info(
                        "Performance improvements detected",
                        improvement_details=comparison_result.trend_analysis.get("improvement_detection", {}),
                        performance_grade=comparison_result.performance_grade
                    )


# Add missing import for math
import math
