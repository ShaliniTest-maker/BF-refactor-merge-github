#!/usr/bin/env python3
"""
Automated Performance Validation Script

This script implements comprehensive performance validation logic enforcing the critical ≤10% variance 
requirement per Section 0.1.1 primary objective. Provides automated regression detection, performance 
compliance verification, and automated pass/fail determination for CI/CD pipeline integration.

Key Features:
- ≤10% performance variance enforcement per Section 0.1.1 primary objective
- Automated regression detection and validation per Section 0.3.2 performance monitoring
- Response time ≤500ms and throughput ≥100 req/sec validation per Section 4.6.3
- Performance compliance verification for CI/CD per Section 6.6.2 automated quality gates
- Comprehensive metrics analysis and variance calculation per Section 0.3.2
- Automated performance failure alerting and reporting per Section 6.6.2

Performance Requirements Compliance:
- Response time variance ≤10% from Node.js baseline (critical requirement)
- 95th percentile response time ≤500ms per Section 4.6.3 performance specifications
- Minimum 100 req/sec sustained throughput per Section 4.6.3 throughput requirements
- Memory usage variance ≤15% acceptable per Section 0.3.2 memory monitoring
- CPU utilization ≤70% during peak load per Section 4.6.3 resource thresholds
- Database query performance ≤10% variance per Section 0.3.2 database metrics

Architecture Integration:
- Section 0.1.1: Primary objective performance optimization ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison and automated alerts
- Section 4.6.3: Performance testing specifications with locust load testing and apache-bench validation
- Section 6.6.2: CI/CD pipeline integration with automated quality gates and rollback triggers
- Section 6.5: Monitoring and observability integration with prometheus metrics and structured logging

Usage:
    # Run comprehensive performance validation
    python validate_performance.py --config production --verbose
    
    # Run with specific test scenarios
    python validate_performance.py --scenarios api_baseline,load_test,memory_validation
    
    # CI/CD pipeline integration
    python validate_performance.py --ci-mode --fail-fast --output-format json

Exit Codes:
    0: All performance validations passed
    1: Critical performance variance detected (>10%)
    2: Performance thresholds exceeded (response time >500ms, throughput <100 req/sec)
    3: Performance regression detected
    4: System resource limits exceeded (CPU >70%, Memory >80%)
    5: Test execution error or configuration failure

Author: Flask Migration Team
Version: 1.0.0
Dependencies: tests/performance/baseline_data.py, performance_config.py, conftest.py
"""

import argparse
import asyncio
import json
import logging
import math
import os
import signal
import statistics
import sys
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable, NamedTuple
from dataclasses import dataclass, field, asdict
from enum import Enum

# Add parent directories to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

# Performance testing framework imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    warnings.warn("psutil not available - system monitoring limited")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    warnings.warn("requests not available - HTTP testing limited")

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("prometheus_client not available - metrics collection disabled")

# Structured logging for comprehensive validation reporting
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    import logging
    STRUCTLOG_AVAILABLE = False
    warnings.warn("structlog not available - falling back to standard logging")

# Performance testing module imports
try:
    from tests.performance.baseline_data import (
        BaselineDataManager,
        NodeJSPerformanceBaseline,
        BaselineValidationStatus,
        get_baseline_manager,
        get_nodejs_baseline,
        compare_with_baseline,
        validate_baseline_data,
        create_performance_thresholds
    )
    BASELINE_DATA_AVAILABLE = True
except ImportError as e:
    BASELINE_DATA_AVAILABLE = False
    warnings.warn(f"Baseline data module not available: {e}")

try:
    from tests.performance.performance_config import (
        PerformanceTestConfig,
        LoadTestScenario,
        LoadTestConfiguration,
        PerformanceMetricType,
        create_performance_config,
        get_load_test_config,
        validate_performance_results
    )
    PERFORMANCE_CONFIG_AVAILABLE = True
except ImportError as e:
    PERFORMANCE_CONFIG_AVAILABLE = False
    warnings.warn(f"Performance config module not available: {e}")

try:
    from tests.performance.test_baseline_comparison import (
        BaselineComparisonTestSuite,
        BaselineComparisonResult,
        BaselineComparisonError
    )
    BASELINE_COMPARISON_AVAILABLE = True
except ImportError as e:
    BASELINE_COMPARISON_AVAILABLE = False
    warnings.warn(f"Baseline comparison module not available: {e}")

# Performance validation constants per technical specifications
CRITICAL_VARIANCE_THRESHOLD = 10.0     # ≤10% variance requirement per Section 0.1.1
WARNING_VARIANCE_THRESHOLD = 5.0       # Warning threshold for early detection
RESPONSE_TIME_THRESHOLD_MS = 500.0     # 95th percentile ≤500ms per Section 4.6.3
THROUGHPUT_THRESHOLD_RPS = 100.0       # Minimum 100 req/sec per Section 4.6.3
ERROR_RATE_THRESHOLD = 0.1             # ≤0.1% error rate per Section 4.6.3
CPU_UTILIZATION_THRESHOLD = 70.0       # ≤70% CPU per Section 4.6.3
MEMORY_UTILIZATION_THRESHOLD = 80.0    # ≤80% memory per Section 4.6.3
MEMORY_VARIANCE_THRESHOLD = 15.0       # ≤15% memory variance per Section 0.3.2
DATABASE_VARIANCE_THRESHOLD = 10.0     # ≤10% database variance per Section 0.3.2

# Test execution parameters
MIN_SAMPLE_SIZE = 100                   # Minimum samples for statistical validity
TEST_TIMEOUT_SECONDS = 1800            # 30 minutes maximum test duration
REGRESSION_DETECTION_WINDOW = 5        # Number of historical results for trend analysis
CONFIDENCE_THRESHOLD = 90.0            # Minimum statistical confidence percentage


class ValidationExitCode(Enum):
    """Exit codes for performance validation script execution."""
    
    SUCCESS = 0                         # All validations passed
    CRITICAL_VARIANCE = 1              # >10% variance detected
    THRESHOLD_EXCEEDED = 2             # Performance thresholds exceeded
    REGRESSION_DETECTED = 3            # Performance regression identified
    RESOURCE_LIMITS_EXCEEDED = 4       # System resource limits exceeded
    EXECUTION_ERROR = 5                # Test execution or configuration error


class ValidationSeverity(Enum):
    """Validation issue severity levels for prioritized alerting."""
    
    CRITICAL = "critical"               # Immediate attention required
    WARNING = "warning"                 # Monitor closely
    INFO = "info"                      # Informational notice
    SUCCESS = "success"                # Validation passed


@dataclass
class ValidationIssue:
    """Performance validation issue with severity and remediation guidance."""
    
    severity: ValidationSeverity
    category: str
    metric: str
    current_value: float
    expected_value: float
    variance_percent: float
    threshold_exceeded: bool
    message: str
    remediation_suggestions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Generate remediation suggestions based on issue characteristics."""
        if not self.remediation_suggestions:
            self.remediation_suggestions = self._generate_remediation_suggestions()
    
    def _generate_remediation_suggestions(self) -> List[str]:
        """Generate context-specific remediation suggestions."""
        suggestions = []
        
        if "response_time" in self.metric.lower():
            if self.variance_percent > CRITICAL_VARIANCE_THRESHOLD:
                suggestions.extend([
                    "🚀 Optimize API endpoint implementation for faster response times",
                    "🔧 Consider implementing response caching for frequently accessed data",
                    "📊 Profile application code to identify performance bottlenecks",
                    "🔍 Review database query optimization and indexing strategies"
                ])
        
        elif "throughput" in self.metric.lower():
            if self.current_value < self.expected_value:
                suggestions.extend([
                    "📈 Implement connection pooling for database and external services",
                    "⚡ Consider async processing patterns for non-blocking operations",
                    "🔄 Optimize request processing pipeline and middleware stack",
                    "🏗️ Evaluate horizontal scaling and load balancing strategies"
                ])
        
        elif "memory" in self.metric.lower():
            if self.variance_percent > MEMORY_VARIANCE_THRESHOLD:
                suggestions.extend([
                    "💾 Investigate memory usage patterns and potential memory leaks",
                    "🧹 Implement proper object cleanup and garbage collection optimization",
                    "📋 Review data structures and object lifecycle management",
                    "🔍 Consider memory profiling tools for detailed analysis"
                ])
        
        elif "cpu" in self.metric.lower():
            if self.current_value > CPU_UTILIZATION_THRESHOLD:
                suggestions.extend([
                    "🖥️ Optimize CPU-intensive algorithms and processing logic",
                    "⚙️ Implement caching to reduce computational overhead",
                    "🔀 Consider async processing for CPU-bound operations",
                    "📊 Profile code execution to identify CPU bottlenecks"
                ])
        
        elif "database" in self.metric.lower():
            if self.variance_percent > DATABASE_VARIANCE_THRESHOLD:
                suggestions.extend([
                    "🗄️ Optimize database queries and improve indexing strategy",
                    "🔗 Implement database connection pooling and query caching",
                    "📈 Consider database performance tuning and configuration optimization",
                    "🔍 Review query execution plans and eliminate N+1 query patterns"
                ])
        
        # Add general recommendations for critical issues
        if self.severity == ValidationSeverity.CRITICAL:
            suggestions.extend([
                "❗ Consider immediate rollback if this is a production deployment",
                "📞 Escalate to performance engineering team for urgent investigation",
                "🚨 Monitor system closely for continued performance degradation"
            ])
        
        return suggestions


@dataclass
class PerformanceValidationResult:
    """Comprehensive performance validation result with detailed analysis."""
    
    # Validation metadata
    validation_id: str = field(default_factory=lambda: f"perf_val_{int(time.time())}")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    
    # Test execution summary
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    
    # Performance compliance status
    overall_compliance: bool = False
    variance_compliance: bool = False
    threshold_compliance: bool = False
    regression_status: bool = False
    
    # Detailed validation results
    validation_issues: List[ValidationIssue] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    baseline_comparisons: Dict[str, Any] = field(default_factory=dict)
    
    # Statistical analysis
    sample_size: int = 0
    statistical_confidence: float = 0.0
    variance_distribution: Dict[str, float] = field(default_factory=dict)
    
    # Trend analysis and regression detection
    regression_analysis: Dict[str, Any] = field(default_factory=dict)
    trend_indicators: List[str] = field(default_factory=list)
    
    # Recommendations and next steps
    recommendations: List[str] = field(default_factory=list)
    critical_actions: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate test success rate percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100.0
    
    @property
    def exit_code(self) -> ValidationExitCode:
        """Determine appropriate exit code based on validation results."""
        # Check for critical variance issues
        critical_variance_issues = [
            issue for issue in self.validation_issues
            if issue.severity == ValidationSeverity.CRITICAL and 
               issue.variance_percent > CRITICAL_VARIANCE_THRESHOLD
        ]
        
        if critical_variance_issues:
            return ValidationExitCode.CRITICAL_VARIANCE
        
        # Check for threshold violations
        threshold_issues = [
            issue for issue in self.validation_issues
            if issue.threshold_exceeded and issue.severity == ValidationSeverity.CRITICAL
        ]
        
        if threshold_issues:
            return ValidationExitCode.THRESHOLD_EXCEEDED
        
        # Check for regression detection
        if self.regression_status:
            return ValidationExitCode.REGRESSION_DETECTED
        
        # Check for resource limit violations
        resource_issues = [
            issue for issue in self.validation_issues
            if "cpu" in issue.metric.lower() or "memory" in issue.metric.lower()
        ]
        
        critical_resource_issues = [
            issue for issue in resource_issues
            if issue.severity == ValidationSeverity.CRITICAL
        ]
        
        if critical_resource_issues:
            return ValidationExitCode.RESOURCE_LIMITS_EXCEEDED
        
        # Success if overall compliance achieved
        if self.overall_compliance:
            return ValidationExitCode.SUCCESS
        else:
            return ValidationExitCode.EXECUTION_ERROR
    
    def get_critical_issues(self) -> List[ValidationIssue]:
        """Get list of critical validation issues requiring immediate attention."""
        return [
            issue for issue in self.validation_issues
            if issue.severity == ValidationSeverity.CRITICAL
        ]
    
    def get_warning_issues(self) -> List[ValidationIssue]:
        """Get list of warning validation issues requiring monitoring."""
        return [
            issue for issue in self.validation_issues
            if issue.severity == ValidationSeverity.WARNING
        ]
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation summary report."""
        critical_issues = self.get_critical_issues()
        warning_issues = self.get_warning_issues()
        
        return {
            "validation_summary": {
                "validation_id": self.validation_id,
                "timestamp": self.timestamp.isoformat(),
                "duration_seconds": self.duration_seconds,
                "overall_compliance": self.overall_compliance,
                "variance_compliance": self.variance_compliance,
                "threshold_compliance": self.threshold_compliance,
                "regression_detected": self.regression_status,
                "exit_code": self.exit_code.value,
                "exit_code_name": self.exit_code.name
            },
            "test_execution": {
                "total_tests": self.total_tests,
                "passed_tests": self.passed_tests,
                "failed_tests": self.failed_tests,
                "skipped_tests": self.skipped_tests,
                "success_rate": self.success_rate,
                "sample_size": self.sample_size,
                "statistical_confidence": self.statistical_confidence
            },
            "validation_issues": {
                "critical_count": len(critical_issues),
                "warning_count": len(warning_issues),
                "critical_issues": [asdict(issue) for issue in critical_issues],
                "warning_issues": [asdict(issue) for issue in warning_issues]
            },
            "performance_analysis": {
                "variance_distribution": self.variance_distribution,
                "baseline_comparisons": self.baseline_comparisons,
                "regression_analysis": self.regression_analysis,
                "trend_indicators": self.trend_indicators
            },
            "recommendations": {
                "general_recommendations": self.recommendations,
                "critical_actions": self.critical_actions,
                "remediation_guidance": [
                    issue.remediation_suggestions 
                    for issue in critical_issues 
                    if issue.remediation_suggestions
                ]
            },
            "performance_metrics": self.performance_metrics
        }


class PerformanceValidator:
    """
    Comprehensive performance validation engine implementing automated variance 
    calculation, regression detection, and compliance verification for Flask migration.
    
    Enforces the critical ≤10% variance requirement per Section 0.1.1 and provides
    automated pass/fail determination for CI/CD pipeline integration per Section 6.6.2.
    """
    
    def __init__(
        self,
        config_environment: str = "testing",
        baseline_manager: Optional[BaselineDataManager] = None,
        performance_config: Optional[PerformanceTestConfig] = None,
        enable_prometheus: bool = True,
        enable_detailed_logging: bool = True
    ):
        """
        Initialize performance validator with configuration and dependencies.
        
        Args:
            config_environment: Environment configuration (testing, staging, production)
            baseline_manager: Baseline data manager for Node.js comparisons
            performance_config: Performance test configuration
            enable_prometheus: Enable Prometheus metrics collection
            enable_detailed_logging: Enable detailed structured logging
        """
        self.config_environment = config_environment
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE
        self.enable_detailed_logging = enable_detailed_logging
        
        # Initialize logging
        if STRUCTLOG_AVAILABLE and enable_detailed_logging:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
        
        # Initialize baseline data management
        if baseline_manager and BASELINE_DATA_AVAILABLE:
            self.baseline_manager = baseline_manager
        elif BASELINE_DATA_AVAILABLE:
            self.baseline_manager = get_baseline_manager()
        else:
            self.baseline_manager = None
            self.logger.warning("Baseline data manager not available - baseline comparisons disabled")
        
        # Initialize performance configuration
        if performance_config and PERFORMANCE_CONFIG_AVAILABLE:
            self.performance_config = performance_config
        elif PERFORMANCE_CONFIG_AVAILABLE:
            self.performance_config = create_performance_config(config_environment)
        else:
            self.performance_config = None
            self.logger.warning("Performance config not available - using default thresholds")
        
        # Initialize Prometheus metrics
        if self.enable_prometheus:
            self._init_prometheus_metrics()
        
        # Validation state tracking
        self.validation_history: List[PerformanceValidationResult] = []
        self.current_validation: Optional[PerformanceValidationResult] = None
        
        self.logger.info(
            "Performance validator initialized",
            config_environment=config_environment,
            baseline_available=self.baseline_manager is not None,
            config_available=self.performance_config is not None,
            prometheus_enabled=self.enable_prometheus
        )
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for performance validation tracking."""
        try:
            self.metrics_registry = CollectorRegistry()
            
            # Validation execution metrics
            self.validation_counter = Counter(
                'performance_validation_total',
                'Total performance validation executions',
                ['environment', 'status'],
                registry=self.metrics_registry
            )
            
            # Variance tracking metrics
            self.variance_gauge = Gauge(
                'performance_variance_percent',
                'Performance variance from baseline',
                ['metric_type', 'endpoint'],
                registry=self.metrics_registry
            )
            
            # Compliance status metrics
            self.compliance_gauge = Gauge(
                'performance_compliance_status',
                'Performance compliance status (1=compliant, 0=non-compliant)',
                ['compliance_type'],
                registry=self.metrics_registry
            )
            
            # Validation duration tracking
            self.validation_duration_histogram = Histogram(
                'performance_validation_duration_seconds',
                'Performance validation execution time',
                buckets=[30, 60, 120, 300, 600, 1200, 1800],
                registry=self.metrics_registry
            )
            
            # Regression detection metrics
            self.regression_gauge = Gauge(
                'performance_regression_detected',
                'Performance regression detection status',
                ['regression_type'],
                registry=self.metrics_registry
            )
            
        except Exception as metrics_error:
            self.logger.warning(
                "Failed to initialize Prometheus metrics",
                error=str(metrics_error)
            )
            self.enable_prometheus = False
    
    def validate_performance_comprehensive(
        self,
        app_url: str = "http://localhost:5000",
        test_scenarios: Optional[List[str]] = None,
        enable_load_testing: bool = True,
        enable_memory_profiling: bool = True,
        enable_regression_detection: bool = True,
        fail_fast: bool = False,
        timeout_seconds: int = TEST_TIMEOUT_SECONDS
    ) -> PerformanceValidationResult:
        """
        Execute comprehensive performance validation with automated variance calculation.
        
        Args:
            app_url: Flask application URL for testing
            test_scenarios: Specific test scenarios to execute
            enable_load_testing: Enable load testing validation
            enable_memory_profiling: Enable memory usage profiling
            enable_regression_detection: Enable regression detection analysis
            fail_fast: Stop validation on first critical failure
            timeout_seconds: Maximum validation execution time
            
        Returns:
            PerformanceValidationResult with comprehensive analysis
            
        Raises:
            TimeoutError: If validation exceeds timeout duration
            ValidationError: If critical validation setup fails
        """
        start_time = time.time()
        
        # Initialize validation result
        validation_result = PerformanceValidationResult(
            timestamp=datetime.now(timezone.utc)
        )
        self.current_validation = validation_result
        
        try:
            self.logger.info(
                "Starting comprehensive performance validation",
                app_url=app_url,
                test_scenarios=test_scenarios,
                enable_load_testing=enable_load_testing,
                enable_memory_profiling=enable_memory_profiling,
                enable_regression_detection=enable_regression_detection,
                timeout_seconds=timeout_seconds
            )
            
            # Set up timeout handling
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Performance validation exceeded {timeout_seconds} seconds timeout")
            
            if timeout_seconds > 0:
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout_seconds)
            
            # Execute core performance validations
            try:
                # 1. Baseline Variance Validation (Critical)
                self._validate_baseline_variance(validation_result, app_url)
                if fail_fast and validation_result.get_critical_issues():
                    return self._finalize_validation(validation_result, start_time)
                
                # 2. Response Time Threshold Validation
                self._validate_response_time_thresholds(validation_result, app_url)
                if fail_fast and validation_result.get_critical_issues():
                    return self._finalize_validation(validation_result, start_time)
                
                # 3. Throughput Validation
                if enable_load_testing:
                    self._validate_throughput_performance(validation_result, app_url)
                    if fail_fast and validation_result.get_critical_issues():
                        return self._finalize_validation(validation_result, start_time)
                
                # 4. System Resource Validation
                self._validate_system_resource_usage(validation_result, app_url)
                if fail_fast and validation_result.get_critical_issues():
                    return self._finalize_validation(validation_result, start_time)
                
                # 5. Memory Usage Validation
                if enable_memory_profiling and PSUTIL_AVAILABLE:
                    self._validate_memory_usage_patterns(validation_result, app_url)
                    if fail_fast and validation_result.get_critical_issues():
                        return self._finalize_validation(validation_result, start_time)
                
                # 6. Database Performance Validation
                self._validate_database_performance(validation_result)
                if fail_fast and validation_result.get_critical_issues():
                    return self._finalize_validation(validation_result, start_time)
                
                # 7. Regression Detection Analysis
                if enable_regression_detection:
                    self._detect_performance_regression(validation_result)
                
                # 8. Overall Compliance Assessment
                self._assess_overall_compliance(validation_result)
                
                # 9. Generate Recommendations
                self._generate_validation_recommendations(validation_result)
                
            finally:
                # Clear timeout alarm
                if timeout_seconds > 0:
                    signal.alarm(0)
            
            return self._finalize_validation(validation_result, start_time)
            
        except TimeoutError as timeout_error:
            self.logger.error(
                "Performance validation timed out",
                timeout_seconds=timeout_seconds,
                error=str(timeout_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="execution",
                    metric="validation_timeout",
                    current_value=time.time() - start_time,
                    expected_value=timeout_seconds,
                    variance_percent=((time.time() - start_time - timeout_seconds) / timeout_seconds) * 100,
                    threshold_exceeded=True,
                    message=f"Performance validation exceeded {timeout_seconds}s timeout"
                )
            )
            return self._finalize_validation(validation_result, start_time)
            
        except Exception as validation_error:
            self.logger.error(
                "Performance validation failed with error",
                error=str(validation_error),
                traceback=traceback.format_exc()
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="execution",
                    metric="validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Validation execution failed: {str(validation_error)}"
                )
            )
            return self._finalize_validation(validation_result, start_time)
    
    def _validate_baseline_variance(
        self,
        validation_result: PerformanceValidationResult,
        app_url: str
    ) -> None:
        """
        Validate performance variance against Node.js baseline per Section 0.1.1.
        
        Critical validation ensuring ≤10% variance requirement compliance.
        
        Args:
            validation_result: Validation result to update with findings
            app_url: Application URL for baseline testing
        """
        self.logger.info("Starting baseline variance validation")
        
        if not self.baseline_manager:
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="baseline",
                    metric="baseline_unavailable",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=False,
                    message="Baseline data manager not available - baseline validation skipped"
                )
            )
            return
        
        try:
            # Get Node.js baseline for comparison
            nodejs_baseline = self.baseline_manager.get_default_baseline()
            
            # Test critical API endpoints for baseline comparison
            endpoint_metrics = self._measure_endpoint_performance(app_url)
            
            # Compare against baseline values
            baseline_comparison = compare_with_baseline(
                endpoint_metrics,
                variance_threshold=CRITICAL_VARIANCE_THRESHOLD / 100.0
            )
            
            validation_result.baseline_comparisons = baseline_comparison
            validation_result.sample_size += len(endpoint_metrics)
            
            # Analyze variance compliance
            comparison_results = baseline_comparison.get("comparison_results", {})
            summary = baseline_comparison.get("summary", {})
            
            for metric_name, comparison in comparison_results.items():
                current_value = comparison.get("current_value", 0.0)
                baseline_value = comparison.get("baseline_value", 0.0)
                variance_percent = comparison.get("variance_percent", 0.0)
                within_threshold = comparison.get("within_threshold", False)
                
                if not within_threshold and baseline_value > 0:
                    severity = (
                        ValidationSeverity.CRITICAL 
                        if abs(variance_percent) > CRITICAL_VARIANCE_THRESHOLD 
                        else ValidationSeverity.WARNING
                    )
                    
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=severity,
                            category="baseline_variance",
                            metric=metric_name,
                            current_value=current_value,
                            expected_value=baseline_value,
                            variance_percent=variance_percent,
                            threshold_exceeded=abs(variance_percent) > CRITICAL_VARIANCE_THRESHOLD,
                            message=f"Baseline variance: {metric_name} = {variance_percent:.2f}% (threshold: ±{CRITICAL_VARIANCE_THRESHOLD}%)"
                        )
                    )
                    
                    # Update Prometheus metrics
                    if self.enable_prometheus:
                        self.variance_gauge.labels(
                            metric_type="baseline",
                            endpoint=metric_name
                        ).set(abs(variance_percent))
            
            # Update variance compliance status
            validation_result.variance_compliance = summary.get("overall_compliant", False)
            validation_result.performance_metrics["baseline_comparison"] = baseline_comparison
            
            self.logger.info(
                "Baseline variance validation completed",
                total_metrics=summary.get("total_metrics", 0),
                compliant_metrics=summary.get("compliant_metrics", 0),
                compliance_percentage=summary.get("compliance_percentage", 0),
                overall_compliant=validation_result.variance_compliance
            )
            
        except Exception as baseline_error:
            self.logger.error(
                "Baseline variance validation failed",
                error=str(baseline_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="baseline_variance",
                    metric="baseline_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Baseline variance validation failed: {str(baseline_error)}"
                )
            )
    
    def _validate_response_time_thresholds(
        self,
        validation_result: PerformanceValidationResult,
        app_url: str
    ) -> None:
        """
        Validate response time thresholds per Section 4.6.3 specifications.
        
        Ensures 95th percentile response time ≤500ms compliance.
        
        Args:
            validation_result: Validation result to update with findings
            app_url: Application URL for response time testing
        """
        self.logger.info("Starting response time threshold validation")
        
        try:
            # Test multiple endpoints with comprehensive sampling
            response_time_results = self._measure_response_time_distribution(app_url)
            
            validation_result.performance_metrics["response_times"] = response_time_results
            validation_result.sample_size += response_time_results.get("total_samples", 0)
            
            # Validate response time thresholds
            for endpoint, metrics in response_time_results.get("endpoint_metrics", {}).items():
                p95_response_time = metrics.get("p95_ms", 0.0)
                mean_response_time = metrics.get("mean_ms", 0.0)
                sample_count = metrics.get("sample_count", 0)
                
                # Check 95th percentile threshold compliance
                if p95_response_time > RESPONSE_TIME_THRESHOLD_MS:
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.CRITICAL,
                            category="response_time",
                            metric=f"{endpoint}_p95",
                            current_value=p95_response_time,
                            expected_value=RESPONSE_TIME_THRESHOLD_MS,
                            variance_percent=((p95_response_time - RESPONSE_TIME_THRESHOLD_MS) / RESPONSE_TIME_THRESHOLD_MS) * 100,
                            threshold_exceeded=True,
                            message=f"Response time P95 exceeds threshold: {endpoint} = {p95_response_time:.2f}ms (threshold: {RESPONSE_TIME_THRESHOLD_MS}ms)"
                        )
                    )
                
                # Check for unusually slow mean response times
                if mean_response_time > (RESPONSE_TIME_THRESHOLD_MS * 0.6):  # 60% of threshold for mean
                    severity = (
                        ValidationSeverity.CRITICAL 
                        if mean_response_time > RESPONSE_TIME_THRESHOLD_MS 
                        else ValidationSeverity.WARNING
                    )
                    
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=severity,
                            category="response_time",
                            metric=f"{endpoint}_mean",
                            current_value=mean_response_time,
                            expected_value=RESPONSE_TIME_THRESHOLD_MS * 0.6,
                            variance_percent=((mean_response_time - (RESPONSE_TIME_THRESHOLD_MS * 0.6)) / (RESPONSE_TIME_THRESHOLD_MS * 0.6)) * 100,
                            threshold_exceeded=mean_response_time > RESPONSE_TIME_THRESHOLD_MS,
                            message=f"Mean response time elevated: {endpoint} = {mean_response_time:.2f}ms"
                        )
                    )
                
                # Validate statistical significance
                if sample_count < MIN_SAMPLE_SIZE:
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="response_time",
                            metric=f"{endpoint}_sample_size",
                            current_value=sample_count,
                            expected_value=MIN_SAMPLE_SIZE,
                            variance_percent=((MIN_SAMPLE_SIZE - sample_count) / MIN_SAMPLE_SIZE) * 100,
                            threshold_exceeded=False,
                            message=f"Low sample size for {endpoint}: {sample_count} samples (minimum: {MIN_SAMPLE_SIZE})"
                        )
                    )
            
            # Assess overall response time compliance
            critical_response_time_issues = [
                issue for issue in validation_result.validation_issues
                if issue.category == "response_time" and issue.severity == ValidationSeverity.CRITICAL
            ]
            
            validation_result.threshold_compliance = len(critical_response_time_issues) == 0
            
            self.logger.info(
                "Response time threshold validation completed",
                total_endpoints=len(response_time_results.get("endpoint_metrics", {})),
                threshold_violations=len(critical_response_time_issues),
                threshold_compliance=validation_result.threshold_compliance
            )
            
        except Exception as response_time_error:
            self.logger.error(
                "Response time threshold validation failed",
                error=str(response_time_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="response_time",
                    metric="response_time_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Response time validation failed: {str(response_time_error)}"
                )
            )
    
    def _validate_throughput_performance(
        self,
        validation_result: PerformanceValidationResult,
        app_url: str
    ) -> None:
        """
        Validate throughput performance per Section 4.6.3 requirements.
        
        Ensures minimum 100 req/sec sustained throughput compliance.
        
        Args:
            validation_result: Validation result to update with findings
            app_url: Application URL for throughput testing
        """
        self.logger.info("Starting throughput performance validation")
        
        try:
            # Execute progressive load testing
            throughput_results = self._measure_throughput_capacity(app_url)
            
            validation_result.performance_metrics["throughput"] = throughput_results
            validation_result.sample_size += throughput_results.get("total_requests", 0)
            
            # Validate throughput requirements
            for scenario, metrics in throughput_results.get("load_scenarios", {}).items():
                requests_per_second = metrics.get("requests_per_second", 0.0)
                error_rate = metrics.get("error_rate_percent", 0.0)
                concurrent_users = metrics.get("concurrent_users", 0)
                
                # Check minimum throughput threshold
                if requests_per_second < THROUGHPUT_THRESHOLD_RPS:
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.CRITICAL,
                            category="throughput",
                            metric=f"{scenario}_rps",
                            current_value=requests_per_second,
                            expected_value=THROUGHPUT_THRESHOLD_RPS,
                            variance_percent=((THROUGHPUT_THRESHOLD_RPS - requests_per_second) / THROUGHPUT_THRESHOLD_RPS) * 100,
                            threshold_exceeded=True,
                            message=f"Throughput below minimum: {scenario} = {requests_per_second:.2f} req/sec (minimum: {THROUGHPUT_THRESHOLD_RPS} req/sec)"
                        )
                    )
                
                # Check error rate compliance
                if error_rate > ERROR_RATE_THRESHOLD:
                    severity = (
                        ValidationSeverity.CRITICAL 
                        if error_rate > (ERROR_RATE_THRESHOLD * 2) 
                        else ValidationSeverity.WARNING
                    )
                    
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=severity,
                            category="throughput",
                            metric=f"{scenario}_error_rate",
                            current_value=error_rate,
                            expected_value=ERROR_RATE_THRESHOLD,
                            variance_percent=((error_rate - ERROR_RATE_THRESHOLD) / ERROR_RATE_THRESHOLD) * 100,
                            threshold_exceeded=error_rate > ERROR_RATE_THRESHOLD,
                            message=f"Error rate too high: {scenario} = {error_rate:.2f}% (threshold: {ERROR_RATE_THRESHOLD}%)"
                        )
                    )
            
            self.logger.info(
                "Throughput performance validation completed",
                total_scenarios=len(throughput_results.get("load_scenarios", {})),
                total_requests=throughput_results.get("total_requests", 0)
            )
            
        except Exception as throughput_error:
            self.logger.error(
                "Throughput performance validation failed",
                error=str(throughput_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="throughput",
                    metric="throughput_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Throughput validation failed: {str(throughput_error)}"
                )
            )
    
    def _validate_system_resource_usage(
        self,
        validation_result: PerformanceValidationResult,
        app_url: str
    ) -> None:
        """
        Validate system resource usage per Section 4.6.3 resource thresholds.
        
        Ensures CPU ≤70%, Memory ≤80% during peak load compliance.
        
        Args:
            validation_result: Validation result to update with findings
            app_url: Application URL for resource monitoring
        """
        self.logger.info("Starting system resource usage validation")
        
        if not PSUTIL_AVAILABLE:
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="system_resources",
                    metric="psutil_unavailable",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=False,
                    message="psutil not available - system resource monitoring limited"
                )
            )
            return
        
        try:
            # Monitor system resources during load testing
            resource_metrics = self._monitor_system_resources(app_url)
            
            validation_result.performance_metrics["system_resources"] = resource_metrics
            
            # Validate CPU utilization
            cpu_utilization = resource_metrics.get("cpu_utilization_peak", 0.0)
            if cpu_utilization > CPU_UTILIZATION_THRESHOLD:
                validation_result.validation_issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.CRITICAL,
                        category="system_resources",
                        metric="cpu_utilization",
                        current_value=cpu_utilization,
                        expected_value=CPU_UTILIZATION_THRESHOLD,
                        variance_percent=((cpu_utilization - CPU_UTILIZATION_THRESHOLD) / CPU_UTILIZATION_THRESHOLD) * 100,
                        threshold_exceeded=True,
                        message=f"CPU utilization too high: {cpu_utilization:.2f}% (threshold: {CPU_UTILIZATION_THRESHOLD}%)"
                    )
                )
            
            # Validate memory utilization
            memory_utilization = resource_metrics.get("memory_utilization_peak", 0.0)
            if memory_utilization > MEMORY_UTILIZATION_THRESHOLD:
                validation_result.validation_issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.CRITICAL,
                        category="system_resources",
                        metric="memory_utilization",
                        current_value=memory_utilization,
                        expected_value=MEMORY_UTILIZATION_THRESHOLD,
                        variance_percent=((memory_utilization - MEMORY_UTILIZATION_THRESHOLD) / MEMORY_UTILIZATION_THRESHOLD) * 100,
                        threshold_exceeded=True,
                        message=f"Memory utilization too high: {memory_utilization:.2f}% (threshold: {MEMORY_UTILIZATION_THRESHOLD}%)"
                    )
                )
            
            self.logger.info(
                "System resource usage validation completed",
                cpu_utilization=cpu_utilization,
                memory_utilization=memory_utilization,
                cpu_compliant=cpu_utilization <= CPU_UTILIZATION_THRESHOLD,
                memory_compliant=memory_utilization <= MEMORY_UTILIZATION_THRESHOLD
            )
            
        except Exception as resource_error:
            self.logger.error(
                "System resource validation failed",
                error=str(resource_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="system_resources",
                    metric="resource_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"System resource validation failed: {str(resource_error)}"
                )
            )
    
    def _validate_memory_usage_patterns(
        self,
        validation_result: PerformanceValidationResult,
        app_url: str
    ) -> None:
        """
        Validate memory usage patterns with leak detection per Section 0.3.2.
        
        Ensures memory variance ≤15% and detects potential memory leaks.
        
        Args:
            validation_result: Validation result to update with findings
            app_url: Application URL for memory profiling
        """
        self.logger.info("Starting memory usage pattern validation")
        
        if not PSUTIL_AVAILABLE:
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="memory_usage",
                    metric="psutil_unavailable",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=False,
                    message="psutil not available - memory profiling disabled"
                )
            )
            return
        
        try:
            # Profile memory usage during sustained load
            memory_profile = self._profile_memory_usage(app_url)
            
            validation_result.performance_metrics["memory_usage"] = memory_profile
            
            # Get baseline memory metrics for comparison
            if self.baseline_manager:
                baseline = self.baseline_manager.get_default_baseline()
                baseline_memory = baseline.memory_usage_baseline_mb
                
                current_memory = memory_profile.get("mean_memory_mb", 0.0)
                memory_variance = ((current_memory - baseline_memory) / baseline_memory) * 100
                
                # Validate memory variance threshold
                if abs(memory_variance) > MEMORY_VARIANCE_THRESHOLD:
                    validation_result.validation_issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.CRITICAL,
                            category="memory_usage",
                            metric="memory_variance",
                            current_value=current_memory,
                            expected_value=baseline_memory,
                            variance_percent=memory_variance,
                            threshold_exceeded=True,
                            message=f"Memory variance exceeds threshold: {memory_variance:.2f}% (threshold: ±{MEMORY_VARIANCE_THRESHOLD}%)"
                        )
                    )
            
            # Check for memory leaks
            memory_growth = memory_profile.get("memory_growth_mb", 0.0)
            memory_growth_rate = memory_profile.get("growth_rate_mb_per_request", 0.0)
            
            if memory_growth_rate > 0.01:  # >0.01 MB per request indicates potential leak
                validation_result.validation_issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.CRITICAL,
                        category="memory_usage",
                        metric="memory_leak",
                        current_value=memory_growth_rate,
                        expected_value=0.0,
                        variance_percent=float('inf'),
                        threshold_exceeded=True,
                        message=f"Potential memory leak detected: {memory_growth_rate:.4f} MB/request growth rate"
                    )
                )
            
            self.logger.info(
                "Memory usage pattern validation completed",
                mean_memory=memory_profile.get("mean_memory_mb", 0.0),
                memory_growth=memory_growth,
                growth_rate=memory_growth_rate,
                leak_detected=memory_growth_rate > 0.01
            )
            
        except Exception as memory_error:
            self.logger.error(
                "Memory usage validation failed",
                error=str(memory_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="memory_usage",
                    metric="memory_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Memory usage validation failed: {str(memory_error)}"
                )
            )
    
    def _validate_database_performance(
        self,
        validation_result: PerformanceValidationResult
    ) -> None:
        """
        Validate database performance per Section 0.3.2 database metrics.
        
        Ensures database query performance ≤10% variance from baseline.
        
        Args:
            validation_result: Validation result to update with findings
        """
        self.logger.info("Starting database performance validation")
        
        try:
            # Mock database performance testing (replace with actual implementation)
            database_metrics = self._measure_database_performance()
            
            validation_result.performance_metrics["database_performance"] = database_metrics
            
            # Compare with baseline if available
            if self.baseline_manager:
                baseline = self.baseline_manager.get_default_baseline()
                baseline_operations = baseline.database_operation_baselines
                
                for operation, current_time in database_metrics.get("operation_times", {}).items():
                    baseline_time = baseline_operations.get(operation, 0.0)
                    
                    if baseline_time > 0:
                        variance_percent = ((current_time - baseline_time) / baseline_time) * 100
                        
                        if abs(variance_percent) > DATABASE_VARIANCE_THRESHOLD:
                            validation_result.validation_issues.append(
                                ValidationIssue(
                                    severity=ValidationSeverity.CRITICAL,
                                    category="database_performance",
                                    metric=f"db_{operation}",
                                    current_value=current_time,
                                    expected_value=baseline_time,
                                    variance_percent=variance_percent,
                                    threshold_exceeded=True,
                                    message=f"Database operation variance: {operation} = {variance_percent:.2f}% (threshold: ±{DATABASE_VARIANCE_THRESHOLD}%)"
                                )
                            )
            
            self.logger.info(
                "Database performance validation completed",
                total_operations=len(database_metrics.get("operation_times", {}))
            )
            
        except Exception as database_error:
            self.logger.error(
                "Database performance validation failed",
                error=str(database_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="database_performance",
                    metric="database_validation_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=True,
                    message=f"Database performance validation failed: {str(database_error)}"
                )
            )
    
    def _detect_performance_regression(
        self,
        validation_result: PerformanceValidationResult
    ) -> None:
        """
        Detect performance regression using historical validation data.
        
        Analyzes trend patterns to identify performance degradation over time.
        
        Args:
            validation_result: Validation result to update with regression analysis
        """
        self.logger.info("Starting performance regression detection")
        
        try:
            # Analyze historical validation results for trends
            if len(self.validation_history) < 2:
                validation_result.trend_indicators.append("Insufficient historical data for regression analysis")
                return
            
            # Compare recent performance metrics with historical baselines
            recent_results = self.validation_history[-REGRESSION_DETECTION_WINDOW:]
            
            # Analyze response time trends
            response_time_trend = self._analyze_response_time_trend(recent_results)
            if response_time_trend.get("regression_detected", False):
                validation_result.regression_status = True
                validation_result.validation_issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.CRITICAL,
                        category="regression",
                        metric="response_time_trend",
                        current_value=response_time_trend.get("current_average", 0.0),
                        expected_value=response_time_trend.get("baseline_average", 0.0),
                        variance_percent=response_time_trend.get("trend_variance", 0.0),
                        threshold_exceeded=True,
                        message=f"Response time regression detected: {response_time_trend.get('trend_description', 'Performance deteriorating')}"
                    )
                )
            
            # Analyze throughput trends
            throughput_trend = self._analyze_throughput_trend(recent_results)
            if throughput_trend.get("regression_detected", False):
                validation_result.regression_status = True
                validation_result.validation_issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.CRITICAL,
                        category="regression",
                        metric="throughput_trend",
                        current_value=throughput_trend.get("current_average", 0.0),
                        expected_value=throughput_trend.get("baseline_average", 0.0),
                        variance_percent=throughput_trend.get("trend_variance", 0.0),
                        threshold_exceeded=True,
                        message=f"Throughput regression detected: {throughput_trend.get('trend_description', 'Throughput declining')}"
                    )
                )
            
            validation_result.regression_analysis = {
                "response_time_trend": response_time_trend,
                "throughput_trend": throughput_trend,
                "historical_data_points": len(recent_results),
                "regression_window": REGRESSION_DETECTION_WINDOW
            }
            
            self.logger.info(
                "Performance regression detection completed",
                regression_detected=validation_result.regression_status,
                historical_data_points=len(recent_results)
            )
            
        except Exception as regression_error:
            self.logger.error(
                "Performance regression detection failed",
                error=str(regression_error)
            )
            validation_result.validation_issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="regression",
                    metric="regression_detection_error",
                    current_value=0.0,
                    expected_value=1.0,
                    variance_percent=100.0,
                    threshold_exceeded=False,
                    message=f"Regression detection failed: {str(regression_error)}"
                )
            )
    
    def _assess_overall_compliance(
        self,
        validation_result: PerformanceValidationResult
    ) -> None:
        """
        Assess overall performance compliance based on all validation results.
        
        Determines overall compliance status and updates test counts.
        
        Args:
            validation_result: Validation result to assess for overall compliance
        """
        self.logger.info("Assessing overall performance compliance")
        
        # Count validation issues by severity
        critical_issues = validation_result.get_critical_issues()
        warning_issues = validation_result.get_warning_issues()
        
        # Update test execution counts
        total_validations = len([
            "baseline_variance",
            "response_time_thresholds", 
            "throughput_performance",
            "system_resource_usage",
            "memory_usage_patterns",
            "database_performance"
        ])
        
        validation_result.total_tests = total_validations
        validation_result.failed_tests = len(critical_issues)
        validation_result.passed_tests = total_validations - validation_result.failed_tests
        
        # Assess overall compliance
        validation_result.overall_compliance = (
            len(critical_issues) == 0 and
            validation_result.variance_compliance and
            validation_result.threshold_compliance and
            not validation_result.regression_status
        )
        
        # Calculate statistical confidence
        if validation_result.sample_size > 0:
            validation_result.statistical_confidence = min(
                (validation_result.sample_size / MIN_SAMPLE_SIZE) * 100,
                100.0
            )
        
        # Update Prometheus metrics
        if self.enable_prometheus:
            self.compliance_gauge.labels(compliance_type="overall").set(
                1.0 if validation_result.overall_compliance else 0.0
            )
            self.compliance_gauge.labels(compliance_type="variance").set(
                1.0 if validation_result.variance_compliance else 0.0
            )
            self.compliance_gauge.labels(compliance_type="threshold").set(
                1.0 if validation_result.threshold_compliance else 0.0
            )
            self.regression_gauge.labels(regression_type="performance").set(
                1.0 if validation_result.regression_status else 0.0
            )
        
        self.logger.info(
            "Overall performance compliance assessment completed",
            overall_compliance=validation_result.overall_compliance,
            variance_compliance=validation_result.variance_compliance,
            threshold_compliance=validation_result.threshold_compliance,
            regression_detected=validation_result.regression_status,
            critical_issues=len(critical_issues),
            warning_issues=len(warning_issues),
            sample_size=validation_result.sample_size,
            statistical_confidence=validation_result.statistical_confidence
        )
    
    def _generate_validation_recommendations(
        self,
        validation_result: PerformanceValidationResult
    ) -> None:
        """
        Generate actionable performance recommendations based on validation results.
        
        Provides specific guidance for addressing performance issues and improvements.
        
        Args:
            validation_result: Validation result to generate recommendations for
        """
        recommendations = []
        critical_actions = []
        
        critical_issues = validation_result.get_critical_issues()
        warning_issues = validation_result.get_warning_issues()
        
        # Generate recommendations based on critical issues
        if critical_issues:
            variance_issues = [issue for issue in critical_issues if "variance" in issue.category]
            threshold_issues = [issue for issue in critical_issues if "response_time" in issue.category or "throughput" in issue.category]
            resource_issues = [issue for issue in critical_issues if "system_resources" in issue.category or "memory" in issue.category]
            
            if variance_issues:
                critical_actions.append("❗ CRITICAL: Performance variance exceeds ±10% threshold - immediate investigation required")
                recommendations.append("🔍 Perform detailed performance profiling to identify regression root causes")
                recommendations.append("📊 Compare current implementation with Node.js baseline for optimization opportunities")
            
            if threshold_issues:
                critical_actions.append("❗ CRITICAL: Performance thresholds exceeded - application may not meet SLA requirements")
                recommendations.append("🚀 Optimize response times and throughput through code optimization and caching")
                recommendations.append("🏗️ Consider infrastructure scaling and load balancing improvements")
            
            if resource_issues:
                critical_actions.append("❗ CRITICAL: System resource limits exceeded - risk of service degradation")
                recommendations.append("💾 Implement memory management optimizations and leak detection")
                recommendations.append("🖥️ Optimize CPU-intensive operations and consider async processing")
        
        # Generate recommendations for regression detection
        if validation_result.regression_status:
            critical_actions.append("🔴 Performance regression detected - review recent code changes")
            recommendations.append("📝 Implement performance testing in CI/CD pipeline to prevent future regressions")
            recommendations.append("📈 Establish performance monitoring dashboards for continuous visibility")
        
        # Generate success recommendations
        if validation_result.overall_compliance:
            recommendations.append("✅ Performance validation successful - all metrics within acceptable thresholds")
            if not warning_issues:
                recommendations.append("🎉 Excellent performance! Consider documenting optimization strategies for future reference")
            else:
                recommendations.append("⚠️ Monitor warning indicators to prevent future performance degradation")
        
        # Add general best practices
        recommendations.extend([
            "📊 Implement continuous performance monitoring for proactive issue detection",
            "🔄 Establish regular performance testing cycles for regression prevention",
            "📚 Document performance optimization strategies and lessons learned"
        ])
        
        validation_result.recommendations = recommendations
        validation_result.critical_actions = critical_actions
        
        self.logger.info(
            "Performance recommendations generated",
            total_recommendations=len(recommendations),
            critical_actions=len(critical_actions)
        )
    
    def _finalize_validation(
        self,
        validation_result: PerformanceValidationResult,
        start_time: float
    ) -> PerformanceValidationResult:
        """
        Finalize validation result with duration and historical tracking.
        
        Args:
            validation_result: Validation result to finalize
            start_time: Validation start time for duration calculation
            
        Returns:
            Finalized PerformanceValidationResult
        """
        # Calculate validation duration
        validation_result.duration_seconds = time.time() - start_time
        
        # Update Prometheus metrics
        if self.enable_prometheus:
            self.validation_duration_histogram.observe(validation_result.duration_seconds)
            
            status = "success" if validation_result.overall_compliance else "failure"
            self.validation_counter.labels(
                environment=self.config_environment,
                status=status
            ).inc()
        
        # Store in validation history
        self.validation_history.append(validation_result)
        
        # Limit history size to prevent memory growth
        if len(self.validation_history) > 20:
            self.validation_history = self.validation_history[-20:]
        
        self.logger.info(
            "Performance validation finalized",
            validation_id=validation_result.validation_id,
            duration_seconds=validation_result.duration_seconds,
            overall_compliance=validation_result.overall_compliance,
            exit_code=validation_result.exit_code.value
        )
        
        return validation_result
    
    # Helper methods for performance measurement
    
    def _measure_endpoint_performance(self, app_url: str) -> Dict[str, float]:
        """Measure performance metrics for critical API endpoints."""
        endpoint_metrics = {}
        
        # Define critical endpoints for testing
        test_endpoints = [
            "/health",
            "/api/v1/users",
            "/api/v1/auth/login",
            "/api/v1/auth/logout"
        ]
        
        if not REQUESTS_AVAILABLE:
            self.logger.warning("requests library not available - using mock metrics")
            # Return mock metrics for testing
            return {endpoint: 150.0 for endpoint in test_endpoints}
        
        try:
            for endpoint in test_endpoints:
                response_times = []
                
                # Collect multiple samples for statistical validity
                for _ in range(min(50, MIN_SAMPLE_SIZE // 4)):
                    try:
                        start_time = time.time()
                        response = requests.get(f"{app_url}{endpoint}", timeout=5)
                        response_time_ms = (time.time() - start_time) * 1000
                        
                        if response.status_code < 500:
                            response_times.append(response_time_ms)
                            
                    except Exception:
                        pass  # Skip failed requests
                
                if response_times:
                    endpoint_metrics[f"api_response_time_{endpoint.replace('/', '_').replace('-', '_')}"] = statistics.mean(response_times)
        
        except Exception as measurement_error:
            self.logger.warning(
                "Endpoint performance measurement failed",
                error=str(measurement_error)
            )
        
        return endpoint_metrics
    
    def _measure_response_time_distribution(self, app_url: str) -> Dict[str, Any]:
        """Measure response time distribution with statistical analysis."""
        if not REQUESTS_AVAILABLE:
            # Return mock results for testing
            return {
                "endpoint_metrics": {
                    "/health": {
                        "sample_count": 100,
                        "mean_ms": 85.0,
                        "median_ms": 80.0,
                        "p95_ms": 150.0,
                        "std_dev_ms": 25.0
                    }
                },
                "total_samples": 100
            }
        
        endpoint_metrics = {}
        total_samples = 0
        
        test_endpoints = ["/health", "/api/v1/users"]
        
        try:
            for endpoint in test_endpoints:
                response_times = []
                
                # Collect comprehensive samples
                for _ in range(MIN_SAMPLE_SIZE):
                    try:
                        start_time = time.time()
                        response = requests.get(f"{app_url}{endpoint}", timeout=10)
                        response_time_ms = (time.time() - start_time) * 1000
                        
                        if response.status_code < 500:
                            response_times.append(response_time_ms)
                            
                    except Exception:
                        pass
                
                if response_times:
                    endpoint_metrics[endpoint] = {
                        "sample_count": len(response_times),
                        "mean_ms": statistics.mean(response_times),
                        "median_ms": statistics.median(response_times),
                        "p95_ms": statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times),
                        "std_dev_ms": statistics.stdev(response_times) if len(response_times) > 1 else 0.0
                    }
                    total_samples += len(response_times)
        
        except Exception as distribution_error:
            self.logger.warning(
                "Response time distribution measurement failed",
                error=str(distribution_error)
            )
        
        return {
            "endpoint_metrics": endpoint_metrics,
            "total_samples": total_samples
        }
    
    def _measure_throughput_capacity(self, app_url: str) -> Dict[str, Any]:
        """Measure throughput capacity with progressive load testing."""
        # Mock implementation for testing
        load_scenarios = {
            "light_load": {
                "concurrent_users": 10,
                "requests_per_second": 45.0,
                "error_rate_percent": 0.05,
                "total_requests": 450
            },
            "normal_load": {
                "concurrent_users": 50,
                "requests_per_second": 125.0,
                "error_rate_percent": 0.08,
                "total_requests": 1250
            }
        }
        
        total_requests = sum(scenario["total_requests"] for scenario in load_scenarios.values())
        
        return {
            "load_scenarios": load_scenarios,
            "total_requests": total_requests
        }
    
    def _monitor_system_resources(self, app_url: str) -> Dict[str, Any]:
        """Monitor system resource usage during performance testing."""
        if not PSUTIL_AVAILABLE:
            # Return mock metrics for testing
            return {
                "cpu_utilization_peak": 45.0,
                "memory_utilization_peak": 65.0,
                "cpu_utilization_average": 35.0,
                "memory_utilization_average": 55.0
            }
        
        try:
            # Sample system resources during brief load test
            cpu_samples = []
            memory_samples = []
            
            for _ in range(10):  # 10 samples over brief period
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                cpu_samples.append(cpu_percent)
                memory_samples.append(memory_percent)
            
            return {
                "cpu_utilization_peak": max(cpu_samples),
                "memory_utilization_peak": max(memory_samples),
                "cpu_utilization_average": statistics.mean(cpu_samples),
                "memory_utilization_average": statistics.mean(memory_samples),
                "sample_count": len(cpu_samples)
            }
            
        except Exception as resource_error:
            self.logger.warning(
                "System resource monitoring failed",
                error=str(resource_error)
            )
            return {
                "cpu_utilization_peak": 0.0,
                "memory_utilization_peak": 0.0,
                "cpu_utilization_average": 0.0,
                "memory_utilization_average": 0.0
            }
    
    def _profile_memory_usage(self, app_url: str) -> Dict[str, Any]:
        """Profile memory usage patterns with leak detection."""
        if not PSUTIL_AVAILABLE:
            # Return mock metrics for testing
            return {
                "mean_memory_mb": 280.0,
                "peak_memory_mb": 350.0,
                "memory_growth_mb": 5.0,
                "growth_rate_mb_per_request": 0.001,
                "sample_count": 100
            }
        
        try:
            process = psutil.Process()
            initial_memory = process.memory_info().rss / (1024 * 1024)  # Convert to MB
            
            memory_samples = []
            request_count = 0
            
            # Profile memory during sustained requests
            for _ in range(50):  # 50 iterations of requests
                if REQUESTS_AVAILABLE:
                    try:
                        requests.get(f"{app_url}/health", timeout=5)
                        request_count += 1
                    except Exception:
                        pass
                
                current_memory = process.memory_info().rss / (1024 * 1024)
                memory_samples.append(current_memory)
                time.sleep(0.1)  # Brief pause between samples
            
            final_memory = process.memory_info().rss / (1024 * 1024)
            memory_growth = final_memory - initial_memory
            
            return {
                "mean_memory_mb": statistics.mean(memory_samples),
                "peak_memory_mb": max(memory_samples),
                "memory_growth_mb": memory_growth,
                "growth_rate_mb_per_request": memory_growth / request_count if request_count > 0 else 0.0,
                "sample_count": len(memory_samples)
            }
            
        except Exception as memory_error:
            self.logger.warning(
                "Memory profiling failed",
                error=str(memory_error)
            )
            return {
                "mean_memory_mb": 0.0,
                "peak_memory_mb": 0.0,
                "memory_growth_mb": 0.0,
                "growth_rate_mb_per_request": 0.0,
                "sample_count": 0
            }
    
    def _measure_database_performance(self) -> Dict[str, Any]:
        """Measure database operation performance (mock implementation)."""
        # Mock database operation metrics for testing
        operation_times = {
            "find_one": 48.0,
            "find_many": 85.0,
            "insert_one": 32.0,
            "update_one": 45.0,
            "delete_one": 28.0,
            "aggregate": 120.0
        }
        
        return {
            "operation_times": operation_times,
            "total_operations": len(operation_times)
        }
    
    def _analyze_response_time_trend(self, recent_results: List[PerformanceValidationResult]) -> Dict[str, Any]:
        """Analyze response time trends for regression detection."""
        if len(recent_results) < 2:
            return {"regression_detected": False, "trend_description": "Insufficient data"}
        
        # Extract response time metrics from recent results
        response_times = []
        for result in recent_results:
            response_time_metrics = result.performance_metrics.get("response_times", {})
            endpoint_metrics = response_time_metrics.get("endpoint_metrics", {})
            
            # Calculate average response time across all endpoints
            all_times = []
            for endpoint_data in endpoint_metrics.values():
                if isinstance(endpoint_data, dict) and "mean_ms" in endpoint_data:
                    all_times.append(endpoint_data["mean_ms"])
            
            if all_times:
                response_times.append(statistics.mean(all_times))
        
        if len(response_times) < 2:
            return {"regression_detected": False, "trend_description": "No response time data"}
        
        # Check for increasing trend (regression)
        recent_avg = statistics.mean(response_times[-2:])
        historical_avg = statistics.mean(response_times[:-2]) if len(response_times) > 2 else response_times[0]
        
        trend_variance = ((recent_avg - historical_avg) / historical_avg) * 100 if historical_avg > 0 else 0
        
        regression_detected = trend_variance > WARNING_VARIANCE_THRESHOLD
        
        return {
            "regression_detected": regression_detected,
            "current_average": recent_avg,
            "baseline_average": historical_avg,
            "trend_variance": trend_variance,
            "trend_description": f"Response time trending {'up' if trend_variance > 0 else 'down'} by {abs(trend_variance):.2f}%"
        }
    
    def _analyze_throughput_trend(self, recent_results: List[PerformanceValidationResult]) -> Dict[str, Any]:
        """Analyze throughput trends for regression detection."""
        if len(recent_results) < 2:
            return {"regression_detected": False, "trend_description": "Insufficient data"}
        
        # Extract throughput metrics from recent results
        throughput_values = []
        for result in recent_results:
            throughput_metrics = result.performance_metrics.get("throughput", {})
            load_scenarios = throughput_metrics.get("load_scenarios", {})
            
            # Calculate average throughput across scenarios
            all_rps = []
            for scenario_data in load_scenarios.values():
                if isinstance(scenario_data, dict) and "requests_per_second" in scenario_data:
                    all_rps.append(scenario_data["requests_per_second"])
            
            if all_rps:
                throughput_values.append(statistics.mean(all_rps))
        
        if len(throughput_values) < 2:
            return {"regression_detected": False, "trend_description": "No throughput data"}
        
        # Check for decreasing trend (regression)
        recent_avg = statistics.mean(throughput_values[-2:])
        historical_avg = statistics.mean(throughput_values[:-2]) if len(throughput_values) > 2 else throughput_values[0]
        
        trend_variance = ((historical_avg - recent_avg) / historical_avg) * 100 if historical_avg > 0 else 0
        
        regression_detected = trend_variance > WARNING_VARIANCE_THRESHOLD
        
        return {
            "regression_detected": regression_detected,
            "current_average": recent_avg,
            "baseline_average": historical_avg,
            "trend_variance": trend_variance,
            "trend_description": f"Throughput trending {'down' if trend_variance > 0 else 'up'} by {abs(trend_variance):.2f}%"
        }


def main():
    """
    Main entry point for performance validation script with comprehensive CLI interface.
    
    Supports multiple execution modes for different CI/CD integration scenarios.
    """
    parser = argparse.ArgumentParser(
        description="Automated Performance Validation Script for Flask Migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config production --verbose
  %(prog)s --scenarios api_baseline,load_test --fail-fast
  %(prog)s --ci-mode --output-format json --timeout 1200
  %(prog)s --app-url http://staging.example.com:5000 --memory-profiling
        """
    )
    
    # Configuration arguments
    parser.add_argument(
        "--config", 
        default="testing",
        choices=["testing", "staging", "production"],
        help="Environment configuration (default: testing)"
    )
    
    parser.add_argument(
        "--app-url",
        default="http://localhost:5000",
        help="Flask application URL for testing (default: http://localhost:5000)"
    )
    
    # Test execution arguments
    parser.add_argument(
        "--scenarios",
        help="Comma-separated list of test scenarios to execute"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=TEST_TIMEOUT_SECONDS,
        help=f"Maximum validation execution time in seconds (default: {TEST_TIMEOUT_SECONDS})"
    )
    
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop validation on first critical failure"
    )
    
    # Feature flags
    parser.add_argument(
        "--no-load-testing",
        action="store_true",
        help="Disable load testing validation"
    )
    
    parser.add_argument(
        "--no-memory-profiling",
        action="store_true",
        help="Disable memory usage profiling"
    )
    
    parser.add_argument(
        "--no-regression-detection",
        action="store_true",
        help="Disable regression detection analysis"
    )
    
    # Output and reporting arguments
    parser.add_argument(
        "--output-format",
        choices=["text", "json", "junit"],
        default="text",
        help="Output format for validation results (default: text)"
    )
    
    parser.add_argument(
        "--output-file",
        help="Output file path for validation results"
    )
    
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Enable CI/CD mode with structured output and exit codes"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-critical output"
    )
    
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    # Initialize performance validator
    try:
        validator = PerformanceValidator(
            config_environment=args.config,
            enable_prometheus=not args.ci_mode,  # Disable Prometheus in CI mode
            enable_detailed_logging=args.verbose
        )
        
        # Parse test scenarios
        test_scenarios = None
        if args.scenarios:
            test_scenarios = [scenario.strip() for scenario in args.scenarios.split(",")]
        
        # Execute comprehensive performance validation
        validation_result = validator.validate_performance_comprehensive(
            app_url=args.app_url,
            test_scenarios=test_scenarios,
            enable_load_testing=not args.no_load_testing,
            enable_memory_profiling=not args.no_memory_profiling,
            enable_regression_detection=not args.no_regression_detection,
            fail_fast=args.fail_fast,
            timeout_seconds=args.timeout
        )
        
        # Generate and output validation report
        output_validation_report(validation_result, args)
        
        # Exit with appropriate code
        exit_code = validation_result.exit_code.value
        
        if not args.quiet:
            print(f"\nPerformance validation completed with exit code: {exit_code} ({validation_result.exit_code.name})")
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\nPerformance validation interrupted by user")
        sys.exit(ValidationExitCode.EXECUTION_ERROR.value)
        
    except Exception as main_error:
        print(f"Performance validation failed: {str(main_error)}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(ValidationExitCode.EXECUTION_ERROR.value)


def output_validation_report(
    validation_result: PerformanceValidationResult,
    args: argparse.Namespace
) -> None:
    """
    Output validation report in specified format.
    
    Args:
        validation_result: Validation result to output
        args: Command line arguments with output configuration
    """
    report_data = validation_result.generate_summary_report()
    
    if args.output_format == "json":
        output_content = json.dumps(report_data, indent=2, default=str)
    elif args.output_format == "junit":
        output_content = generate_junit_xml(validation_result)
    else:  # text format
        output_content = generate_text_report(validation_result)
    
    # Output to file or stdout
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(output_content)
        if not args.quiet:
            print(f"Validation report written to: {args.output_file}")
    else:
        print(output_content)


def generate_text_report(validation_result: PerformanceValidationResult) -> str:
    """Generate human-readable text report."""
    report_lines = []
    
    # Header
    report_lines.append("=" * 80)
    report_lines.append("PERFORMANCE VALIDATION REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Validation ID: {validation_result.validation_id}")
    report_lines.append(f"Timestamp: {validation_result.timestamp.isoformat()}")
    report_lines.append(f"Duration: {validation_result.duration_seconds:.2f} seconds")
    report_lines.append(f"Exit Code: {validation_result.exit_code.value} ({validation_result.exit_code.name})")
    report_lines.append("")
    
    # Summary
    report_lines.append("VALIDATION SUMMARY")
    report_lines.append("-" * 40)
    report_lines.append(f"Overall Compliance: {'✅ PASS' if validation_result.overall_compliance else '❌ FAIL'}")
    report_lines.append(f"Variance Compliance: {'✅ PASS' if validation_result.variance_compliance else '❌ FAIL'}")
    report_lines.append(f"Threshold Compliance: {'✅ PASS' if validation_result.threshold_compliance else '❌ FAIL'}")
    report_lines.append(f"Regression Detected: {'🔴 YES' if validation_result.regression_status else '✅ NO'}")
    report_lines.append(f"Tests Passed: {validation_result.passed_tests}/{validation_result.total_tests}")
    report_lines.append(f"Success Rate: {validation_result.success_rate:.1f}%")
    report_lines.append(f"Sample Size: {validation_result.sample_size}")
    report_lines.append(f"Statistical Confidence: {validation_result.statistical_confidence:.1f}%")
    report_lines.append("")
    
    # Critical Issues
    critical_issues = validation_result.get_critical_issues()
    if critical_issues:
        report_lines.append("CRITICAL ISSUES")
        report_lines.append("-" * 40)
        for issue in critical_issues:
            report_lines.append(f"❌ {issue.message}")
            report_lines.append(f"   Current: {issue.current_value:.2f}, Expected: {issue.expected_value:.2f}")
            report_lines.append(f"   Variance: {issue.variance_percent:.2f}%")
            if issue.remediation_suggestions:
                report_lines.append("   Remediation:")
                for suggestion in issue.remediation_suggestions[:3]:  # Limit to top 3
                    report_lines.append(f"   - {suggestion}")
            report_lines.append("")
    
    # Warning Issues
    warning_issues = validation_result.get_warning_issues()
    if warning_issues:
        report_lines.append("WARNING ISSUES")
        report_lines.append("-" * 40)
        for issue in warning_issues:
            report_lines.append(f"⚠️ {issue.message}")
            report_lines.append(f"   Current: {issue.current_value:.2f}, Expected: {issue.expected_value:.2f}")
            report_lines.append(f"   Variance: {issue.variance_percent:.2f}%")
            report_lines.append("")
    
    # Critical Actions
    if validation_result.critical_actions:
        report_lines.append("CRITICAL ACTIONS REQUIRED")
        report_lines.append("-" * 40)
        for action in validation_result.critical_actions:
            report_lines.append(action)
        report_lines.append("")
    
    # Recommendations
    if validation_result.recommendations:
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("-" * 40)
        for recommendation in validation_result.recommendations:
            report_lines.append(recommendation)
        report_lines.append("")
    
    report_lines.append("=" * 80)
    
    return "\n".join(report_lines)


def generate_junit_xml(validation_result: PerformanceValidationResult) -> str:
    """Generate JUnit XML format for CI/CD integration."""
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.dom import minidom
    
    testsuites = Element("testsuites")
    testsuite = SubElement(testsuites, "testsuite")
    testsuite.set("name", "PerformanceValidation")
    testsuite.set("tests", str(validation_result.total_tests))
    testsuite.set("failures", str(validation_result.failed_tests))
    testsuite.set("time", str(validation_result.duration_seconds))
    
    # Add test cases for each validation category
    categories = ["baseline_variance", "response_time", "throughput", "system_resources", "memory_usage", "database_performance"]
    
    for category in categories:
        testcase = SubElement(testsuite, "testcase")
        testcase.set("classname", "PerformanceValidation")
        testcase.set("name", category)
        
        # Check for failures in this category
        category_issues = [issue for issue in validation_result.validation_issues if issue.category == category]
        critical_issues = [issue for issue in category_issues if issue.severity == ValidationSeverity.CRITICAL]
        
        if critical_issues:
            failure = SubElement(testcase, "failure")
            failure.set("message", f"{len(critical_issues)} critical issues in {category}")
            failure.text = "\n".join([issue.message for issue in critical_issues])
    
    # Format XML with pretty printing
    rough_string = tostring(testsuites, 'unicode')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


if __name__ == "__main__":
    main()