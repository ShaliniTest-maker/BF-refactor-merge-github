"""
Comprehensive Load Testing Implementation for Flask Migration Performance Validation

This module provides enterprise-grade load testing capabilities using Locust framework
to validate that the Python/Flask migration maintains ≤10% performance variance compared
to the Node.js baseline implementation. Implements progressive scaling, throughput
measurement, automated baseline comparison, and comprehensive performance reporting.

Key Features:
- Locust (≥2.x) load testing framework integration per Section 6.6.1
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- Automated baseline comparison with Node.js performance metrics per Section 0.3.2
- Comprehensive performance degradation detection and alerting per Section 6.6.1
- CI/CD pipeline integration with automated performance gates per Section 6.6.2
- Real-time monitoring and performance trend analysis per Section 0.3.2
- Detailed reporting with variance analysis and compliance validation

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 4.6.3: Load testing specifications with progressive user scaling and endurance testing
- Section 6.6.1: Locust ≥2.x performance testing framework with user behavior simulation
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 6.6.2: CI/CD integration with automated performance validation and regression detection

Dependencies:
- locust ≥2.x: Load testing framework with distributed capabilities
- pytest ≥7.4+: Test framework for comprehensive test execution and reporting
- requests ≥2.31+: HTTP client for health checks and API validation
- structlog ≥23.1+: Structured logging for comprehensive performance monitoring
- prometheus-client ≥0.17+: Metrics collection and monitoring integration

Author: Flask Migration Team
Version: 1.0.0
"""

import os
import sys
import time
import json
import subprocess
import threading
import signal
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
from contextlib import contextmanager
import tempfile
import shutil

# Core testing framework
import pytest
from pytest import FixtureRequest

# HTTP client for health checks and API validation
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

# Monitoring and logging
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    import logging
    STRUCTLOG_AVAILABLE = False

# Prometheus metrics if available
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, start_http_server, push_to_gateway
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Load testing framework
try:
    from locust import HttpUser, task, between, events, runners
    from locust.env import Environment
    from locust.runners import LocalRunner, WorkerRunner
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    from locust.exception import RescheduleTask, StopUser
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

# Performance testing components
from baseline_data import (
    BaselineDataManager,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    CRITICAL_VARIANCE_THRESHOLD
)

# Optional imports for enhanced functionality
try:
    from locustfile import (
        APIReadOperationsUser,
        APIWriteOperationsUser,
        AuthenticationFlowUser,
        FileUploadOperationsUser,
        BaseFlaskUser,
        PerformanceMetricsCollector
    )
    LOCUSTFILE_AVAILABLE = True
except ImportError:
    LOCUSTFILE_AVAILABLE = False


# Performance test configuration constants per Section 4.6.3
DEFAULT_MIN_USERS = 10              # Minimum concurrent users per Section 4.6.3
DEFAULT_MAX_USERS = 1000            # Maximum concurrent users per Section 4.6.3
DEFAULT_SPAWN_RATE = 5              # Users spawned per second
DEFAULT_TEST_DURATION = 1800        # 30-minute sustained load per Section 4.6.3
DEFAULT_HOST = "http://localhost:5000"  # Default Flask application host
DEFAULT_TARGET_RPS = 100            # Minimum 100 requests/second per Section 4.6.3
DEFAULT_RESPONSE_TIME_THRESHOLD = 500  # 95th percentile ≤500ms per Section 4.6.3
DEFAULT_ERROR_RATE_THRESHOLD = 0.1  # ≤0.1% error rate per Section 4.6.3


@dataclass
class LoadTestConfiguration:
    """
    Comprehensive load test configuration supporting flexible test execution.
    
    Implements Section 4.6.3 load testing parameters with configurable scaling,
    duration, and performance thresholds for diverse testing scenarios.
    """
    min_users: int = DEFAULT_MIN_USERS
    max_users: int = DEFAULT_MAX_USERS
    spawn_rate: float = DEFAULT_SPAWN_RATE
    test_duration: int = DEFAULT_TEST_DURATION
    host: str = DEFAULT_HOST
    target_rps: float = DEFAULT_TARGET_RPS
    response_time_threshold: float = DEFAULT_RESPONSE_TIME_THRESHOLD
    error_rate_threshold: float = DEFAULT_ERROR_RATE_THRESHOLD
    variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD / 100.0  # Convert percentage to decimal
    ramp_up_time: int = 300          # 5-minute ramp-up period
    cool_down_time: int = 120        # 2-minute cool-down period
    steady_state_time: int = 1200    # 20-minute steady state minimum
    geographic_simulation: bool = True
    enable_monitoring: bool = True
    enable_real_time_alerts: bool = True
    report_output_dir: str = "tests/performance/reports"
    baseline_data_file: Optional[str] = None
    prometheus_gateway: Optional[str] = None
    slack_webhook_url: Optional[str] = None


@dataclass
class LoadTestResult:
    """
    Comprehensive load test execution results with performance analysis.
    
    Captures all critical performance metrics, baseline comparison results,
    and compliance validation per Section 0.3.2 monitoring requirements.
    """
    test_id: str
    configuration: LoadTestConfiguration
    start_time: datetime
    end_time: datetime
    total_duration: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    error_rate_percent: float
    average_response_time_ms: float
    median_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    max_response_time_ms: float
    min_response_time_ms: float
    requests_per_second: float
    peak_rps: float
    concurrent_users_achieved: int
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)
    performance_compliance: Dict[str, bool] = field(default_factory=dict)
    endpoint_performance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    resource_utilization: Dict[str, float] = field(default_factory=dict)
    variance_analysis: Dict[str, float] = field(default_factory=dict)
    alerts_triggered: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate derived metrics and validate test results."""
        if self.total_requests > 0:
            self.success_rate_percent = (self.successful_requests / self.total_requests) * 100.0
        else:
            self.success_rate_percent = 0.0
        
        # Validate performance compliance
        self.performance_compliance.update({
            "response_time_compliant": self.p95_response_time_ms <= self.configuration.response_time_threshold,
            "error_rate_compliant": self.error_rate_percent <= self.configuration.error_rate_threshold,
            "throughput_compliant": self.requests_per_second >= self.configuration.target_rps,
            "variance_compliant": self._validate_variance_compliance()
        })
    
    def _validate_variance_compliance(self) -> bool:
        """Validate overall variance compliance against baseline."""
        if not self.baseline_comparison:
            return False
        
        return self.baseline_comparison.get("overall_compliance", False)
    
    def is_successful(self) -> bool:
        """Check if load test meets all success criteria."""
        return all(self.performance_compliance.values()) and len(self.alerts_triggered) == 0
    
    def get_summary_dict(self) -> Dict[str, Any]:
        """Generate comprehensive test result summary."""
        return {
            "test_metadata": {
                "test_id": self.test_id,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "duration_seconds": self.total_duration,
                "configuration": self.configuration.__dict__
            },
            "performance_metrics": {
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "error_rate_percent": self.error_rate_percent,
                "success_rate_percent": self.success_rate_percent,
                "average_response_time_ms": self.average_response_time_ms,
                "p95_response_time_ms": self.p95_response_time_ms,
                "p99_response_time_ms": self.p99_response_time_ms,
                "requests_per_second": self.requests_per_second,
                "peak_rps": self.peak_rps,
                "concurrent_users_achieved": self.concurrent_users_achieved
            },
            "compliance_validation": {
                "overall_success": self.is_successful(),
                "performance_compliance": self.performance_compliance,
                "variance_analysis": self.variance_analysis,
                "baseline_comparison": self.baseline_comparison
            },
            "quality_assessment": {
                "alerts_triggered": self.alerts_triggered,
                "recommendations": self.recommendations,
                "endpoint_performance": self.endpoint_performance,
                "resource_utilization": self.resource_utilization
            }
        }


class LoadTestMetricsCollector:
    """
    Advanced metrics collection and analysis system for load testing.
    
    Provides real-time performance monitoring, baseline comparison, variance
    analysis, and automated alerting per Section 0.3.2 performance monitoring.
    """
    
    def __init__(self, config: LoadTestConfiguration):
        self.config = config
        self.start_time = None
        self.end_time = None
        
        # Performance data storage
        self.response_times: List[float] = []
        self.request_timestamps: List[float] = []
        self.error_timestamps: List[float] = []
        self.concurrent_users_timeline: List[Tuple[float, int]] = []
        self.throughput_timeline: List[Tuple[float, float]] = []
        
        # Endpoint-specific metrics
        self.endpoint_metrics: Dict[str, Dict[str, List[float]]] = {}
        
        # Resource utilization tracking
        self.cpu_utilization_samples: List[float] = []
        self.memory_usage_samples: List[float] = []
        
        # Alert management
        self.alerts_triggered: List[str] = []
        self.performance_warnings: List[str] = []
        
        # Prometheus metrics integration
        if PROMETHEUS_AVAILABLE and config.enable_monitoring:
            self._setup_prometheus_metrics()
        
        # Structured logging setup
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("load_test_metrics")
        else:
            self.logger = logging.getLogger("load_test_metrics")
    
    def _setup_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics collection."""
        self.registry = CollectorRegistry()
        
        self.response_time_histogram = Histogram(
            'load_test_response_time_seconds',
            'Response time distribution during load testing',
            ['endpoint', 'method'],
            registry=self.registry
        )
        
        self.request_counter = Counter(
            'load_test_requests_total',
            'Total requests during load testing',
            ['endpoint', 'method', 'status'],
            registry=self.registry
        )
        
        self.throughput_gauge = Gauge(
            'load_test_current_rps',
            'Current requests per second',
            registry=self.registry
        )
        
        self.concurrent_users_gauge = Gauge(
            'load_test_concurrent_users',
            'Current concurrent users',
            registry=self.registry
        )
        
        self.error_rate_gauge = Gauge(
            'load_test_error_rate_percent',
            'Current error rate percentage',
            registry=self.registry
        )
    
    def start_collection(self) -> None:
        """Initialize metrics collection."""
        self.start_time = time.time()
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Load test metrics collection started", timestamp=self.start_time)
    
    def stop_collection(self) -> None:
        """Finalize metrics collection."""
        self.end_time = time.time()
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Load test metrics collection completed", 
                           timestamp=self.end_time, 
                           duration=self.end_time - self.start_time)
    
    def record_request(self, endpoint: str, method: str, response_time_ms: float, 
                      status_code: int, success: bool, timestamp: float = None) -> None:
        """Record individual request metrics with comprehensive analysis."""
        if timestamp is None:
            timestamp = time.time()
        
        # Store response time data
        self.response_times.append(response_time_ms)
        self.request_timestamps.append(timestamp)
        
        # Track errors
        if not success or status_code >= 400:
            self.error_timestamps.append(timestamp)
        
        # Endpoint-specific tracking
        endpoint_key = f"{method} {endpoint}"
        if endpoint_key not in self.endpoint_metrics:
            self.endpoint_metrics[endpoint_key] = {
                "response_times": [],
                "error_count": 0,
                "request_count": 0
            }
        
        self.endpoint_metrics[endpoint_key]["response_times"].append(response_time_ms)
        self.endpoint_metrics[endpoint_key]["request_count"] += 1
        
        if not success:
            self.endpoint_metrics[endpoint_key]["error_count"] += 1
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE and hasattr(self, 'response_time_histogram'):
            self.response_time_histogram.labels(endpoint=endpoint, method=method).observe(response_time_ms / 1000.0)
            status = "success" if success else "error"
            self.request_counter.labels(endpoint=endpoint, method=method, status=status).inc()
        
        # Real-time performance monitoring
        if self.config.enable_real_time_alerts:
            self._check_real_time_performance_alerts(response_time_ms, success)
    
    def record_concurrent_users(self, user_count: int, timestamp: float = None) -> None:
        """Record concurrent user count for capacity analysis."""
        if timestamp is None:
            timestamp = time.time()
        
        self.concurrent_users_timeline.append((timestamp, user_count))
        
        if PROMETHEUS_AVAILABLE and hasattr(self, 'concurrent_users_gauge'):
            self.concurrent_users_gauge.set(user_count)
    
    def record_throughput(self, rps: float, timestamp: float = None) -> None:
        """Record throughput measurement for trend analysis."""
        if timestamp is None:
            timestamp = time.time()
        
        self.throughput_timeline.append((timestamp, rps))
        
        if PROMETHEUS_AVAILABLE and hasattr(self, 'throughput_gauge'):
            self.throughput_gauge.set(rps)
    
    def record_resource_utilization(self, cpu_percent: float, memory_mb: float) -> None:
        """Record system resource utilization during testing."""
        self.cpu_utilization_samples.append(cpu_percent)
        self.memory_usage_samples.append(memory_mb)
    
    def _check_real_time_performance_alerts(self, response_time_ms: float, success: bool) -> None:
        """Monitor real-time performance and trigger alerts for threshold violations."""
        # Response time alert
        if response_time_ms > self.config.response_time_threshold * 1.5:  # 150% of threshold
            alert_msg = f"Critical response time: {response_time_ms:.2f}ms exceeds 150% of threshold ({self.config.response_time_threshold}ms)"
            if alert_msg not in self.alerts_triggered:
                self.alerts_triggered.append(alert_msg)
                if STRUCTLOG_AVAILABLE:
                    self.logger.error("Performance alert triggered", alert=alert_msg)
        
        # Calculate recent error rate
        if len(self.error_timestamps) > 0 and len(self.request_timestamps) > 0:
            recent_window = 60  # Last 60 seconds
            current_time = time.time()
            recent_errors = len([t for t in self.error_timestamps if current_time - t <= recent_window])
            recent_requests = len([t for t in self.request_timestamps if current_time - t <= recent_window])
            
            if recent_requests > 0:
                recent_error_rate = (recent_errors / recent_requests) * 100.0
                if recent_error_rate > self.config.error_rate_threshold * 5:  # 5x threshold
                    alert_msg = f"Critical error rate: {recent_error_rate:.2f}% exceeds 5x threshold ({self.config.error_rate_threshold}%)"
                    if alert_msg not in self.alerts_triggered:
                        self.alerts_triggered.append(alert_msg)
                        if STRUCTLOG_AVAILABLE:
                            self.logger.error("Error rate alert triggered", alert=alert_msg)
    
    def calculate_performance_statistics(self) -> Dict[str, Any]:
        """Calculate comprehensive performance statistics from collected data."""
        if not self.response_times:
            return {"error": "No performance data available"}
        
        # Response time statistics
        response_stats = {
            "mean_response_time_ms": statistics.mean(self.response_times),
            "median_response_time_ms": statistics.median(self.response_times),
            "p95_response_time_ms": self._calculate_percentile(self.response_times, 95),
            "p99_response_time_ms": self._calculate_percentile(self.response_times, 99),
            "min_response_time_ms": min(self.response_times),
            "max_response_time_ms": max(self.response_times),
            "std_deviation_ms": statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0.0
        }
        
        # Request and error statistics
        total_requests = len(self.request_timestamps)
        total_errors = len(self.error_timestamps)
        error_rate = (total_errors / total_requests) * 100.0 if total_requests > 0 else 0.0
        
        # Throughput statistics
        if self.throughput_timeline:
            throughput_values = [rps for _, rps in self.throughput_timeline]
            throughput_stats = {
                "average_rps": statistics.mean(throughput_values),
                "peak_rps": max(throughput_values),
                "min_rps": min(throughput_values)
            }
        else:
            # Calculate throughput from timestamps
            if len(self.request_timestamps) > 1 and self.start_time and self.end_time:
                duration = self.end_time - self.start_time
                avg_rps = total_requests / duration if duration > 0 else 0
                throughput_stats = {
                    "average_rps": avg_rps,
                    "peak_rps": avg_rps,
                    "min_rps": avg_rps
                }
            else:
                throughput_stats = {"average_rps": 0, "peak_rps": 0, "min_rps": 0}
        
        # Concurrent users statistics
        if self.concurrent_users_timeline:
            user_counts = [users for _, users in self.concurrent_users_timeline]
            concurrent_stats = {
                "max_concurrent_users": max(user_counts),
                "avg_concurrent_users": statistics.mean(user_counts),
                "min_concurrent_users": min(user_counts)
            }
        else:
            concurrent_stats = {"max_concurrent_users": 0, "avg_concurrent_users": 0, "min_concurrent_users": 0}
        
        # Resource utilization statistics
        resource_stats = {}
        if self.cpu_utilization_samples:
            resource_stats["cpu"] = {
                "avg_cpu_percent": statistics.mean(self.cpu_utilization_samples),
                "peak_cpu_percent": max(self.cpu_utilization_samples),
                "min_cpu_percent": min(self.cpu_utilization_samples)
            }
        
        if self.memory_usage_samples:
            resource_stats["memory"] = {
                "avg_memory_mb": statistics.mean(self.memory_usage_samples),
                "peak_memory_mb": max(self.memory_usage_samples),
                "min_memory_mb": min(self.memory_usage_samples)
            }
        
        # Endpoint-specific performance analysis
        endpoint_stats = {}
        for endpoint, metrics in self.endpoint_metrics.items():
            if metrics["response_times"]:
                endpoint_stats[endpoint] = {
                    "avg_response_time_ms": statistics.mean(metrics["response_times"]),
                    "p95_response_time_ms": self._calculate_percentile(metrics["response_times"], 95),
                    "request_count": metrics["request_count"],
                    "error_count": metrics["error_count"],
                    "error_rate_percent": (metrics["error_count"] / metrics["request_count"]) * 100.0 if metrics["request_count"] > 0 else 0.0
                }
        
        return {
            "response_time_metrics": response_stats,
            "request_metrics": {
                "total_requests": total_requests,
                "successful_requests": total_requests - total_errors,
                "failed_requests": total_errors,
                "error_rate_percent": error_rate
            },
            "throughput_metrics": throughput_stats,
            "concurrent_user_metrics": concurrent_stats,
            "resource_utilization_metrics": resource_stats,
            "endpoint_performance_metrics": endpoint_stats,
            "test_duration_seconds": (self.end_time - self.start_time) if self.start_time and self.end_time else 0
        }
    
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate specified percentile from data list."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int((percentile / 100.0) * len(sorted_data))
        index = min(index, len(sorted_data) - 1)
        return sorted_data[index]
    
    def validate_against_baseline(self) -> Dict[str, Any]:
        """Validate current performance against Node.js baseline metrics."""
        performance_stats = self.calculate_performance_statistics()
        
        flask_metrics = {
            "response_time_ms": performance_stats["response_time_metrics"]["mean_response_time_ms"],
            "requests_per_second": performance_stats["throughput_metrics"]["average_rps"],
            "error_rate_percent": performance_stats["request_metrics"]["error_rate_percent"]
        }
        
        # Add resource utilization if available
        if "resource_utilization_metrics" in performance_stats:
            if "cpu" in performance_stats["resource_utilization_metrics"]:
                flask_metrics["cpu_utilization_percent"] = performance_stats["resource_utilization_metrics"]["cpu"]["avg_cpu_percent"]
            if "memory" in performance_stats["resource_utilization_metrics"]:
                flask_metrics["memory_usage_mb"] = performance_stats["resource_utilization_metrics"]["memory"]["avg_memory_mb"]
        
        return validate_flask_performance_against_baseline(flask_metrics)


class LoadTestOrchestrator:
    """
    Enterprise-grade load test orchestration and management system.
    
    Provides comprehensive load test execution, monitoring, reporting, and
    integration with CI/CD pipelines per Section 6.6.2 automation requirements.
    """
    
    def __init__(self, config: LoadTestConfiguration):
        self.config = config
        self.metrics_collector = LoadTestMetricsCollector(config)
        self.locust_process = None
        self.monitoring_thread = None
        self.shutdown_requested = False
        
        # Setup output directories
        self.report_dir = Path(config.report_output_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Structured logging setup
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("load_test_orchestrator")
        else:
            self.logger = logging.getLogger("load_test_orchestrator")
    
    def execute_load_test(self) -> LoadTestResult:
        """
        Execute comprehensive load test with full monitoring and analysis.
        
        Returns:
            LoadTestResult containing complete performance analysis and compliance validation
        """
        if not LOCUST_AVAILABLE:
            raise RuntimeError("Locust framework is not available. Install with: pip install locust>=2.0")
        
        test_id = self._generate_test_id()
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Starting load test execution", 
                           test_id=test_id, 
                           configuration=self.config.__dict__)
        
        try:
            # Pre-test validation
            self._validate_test_environment()
            
            # Start monitoring
            self.metrics_collector.start_collection()
            self._start_monitoring_thread()
            
            # Execute load test
            start_time = datetime.now(timezone.utc)
            self._execute_locust_load_test()
            end_time = datetime.now(timezone.utc)
            
            # Stop monitoring
            self._stop_monitoring_thread()
            self.metrics_collector.stop_collection()
            
            # Analyze results
            performance_stats = self.metrics_collector.calculate_performance_statistics()
            baseline_comparison = self.metrics_collector.validate_against_baseline()
            
            # Generate comprehensive result
            result = self._create_load_test_result(
                test_id, start_time, end_time, performance_stats, baseline_comparison
            )
            
            # Generate reports
            self._generate_comprehensive_reports(result)
            
            # Send alerts if configured
            if self.config.enable_real_time_alerts and result.alerts_triggered:
                self._send_performance_alerts(result)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info("Load test execution completed", 
                               test_id=test_id,
                               success=result.is_successful(),
                               performance_compliant=result.performance_compliance)
            
            return result
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Load test execution failed", 
                                test_id=test_id, 
                                error=str(e))
            raise
        
        finally:
            self._cleanup_test_resources()
    
    def _generate_test_id(self) -> str:
        """Generate unique test identifier with timestamp."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"load_test_{timestamp}"
    
    def _validate_test_environment(self) -> None:
        """Validate that the test environment is ready for load testing."""
        # Check Flask application availability
        try:
            response = requests.get(f"{self.config.host}/api/v1/health/status", timeout=10)
            if response.status_code != 200:
                raise RuntimeError(f"Flask application not healthy: {response.status_code}")
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Flask application at {self.config.host}: {str(e)}")
        
        # Validate Locust file availability
        locust_file = Path(__file__).parent / "locustfile.py"
        if not locust_file.exists():
            raise RuntimeError(f"Locustfile not found: {locust_file}")
        
        # Check system resources
        import psutil
        available_memory = psutil.virtual_memory().available / (1024 * 1024)  # MB
        if available_memory < 1024:  # Less than 1GB
            self.logger.warning("Low available memory for load testing", 
                              available_memory_mb=available_memory)
    
    def _execute_locust_load_test(self) -> None:
        """Execute Locust load test with progressive scaling."""
        locust_file = Path(__file__).parent / "locustfile.py"
        
        # Prepare Locust command
        locust_cmd = [
            "locust",
            "-f", str(locust_file),
            "--host", self.config.host,
            "--users", str(self.config.max_users),
            "--spawn-rate", str(self.config.spawn_rate),
            "--run-time", f"{self.config.test_duration}s",
            "--html", str(self.report_dir / "locust_report.html"),
            "--csv", str(self.report_dir / "locust_data"),
            "--headless",
            "--only-summary"
        ]
        
        # Add CSV export for detailed analysis
        locust_cmd.extend([
            "--csv-full-history",
            "--print-stats"
        ])
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Executing Locust load test", command=" ".join(locust_cmd))
        
        # Execute Locust process
        try:
            self.locust_process = subprocess.Popen(
                locust_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor process output
            self._monitor_locust_process()
            
            # Wait for completion
            stdout, stderr = self.locust_process.communicate()
            
            if self.locust_process.returncode != 0:
                raise RuntimeError(f"Locust execution failed: {stderr}")
            
        except Exception as e:
            if self.locust_process:
                self.locust_process.terminate()
            raise RuntimeError(f"Failed to execute Locust load test: {str(e)}")
    
    def _monitor_locust_process(self) -> None:
        """Monitor Locust process output for real-time metrics."""
        if not self.locust_process:
            return
        
        while self.locust_process.poll() is None:
            try:
                output = self.locust_process.stdout.readline()
                if output:
                    # Parse Locust output for metrics
                    self._parse_locust_output(output.strip())
                time.sleep(1)
            except Exception as e:
                if STRUCTLOG_AVAILABLE:
                    self.logger.warning("Error monitoring Locust output", error=str(e))
                break
    
    def _parse_locust_output(self, output: str) -> None:
        """Parse Locust output for real-time metrics extraction."""
        # Parse current user count
        if "users:" in output.lower():
            try:
                # Extract user count from Locust output
                parts = output.split()
                for i, part in enumerate(parts):
                    if "users" in part.lower() and i > 0:
                        user_count = int(parts[i-1])
                        self.metrics_collector.record_concurrent_users(user_count)
                        break
            except (ValueError, IndexError):
                pass
        
        # Parse RPS if available
        if "rps:" in output.lower() or "requests/s" in output.lower():
            try:
                # Extract RPS from Locust output
                parts = output.split()
                for i, part in enumerate(parts):
                    if "rps" in part.lower() or "requests/s" in part.lower():
                        if i > 0:
                            rps = float(parts[i-1])
                            self.metrics_collector.record_throughput(rps)
                            break
            except (ValueError, IndexError):
                pass
    
    def _start_monitoring_thread(self) -> None:
        """Start background monitoring thread for system resource tracking."""
        self.monitoring_thread = threading.Thread(target=self._monitor_system_resources)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
    
    def _stop_monitoring_thread(self) -> None:
        """Stop background monitoring thread."""
        self.shutdown_requested = True
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5.0)
    
    def _monitor_system_resources(self) -> None:
        """Monitor system resources during load testing."""
        import psutil
        
        while not self.shutdown_requested:
            try:
                # Collect CPU and memory usage
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                memory_mb = memory_info.used / (1024 * 1024)
                
                self.metrics_collector.record_resource_utilization(cpu_percent, memory_mb)
                
                # Sleep before next collection
                time.sleep(5)
                
            except Exception as e:
                if STRUCTLOG_AVAILABLE:
                    self.logger.warning("Error collecting system metrics", error=str(e))
                time.sleep(10)
    
    def _create_load_test_result(self, test_id: str, start_time: datetime, 
                                end_time: datetime, performance_stats: Dict[str, Any],
                                baseline_comparison: Dict[str, Any]) -> LoadTestResult:
        """Create comprehensive LoadTestResult from collected metrics."""
        
        # Extract key metrics from performance stats
        response_metrics = performance_stats.get("response_time_metrics", {})
        request_metrics = performance_stats.get("request_metrics", {})
        throughput_metrics = performance_stats.get("throughput_metrics", {})
        concurrent_metrics = performance_stats.get("concurrent_user_metrics", {})
        
        # Calculate variance analysis
        variance_analysis = {}
        if baseline_comparison and "variance_analysis" in baseline_comparison:
            for metric, analysis in baseline_comparison["variance_analysis"].items():
                variance_analysis[metric] = analysis.get("variance_percent", 0.0)
        
        # Generate recommendations
        recommendations = self._generate_performance_recommendations(
            performance_stats, baseline_comparison
        )
        
        result = LoadTestResult(
            test_id=test_id,
            configuration=self.config,
            start_time=start_time,
            end_time=end_time,
            total_duration=(end_time - start_time).total_seconds(),
            total_requests=request_metrics.get("total_requests", 0),
            successful_requests=request_metrics.get("successful_requests", 0),
            failed_requests=request_metrics.get("failed_requests", 0),
            error_rate_percent=request_metrics.get("error_rate_percent", 0.0),
            average_response_time_ms=response_metrics.get("mean_response_time_ms", 0.0),
            median_response_time_ms=response_metrics.get("median_response_time_ms", 0.0),
            p95_response_time_ms=response_metrics.get("p95_response_time_ms", 0.0),
            p99_response_time_ms=response_metrics.get("p99_response_time_ms", 0.0),
            max_response_time_ms=response_metrics.get("max_response_time_ms", 0.0),
            min_response_time_ms=response_metrics.get("min_response_time_ms", 0.0),
            requests_per_second=throughput_metrics.get("average_rps", 0.0),
            peak_rps=throughput_metrics.get("peak_rps", 0.0),
            concurrent_users_achieved=concurrent_metrics.get("max_concurrent_users", 0),
            baseline_comparison=baseline_comparison,
            endpoint_performance=performance_stats.get("endpoint_performance_metrics", {}),
            resource_utilization=performance_stats.get("resource_utilization_metrics", {}),
            variance_analysis=variance_analysis,
            alerts_triggered=self.metrics_collector.alerts_triggered,
            recommendations=recommendations
        )
        
        return result
    
    def _generate_performance_recommendations(self, performance_stats: Dict[str, Any],
                                            baseline_comparison: Dict[str, Any]) -> List[str]:
        """Generate performance optimization recommendations based on test results."""
        recommendations = []
        
        # Response time recommendations
        response_metrics = performance_stats.get("response_time_metrics", {})
        p95_response_time = response_metrics.get("p95_response_time_ms", 0)
        
        if p95_response_time > self.config.response_time_threshold:
            recommendations.append(
                f"Response time optimization needed: P95 {p95_response_time:.2f}ms "
                f"exceeds threshold {self.config.response_time_threshold}ms"
            )
        
        if p95_response_time > self.config.response_time_threshold * 1.5:
            recommendations.append(
                "Critical response time issue requires immediate investigation"
            )
        
        # Throughput recommendations
        throughput_metrics = performance_stats.get("throughput_metrics", {})
        avg_rps = throughput_metrics.get("average_rps", 0)
        
        if avg_rps < self.config.target_rps:
            recommendations.append(
                f"Throughput below target: {avg_rps:.2f} RPS < {self.config.target_rps} RPS"
            )
        
        # Error rate recommendations
        request_metrics = performance_stats.get("request_metrics", {})
        error_rate = request_metrics.get("error_rate_percent", 0)
        
        if error_rate > self.config.error_rate_threshold:
            recommendations.append(
                f"Error rate exceeds threshold: {error_rate:.3f}% > {self.config.error_rate_threshold}%"
            )
        
        # Baseline comparison recommendations
        if baseline_comparison and not baseline_comparison.get("overall_compliance", False):
            recommendations.append(
                "Performance regression detected compared to Node.js baseline"
            )
            
            if "variance_analysis" in baseline_comparison:
                for metric, analysis in baseline_comparison["variance_analysis"].items():
                    if not analysis.get("compliant", True):
                        variance = analysis.get("variance_percent", 0)
                        recommendations.append(
                            f"{metric.replace('_', ' ').title()} variance {variance:+.2f}% "
                            f"exceeds {self.config.variance_threshold * 100:.1f}% threshold"
                        )
        
        # Resource utilization recommendations
        resource_metrics = performance_stats.get("resource_utilization_metrics", {})
        if "cpu" in resource_metrics:
            avg_cpu = resource_metrics["cpu"].get("avg_cpu_percent", 0)
            if avg_cpu > 70:
                recommendations.append(
                    f"High CPU utilization: {avg_cpu:.1f}% - consider scaling or optimization"
                )
        
        if "memory" in resource_metrics:
            avg_memory = resource_metrics["memory"].get("avg_memory_mb", 0)
            if avg_memory > 2048:  # > 2GB
                recommendations.append(
                    f"High memory usage: {avg_memory:.1f}MB - investigate memory leaks"
                )
        
        # Add positive recommendations if performance is good
        if not recommendations:
            recommendations.append(
                "Excellent performance! All metrics within acceptable thresholds."
            )
        
        return recommendations
    
    def _generate_comprehensive_reports(self, result: LoadTestResult) -> None:
        """Generate comprehensive performance reports in multiple formats."""
        # JSON detailed report
        json_report_path = self.report_dir / f"{result.test_id}_detailed_report.json"
        with open(json_report_path, 'w') as f:
            json.dump(result.get_summary_dict(), f, indent=2, default=str)
        
        # Markdown summary report
        markdown_report_path = self.report_dir / f"{result.test_id}_summary.md"
        self._generate_markdown_report(result, markdown_report_path)
        
        # CSV performance data
        csv_report_path = self.report_dir / f"{result.test_id}_performance_data.csv"
        self._generate_csv_report(result, csv_report_path)
        
        # CI/CD integration report
        ci_report_path = self.report_dir / f"{result.test_id}_ci_report.json"
        self._generate_ci_integration_report(result, ci_report_path)
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Performance reports generated",
                           json_report=str(json_report_path),
                           markdown_report=str(markdown_report_path),
                           csv_report=str(csv_report_path),
                           ci_report=str(ci_report_path))
    
    def _generate_markdown_report(self, result: LoadTestResult, output_path: Path) -> None:
        """Generate comprehensive markdown performance report."""
        
        # Determine overall status
        status_emoji = "✅" if result.is_successful() else "❌"
        compliance_status = "PASS" if result.performance_compliance.get("variance_compliant", False) else "FAIL"
        
        markdown_content = f"""# Load Test Performance Report

**Test ID:** {result.test_id}  
**Status:** {status_emoji} {compliance_status}  
**Executed:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Duration:** {result.total_duration:.0f} seconds ({result.total_duration/60:.1f} minutes)  

## Executive Summary

{self._generate_executive_summary(result)}

## Performance Metrics

### Response Time Analysis
| Metric | Value | Threshold | Status |
|--------|--------|-----------|--------|
| Average Response Time | {result.average_response_time_ms:.2f}ms | - | ℹ️ |
| Median Response Time | {result.median_response_time_ms:.2f}ms | - | ℹ️ |
| 95th Percentile | {result.p95_response_time_ms:.2f}ms | ≤{result.configuration.response_time_threshold}ms | {'✅' if result.performance_compliance.get('response_time_compliant', False) else '❌'} |
| 99th Percentile | {result.p99_response_time_ms:.2f}ms | - | ℹ️ |
| Max Response Time | {result.max_response_time_ms:.2f}ms | - | ℹ️ |

### Throughput Analysis
| Metric | Value | Threshold | Status |
|--------|--------|-----------|--------|
| Average RPS | {result.requests_per_second:.2f} | ≥{result.configuration.target_rps} | {'✅' if result.performance_compliance.get('throughput_compliant', False) else '❌'} |
| Peak RPS | {result.peak_rps:.2f} | - | ℹ️ |
| Total Requests | {result.total_requests:,} | - | ℹ️ |
| Successful Requests | {result.successful_requests:,} | - | ℹ️ |

### Error Analysis
| Metric | Value | Threshold | Status |
|--------|--------|-----------|--------|
| Failed Requests | {result.failed_requests:,} | - | ℹ️ |
| Error Rate | {result.error_rate_percent:.3f}% | ≤{result.configuration.error_rate_threshold}% | {'✅' if result.performance_compliance.get('error_rate_compliant', False) else '❌'} |
| Success Rate | {(result.successful_requests/result.total_requests)*100:.3f}% | - | ℹ️ |

## Baseline Comparison

"""
        
        # Add baseline comparison section
        if result.baseline_comparison:
            overall_compliance = result.baseline_comparison.get("overall_compliance", False)
            compliance_emoji = "✅" if overall_compliance else "❌"
            
            markdown_content += f"""**Overall Baseline Compliance:** {compliance_emoji} {'PASS' if overall_compliance else 'FAIL'}

### Variance Analysis
| Metric | Current Value | Baseline Value | Variance | Status |
|--------|---------------|----------------|----------|--------|
"""
            
            if "variance_analysis" in result.baseline_comparison:
                for metric, analysis in result.baseline_comparison["variance_analysis"].items():
                    current_val = analysis.get("current_value", 0)
                    baseline_val = analysis.get("baseline_value", 0)
                    variance = analysis.get("variance_percent", 0)
                    compliant = analysis.get("compliant", False)
                    status_emoji = "✅" if compliant else "❌"
                    
                    metric_name = metric.replace('_', ' ').title()
                    markdown_content += f"| {metric_name} | {current_val:.2f} | {baseline_val:.2f} | {variance:+.2f}% | {status_emoji} |\n"
        
        # Add endpoint performance section
        if result.endpoint_performance:
            markdown_content += f"""
## Endpoint Performance Analysis

| Endpoint | Avg Response Time | P95 Response Time | Requests | Error Rate |
|----------|-------------------|-------------------|----------|------------|
"""
            for endpoint, metrics in result.endpoint_performance.items():
                avg_time = metrics.get("avg_response_time_ms", 0)
                p95_time = metrics.get("p95_response_time_ms", 0)
                req_count = metrics.get("request_count", 0)
                error_rate = metrics.get("error_rate_percent", 0)
                
                markdown_content += f"| {endpoint} | {avg_time:.2f}ms | {p95_time:.2f}ms | {req_count:,} | {error_rate:.2f}% |\n"
        
        # Add alerts and recommendations
        if result.alerts_triggered:
            markdown_content += f"""
## ⚠️ Performance Alerts

"""
            for alert in result.alerts_triggered:
                markdown_content += f"- ❌ {alert}\n"
        
        if result.recommendations:
            markdown_content += f"""
## 💡 Recommendations

"""
            for recommendation in result.recommendations:
                markdown_content += f"- {recommendation}\n"
        
        # Add test configuration
        markdown_content += f"""
## Test Configuration

- **Target Users:** {result.configuration.min_users} → {result.configuration.max_users}
- **Spawn Rate:** {result.configuration.spawn_rate} users/second
- **Test Duration:** {result.configuration.test_duration} seconds
- **Target Host:** {result.configuration.host}
- **Performance Variance Threshold:** ≤{result.configuration.variance_threshold * 100:.1f}%

## Quality Gates Summary

| Gate | Status | Details |
|------|--------|---------|
| Response Time | {'✅ PASS' if result.performance_compliance.get('response_time_compliant', False) else '❌ FAIL'} | P95 ≤{result.configuration.response_time_threshold}ms |
| Error Rate | {'✅ PASS' if result.performance_compliance.get('error_rate_compliant', False) else '❌ FAIL'} | ≤{result.configuration.error_rate_threshold}% |
| Throughput | {'✅ PASS' if result.performance_compliance.get('throughput_compliant', False) else '❌ FAIL'} | ≥{result.configuration.target_rps} RPS |
| Variance Compliance | {'✅ PASS' if result.performance_compliance.get('variance_compliant', False) else '❌ FAIL'} | ≤{result.configuration.variance_threshold * 100:.1f}% variance |

**Overall Result:** {status_emoji} {'SUCCESS' if result.is_successful() else 'FAILURE'}
"""
        
        # Write markdown content
        with open(output_path, 'w') as f:
            f.write(markdown_content)
    
    def _generate_executive_summary(self, result: LoadTestResult) -> str:
        """Generate executive summary of load test results."""
        if result.is_successful():
            summary = f"""✅ **Load test completed successfully!** The Flask application demonstrates excellent performance characteristics with all quality gates satisfied.

**Key Achievements:**
- Response time P95: {result.p95_response_time_ms:.2f}ms (≤{result.configuration.response_time_threshold}ms threshold)
- Throughput: {result.requests_per_second:.2f} RPS (≥{result.configuration.target_rps} RPS target)  
- Error rate: {result.error_rate_percent:.3f}% (≤{result.configuration.error_rate_threshold}% threshold)
- Concurrent users: {result.concurrent_users_achieved} users successfully handled
"""
            
            if result.baseline_comparison and result.baseline_comparison.get("overall_compliance", False):
                summary += f"- **Baseline compliance:** ✅ Within {result.configuration.variance_threshold * 100:.1f}% variance of Node.js performance"
        else:
            summary = f"""❌ **Load test identified performance issues requiring attention.** The Flask application needs optimization to meet production readiness criteria.

**Critical Issues:**
"""
            if not result.performance_compliance.get("response_time_compliant", False):
                summary += f"- Response time P95: {result.p95_response_time_ms:.2f}ms exceeds {result.configuration.response_time_threshold}ms threshold\n"
            
            if not result.performance_compliance.get("error_rate_compliant", False):
                summary += f"- Error rate: {result.error_rate_percent:.3f}% exceeds {result.configuration.error_rate_threshold}% threshold\n"
            
            if not result.performance_compliance.get("throughput_compliant", False):
                summary += f"- Throughput: {result.requests_per_second:.2f} RPS below {result.configuration.target_rps} RPS target\n"
            
            if not result.performance_compliance.get("variance_compliant", False):
                summary += f"- Baseline variance exceeds {result.configuration.variance_threshold * 100:.1f}% threshold\n"
        
        return summary
    
    def _generate_csv_report(self, result: LoadTestResult, output_path: Path) -> None:
        """Generate CSV performance data for analysis."""
        import csv
        
        # Prepare CSV data
        csv_data = []
        
        # Add summary metrics
        csv_data.append([
            "test_id", "timestamp", "metric_type", "metric_name", "value", "unit", "threshold", "compliant"
        ])
        
        timestamp = result.start_time.isoformat()
        
        # Response time metrics
        csv_data.extend([
            [result.test_id, timestamp, "response_time", "average", result.average_response_time_ms, "ms", "", ""],
            [result.test_id, timestamp, "response_time", "p95", result.p95_response_time_ms, "ms", result.configuration.response_time_threshold, result.performance_compliance.get("response_time_compliant", False)],
            [result.test_id, timestamp, "response_time", "p99", result.p99_response_time_ms, "ms", "", ""],
            [result.test_id, timestamp, "response_time", "max", result.max_response_time_ms, "ms", "", ""]
        ])
        
        # Throughput metrics
        csv_data.extend([
            [result.test_id, timestamp, "throughput", "average_rps", result.requests_per_second, "rps", result.configuration.target_rps, result.performance_compliance.get("throughput_compliant", False)],
            [result.test_id, timestamp, "throughput", "peak_rps", result.peak_rps, "rps", "", ""]
        ])
        
        # Error metrics
        csv_data.extend([
            [result.test_id, timestamp, "error", "total_requests", result.total_requests, "count", "", ""],
            [result.test_id, timestamp, "error", "failed_requests", result.failed_requests, "count", "", ""],
            [result.test_id, timestamp, "error", "error_rate", result.error_rate_percent, "percent", result.configuration.error_rate_threshold, result.performance_compliance.get("error_rate_compliant", False)]
        ])
        
        # Baseline comparison metrics
        if result.baseline_comparison and "variance_analysis" in result.baseline_comparison:
            for metric, analysis in result.baseline_comparison["variance_analysis"].items():
                variance = analysis.get("variance_percent", 0)
                compliant = analysis.get("compliant", False)
                csv_data.append([
                    result.test_id, timestamp, "baseline_variance", metric, variance, "percent", 
                    result.configuration.variance_threshold * 100, compliant
                ])
        
        # Write CSV file
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
    
    def _generate_ci_integration_report(self, result: LoadTestResult, output_path: Path) -> None:
        """Generate CI/CD integration report for automated pipeline decisions."""
        ci_report = {
            "test_metadata": {
                "test_id": result.test_id,
                "timestamp": result.start_time.isoformat(),
                "duration_seconds": result.total_duration,
                "configuration": {
                    "min_users": result.configuration.min_users,
                    "max_users": result.configuration.max_users,
                    "test_duration": result.configuration.test_duration,
                    "variance_threshold": result.configuration.variance_threshold
                }
            },
            "quality_gates": {
                "overall_success": result.is_successful(),
                "response_time_gate": {
                    "passed": result.performance_compliance.get("response_time_compliant", False),
                    "threshold": result.configuration.response_time_threshold,
                    "actual": result.p95_response_time_ms,
                    "metric": "p95_response_time_ms"
                },
                "error_rate_gate": {
                    "passed": result.performance_compliance.get("error_rate_compliant", False),
                    "threshold": result.configuration.error_rate_threshold,
                    "actual": result.error_rate_percent,
                    "metric": "error_rate_percent"
                },
                "throughput_gate": {
                    "passed": result.performance_compliance.get("throughput_compliant", False),
                    "threshold": result.configuration.target_rps,
                    "actual": result.requests_per_second,
                    "metric": "requests_per_second"
                },
                "variance_gate": {
                    "passed": result.performance_compliance.get("variance_compliant", False),
                    "threshold": result.configuration.variance_threshold * 100,
                    "baseline_comparison": result.baseline_comparison,
                    "metric": "baseline_variance_percent"
                }
            },
            "pipeline_decision": {
                "deployment_approved": result.is_successful(),
                "requires_manual_review": len(result.alerts_triggered) > 0,
                "critical_issues": result.alerts_triggered,
                "recommendations": result.recommendations
            },
            "performance_summary": {
                "total_requests": result.total_requests,
                "error_rate_percent": result.error_rate_percent,
                "p95_response_time_ms": result.p95_response_time_ms,
                "average_rps": result.requests_per_second,
                "concurrent_users_achieved": result.concurrent_users_achieved
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(ci_report, f, indent=2, default=str)
    
    def _send_performance_alerts(self, result: LoadTestResult) -> None:
        """Send performance alerts via configured notification channels."""
        if not result.alerts_triggered:
            return
        
        # Slack webhook notification
        if self.config.slack_webhook_url:
            self._send_slack_alert(result)
        
        # Push to Prometheus Alertmanager if configured
        if self.config.prometheus_gateway and PROMETHEUS_AVAILABLE:
            self._push_prometheus_alerts(result)
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Performance alerts sent", 
                           alert_count=len(result.alerts_triggered),
                           test_id=result.test_id)
    
    def _send_slack_alert(self, result: LoadTestResult) -> None:
        """Send performance alert to Slack webhook."""
        try:
            status_emoji = "✅" if result.is_successful() else "❌"
            color = "good" if result.is_successful() else "danger"
            
            slack_payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"{status_emoji} Load Test Performance Alert",
                        "fields": [
                            {
                                "title": "Test ID",
                                "value": result.test_id,
                                "short": True
                            },
                            {
                                "title": "Status",
                                "value": "SUCCESS" if result.is_successful() else "FAILURE",
                                "short": True
                            },
                            {
                                "title": "P95 Response Time",
                                "value": f"{result.p95_response_time_ms:.2f}ms",
                                "short": True
                            },
                            {
                                "title": "Error Rate",
                                "value": f"{result.error_rate_percent:.3f}%",
                                "short": True
                            },
                            {
                                "title": "Throughput",
                                "value": f"{result.requests_per_second:.2f} RPS",
                                "short": True
                            },
                            {
                                "title": "Alerts Triggered",
                                "value": str(len(result.alerts_triggered)),
                                "short": True
                            }
                        ],
                        "text": "\n".join(result.alerts_triggered) if result.alerts_triggered else "All performance metrics within acceptable thresholds.",
                        "footer": "Flask Migration Load Testing",
                        "ts": int(result.start_time.timestamp())
                    }
                ]
            }
            
            response = requests.post(self.config.slack_webhook_url, json=slack_payload, timeout=10)
            response.raise_for_status()
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Failed to send Slack alert", error=str(e))
    
    def _push_prometheus_alerts(self, result: LoadTestResult) -> None:
        """Push performance metrics to Prometheus Pushgateway."""
        try:
            # Create alert metrics
            from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
            
            registry = CollectorRegistry()
            
            # Performance alert gauge
            alert_gauge = Gauge(
                'load_test_performance_alert',
                'Load test performance alert indicator',
                ['test_id', 'alert_type'],
                registry=registry
            )
            
            # Set alert metrics
            for alert in result.alerts_triggered:
                alert_type = "response_time" if "response time" in alert.lower() else "error_rate"
                alert_gauge.labels(test_id=result.test_id, alert_type=alert_type).set(1)
            
            # Push to gateway
            push_to_gateway(self.config.prometheus_gateway, job='load_test_alerts', registry=registry)
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Failed to push Prometheus alerts", error=str(e))
    
    def _cleanup_test_resources(self) -> None:
        """Clean up test resources and temporary files."""
        try:
            # Terminate Locust process if still running
            if self.locust_process and self.locust_process.poll() is None:
                self.locust_process.terminate()
                self.locust_process.wait(timeout=10)
        
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning("Error during test cleanup", error=str(e))


# Pytest fixtures and test functions

@pytest.fixture(scope="module")
def load_test_config() -> LoadTestConfiguration:
    """
    Pytest fixture providing load test configuration.
    
    Configures test parameters based on environment variables and test context
    per Section 6.6.2 CI/CD integration requirements.
    """
    config = LoadTestConfiguration(
        min_users=int(os.getenv("LOAD_TEST_MIN_USERS", DEFAULT_MIN_USERS)),
        max_users=int(os.getenv("LOAD_TEST_MAX_USERS", DEFAULT_MAX_USERS)),
        spawn_rate=float(os.getenv("LOAD_TEST_SPAWN_RATE", DEFAULT_SPAWN_RATE)),
        test_duration=int(os.getenv("LOAD_TEST_DURATION", DEFAULT_TEST_DURATION)),
        host=os.getenv("LOAD_TEST_HOST", DEFAULT_HOST),
        target_rps=float(os.getenv("LOAD_TEST_TARGET_RPS", DEFAULT_TARGET_RPS)),
        response_time_threshold=float(os.getenv("LOAD_TEST_RESPONSE_THRESHOLD", DEFAULT_RESPONSE_TIME_THRESHOLD)),
        error_rate_threshold=float(os.getenv("LOAD_TEST_ERROR_THRESHOLD", DEFAULT_ERROR_RATE_THRESHOLD)),
        enable_monitoring=os.getenv("LOAD_TEST_ENABLE_MONITORING", "true").lower() == "true",
        enable_real_time_alerts=os.getenv("LOAD_TEST_ENABLE_ALERTS", "true").lower() == "true",
        prometheus_gateway=os.getenv("PROMETHEUS_PUSHGATEWAY_URL"),
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL")
    )
    
    # Adjust for CI/CD environment
    if os.getenv("CI") == "true":
        # Reduce test duration for CI/CD pipeline
        config.test_duration = min(config.test_duration, 600)  # Max 10 minutes in CI
        config.max_users = min(config.max_users, 100)  # Max 100 users in CI
    
    return config


@pytest.fixture
def flask_app_health_check(load_test_config: LoadTestConfiguration):
    """
    Pytest fixture ensuring Flask application is healthy before load testing.
    
    Validates application availability and basic functionality per Section 4.6.3
    pre-test environment validation requirements.
    """
    try:
        # Health check with retries
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = requests.get(f"{load_test_config.host}/api/v1/health/status", timeout=10)
                if response.status_code == 200:
                    break
            except (RequestException, Timeout, ConnectionError):
                if attempt == max_retries - 1:
                    raise
                time.sleep(2)
        
        # Basic API functionality check
        auth_response = requests.post(
            f"{load_test_config.host}/api/v1/auth/login",
            json={"username": "test@example.com", "password": "test_password"},
            timeout=10
        )
        
        # Note: This may return 401 which is expected for test credentials
        # We just want to ensure the endpoint is responding
        assert auth_response.status_code in [200, 401, 400], f"Auth endpoint not responding properly: {auth_response.status_code}"
        
        yield True
        
    except Exception as e:
        pytest.skip(f"Flask application not available for load testing: {str(e)}")


class TestLoadTesting:
    """
    Comprehensive load testing test class implementing Section 4.6.3 requirements.
    
    Provides progressive scaling validation, baseline comparison, performance
    regression detection, and automated compliance validation per technical
    specification requirements.
    """
    
    def test_progressive_user_scaling_validation(self, load_test_config: LoadTestConfiguration,
                                               flask_app_health_check) -> None:
        """
        Test progressive user scaling from 10 to 1000 concurrent users per Section 4.6.3.
        
        Validates that the Flask application can handle progressive load increases
        while maintaining performance within acceptable thresholds.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure for progressive scaling test
        scaling_config = LoadTestConfiguration(
            min_users=10,
            max_users=100,  # Reduced for test efficiency
            spawn_rate=2,
            test_duration=300,  # 5 minutes for test
            host=load_test_config.host,
            target_rps=50,  # Adjusted for smaller scale
            response_time_threshold=load_test_config.response_time_threshold,
            error_rate_threshold=load_test_config.error_rate_threshold,
            report_output_dir=str(Path(load_test_config.report_output_dir) / "progressive_scaling")
        )
        
        orchestrator = LoadTestOrchestrator(scaling_config)
        result = orchestrator.execute_load_test()
        
        # Validate progressive scaling success
        assert result.concurrent_users_achieved >= scaling_config.min_users, \
            f"Failed to achieve minimum concurrent users: {result.concurrent_users_achieved} < {scaling_config.min_users}"
        
        assert result.total_requests > 0, "No requests were executed during progressive scaling test"
        
        # Validate performance compliance
        assert result.p95_response_time_ms <= scaling_config.response_time_threshold, \
            f"Response time threshold exceeded: {result.p95_response_time_ms}ms > {scaling_config.response_time_threshold}ms"
        
        assert result.error_rate_percent <= scaling_config.error_rate_threshold, \
            f"Error rate threshold exceeded: {result.error_rate_percent}% > {scaling_config.error_rate_threshold}%"
        
        # Log test results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_progressive_scaling")
            logger.info("Progressive scaling test completed",
                       test_id=result.test_id,
                       concurrent_users_achieved=result.concurrent_users_achieved,
                       p95_response_time_ms=result.p95_response_time_ms,
                       error_rate_percent=result.error_rate_percent,
                       success=result.is_successful())
    
    def test_baseline_performance_comparison(self, load_test_config: LoadTestConfiguration,
                                           flask_app_health_check) -> None:
        """
        Test baseline performance comparison with Node.js implementation per Section 0.3.2.
        
        Validates that Flask implementation maintains ≤10% performance variance
        compared to the Node.js baseline metrics.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure for baseline comparison test
        baseline_config = LoadTestConfiguration(
            min_users=50,
            max_users=200,
            spawn_rate=5,
            test_duration=600,  # 10 minutes for reliable baseline comparison
            host=load_test_config.host,
            target_rps=load_test_config.target_rps,
            response_time_threshold=load_test_config.response_time_threshold,
            error_rate_threshold=load_test_config.error_rate_threshold,
            variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD / 100.0,
            report_output_dir=str(Path(load_test_config.report_output_dir) / "baseline_comparison")
        )
        
        orchestrator = LoadTestOrchestrator(baseline_config)
        result = orchestrator.execute_load_test()
        
        # Validate baseline comparison
        assert result.baseline_comparison, "Baseline comparison data not available"
        
        baseline_compliance = result.baseline_comparison.get("overall_compliance", False)
        assert baseline_compliance, \
            f"Baseline performance variance exceeds {baseline_config.variance_threshold * 100:.1f}% threshold"
        
        # Validate specific variance metrics
        if "variance_analysis" in result.baseline_comparison:
            for metric, analysis in result.baseline_comparison["variance_analysis"].items():
                variance = analysis.get("variance_percent", 0)
                compliant = analysis.get("compliant", False)
                
                assert compliant, \
                    f"{metric} variance {variance:+.2f}% exceeds {baseline_config.variance_threshold * 100:.1f}% threshold"
        
        # Ensure no critical performance alerts
        critical_alerts = [alert for alert in result.alerts_triggered if "critical" in alert.lower()]
        assert len(critical_alerts) == 0, f"Critical performance alerts detected: {critical_alerts}"
        
        # Log baseline comparison results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_baseline_comparison")
            logger.info("Baseline comparison test completed",
                       test_id=result.test_id,
                       baseline_compliance=baseline_compliance,
                       variance_analysis=result.baseline_comparison.get("variance_analysis", {}),
                       alerts_triggered=len(result.alerts_triggered))
    
    def test_sustained_load_endurance(self, load_test_config: LoadTestConfiguration,
                                    flask_app_health_check) -> None:
        """
        Test sustained load endurance per Section 4.6.3 30-minute requirement.
        
        Validates that the Flask application can maintain consistent performance
        under sustained load for extended periods without degradation.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure for endurance test
        endurance_config = LoadTestConfiguration(
            min_users=100,
            max_users=100,  # Constant load
            spawn_rate=10,  # Quick ramp-up
            test_duration=1800,  # 30 minutes sustained load per Section 4.6.3
            host=load_test_config.host,
            target_rps=load_test_config.target_rps,
            response_time_threshold=load_test_config.response_time_threshold,
            error_rate_threshold=load_test_config.error_rate_threshold,
            steady_state_time=1500,  # 25 minutes steady state
            report_output_dir=str(Path(load_test_config.report_output_dir) / "endurance_testing")
        )
        
        # Reduce duration for CI environments
        if os.getenv("CI") == "true":
            endurance_config.test_duration = 600  # 10 minutes in CI
            endurance_config.steady_state_time = 480  # 8 minutes steady state
        
        orchestrator = LoadTestOrchestrator(endurance_config)
        result = orchestrator.execute_load_test()
        
        # Validate endurance test success
        assert result.total_duration >= endurance_config.steady_state_time, \
            f"Test duration {result.total_duration}s insufficient for endurance validation"
        
        # Validate sustained performance
        assert result.requests_per_second >= endurance_config.target_rps * 0.9, \
            f"Sustained throughput below target: {result.requests_per_second} < {endurance_config.target_rps * 0.9} RPS"
        
        assert result.error_rate_percent <= endurance_config.error_rate_threshold, \
            f"Error rate exceeded during sustained load: {result.error_rate_percent}% > {endurance_config.error_rate_threshold}%"
        
        # Validate no performance degradation alerts
        degradation_alerts = [alert for alert in result.alerts_triggered 
                            if "degradation" in alert.lower() or "critical" in alert.lower()]
        assert len(degradation_alerts) == 0, f"Performance degradation detected: {degradation_alerts}"
        
        # Log endurance test results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_endurance")
            logger.info("Endurance test completed",
                       test_id=result.test_id,
                       duration_seconds=result.total_duration,
                       sustained_rps=result.requests_per_second,
                       error_rate_percent=result.error_rate_percent,
                       success=result.is_successful())
    
    def test_peak_load_capacity_validation(self, load_test_config: LoadTestConfiguration,
                                         flask_app_health_check) -> None:
        """
        Test peak load capacity validation per Section 4.6.3 1000 user requirement.
        
        Validates that the Flask application can handle peak concurrent user
        loads while maintaining acceptable performance characteristics.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure for peak load test
        peak_config = LoadTestConfiguration(
            min_users=500,
            max_users=1000,  # Peak load per Section 4.6.3
            spawn_rate=10,
            test_duration=900,  # 15 minutes at peak
            host=load_test_config.host,
            target_rps=load_test_config.target_rps * 2,  # Higher target for peak
            response_time_threshold=load_test_config.response_time_threshold * 1.5,  # Relaxed for peak
            error_rate_threshold=load_test_config.error_rate_threshold * 2,  # Relaxed for peak
            report_output_dir=str(Path(load_test_config.report_output_dir) / "peak_capacity")
        )
        
        # Reduce scale for CI environments
        if os.getenv("CI") == "true":
            peak_config.max_users = 200
            peak_config.test_duration = 300
            peak_config.target_rps = load_test_config.target_rps
        
        orchestrator = LoadTestOrchestrator(peak_config)
        result = orchestrator.execute_load_test()
        
        # Validate peak capacity handling
        expected_min_users = peak_config.max_users * 0.8  # At least 80% of target
        assert result.concurrent_users_achieved >= expected_min_users, \
            f"Failed to achieve minimum peak capacity: {result.concurrent_users_achieved} < {expected_min_users}"
        
        # Validate system stability under peak load
        assert result.total_requests > 0, "No requests processed during peak load test"
        
        # Allow higher error rates at peak load but ensure system doesn't crash
        max_acceptable_error_rate = 5.0  # 5% maximum at peak load
        assert result.error_rate_percent <= max_acceptable_error_rate, \
            f"Excessive error rate at peak load: {result.error_rate_percent}% > {max_acceptable_error_rate}%"
        
        # Ensure response times don't become completely unreasonable
        max_acceptable_p95 = peak_config.response_time_threshold * 2
        assert result.p95_response_time_ms <= max_acceptable_p95, \
            f"Response times too high at peak load: {result.p95_response_time_ms}ms > {max_acceptable_p95}ms"
        
        # Log peak capacity results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_peak_capacity")
            logger.info("Peak capacity test completed",
                       test_id=result.test_id,
                       peak_users_achieved=result.concurrent_users_achieved,
                       peak_rps=result.peak_rps,
                       p95_response_time_ms=result.p95_response_time_ms,
                       error_rate_percent=result.error_rate_percent)
    
    @pytest.mark.parametrize("test_scenario", [
        "api_read_heavy",
        "api_write_heavy", 
        "mixed_workload",
        "authentication_focused"
    ])
    def test_scenario_specific_performance(self, test_scenario: str,
                                         load_test_config: LoadTestConfiguration,
                                         flask_app_health_check) -> None:
        """
        Test scenario-specific performance validation per Section 4.6.3 user behavior simulation.
        
        Validates performance across different usage patterns including read-heavy,
        write-heavy, mixed workloads, and authentication-focused scenarios.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure scenario-specific test parameters
        scenario_configs = {
            "api_read_heavy": {
                "users": 150,
                "duration": 600,
                "target_rps": load_test_config.target_rps * 1.5,
                "response_threshold": load_test_config.response_time_threshold * 0.8
            },
            "api_write_heavy": {
                "users": 100,
                "duration": 600,
                "target_rps": load_test_config.target_rps * 0.7,
                "response_threshold": load_test_config.response_time_threshold * 1.2
            },
            "mixed_workload": {
                "users": 200,
                "duration": 900,
                "target_rps": load_test_config.target_rps,
                "response_threshold": load_test_config.response_time_threshold
            },
            "authentication_focused": {
                "users": 100,
                "duration": 600,
                "target_rps": load_test_config.target_rps * 0.6,
                "response_threshold": load_test_config.response_time_threshold * 1.1
            }
        }
        
        scenario_params = scenario_configs[test_scenario]
        
        # Reduce for CI environment
        if os.getenv("CI") == "true":
            scenario_params["users"] = min(scenario_params["users"], 50)
            scenario_params["duration"] = min(scenario_params["duration"], 300)
        
        scenario_config = LoadTestConfiguration(
            min_users=scenario_params["users"] // 2,
            max_users=scenario_params["users"],
            spawn_rate=5,
            test_duration=scenario_params["duration"],
            host=load_test_config.host,
            target_rps=scenario_params["target_rps"],
            response_time_threshold=scenario_params["response_threshold"],
            error_rate_threshold=load_test_config.error_rate_threshold,
            report_output_dir=str(Path(load_test_config.report_output_dir) / f"scenario_{test_scenario}")
        )
        
        orchestrator = LoadTestOrchestrator(scenario_config)
        result = orchestrator.execute_load_test()
        
        # Validate scenario-specific performance
        assert result.total_requests > 0, f"No requests processed in {test_scenario} scenario"
        
        assert result.requests_per_second >= scenario_config.target_rps * 0.8, \
            f"{test_scenario} throughput below target: {result.requests_per_second} < {scenario_config.target_rps * 0.8}"
        
        assert result.error_rate_percent <= scenario_config.error_rate_threshold, \
            f"{test_scenario} error rate exceeded: {result.error_rate_percent}% > {scenario_config.error_rate_threshold}%"
        
        # Scenario-specific validations
        if test_scenario == "api_read_heavy":
            # Read-heavy workloads should have low response times
            assert result.p95_response_time_ms <= scenario_config.response_time_threshold, \
                f"Read-heavy scenario response time too high: {result.p95_response_time_ms}ms"
        
        elif test_scenario == "authentication_focused":
            # Authentication scenarios should have minimal errors
            assert result.error_rate_percent <= 0.5, \
                f"Authentication errors too high: {result.error_rate_percent}%"
        
        # Log scenario test results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_scenario_performance")
            logger.info("Scenario performance test completed",
                       scenario=test_scenario,
                       test_id=result.test_id,
                       requests_per_second=result.requests_per_second,
                       p95_response_time_ms=result.p95_response_time_ms,
                       error_rate_percent=result.error_rate_percent,
                       success=result.is_successful())
    
    def test_performance_regression_detection(self, load_test_config: LoadTestConfiguration,
                                            flask_app_health_check) -> None:
        """
        Test performance regression detection per Section 0.3.2 monitoring requirements.
        
        Validates that the automated performance monitoring system can detect
        performance regressions and trigger appropriate alerts.
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust framework not available")
        
        # Configure for regression detection test
        regression_config = LoadTestConfiguration(
            min_users=100,
            max_users=100,
            spawn_rate=10,
            test_duration=300,  # 5 minutes
            host=load_test_config.host,
            target_rps=load_test_config.target_rps,
            response_time_threshold=load_test_config.response_time_threshold,
            error_rate_threshold=load_test_config.error_rate_threshold,
            variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD / 100.0,
            enable_real_time_alerts=True,
            report_output_dir=str(Path(load_test_config.report_output_dir) / "regression_detection")
        )
        
        orchestrator = LoadTestOrchestrator(regression_config)
        result = orchestrator.execute_load_test()
        
        # Validate regression detection functionality
        assert result.baseline_comparison is not None, "Baseline comparison not performed"
        
        # Check that variance analysis is performed
        if "variance_analysis" in result.baseline_comparison:
            variance_metrics = result.baseline_comparison["variance_analysis"]
            assert len(variance_metrics) > 0, "No variance analysis performed"
            
            # Validate that variance is calculated for key metrics
            expected_metrics = ["response_time", "throughput"]
            for metric in expected_metrics:
                found_metric = any(metric in key for key in variance_metrics.keys())
                assert found_metric, f"Variance analysis missing for {metric}"
        
        # Validate alert system functionality
        # Note: We expect no alerts for a healthy system, but system should be capable of detecting them
        if result.alerts_triggered:
            # If alerts are triggered, they should be properly formatted and actionable
            for alert in result.alerts_triggered:
                assert isinstance(alert, str) and len(alert) > 0, "Invalid alert format"
                assert any(keyword in alert.lower() for keyword in ["response", "error", "critical", "threshold"]), \
                    f"Alert lacks performance context: {alert}"
        
        # Validate recommendations are generated
        assert len(result.recommendations) > 0, "No performance recommendations generated"
        
        # Log regression detection results
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger("test_regression_detection")
            logger.info("Regression detection test completed",
                       test_id=result.test_id,
                       baseline_compliance=result.baseline_comparison.get("overall_compliance", False),
                       alerts_triggered=len(result.alerts_triggered),
                       recommendations_count=len(result.recommendations),
                       variance_metrics_analyzed=len(result.baseline_comparison.get("variance_analysis", {})))


# Main execution for standalone testing
if __name__ == "__main__":
    """
    Standalone execution for load testing outside of pytest framework.
    
    Provides command-line interface for manual load test execution with
    configurable parameters per Section 6.6.2 automation requirements.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Flask Migration Load Testing")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Flask application host URL")
    parser.add_argument("--min-users", type=int, default=DEFAULT_MIN_USERS, help="Minimum concurrent users")
    parser.add_argument("--max-users", type=int, default=DEFAULT_MAX_USERS, help="Maximum concurrent users")
    parser.add_argument("--duration", type=int, default=DEFAULT_TEST_DURATION, help="Test duration in seconds")
    parser.add_argument("--spawn-rate", type=float, default=DEFAULT_SPAWN_RATE, help="User spawn rate per second")
    parser.add_argument("--target-rps", type=float, default=DEFAULT_TARGET_RPS, help="Target requests per second")
    parser.add_argument("--report-dir", default="tests/performance/reports", help="Report output directory")
    parser.add_argument("--enable-alerts", action="store_true", help="Enable real-time performance alerts")
    parser.add_argument("--slack-webhook", help="Slack webhook URL for alerts")
    parser.add_argument("--prometheus-gateway", help="Prometheus pushgateway URL")
    
    args = parser.parse_args()
    
    # Create configuration from command line arguments
    config = LoadTestConfiguration(
        min_users=args.min_users,
        max_users=args.max_users,
        spawn_rate=args.spawn_rate,
        test_duration=args.duration,
        host=args.host,
        target_rps=args.target_rps,
        report_output_dir=args.report_dir,
        enable_real_time_alerts=args.enable_alerts,
        slack_webhook_url=args.slack_webhook,
        prometheus_gateway=args.prometheus_gateway
    )
    
    print(f"🚀 Starting Flask Migration Load Test")
    print(f"Host: {config.host}")
    print(f"Users: {config.min_users} → {config.max_users}")
    print(f"Duration: {config.test_duration} seconds ({config.test_duration // 60} minutes)")
    print(f"Target RPS: {config.target_rps}")
    print(f"Reports: {config.report_output_dir}")
    
    try:
        orchestrator = LoadTestOrchestrator(config)
        result = orchestrator.execute_load_test()
        
        print(f"\n📊 Load Test Results:")
        print(f"Test ID: {result.test_id}")
        print(f"Status: {'✅ SUCCESS' if result.is_successful() else '❌ FAILURE'}")
        print(f"Total Requests: {result.total_requests:,}")
        print(f"Error Rate: {result.error_rate_percent:.3f}%")
        print(f"P95 Response Time: {result.p95_response_time_ms:.2f}ms")
        print(f"Average RPS: {result.requests_per_second:.2f}")
        print(f"Peak RPS: {result.peak_rps:.2f}")
        print(f"Concurrent Users: {result.concurrent_users_achieved}")
        
        if result.baseline_comparison:
            compliance = result.baseline_comparison.get("overall_compliance", False)
            print(f"Baseline Compliance: {'✅ PASS' if compliance else '❌ FAIL'}")
        
        if result.alerts_triggered:
            print(f"\n⚠️ Alerts Triggered ({len(result.alerts_triggered)}):")
            for alert in result.alerts_triggered:
                print(f"  - {alert}")
        
        print(f"\n💡 Recommendations ({len(result.recommendations)}):")
        for recommendation in result.recommendations:
            print(f"  - {recommendation}")
        
        print(f"\n📁 Reports generated in: {config.report_output_dir}")
        
        # Exit with appropriate code
        exit(0 if result.is_successful() else 1)
        
    except Exception as e:
        print(f"\n❌ Load test failed: {str(e)}")
        exit(1)