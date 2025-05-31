#!/usr/bin/env python3
"""
Load Testing Orchestration Script for Flask Migration Performance Validation

This comprehensive orchestration script manages Locust and Apache Bench test execution,
coordinates distributed load testing with realistic user behavior simulation, implements
progressive scaling from 10 to 1000 concurrent users, and provides automated performance
monitoring with baseline comparison per technical specification requirements.

Key Features:
- Locust (≥2.x) distributed load testing framework per Section 6.6.1
- Apache Bench integration for HTTP performance measurement per Section 6.6.1
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- 30-minute sustained load testing minimum per Section 4.6.3
- Realistic user behavior simulation and workflow testing per Section 4.6.3
- Distributed load testing coordination per Section 6.6.1
- Automated baseline comparison with ≤10% variance validation per Section 0.1.1
- Comprehensive performance monitoring and alerting per Section 0.3.2
- CI/CD pipeline integration per Section 6.6.2

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 4.6.3: Load testing specifications with progressive user scaling and endurance testing
- Section 6.6.1: Locust ≥2.x performance testing framework with distributed capabilities
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 6.6.2: CI/CD integration with automated performance validation and regression detection

Usage Examples:
    # Basic load test execution
    python orchestrate_load_tests.py --host http://localhost:5000 --users 100 --duration 600

    # Comprehensive endurance testing
    python orchestrate_load_tests.py --endurance --baseline-validation --distributed

    # CI/CD pipeline integration
    python orchestrate_load_tests.py --ci-mode --report-format json

    # Custom scaling configuration
    python orchestrate_load_tests.py --min-users 10 --max-users 1000 --scaling-strategy progressive

Dependencies:
- locust ≥2.x: Distributed load testing framework
- apache-bench: HTTP server performance measurement tool
- pytest ≥7.4+: Test framework for execution validation
- structlog ≥23.1+: Structured logging for comprehensive monitoring
- prometheus-client ≥0.17+: Metrics collection and monitoring integration

Author: Flask Migration Team
Version: 1.0.0
"""

import argparse
import asyncio
import json
import logging
import multiprocessing
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Future, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable, Generator
import shutil
import socket
import uuid

# Core imports
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Performance testing framework imports
try:
    import locust
    from locust import HttpUser, task, between, events
    from locust.env import Environment
    from locust.runners import LocalRunner, MasterRunner, WorkerRunner
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

# Monitoring and metrics imports
try:
    import structlog
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, start_http_server, push_to_gateway
    MONITORING_AVAILABLE = True
except ImportError:
    MONITORING_AVAILABLE = False

# Performance testing module imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from performance_config import (
    BasePerformanceConfig,
    PerformanceConfigFactory,
    LoadTestConfiguration,
    BaselineMetrics,
    PerformanceThreshold,
    LoadTestPhase,
    PerformanceTestType
)

from baseline_data import (
    BaselineDataManager,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD
)

from test_load_testing import (
    LoadTestOrchestrator,
    LoadTestResult,
    LoadTestConfiguration as TestLoadConfig,
    LoadTestMetricsCollector
)

# Configure structured logging
if MONITORING_AVAILABLE:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    logger = structlog.get_logger("load_test_orchestrator")
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("load_test_orchestrator")


# Load testing orchestration constants per Section 4.6.3
DEFAULT_MIN_USERS = 10
DEFAULT_MAX_USERS = 1000
DEFAULT_SPAWN_RATE = 5.0
DEFAULT_TEST_DURATION = 1800  # 30 minutes
DEFAULT_HOST = "http://localhost:5000"
DEFAULT_APACHE_BENCH_REQUESTS = 10000
DEFAULT_APACHE_BENCH_CONCURRENCY = 100
DISTRIBUTED_WORKERS_COUNT = 4
PERFORMANCE_REPORT_INTERVAL = 30
HEALTH_CHECK_INTERVAL = 10
VARIANCE_ALERT_THRESHOLD = 8.0  # Alert at 8% variance (before 10% limit)


class LoadTestPhaseType:
    """Load test phase type enumeration for orchestration."""
    PREPARATION = "preparation"
    APACHE_BENCH = "apache_bench"
    LOCUST_WARMUP = "locust_warmup"
    LOCUST_RAMPUP = "locust_rampup"
    LOCUST_SUSTAINED = "locust_sustained"
    LOCUST_PEAK = "locust_peak"
    BASELINE_VALIDATION = "baseline_validation"
    REPORTING = "reporting"
    CLEANUP = "cleanup"


@dataclass
class OrchestrationConfig:
    """
    Comprehensive orchestration configuration for load testing coordination.
    
    Implements Section 4.6.3 load testing specifications with progressive scaling,
    endurance testing, and distributed coordination capabilities.
    """
    # Basic load testing parameters
    host: str = DEFAULT_HOST
    min_users: int = DEFAULT_MIN_USERS
    max_users: int = DEFAULT_MAX_USERS
    spawn_rate: float = DEFAULT_SPAWN_RATE
    test_duration: int = DEFAULT_TEST_DURATION
    
    # Progressive scaling configuration
    scaling_strategy: str = "progressive"  # progressive, immediate, stepped
    ramp_up_duration: int = 300           # 5-minute ramp-up
    steady_state_duration: int = 1200     # 20-minute steady state
    ramp_down_duration: int = 300         # 5-minute ramp-down
    
    # Apache Bench configuration
    apache_bench_enabled: bool = True
    ab_requests: int = DEFAULT_APACHE_BENCH_REQUESTS
    ab_concurrency: int = DEFAULT_APACHE_BENCH_CONCURRENCY
    ab_endpoints: List[str] = None
    
    # Distributed testing configuration
    distributed_mode: bool = False
    worker_count: int = DISTRIBUTED_WORKERS_COUNT
    master_host: str = "localhost"
    master_port: int = 5557
    
    # Test execution modes
    endurance_mode: bool = False
    spike_test_mode: bool = False
    baseline_validation: bool = True
    ci_mode: bool = False
    
    # Monitoring and reporting
    performance_monitoring: bool = True
    real_time_alerts: bool = True
    prometheus_enabled: bool = False
    prometheus_gateway: Optional[str] = None
    report_format: str = "json"  # json, markdown, html, all
    report_output_dir: str = "tests/performance/reports"
    
    # Environment and integration
    environment: str = "testing"
    flask_app_ready_timeout: int = 60
    health_check_endpoint: str = "/health"
    pre_test_validation: bool = True
    post_test_cleanup: bool = True
    
    # Advanced configuration
    user_behavior_simulation: bool = True
    geographic_distribution: bool = True
    realistic_think_time: bool = True
    session_persistence: bool = True
    
    # Failure handling
    max_failure_rate: float = 5.0         # 5% max failure rate
    abort_on_critical_failure: bool = True
    retry_failed_requests: bool = True
    
    def __post_init__(self):
        """Post-initialization configuration validation and setup."""
        if self.ab_endpoints is None:
            self.ab_endpoints = [
                "/health",
                "/api/v1/users",
                "/api/v1/data/reports",
                "/api/v1/auth/login"
            ]
        
        # Adjust configuration for CI mode
        if self.ci_mode:
            self.max_users = min(self.max_users, 200)
            self.test_duration = min(self.test_duration, 900)  # 15 minutes max in CI
            self.distributed_mode = False
            self.real_time_alerts = False
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate orchestration configuration parameters."""
        if self.min_users >= self.max_users:
            raise ValueError("min_users must be less than max_users")
        
        if self.test_duration <= 0:
            raise ValueError("test_duration must be positive")
        
        if self.spawn_rate <= 0:
            raise ValueError("spawn_rate must be positive")
        
        if self.max_failure_rate < 0 or self.max_failure_rate > 100:
            raise ValueError("max_failure_rate must be between 0 and 100")
    
    def get_load_test_config(self) -> LoadTestConfiguration:
        """Convert to LoadTestConfiguration for compatibility."""
        return LoadTestConfiguration(
            min_users=self.min_users,
            max_users=self.max_users,
            user_spawn_rate=self.spawn_rate,
            test_duration=self.test_duration,
            ramp_up_time=self.ramp_up_duration,
            steady_state_time=self.steady_state_duration,
            ramp_down_time=self.ramp_down_duration,
            target_request_rate=100  # Default per Section 4.6.3
        )


@dataclass
class OrchestrationResult:
    """
    Comprehensive orchestration execution results with performance analysis.
    
    Captures all performance metrics, baseline comparisons, and compliance
    validation across all load testing phases per Section 0.3.2 requirements.
    """
    orchestration_id: str
    config: OrchestrationConfig
    start_time: datetime
    end_time: datetime
    total_duration: float
    
    # Phase execution results
    phase_results: Dict[str, Any]
    
    # Apache Bench results
    apache_bench_results: Dict[str, Dict[str, Any]]
    
    # Locust load testing results
    locust_results: Optional[LoadTestResult]
    
    # Performance analysis
    baseline_comparison: Dict[str, Any]
    performance_compliance: Dict[str, bool]
    variance_analysis: Dict[str, float]
    
    # Quality assessment
    overall_success: bool
    critical_issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    
    # Monitoring data
    resource_utilization: Dict[str, Any]
    real_time_metrics: List[Dict[str, Any]]
    alert_history: List[str]
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate comprehensive orchestration summary."""
        return {
            "orchestration_metadata": {
                "orchestration_id": self.orchestration_id,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "total_duration": self.total_duration,
                "configuration": asdict(self.config)
            },
            "execution_summary": {
                "overall_success": self.overall_success,
                "phases_completed": len(self.phase_results),
                "critical_issues_count": len(self.critical_issues),
                "warnings_count": len(self.warnings),
                "recommendations_count": len(self.recommendations)
            },
            "performance_summary": {
                "baseline_compliance": self.baseline_comparison.get("overall_compliance", False),
                "variance_analysis": self.variance_analysis,
                "performance_compliance": self.performance_compliance,
                "apache_bench_summary": self._summarize_apache_bench_results(),
                "locust_summary": self._summarize_locust_results()
            },
            "quality_assessment": {
                "critical_issues": self.critical_issues,
                "warnings": self.warnings,
                "recommendations": self.recommendations,
                "alert_history": self.alert_history
            }
        }
    
    def _summarize_apache_bench_results(self) -> Dict[str, Any]:
        """Summarize Apache Bench results across all endpoints."""
        if not self.apache_bench_results:
            return {}
        
        summary = {
            "endpoints_tested": len(self.apache_bench_results),
            "total_requests": 0,
            "average_response_time": 0,
            "average_throughput": 0,
            "fastest_endpoint": None,
            "slowest_endpoint": None
        }
        
        response_times = []
        throughputs = []
        
        for endpoint, results in self.apache_bench_results.items():
            if "total_requests" in results:
                summary["total_requests"] += results["total_requests"]
            
            if "response_time_mean" in results:
                response_times.append(results["response_time_mean"])
            
            if "requests_per_second" in results:
                throughputs.append(results["requests_per_second"])
        
        if response_times:
            summary["average_response_time"] = statistics.mean(response_times)
            summary["fastest_endpoint"] = min(self.apache_bench_results.items(), 
                                            key=lambda x: x[1].get("response_time_mean", float('inf')))[0]
            summary["slowest_endpoint"] = max(self.apache_bench_results.items(),
                                            key=lambda x: x[1].get("response_time_mean", 0))[0]
        
        if throughputs:
            summary["average_throughput"] = statistics.mean(throughputs)
        
        return summary
    
    def _summarize_locust_results(self) -> Dict[str, Any]:
        """Summarize Locust load testing results."""
        if not self.locust_results:
            return {}
        
        return {
            "total_requests": self.locust_results.total_requests,
            "successful_requests": self.locust_results.successful_requests,
            "error_rate_percent": self.locust_results.error_rate_percent,
            "average_response_time_ms": self.locust_results.average_response_time_ms,
            "p95_response_time_ms": self.locust_results.p95_response_time_ms,
            "requests_per_second": self.locust_results.requests_per_second,
            "peak_rps": self.locust_results.peak_rps,
            "concurrent_users_achieved": self.locust_results.concurrent_users_achieved,
            "test_success": self.locust_results.is_successful()
        }


class LoadTestOrchestrationEngine:
    """
    Enterprise-grade load testing orchestration engine providing comprehensive
    coordination of Locust and Apache Bench testing with distributed execution,
    performance monitoring, and baseline validation per Section 6.6.1 requirements.
    """
    
    def __init__(self, config: OrchestrationConfig):
        self.config = config
        self.orchestration_id = str(uuid.uuid4())[:8]
        self.start_time = None
        self.end_time = None
        
        # Performance monitoring
        self.performance_config = PerformanceConfigFactory.get_config(config.environment)
        self.baseline_manager = default_baseline_manager
        self.metrics_collector = None
        
        # Process management
        self.running_processes = []
        self.monitoring_threads = []
        self.shutdown_requested = False
        
        # Results storage
        self.phase_results = {}
        self.apache_bench_results = {}
        self.locust_results = None
        self.real_time_metrics = []
        self.alert_history = []
        
        # Setup output directories
        self.report_dir = Path(config.report_output_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize monitoring if available
        if MONITORING_AVAILABLE and config.performance_monitoring:
            self._setup_performance_monitoring()
        
        logger.info(
            "Load test orchestration engine initialized",
            orchestration_id=self.orchestration_id,
            config=asdict(config)
        )
    
    def _setup_performance_monitoring(self):
        """Setup performance monitoring infrastructure."""
        if not MONITORING_AVAILABLE:
            return
        
        self.metrics_registry = CollectorRegistry()
        
        # Create orchestration-specific metrics
        self.phase_duration_histogram = Histogram(
            'orchestration_phase_duration_seconds',
            'Duration of orchestration phases',
            ['phase', 'orchestration_id'],
            registry=self.metrics_registry
        )
        
        self.concurrent_users_gauge = Gauge(
            'orchestration_concurrent_users',
            'Current concurrent users across all tests',
            ['orchestration_id'],
            registry=self.metrics_registry
        )
        
        self.error_rate_gauge = Gauge(
            'orchestration_error_rate_percent',
            'Current error rate across all tests',
            ['orchestration_id'],
            registry=self.metrics_registry
        )
        
        self.baseline_variance_gauge = Gauge(
            'orchestration_baseline_variance_percent',
            'Current baseline variance percentage',
            ['metric', 'orchestration_id'],
            registry=self.metrics_registry
        )
        
        logger.info("Performance monitoring setup completed")
    
    def execute_load_testing_orchestration(self) -> OrchestrationResult:
        """
        Execute comprehensive load testing orchestration with all phases.
        
        Coordinates Apache Bench testing, Locust distributed load testing,
        progressive scaling, baseline validation, and comprehensive reporting
        per Section 4.6.3 and Section 6.6.1 requirements.
        
        Returns:
            OrchestrationResult containing complete execution analysis
        """
        self.start_time = datetime.now(timezone.utc)
        
        logger.info(
            "Starting load testing orchestration",
            orchestration_id=self.orchestration_id,
            config=asdict(self.config)
        )
        
        try:
            # Register signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Execute orchestration phases
            self._execute_phase(LoadTestPhaseType.PREPARATION, self._preparation_phase)
            
            if self.config.apache_bench_enabled:
                self._execute_phase(LoadTestPhaseType.APACHE_BENCH, self._apache_bench_phase)
            
            self._execute_phase(LoadTestPhaseType.LOCUST_WARMUP, self._locust_warmup_phase)
            self._execute_phase(LoadTestPhaseType.LOCUST_RAMPUP, self._locust_rampup_phase)
            self._execute_phase(LoadTestPhaseType.LOCUST_SUSTAINED, self._locust_sustained_phase)
            
            if self.config.spike_test_mode:
                self._execute_phase(LoadTestPhaseType.LOCUST_PEAK, self._locust_peak_phase)
            
            if self.config.baseline_validation:
                self._execute_phase(LoadTestPhaseType.BASELINE_VALIDATION, self._baseline_validation_phase)
            
            self._execute_phase(LoadTestPhaseType.REPORTING, self._reporting_phase)
            
            # Generate final results
            result = self._generate_orchestration_result()
            
            logger.info(
                "Load testing orchestration completed successfully",
                orchestration_id=self.orchestration_id,
                success=result.overall_success,
                duration=result.total_duration
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "Load testing orchestration failed",
                orchestration_id=self.orchestration_id,
                error=str(e),
                traceback=traceback.format_exc()
            )
            
            # Generate failure result
            return self._generate_failure_result(str(e))
            
        finally:
            self._execute_phase(LoadTestPhaseType.CLEANUP, self._cleanup_phase)
            self._cleanup_resources()
    
    def _execute_phase(self, phase_type: str, phase_func: Callable) -> None:
        """
        Execute individual orchestration phase with monitoring and error handling.
        
        Args:
            phase_type: Type of phase being executed
            phase_func: Function to execute for this phase
        """
        if self.shutdown_requested:
            logger.warning(f"Skipping phase {phase_type} due to shutdown request")
            return
        
        phase_start = time.time()
        
        logger.info(f"Starting orchestration phase: {phase_type}")
        
        try:
            phase_result = phase_func()
            phase_duration = time.time() - phase_start
            
            self.phase_results[phase_type] = {
                "success": True,
                "duration": phase_duration,
                "result": phase_result,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Record metrics
            if MONITORING_AVAILABLE and hasattr(self, 'phase_duration_histogram'):
                self.phase_duration_histogram.labels(
                    phase=phase_type,
                    orchestration_id=self.orchestration_id
                ).observe(phase_duration)
            
            logger.info(
                f"Orchestration phase completed: {phase_type}",
                duration=phase_duration,
                success=True
            )
            
        except Exception as e:
            phase_duration = time.time() - phase_start
            
            self.phase_results[phase_type] = {
                "success": False,
                "duration": phase_duration,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            logger.error(
                f"Orchestration phase failed: {phase_type}",
                duration=phase_duration,
                error=str(e)
            )
            
            # Decide whether to continue or abort
            if self.config.abort_on_critical_failure and phase_type in [
                LoadTestPhaseType.PREPARATION,
                LoadTestPhaseType.LOCUST_SUSTAINED
            ]:
                raise
    
    def _preparation_phase(self) -> Dict[str, Any]:
        """
        Preparation phase: Environment validation and setup.
        
        Returns:
            Dictionary containing preparation phase results
        """
        preparation_results = {
            "flask_app_health": False,
            "dependencies_available": False,
            "environment_ready": False,
            "baseline_data_loaded": False
        }
        
        # Check Flask application health
        preparation_results["flask_app_health"] = self._validate_flask_application()
        
        # Check dependencies
        preparation_results["dependencies_available"] = self._validate_dependencies()
        
        # Validate environment
        preparation_results["environment_ready"] = self._validate_test_environment()
        
        # Load baseline data
        if self.config.baseline_validation:
            preparation_results["baseline_data_loaded"] = self._load_baseline_data()
        
        # Start monitoring if enabled
        if self.config.performance_monitoring:
            self._start_performance_monitoring()
            preparation_results["monitoring_started"] = True
        
        # Validate all preparation steps
        critical_checks = ["flask_app_health", "dependencies_available", "environment_ready"]
        all_critical_passed = all(preparation_results.get(check, False) for check in critical_checks)
        
        if not all_critical_passed:
            failed_checks = [check for check in critical_checks if not preparation_results.get(check, False)]
            raise RuntimeError(f"Critical preparation checks failed: {failed_checks}")
        
        logger.info("Preparation phase completed successfully", results=preparation_results)
        return preparation_results
    
    def _validate_flask_application(self) -> bool:
        """Validate Flask application health and availability."""
        try:
            # Configure requests session with retries
            session = requests.Session()
            retry_strategy = Retry(
                total=5,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Test basic connectivity
            health_url = f"{self.config.host}{self.config.health_check_endpoint}"
            response = session.get(health_url, timeout=10)
            
            if response.status_code == 200:
                logger.info("Flask application health check passed", url=health_url)
                return True
            else:
                logger.error(
                    "Flask application health check failed",
                    url=health_url,
                    status_code=response.status_code
                )
                return False
                
        except Exception as e:
            logger.error("Flask application validation failed", error=str(e))
            return False
    
    def _validate_dependencies(self) -> bool:
        """Validate required dependencies for load testing."""
        dependencies_status = {
            "locust": LOCUST_AVAILABLE,
            "apache_bench": self._check_apache_bench_availability(),
            "monitoring": MONITORING_AVAILABLE
        }
        
        # Check critical dependencies
        critical_deps = ["locust"]
        if self.config.apache_bench_enabled:
            critical_deps.append("apache_bench")
        
        critical_missing = [dep for dep in critical_deps if not dependencies_status[dep]]
        
        if critical_missing:
            logger.error("Critical dependencies missing", missing=critical_missing)
            return False
        
        logger.info("Dependency validation passed", dependencies=dependencies_status)
        return True
    
    def _check_apache_bench_availability(self) -> bool:
        """Check if Apache Bench is available."""
        try:
            subprocess.run(["ab", "-V"], capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _validate_test_environment(self) -> bool:
        """Validate test environment configuration and resources."""
        try:
            # Check available memory
            import psutil
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            
            if available_memory_gb < 2.0:  # Require at least 2GB
                logger.warning(
                    "Low available memory for load testing",
                    available_gb=available_memory_gb
                )
            
            # Check available disk space
            disk_usage = psutil.disk_usage(str(self.report_dir))
            available_disk_gb = disk_usage.free / (1024**3)
            
            if available_disk_gb < 1.0:  # Require at least 1GB
                logger.error(
                    "Insufficient disk space for reports",
                    available_gb=available_disk_gb
                )
                return False
            
            # Check network connectivity
            test_endpoints = [
                f"{self.config.host}/health",
                f"{self.config.host}/api/v1/users"
            ]
            
            for endpoint in test_endpoints:
                try:
                    response = requests.get(endpoint, timeout=5)
                    # Accept any response (even errors) as connectivity confirmation
                except requests.exceptions.RequestException:
                    logger.warning("Network connectivity issue", endpoint=endpoint)
            
            logger.info("Test environment validation passed")
            return True
            
        except Exception as e:
            logger.error("Test environment validation failed", error=str(e))
            return False
    
    def _load_baseline_data(self) -> bool:
        """Load baseline performance data for comparison."""
        try:
            # Verify baseline data availability
            summary = self.baseline_manager.generate_baseline_summary()
            
            if summary["baseline_data_summary"]["total_response_time_baselines"] == 0:
                logger.warning("No baseline data available for comparison")
                return False
            
            logger.info(
                "Baseline data loaded successfully",
                baseline_summary=summary["baseline_data_summary"]
            )
            return True
            
        except Exception as e:
            logger.error("Failed to load baseline data", error=str(e))
            return False
    
    def _start_performance_monitoring(self) -> None:
        """Start background performance monitoring."""
        if not MONITORING_AVAILABLE:
            return
        
        def monitoring_loop():
            """Background monitoring loop."""
            while not self.shutdown_requested:
                try:
                    # Collect system metrics
                    import psutil
                    
                    metric_data = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cpu_percent": psutil.cpu_percent(interval=1),
                        "memory_percent": psutil.virtual_memory().percent,
                        "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                        "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
                    }
                    
                    self.real_time_metrics.append(metric_data)
                    
                    # Keep only last 1000 metrics to prevent memory issues
                    if len(self.real_time_metrics) > 1000:
                        self.real_time_metrics = self.real_time_metrics[-1000:]
                    
                    time.sleep(PERFORMANCE_REPORT_INTERVAL)
                    
                except Exception as e:
                    logger.warning("Performance monitoring error", error=str(e))
                    time.sleep(30)  # Wait longer on error
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        self.monitoring_threads.append(monitoring_thread)
        
        logger.info("Performance monitoring started")
    
    def _apache_bench_phase(self) -> Dict[str, Any]:
        """
        Apache Bench testing phase for HTTP performance measurement.
        
        Returns:
            Dictionary containing Apache Bench results for all endpoints
        """
        logger.info("Starting Apache Bench testing phase")
        
        ab_results = {}
        
        # Test each configured endpoint
        for endpoint in self.config.ab_endpoints:
            if self.shutdown_requested:
                break
            
            logger.info(f"Running Apache Bench test for endpoint: {endpoint}")
            
            try:
                result = self._run_apache_bench_test(endpoint)
                ab_results[endpoint] = result
                
                # Validate against thresholds
                self._validate_apache_bench_result(endpoint, result)
                
            except Exception as e:
                logger.error(f"Apache Bench test failed for {endpoint}", error=str(e))
                ab_results[endpoint] = {"error": str(e)}
        
        self.apache_bench_results = ab_results
        
        logger.info(
            "Apache Bench testing phase completed",
            endpoints_tested=len(ab_results),
            successful_tests=len([r for r in ab_results.values() if "error" not in r])
        )
        
        return ab_results
    
    def _run_apache_bench_test(self, endpoint: str) -> Dict[str, Any]:
        """
        Execute Apache Bench test for specific endpoint.
        
        Args:
            endpoint: API endpoint to test
            
        Returns:
            Dictionary containing Apache Bench performance results
        """
        url = f"{self.config.host}{endpoint}"
        
        # Prepare Apache Bench command
        cmd = [
            "ab",
            "-n", str(self.config.ab_requests),
            "-c", str(self.config.ab_concurrency),
            "-s", "30",  # 30-second timeout
            "-k",        # Keep-alive
            "-g", "-",   # Generate gnuplot data
            url
        ]
        
        logger.info(
            "Executing Apache Bench command",
            endpoint=endpoint,
            requests=self.config.ab_requests,
            concurrency=self.config.ab_concurrency
        )
        
        try:
            # Execute Apache Bench
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                raise RuntimeError(f"Apache Bench failed: {result.stderr}")
            
            # Parse results
            parsed_results = self._parse_apache_bench_output(result.stdout)
            parsed_results["execution_time"] = execution_time
            parsed_results["endpoint"] = endpoint
            parsed_results["url"] = url
            
            logger.info(
                "Apache Bench test completed",
                endpoint=endpoint,
                requests_per_second=parsed_results.get("requests_per_second", 0),
                response_time_mean=parsed_results.get("response_time_mean", 0)
            )
            
            return parsed_results
            
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Apache Bench test timed out for {endpoint}")
        except Exception as e:
            raise RuntimeError(f"Apache Bench execution failed for {endpoint}: {str(e)}")
    
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
                    
                elif "Time per request:" in line and "across all concurrent requests" in line:
                    parts = line.split()
                    results["response_time_concurrent"] = float(parts[3])
                    
                elif "Transfer rate:" in line:
                    parts = line.split()
                    results["transfer_rate_kbps"] = float(parts[2])
                    
                elif "Complete requests:" in line:
                    parts = line.split()
                    results["total_requests"] = int(parts[2])
                    
                elif "Failed requests:" in line:
                    parts = line.split()
                    results["failed_requests"] = int(parts[2])
                    
                elif "%" in line and "ms" in line and "Percentage" not in line:
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
            
            # Calculate error rate
            total_requests = results.get("total_requests", 0)
            failed_requests = results.get("failed_requests", 0)
            if total_requests > 0:
                results["error_rate_percent"] = (failed_requests / total_requests) * 100.0
            else:
                results["error_rate_percent"] = 0.0
            
        except Exception as e:
            logger.warning("Error parsing Apache Bench output", error=str(e))
        
        return results
    
    def _validate_apache_bench_result(self, endpoint: str, result: Dict[str, Any]) -> None:
        """
        Validate Apache Bench result against performance thresholds.
        
        Args:
            endpoint: Tested endpoint
            result: Apache Bench test results
        """
        # Check response time threshold (500ms per Section 4.6.3)
        response_time = result.get("response_time_mean", 0)
        if response_time > 500:
            warning = f"Apache Bench: {endpoint} response time {response_time:.2f}ms exceeds 500ms threshold"
            self.alert_history.append(warning)
            logger.warning(warning)
        
        # Check throughput threshold (100 RPS minimum per Section 4.6.3)
        rps = result.get("requests_per_second", 0)
        if rps < 100:
            warning = f"Apache Bench: {endpoint} throughput {rps:.2f} RPS below 100 RPS threshold"
            self.alert_history.append(warning)
            logger.warning(warning)
        
        # Check error rate threshold (≤0.1% per Section 4.6.3)
        error_rate = result.get("error_rate_percent", 0)
        if error_rate > 0.1:
            warning = f"Apache Bench: {endpoint} error rate {error_rate:.3f}% exceeds 0.1% threshold"
            self.alert_history.append(warning)
            logger.warning(warning)
    
    def _locust_warmup_phase(self) -> Dict[str, Any]:
        """
        Locust warmup phase with minimal user load.
        
        Returns:
            Dictionary containing warmup phase results
        """
        logger.info("Starting Locust warmup phase")
        
        warmup_config = TestLoadConfig(
            min_users=5,
            max_users=10,
            spawn_rate=2.0,
            test_duration=120,  # 2-minute warmup
            host=self.config.host,
            target_rps=50,
            response_time_threshold=1000,  # Relaxed for warmup
            error_rate_threshold=1.0,      # Relaxed for warmup
            report_output_dir=str(self.report_dir / "warmup")
        )
        
        orchestrator = LoadTestOrchestrator(warmup_config)
        warmup_result = orchestrator.execute_load_test()
        
        logger.info(
            "Locust warmup phase completed",
            success=warmup_result.is_successful(),
            total_requests=warmup_result.total_requests,
            error_rate=warmup_result.error_rate_percent
        )
        
        return {
            "success": warmup_result.is_successful(),
            "total_requests": warmup_result.total_requests,
            "error_rate_percent": warmup_result.error_rate_percent,
            "average_response_time_ms": warmup_result.average_response_time_ms,
            "requests_per_second": warmup_result.requests_per_second
        }
    
    def _locust_rampup_phase(self) -> Dict[str, Any]:
        """
        Locust ramp-up phase with progressive scaling.
        
        Returns:
            Dictionary containing ramp-up phase results
        """
        logger.info("Starting Locust ramp-up phase")
        
        rampup_config = TestLoadConfig(
            min_users=self.config.min_users,
            max_users=self.config.max_users // 2,  # Ramp to 50% of max
            spawn_rate=self.config.spawn_rate,
            test_duration=self.config.ramp_up_duration,
            host=self.config.host,
            target_rps=100,
            response_time_threshold=500,
            error_rate_threshold=0.5,
            report_output_dir=str(self.report_dir / "rampup")
        )
        
        orchestrator = LoadTestOrchestrator(rampup_config)
        rampup_result = orchestrator.execute_load_test()
        
        # Validate ramp-up performance
        if rampup_result.error_rate_percent > 1.0:
            warning = f"Ramp-up error rate {rampup_result.error_rate_percent:.2f}% may indicate scaling issues"
            self.alert_history.append(warning)
            logger.warning(warning)
        
        logger.info(
            "Locust ramp-up phase completed",
            success=rampup_result.is_successful(),
            max_users_achieved=rampup_result.concurrent_users_achieved,
            peak_rps=rampup_result.peak_rps
        )
        
        return {
            "success": rampup_result.is_successful(),
            "max_users_achieved": rampup_result.concurrent_users_achieved,
            "total_requests": rampup_result.total_requests,
            "error_rate_percent": rampup_result.error_rate_percent,
            "peak_rps": rampup_result.peak_rps,
            "p95_response_time_ms": rampup_result.p95_response_time_ms
        }
    
    def _locust_sustained_phase(self) -> Dict[str, Any]:
        """
        Locust sustained load phase per Section 4.6.3 30-minute requirement.
        
        Returns:
            Dictionary containing sustained load phase results
        """
        logger.info("Starting Locust sustained load phase")
        
        sustained_config = TestLoadConfig(
            min_users=self.config.max_users,
            max_users=self.config.max_users,
            spawn_rate=self.config.spawn_rate,
            test_duration=self.config.steady_state_duration,
            host=self.config.host,
            target_rps=100,
            response_time_threshold=500,
            error_rate_threshold=0.1,
            report_output_dir=str(self.report_dir / "sustained")
        )
        
        # Adjust for CI mode
        if self.config.ci_mode:
            sustained_config.test_duration = min(sustained_config.test_duration, 600)  # 10 min max in CI
            sustained_config.max_users = min(sustained_config.max_users, 200)
        
        orchestrator = LoadTestOrchestrator(sustained_config)
        sustained_result = orchestrator.execute_load_test()
        
        # Store main Locust results
        self.locust_results = sustained_result
        
        # Validate sustained load performance
        if sustained_result.error_rate_percent > self.config.max_failure_rate:
            critical_issue = f"Sustained load error rate {sustained_result.error_rate_percent:.2f}% exceeds {self.config.max_failure_rate}% threshold"
            self.alert_history.append(critical_issue)
            logger.error(critical_issue)
        
        # Update real-time metrics
        if MONITORING_AVAILABLE and hasattr(self, 'concurrent_users_gauge'):
            self.concurrent_users_gauge.labels(orchestration_id=self.orchestration_id).set(
                sustained_result.concurrent_users_achieved
            )
            self.error_rate_gauge.labels(orchestration_id=self.orchestration_id).set(
                sustained_result.error_rate_percent
            )
        
        logger.info(
            "Locust sustained load phase completed",
            success=sustained_result.is_successful(),
            duration=sustained_result.total_duration,
            avg_rps=sustained_result.requests_per_second,
            p95_response_time=sustained_result.p95_response_time_ms
        )
        
        return {
            "success": sustained_result.is_successful(),
            "duration": sustained_result.total_duration,
            "total_requests": sustained_result.total_requests,
            "error_rate_percent": sustained_result.error_rate_percent,
            "average_response_time_ms": sustained_result.average_response_time_ms,
            "p95_response_time_ms": sustained_result.p95_response_time_ms,
            "requests_per_second": sustained_result.requests_per_second,
            "concurrent_users_achieved": sustained_result.concurrent_users_achieved
        }
    
    def _locust_peak_phase(self) -> Dict[str, Any]:
        """
        Locust peak load testing phase for spike testing.
        
        Returns:
            Dictionary containing peak load phase results
        """
        logger.info("Starting Locust peak load phase")
        
        peak_users = min(self.config.max_users * 1.5, 1500)  # 150% of max users, capped at 1500
        
        peak_config = TestLoadConfig(
            min_users=self.config.max_users,
            max_users=int(peak_users),
            spawn_rate=self.config.spawn_rate * 2,  # Faster spawn for spike
            test_duration=300,  # 5-minute peak test
            host=self.config.host,
            target_rps=200,     # Higher target for peak
            response_time_threshold=1000,  # Relaxed for peak load
            error_rate_threshold=2.0,      # Relaxed for peak load
            report_output_dir=str(self.report_dir / "peak")
        )
        
        orchestrator = LoadTestOrchestrator(peak_config)
        peak_result = orchestrator.execute_load_test()
        
        logger.info(
            "Locust peak load phase completed",
            success=peak_result.is_successful(),
            peak_users=peak_result.concurrent_users_achieved,
            peak_rps=peak_result.peak_rps,
            error_rate=peak_result.error_rate_percent
        )
        
        return {
            "success": peak_result.is_successful(),
            "peak_users_achieved": peak_result.concurrent_users_achieved,
            "peak_rps": peak_result.peak_rps,
            "total_requests": peak_result.total_requests,
            "error_rate_percent": peak_result.error_rate_percent,
            "p95_response_time_ms": peak_result.p95_response_time_ms
        }
    
    def _baseline_validation_phase(self) -> Dict[str, Any]:
        """
        Baseline validation phase per Section 0.3.2 requirements.
        
        Returns:
            Dictionary containing baseline validation results
        """
        logger.info("Starting baseline validation phase")
        
        if not self.locust_results:
            logger.warning("No Locust results available for baseline validation")
            return {"success": False, "error": "No Locust results for validation"}
        
        try:
            # Prepare current metrics for validation
            current_metrics = {
                "response_time_ms": self.locust_results.average_response_time_ms,
                "requests_per_second": self.locust_results.requests_per_second,
                "error_rate_percent": self.locust_results.error_rate_percent
            }
            
            # Add Apache Bench metrics if available
            if self.apache_bench_results:
                ab_response_times = []
                ab_throughputs = []
                
                for endpoint_result in self.apache_bench_results.values():
                    if "response_time_mean" in endpoint_result:
                        ab_response_times.append(endpoint_result["response_time_mean"])
                    if "requests_per_second" in endpoint_result:
                        ab_throughputs.append(endpoint_result["requests_per_second"])
                
                if ab_response_times:
                    current_metrics["apache_bench_response_time_ms"] = statistics.mean(ab_response_times)
                if ab_throughputs:
                    current_metrics["apache_bench_throughput_rps"] = statistics.mean(ab_throughputs)
            
            # Perform baseline validation
            baseline_comparison = validate_flask_performance_against_baseline(current_metrics)
            
            # Extract variance analysis
            variance_analysis = {}
            if "variance_analysis" in baseline_comparison:
                for metric, analysis in baseline_comparison["variance_analysis"].items():
                    variance_percent = analysis.get("variance_percent", 0)
                    variance_analysis[metric] = variance_percent
                    
                    # Update Prometheus metrics
                    if MONITORING_AVAILABLE and hasattr(self, 'baseline_variance_gauge'):
                        self.baseline_variance_gauge.labels(
                            metric=metric,
                            orchestration_id=self.orchestration_id
                        ).set(abs(variance_percent))
                    
                    # Check variance threshold
                    if abs(variance_percent) > VARIANCE_ALERT_THRESHOLD:
                        alert = f"Baseline variance alert: {metric} {variance_percent:+.2f}% (threshold: ±{VARIANCE_ALERT_THRESHOLD}%)"
                        self.alert_history.append(alert)
                        logger.warning(alert)
            
            logger.info(
                "Baseline validation completed",
                overall_compliance=baseline_comparison.get("overall_compliance", False),
                variance_analysis=variance_analysis
            )
            
            return {
                "success": True,
                "baseline_comparison": baseline_comparison,
                "variance_analysis": variance_analysis,
                "current_metrics": current_metrics,
                "overall_compliance": baseline_comparison.get("overall_compliance", False)
            }
            
        except Exception as e:
            logger.error("Baseline validation failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "baseline_comparison": {},
                "variance_analysis": {},
                "overall_compliance": False
            }
    
    def _reporting_phase(self) -> Dict[str, Any]:
        """
        Generate comprehensive orchestration reports.
        
        Returns:
            Dictionary containing reporting phase results
        """
        logger.info("Starting reporting phase")
        
        try:
            # Generate orchestration result
            result = self._generate_orchestration_result()
            
            # Generate reports in requested formats
            report_paths = {}
            
            if self.config.report_format in ["json", "all"]:
                json_path = self._generate_json_report(result)
                report_paths["json"] = str(json_path)
            
            if self.config.report_format in ["markdown", "all"]:
                md_path = self._generate_markdown_report(result)
                report_paths["markdown"] = str(md_path)
            
            if self.config.report_format in ["html", "all"]:
                html_path = self._generate_html_report(result)
                report_paths["html"] = str(html_path)
            
            # Generate CI/CD integration report
            ci_path = self._generate_ci_report(result)
            report_paths["ci_cd"] = str(ci_path)
            
            logger.info(
                "Reporting phase completed",
                report_paths=report_paths,
                overall_success=result.overall_success
            )
            
            return {
                "success": True,
                "report_paths": report_paths,
                "overall_success": result.overall_success
            }
            
        except Exception as e:
            logger.error("Reporting phase failed", error=str(e))
            return {"success": False, "error": str(e)}
    
    def _cleanup_phase(self) -> Dict[str, Any]:
        """
        Cleanup phase for resource management.
        
        Returns:
            Dictionary containing cleanup phase results
        """
        logger.info("Starting cleanup phase")
        
        cleanup_results = {
            "processes_terminated": 0,
            "threads_stopped": 0,
            "temp_files_cleaned": 0,
            "monitoring_stopped": False
        }
        
        try:
            # Terminate running processes
            for process in self.running_processes:
                try:
                    if process.poll() is None:  # Process still running
                        process.terminate()
                        process.wait(timeout=10)
                        cleanup_results["processes_terminated"] += 1
                except Exception as e:
                    logger.warning(f"Error terminating process: {e}")
            
            # Stop monitoring threads
            self.shutdown_requested = True
            for thread in self.monitoring_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
                    cleanup_results["threads_stopped"] += 1
            
            cleanup_results["monitoring_stopped"] = True
            
            logger.info("Cleanup phase completed", results=cleanup_results)
            return cleanup_results
            
        except Exception as e:
            logger.error("Cleanup phase failed", error=str(e))
            return {"success": False, "error": str(e)}
    
    def _generate_orchestration_result(self) -> OrchestrationResult:
        """Generate comprehensive orchestration result."""
        self.end_time = datetime.now(timezone.utc)
        total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Analyze baseline comparison results
        baseline_comparison = {}
        variance_analysis = {}
        performance_compliance = {}
        
        if LoadTestPhaseType.BASELINE_VALIDATION in self.phase_results:
            baseline_phase = self.phase_results[LoadTestPhaseType.BASELINE_VALIDATION]
            if baseline_phase.get("success", False) and "result" in baseline_phase:
                baseline_comparison = baseline_phase["result"].get("baseline_comparison", {})
                variance_analysis = baseline_phase["result"].get("variance_analysis", {})
        
        # Determine performance compliance
        if self.locust_results:
            performance_compliance = {
                "response_time_compliant": self.locust_results.p95_response_time_ms <= 500,
                "error_rate_compliant": self.locust_results.error_rate_percent <= 0.1,
                "throughput_compliant": self.locust_results.requests_per_second >= 100,
                "variance_compliant": baseline_comparison.get("overall_compliance", False)
            }
        
        # Collect critical issues and warnings
        critical_issues = []
        warnings = []
        recommendations = []
        
        # Check for critical failures
        for phase_name, phase_result in self.phase_results.items():
            if not phase_result.get("success", False):
                critical_issues.append(f"Phase {phase_name} failed: {phase_result.get('error', 'Unknown error')}")
        
        # Check performance issues
        if self.locust_results:
            if self.locust_results.error_rate_percent > self.config.max_failure_rate:
                critical_issues.append(f"Error rate {self.locust_results.error_rate_percent:.2f}% exceeds {self.config.max_failure_rate}% threshold")
            
            if self.locust_results.p95_response_time_ms > 500:
                warnings.append(f"P95 response time {self.locust_results.p95_response_time_ms:.2f}ms exceeds 500ms threshold")
            
            if self.locust_results.requests_per_second < 100:
                warnings.append(f"Throughput {self.locust_results.requests_per_second:.2f} RPS below 100 RPS target")
        
        # Generate recommendations
        if not critical_issues and not warnings:
            recommendations.append("Excellent performance! All metrics within acceptable thresholds.")
        else:
            if critical_issues:
                recommendations.append("Address critical performance issues before deployment.")
            if warnings:
                recommendations.append("Consider performance optimization for improved response times.")
        
        # Determine overall success
        overall_success = (
            len(critical_issues) == 0 and
            all(performance_compliance.values()) if performance_compliance else True
        )
        
        return OrchestrationResult(
            orchestration_id=self.orchestration_id,
            config=self.config,
            start_time=self.start_time,
            end_time=self.end_time,
            total_duration=total_duration,
            phase_results=self.phase_results,
            apache_bench_results=self.apache_bench_results,
            locust_results=self.locust_results,
            baseline_comparison=baseline_comparison,
            performance_compliance=performance_compliance,
            variance_analysis=variance_analysis,
            overall_success=overall_success,
            critical_issues=critical_issues,
            warnings=warnings,
            recommendations=recommendations,
            resource_utilization=self._analyze_resource_utilization(),
            real_time_metrics=self.real_time_metrics,
            alert_history=self.alert_history
        )
    
    def _generate_failure_result(self, error_message: str) -> OrchestrationResult:
        """Generate failure result for orchestration errors."""
        end_time = datetime.now(timezone.utc)
        total_duration = (end_time - self.start_time).total_seconds() if self.start_time else 0
        
        return OrchestrationResult(
            orchestration_id=self.orchestration_id,
            config=self.config,
            start_time=self.start_time or end_time,
            end_time=end_time,
            total_duration=total_duration,
            phase_results=self.phase_results,
            apache_bench_results=self.apache_bench_results,
            locust_results=self.locust_results,
            baseline_comparison={},
            performance_compliance={},
            variance_analysis={},
            overall_success=False,
            critical_issues=[f"Orchestration failed: {error_message}"],
            warnings=[],
            recommendations=["Review orchestration logs and fix critical issues before retrying."],
            resource_utilization={},
            real_time_metrics=self.real_time_metrics,
            alert_history=self.alert_history
        )
    
    def _analyze_resource_utilization(self) -> Dict[str, Any]:
        """Analyze resource utilization from collected metrics."""
        if not self.real_time_metrics:
            return {}
        
        cpu_samples = [m.get("cpu_percent", 0) for m in self.real_time_metrics if "cpu_percent" in m]
        memory_samples = [m.get("memory_percent", 0) for m in self.real_time_metrics if "memory_percent" in m]
        
        analysis = {}
        
        if cpu_samples:
            analysis["cpu"] = {
                "average_percent": statistics.mean(cpu_samples),
                "peak_percent": max(cpu_samples),
                "min_percent": min(cpu_samples),
                "std_dev": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0
            }
        
        if memory_samples:
            analysis["memory"] = {
                "average_percent": statistics.mean(memory_samples),
                "peak_percent": max(memory_samples),
                "min_percent": min(memory_samples),
                "std_dev": statistics.stdev(memory_samples) if len(memory_samples) > 1 else 0
            }
        
        return analysis
    
    def _generate_json_report(self, result: OrchestrationResult) -> Path:
        """Generate comprehensive JSON report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"orchestration_report_{self.orchestration_id}_{timestamp}.json"
        report_path = self.report_dir / filename
        
        report_data = result.generate_summary()
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {report_path}")
        return report_path
    
    def _generate_markdown_report(self, result: OrchestrationResult) -> Path:
        """Generate comprehensive Markdown report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"orchestration_summary_{self.orchestration_id}_{timestamp}.md"
        report_path = self.report_dir / filename
        
        # Generate markdown content
        status_emoji = "✅" if result.overall_success else "❌"
        status_text = "SUCCESS" if result.overall_success else "FAILURE"
        
        markdown_content = f"""# Load Testing Orchestration Report

**Orchestration ID:** {result.orchestration_id}  
**Status:** {status_emoji} {status_text}  
**Executed:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Duration:** {result.total_duration:.0f} seconds ({result.total_duration/60:.1f} minutes)  

## Executive Summary

{self._generate_executive_summary(result)}

## Configuration Summary

- **Target Host:** {result.config.host}
- **User Range:** {result.config.min_users} → {result.config.max_users} concurrent users
- **Test Duration:** {result.config.test_duration} seconds ({result.config.test_duration//60} minutes)
- **Scaling Strategy:** {result.config.scaling_strategy}
- **Apache Bench:** {'✅ Enabled' if result.config.apache_bench_enabled else '❌ Disabled'}
- **Distributed Mode:** {'✅ Enabled' if result.config.distributed_mode else '❌ Disabled'}
- **Baseline Validation:** {'✅ Enabled' if result.config.baseline_validation else '❌ Disabled'}

## Phase Execution Summary

| Phase | Status | Duration | Result |
|-------|--------|----------|--------|
"""
        
        for phase_name, phase_result in result.phase_results.items():
            status = "✅ SUCCESS" if phase_result.get("success", False) else "❌ FAILURE"
            duration = f"{phase_result.get('duration', 0):.1f}s"
            error = phase_result.get("error", "Completed successfully")
            
            markdown_content += f"| {phase_name} | {status} | {duration} | {error} |\n"
        
        # Add Apache Bench results
        if result.apache_bench_results:
            markdown_content += f"""
## Apache Bench Results

| Endpoint | Requests/Sec | Avg Response Time | Error Rate | Status |
|----------|---------------|-------------------|------------|--------|
"""
            
            for endpoint, ab_result in result.apache_bench_results.items():
                if "error" not in ab_result:
                    rps = ab_result.get("requests_per_second", 0)
                    response_time = ab_result.get("response_time_mean", 0)
                    error_rate = ab_result.get("error_rate_percent", 0)
                    status = "✅" if rps >= 100 and response_time <= 500 and error_rate <= 0.1 else "⚠️"
                    
                    markdown_content += f"| {endpoint} | {rps:.2f} | {response_time:.2f}ms | {error_rate:.3f}% | {status} |\n"
                else:
                    markdown_content += f"| {endpoint} | - | - | - | ❌ Error |\n"
        
        # Add Locust results
        if result.locust_results:
            locust = result.locust_results
            markdown_content += f"""
## Locust Load Testing Results

### Performance Metrics
| Metric | Value | Threshold | Status |
|--------|--------|-----------|--------|
| Total Requests | {locust.total_requests:,} | - | ℹ️ |
| Error Rate | {locust.error_rate_percent:.3f}% | ≤0.1% | {'✅' if locust.error_rate_percent <= 0.1 else '❌'} |
| Average Response Time | {locust.average_response_time_ms:.2f}ms | - | ℹ️ |
| P95 Response Time | {locust.p95_response_time_ms:.2f}ms | ≤500ms | {'✅' if locust.p95_response_time_ms <= 500 else '❌'} |
| Throughput | {locust.requests_per_second:.2f} RPS | ≥100 RPS | {'✅' if locust.requests_per_second >= 100 else '❌'} |
| Peak Throughput | {locust.peak_rps:.2f} RPS | - | ℹ️ |
| Max Concurrent Users | {locust.concurrent_users_achieved} | - | ℹ️ |
"""
        
        # Add baseline validation
        if result.baseline_comparison:
            compliance = result.baseline_comparison.get("overall_compliance", False)
            compliance_status = "✅ PASS" if compliance else "❌ FAIL"
            
            markdown_content += f"""
## Baseline Validation

**Overall Compliance:** {compliance_status}

### Variance Analysis
| Metric | Variance | Status |
|--------|----------|--------|
"""
            
            for metric, variance in result.variance_analysis.items():
                status = "✅ PASS" if abs(variance) <= PERFORMANCE_VARIANCE_THRESHOLD else "❌ FAIL"
                markdown_content += f"| {metric.replace('_', ' ').title()} | {variance:+.2f}% | {status} |\n"
        
        # Add issues and recommendations
        if result.critical_issues:
            markdown_content += f"""
## ❌ Critical Issues

"""
            for issue in result.critical_issues:
                markdown_content += f"- {issue}\n"
        
        if result.warnings:
            markdown_content += f"""
## ⚠️ Warnings

"""
            for warning in result.warnings:
                markdown_content += f"- {warning}\n"
        
        if result.recommendations:
            markdown_content += f"""
## 💡 Recommendations

"""
            for recommendation in result.recommendations:
                markdown_content += f"- {recommendation}\n"
        
        markdown_content += f"""
## Summary

**Overall Result:** {status_emoji} {'SUCCESS' if result.overall_success else 'FAILURE'}  
**Performance Compliance:** {'✅ All gates passed' if all(result.performance_compliance.values()) else '❌ Some gates failed'}  
**Baseline Compliance:** {'✅ Within variance threshold' if result.baseline_comparison.get('overall_compliance', False) else '❌ Variance threshold exceeded'}  

*Report generated by Flask Migration Load Testing Orchestration Engine*
"""
        
        with open(report_path, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report generated: {report_path}")
        return report_path
    
    def _generate_executive_summary(self, result: OrchestrationResult) -> str:
        """Generate executive summary for reports."""
        if result.overall_success:
            summary = f"""✅ **Load testing orchestration completed successfully!** The Flask application demonstrates excellent performance characteristics across all testing phases.

**Key Achievements:**"""
            
            if result.locust_results:
                summary += f"""
- **Sustained Load:** {result.locust_results.concurrent_users_achieved} concurrent users handled successfully
- **Response Time:** P95 {result.locust_results.p95_response_time_ms:.2f}ms (≤500ms threshold)
- **Throughput:** {result.locust_results.requests_per_second:.2f} RPS (≥100 RPS target)
- **Error Rate:** {result.locust_results.error_rate_percent:.3f}% (≤0.1% threshold)"""
            
            if result.baseline_comparison.get("overall_compliance", False):
                summary += f"""
- **Baseline Compliance:** ✅ Within {PERFORMANCE_VARIANCE_THRESHOLD:.1f}% variance of Node.js performance"""
            
            if result.apache_bench_results:
                successful_ab = len([r for r in result.apache_bench_results.values() if "error" not in r])
                summary += f"""
- **Apache Bench:** {successful_ab}/{len(result.apache_bench_results)} endpoints validated successfully"""
        
        else:
            summary = f"""❌ **Load testing orchestration identified performance issues requiring attention.** The Flask application needs optimization to meet production readiness criteria.

**Critical Issues:**"""
            
            for issue in result.critical_issues:
                summary += f"""
- {issue}"""
            
            if result.warnings:
                summary += f"""

**Performance Warnings:**"""
                for warning in result.warnings:
                    summary += f"""
- {warning}"""
        
        return summary
    
    def _generate_html_report(self, result: OrchestrationResult) -> Path:
        """Generate comprehensive HTML report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"orchestration_report_{self.orchestration_id}_{timestamp}.html"
        report_path = self.report_dir / filename
        
        # Generate HTML content (basic template)
        status_class = "success" if result.overall_success else "failure"
        status_text = "SUCCESS" if result.overall_success else "FAILURE"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Load Testing Orchestration Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }}
        .status.success {{ color: #28a745; }}
        .status.failure {{ color: #dc3545; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        .metric-good {{ color: #28a745; }}
        .metric-warning {{ color: #ffc107; }}
        .metric-bad {{ color: #dc3545; }}
        .phase-success {{ background-color: #d4edda; }}
        .phase-failure {{ background-color: #f8d7da; }}
        .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Load Testing Orchestration Report</h1>
            <p><strong>Orchestration ID:</strong> {result.orchestration_id}</p>
            <p><strong>Status:</strong> <span class="status {status_class}">{status_text}</span></p>
            <p><strong>Executed:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Duration:</strong> {result.total_duration:.0f} seconds ({result.total_duration/60:.1f} minutes)</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>{self._generate_executive_summary(result).replace('**', '<strong>').replace('**', '</strong>')}</p>
        </div>
"""
        
        # Add phase results table
        html_content += """
        <h2>Phase Execution Results</h2>
        <table>
            <thead>
                <tr><th>Phase</th><th>Status</th><th>Duration</th><th>Details</th></tr>
            </thead>
            <tbody>
"""
        
        for phase_name, phase_result in result.phase_results.items():
            status = "SUCCESS" if phase_result.get("success", False) else "FAILURE"
            status_class = "phase-success" if phase_result.get("success", False) else "phase-failure"
            duration = f"{phase_result.get('duration', 0):.1f}s"
            details = phase_result.get("error", "Completed successfully")
            
            html_content += f"""
                <tr class="{status_class}">
                    <td>{phase_name}</td>
                    <td>{status}</td>
                    <td>{duration}</td>
                    <td>{details}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
"""
        
        # Add performance results if available
        if result.locust_results:
            locust = result.locust_results
            html_content += f"""
        <h2>Performance Results</h2>
        <table>
            <thead>
                <tr><th>Metric</th><th>Value</th><th>Threshold</th><th>Status</th></tr>
            </thead>
            <tbody>
                <tr>
                    <td>Total Requests</td>
                    <td>{locust.total_requests:,}</td>
                    <td>-</td>
                    <td>-</td>
                </tr>
                <tr>
                    <td>Error Rate</td>
                    <td>{locust.error_rate_percent:.3f}%</td>
                    <td>≤0.1%</td>
                    <td class="{'metric-good' if locust.error_rate_percent <= 0.1 else 'metric-bad'}">{'PASS' if locust.error_rate_percent <= 0.1 else 'FAIL'}</td>
                </tr>
                <tr>
                    <td>P95 Response Time</td>
                    <td>{locust.p95_response_time_ms:.2f}ms</td>
                    <td>≤500ms</td>
                    <td class="{'metric-good' if locust.p95_response_time_ms <= 500 else 'metric-bad'}">{'PASS' if locust.p95_response_time_ms <= 500 else 'FAIL'}</td>
                </tr>
                <tr>
                    <td>Throughput</td>
                    <td>{locust.requests_per_second:.2f} RPS</td>
                    <td>≥100 RPS</td>
                    <td class="{'metric-good' if locust.requests_per_second >= 100 else 'metric-bad'}">{'PASS' if locust.requests_per_second >= 100 else 'FAIL'}</td>
                </tr>
            </tbody>
        </table>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        return report_path
    
    def _generate_ci_report(self, result: OrchestrationResult) -> Path:
        """Generate CI/CD integration report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"ci_integration_report_{self.orchestration_id}_{timestamp}.json"
        report_path = self.report_dir / filename
        
        ci_report = {
            "ci_integration": {
                "orchestration_id": result.orchestration_id,
                "timestamp": result.start_time.isoformat(),
                "duration_seconds": result.total_duration,
                "overall_success": result.overall_success
            },
            "quality_gates": {
                "all_phases_passed": all(phase.get("success", False) for phase in result.phase_results.values()),
                "performance_compliance": result.performance_compliance,
                "baseline_compliance": result.baseline_comparison.get("overall_compliance", False),
                "critical_issues_count": len(result.critical_issues),
                "warnings_count": len(result.warnings)
            },
            "deployment_decision": {
                "approve_deployment": result.overall_success and len(result.critical_issues) == 0,
                "requires_manual_review": len(result.warnings) > 0 or len(result.alert_history) > 5,
                "critical_blockers": result.critical_issues,
                "performance_warnings": result.warnings
            },
            "performance_summary": result._summarize_locust_results() if result.locust_results else {},
            "apache_bench_summary": result._summarize_apache_bench_results(),
            "recommendations": result.recommendations
        }
        
        with open(report_path, 'w') as f:
            json.dump(ci_report, f, indent=2, default=str)
        
        logger.info(f"CI/CD integration report generated: {report_path}")
        return report_path
    
    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.shutdown_requested = True
    
    def _cleanup_resources(self):
        """Clean up orchestration resources."""
        try:
            # Terminate any remaining processes
            for process in self.running_processes:
                if process.poll() is None:
                    process.terminate()
            
            # Stop monitoring threads
            self.shutdown_requested = True
            
            logger.info("Orchestration resources cleaned up")
            
        except Exception as e:
            logger.error("Error during resource cleanup", error=str(e))


def create_orchestration_config_from_args(args: argparse.Namespace) -> OrchestrationConfig:
    """
    Create orchestration configuration from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        OrchestrationConfig instance
    """
    return OrchestrationConfig(
        host=args.host,
        min_users=args.min_users,
        max_users=args.max_users,
        spawn_rate=args.spawn_rate,
        test_duration=args.duration,
        scaling_strategy=args.scaling_strategy,
        apache_bench_enabled=not args.disable_apache_bench,
        ab_requests=args.ab_requests,
        ab_concurrency=args.ab_concurrency,
        distributed_mode=args.distributed,
        worker_count=args.workers,
        endurance_mode=args.endurance,
        spike_test_mode=args.spike_test,
        baseline_validation=args.baseline_validation,
        ci_mode=args.ci_mode,
        performance_monitoring=not args.disable_monitoring,
        real_time_alerts=not args.disable_alerts,
        prometheus_enabled=args.prometheus,
        prometheus_gateway=args.prometheus_gateway,
        report_format=args.report_format,
        report_output_dir=args.report_dir,
        environment=args.environment,
        pre_test_validation=not args.skip_validation,
        post_test_cleanup=not args.skip_cleanup,
        max_failure_rate=args.max_failure_rate,
        abort_on_critical_failure=not args.continue_on_failure
    )


def main():
    """Main entry point for load testing orchestration."""
    parser = argparse.ArgumentParser(
        description="Load Testing Orchestration for Flask Migration Performance Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic load test
  %(prog)s --host http://localhost:5000 --users 100 --duration 600

  # Endurance testing with baseline validation
  %(prog)s --endurance --baseline-validation --users 500 --duration 1800

  # CI/CD mode with JSON reporting
  %(prog)s --ci-mode --report-format json --max-users 200

  # Distributed load testing
  %(prog)s --distributed --workers 4 --users 1000 --duration 1200

  # Apache Bench only testing
  %(prog)s --disable-locust --ab-requests 50000 --ab-concurrency 200
        """
    )
    
    # Basic configuration
    parser.add_argument("--host", default=DEFAULT_HOST,
                      help="Flask application host URL (default: %(default)s)")
    parser.add_argument("--min-users", type=int, default=DEFAULT_MIN_USERS,
                      help="Minimum concurrent users (default: %(default)s)")
    parser.add_argument("--max-users", type=int, default=DEFAULT_MAX_USERS,
                      help="Maximum concurrent users (default: %(default)s)")
    parser.add_argument("--users", type=int, dest="max_users",
                      help="Alias for --max-users")
    parser.add_argument("--spawn-rate", type=float, default=DEFAULT_SPAWN_RATE,
                      help="User spawn rate per second (default: %(default)s)")
    parser.add_argument("--duration", type=int, default=DEFAULT_TEST_DURATION,
                      help="Test duration in seconds (default: %(default)s)")
    
    # Scaling configuration
    parser.add_argument("--scaling-strategy", choices=["progressive", "immediate", "stepped"],
                      default="progressive", help="User scaling strategy (default: %(default)s)")
    
    # Apache Bench configuration
    parser.add_argument("--disable-apache-bench", action="store_true",
                      help="Disable Apache Bench testing")
    parser.add_argument("--ab-requests", type=int, default=DEFAULT_APACHE_BENCH_REQUESTS,
                      help="Apache Bench total requests (default: %(default)s)")
    parser.add_argument("--ab-concurrency", type=int, default=DEFAULT_APACHE_BENCH_CONCURRENCY,
                      help="Apache Bench concurrency level (default: %(default)s)")
    
    # Distributed testing
    parser.add_argument("--distributed", action="store_true",
                      help="Enable distributed load testing")
    parser.add_argument("--workers", type=int, default=DISTRIBUTED_WORKERS_COUNT,
                      help="Number of distributed workers (default: %(default)s)")
    
    # Test modes
    parser.add_argument("--endurance", action="store_true",
                      help="Enable endurance testing mode")
    parser.add_argument("--spike-test", action="store_true",
                      help="Enable spike testing mode")
    parser.add_argument("--baseline-validation", action="store_true", default=True,
                      help="Enable baseline validation (default: enabled)")
    parser.add_argument("--ci-mode", action="store_true",
                      help="Enable CI/CD mode with optimized settings")
    
    # Monitoring and alerting
    parser.add_argument("--disable-monitoring", action="store_true",
                      help="Disable performance monitoring")
    parser.add_argument("--disable-alerts", action="store_true",
                      help="Disable real-time alerts")
    parser.add_argument("--prometheus", action="store_true",
                      help="Enable Prometheus metrics")
    parser.add_argument("--prometheus-gateway",
                      help="Prometheus pushgateway URL")
    
    # Reporting
    parser.add_argument("--report-format", choices=["json", "markdown", "html", "all"],
                      default="json", help="Report output format (default: %(default)s)")
    parser.add_argument("--report-dir", default="tests/performance/reports",
                      help="Report output directory (default: %(default)s)")
    
    # Environment and execution
    parser.add_argument("--environment", choices=["development", "testing", "staging", "production", "ci_cd"],
                      default="testing", help="Testing environment (default: %(default)s)")
    parser.add_argument("--skip-validation", action="store_true",
                      help="Skip pre-test validation")
    parser.add_argument("--skip-cleanup", action="store_true",
                      help="Skip post-test cleanup")
    
    # Failure handling
    parser.add_argument("--max-failure-rate", type=float, default=5.0,
                      help="Maximum failure rate percentage (default: %(default)s)")
    parser.add_argument("--continue-on-failure", action="store_true",
                      help="Continue testing even on critical failures")
    
    # Logging
    parser.add_argument("--verbose", "-v", action="store_true",
                      help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true",
                      help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        # Create orchestration configuration
        config = create_orchestration_config_from_args(args)
        
        # Validate dependencies
        if not LOCUST_AVAILABLE:
            logger.error("Locust is not available. Install with: pip install locust>=2.0")
            return 1
        
        if config.apache_bench_enabled and not shutil.which("ab"):
            logger.error("Apache Bench is not available. Install apache2-utils package.")
            return 1
        
        # Create and execute orchestration
        logger.info("Starting load testing orchestration", config=asdict(config))
        
        engine = LoadTestOrchestrationEngine(config)
        result = engine.execute_load_testing_orchestration()
        
        # Print summary
        print(f"\n🎯 Load Testing Orchestration Complete")
        print(f"Orchestration ID: {result.orchestration_id}")
        print(f"Status: {'✅ SUCCESS' if result.overall_success else '❌ FAILURE'}")
        print(f"Duration: {result.total_duration:.0f} seconds ({result.total_duration/60:.1f} minutes)")
        
        if result.locust_results:
            print(f"\n📊 Performance Summary:")
            print(f"  Total Requests: {result.locust_results.total_requests:,}")
            print(f"  Error Rate: {result.locust_results.error_rate_percent:.3f}%")
            print(f"  P95 Response Time: {result.locust_results.p95_response_time_ms:.2f}ms")
            print(f"  Throughput: {result.locust_results.requests_per_second:.2f} RPS")
            print(f"  Peak RPS: {result.locust_results.peak_rps:.2f}")
            print(f"  Max Users: {result.locust_results.concurrent_users_achieved}")
        
        if result.baseline_comparison:
            compliance = result.baseline_comparison.get("overall_compliance", False)
            print(f"\n🔍 Baseline Validation: {'✅ PASS' if compliance else '❌ FAIL'}")
            
            if result.variance_analysis:
                print("  Variance Analysis:")
                for metric, variance in result.variance_analysis.items():
                    status = "✅" if abs(variance) <= PERFORMANCE_VARIANCE_THRESHOLD else "❌"
                    print(f"    {metric}: {variance:+.2f}% {status}")
        
        if result.critical_issues:
            print(f"\n❌ Critical Issues ({len(result.critical_issues)}):")
            for issue in result.critical_issues:
                print(f"  - {issue}")
        
        if result.warnings:
            print(f"\n⚠️ Warnings ({len(result.warnings)}):")
            for warning in result.warnings:
                print(f"  - {warning}")
        
        if result.recommendations:
            print(f"\n💡 Recommendations:")
            for recommendation in result.recommendations:
                print(f"  - {recommendation}")
        
        print(f"\n📁 Reports generated in: {config.report_output_dir}")
        
        # Return appropriate exit code
        return 0 if result.overall_success else 1
        
    except KeyboardInterrupt:
        logger.info("Orchestration interrupted by user")
        return 130
    except Exception as e:
        logger.error("Orchestration failed", error=str(e), traceback=traceback.format_exc())
        return 1


if __name__ == "__main__":
    exit(main())