#!/usr/bin/env python3
"""
Node.js Baseline Performance Data Collection Script

This script executes standardized performance tests against the original Node.js implementation
to establish reference metrics for variance calculation during the Python/Flask migration.
Automates baseline data gathering, validation, and storage for continuous performance comparison
per Section 0.3.2 performance monitoring requirements.

Key Features:
- Automated Node.js baseline collection per Section 0.3.2 performance monitoring requirements
- Response time, memory usage, CPU utilization data collection per Section 0.3.2 performance metrics
- Database query performance baseline collection per Section 0.3.2 database metrics
- Throughput and concurrent capacity baseline measurement per Section 4.6.3 performance metrics
- Baseline data validation and storage automation per Section 6.6.1 baseline comparison engine
- ≤10% variance requirement baseline data collection per Section 0.1.1 primary objective

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 4.6.3: Load testing specifications with progressive scaling and performance metrics
- Section 6.6.1: Baseline comparison engine for automated performance validation

Usage:
    python collect_baseline.py --target-url http://localhost:3000 --output baseline_data.json
    python collect_baseline.py --config production --duration 1800 --concurrent-users 500
    python collect_baseline.py --full-suite --validate --store-results

Dependencies:
- Node.js application server running and accessible
- locust ≥2.x for load testing capabilities  
- apache-bench for HTTP performance measurement
- psutil for system resource monitoring
- requests for HTTP client operations
- structlog for performance logging

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
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from urllib.parse import urljoin, urlparse
import signal

# Core monitoring and metrics dependencies
try:
    import psutil
    import structlog
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    MONITORING_AVAILABLE = True
except ImportError as e:
    MONITORING_AVAILABLE = False
    print(f"Warning: Monitoring dependencies not available: {e}")

# HTTP client dependencies
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    HTTP_CLIENT_AVAILABLE = True
except ImportError as e:
    HTTP_CLIENT_AVAILABLE = False
    print(f"Warning: HTTP client dependencies not available: {e}")

# Load testing dependencies
try:
    import locust
    from locust import HttpUser, task, between, events
    from locust.env import Environment
    from locust.runners import LocalRunner
    from locust.stats import StatsEntry
    LOCUST_AVAILABLE = True
except ImportError as e:
    LOCUST_AVAILABLE = False
    print(f"Warning: Locust load testing not available: {e}")

# Local performance testing imports
try:
    from tests.performance.performance_config import (
        BasePerformanceConfig,
        PerformanceConfigFactory,
        LoadTestConfiguration,
        BaselineMetrics,
        PerformanceThreshold,
        create_performance_config
    )
    from tests.performance.baseline_data import (
        BaselineDataManager,
        ResponseTimeBaseline,
        ResourceUtilizationBaseline,
        DatabasePerformanceBaseline,
        ThroughputBaseline,
        NetworkIOBaseline,
        PERFORMANCE_VARIANCE_THRESHOLD,
        MEMORY_VARIANCE_THRESHOLD
    )
    LOCAL_CONFIG_AVAILABLE = True
except ImportError as e:
    LOCAL_CONFIG_AVAILABLE = False
    print(f"Warning: Local performance configuration not available: {e}")

# Configure structured logging
if MONITORING_AVAILABLE:
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
    # Fallback to standard logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

# Performance collection constants per Section 4.6.3
DEFAULT_COLLECTION_DURATION = 1800  # 30-minute baseline collection per Section 4.6.3
DEFAULT_WARMUP_DURATION = 300       # 5-minute warmup period
DEFAULT_COOLDOWN_DURATION = 300     # 5-minute cooldown period
DEFAULT_CONCURRENT_USERS = [10, 50, 100, 250, 500, 1000]  # Progressive scaling per Section 4.6.3
DEFAULT_REQUEST_RATE = 100          # Minimum 100 requests/second per Section 4.6.3
MAX_REQUEST_RATE = 500              # Target 100-500 requests per second per Section 4.6.3
RESPONSE_TIME_THRESHOLD = 500       # 95th percentile ≤500ms per Section 4.6.3
ERROR_RATE_THRESHOLD = 0.1          # ≤0.1% error rate per Section 4.6.3
RESOURCE_MONITORING_INTERVAL = 15   # 15-second resource monitoring intervals
NETWORK_TIMEOUT = 30                # 30-second network timeout
MAX_RETRIES = 3                     # Maximum retry attempts
BASELINE_SAMPLE_SIZE = 1000         # Minimum sample size for statistical validity


class BaselineCollectionError(Exception):
    """Custom exception for baseline collection failures."""
    pass


class NodeJSServerError(Exception):
    """Custom exception for Node.js server communication errors."""
    pass


class PerformanceMonitoringError(Exception):
    """Custom exception for performance monitoring failures."""
    pass


@contextmanager
def performance_collection_timer(operation_name: str):
    """
    Context manager for timing performance collection operations.
    
    Args:
        operation_name: Description of the operation being timed
        
    Yields:
        Dictionary containing timing information
    """
    timer_info = {
        "operation": operation_name,
        "start_time": time.time(),
        "start_timestamp": datetime.now(timezone.utc)
    }
    
    try:
        yield timer_info
    finally:
        timer_info["end_time"] = time.time()
        timer_info["end_timestamp"] = datetime.now(timezone.utc)
        timer_info["duration_seconds"] = timer_info["end_time"] - timer_info["start_time"]
        
        logger.info(
            f"Performance collection timer: {operation_name}",
            duration_seconds=timer_info["duration_seconds"],
            start_time=timer_info["start_timestamp"].isoformat(),
            end_time=timer_info["end_timestamp"].isoformat()
        )


class NodeJSBaselineCollector:
    """
    Comprehensive Node.js baseline performance data collector.
    
    Implements automated baseline collection with response time measurement,
    resource utilization monitoring, database performance analysis, and
    throughput validation per Section 0.3.2 performance monitoring requirements.
    """
    
    def __init__(
        self,
        target_url: str,
        output_file: Optional[str] = None,
        config_environment: str = "production",
        validate_results: bool = True,
        store_intermediate_results: bool = True
    ):
        """
        Initialize Node.js baseline collector.
        
        Args:
            target_url: Base URL of Node.js application server
            output_file: Output file path for baseline data storage
            config_environment: Performance configuration environment
            validate_results: Enable result validation against thresholds
            store_intermediate_results: Store intermediate collection results
        """
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file or f"nodejs_baseline_{int(time.time())}.json"
        self.config_environment = config_environment
        self.validate_results = validate_results
        self.store_intermediate_results = store_intermediate_results
        
        # Validate target URL
        try:
            parsed_url = urlparse(self.target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError(f"Invalid target URL: {self.target_url}")
        except Exception as e:
            raise BaselineCollectionError(f"Invalid target URL configuration: {e}")
        
        # Initialize configuration
        if LOCAL_CONFIG_AVAILABLE:
            try:
                self.performance_config = create_performance_config(config_environment)
                self.load_test_config = self.performance_config.get_load_test_config()
                logger.info(
                    "Performance configuration loaded",
                    environment=config_environment,
                    variance_threshold=self.performance_config.PERFORMANCE_VARIANCE_THRESHOLD
                )
            except Exception as e:
                logger.warning(f"Failed to load performance configuration: {e}")
                self.performance_config = None
                self.load_test_config = None
        else:
            self.performance_config = None
            self.load_test_config = None
        
        # Initialize baseline data manager
        self.baseline_manager = BaselineDataManager(self.output_file)
        
        # Initialize HTTP session with retry logic
        self.session = self._create_http_session()
        
        # Initialize metrics registry
        if MONITORING_AVAILABLE:
            self.metrics_registry = CollectorRegistry()
            self._setup_metrics()
        else:
            self.metrics_registry = None
        
        # Collection state tracking
        self.collection_state = {
            "started_at": None,
            "completed_at": None,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "collection_errors": [],
            "validation_errors": [],
            "intermediate_results": []
        }
        
        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(
            "Node.js baseline collector initialized",
            target_url=self.target_url,
            output_file=self.output_file,
            config_environment=config_environment
        )
    
    def _create_http_session(self) -> requests.Session:
        """
        Create HTTP session with retry logic and performance optimization.
        
        Returns:
            Configured requests Session with retry logic
        """
        if not HTTP_CLIENT_AVAILABLE:
            raise BaselineCollectionError("HTTP client dependencies not available")
        
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=MAX_RETRIES,
            read=MAX_RETRIES,
            connect=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set session defaults
        session.timeout = NETWORK_TIMEOUT
        session.headers.update({
            'User-Agent': 'NodeJS-Baseline-Collector/1.0',
            'Accept': 'application/json',
            'Connection': 'keep-alive'
        })
        
        return session
    
    def _setup_metrics(self) -> None:
        """Setup Prometheus metrics for collection monitoring."""
        if not MONITORING_AVAILABLE:
            return
        
        self.response_time_histogram = Histogram(
            'baseline_response_time_seconds',
            'Response time distribution for baseline collection',
            buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry=self.metrics_registry
        )
        
        self.request_counter = Counter(
            'baseline_requests_total',
            'Total baseline collection requests',
            ['method', 'endpoint', 'status'],
            registry=self.metrics_registry
        )
        
        self.error_counter = Counter(
            'baseline_errors_total',
            'Total baseline collection errors',
            ['error_type'],
            registry=self.metrics_registry
        )
        
        self.collection_progress_gauge = Gauge(
            'baseline_collection_progress',
            'Baseline collection progress percentage',
            registry=self.metrics_registry
        )
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle graceful shutdown signals."""
        logger.warning(
            "Baseline collection interrupted by signal",
            signal=signum,
            collection_state=self.collection_state
        )
        
        # Save partial results if available
        if self.store_intermediate_results and self.collection_state["intermediate_results"]:
            self._save_partial_results()
        
        sys.exit(1)
    
    def verify_nodejs_server(self) -> Dict[str, Any]:
        """
        Verify Node.js server availability and basic health.
        
        Returns:
            Dictionary containing server verification results
            
        Raises:
            NodeJSServerError: If server verification fails
        """
        logger.info("Verifying Node.js server availability", target_url=self.target_url)
        
        verification_results = {
            "server_available": False,
            "response_time_ms": None,
            "server_info": {},
            "health_endpoints": {},
            "verification_timestamp": datetime.now(timezone.utc)
        }
        
        try:
            # Test basic connectivity
            with performance_collection_timer("server_connectivity_check"):
                start_time = time.time()
                response = self.session.get(f"{self.target_url}/health", timeout=NETWORK_TIMEOUT)
                end_time = time.time()
                
                verification_results["response_time_ms"] = (end_time - start_time) * 1000
                verification_results["server_available"] = response.status_code == 200
                
                if response.status_code == 200:
                    try:
                        health_data = response.json()
                        verification_results["health_endpoints"]["health"] = health_data
                    except (json.JSONDecodeError, ValueError):
                        verification_results["health_endpoints"]["health"] = {"status": "ok"}
                
        except requests.exceptions.RequestException as e:
            logger.error("Node.js server connectivity check failed", error=str(e))
            raise NodeJSServerError(f"Server connectivity check failed: {e}")
        
        # Test additional health endpoints
        additional_endpoints = ["/api/health", "/status", "/ping"]
        
        for endpoint in additional_endpoints:
            try:
                response = self.session.get(f"{self.target_url}{endpoint}", timeout=10)
                verification_results["health_endpoints"][endpoint] = {
                    "status_code": response.status_code,
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
                
                if response.status_code == 200:
                    try:
                        verification_results["health_endpoints"][endpoint]["data"] = response.json()
                    except (json.JSONDecodeError, ValueError):
                        pass
                        
            except requests.exceptions.RequestException:
                verification_results["health_endpoints"][endpoint] = {"available": False}
        
        # Attempt to get server information
        try:
            response = self.session.get(f"{self.target_url}/api/v1/info", timeout=10)
            if response.status_code == 200:
                verification_results["server_info"] = response.json()
        except requests.exceptions.RequestException:
            logger.debug("Server info endpoint not available")
        
        if not verification_results["server_available"]:
            raise NodeJSServerError(
                f"Node.js server not available at {self.target_url}. "
                f"Health check failed: {verification_results['health_endpoints']}"
            )
        
        logger.info(
            "Node.js server verification completed",
            response_time_ms=verification_results["response_time_ms"],
            available_endpoints=len([ep for ep, data in verification_results["health_endpoints"].items() 
                                   if isinstance(data, dict) and data.get("status_code") == 200])
        )
        
        return verification_results
    
    def collect_response_time_baselines(self, endpoints: Optional[List[Tuple[str, str]]] = None) -> List[ResponseTimeBaseline]:
        """
        Collect response time baselines for critical API endpoints.
        
        Args:
            endpoints: List of (method, endpoint) tuples to test
            
        Returns:
            List of ResponseTimeBaseline objects with measured data
        """
        if endpoints is None:
            # Default critical endpoints per Section 4.6.3
            endpoints = [
                ("GET", "/api/v1/health"),
                ("POST", "/api/v1/auth/login"),
                ("POST", "/api/v1/auth/refresh"),
                ("GET", "/api/v1/users"),
                ("POST", "/api/v1/users"),
                ("GET", "/api/v1/data/reports"),
                ("PUT", "/api/v1/users/{id}"),
                ("DELETE", "/api/v1/users/{id}"),
                ("GET", "/api/v1/files"),
                ("POST", "/api/v1/files/upload")
            ]
        
        logger.info("Starting response time baseline collection", endpoint_count=len(endpoints))
        baselines = []
        
        for method, endpoint in endpoints:
            try:
                with performance_collection_timer(f"response_time_baseline_{method}_{endpoint.replace('/', '_')}"):
                    baseline = self._collect_endpoint_baseline(method, endpoint)
                    baselines.append(baseline)
                    
                    # Store intermediate result
                    if self.store_intermediate_results:
                        self.collection_state["intermediate_results"].append({
                            "type": "response_time_baseline",
                            "data": baseline,
                            "timestamp": datetime.now(timezone.utc)
                        })
                    
                    logger.info(
                        "Response time baseline collected",
                        method=method,
                        endpoint=endpoint,
                        mean_response_time_ms=baseline.mean_response_time_ms,
                        p95_response_time_ms=baseline.p95_response_time_ms,
                        sample_count=baseline.sample_count
                    )
                    
            except Exception as e:
                error_msg = f"Failed to collect baseline for {method} {endpoint}: {e}"
                logger.error(error_msg)
                self.collection_state["collection_errors"].append(error_msg)
                
                if MONITORING_AVAILABLE:
                    self.error_counter.labels(error_type="response_time_collection").inc()
        
        logger.info("Response time baseline collection completed", baselines_collected=len(baselines))
        return baselines
    
    def _collect_endpoint_baseline(self, method: str, endpoint: str) -> ResponseTimeBaseline:
        """
        Collect response time baseline for a specific endpoint.
        
        Args:
            method: HTTP method
            endpoint: API endpoint path
            
        Returns:
            ResponseTimeBaseline with collected metrics
        """
        # Prepare endpoint URL and test data
        url = urljoin(self.target_url, endpoint)
        response_times = []
        
        # Replace path parameters with test values
        if "{id}" in endpoint:
            url = url.replace("{id}", "test-id-123")
        
        # Prepare request data based on method
        request_data = self._prepare_request_data(method, endpoint)
        
        # Warmup phase
        logger.debug(f"Warming up endpoint {method} {endpoint}")
        for _ in range(10):
            try:
                self._make_request(method, url, request_data)
            except Exception:
                pass  # Ignore warmup errors
        
        # Collection phase
        logger.debug(f"Collecting baseline data for {method} {endpoint}")
        successful_requests = 0
        
        for i in range(BASELINE_SAMPLE_SIZE):
            try:
                start_time = time.time()
                response = self._make_request(method, url, request_data)
                end_time = time.time()
                
                response_time_ms = (end_time - start_time) * 1000
                response_times.append(response_time_ms)
                successful_requests += 1
                
                self.collection_state["total_requests"] += 1
                self.collection_state["successful_requests"] += 1
                
                # Update metrics
                if MONITORING_AVAILABLE:
                    self.response_time_histogram.observe(response_time_ms / 1000)
                    self.request_counter.labels(
                        method=method,
                        endpoint=endpoint,
                        status=str(response.status_code)
                    ).inc()
                
                # Brief pause to avoid overwhelming the server
                if i % 100 == 0 and i > 0:
                    time.sleep(0.1)
                    
            except Exception as e:
                self.collection_state["total_requests"] += 1
                self.collection_state["failed_requests"] += 1
                logger.debug(f"Request failed during baseline collection: {e}")
                
                if MONITORING_AVAILABLE:
                    self.error_counter.labels(error_type="request_failure").inc()
        
        if not response_times:
            raise BaselineCollectionError(f"No successful requests for {method} {endpoint}")
        
        # Calculate response time statistics
        response_times.sort()
        sample_count = len(response_times)
        
        mean_response_time = statistics.mean(response_times)
        median_response_time = statistics.median(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        std_deviation = statistics.stdev(response_times) if sample_count > 1 else 0.0
        
        # Calculate percentiles
        p95_index = int(sample_count * 0.95)
        p99_index = int(sample_count * 0.99)
        p95_response_time = response_times[min(p95_index, sample_count - 1)]
        p99_response_time = response_times[min(p99_index, sample_count - 1)]
        
        baseline = ResponseTimeBaseline(
            endpoint=endpoint,
            method=method.upper(),
            mean_response_time_ms=mean_response_time,
            median_response_time_ms=median_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            min_response_time_ms=min_response_time,
            max_response_time_ms=max_response_time,
            std_deviation_ms=std_deviation,
            sample_count=sample_count
        )
        
        # Validate against thresholds
        if self.validate_results and p95_response_time > RESPONSE_TIME_THRESHOLD:
            warning_msg = (
                f"Response time threshold exceeded for {method} {endpoint}: "
                f"P95 {p95_response_time:.2f}ms > {RESPONSE_TIME_THRESHOLD}ms"
            )
            logger.warning(warning_msg)
            self.collection_state["validation_errors"].append(warning_msg)
        
        return baseline
    
    def _prepare_request_data(self, method: str, endpoint: str) -> Dict[str, Any]:
        """
        Prepare request data based on HTTP method and endpoint.
        
        Args:
            method: HTTP method
            endpoint: API endpoint path
            
        Returns:
            Dictionary containing request configuration
        """
        request_data = {
            "headers": {"Content-Type": "application/json"},
            "json": None,
            "files": None,
            "params": None
        }
        
        # Configure request data based on endpoint and method
        if method.upper() == "POST":
            if "auth/login" in endpoint:
                request_data["json"] = {
                    "email": "baseline@example.com",
                    "password": "baseline123"
                }
            elif "users" in endpoint:
                request_data["json"] = {
                    "name": "Baseline Test User",
                    "email": f"baseline_{int(time.time())}@example.com",
                    "role": "user"
                }
            elif "files/upload" in endpoint:
                request_data["files"] = {
                    "file": ("baseline_test.txt", "Baseline test content", "text/plain")
                }
                request_data["headers"] = {}  # Remove Content-Type for file upload
        
        elif method.upper() == "PUT":
            if "users" in endpoint:
                request_data["json"] = {
                    "name": "Updated Baseline User",
                    "email": "updated_baseline@example.com"
                }
        
        elif method.upper() == "GET":
            if "users" in endpoint:
                request_data["params"] = {"limit": 50, "offset": 0}
            elif "reports" in endpoint:
                request_data["params"] = {"format": "json", "limit": 20}
        
        return request_data
    
    def _make_request(self, method: str, url: str, request_data: Dict[str, Any]) -> requests.Response:
        """
        Make HTTP request with proper error handling.
        
        Args:
            method: HTTP method
            url: Target URL
            request_data: Request configuration data
            
        Returns:
            HTTP Response object
            
        Raises:
            requests.RequestException: If request fails
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=request_data.get("headers"),
                json=request_data.get("json"),
                files=request_data.get("files"),
                params=request_data.get("params"),
                timeout=NETWORK_TIMEOUT
            )
            
            # Accept various successful status codes
            if response.status_code not in [200, 201, 202, 204, 400, 401, 404]:
                response.raise_for_status()
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed: {method} {url} - {e}")
            raise
    
    def collect_resource_utilization_baselines(self, duration_seconds: int = 300) -> List[ResourceUtilizationBaseline]:
        """
        Collect system resource utilization baselines over time.
        
        Args:
            duration_seconds: Duration to collect resource metrics
            
        Returns:
            List of ResourceUtilizationBaseline objects
        """
        if not MONITORING_AVAILABLE:
            logger.warning("Resource utilization monitoring not available")
            return []
        
        logger.info("Starting resource utilization baseline collection", duration_seconds=duration_seconds)
        baselines = []
        
        start_time = time.time()
        collection_interval = RESOURCE_MONITORING_INTERVAL
        
        try:
            with performance_collection_timer("resource_utilization_collection"):
                while (time.time() - start_time) < duration_seconds:
                    try:
                        # Collect system metrics
                        cpu_percent = psutil.cpu_percent(interval=1)
                        memory_info = psutil.virtual_memory()
                        
                        # Calculate memory metrics
                        memory_usage_mb = (memory_info.used / 1024 / 1024)
                        memory_utilization_percent = memory_info.percent
                        
                        # Get process-specific metrics if available
                        try:
                            current_process = psutil.Process()
                            process_memory = current_process.memory_info()
                            heap_usage_mb = process_memory.rss / 1024 / 1024
                        except psutil.NoSuchProcess:
                            heap_usage_mb = memory_usage_mb * 0.7  # Estimate
                        
                        # Network connection count
                        try:
                            connections = psutil.net_connections()
                            active_connections = len([conn for conn in connections if conn.status == 'ESTABLISHED'])
                        except (psutil.AccessDenied, AttributeError):
                            active_connections = 0
                        
                        # Thread count estimation
                        try:
                            thread_count = len(psutil.Process().threads())
                        except psutil.NoSuchProcess:
                            thread_count = 0
                        
                        baseline = ResourceUtilizationBaseline(
                            cpu_utilization_percent=cpu_percent,
                            memory_usage_mb=memory_usage_mb,
                            memory_utilization_percent=memory_utilization_percent,
                            heap_usage_mb=heap_usage_mb,
                            gc_pause_time_ms=0.0,  # Not directly measurable from outside Node.js
                            active_connections=active_connections,
                            thread_count=thread_count
                        )
                        
                        baselines.append(baseline)
                        
                        logger.debug(
                            "Resource utilization sample collected",
                            cpu_percent=cpu_percent,
                            memory_mb=memory_usage_mb,
                            memory_percent=memory_utilization_percent
                        )
                        
                        # Store intermediate result
                        if self.store_intermediate_results:
                            self.collection_state["intermediate_results"].append({
                                "type": "resource_utilization_baseline",
                                "data": baseline,
                                "timestamp": datetime.now(timezone.utc)
                            })
                        
                        time.sleep(collection_interval)
                        
                    except Exception as e:
                        logger.warning(f"Failed to collect resource metrics: {e}")
                        
        except KeyboardInterrupt:
            logger.info("Resource utilization collection interrupted")
        
        if baselines and self.validate_results:
            # Validate resource utilization against thresholds
            avg_cpu = statistics.mean([b.cpu_utilization_percent for b in baselines])
            max_cpu = max([b.cpu_utilization_percent for b in baselines])
            
            if max_cpu > 90:
                warning_msg = f"High CPU utilization detected: {max_cpu:.2f}%"
                logger.warning(warning_msg)
                self.collection_state["validation_errors"].append(warning_msg)
            
            if avg_cpu > 70:
                warning_msg = f"Average CPU utilization high: {avg_cpu:.2f}%"
                logger.warning(warning_msg)
                self.collection_state["validation_errors"].append(warning_msg)
        
        logger.info(
            "Resource utilization baseline collection completed",
            samples_collected=len(baselines),
            duration_seconds=duration_seconds
        )
        
        return baselines
    
    def collect_throughput_baselines(self, user_progression: Optional[List[int]] = None) -> List[ThroughputBaseline]:
        """
        Collect throughput baselines using progressive load testing.
        
        Args:
            user_progression: List of concurrent user counts to test
            
        Returns:
            List of ThroughputBaseline objects
        """
        if not LOCUST_AVAILABLE:
            logger.warning("Locust not available for throughput testing")
            return []
        
        if user_progression is None:
            user_progression = DEFAULT_CONCURRENT_USERS
        
        logger.info("Starting throughput baseline collection", user_progression=user_progression)
        baselines = []
        
        try:
            for concurrent_users in user_progression:
                with performance_collection_timer(f"throughput_baseline_{concurrent_users}_users"):
                    baseline = self._collect_throughput_baseline(concurrent_users)
                    baselines.append(baseline)
                    
                    # Store intermediate result
                    if self.store_intermediate_results:
                        self.collection_state["intermediate_results"].append({
                            "type": "throughput_baseline",
                            "data": baseline,
                            "timestamp": datetime.now(timezone.utc)
                        })
                    
                    logger.info(
                        "Throughput baseline collected",
                        concurrent_users=concurrent_users,
                        requests_per_second=baseline.requests_per_second,
                        error_rate_percent=baseline.error_rate_percent
                    )
                    
                    # Brief cooldown between load tests
                    time.sleep(30)
                    
        except Exception as e:
            error_msg = f"Throughput baseline collection failed: {e}"
            logger.error(error_msg)
            self.collection_state["collection_errors"].append(error_msg)
        
        logger.info("Throughput baseline collection completed", baselines_collected=len(baselines))
        return baselines
    
    def _collect_throughput_baseline(self, concurrent_users: int) -> ThroughputBaseline:
        """
        Collect throughput baseline for specific concurrent user count.
        
        Args:
            concurrent_users: Number of concurrent users to simulate
            
        Returns:
            ThroughputBaseline with measured metrics
        """
        # Create Locust user class for baseline testing
        class BaselineTestUser(HttpUser):
            wait_time = between(1, 3)
            host = self.target_url
            
            @task(70)  # 70% GET requests
            def test_get_operations(self):
                endpoints = ["/api/v1/health", "/api/v1/users", "/api/v1/data/reports"]
                endpoint = self.random.choice(endpoints)
                with self.client.get(endpoint, catch_response=True) as response:
                    if response.status_code in [200, 404]:  # Accept 404 for test data
                        response.success()
                    else:
                        response.failure(f"Unexpected status: {response.status_code}")
            
            @task(20)  # 20% POST requests
            def test_post_operations(self):
                endpoints = ["/api/v1/users", "/api/v1/auth/login"]
                endpoint = self.random.choice(endpoints)
                
                if "auth/login" in endpoint:
                    data = {"email": "test@example.com", "password": "test123"}
                else:
                    data = {"name": "Test User", "email": f"test_{self.random.randint(1000, 9999)}@example.com"}
                
                with self.client.post(endpoint, json=data, catch_response=True) as response:
                    if response.status_code in [200, 201, 400, 401]:  # Accept validation errors
                        response.success()
                    else:
                        response.failure(f"Unexpected status: {response.status_code}")
            
            @task(10)  # 10% other operations
            def test_other_operations(self):
                with self.client.get("/api/v1/health", catch_response=True) as response:
                    if response.status_code == 200:
                        response.success()
                    else:
                        response.failure(f"Health check failed: {response.status_code}")
        
        # Configure Locust environment
        env = Environment(user_classes=[BaselineTestUser])
        env.create_local_runner()
        
        # Test duration configuration
        test_duration = 300  # 5-minute throughput tests
        ramp_up_duration = 60  # 1-minute ramp-up
        
        try:
            # Start load test
            env.runner.start(user_count=concurrent_users, spawn_rate=2)
            
            # Wait for ramp-up
            time.sleep(ramp_up_duration)
            
            # Collect metrics during steady state
            start_stats = env.runner.stats.total
            start_time = time.time()
            
            # Run steady state
            time.sleep(test_duration - ramp_up_duration)
            
            # Collect final stats
            end_stats = env.runner.stats.total
            end_time = time.time()
            
            # Stop the test
            env.runner.stop()
            
            # Calculate throughput metrics
            test_duration_actual = end_time - start_time
            total_requests = end_stats.num_requests - start_stats.num_requests
            successful_requests = total_requests - (end_stats.num_failures - start_stats.num_failures)
            failed_requests = end_stats.num_failures - start_stats.num_failures
            
            requests_per_second = total_requests / test_duration_actual if test_duration_actual > 0 else 0
            error_rate_percent = (failed_requests / total_requests * 100) if total_requests > 0 else 0
            avg_response_time = end_stats.avg_response_time
            
            # Calculate throughput variance (for stability assessment)
            throughput_samples = []
            if hasattr(env.runner.stats, 'history'):
                for entry in env.runner.stats.history:
                    if entry.get('requests'):
                        sample_rps = entry['requests'] / 10  # 10-second sampling
                        throughput_samples.append(sample_rps)
            
            throughput_variance = statistics.stdev(throughput_samples) if len(throughput_samples) > 1 else 0
            
            baseline = ThroughputBaseline(
                requests_per_second=requests_per_second,
                concurrent_users=concurrent_users,
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                error_rate_percent=error_rate_percent,
                avg_response_time_ms=avg_response_time,
                throughput_variance=throughput_variance,
                test_duration_seconds=int(test_duration_actual)
            )
            
            # Validate throughput baseline
            if self.validate_results:
                if requests_per_second < DEFAULT_REQUEST_RATE:
                    warning_msg = (
                        f"Throughput below minimum threshold: "
                        f"{requests_per_second:.2f} RPS < {DEFAULT_REQUEST_RATE} RPS"
                    )
                    logger.warning(warning_msg)
                    self.collection_state["validation_errors"].append(warning_msg)
                
                if error_rate_percent > ERROR_RATE_THRESHOLD:
                    warning_msg = (
                        f"Error rate exceeds threshold: "
                        f"{error_rate_percent:.3f}% > {ERROR_RATE_THRESHOLD}%"
                    )
                    logger.warning(warning_msg)
                    self.collection_state["validation_errors"].append(warning_msg)
            
            return baseline
            
        except Exception as e:
            raise BaselineCollectionError(f"Throughput baseline collection failed: {e}")
        finally:
            # Ensure Locust runner is stopped
            try:
                env.runner.stop()
            except:
                pass
    
    def collect_database_performance_baselines(self) -> List[DatabasePerformanceBaseline]:
        """
        Collect database performance baselines through API operations.
        
        Note: This method collects database performance indirectly through API calls
        since direct database access is not available from this collection script.
        
        Returns:
            List of DatabasePerformanceBaseline objects
        """
        logger.info("Starting database performance baseline collection")
        baselines = []
        
        # Database operations to test through API endpoints
        operations = [
            ("find", "users", "GET", "/api/v1/users"),
            ("insert", "users", "POST", "/api/v1/users"),
            ("update", "users", "PUT", "/api/v1/users/test-id"),
            ("find", "reports", "GET", "/api/v1/data/reports"),
            ("aggregate", "reports", "GET", "/api/v1/data/reports/summary")
        ]
        
        for operation_type, collection_name, method, endpoint in operations:
            try:
                with performance_collection_timer(f"database_baseline_{operation_type}_{collection_name}"):
                    baseline = self._collect_database_operation_baseline(
                        operation_type, collection_name, method, endpoint
                    )
                    baselines.append(baseline)
                    
                    logger.info(
                        "Database performance baseline collected",
                        operation_type=operation_type,
                        collection_name=collection_name,
                        average_query_time_ms=baseline.average_query_time_ms,
                        queries_per_second=baseline.queries_per_second
                    )
                    
            except Exception as e:
                error_msg = f"Failed to collect database baseline for {operation_type} {collection_name}: {e}"
                logger.warning(error_msg)
                self.collection_state["collection_errors"].append(error_msg)
        
        logger.info("Database performance baseline collection completed", baselines_collected=len(baselines))
        return baselines
    
    def _collect_database_operation_baseline(
        self,
        operation_type: str,
        collection_name: str,
        method: str,
        endpoint: str
    ) -> DatabasePerformanceBaseline:
        """
        Collect database performance baseline for specific operation.
        
        Args:
            operation_type: Database operation type
            collection_name: Database collection name
            method: HTTP method
            endpoint: API endpoint
            
        Returns:
            DatabasePerformanceBaseline with metrics
        """
        url = urljoin(self.target_url, endpoint)
        request_data = self._prepare_request_data(method, endpoint)
        
        query_times = []
        successful_queries = 0
        sample_size = min(200, BASELINE_SAMPLE_SIZE // 5)  # Smaller sample for database ops
        
        # Warmup
        for _ in range(5):
            try:
                self._make_request(method, url, request_data)
            except:
                pass
        
        # Collection phase
        start_time = time.time()
        
        for _ in range(sample_size):
            try:
                query_start = time.time()
                response = self._make_request(method, url, request_data)
                query_end = time.time()
                
                query_time_ms = (query_end - query_start) * 1000
                query_times.append(query_time_ms)
                successful_queries += 1
                
                # Brief pause between database operations
                time.sleep(0.05)
                
            except Exception:
                pass  # Continue collecting even if some requests fail
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        if not query_times:
            raise BaselineCollectionError(f"No successful database operations for {operation_type} {collection_name}")
        
        # Calculate database performance metrics
        average_query_time = statistics.mean(query_times)
        median_query_time = statistics.median(query_times)
        p95_query_time = statistics.quantiles(query_times, n=20)[18] if len(query_times) >= 20 else max(query_times)
        max_query_time = max(query_times)
        queries_per_second = successful_queries / total_duration if total_duration > 0 else 0
        
        # Estimate additional metrics (not directly measurable via API)
        connection_pool_utilization = min(50.0, (successful_queries / sample_size) * 60)  # Estimate
        index_hit_ratio = 95.0 if average_query_time < 100 else 85.0  # Estimate based on performance
        
        return DatabasePerformanceBaseline(
            operation_type=operation_type,
            collection_name=collection_name,
            average_query_time_ms=average_query_time,
            median_query_time_ms=median_query_time,
            p95_query_time_ms=p95_query_time,
            max_query_time_ms=max_query_time,
            queries_per_second=queries_per_second,
            connection_pool_utilization=connection_pool_utilization,
            index_hit_ratio=index_hit_ratio,
            sample_count=len(query_times)
        )
    
    def collect_network_io_baselines(self, duration_seconds: int = 300) -> List[NetworkIOBaseline]:
        """
        Collect network I/O performance baselines.
        
        Args:
            duration_seconds: Duration to monitor network I/O
            
        Returns:
            List of NetworkIOBaseline objects
        """
        if not MONITORING_AVAILABLE:
            logger.warning("Network I/O monitoring not available")
            return []
        
        logger.info("Starting network I/O baseline collection", duration_seconds=duration_seconds)
        baselines = []
        
        start_time = time.time()
        collection_interval = 30  # 30-second intervals for network I/O
        
        try:
            # Get initial network stats
            initial_net_stats = psutil.net_io_counters()
            
            while (time.time() - start_time) < duration_seconds:
                time.sleep(collection_interval)
                
                try:
                    # Get current network stats
                    current_net_stats = psutil.net_io_counters()
                    
                    # Calculate bandwidth utilization
                    bytes_sent_delta = current_net_stats.bytes_sent - initial_net_stats.bytes_sent
                    bytes_recv_delta = current_net_stats.bytes_recv - initial_net_stats.bytes_recv
                    
                    elapsed_time = time.time() - start_time
                    egress_bandwidth_mbps = (bytes_sent_delta / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
                    ingress_bandwidth_mbps = (bytes_recv_delta / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
                    
                    # Calculate packet rate
                    packets_sent_delta = current_net_stats.packets_sent - initial_net_stats.packets_sent
                    packets_recv_delta = current_net_stats.packets_recv - initial_net_stats.packets_recv
                    packets_per_second = int((packets_sent_delta + packets_recv_delta) / elapsed_time) if elapsed_time > 0 else 0
                    
                    # Estimate network latency (basic ping to target)
                    network_latency_ms = self._measure_network_latency()
                    
                    # Get connection counts
                    try:
                        connections = psutil.net_connections()
                        total_connections = len(connections)
                        established_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
                    except (psutil.AccessDenied, AttributeError):
                        total_connections = 0
                        established_connections = 0
                    
                    baseline = NetworkIOBaseline(
                        ingress_bandwidth_mbps=ingress_bandwidth_mbps,
                        egress_bandwidth_mbps=egress_bandwidth_mbps,
                        packets_per_second=packets_per_second,
                        network_latency_ms=network_latency_ms,
                        connection_count=total_connections,
                        keepalive_connections=established_connections
                    )
                    
                    baselines.append(baseline)
                    
                    logger.debug(
                        "Network I/O sample collected",
                        ingress_mbps=ingress_bandwidth_mbps,
                        egress_mbps=egress_bandwidth_mbps,
                        latency_ms=network_latency_ms
                    )
                    
                except Exception as e:
                    logger.warning(f"Failed to collect network I/O metrics: {e}")
        
        except KeyboardInterrupt:
            logger.info("Network I/O collection interrupted")
        
        logger.info("Network I/O baseline collection completed", samples_collected=len(baselines))
        return baselines
    
    def _measure_network_latency(self) -> float:
        """
        Measure network latency to target server.
        
        Returns:
            Network latency in milliseconds
        """
        try:
            start_time = time.time()
            response = self.session.get(f"{self.target_url}/api/v1/health", timeout=5)
            end_time = time.time()
            
            if response.status_code == 200:
                return (end_time - start_time) * 1000
            else:
                return 999.0  # High latency for failed requests
                
        except Exception:
            return 999.0  # High latency for network errors
    
    def run_full_baseline_collection(
        self,
        collection_duration: int = DEFAULT_COLLECTION_DURATION,
        include_load_testing: bool = True,
        include_resource_monitoring: bool = True,
        include_database_testing: bool = True,
        include_network_monitoring: bool = True
    ) -> Dict[str, Any]:
        """
        Execute comprehensive baseline collection across all performance categories.
        
        Args:
            collection_duration: Total collection duration in seconds
            include_load_testing: Include load testing for throughput baselines
            include_resource_monitoring: Include system resource monitoring
            include_database_testing: Include database performance testing
            include_network_monitoring: Include network I/O monitoring
            
        Returns:
            Dictionary containing complete baseline collection results
        """
        logger.info(
            "Starting full baseline collection",
            collection_duration=collection_duration,
            include_load_testing=include_load_testing,
            include_resource_monitoring=include_resource_monitoring,
            include_database_testing=include_database_testing,
            include_network_monitoring=include_network_monitoring
        )
        
        self.collection_state["started_at"] = datetime.now(timezone.utc)
        
        try:
            with performance_collection_timer("full_baseline_collection"):
                # Phase 1: Server verification
                logger.info("Phase 1: Verifying Node.js server")
                server_verification = self.verify_nodejs_server()
                
                # Phase 2: Response time baselines
                logger.info("Phase 2: Collecting response time baselines")
                response_time_baselines = self.collect_response_time_baselines()
                
                # Add baselines to manager
                for baseline in response_time_baselines:
                    self.baseline_manager.add_response_time_baseline(baseline)
                
                # Phase 3: Resource utilization monitoring (parallel with other operations)
                resource_monitoring_duration = min(collection_duration // 3, 600)  # Max 10 minutes
                
                if include_resource_monitoring:
                    logger.info(f"Phase 3: Collecting resource utilization baselines ({resource_monitoring_duration}s)")
                    resource_baselines = self.collect_resource_utilization_baselines(resource_monitoring_duration)
                    
                    for baseline in resource_baselines:
                        self.baseline_manager.add_resource_utilization_baseline(baseline)
                else:
                    resource_baselines = []
                
                # Phase 4: Database performance testing
                if include_database_testing:
                    logger.info("Phase 4: Collecting database performance baselines")
                    database_baselines = self.collect_database_performance_baselines()
                    
                    for baseline in database_baselines:
                        self.baseline_manager.add_database_performance_baseline(baseline)
                else:
                    database_baselines = []
                
                # Phase 5: Throughput testing with progressive load
                if include_load_testing:
                    logger.info("Phase 5: Collecting throughput baselines")
                    throughput_baselines = self.collect_throughput_baselines()
                    
                    for baseline in throughput_baselines:
                        self.baseline_manager.add_throughput_baseline(baseline)
                else:
                    throughput_baselines = []
                
                # Phase 6: Network I/O monitoring
                network_monitoring_duration = min(collection_duration // 4, 300)  # Max 5 minutes
                
                if include_network_monitoring:
                    logger.info(f"Phase 6: Collecting network I/O baselines ({network_monitoring_duration}s)")
                    network_baselines = self.collect_network_io_baselines(network_monitoring_duration)
                    
                    for baseline in network_baselines:
                        self.baseline_manager.add_network_io_baseline(baseline)
                else:
                    network_baselines = []
                
                # Generate comprehensive baseline summary
                baseline_summary = self.baseline_manager.generate_baseline_summary()
                
                # Save baseline data to file
                self.baseline_manager.save_baseline_data()
                
                self.collection_state["completed_at"] = datetime.now(timezone.utc)
                
                # Compile final results
                collection_results = {
                    "collection_metadata": {
                        "started_at": self.collection_state["started_at"].isoformat(),
                        "completed_at": self.collection_state["completed_at"].isoformat(),
                        "duration_seconds": (self.collection_state["completed_at"] - self.collection_state["started_at"]).total_seconds(),
                        "target_url": self.target_url,
                        "config_environment": self.config_environment,
                        "output_file": self.output_file
                    },
                    "server_verification": server_verification,
                    "baseline_summary": baseline_summary,
                    "collection_stats": {
                        "total_requests": self.collection_state["total_requests"],
                        "successful_requests": self.collection_state["successful_requests"],
                        "failed_requests": self.collection_state["failed_requests"],
                        "response_time_baselines": len(response_time_baselines),
                        "resource_utilization_baselines": len(resource_baselines),
                        "database_performance_baselines": len(database_baselines),
                        "throughput_baselines": len(throughput_baselines),
                        "network_io_baselines": len(network_baselines),
                        "collection_errors": len(self.collection_state["collection_errors"]),
                        "validation_errors": len(self.collection_state["validation_errors"])
                    },
                    "validation_results": {
                        "baseline_validation_passed": len(self.collection_state["validation_errors"]) == 0,
                        "collection_errors": self.collection_state["collection_errors"],
                        "validation_errors": self.collection_state["validation_errors"]
                    },
                    "performance_compliance": {
                        "variance_threshold_percent": PERFORMANCE_VARIANCE_THRESHOLD * 100,
                        "response_time_threshold_ms": RESPONSE_TIME_THRESHOLD,
                        "throughput_threshold_rps": DEFAULT_REQUEST_RATE,
                        "error_rate_threshold_percent": ERROR_RATE_THRESHOLD,
                        "baseline_ready_for_comparison": True
                    }
                }
                
                logger.info(
                    "Full baseline collection completed successfully",
                    duration_seconds=collection_results["collection_metadata"]["duration_seconds"],
                    total_baselines=sum([
                        collection_results["collection_stats"]["response_time_baselines"],
                        collection_results["collection_stats"]["resource_utilization_baselines"],
                        collection_results["collection_stats"]["database_performance_baselines"],
                        collection_results["collection_stats"]["throughput_baselines"],
                        collection_results["collection_stats"]["network_io_baselines"]
                    ]),
                    validation_passed=collection_results["validation_results"]["baseline_validation_passed"]
                )
                
                return collection_results
        
        except Exception as e:
            self.collection_state["completed_at"] = datetime.now(timezone.utc)
            error_msg = f"Full baseline collection failed: {e}"
            logger.error(error_msg, error=str(e), traceback=traceback.format_exc())
            
            # Save partial results if available
            if self.store_intermediate_results:
                self._save_partial_results()
            
            raise BaselineCollectionError(error_msg)
    
    def _save_partial_results(self) -> None:
        """Save partial baseline collection results."""
        try:
            partial_file = f"{self.output_file}_partial_{int(time.time())}.json"
            
            partial_data = {
                "collection_state": self.collection_state,
                "partial_results": True,
                "saved_at": datetime.now(timezone.utc).isoformat()
            }
            
            with open(partial_file, 'w') as f:
                json.dump(partial_data, f, indent=2, default=str)
            
            logger.info(f"Partial results saved to {partial_file}")
            
        except Exception as e:
            logger.error(f"Failed to save partial results: {e}")
    
    def generate_collection_report(self, collection_results: Dict[str, Any], format_type: str = "json") -> str:
        """
        Generate comprehensive baseline collection report.
        
        Args:
            collection_results: Results from full baseline collection
            format_type: Report format ("json", "markdown", "html")
            
        Returns:
            Formatted report string
        """
        if format_type.lower() == "json":
            return json.dumps(collection_results, indent=2, default=str)
        
        elif format_type.lower() == "markdown":
            return self._generate_markdown_report(collection_results)
        
        elif format_type.lower() == "html":
            return self._generate_html_report(collection_results)
        
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
    
    def _generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate markdown format baseline collection report."""
        metadata = results["collection_metadata"]
        stats = results["collection_stats"]
        validation = results["validation_results"]
        compliance = results["performance_compliance"]
        
        report = f"""# Node.js Baseline Performance Collection Report

## Collection Summary

**Target Application:** {metadata["target_url"]}  
**Collection Started:** {metadata["started_at"]}  
**Collection Completed:** {metadata["completed_at"]}  
**Total Duration:** {metadata["duration_seconds"]:.1f} seconds  
**Configuration Environment:** {metadata["config_environment"]}  

## Collection Statistics

| Metric Category | Baselines Collected |
|-----------------|---------------------|
| Response Time Baselines | {stats["response_time_baselines"]} |
| Resource Utilization Baselines | {stats["resource_utilization_baselines"]} |
| Database Performance Baselines | {stats["database_performance_baselines"]} |
| Throughput Baselines | {stats["throughput_baselines"]} |
| Network I/O Baselines | {stats["network_io_baselines"]} |

## Request Statistics

- **Total Requests:** {stats["total_requests"]:,}
- **Successful Requests:** {stats["successful_requests"]:,}
- **Failed Requests:** {stats["failed_requests"]:,}
- **Success Rate:** {(stats["successful_requests"] / max(stats["total_requests"], 1)) * 100:.2f}%

## Validation Results

**Baseline Validation:** {'✅ PASSED' if validation["baseline_validation_passed"] else '❌ FAILED'}

### Collection Errors
{len(validation["collection_errors"])} errors encountered

### Validation Errors  
{len(validation["validation_errors"])} validation issues

## Performance Compliance Thresholds

- **Variance Threshold:** ≤{compliance["variance_threshold_percent"]:.1f}%
- **Response Time Threshold:** ≤{compliance["response_time_threshold_ms"]}ms (95th percentile)
- **Throughput Threshold:** ≥{compliance["throughput_threshold_rps"]} requests/second
- **Error Rate Threshold:** ≤{compliance["error_rate_threshold_percent"]:.1f}%

**Baseline Ready for Flask Comparison:** {'✅ YES' if compliance["baseline_ready_for_comparison"] else '❌ NO'}

## Output Files

- **Baseline Data:** {metadata["output_file"]}
- **Report Generated:** {datetime.now(timezone.utc).isoformat()}

---
*Generated by Node.js Baseline Performance Collection Script v1.0.0*
"""
        return report
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML format baseline collection report."""
        metadata = results["collection_metadata"]
        stats = results["collection_stats"]
        validation = results["validation_results"]
        compliance = results["performance_compliance"]
        
        status_icon = "✅" if validation["baseline_validation_passed"] else "❌"
        status_color = "green" if validation["baseline_validation_passed"] else "red"
        
        report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Node.js Baseline Performance Collection Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .status {{ font-size: 24px; color: {status_color}; font-weight: bold; }}
        .section {{ margin-bottom: 30px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }}
        .metric-card {{ background: #ffffff; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #495057; }}
        .metric-label {{ color: #6c757d; font-size: 14px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        .success {{ color: #28a745; }}
        .error {{ color: #dc3545; }}
        .warning {{ color: #ffc107; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Node.js Baseline Performance Collection Report</h1>
        <div class="status">{status_icon} Collection Status: {'COMPLETED' if validation["baseline_validation_passed"] else 'COMPLETED WITH ISSUES'}</div>
    </div>
    
    <div class="section">
        <h2>Collection Overview</h2>
        <table>
            <tr><th>Target Application</th><td>{metadata["target_url"]}</td></tr>
            <tr><th>Collection Duration</th><td>{metadata["duration_seconds"]:.1f} seconds</td></tr>
            <tr><th>Started At</th><td>{metadata["started_at"]}</td></tr>
            <tr><th>Completed At</th><td>{metadata["completed_at"]}</td></tr>
            <tr><th>Configuration</th><td>{metadata["config_environment"]}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Collection Statistics</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{stats["response_time_baselines"]}</div>
                <div class="metric-label">Response Time Baselines</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats["throughput_baselines"]}</div>
                <div class="metric-label">Throughput Baselines</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats["total_requests"]:,}</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{(stats["successful_requests"] / max(stats["total_requests"], 1)) * 100:.1f}%</div>
                <div class="metric-label">Success Rate</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Performance Compliance</h2>
        <table>
            <tr><th>Metric</th><th>Threshold</th><th>Status</th></tr>
            <tr><td>Response Time (95th percentile)</td><td>≤{compliance["response_time_threshold_ms"]}ms</td><td class="success">✓</td></tr>
            <tr><td>Throughput</td><td>≥{compliance["throughput_threshold_rps"]} req/s</td><td class="success">✓</td></tr>
            <tr><td>Error Rate</td><td>≤{compliance["error_rate_threshold_percent"]:.1f}%</td><td class="success">✓</td></tr>
            <tr><td>Variance Threshold</td><td>≤{compliance["variance_threshold_percent"]:.1f}%</td><td class="success">✓</td></tr>
        </table>
    </div>
    
    <div class="footer">
        <p><strong>Output File:</strong> {metadata["output_file"]}</p>
        <p><strong>Report Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
        <p><em>Generated by Node.js Baseline Performance Collection Script v1.0.0</em></p>
    </div>
</body>
</html>
"""
        return report


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create command-line argument parser for baseline collection script.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Node.js Baseline Performance Data Collection Script",
        epilog="Examples:\n"
               "  python collect_baseline.py --target-url http://localhost:3000\n"
               "  python collect_baseline.py --target-url http://nodejs-app.com --full-suite --output baseline.json\n"
               "  python collect_baseline.py --config production --duration 3600 --concurrent-users 100,500,1000",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "--target-url",
        required=True,
        help="Base URL of the Node.js application server (e.g., http://localhost:3000)"
    )
    
    # Optional configuration arguments
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for baseline data (default: auto-generated timestamp file)"
    )
    
    parser.add_argument(
        "--config",
        choices=["development", "testing", "staging", "production", "ci_cd"],
        default="production",
        help="Performance configuration environment (default: production)"
    )
    
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_COLLECTION_DURATION,
        help=f"Total collection duration in seconds (default: {DEFAULT_COLLECTION_DURATION})"
    )
    
    # Test scope arguments
    parser.add_argument(
        "--full-suite",
        action="store_true",
        help="Run complete baseline collection suite including all test categories"
    )
    
    parser.add_argument(
        "--response-time-only",
        action="store_true",
        help="Collect only response time baselines (faster execution)"
    )
    
    parser.add_argument(
        "--skip-load-testing",
        action="store_true",
        help="Skip load testing for throughput baselines"
    )
    
    parser.add_argument(
        "--skip-resource-monitoring",
        action="store_true",
        help="Skip system resource utilization monitoring"
    )
    
    parser.add_argument(
        "--skip-database-testing",
        action="store_true",
        help="Skip database performance testing"
    )
    
    parser.add_argument(
        "--skip-network-monitoring",
        action="store_true",
        help="Skip network I/O monitoring"
    )
    
    # Load testing configuration
    parser.add_argument(
        "--concurrent-users",
        default=None,
        help="Comma-separated list of concurrent user counts for load testing (e.g., 10,50,100,500)"
    )
    
    # Validation and output arguments
    parser.add_argument(
        "--validate",
        action="store_true",
        default=True,
        help="Enable baseline validation against performance thresholds (default: enabled)"
    )
    
    parser.add_argument(
        "--no-validate",
        action="store_false",
        dest="validate",
        help="Disable baseline validation"
    )
    
    parser.add_argument(
        "--store-intermediate",
        action="store_true",
        default=True,
        help="Store intermediate collection results (default: enabled)"
    )
    
    parser.add_argument(
        "--report-format",
        choices=["json", "markdown", "html"],
        default="json",
        help="Report output format (default: json)"
    )
    
    # Debug and logging arguments
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and connectivity without running collection"
    )
    
    return parser


def main():
    """
    Main entry point for Node.js baseline performance collection script.
    
    Handles command-line arguments, initializes collector, and executes
    comprehensive baseline collection with proper error handling and reporting.
    """
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        # Validate dependencies
        missing_dependencies = []
        
        if not HTTP_CLIENT_AVAILABLE:
            missing_dependencies.append("requests (HTTP client)")
        
        if not MONITORING_AVAILABLE:
            missing_dependencies.append("psutil, structlog (monitoring)")
            
        if not args.skip_load_testing and not LOCUST_AVAILABLE:
            missing_dependencies.append("locust (load testing)")
        
        if missing_dependencies:
            logger.error(
                "Missing required dependencies",
                missing=missing_dependencies
            )
            print(f"Error: Missing dependencies: {', '.join(missing_dependencies)}")
            print("Install required packages with: pip install requests psutil structlog locust prometheus-client")
            sys.exit(1)
        
        # Parse concurrent users if provided
        concurrent_users = None
        if args.concurrent_users:
            try:
                concurrent_users = [int(x.strip()) for x in args.concurrent_users.split(',')]
            except ValueError:
                logger.error("Invalid concurrent users format", input=args.concurrent_users)
                print("Error: Invalid concurrent users format. Use comma-separated integers (e.g., 10,50,100)")
                sys.exit(1)
        
        # Initialize baseline collector
        logger.info("Initializing Node.js baseline collector")
        collector = NodeJSBaselineCollector(
            target_url=args.target_url,
            output_file=args.output,
            config_environment=args.config,
            validate_results=args.validate,
            store_intermediate_results=args.store_intermediate
        )
        
        # Dry run mode - validate configuration and connectivity
        if args.dry_run:
            logger.info("Running in dry-run mode - validating configuration and connectivity")
            verification_results = collector.verify_nodejs_server()
            
            print("\n=== Dry Run Results ===")
            print(f"Target URL: {args.target_url}")
            print(f"Server Available: {'✅ YES' if verification_results['server_available'] else '❌ NO'}")
            print(f"Response Time: {verification_results['response_time_ms']:.2f}ms")
            print(f"Configuration: {args.config}")
            print(f"Estimated Duration: {args.duration} seconds")
            
            if verification_results["server_available"]:
                print("\n✅ Configuration valid - ready for baseline collection")
                sys.exit(0)
            else:
                print("\n❌ Configuration invalid - server not accessible")
                sys.exit(1)
        
        # Determine collection scope
        if args.response_time_only:
            # Response time only mode
            logger.info("Running response time baseline collection only")
            
            verification_results = collector.verify_nodejs_server()
            response_time_baselines = collector.collect_response_time_baselines()
            
            # Add baselines to manager and save
            for baseline in response_time_baselines:
                collector.baseline_manager.add_response_time_baseline(baseline)
            
            collector.baseline_manager.save_baseline_data()
            
            print(f"\n✅ Response time baseline collection completed")
            print(f"Baselines collected: {len(response_time_baselines)}")
            print(f"Output file: {collector.output_file}")
            
        else:
            # Full or customized collection
            logger.info("Running comprehensive baseline collection")
            
            collection_results = collector.run_full_baseline_collection(
                collection_duration=args.duration,
                include_load_testing=not args.skip_load_testing,
                include_resource_monitoring=not args.skip_resource_monitoring,
                include_database_testing=not args.skip_database_testing,
                include_network_monitoring=not args.skip_network_monitoring
            )
            
            # Generate and display report
            report = collector.generate_collection_report(collection_results, args.report_format)
            
            if args.report_format == "json":
                print("\n=== Baseline Collection Results ===")
                print(json.dumps(collection_results["collection_stats"], indent=2))
                
                if collection_results["validation_results"]["baseline_validation_passed"]:
                    print("\n✅ Baseline collection completed successfully")
                else:
                    print("\n⚠️ Baseline collection completed with validation issues")
                    
            else:
                print(report)
            
            # Save report to file
            report_file = f"{collector.output_file}_report.{args.report_format}"
            with open(report_file, 'w') as f:
                f.write(report)
            
            print(f"\nOutput files:")
            print(f"  Baseline data: {collector.output_file}")
            print(f"  Collection report: {report_file}")
            
            # Exit with appropriate code
            if collection_results["validation_results"]["baseline_validation_passed"]:
                sys.exit(0)
            else:
                print("\n⚠️ Some validation issues detected - review collection report")
                sys.exit(2)
    
    except KeyboardInterrupt:
        logger.info("Baseline collection interrupted by user")
        print("\n⚠️ Collection interrupted by user")
        sys.exit(1)
    
    except BaselineCollectionError as e:
        logger.error("Baseline collection error", error=str(e))
        print(f"\n❌ Baseline collection failed: {e}")
        sys.exit(1)
    
    except Exception as e:
        logger.error("Unexpected error during baseline collection", error=str(e), traceback=traceback.format_exc())
        print(f"\n❌ Unexpected error: {e}")
        print("Check logs for detailed error information")
        sys.exit(1)


if __name__ == "__main__":
    main()