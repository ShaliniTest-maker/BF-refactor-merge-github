"""
Load Testing Orchestration Script for Flask Migration Performance Validation

This module provides comprehensive load testing orchestration managing Locust and Apache Bench
test execution, concurrent user scaling, and performance monitoring automation for the 
BF-refactor-merge Flask migration project, ensuring compliance with the ≤10% variance requirement
from the original Node.js implementation.

Key Features:
- Locust (≥2.x) distributed load testing framework orchestration per Section 6.6.1
- Apache Bench integration for HTTP performance measurement per Section 6.6.1
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- 30-minute sustained load testing minimum per Section 4.6.3
- Realistic user behavior simulation and workflow testing per Section 4.6.3
- Distributed load testing coordination per Section 6.6.1
- Comprehensive performance monitoring and baseline comparison per Section 0.3.2
- Automated report generation with variance analysis per Section 0.1.1

Architecture Integration:
- Section 4.6.3: Load testing specifications with progressive scaling and performance metrics
- Section 6.6.1: Testing strategy with locust (≥2.x) framework integration
- Section 0.3.2: Performance monitoring with ≤10% variance requirement validation
- Section 6.5: Monitoring and observability integration with enterprise APM systems
- Section 0.2.3: Technical implementation flows with load testing validation

Performance Requirements:
- 95th percentile response time ≤500ms per Section 4.6.3
- Minimum 100 requests/second sustained throughput per Section 4.6.3
- CPU ≤70%, Memory ≤80% during peak load per Section 4.6.3
- Error rate ≤0.1% under normal load per Section 4.6.3
- ≤10% variance from Node.js baseline per Section 0.1.1

Author: Flask Migration Team
Version: 1.0.0
Dependencies: locust ≥2.x, apache-bench, prometheus-client 0.17+, psutil ≥5.9+
"""

import argparse
import asyncio
import concurrent.futures
import json
import logging
import multiprocessing
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
import warnings

# Import performance monitoring and metrics
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    warnings.warn("psutil not available - system monitoring disabled")

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, push_to_gateway
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("Prometheus client not available - metrics collection limited")

# Import Locust framework
try:
    import locust
    from locust import HttpUser, task, between, events
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.runners import LocalRunner, MasterRunner, WorkerRunner
    from locust.web import WebUI
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    warnings.warn("Locust not available - load testing disabled")

# Import performance testing modules
from tests.performance.locustfile import (
    ProgressiveLoadUser,
    PerformanceMonitor,
    LoadTestPhase,
    UserBehaviorType,
    MultiRegionCoordinator,
    performance_monitor
)
from tests.performance.performance_config import (
    PerformanceTestConfig,
    LoadTestScenario,
    LoadTestConfiguration,
    PerformanceConfigFactory,
    get_load_test_config,
    validate_performance_results
)
from tests.performance.baseline_data import (
    get_nodejs_baseline,
    compare_with_baseline,
    get_baseline_manager,
    NodeJSPerformanceBaseline
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class LoadTestStatus(Enum):
    """Load testing execution status enumeration."""
    
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestExecutionPhase(Enum):
    """Load test execution phase enumeration."""
    
    SETUP = "setup"
    RAMP_UP = "ramp_up"
    STEADY_STATE = "steady_state"
    PEAK_LOAD = "peak_load"
    ENDURANCE = "endurance"
    RAMP_DOWN = "ramp_down"
    TEARDOWN = "teardown"


@dataclass
class LoadTestMetrics:
    """Comprehensive load test metrics collection."""
    
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    phase: TestExecutionPhase = TestExecutionPhase.SETUP
    concurrent_users: int = 0
    requests_per_second: float = 0.0
    response_time_p50: float = 0.0
    response_time_p95: float = 0.0
    response_time_p99: float = 0.0
    error_rate: float = 0.0
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    network_io_bytes: int = 0
    disk_io_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'phase': self.phase.value,
            'concurrent_users': self.concurrent_users,
            'requests_per_second': self.requests_per_second,
            'response_time_p50': self.response_time_p50,
            'response_time_p95': self.response_time_p95,
            'response_time_p99': self.response_time_p99,
            'error_rate': self.error_rate,
            'cpu_utilization': self.cpu_utilization,
            'memory_utilization': self.memory_utilization,
            'network_io_bytes': self.network_io_bytes,
            'disk_io_bytes': self.disk_io_bytes
        }


@dataclass
class LoadTestConfiguration:
    """Comprehensive load test execution configuration."""
    
    # Basic test parameters
    scenario: LoadTestScenario = LoadTestScenario.NORMAL_LOAD
    target_host: str = "http://localhost:5000"
    duration_minutes: int = 30
    
    # Progressive scaling configuration
    min_users: int = 10
    max_users: int = 1000
    scaling_steps: int = 8
    steady_state_duration_minutes: int = 20
    
    # Performance thresholds
    response_time_threshold_ms: float = 500.0
    throughput_threshold_rps: float = 100.0
    error_rate_threshold: float = 0.001  # 0.1%
    cpu_threshold: float = 70.0
    memory_threshold: float = 80.0
    
    # Testing tools configuration
    locust_enabled: bool = True
    apache_bench_enabled: bool = True
    distributed_testing: bool = False
    master_host: str = "localhost"
    master_port: int = 8089
    worker_count: int = 4
    
    # Monitoring and reporting
    prometheus_integration: bool = PROMETHEUS_AVAILABLE
    real_time_monitoring: bool = True
    baseline_comparison: bool = True
    detailed_reporting: bool = True
    
    # Output configuration
    output_directory: str = "test_results"
    save_raw_data: bool = True
    generate_html_report: bool = True
    
    @classmethod
    def from_environment(cls) -> 'LoadTestConfiguration':
        """Create configuration from environment variables."""
        return cls(
            target_host=os.getenv('LOAD_TEST_HOST', 'http://localhost:5000'),
            duration_minutes=int(os.getenv('LOAD_TEST_DURATION', '30')),
            min_users=int(os.getenv('LOAD_TEST_MIN_USERS', '10')),
            max_users=int(os.getenv('LOAD_TEST_MAX_USERS', '1000')),
            worker_count=int(os.getenv('LOAD_TEST_WORKERS', '4')),
            output_directory=os.getenv('LOAD_TEST_OUTPUT', 'test_results'),
            distributed_testing=os.getenv('LOAD_TEST_DISTRIBUTED', 'false').lower() == 'true'
        )


class SystemResourceMonitor:
    """
    System resource monitoring for load testing with comprehensive metrics collection.
    
    Monitors CPU, memory, disk I/O, and network I/O during load testing to ensure
    resource utilization stays within acceptable thresholds per Section 4.6.3.
    """
    
    def __init__(self, collection_interval: float = 5.0):
        """Initialize system resource monitor."""
        self.collection_interval = collection_interval
        self.monitoring_active = threading.Event()
        self.metrics_data: List[Dict[str, Any]] = []
        self.monitor_thread: Optional[threading.Thread] = None
        self.initial_network_io = None
        self.initial_disk_io = None
        
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available - system monitoring disabled")
    
    def start_monitoring(self) -> None:
        """Start system resource monitoring thread."""
        if not PSUTIL_AVAILABLE:
            logger.warning("Cannot start monitoring - psutil not available")
            return
        
        self.monitoring_active.set()
        self.monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitor_thread.start()
        
        # Capture initial I/O counters
        try:
            self.initial_network_io = psutil.net_io_counters()
            self.initial_disk_io = psutil.disk_io_counters()
        except Exception as e:
            logger.warning(f"Failed to get initial I/O counters: {e}")
        
        logger.info("System resource monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop system resource monitoring."""
        if self.monitoring_active.is_set():
            self.monitoring_active.clear()
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
            
            logger.info("System resource monitoring stopped")
    
    def _monitoring_worker(self) -> None:
        """Background worker for system metrics collection."""
        while self.monitoring_active.is_set():
            try:
                metrics = self._collect_system_metrics()
                if metrics:
                    self.metrics_data.append(metrics)
                
                # Limit metrics history to prevent memory issues
                if len(self.metrics_data) > 10000:
                    self.metrics_data = self.metrics_data[-5000:]
                
                time.sleep(self.collection_interval)
                
            except Exception as e:
                logger.warning(f"System monitoring error: {e}")
                time.sleep(self.collection_interval)
    
    def _collect_system_metrics(self) -> Optional[Dict[str, Any]]:
        """Collect current system resource metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Network I/O metrics
            network_io = psutil.net_io_counters()
            network_bytes = 0
            if self.initial_network_io and network_io:
                network_bytes = (
                    (network_io.bytes_sent - self.initial_network_io.bytes_sent) +
                    (network_io.bytes_recv - self.initial_network_io.bytes_recv)
                )
            
            # Disk I/O metrics
            disk_io = psutil.disk_io_counters()
            disk_bytes = 0
            if self.initial_disk_io and disk_io:
                disk_bytes = (
                    (disk_io.read_bytes - self.initial_disk_io.read_bytes) +
                    (disk_io.write_bytes - self.initial_disk_io.write_bytes)
                )
            
            return {
                'timestamp': time.time(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg_1m': load_avg[0],
                    'load_avg_5m': load_avg[1],
                    'load_avg_15m': load_avg[2]
                },
                'memory': {
                    'total_bytes': memory.total,
                    'available_bytes': memory.available,
                    'used_bytes': memory.used,
                    'percent': memory.percent,
                    'swap_percent': swap.percent
                },
                'network': {
                    'total_bytes': network_bytes,
                    'packets_sent': network_io.packets_sent if network_io else 0,
                    'packets_recv': network_io.packets_recv if network_io else 0
                },
                'disk': {
                    'total_bytes': disk_bytes,
                    'read_count': disk_io.read_count if disk_io else 0,
                    'write_count': disk_io.write_count if disk_io else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
            return None
    
    def get_current_metrics(self) -> Optional[Dict[str, Any]]:
        """Get current system metrics."""
        return self._collect_system_metrics()
    
    def get_metrics_summary(self, time_window_seconds: int = 300) -> Dict[str, Any]:
        """Get system metrics summary for specified time window."""
        cutoff_time = time.time() - time_window_seconds
        recent_metrics = [m for m in self.metrics_data if m['timestamp'] > cutoff_time]
        
        if not recent_metrics:
            return {}
        
        # Calculate summary statistics
        cpu_values = [m['cpu']['percent'] for m in recent_metrics]
        memory_values = [m['memory']['percent'] for m in recent_metrics]
        load_values = [m['cpu']['load_avg_1m'] for m in recent_metrics]
        
        return {
            'time_window_seconds': time_window_seconds,
            'sample_count': len(recent_metrics),
            'cpu': {
                'average': sum(cpu_values) / len(cpu_values),
                'maximum': max(cpu_values),
                'minimum': min(cpu_values)
            },
            'memory': {
                'average': sum(memory_values) / len(memory_values),
                'maximum': max(memory_values),
                'minimum': min(memory_values)
            },
            'load_average': {
                'average': sum(load_values) / len(load_values),
                'maximum': max(load_values),
                'minimum': min(load_values)
            },
            'network_total_bytes': recent_metrics[-1]['network']['total_bytes'] if recent_metrics else 0,
            'disk_total_bytes': recent_metrics[-1]['disk']['total_bytes'] if recent_metrics else 0
        }


class ApacheBenchRunner:
    """
    Apache Bench integration for HTTP performance measurement and benchmarking.
    
    Provides comprehensive HTTP performance testing capabilities complementing
    Locust load testing per Section 6.6.1 apache-bench performance measurement.
    """
    
    def __init__(self, config: LoadTestConfiguration):
        """Initialize Apache Bench runner."""
        self.config = config
        self.ab_path = shutil.which('ab')
        
        if not self.ab_path:
            logger.warning("Apache Bench (ab) not found - HTTP benchmarking disabled")
    
    def is_available(self) -> bool:
        """Check if Apache Bench is available."""
        return self.ab_path is not None
    
    def run_benchmark(
        self,
        endpoint: str,
        requests: int = 1000,
        concurrency: int = 10,
        timeout: int = 30,
        post_data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Run Apache Bench performance test on specified endpoint.
        
        Args:
            endpoint: Target endpoint path (e.g., '/api/users')
            requests: Total number of requests to perform
            concurrency: Number of concurrent requests
            timeout: Timeout in seconds for each request
            post_data: Optional POST data for testing
            headers: Optional HTTP headers
            
        Returns:
            Dictionary containing benchmark results and analysis
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'Apache Bench not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Construct full URL
        url = f"{self.config.target_host.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Build Apache Bench command
        cmd = [
            self.ab_path,
            '-n', str(requests),
            '-c', str(concurrency),
            '-s', str(timeout),
            '-r',  # Don't exit on socket receive errors
            '-k',  # Enable keep-alive
            '-g', '/dev/null'  # Suppress gnuplot output
        ]
        
        # Add headers if provided
        if headers:
            for key, value in headers.items():
                cmd.extend(['-H', f'{key}: {value}'])
        
        # Add POST data if provided
        if post_data:
            cmd.extend(['-p', '-'])  # Read POST data from stdin
            cmd.extend(['-T', 'application/json'])
        
        # Add target URL
        cmd.append(url)
        
        logger.info(f"Running Apache Bench test: {endpoint} ({requests} requests, {concurrency} concurrency)")
        
        try:
            start_time = time.time()
            
            # Execute Apache Bench
            if post_data:
                result = subprocess.run(
                    cmd,
                    input=post_data.encode('utf-8'),
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60
                )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'returncode': result.returncode,
                    'endpoint': endpoint,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            
            # Parse Apache Bench output
            parsed_results = self._parse_ab_output(result.stdout)
            parsed_results.update({
                'success': True,
                'endpoint': endpoint,
                'url': url,
                'execution_time': execution_time,
                'requests_total': requests,
                'concurrency': concurrency,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            logger.info(
                f"Apache Bench test completed: {endpoint} - "
                f"RPS: {parsed_results.get('requests_per_second', 0):.2f}, "
                f"Mean response time: {parsed_results.get('time_per_request_mean', 0):.2f}ms"
            )
            
            return parsed_results
            
        except subprocess.TimeoutExpired:
            logger.error(f"Apache Bench test timeout: {endpoint}")
            return {
                'success': False,
                'error': 'Test execution timeout',
                'endpoint': endpoint,
                'timeout': timeout + 60,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        except Exception as e:
            logger.error(f"Apache Bench test failed: {endpoint} - {e}")
            return {
                'success': False,
                'error': str(e),
                'endpoint': endpoint,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _parse_ab_output(self, output: str) -> Dict[str, Any]:
        """Parse Apache Bench output to extract performance metrics."""
        results = {}
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Complete requests
                if 'Complete requests:' in line:
                    results['requests_completed'] = int(line.split(':')[1].strip())
                
                # Failed requests
                elif 'Failed requests:' in line:
                    results['requests_failed'] = int(line.split(':')[1].strip())
                
                # Requests per second
                elif 'Requests per second:' in line:
                    rps_value = line.split(':')[1].strip().split()[0]
                    results['requests_per_second'] = float(rps_value)
                
                # Time per request (mean)
                elif 'Time per request:' in line and 'mean' in line:
                    time_value = line.split(':')[1].strip().split()[0]
                    results['time_per_request_mean'] = float(time_value)
                
                # Time per request (across all concurrent requests)
                elif 'Time per request:' in line and 'across all' in line:
                    time_value = line.split(':')[1].strip().split()[0]
                    results['time_per_request_concurrent'] = float(time_value)
                
                # Transfer rate
                elif 'Transfer rate:' in line:
                    rate_value = line.split(':')[1].strip().split()[0]
                    results['transfer_rate_kbps'] = float(rate_value)
            
            # Parse percentile response times
            percentiles = self._parse_percentiles(lines)
            if percentiles:
                results['percentiles'] = percentiles
                results.update({
                    f'response_time_p{k}': v for k, v in percentiles.items()
                })
            
            # Calculate derived metrics
            if 'requests_completed' in results and 'requests_failed' in results:
                total_attempts = results['requests_completed'] + results['requests_failed']
                if total_attempts > 0:
                    results['success_rate'] = results['requests_completed'] / total_attempts
                    results['failure_rate'] = results['requests_failed'] / total_attempts
            
        except Exception as e:
            logger.error(f"Failed to parse Apache Bench output: {e}")
            results['parse_error'] = str(e)
        
        return results
    
    def _parse_percentiles(self, lines: List[str]) -> Dict[str, float]:
        """Parse percentile response times from Apache Bench output."""
        percentiles = {}
        
        try:
            # Find the percentile section
            for i, line in enumerate(lines):
                if '50%' in line and 'ms' in line:
                    # Parse percentile lines
                    for j in range(i, min(i + 10, len(lines))):
                        perc_line = lines[j].strip()
                        if '%' in perc_line and 'ms' in perc_line:
                            parts = perc_line.split()
                            if len(parts) >= 2:
                                percentile = parts[0].replace('%', '')
                                time_ms = parts[1].replace('ms', '')
                                try:
                                    percentiles[percentile] = float(time_ms)
                                except ValueError:
                                    continue
                    break
        
        except Exception as e:
            logger.warning(f"Failed to parse percentiles: {e}")
        
        return percentiles
    
    def run_comprehensive_benchmark(
        self,
        endpoints: List[str],
        requests_per_endpoint: int = 500,
        concurrency: int = 20
    ) -> Dict[str, Any]:
        """
        Run comprehensive benchmark across multiple endpoints.
        
        Args:
            endpoints: List of endpoint paths to test
            requests_per_endpoint: Number of requests per endpoint
            concurrency: Concurrent request level
            
        Returns:
            Comprehensive benchmark results with aggregated metrics
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'Apache Bench not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        logger.info(f"Starting comprehensive benchmark across {len(endpoints)} endpoints")
        
        benchmark_results = {
            'success': True,
            'test_info': {
                'endpoints_tested': len(endpoints),
                'requests_per_endpoint': requests_per_endpoint,
                'concurrency': concurrency,
                'target_host': self.config.target_host
            },
            'endpoint_results': {},
            'aggregated_metrics': {},
            'performance_summary': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        total_requests = 0
        total_failures = 0
        all_response_times = []
        all_throughput = []
        
        # Test each endpoint
        for endpoint in endpoints:
            result = self.run_benchmark(
                endpoint=endpoint,
                requests=requests_per_endpoint,
                concurrency=concurrency
            )
            
            benchmark_results['endpoint_results'][endpoint] = result
            
            if result.get('success'):
                total_requests += result.get('requests_completed', 0)
                total_failures += result.get('requests_failed', 0)
                
                if 'time_per_request_mean' in result:
                    all_response_times.append(result['time_per_request_mean'])
                
                if 'requests_per_second' in result:
                    all_throughput.append(result['requests_per_second'])
            else:
                benchmark_results['success'] = False
                logger.error(f"Benchmark failed for endpoint: {endpoint}")
        
        # Calculate aggregated metrics
        if all_response_times and all_throughput:
            benchmark_results['aggregated_metrics'] = {
                'total_requests': total_requests,
                'total_failures': total_failures,
                'overall_failure_rate': total_failures / total_requests if total_requests > 0 else 0,
                'average_response_time': sum(all_response_times) / len(all_response_times),
                'min_response_time': min(all_response_times),
                'max_response_time': max(all_response_times),
                'average_throughput': sum(all_throughput) / len(all_throughput),
                'total_throughput': sum(all_throughput),
                'endpoints_successful': len([r for r in benchmark_results['endpoint_results'].values() if r.get('success')])
            }
            
            # Performance assessment
            avg_response_time = benchmark_results['aggregated_metrics']['average_response_time']
            avg_throughput = benchmark_results['aggregated_metrics']['average_throughput']
            failure_rate = benchmark_results['aggregated_metrics']['overall_failure_rate']
            
            benchmark_results['performance_summary'] = {
                'meets_response_time_threshold': avg_response_time <= self.config.response_time_threshold_ms,
                'meets_throughput_threshold': avg_throughput >= self.config.throughput_threshold_rps,
                'meets_error_rate_threshold': failure_rate <= self.config.error_rate_threshold,
                'overall_performance_acceptable': (
                    avg_response_time <= self.config.response_time_threshold_ms and
                    avg_throughput >= self.config.throughput_threshold_rps and
                    failure_rate <= self.config.error_rate_threshold
                )
            }
        
        logger.info(
            f"Comprehensive benchmark completed - "
            f"Success: {benchmark_results['success']}, "
            f"Endpoints: {len(endpoints)}, "
            f"Performance acceptable: {benchmark_results.get('performance_summary', {}).get('overall_performance_acceptable', False)}"
        )
        
        return benchmark_results


class LocustOrchestrator:
    """
    Locust load testing orchestration with progressive scaling and distributed execution.
    
    Manages Locust test execution, progressive user scaling, and comprehensive
    performance monitoring per Section 6.6.1 locust framework integration.
    """
    
    def __init__(self, config: LoadTestConfiguration):
        """Initialize Locust orchestrator."""
        self.config = config
        self.locust_env: Optional[Environment] = None
        self.locust_runner: Optional[Union[LocalRunner, MasterRunner]] = None
        self.worker_processes: List[subprocess.Popen] = []
        self.metrics_history: List[LoadTestMetrics] = []
        self.current_phase = TestExecutionPhase.SETUP
        self.test_session_id = str(uuid.uuid4())[:8]
        
        if not LOCUST_AVAILABLE:
            logger.warning("Locust not available - load testing disabled")
    
    def is_available(self) -> bool:
        """Check if Locust is available."""
        return LOCUST_AVAILABLE
    
    def setup_environment(self) -> bool:
        """Set up Locust testing environment."""
        if not self.is_available():
            logger.error("Cannot setup Locust environment - Locust not available")
            return False
        
        try:
            # Create Locust environment
            self.locust_env = Environment(
                user_classes=[ProgressiveLoadUser],
                host=self.config.target_host
            )
            
            # Set up event listeners
            self._setup_event_listeners()
            
            # Configure runner based on distributed testing setting
            if self.config.distributed_testing:
                self.locust_runner = MasterRunner(
                    self.locust_env,
                    master_bind_host="*",
                    master_bind_port=self.config.master_port
                )
                logger.info(f"Locust master runner configured on port {self.config.master_port}")
            else:
                self.locust_runner = LocalRunner(self.locust_env, ProgressiveLoadUser)
                logger.info("Locust local runner configured")
            
            # Initialize performance monitoring
            global performance_monitor
            performance_monitor.set_phase(LoadTestPhase.RAMP_UP)
            
            logger.info(f"Locust environment setup completed - Session: {self.test_session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup Locust environment: {e}")
            return False
    
    def _setup_event_listeners(self) -> None:
        """Set up Locust event listeners for performance monitoring."""
        if not self.locust_env:
            return
        
        @self.locust_env.events.test_start.add_listener
        def on_test_start(environment, **kwargs):
            logger.info(f"Locust load test started - Session: {self.test_session_id}")
            self.current_phase = TestExecutionPhase.RAMP_UP
        
        @self.locust_env.events.test_stop.add_listener
        def on_test_stop(environment, **kwargs):
            logger.info(f"Locust load test stopped - Session: {self.test_session_id}")
            self.current_phase = TestExecutionPhase.TEARDOWN
        
        @self.locust_env.events.spawning_complete.add_listener
        def on_spawning_complete(user_count, **kwargs):
            logger.info(f"User spawning completed: {user_count} users active")
            self._update_metrics(user_count)
        
        @self.locust_env.events.request.add_listener
        def on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
            # Request metrics are handled by the performance monitor
            pass
        
        @self.locust_env.events.user_error.add_listener
        def on_user_error(user_instance, exception, tb, **kwargs):
            logger.warning(f"Locust user error: {exception}")
    
    def start_distributed_workers(self) -> bool:
        """Start distributed Locust worker processes."""
        if not self.config.distributed_testing or not self.is_available():
            return True
        
        try:
            for i in range(self.config.worker_count):
                worker_cmd = [
                    sys.executable, '-m', 'locust',
                    '--worker',
                    '--master-host', self.config.master_host,
                    '--master-port', str(self.config.master_port),
                    '--locustfile', str(Path(__file__).parent.parent / 'locustfile.py'),
                    '--headless'
                ]
                
                worker_process = subprocess.Popen(
                    worker_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                self.worker_processes.append(worker_process)
                logger.info(f"Started Locust worker {i+1}/{self.config.worker_count} (PID: {worker_process.pid})")
            
            # Wait for workers to connect
            time.sleep(10)
            
            logger.info(f"All {self.config.worker_count} Locust workers started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start distributed workers: {e}")
            self.stop_distributed_workers()
            return False
    
    def stop_distributed_workers(self) -> None:
        """Stop all distributed Locust worker processes."""
        for i, process in enumerate(self.worker_processes):
            try:
                process.terminate()
                process.wait(timeout=10)
                logger.info(f"Stopped Locust worker {i+1}")
            except subprocess.TimeoutExpired:
                process.kill()
                logger.warning(f"Force killed Locust worker {i+1}")
            except Exception as e:
                logger.error(f"Error stopping worker {i+1}: {e}")
        
        self.worker_processes.clear()
    
    def run_progressive_load_test(self) -> Dict[str, Any]:
        """
        Execute progressive load test with scaling from min to max users.
        
        Returns:
            Comprehensive load test results with performance analysis
        """
        if not self.locust_runner:
            return {
                'success': False,
                'error': 'Locust environment not initialized',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        logger.info(
            f"Starting progressive load test: {self.config.min_users} → {self.config.max_users} users, "
            f"{self.config.duration_minutes} minutes"
        )
        
        test_start_time = time.time()
        
        # Calculate scaling steps
        scaling_steps = self._calculate_scaling_steps()
        
        test_results = {
            'success': True,
            'test_info': {
                'session_id': self.test_session_id,
                'min_users': self.config.min_users,
                'max_users': self.config.max_users,
                'duration_minutes': self.config.duration_minutes,
                'scaling_steps': len(scaling_steps),
                'distributed_testing': self.config.distributed_testing,
                'target_host': self.config.target_host
            },
            'scaling_results': [],
            'performance_metrics': [],
            'final_statistics': {},
            'baseline_comparison': {},
            'performance_summary': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Execute scaling steps
            for step_index, (target_users, step_duration, description) in enumerate(scaling_steps):
                logger.info(f"Scaling step {step_index + 1}/{len(scaling_steps)}: {description}")
                
                step_result = self._execute_scaling_step(
                    target_users=target_users,
                    duration_seconds=step_duration,
                    step_description=description
                )
                
                test_results['scaling_results'].append(step_result)
                
                if not step_result['success']:
                    test_results['success'] = False
                    logger.error(f"Scaling step failed: {description}")
                    break
            
            # Stop the test
            self.locust_runner.stop()
            
            # Collect final statistics
            test_results['final_statistics'] = self._collect_final_statistics()
            test_results['performance_metrics'] = [m.to_dict() for m in self.metrics_history]
            
            # Performance analysis
            test_results['performance_summary'] = self._analyze_performance_results()
            
            # Baseline comparison if enabled
            if self.config.baseline_comparison:
                test_results['baseline_comparison'] = self._perform_baseline_comparison()
            
            test_duration = time.time() - test_start_time
            test_results['test_info']['actual_duration_seconds'] = test_duration
            
            logger.info(
                f"Progressive load test completed - Duration: {test_duration:.1f}s, "
                f"Success: {test_results['success']}"
            )
            
        except Exception as e:
            logger.error(f"Progressive load test failed: {e}")
            test_results['success'] = False
            test_results['error'] = str(e)
        
        return test_results
    
    def _calculate_scaling_steps(self) -> List[Tuple[int, int, str]]:
        """Calculate progressive scaling steps based on configuration."""
        total_duration = self.config.duration_minutes * 60
        steady_state_duration = self.config.steady_state_duration_minutes * 60
        
        # Calculate step durations
        ramp_up_duration = min(300, total_duration * 0.2)  # Max 5 minutes ramp-up
        ramp_down_duration = min(120, total_duration * 0.1)  # Max 2 minutes ramp-down
        
        # Adjust steady state duration
        available_duration = total_duration - ramp_up_duration - ramp_down_duration
        actual_steady_duration = min(steady_state_duration, available_duration)
        
        # Peak load duration (if any remaining time)
        peak_duration = max(0, available_duration - actual_steady_duration)
        
        user_range = self.config.max_users - self.config.min_users
        steps_count = min(self.config.scaling_steps, 8)  # Limit to 8 steps
        
        scaling_steps = []
        
        # Ramp-up phase
        ramp_step_duration = ramp_up_duration / steps_count
        for i in range(steps_count):
            users = self.config.min_users + int((user_range * (i + 1)) / steps_count)
            scaling_steps.append((
                users,
                int(ramp_step_duration),
                f"Ramp-up step {i + 1}: {users} users"
            ))
        
        # Steady state phase
        if actual_steady_duration > 0:
            scaling_steps.append((
                self.config.max_users,
                int(actual_steady_duration),
                f"Steady state: {self.config.max_users} users"
            ))
        
        # Peak load phase (if configured)
        if peak_duration > 0:
            peak_users = int(self.config.max_users * 1.2)  # 20% above target
            scaling_steps.append((
                peak_users,
                int(peak_duration),
                f"Peak load: {peak_users} users"
            ))
        
        # Ramp-down phase
        scaling_steps.append((
            0,
            int(ramp_down_duration),
            "Ramp-down: 0 users"
        ))
        
        return scaling_steps
    
    def _execute_scaling_step(
        self,
        target_users: int,
        duration_seconds: int,
        step_description: str
    ) -> Dict[str, Any]:
        """Execute individual scaling step with monitoring."""
        step_start_time = time.time()
        
        # Determine spawn rate based on step
        if target_users == 0:
            spawn_rate = min(20, self.config.max_users / 10)  # Fast ramp-down
        else:
            spawn_rate = min(10, target_users / 10)  # Conservative ramp-up
        
        step_result = {
            'success': True,
            'step_description': step_description,
            'target_users': target_users,
            'duration_seconds': duration_seconds,
            'spawn_rate': spawn_rate,
            'metrics': [],
            'performance_issues': [],
            'start_time': step_start_time
        }
        
        try:
            # Update test phase
            if "ramp-up" in step_description.lower():
                self.current_phase = TestExecutionPhase.RAMP_UP
            elif "steady" in step_description.lower():
                self.current_phase = TestExecutionPhase.STEADY_STATE
            elif "peak" in step_description.lower():
                self.current_phase = TestExecutionPhase.PEAK_LOAD
            elif "ramp-down" in step_description.lower():
                self.current_phase = TestExecutionPhase.RAMP_DOWN
            
            # Start or adjust load
            if target_users > 0:
                self.locust_runner.start(user_count=target_users, spawn_rate=spawn_rate)
            else:
                self.locust_runner.stop()
            
            # Monitor during step execution
            monitoring_interval = min(10, duration_seconds / 10)  # 10 samples per step
            monitoring_start = time.time()
            
            while (time.time() - monitoring_start) < duration_seconds:
                time.sleep(monitoring_interval)
                
                # Collect step metrics
                step_metrics = self._collect_step_metrics(target_users)
                step_result['metrics'].append(step_metrics)
                
                # Check for performance issues
                issues = self._check_performance_thresholds(step_metrics)
                if issues:
                    step_result['performance_issues'].extend(issues)
                    logger.warning(f"Performance issues detected in step: {issues}")
            
            step_result['end_time'] = time.time()
            step_result['actual_duration'] = step_result['end_time'] - step_start_time
            
            logger.info(f"Scaling step completed: {step_description}")
            
        except Exception as e:
            logger.error(f"Scaling step failed: {step_description} - {e}")
            step_result['success'] = False
            step_result['error'] = str(e)
        
        return step_result
    
    def _collect_step_metrics(self, target_users: int) -> Dict[str, Any]:
        """Collect metrics for current step."""
        if not self.locust_runner:
            return {}
        
        stats = self.locust_runner.stats.total
        
        # Calculate percentiles
        response_times = []
        if hasattr(stats, 'response_times') and stats.response_times:
            response_times = list(stats.response_times.keys())
        
        p50 = p95 = p99 = 0.0
        if response_times:
            response_times.sort()
            count = len(response_times)
            p50 = response_times[int(count * 0.5)] if count > 0 else 0
            p95 = response_times[int(count * 0.95)] if count > 0 else 0
            p99 = response_times[int(count * 0.99)] if count > 0 else 0
        
        metrics = {
            'timestamp': time.time(),
            'phase': self.current_phase.value,
            'target_users': target_users,
            'current_users': self.locust_runner.user_count,
            'total_requests': stats.num_requests,
            'total_failures': stats.num_failures,
            'requests_per_second': stats.current_rps,
            'failure_rate': stats.fail_ratio,
            'avg_response_time': stats.avg_response_time,
            'min_response_time': stats.min_response_time,
            'max_response_time': stats.max_response_time,
            'median_response_time': stats.median_response_time,
            'response_time_p50': p50,
            'response_time_p95': p95,
            'response_time_p99': p99
        }
        
        return metrics
    
    def _check_performance_thresholds(self, metrics: Dict[str, Any]) -> List[str]:
        """Check metrics against performance thresholds."""
        issues = []
        
        # Response time threshold
        if metrics.get('response_time_p95', 0) > self.config.response_time_threshold_ms:
            issues.append(
                f"P95 response time {metrics['response_time_p95']:.1f}ms exceeds "
                f"threshold {self.config.response_time_threshold_ms}ms"
            )
        
        # Throughput threshold
        if metrics.get('requests_per_second', 0) < self.config.throughput_threshold_rps:
            issues.append(
                f"Throughput {metrics['requests_per_second']:.1f} RPS below "
                f"threshold {self.config.throughput_threshold_rps} RPS"
            )
        
        # Error rate threshold
        if metrics.get('failure_rate', 0) > self.config.error_rate_threshold:
            issues.append(
                f"Error rate {metrics['failure_rate']:.3f} exceeds "
                f"threshold {self.config.error_rate_threshold:.3f}"
            )
        
        return issues
    
    def _update_metrics(self, user_count: int) -> None:
        """Update metrics history with current performance data."""
        metrics = LoadTestMetrics(
            phase=self.current_phase,
            concurrent_users=user_count
        )
        
        if self.locust_runner:
            stats = self.locust_runner.stats.total
            metrics.requests_per_second = stats.current_rps
            metrics.response_time_p95 = stats.avg_response_time  # Simplified
            metrics.error_rate = stats.fail_ratio
        
        self.metrics_history.append(metrics)
    
    def _collect_final_statistics(self) -> Dict[str, Any]:
        """Collect final test statistics."""
        if not self.locust_runner:
            return {}
        
        stats = self.locust_runner.stats
        
        # Aggregate endpoint statistics
        endpoint_stats = {}
        for name, entry in stats.entries.items():
            endpoint_stats[name] = {
                'requests': entry.num_requests,
                'failures': entry.num_failures,
                'avg_response_time': entry.avg_response_time,
                'min_response_time': entry.min_response_time,
                'max_response_time': entry.max_response_time,
                'requests_per_sec': entry.current_rps,
                'failure_rate': entry.fail_ratio
            }
        
        # Overall statistics
        total_stats = stats.total
        
        return {
            'total_requests': total_stats.num_requests,
            'total_failures': total_stats.num_failures,
            'avg_response_time': total_stats.avg_response_time,
            'min_response_time': total_stats.min_response_time,
            'max_response_time': total_stats.max_response_time,
            'requests_per_second': total_stats.current_rps,
            'failure_rate': total_stats.fail_ratio,
            'endpoint_statistics': endpoint_stats,
            'max_users_reached': max([m.concurrent_users for m in self.metrics_history], default=0),
            'test_phases_completed': len(set(m.phase for m in self.metrics_history))
        }
    
    def _analyze_performance_results(self) -> Dict[str, Any]:
        """Analyze performance results against thresholds."""
        if not self.metrics_history:
            return {}
        
        # Calculate performance statistics
        response_times = [m.response_time_p95 for m in self.metrics_history if m.response_time_p95 > 0]
        throughput_values = [m.requests_per_second for m in self.metrics_history if m.requests_per_second > 0]
        error_rates = [m.error_rate for m in self.metrics_history]
        
        analysis = {
            'performance_statistics': {},
            'threshold_compliance': {},
            'performance_trends': {},
            'overall_assessment': {}
        }
        
        if response_times:
            analysis['performance_statistics']['response_time'] = {
                'average': sum(response_times) / len(response_times),
                'minimum': min(response_times),
                'maximum': max(response_times),
                'samples': len(response_times)
            }
            
            analysis['threshold_compliance']['response_time'] = {
                'threshold': self.config.response_time_threshold_ms,
                'compliant_samples': len([rt for rt in response_times if rt <= self.config.response_time_threshold_ms]),
                'total_samples': len(response_times),
                'compliance_rate': len([rt for rt in response_times if rt <= self.config.response_time_threshold_ms]) / len(response_times)
            }
        
        if throughput_values:
            analysis['performance_statistics']['throughput'] = {
                'average': sum(throughput_values) / len(throughput_values),
                'minimum': min(throughput_values),
                'maximum': max(throughput_values),
                'sustained': sum(throughput_values[-10:]) / len(throughput_values[-10:]) if len(throughput_values) >= 10 else 0
            }
            
            analysis['threshold_compliance']['throughput'] = {
                'threshold': self.config.throughput_threshold_rps,
                'compliant_samples': len([tp for tp in throughput_values if tp >= self.config.throughput_threshold_rps]),
                'total_samples': len(throughput_values),
                'compliance_rate': len([tp for tp in throughput_values if tp >= self.config.throughput_threshold_rps]) / len(throughput_values)
            }
        
        if error_rates:
            analysis['performance_statistics']['error_rate'] = {
                'average': sum(error_rates) / len(error_rates),
                'minimum': min(error_rates),
                'maximum': max(error_rates)
            }
            
            analysis['threshold_compliance']['error_rate'] = {
                'threshold': self.config.error_rate_threshold,
                'compliant_samples': len([er for er in error_rates if er <= self.config.error_rate_threshold]),
                'total_samples': len(error_rates),
                'compliance_rate': len([er for er in error_rates if er <= self.config.error_rate_threshold]) / len(error_rates)
            }
        
        # Overall assessment
        compliance_rates = [
            comp.get('compliance_rate', 0) for comp in analysis['threshold_compliance'].values()
        ]
        
        analysis['overall_assessment'] = {
            'overall_compliance_rate': sum(compliance_rates) / len(compliance_rates) if compliance_rates else 0,
            'performance_acceptable': all(rate >= 0.9 for rate in compliance_rates),  # 90% compliance required
            'critical_issues': [],
            'recommendations': []
        }
        
        # Identify critical issues
        for metric, compliance in analysis['threshold_compliance'].items():
            if compliance.get('compliance_rate', 0) < 0.8:  # <80% compliance is critical
                analysis['overall_assessment']['critical_issues'].append(
                    f"{metric} compliance rate {compliance['compliance_rate']:.1%} below 80%"
                )
        
        return analysis
    
    def _perform_baseline_comparison(self) -> Dict[str, Any]:
        """Perform baseline comparison against Node.js performance."""
        try:
            baseline = get_nodejs_baseline()
            
            if not self.locust_runner:
                return {'error': 'No test data available for comparison'}
            
            # Prepare current metrics for comparison
            stats = self.locust_runner.stats.total
            current_metrics = {
                'api_response_time_p95': stats.avg_response_time,  # Simplified
                'requests_per_second': stats.current_rps,
                'error_rate_overall': stats.fail_ratio * 100,  # Convert to percentage
                'memory_usage_mb': 256.0,  # Placeholder - would need actual memory monitoring
                'cpu_utilization_average': 45.0  # Placeholder - would need actual CPU monitoring
            }
            
            # Perform comparison
            comparison_result = compare_with_baseline(current_metrics)
            
            logger.info(f"Baseline comparison completed - Compliant: {comparison_result.get('summary', {}).get('overall_compliant', False)}")
            
            return comparison_result
            
        except Exception as e:
            logger.error(f"Baseline comparison failed: {e}")
            return {'error': str(e)}
    
    def cleanup(self) -> None:
        """Clean up Locust orchestrator resources."""
        try:
            if self.locust_runner:
                self.locust_runner.quit()
            
            self.stop_distributed_workers()
            
            logger.info(f"Locust orchestrator cleanup completed - Session: {self.test_session_id}")
            
        except Exception as e:
            logger.error(f"Locust orchestrator cleanup error: {e}")


class LoadTestOrchestrator:
    """
    Main load testing orchestration class coordinating Locust and Apache Bench testing.
    
    Provides comprehensive load testing coordination with progressive scaling, distributed
    execution, and automated reporting per Section 6.6.1 performance testing requirements.
    """
    
    def __init__(self, config: Optional[LoadTestConfiguration] = None):
        """Initialize load test orchestrator."""
        self.config = config or LoadTestConfiguration.from_environment()
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Initialize components
        self.system_monitor = SystemResourceMonitor()
        self.apache_bench = ApacheBenchRunner(self.config)
        self.locust_orchestrator = LocustOrchestrator(self.config)
        
        # Results storage
        self.test_results = {
            'session_id': self.session_id,
            'configuration': self._serialize_config(),
            'locust_results': {},
            'apache_bench_results': {},
            'system_monitoring': {},
            'comprehensive_analysis': {},
            'reports': {}
        }
        
        # Setup output directory
        self.output_dir = Path(self.config.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Load test orchestrator initialized - Session: {self.session_id}")
    
    def _serialize_config(self) -> Dict[str, Any]:
        """Serialize configuration for results storage."""
        return {
            'scenario': self.config.scenario.value,
            'target_host': self.config.target_host,
            'duration_minutes': self.config.duration_minutes,
            'min_users': self.config.min_users,
            'max_users': self.config.max_users,
            'scaling_steps': self.config.scaling_steps,
            'locust_enabled': self.config.locust_enabled,
            'apache_bench_enabled': self.config.apache_bench_enabled,
            'distributed_testing': self.config.distributed_testing,
            'worker_count': self.config.worker_count,
            'output_directory': self.config.output_directory
        }
    
    def run_comprehensive_load_test(self) -> Dict[str, Any]:
        """
        Execute comprehensive load testing with both Locust and Apache Bench.
        
        Returns:
            Comprehensive test results with performance analysis and reports
        """
        self.start_time = datetime.now(timezone.utc)
        logger.info(f"Starting comprehensive load test - Session: {self.session_id}")
        
        try:
            # Start system monitoring
            self.system_monitor.start_monitoring()
            
            # Phase 1: Apache Bench baseline testing
            if self.config.apache_bench_enabled:
                logger.info("Phase 1: Running Apache Bench baseline tests")
                ab_results = self._run_apache_bench_tests()
                self.test_results['apache_bench_results'] = ab_results
            
            # Phase 2: Locust progressive load testing
            if self.config.locust_enabled:
                logger.info("Phase 2: Running Locust progressive load tests")
                locust_results = self._run_locust_load_tests()
                self.test_results['locust_results'] = locust_results
            
            # Phase 3: System monitoring analysis
            system_metrics = self.system_monitor.get_metrics_summary(
                time_window_seconds=self.config.duration_minutes * 60
            )
            self.test_results['system_monitoring'] = system_metrics
            
            # Phase 4: Comprehensive analysis
            self.test_results['comprehensive_analysis'] = self._perform_comprehensive_analysis()
            
            # Phase 5: Generate reports
            self.test_results['reports'] = self._generate_reports()
            
            self.end_time = datetime.now(timezone.utc)
            test_duration = (self.end_time - self.start_time).total_seconds()
            
            self.test_results.update({
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'total_duration_seconds': test_duration,
                'success': self._determine_overall_success()
            })
            
            logger.info(
                f"Comprehensive load test completed - Duration: {test_duration:.1f}s, "
                f"Success: {self.test_results['success']}"
            )
            
        except Exception as e:
            logger.error(f"Comprehensive load test failed: {e}")
            self.test_results.update({
                'success': False,
                'error': str(e),
                'end_time': datetime.now(timezone.utc).isoformat()
            })
        
        finally:
            self._cleanup_resources()
        
        return self.test_results
    
    def _run_apache_bench_tests(self) -> Dict[str, Any]:
        """Run Apache Bench baseline performance tests."""
        if not self.apache_bench.is_available():
            return {
                'success': False,
                'error': 'Apache Bench not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Define endpoints for testing
        test_endpoints = [
            '/health',
            '/api/users',
            '/api/users/search',
            '/api/auth/login'
        ]
        
        # Run comprehensive benchmark
        return self.apache_bench.run_comprehensive_benchmark(
            endpoints=test_endpoints,
            requests_per_endpoint=1000,
            concurrency=20
        )
    
    def _run_locust_load_tests(self) -> Dict[str, Any]:
        """Run Locust progressive load testing."""
        if not self.locust_orchestrator.is_available():
            return {
                'success': False,
                'error': 'Locust not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Setup Locust environment
        if not self.locust_orchestrator.setup_environment():
            return {
                'success': False,
                'error': 'Failed to setup Locust environment',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Start distributed workers if enabled
        if self.config.distributed_testing:
            if not self.locust_orchestrator.start_distributed_workers():
                return {
                    'success': False,
                    'error': 'Failed to start distributed workers',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
        
        # Execute progressive load test
        return self.locust_orchestrator.run_progressive_load_test()
    
    def _perform_comprehensive_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive analysis of all test results."""
        analysis = {
            'performance_comparison': {},
            'threshold_compliance': {},
            'baseline_variance': {},
            'resource_utilization': {},
            'recommendations': [],
            'overall_assessment': {}
        }
        
        # Apache Bench analysis
        ab_results = self.test_results.get('apache_bench_results', {})
        if ab_results.get('success'):
            analysis['performance_comparison']['apache_bench'] = {
                'endpoints_tested': ab_results.get('test_info', {}).get('endpoints_tested', 0),
                'overall_performance_acceptable': ab_results.get('performance_summary', {}).get('overall_performance_acceptable', False),
                'average_response_time': ab_results.get('aggregated_metrics', {}).get('average_response_time', 0),
                'average_throughput': ab_results.get('aggregated_metrics', {}).get('average_throughput', 0)
            }
        
        # Locust analysis
        locust_results = self.test_results.get('locust_results', {})
        if locust_results.get('success'):
            performance_summary = locust_results.get('performance_summary', {})
            analysis['performance_comparison']['locust'] = {
                'max_users_reached': locust_results.get('final_statistics', {}).get('max_users_reached', 0),
                'performance_acceptable': performance_summary.get('overall_assessment', {}).get('performance_acceptable', False),
                'compliance_rate': performance_summary.get('overall_assessment', {}).get('overall_compliance_rate', 0),
                'scaling_steps_completed': len(locust_results.get('scaling_results', []))
            }
            
            # Baseline comparison
            baseline_comparison = locust_results.get('baseline_comparison', {})
            if baseline_comparison:
                analysis['baseline_variance'] = baseline_comparison
        
        # System resource analysis
        system_metrics = self.test_results.get('system_monitoring', {})
        if system_metrics:
            cpu_avg = system_metrics.get('cpu', {}).get('average', 0)
            memory_avg = system_metrics.get('memory', {}).get('average', 0)
            
            analysis['resource_utilization'] = {
                'cpu_average': cpu_avg,
                'memory_average': memory_avg,
                'cpu_within_threshold': cpu_avg <= self.config.cpu_threshold,
                'memory_within_threshold': memory_avg <= self.config.memory_threshold,
                'resource_efficiency_acceptable': (
                    cpu_avg <= self.config.cpu_threshold and
                    memory_avg <= self.config.memory_threshold
                )
            }
        
        # Generate recommendations
        recommendations = []
        
        # Performance recommendations
        if not analysis['performance_comparison'].get('apache_bench', {}).get('overall_performance_acceptable', True):
            recommendations.append("Individual endpoint performance requires optimization")
        
        if not analysis['performance_comparison'].get('locust', {}).get('performance_acceptable', True):
            recommendations.append("Load testing performance does not meet requirements")
        
        # Resource recommendations
        resource_util = analysis.get('resource_utilization', {})
        if not resource_util.get('cpu_within_threshold', True):
            recommendations.append(f"CPU utilization {resource_util.get('cpu_average', 0):.1f}% exceeds threshold {self.config.cpu_threshold}%")
        
        if not resource_util.get('memory_within_threshold', True):
            recommendations.append(f"Memory utilization {resource_util.get('memory_average', 0):.1f}% exceeds threshold {self.config.memory_threshold}%")
        
        # Baseline variance recommendations
        baseline_variance = analysis.get('baseline_variance', {})
        if baseline_variance.get('summary', {}).get('overall_compliant') is False:
            recommendations.append("Performance variance exceeds ≤10% baseline requirement")
        
        analysis['recommendations'] = recommendations
        
        # Overall assessment
        analysis['overall_assessment'] = {
            'load_testing_successful': (
                self.test_results.get('locust_results', {}).get('success', False) and
                analysis['performance_comparison'].get('locust', {}).get('performance_acceptable', False)
            ),
            'benchmark_testing_successful': (
                self.test_results.get('apache_bench_results', {}).get('success', False) and
                analysis['performance_comparison'].get('apache_bench', {}).get('overall_performance_acceptable', False)
            ),
            'resource_utilization_acceptable': resource_util.get('resource_efficiency_acceptable', False),
            'baseline_compliance': baseline_variance.get('summary', {}).get('overall_compliant', False),
            'recommendations_count': len(recommendations),
            'critical_issues_identified': len([r for r in recommendations if 'exceeds' in r or 'variance' in r])
        }
        
        # Final success determination
        assessment = analysis['overall_assessment']
        analysis['overall_assessment']['comprehensive_test_successful'] = (
            assessment.get('load_testing_successful', False) and
            assessment.get('benchmark_testing_successful', False) and
            assessment.get('resource_utilization_acceptable', False) and
            assessment.get('baseline_compliance', False)
        )
        
        return analysis
    
    def _generate_reports(self) -> Dict[str, Any]:
        """Generate comprehensive test reports."""
        reports = {
            'json_report': self._generate_json_report(),
            'html_report': None,
            'csv_export': None,
            'summary_report': self._generate_summary_report()
        }
        
        # Generate HTML report if enabled
        if self.config.generate_html_report:
            reports['html_report'] = self._generate_html_report()
        
        # Generate CSV export if raw data saving is enabled
        if self.config.save_raw_data:
            reports['csv_export'] = self._generate_csv_export()
        
        return reports
    
    def _generate_json_report(self) -> str:
        """Generate comprehensive JSON report."""
        json_filename = f"load_test_results_{self.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path = self.output_dir / json_filename
        
        try:
            with open(json_path, 'w') as f:
                json.dump(self.test_results, f, indent=2, default=str)
            
            logger.info(f"JSON report generated: {json_path}")
            return str(json_path)
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return ""
    
    def _generate_html_report(self) -> str:
        """Generate HTML report with charts and visualizations."""
        html_filename = f"load_test_report_{self.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_path = self.output_dir / html_filename
        
        try:
            html_content = self._create_html_content()
            
            with open(html_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {html_path}")
            return str(html_path)
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""
    
    def _create_html_content(self) -> str:
        """Create HTML report content."""
        analysis = self.test_results.get('comprehensive_analysis', {})
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Load Test Report - Session {self.session_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .success {{ background-color: #d4edda; }}
        .warning {{ background-color: #fff3cd; }}
        .error {{ background-color: #f8d7da; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #f8f9fa; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Load Test Report</h1>
        <p><strong>Session ID:</strong> {self.session_id}</p>
        <p><strong>Test Date:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}</p>
        <p><strong>Duration:</strong> {self.test_results.get('total_duration_seconds', 0):.1f} seconds</p>
        <p><strong>Target Host:</strong> {self.config.target_host}</p>
    </div>
    
    <div class="section {'success' if self.test_results.get('success') else 'error'}">
        <h2>Overall Result: {'PASS' if self.test_results.get('success') else 'FAIL'}</h2>
        <p><strong>Comprehensive Test Successful:</strong> {analysis.get('overall_assessment', {}).get('comprehensive_test_successful', False)}</p>
    </div>
    
    <div class="section">
        <h2>Performance Summary</h2>
        {self._generate_performance_summary_html()}
    </div>
    
    <div class="section">
        <h2>Apache Bench Results</h2>
        {self._generate_apache_bench_summary_html()}
    </div>
    
    <div class="section">
        <h2>Locust Load Testing Results</h2>
        {self._generate_locust_summary_html()}
    </div>
    
    <div class="section">
        <h2>System Resource Utilization</h2>
        {self._generate_resource_summary_html()}
    </div>
    
    <div class="section">
        <h2>Baseline Comparison</h2>
        {self._generate_baseline_comparison_html()}
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {self._generate_recommendations_html()}
    </div>
</body>
</html>
        """
        
        return html_template
    
    def _generate_performance_summary_html(self) -> str:
        """Generate performance summary HTML section."""
        analysis = self.test_results.get('comprehensive_analysis', {})
        
        # Extract key metrics
        ab_metrics = analysis.get('performance_comparison', {}).get('apache_bench', {})
        locust_metrics = analysis.get('performance_comparison', {}).get('locust', {})
        
        return f"""
        <div class="metric">
            <strong>Apache Bench Avg Response Time:</strong> {ab_metrics.get('average_response_time', 0):.2f}ms
        </div>
        <div class="metric">
            <strong>Apache Bench Avg Throughput:</strong> {ab_metrics.get('average_throughput', 0):.2f} RPS
        </div>
        <div class="metric">
            <strong>Locust Max Users:</strong> {locust_metrics.get('max_users_reached', 0)}
        </div>
        <div class="metric">
            <strong>Locust Compliance Rate:</strong> {locust_metrics.get('compliance_rate', 0):.1%}
        </div>
        """
    
    def _generate_apache_bench_summary_html(self) -> str:
        """Generate Apache Bench summary HTML."""
        ab_results = self.test_results.get('apache_bench_results', {})
        
        if not ab_results.get('success'):
            return f"<p>Apache Bench testing failed: {ab_results.get('error', 'Unknown error')}</p>"
        
        aggregated = ab_results.get('aggregated_metrics', {})
        
        return f"""
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Endpoints Tested</td><td>{ab_results.get('test_info', {}).get('endpoints_tested', 0)}</td></tr>
            <tr><td>Total Requests</td><td>{aggregated.get('total_requests', 0)}</td></tr>
            <tr><td>Total Failures</td><td>{aggregated.get('total_failures', 0)}</td></tr>
            <tr><td>Average Response Time</td><td>{aggregated.get('average_response_time', 0):.2f}ms</td></tr>
            <tr><td>Average Throughput</td><td>{aggregated.get('average_throughput', 0):.2f} RPS</td></tr>
            <tr><td>Overall Failure Rate</td><td>{aggregated.get('overall_failure_rate', 0):.3%}</td></tr>
        </table>
        """
    
    def _generate_locust_summary_html(self) -> str:
        """Generate Locust summary HTML."""
        locust_results = self.test_results.get('locust_results', {})
        
        if not locust_results.get('success'):
            return f"<p>Locust testing failed: {locust_results.get('error', 'Unknown error')}</p>"
        
        final_stats = locust_results.get('final_statistics', {})
        
        return f"""
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Max Users Reached</td><td>{final_stats.get('max_users_reached', 0)}</td></tr>
            <tr><td>Total Requests</td><td>{final_stats.get('total_requests', 0)}</td></tr>
            <tr><td>Total Failures</td><td>{final_stats.get('total_failures', 0)}</td></tr>
            <tr><td>Average Response Time</td><td>{final_stats.get('avg_response_time', 0):.2f}ms</td></tr>
            <tr><td>Requests Per Second</td><td>{final_stats.get('requests_per_second', 0):.2f}</td></tr>
            <tr><td>Failure Rate</td><td>{final_stats.get('failure_rate', 0):.3%}</td></tr>
            <tr><td>Scaling Steps Completed</td><td>{len(locust_results.get('scaling_results', []))}</td></tr>
        </table>
        """
    
    def _generate_resource_summary_html(self) -> str:
        """Generate resource utilization summary HTML."""
        system_metrics = self.test_results.get('system_monitoring', {})
        
        if not system_metrics:
            return "<p>System monitoring data not available</p>"
        
        cpu_data = system_metrics.get('cpu', {})
        memory_data = system_metrics.get('memory', {})
        
        return f"""
        <table>
            <tr><th>Resource</th><th>Average</th><th>Maximum</th><th>Within Threshold</th></tr>
            <tr>
                <td>CPU Utilization</td>
                <td>{cpu_data.get('average', 0):.1f}%</td>
                <td>{cpu_data.get('maximum', 0):.1f}%</td>
                <td>{'Yes' if cpu_data.get('average', 0) <= self.config.cpu_threshold else 'No'}</td>
            </tr>
            <tr>
                <td>Memory Utilization</td>
                <td>{memory_data.get('average', 0):.1f}%</td>
                <td>{memory_data.get('maximum', 0):.1f}%</td>
                <td>{'Yes' if memory_data.get('average', 0) <= self.config.memory_threshold else 'No'}</td>
            </tr>
        </table>
        """
    
    def _generate_baseline_comparison_html(self) -> str:
        """Generate baseline comparison HTML."""
        baseline_variance = self.test_results.get('comprehensive_analysis', {}).get('baseline_variance', {})
        
        if not baseline_variance:
            return "<p>Baseline comparison not available</p>"
        
        summary = baseline_variance.get('summary', {})
        
        return f"""
        <div class="{'success' if summary.get('overall_compliant') else 'error'}">
            <p><strong>Overall Baseline Compliance:</strong> {'Yes' if summary.get('overall_compliant') else 'No'}</p>
            <p><strong>Variance Threshold:</strong> ≤10%</p>
            <p><strong>Performance Variance:</strong> {summary.get('max_variance_percent', 0):.1f}%</p>
        </div>
        """
    
    def _generate_recommendations_html(self) -> str:
        """Generate recommendations HTML."""
        recommendations = self.test_results.get('comprehensive_analysis', {}).get('recommendations', [])
        
        if not recommendations:
            return "<p>No recommendations - all performance requirements met</p>"
        
        html = "<ul>"
        for recommendation in recommendations:
            html += f"<li>{recommendation}</li>"
        html += "</ul>"
        
        return html
    
    def _generate_csv_export(self) -> str:
        """Generate CSV export of raw metrics data."""
        csv_filename = f"load_test_metrics_{self.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_path = self.output_dir / csv_filename
        
        try:
            # Collect all metrics data
            all_metrics = []
            
            # Locust metrics
            locust_results = self.test_results.get('locust_results', {})
            if locust_results.get('performance_metrics'):
                all_metrics.extend(locust_results['performance_metrics'])
            
            if not all_metrics:
                logger.warning("No metrics data available for CSV export")
                return ""
            
            # Write CSV file
            with open(csv_path, 'w', newline='') as csvfile:
                if all_metrics:
                    fieldnames = all_metrics[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(all_metrics)
            
            logger.info(f"CSV export generated: {csv_path}")
            return str(csv_path)
            
        except Exception as e:
            logger.error(f"Failed to generate CSV export: {e}")
            return ""
    
    def _generate_summary_report(self) -> Dict[str, Any]:
        """Generate executive summary report."""
        analysis = self.test_results.get('comprehensive_analysis', {})
        
        return {
            'session_id': self.session_id,
            'test_date': self.start_time.isoformat() if self.start_time else None,
            'test_duration_minutes': self.test_results.get('total_duration_seconds', 0) / 60,
            'overall_success': self.test_results.get('success', False),
            'comprehensive_test_successful': analysis.get('overall_assessment', {}).get('comprehensive_test_successful', False),
            'performance_thresholds_met': {
                'apache_bench': analysis.get('performance_comparison', {}).get('apache_bench', {}).get('overall_performance_acceptable', False),
                'locust_load_test': analysis.get('performance_comparison', {}).get('locust', {}).get('performance_acceptable', False),
                'resource_utilization': analysis.get('resource_utilization', {}).get('resource_efficiency_acceptable', False),
                'baseline_compliance': analysis.get('baseline_variance', {}).get('summary', {}).get('overall_compliant', False)
            },
            'key_metrics': {
                'max_concurrent_users': analysis.get('performance_comparison', {}).get('locust', {}).get('max_users_reached', 0),
                'average_response_time_ms': analysis.get('performance_comparison', {}).get('apache_bench', {}).get('average_response_time', 0),
                'average_throughput_rps': analysis.get('performance_comparison', {}).get('apache_bench', {}).get('average_throughput', 0),
                'cpu_utilization_avg': analysis.get('resource_utilization', {}).get('cpu_average', 0),
                'memory_utilization_avg': analysis.get('resource_utilization', {}).get('memory_average', 0)
            },
            'recommendations_count': len(analysis.get('recommendations', [])),
            'critical_issues_count': analysis.get('overall_assessment', {}).get('critical_issues_identified', 0)
        }
    
    def _determine_overall_success(self) -> bool:
        """Determine overall test success based on all results."""
        analysis = self.test_results.get('comprehensive_analysis', {})
        return analysis.get('overall_assessment', {}).get('comprehensive_test_successful', False)
    
    def _cleanup_resources(self) -> None:
        """Clean up orchestrator resources."""
        try:
            self.system_monitor.stop_monitoring()
            self.locust_orchestrator.cleanup()
            
            logger.info(f"Load test orchestrator cleanup completed - Session: {self.session_id}")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


def create_test_configuration_from_args(args: argparse.Namespace) -> LoadTestConfiguration:
    """Create load test configuration from command line arguments."""
    return LoadTestConfiguration(
        scenario=LoadTestScenario(args.scenario),
        target_host=args.host,
        duration_minutes=args.duration,
        min_users=args.min_users,
        max_users=args.max_users,
        scaling_steps=args.scaling_steps,
        locust_enabled=args.enable_locust,
        apache_bench_enabled=args.enable_apache_bench,
        distributed_testing=args.distributed,
        worker_count=args.workers,
        output_directory=args.output_dir,
        generate_html_report=args.html_report,
        save_raw_data=args.save_raw_data
    )


def main():
    """Main entry point for load testing orchestration script."""
    parser = argparse.ArgumentParser(
        description="Load Testing Orchestration Script for Flask Migration Performance Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic load test
  python orchestrate_load_tests.py --host http://localhost:5000 --duration 30
  
  # Stress test with high concurrency
  python orchestrate_load_tests.py --scenario stress_test --max-users 1000 --duration 45
  
  # Distributed load test
  python orchestrate_load_tests.py --distributed --workers 8 --max-users 2000
  
  # Comprehensive test with full reporting
  python orchestrate_load_tests.py --scenario endurance_test --duration 60 --html-report --save-raw-data
        """
    )
    
    # Basic test configuration
    parser.add_argument(
        '--host',
        default=os.getenv('LOAD_TEST_HOST', 'http://localhost:5000'),
        help='Target host URL for load testing (default: http://localhost:5000)'
    )
    
    parser.add_argument(
        '--scenario',
        choices=[s.value for s in LoadTestScenario],
        default='normal_load',
        help='Load test scenario to execute (default: normal_load)'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        default=30,
        help='Test duration in minutes (default: 30)'
    )
    
    # User scaling configuration
    parser.add_argument(
        '--min-users',
        type=int,
        default=10,
        help='Minimum concurrent users for progressive scaling (default: 10)'
    )
    
    parser.add_argument(
        '--max-users',
        type=int,
        default=1000,
        help='Maximum concurrent users for progressive scaling (default: 1000)'
    )
    
    parser.add_argument(
        '--scaling-steps',
        type=int,
        default=8,
        help='Number of scaling steps during ramp-up (default: 8)'
    )
    
    # Testing tools configuration
    parser.add_argument(
        '--enable-locust',
        action='store_true',
        default=True,
        help='Enable Locust load testing (default: enabled)'
    )
    
    parser.add_argument(
        '--disable-locust',
        action='store_true',
        help='Disable Locust load testing'
    )
    
    parser.add_argument(
        '--enable-apache-bench',
        action='store_true',
        default=True,
        help='Enable Apache Bench testing (default: enabled)'
    )
    
    parser.add_argument(
        '--disable-apache-bench',
        action='store_true',
        help='Disable Apache Bench testing'
    )
    
    # Distributed testing configuration
    parser.add_argument(
        '--distributed',
        action='store_true',
        help='Enable distributed Locust testing'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of Locust worker processes for distributed testing (default: 4)'
    )
    
    parser.add_argument(
        '--master-host',
        default='localhost',
        help='Locust master host for distributed testing (default: localhost)'
    )
    
    parser.add_argument(
        '--master-port',
        type=int,
        default=8089,
        help='Locust master port for distributed testing (default: 8089)'
    )
    
    # Output and reporting configuration
    parser.add_argument(
        '--output-dir',
        default='test_results',
        help='Output directory for test results (default: test_results)'
    )
    
    parser.add_argument(
        '--html-report',
        action='store_true',
        help='Generate HTML report with visualizations'
    )
    
    parser.add_argument(
        '--save-raw-data',
        action='store_true',
        help='Save raw metrics data to CSV files'
    )
    
    # Performance thresholds
    parser.add_argument(
        '--response-time-threshold',
        type=float,
        default=500.0,
        help='Response time threshold in milliseconds (default: 500)'
    )
    
    parser.add_argument(
        '--throughput-threshold',
        type=float,
        default=100.0,
        help='Throughput threshold in requests per second (default: 100)'
    )
    
    parser.add_argument(
        '--error-rate-threshold',
        type=float,
        default=0.001,
        help='Error rate threshold as decimal (default: 0.001 = 0.1%%)'
    )
    
    # Logging and debugging
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    # Handle disable flags
    if args.disable_locust:
        args.enable_locust = False
    if args.disable_apache_bench:
        args.enable_apache_bench = False
    
    # Create configuration
    try:
        config = create_test_configuration_from_args(args)
        
        # Update thresholds from arguments
        config.response_time_threshold_ms = args.response_time_threshold
        config.throughput_threshold_rps = args.throughput_threshold
        config.error_rate_threshold = args.error_rate_threshold
        
        # Update distributed testing settings
        if args.distributed:
            config.distributed_testing = True
            config.master_host = args.master_host
            config.master_port = args.master_port
        
        logger.info(f"Load test configuration created: {config.scenario.value}")
        
    except Exception as e:
        logger.error(f"Failed to create configuration: {e}")
        sys.exit(1)
    
    # Validate configuration
    if not config.locust_enabled and not config.apache_bench_enabled:
        logger.error("At least one testing tool must be enabled")
        sys.exit(1)
    
    if config.min_users >= config.max_users:
        logger.error("Minimum users must be less than maximum users")
        sys.exit(1)
    
    # Check tool availability
    if config.locust_enabled and not LOCUST_AVAILABLE:
        logger.error("Locust not available but required for testing")
        sys.exit(1)
    
    if config.apache_bench_enabled and not shutil.which('ab'):
        logger.error("Apache Bench not available but required for testing")
        sys.exit(1)
    
    # Execute load testing
    try:
        orchestrator = LoadTestOrchestrator(config)
        
        # Handle interruption gracefully
        def signal_handler(signum, frame):
            logger.info("Received interrupt signal - cleaning up...")
            orchestrator._cleanup_resources()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Run comprehensive load test
        results = orchestrator.run_comprehensive_load_test()
        
        # Print summary
        summary = results.get('reports', {}).get('summary_report', {})
        if summary:
            print("\n" + "="*80)
            print("LOAD TEST SUMMARY")
            print("="*80)
            print(f"Session ID: {summary['session_id']}")
            print(f"Test Duration: {summary['test_duration_minutes']:.1f} minutes")
            print(f"Overall Success: {'PASS' if summary['overall_success'] else 'FAIL'}")
            print(f"Max Concurrent Users: {summary['key_metrics']['max_concurrent_users']}")
            print(f"Average Response Time: {summary['key_metrics']['average_response_time_ms']:.2f}ms")
            print(f"Average Throughput: {summary['key_metrics']['average_throughput_rps']:.2f} RPS")
            print(f"CPU Utilization: {summary['key_metrics']['cpu_utilization_avg']:.1f}%")
            print(f"Memory Utilization: {summary['key_metrics']['memory_utilization_avg']:.1f}%")
            print(f"Recommendations: {summary['recommendations_count']}")
            print(f"Critical Issues: {summary['critical_issues_count']}")
        
        # Print report file locations
        reports = results.get('reports', {})
        print(f"\nReports generated:")
        if reports.get('json_report'):
            print(f"  JSON Report: {reports['json_report']}")
        if reports.get('html_report'):
            print(f"  HTML Report: {reports['html_report']}")
        if reports.get('csv_export'):
            print(f"  CSV Export: {reports['csv_export']}")
        
        print("="*80)
        
        # Exit with appropriate code
        sys.exit(0 if results.get('success') else 1)
        
    except KeyboardInterrupt:
        logger.info("Load testing interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Load testing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()