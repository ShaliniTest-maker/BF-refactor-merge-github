"""
Locust Load Testing Configuration for Flask Migration Performance Validation

This comprehensive load testing configuration implements realistic user behavior simulation,
progressive scaling patterns, and baseline performance validation for the Flask migration
project. Ensures compliance with the ≤10% variance requirement per Section 0.1.1 through
comprehensive user workflow simulation and performance monitoring.

Key Features:
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- 30-minute sustained load testing minimum per Section 4.6.3
- Multi-region load simulation per Section 4.6.3 geographic distribution
- Realistic API workflow simulation per Section 4.6.3 user behavior simulation
- Concurrent request handling validation per Section 0.2.3 load testing
- Comprehensive performance monitoring and baseline comparison per Section 0.3.2
- CI/CD pipeline integration per Section 6.6.2 automated performance gates

Architecture Integration:
- Section 4.6.3: Load testing specifications with progressive user scaling and endurance testing
- Section 6.6.1: Locust ≥2.x performance testing framework with user behavior simulation
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 6.6.2: CI/CD integration with automated performance validation and regression detection

Author: Flask Migration Team
Version: 1.0.0
Dependencies: locust ≥2.x, requests ≥2.31+, structlog ≥23.1+, prometheus-client ≥0.17+
"""

import os
import sys
import time
import json
import random
import statistics
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from pathlib import Path
import logging
from dataclasses import dataclass, field

# Locust framework imports
from locust import HttpUser, task, between, events, runners
from locust.env import Environment
from locust.stats import stats_printer, stats_history
from locust.log import setup_logging
from locust.exception import RescheduleTask, StopUser

# Performance testing configuration imports
from performance_config import (
    PerformanceConfigFactory,
    LoadTestConfiguration,
    BaselineMetrics,
    PerformanceThreshold,
    LoadTestPhase,
    PerformanceTestType,
    BasePerformanceConfig
)
from baseline_data import (
    BaselineDataManager,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD
)

# Optional imports for enhanced functionality
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Performance test configuration
PERFORMANCE_ENV = os.getenv('PERFORMANCE_ENV', 'development')
LOAD_TEST_CONFIG = PerformanceConfigFactory.get_load_test_config(PERFORMANCE_ENV)
BASELINE_METRICS = PerformanceConfigFactory.get_baseline_metrics(PERFORMANCE_ENV)
PERFORMANCE_CONFIG = PerformanceConfigFactory.get_config(PERFORMANCE_ENV)

# Test execution parameters per Section 4.6.3
MIN_USERS = LOAD_TEST_CONFIG.min_users  # 10 concurrent users minimum
MAX_USERS = LOAD_TEST_CONFIG.max_users  # 1000 concurrent users maximum
TEST_DURATION = LOAD_TEST_CONFIG.test_duration  # 30-minute sustained load
USER_SPAWN_RATE = LOAD_TEST_CONFIG.user_spawn_rate  # Users spawned per second
TARGET_RPS = LOAD_TEST_CONFIG.target_request_rate  # 100 requests/second minimum

# Geographic distribution simulation per Section 4.6.3
GEOGRAPHIC_REGIONS = LOAD_TEST_CONFIG.geographic_regions
SCENARIO_WEIGHTS = LOAD_TEST_CONFIG.scenario_weights

# Performance validation thresholds per Section 0.1.1
VARIANCE_THRESHOLD = PERFORMANCE_CONFIG.PERFORMANCE_VARIANCE_THRESHOLD  # ≤10% variance
RESPONSE_TIME_THRESHOLD = PERFORMANCE_CONFIG.RESPONSE_TIME_P95_THRESHOLD  # 500ms P95
ERROR_RATE_THRESHOLD = PERFORMANCE_CONFIG.ERROR_RATE_THRESHOLD  # 0.1% error rate


@dataclass
class UserSession:
    """User session state management for realistic workflow simulation."""
    
    user_id: str
    session_token: Optional[str] = None
    auth_timestamp: Optional[datetime] = None
    request_count: int = 0
    error_count: int = 0
    last_request_time: Optional[datetime] = None
    geographic_region: str = "us-east-1"
    user_type: str = "standard"  # standard, premium, admin
    
    def is_authenticated(self) -> bool:
        """Check if user session is authenticated and valid."""
        if not self.session_token or not self.auth_timestamp:
            return False
        
        # Session expires after 1 hour
        session_age = datetime.now(timezone.utc) - self.auth_timestamp
        return session_age.total_seconds() < 3600
    
    def record_request(self, success: bool = True) -> None:
        """Record request execution for session tracking."""
        self.request_count += 1
        if not success:
            self.error_count += 1
        self.last_request_time = datetime.now(timezone.utc)
    
    def get_error_rate(self) -> float:
        """Calculate session error rate percentage."""
        if self.request_count == 0:
            return 0.0
        return (self.error_count / self.request_count) * 100.0


class PerformanceMetricsCollector:
    """
    Comprehensive performance metrics collection and validation system.
    
    Implements real-time performance monitoring, baseline comparison, and
    variance validation per Section 0.3.2 performance monitoring requirements.
    """
    
    def __init__(self):
        self.response_times: List[float] = []
        self.request_counts: Dict[str, int] = {}
        self.error_counts: Dict[str, int] = {}
        self.throughput_samples: List[float] = []
        self.concurrent_users_samples: List[int] = []
        self.variance_violations: List[Dict[str, Any]] = []
        
        # Prometheus metrics setup if available
        if PROMETHEUS_AVAILABLE:
            self.registry = CollectorRegistry()
            self.response_time_histogram = Histogram(
                'locust_response_time_seconds',
                'Response time histogram',
                ['method', 'endpoint'],
                registry=self.registry
            )
            self.request_counter = Counter(
                'locust_requests_total',
                'Total request count',
                ['method', 'endpoint', 'status'],
                registry=self.registry
            )
            self.throughput_gauge = Gauge(
                'locust_throughput_rps',
                'Current throughput in requests per second',
                registry=self.registry
            )
            self.concurrent_users_gauge = Gauge(
                'locust_concurrent_users',
                'Current concurrent user count',
                registry=self.registry
            )
    
    def record_request(self, method: str, endpoint: str, response_time: float, 
                      status_code: int, success: bool) -> None:
        """Record individual request metrics for performance analysis."""
        self.response_times.append(response_time)
        
        endpoint_key = f"{method} {endpoint}"
        self.request_counts[endpoint_key] = self.request_counts.get(endpoint_key, 0) + 1
        
        if not success or status_code >= 400:
            self.error_counts[endpoint_key] = self.error_counts.get(endpoint_key, 0) + 1
        
        # Update Prometheus metrics if available
        if PROMETHEUS_AVAILABLE:
            self.response_time_histogram.labels(method=method, endpoint=endpoint).observe(response_time / 1000.0)
            status = "success" if success else "error"
            self.request_counter.labels(method=method, endpoint=endpoint, status=status).inc()
    
    def record_throughput_sample(self, rps: float) -> None:
        """Record throughput sample for trend analysis."""
        self.throughput_samples.append(rps)
        if PROMETHEUS_AVAILABLE:
            self.throughput_gauge.set(rps)
    
    def record_concurrent_users(self, user_count: int) -> None:
        """Record concurrent user count for capacity analysis."""
        self.concurrent_users_samples.append(user_count)
        if PROMETHEUS_AVAILABLE:
            self.concurrent_users_gauge.set(user_count)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance summary with baseline comparison.
        
        Returns:
            Dictionary containing performance metrics and variance analysis
        """
        if not self.response_times:
            return {"error": "No performance data collected"}
        
        # Calculate response time statistics
        response_stats = {
            "mean_response_time_ms": statistics.mean(self.response_times),
            "median_response_time_ms": statistics.median(self.response_times),
            "p95_response_time_ms": self._calculate_percentile(self.response_times, 95),
            "p99_response_time_ms": self._calculate_percentile(self.response_times, 99),
            "min_response_time_ms": min(self.response_times),
            "max_response_time_ms": max(self.response_times),
            "std_deviation_ms": statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0.0
        }
        
        # Calculate throughput statistics
        throughput_stats = {
            "avg_throughput_rps": statistics.mean(self.throughput_samples) if self.throughput_samples else 0.0,
            "peak_throughput_rps": max(self.throughput_samples) if self.throughput_samples else 0.0,
            "min_throughput_rps": min(self.throughput_samples) if self.throughput_samples else 0.0
        }
        
        # Calculate error rate statistics
        total_requests = sum(self.request_counts.values())
        total_errors = sum(self.error_counts.values())
        error_rate = (total_errors / total_requests) * 100.0 if total_requests > 0 else 0.0
        
        # Validate against baseline performance
        baseline_validation = self._validate_against_baseline(response_stats, throughput_stats, error_rate)
        
        return {
            "response_time_metrics": response_stats,
            "throughput_metrics": throughput_stats,
            "error_metrics": {
                "total_requests": total_requests,
                "total_errors": total_errors,
                "error_rate_percent": error_rate
            },
            "baseline_validation": baseline_validation,
            "performance_compliance": {
                "within_variance_threshold": baseline_validation.get("overall_compliance", False),
                "response_time_compliant": response_stats["p95_response_time_ms"] <= RESPONSE_TIME_THRESHOLD,
                "error_rate_compliant": error_rate <= ERROR_RATE_THRESHOLD,
                "throughput_compliant": throughput_stats["avg_throughput_rps"] >= TARGET_RPS
            }
        }
    
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate specified percentile from data list."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int((percentile / 100.0) * len(sorted_data))
        index = min(index, len(sorted_data) - 1)
        return sorted_data[index]
    
    def _validate_against_baseline(self, response_stats: Dict[str, float], 
                                 throughput_stats: Dict[str, float], 
                                 error_rate: float) -> Dict[str, Any]:
        """Validate current performance against Node.js baseline metrics."""
        flask_metrics = {
            "response_time_ms": response_stats["mean_response_time_ms"],
            "requests_per_second": throughput_stats["avg_throughput_rps"],
            "error_rate_percent": error_rate
        }
        
        return validate_flask_performance_against_baseline(flask_metrics)


# Global performance metrics collector
performance_collector = PerformanceMetricsCollector()


class BaseFlaskUser(HttpUser):
    """
    Base Flask user class providing common functionality for load testing.
    
    Implements realistic user behavior patterns, session management, and
    performance monitoring per Section 6.6.1 user behavior simulation.
    """
    
    abstract = True
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests
    
    def __init__(self, environment):
        super().__init__(environment)
        self.session_data = UserSession(
            user_id=f"user_{random.randint(10000, 99999)}",
            geographic_region=random.choice(GEOGRAPHIC_REGIONS)
        )
        
        # Configure session headers for realistic requests
        self.client.headers.update({
            "User-Agent": self._get_realistic_user_agent(),
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "X-Requested-With": "XMLHttpRequest",
            "X-Client-Region": self.session_data.geographic_region
        })
    
    def on_start(self):
        """Initialize user session and perform authentication."""
        self.authenticate_user()
    
    def on_stop(self):
        """Clean up user session and log performance metrics."""
        self._log_user_performance_summary()
    
    def authenticate_user(self) -> bool:
        """
        Perform user authentication with realistic login flow.
        
        Returns:
            True if authentication successful, False otherwise
        """
        login_data = {
            "username": f"{self.session_data.user_id}@example.com",
            "password": "test_password_123"
        }
        
        start_time = time.time()
        
        with self.client.post(
            "/api/v1/auth/login",
            json=login_data,
            catch_response=True,
            name="Authentication Flow"
        ) as response:
            response_time = (time.time() - start_time) * 1000
            success = response.status_code == 200
            
            if success:
                try:
                    auth_data = response.json()
                    self.session_data.session_token = auth_data.get("access_token")
                    self.session_data.auth_timestamp = datetime.now(timezone.utc)
                    
                    # Add authorization header for subsequent requests
                    self.client.headers["Authorization"] = f"Bearer {self.session_data.session_token}"
                    response.success()
                except Exception as e:
                    success = False
                    response.failure(f"Authentication parsing failed: {str(e)}")
            else:
                response.failure(f"Authentication failed with status {response.status_code}")
            
            # Record authentication performance
            performance_collector.record_request(
                "POST", "/api/v1/auth/login", response_time, response.status_code, success
            )
            self.session_data.record_request(success)
            
            return success
    
    def refresh_authentication(self) -> bool:
        """
        Refresh user authentication token when expired.
        
        Returns:
            True if refresh successful, False otherwise
        """
        if not self.session_data.session_token:
            return self.authenticate_user()
        
        start_time = time.time()
        
        with self.client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {self.session_data.session_token}"},
            catch_response=True,
            name="Token Refresh"
        ) as response:
            response_time = (time.time() - start_time) * 1000
            success = response.status_code == 200
            
            if success:
                try:
                    auth_data = response.json()
                    self.session_data.session_token = auth_data.get("access_token")
                    self.session_data.auth_timestamp = datetime.now(timezone.utc)
                    
                    # Update authorization header
                    self.client.headers["Authorization"] = f"Bearer {self.session_data.session_token}"
                    response.success()
                except Exception as e:
                    success = False
                    response.failure(f"Token refresh parsing failed: {str(e)}")
            else:
                response.failure(f"Token refresh failed with status {response.status_code}")
            
            # Record refresh performance
            performance_collector.record_request(
                "POST", "/api/v1/auth/refresh", response_time, response.status_code, success
            )
            self.session_data.record_request(success)
            
            return success
    
    def make_authenticated_request(self, method: str, endpoint: str, 
                                 data: Optional[Dict] = None, 
                                 params: Optional[Dict] = None,
                                 name: Optional[str] = None) -> Any:
        """
        Make authenticated API request with performance monitoring.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Optional request data for POST/PUT requests
            params: Optional query parameters
            name: Optional custom name for request tracking
            
        Returns:
            Response object or None if request failed
        """
        # Ensure user is authenticated
        if not self.session_data.is_authenticated():
            if not self.refresh_authentication():
                raise StopUser("Authentication failed")
        
        request_name = name or f"{method} {endpoint}"
        start_time = time.time()
        
        # Prepare request arguments
        request_args = {
            "catch_response": True,
            "name": request_name
        }
        
        if data:
            request_args["json"] = data
        if params:
            request_args["params"] = params
        
        # Execute request based on method
        if method.upper() == "GET":
            response_context = self.client.get(endpoint, **request_args)
        elif method.upper() == "POST":
            response_context = self.client.post(endpoint, **request_args)
        elif method.upper() == "PUT":
            response_context = self.client.put(endpoint, **request_args)
        elif method.upper() == "DELETE":
            response_context = self.client.delete(endpoint, **request_args)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        with response_context as response:
            response_time = (time.time() - start_time) * 1000
            success = 200 <= response.status_code < 400
            
            if success:
                response.success()
            else:
                response.failure(f"Request failed with status {response.status_code}")
            
            # Record request performance
            performance_collector.record_request(
                method.upper(), endpoint, response_time, response.status_code, success
            )
            self.session_data.record_request(success)
            
            # Check for authentication errors
            if response.status_code == 401:
                self.session_data.session_token = None
                self.session_data.auth_timestamp = None
                if "Authorization" in self.client.headers:
                    del self.client.headers["Authorization"]
            
            return response if success else None
    
    def _get_realistic_user_agent(self) -> str:
        """Generate realistic User-Agent string for requests."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0"
        ]
        return random.choice(user_agents)
    
    def _log_user_performance_summary(self) -> None:
        """Log user session performance summary."""
        if STRUCTLOG_AVAILABLE:
            logger = structlog.get_logger()
            logger.info(
                "User session completed",
                user_id=self.session_data.user_id,
                total_requests=self.session_data.request_count,
                error_count=self.session_data.error_count,
                error_rate=self.session_data.get_error_rate(),
                geographic_region=self.session_data.geographic_region
            )


class APIReadOperationsUser(BaseFlaskUser):
    """
    API read operations user simulating data retrieval workflows.
    
    Implements 60% of user behavior per scenario weights focusing on
    data retrieval, search, and read-heavy operations per Section 4.6.3.
    """
    
    weight = int(SCENARIO_WEIGHTS["api_read_operations"] * 100)  # 60% of users
    
    @task(10)
    def get_user_profile(self):
        """Retrieve user profile information."""
        self.make_authenticated_request("GET", "/api/v1/users/profile")
    
    @task(8)
    def list_users(self):
        """List users with pagination."""
        params = {
            "page": random.randint(1, 10),
            "limit": random.choice([10, 25, 50])
        }
        self.make_authenticated_request("GET", "/api/v1/users", params=params)
    
    @task(6)
    def get_reports_data(self):
        """Retrieve reports data with filtering."""
        params = {
            "date_from": "2023-01-01",
            "date_to": "2023-12-31",
            "format": "json"
        }
        self.make_authenticated_request("GET", "/api/v1/data/reports", params=params)
    
    @task(5)
    def search_users(self):
        """Search users with query parameters."""
        params = {
            "q": random.choice(["john", "admin", "test", "user"]),
            "filters": "active:true"
        }
        self.make_authenticated_request("GET", "/api/v1/users/search", params=params)
    
    @task(4)
    def get_analytics_dashboard(self):
        """Retrieve analytics dashboard data."""
        self.make_authenticated_request("GET", "/api/v1/analytics/dashboard")
    
    @task(3)
    def get_system_status(self):
        """Check system health and status."""
        self.make_authenticated_request("GET", "/api/v1/health/status")


class APIWriteOperationsUser(BaseFlaskUser):
    """
    API write operations user simulating data modification workflows.
    
    Implements 25% of user behavior per scenario weights focusing on
    data creation, updates, and write-heavy operations per Section 4.6.3.
    """
    
    weight = int(SCENARIO_WEIGHTS["api_write_operations"] * 100)  # 25% of users
    
    @task(8)
    def create_user(self):
        """Create new user account."""
        user_data = {
            "username": f"testuser_{random.randint(1000, 9999)}",
            "email": f"test_{random.randint(1000, 9999)}@example.com",
            "full_name": f"Test User {random.randint(1000, 9999)}",
            "role": random.choice(["user", "moderator"])
        }
        self.make_authenticated_request("POST", "/api/v1/users", data=user_data)
    
    @task(6)
    def update_user_profile(self):
        """Update user profile information."""
        update_data = {
            "full_name": f"Updated User {random.randint(1000, 9999)}",
            "preferences": {
                "theme": random.choice(["light", "dark"]),
                "notifications": random.choice([True, False])
            }
        }
        self.make_authenticated_request("PUT", "/api/v1/users/profile", data=update_data)
    
    @task(5)
    def create_report(self):
        """Create new report entry."""
        report_data = {
            "title": f"Test Report {random.randint(1000, 9999)}",
            "type": random.choice(["daily", "weekly", "monthly"]),
            "data": {"metrics": {"value": random.randint(100, 1000)}},
            "tags": ["test", "automated"]
        }
        self.make_authenticated_request("POST", "/api/v1/data/reports", data=report_data)
    
    @task(4)
    def update_system_settings(self):
        """Update system configuration settings."""
        settings_data = {
            "maintenance_mode": False,
            "max_upload_size": 50 * 1024 * 1024,  # 50MB
            "session_timeout": 3600
        }
        self.make_authenticated_request("PUT", "/api/v1/admin/settings", data=settings_data)
    
    @task(3)
    def delete_old_data(self):
        """Delete old or expired data."""
        params = {"older_than": "30d"}
        self.make_authenticated_request("DELETE", "/api/v1/data/cleanup", params=params)


class AuthenticationFlowUser(BaseFlaskUser):
    """
    Authentication flow user simulating login, logout, and session management.
    
    Implements 10% of user behavior per scenario weights focusing on
    authentication workflows and session management per Section 4.6.3.
    """
    
    weight = int(SCENARIO_WEIGHTS["authentication_flow"] * 100)  # 10% of users
    
    @task(10)
    def perform_login_logout_cycle(self):
        """Perform complete login/logout cycle."""
        # Logout if already authenticated
        if self.session_data.is_authenticated():
            self.make_authenticated_request("POST", "/api/v1/auth/logout")
            self.session_data.session_token = None
            self.session_data.auth_timestamp = None
            if "Authorization" in self.client.headers:
                del self.client.headers["Authorization"]
        
        # Perform fresh authentication
        self.authenticate_user()
        
        # Verify authentication with profile request
        self.make_authenticated_request("GET", "/api/v1/users/profile")
    
    @task(8)
    def refresh_token_cycle(self):
        """Test token refresh functionality."""
        if self.session_data.is_authenticated():
            # Force token refresh
            self.refresh_authentication()
            
            # Validate refreshed token with API request
            self.make_authenticated_request("GET", "/api/v1/auth/validate")
    
    @task(5)
    def check_session_status(self):
        """Check current session status and validity."""
        self.make_authenticated_request("GET", "/api/v1/auth/session")
    
    @task(3)
    def update_password(self):
        """Update user password."""
        password_data = {
            "current_password": "test_password_123",
            "new_password": f"new_password_{random.randint(1000, 9999)}",
            "confirm_password": f"new_password_{random.randint(1000, 9999)}"
        }
        self.make_authenticated_request("PUT", "/api/v1/auth/password", data=password_data)


class FileUploadOperationsUser(BaseFlaskUser):
    """
    File upload operations user simulating file handling workflows.
    
    Implements 5% of user behavior per scenario weights focusing on
    file upload, download, and storage operations per Section 4.6.3.
    """
    
    weight = int(SCENARIO_WEIGHTS["file_upload_operations"] * 100)  # 5% of users
    
    @task(8)
    def upload_document(self):
        """Upload document file to the system."""
        # Simulate file upload with multipart form data
        files = {
            "file": ("test_document.txt", "This is a test document content for load testing.", "text/plain")
        }
        data = {
            "description": f"Test upload {random.randint(1000, 9999)}",
            "category": random.choice(["document", "report", "data"])
        }
        
        start_time = time.time()
        
        with self.client.post(
            "/api/v1/files/upload",
            files=files,
            data=data,
            catch_response=True,
            name="File Upload"
        ) as response:
            response_time = (time.time() - start_time) * 1000
            success = response.status_code == 201
            
            if success:
                response.success()
            else:
                response.failure(f"File upload failed with status {response.status_code}")
            
            # Record file upload performance
            performance_collector.record_request(
                "POST", "/api/v1/files/upload", response_time, response.status_code, success
            )
            self.session_data.record_request(success)
    
    @task(6)
    def list_uploaded_files(self):
        """List user's uploaded files."""
        params = {
            "page": random.randint(1, 5),
            "limit": random.choice([10, 20, 50])
        }
        self.make_authenticated_request("GET", "/api/v1/files", params=params)
    
    @task(4)
    def download_file(self):
        """Download file from the system."""
        # Simulate downloading a file by ID
        file_id = f"file_{random.randint(1, 1000)}"
        self.make_authenticated_request("GET", f"/api/v1/files/{file_id}/download")
    
    @task(3)
    def delete_uploaded_file(self):
        """Delete uploaded file."""
        file_id = f"file_{random.randint(1, 1000)}"
        self.make_authenticated_request("DELETE", f"/api/v1/files/{file_id}")


# Locust event handlers for performance monitoring and reporting

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Initialize performance monitoring when test starts."""
    print(f"\n🚀 Starting Flask Migration Load Test")
    print(f"Environment: {PERFORMANCE_ENV}")
    print(f"Target Users: {MIN_USERS} → {MAX_USERS}")
    print(f"Test Duration: {TEST_DURATION} seconds ({TEST_DURATION // 60} minutes)")
    print(f"Spawn Rate: {USER_SPAWN_RATE} users/second")
    print(f"Geographic Regions: {', '.join(GEOGRAPHIC_REGIONS)}")
    print(f"Performance Variance Threshold: ≤{VARIANCE_THRESHOLD * 100:.1f}%")
    
    # Start Prometheus metrics server if available
    if PROMETHEUS_AVAILABLE:
        try:
            prometheus_port = int(os.getenv('PROMETHEUS_PORT', 8089))
            start_http_server(prometheus_port, registry=performance_collector.registry)
            print(f"📊 Prometheus metrics server started on port {prometheus_port}")
        except Exception as e:
            print(f"⚠️ Failed to start Prometheus metrics server: {e}")
    
    # Initialize structured logging if available
    if STRUCTLOG_AVAILABLE:
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


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Generate final performance report when test completes."""
    print(f"\n🏁 Load Test Completed")
    
    # Generate comprehensive performance summary
    performance_summary = performance_collector.get_performance_summary()
    
    # Display performance results
    print(f"\n📈 Performance Summary:")
    if "response_time_metrics" in performance_summary:
        rt_metrics = performance_summary["response_time_metrics"]
        print(f"  Mean Response Time: {rt_metrics['mean_response_time_ms']:.2f}ms")
        print(f"  95th Percentile: {rt_metrics['p95_response_time_ms']:.2f}ms")
        print(f"  99th Percentile: {rt_metrics['p99_response_time_ms']:.2f}ms")
    
    if "throughput_metrics" in performance_summary:
        tp_metrics = performance_summary["throughput_metrics"]
        print(f"  Average Throughput: {tp_metrics['avg_throughput_rps']:.2f} RPS")
        print(f"  Peak Throughput: {tp_metrics['peak_throughput_rps']:.2f} RPS")
    
    if "error_metrics" in performance_summary:
        err_metrics = performance_summary["error_metrics"]
        print(f"  Total Requests: {err_metrics['total_requests']}")
        print(f"  Error Rate: {err_metrics['error_rate_percent']:.3f}%")
    
    # Display baseline validation results
    if "baseline_validation" in performance_summary:
        validation = performance_summary["baseline_validation"]
        print(f"\n🔍 Baseline Validation:")
        print(f"  Overall Compliance: {'✅ PASS' if validation.get('overall_compliance', False) else '❌ FAIL'}")
        
        if "variance_analysis" in validation:
            for metric, analysis in validation["variance_analysis"].items():
                variance = analysis.get("variance_percent", 0)
                status = "✅ PASS" if analysis.get("compliant", False) else "❌ FAIL"
                print(f"  {metric.replace('_', ' ').title()}: {variance:+.2f}% variance {status}")
    
    # Display compliance status
    if "performance_compliance" in performance_summary:
        compliance = performance_summary["performance_compliance"]
        print(f"\n✅ Compliance Status:")
        print(f"  Variance Threshold: {'✅ PASS' if compliance.get('within_variance_threshold', False) else '❌ FAIL'}")
        print(f"  Response Time: {'✅ PASS' if compliance.get('response_time_compliant', False) else '❌ FAIL'}")
        print(f"  Error Rate: {'✅ PASS' if compliance.get('error_rate_compliant', False) else '❌ FAIL'}")
        print(f"  Throughput: {'✅ PASS' if compliance.get('throughput_compliant', False) else '❌ FAIL'}")
    
    # Save performance report to file
    _save_performance_report(performance_summary)
    
    # Log final summary with structured logging
    if STRUCTLOG_AVAILABLE:
        logger = structlog.get_logger()
        logger.info("Load test completed", performance_summary=performance_summary)


@events.user_add.add_listener
def on_user_add(user_instance, **kwargs):
    """Track user addition for concurrent user monitoring."""
    current_users = len(user_instance.environment.runner.user_greenlets)
    performance_collector.record_concurrent_users(current_users)


@events.user_remove.add_listener
def on_user_remove(user_instance, **kwargs):
    """Track user removal for concurrent user monitoring."""
    current_users = len(user_instance.environment.runner.user_greenlets)
    performance_collector.record_concurrent_users(current_users)


@events.request_success.add_listener
def on_request_success(request_type, name, response_time, response_length, **kwargs):
    """Track successful requests for throughput calculation."""
    # Calculate current RPS based on recent successful requests
    current_time = time.time()
    if not hasattr(on_request_success, 'request_times'):
        on_request_success.request_times = []
    
    on_request_success.request_times.append(current_time)
    
    # Keep only requests from the last 10 seconds for RPS calculation
    cutoff_time = current_time - 10
    on_request_success.request_times = [t for t in on_request_success.request_times if t > cutoff_time]
    
    # Calculate and record current RPS
    if len(on_request_success.request_times) > 1:
        time_window = on_request_success.request_times[-1] - on_request_success.request_times[0]
        if time_window > 0:
            current_rps = (len(on_request_success.request_times) - 1) / time_window
            performance_collector.record_throughput_sample(current_rps)


def _save_performance_report(performance_summary: Dict[str, Any]) -> None:
    """Save comprehensive performance report to file."""
    try:
        report_dir = Path("tests/performance/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"load_test_report_{timestamp}.json"
        
        # Enhanced report with metadata
        enhanced_report = {
            "metadata": {
                "test_type": "locust_load_test",
                "environment": PERFORMANCE_ENV,
                "test_duration_seconds": TEST_DURATION,
                "min_users": MIN_USERS,
                "max_users": MAX_USERS,
                "spawn_rate": USER_SPAWN_RATE,
                "target_rps": TARGET_RPS,
                "variance_threshold": VARIANCE_THRESHOLD,
                "geographic_regions": GEOGRAPHIC_REGIONS,
                "scenario_weights": SCENARIO_WEIGHTS,
                "generated_at": datetime.now(timezone.utc).isoformat()
            },
            "performance_results": performance_summary,
            "test_configuration": {
                "load_test_config": LOAD_TEST_CONFIG.__dict__,
                "baseline_metrics": BASELINE_METRICS.__dict__,
                "performance_config": {
                    "variance_threshold": PERFORMANCE_CONFIG.PERFORMANCE_VARIANCE_THRESHOLD,
                    "response_time_threshold": PERFORMANCE_CONFIG.RESPONSE_TIME_P95_THRESHOLD,
                    "error_rate_threshold": PERFORMANCE_CONFIG.ERROR_RATE_THRESHOLD
                }
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(enhanced_report, f, indent=2, default=str)
        
        print(f"\n📄 Performance report saved: {report_file}")
        
        # Generate markdown summary report
        _generate_markdown_summary(enhanced_report, report_dir, timestamp)
        
    except Exception as e:
        print(f"⚠️ Failed to save performance report: {e}")


def _generate_markdown_summary(report_data: Dict[str, Any], report_dir: Path, timestamp: str) -> None:
    """Generate markdown summary report for easy reading."""
    try:
        summary_file = report_dir / f"load_test_summary_{timestamp}.md"
        
        metadata = report_data["metadata"]
        results = report_data["performance_results"]
        
        markdown_content = f"""# Load Test Summary Report

**Generated:** {metadata['generated_at']}  
**Environment:** {metadata['environment']}  
**Test Duration:** {metadata['test_duration_seconds']} seconds ({metadata['test_duration_seconds'] // 60} minutes)  
**User Range:** {metadata['min_users']} → {metadata['max_users']} concurrent users  
**Spawn Rate:** {metadata['spawn_rate']} users/second  

## Performance Results

### Response Time Metrics
"""
        
        if "response_time_metrics" in results:
            rt_metrics = results["response_time_metrics"]
            markdown_content += f"""
| Metric | Value |
|--------|--------|
| Mean Response Time | {rt_metrics['mean_response_time_ms']:.2f}ms |
| Median Response Time | {rt_metrics['median_response_time_ms']:.2f}ms |
| 95th Percentile | {rt_metrics['p95_response_time_ms']:.2f}ms |
| 99th Percentile | {rt_metrics['p99_response_time_ms']:.2f}ms |
| Min Response Time | {rt_metrics['min_response_time_ms']:.2f}ms |
| Max Response Time | {rt_metrics['max_response_time_ms']:.2f}ms |
"""
        
        if "throughput_metrics" in results:
            tp_metrics = results["throughput_metrics"]
            markdown_content += f"""
### Throughput Metrics

| Metric | Value |
|--------|--------|
| Average Throughput | {tp_metrics['avg_throughput_rps']:.2f} RPS |
| Peak Throughput | {tp_metrics['peak_throughput_rps']:.2f} RPS |
| Min Throughput | {tp_metrics['min_throughput_rps']:.2f} RPS |
"""
        
        if "error_metrics" in results:
            err_metrics = results["error_metrics"]
            markdown_content += f"""
### Error Metrics

| Metric | Value |
|--------|--------|
| Total Requests | {err_metrics['total_requests']} |
| Total Errors | {err_metrics['total_errors']} |
| Error Rate | {err_metrics['error_rate_percent']:.3f}% |
"""
        
        if "baseline_validation" in results:
            validation = results["baseline_validation"]
            compliance_status = "✅ PASS" if validation.get("overall_compliance", False) else "❌ FAIL"
            
            markdown_content += f"""
### Baseline Validation

**Overall Compliance:** {compliance_status}

"""
            
            if "variance_analysis" in validation:
                markdown_content += """| Metric | Variance | Status |
|--------|----------|--------|
"""
                for metric, analysis in validation["variance_analysis"].items():
                    variance = analysis.get("variance_percent", 0)
                    status = "✅ PASS" if analysis.get("compliant", False) else "❌ FAIL"
                    metric_name = metric.replace('_', ' ').title()
                    markdown_content += f"| {metric_name} | {variance:+.2f}% | {status} |\n"
        
        if "performance_compliance" in results:
            compliance = results["performance_compliance"]
            markdown_content += f"""
### Compliance Summary

| Requirement | Status |
|-------------|--------|
| Variance Threshold (≤{metadata['variance_threshold']*100:.1f}%) | {'✅ PASS' if compliance.get('within_variance_threshold', False) else '❌ FAIL'} |
| Response Time (≤500ms P95) | {'✅ PASS' if compliance.get('response_time_compliant', False) else '❌ FAIL'} |
| Error Rate (≤0.1%) | {'✅ PASS' if compliance.get('error_rate_compliant', False) else '❌ FAIL'} |
| Throughput (≥{metadata['target_rps']} RPS) | {'✅ PASS' if compliance.get('throughput_compliant', False) else '❌ FAIL'} |

## Test Configuration

- **Geographic Regions:** {', '.join(metadata['geographic_regions'])}
- **Scenario Weights:** {metadata['scenario_weights']}
- **Variance Threshold:** ≤{metadata['variance_threshold']*100:.1f}%
"""
        
        with open(summary_file, 'w') as f:
            f.write(markdown_content)
        
        print(f"📄 Markdown summary saved: {summary_file}")
        
    except Exception as e:
        print(f"⚠️ Failed to generate markdown summary: {e}")


# Custom load shape for progressive scaling per Section 4.6.3
class ProgressiveLoadShape:
    """
    Custom load shape implementing progressive user scaling from 10 to 1000 users.
    
    Provides gradual load increase following the load testing configuration
    requirements per Section 4.6.3 with proper ramp-up, steady state, and
    ramp-down phases.
    """
    
    def __init__(self):
        self.user_progression = LOAD_TEST_CONFIG.get_user_progression()
        self.spawn_rate = USER_SPAWN_RATE
    
    def tick(self):
        """Return user count and spawn rate for current time."""
        run_time = round(time.time() - self.start_time)
        
        for time_point, user_count in self.user_progression:
            if run_time <= time_point:
                return user_count, self.spawn_rate
        
        # Test completed, ramp down to 0
        return 0, self.spawn_rate


# Export user classes for Locust discovery
__all__ = [
    'APIReadOperationsUser',
    'APIWriteOperationsUser', 
    'AuthenticationFlowUser',
    'FileUploadOperationsUser',
    'BaseFlaskUser',
    'PerformanceMetricsCollector'
]


if __name__ == "__main__":
    # Configuration summary for direct execution
    print("Flask Migration Load Testing Configuration")
    print("=" * 50)
    print(f"Environment: {PERFORMANCE_ENV}")
    print(f"Min Users: {MIN_USERS}")
    print(f"Max Users: {MAX_USERS}")
    print(f"Test Duration: {TEST_DURATION} seconds")
    print(f"Spawn Rate: {USER_SPAWN_RATE} users/second")
    print(f"Target RPS: {TARGET_RPS}")
    print(f"Variance Threshold: ≤{VARIANCE_THRESHOLD * 100:.1f}%")
    print(f"Geographic Regions: {', '.join(GEOGRAPHIC_REGIONS)}")
    print("\nUser Classes:")
    for cls_name in __all__:
        if 'User' in cls_name and cls_name != 'BaseFlaskUser':
            cls = globals()[cls_name]
            if hasattr(cls, 'weight'):
                print(f"  - {cls_name}: {cls.weight}% of users")
    print("\nRun with: locust -f locustfile.py --host=http://localhost:5000")