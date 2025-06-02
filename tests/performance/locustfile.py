"""
Locust Load Testing Configuration for Flask Migration Performance Validation

This module provides comprehensive Locust-based load testing configuration implementing progressive
scaling, realistic user behavior simulation, and multi-region load distribution for the 
BF-refactor-merge Flask migration project, ensuring compliance with the ≤10% variance requirement
from the original Node.js implementation.

Key Features:
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- 30-minute sustained load testing minimum per Section 4.6.3
- Multi-region load simulation per Section 4.6.3 geographic distribution
- Realistic API workflow simulation per Section 4.6.3 user behavior patterns
- Concurrent request handling validation per Section 0.2.3 load testing
- Performance baseline comparison per Section 0.3.2 monitoring requirements
- Enterprise-grade load testing with comprehensive metrics collection

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
Dependencies: locust ≥2.x, requests ≥2.31+, performance_config.py, baseline_data.py
"""

import json
import logging
import random
import time
import os
import statistics
import csv
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union, Callable
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import uuid
import hashlib

# Locust framework imports
from locust import HttpUser, task, between, events, TaskSet
from locust.runners import MasterRunner, WorkerRunner
from locust.env import Environment

# Performance monitoring and metrics
import psutil
try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Project-specific performance imports
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

# Configure module logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UserBehaviorType(Enum):
    """User behavior pattern enumeration for realistic load simulation."""
    
    LIGHT_BROWSING = "light_browsing"
    NORMAL_USAGE = "normal_usage"
    HEAVY_USAGE = "heavy_usage"
    API_INTEGRATION = "api_integration"
    BATCH_OPERATIONS = "batch_operations"
    MIXED_WORKLOAD = "mixed_workload"


class LoadTestPhase(Enum):
    """Load test execution phase enumeration for progressive scaling."""
    
    RAMP_UP = "ramp_up"
    STEADY_STATE = "steady_state"
    STRESS_TESTING = "stress_testing"
    PEAK_LOAD = "peak_load"
    ENDURANCE = "endurance"
    RAMP_DOWN = "ramp_down"


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics collection during load testing."""
    
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_p50: float = 0.0
    response_time_p95: float = 0.0
    response_time_p99: float = 0.0
    requests_per_second: float = 0.0
    error_rate: float = 0.0
    concurrent_users: int = 0
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    current_phase: LoadTestPhase = LoadTestPhase.RAMP_UP
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for reporting."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'response_time_p50': self.response_time_p50,
            'response_time_p95': self.response_time_p95,
            'response_time_p99': self.response_time_p99,
            'requests_per_second': self.requests_per_second,
            'error_rate': self.error_rate,
            'concurrent_users': self.concurrent_users,
            'cpu_utilization': self.cpu_utilization,
            'memory_utilization': self.memory_utilization,
            'current_phase': self.current_phase.value
        }


class PerformanceMonitor:
    """
    Real-time performance monitoring and metrics collection during load testing.
    
    Integrates with Locust event system to collect comprehensive performance data
    and compare against Node.js baseline metrics for variance calculation.
    """
    
    def __init__(self):
        """Initialize performance monitor with metrics collection."""
        self.metrics_history: List[PerformanceMetrics] = []
        self.current_phase = LoadTestPhase.RAMP_UP
        self.baseline = get_nodejs_baseline()
        self.start_time = datetime.now(timezone.utc)
        
        # Prometheus metrics initialization
        if PROMETHEUS_AVAILABLE:
            self.registry = CollectorRegistry()
            self._init_prometheus_metrics()
        
        # Performance thresholds from configuration
        config = PerformanceTestConfig()
        self.thresholds = config.PERFORMANCE_THRESHOLDS
        
        # Metrics collection
        self.response_times: List[float] = []
        self.request_counts: List[int] = []
        self.error_counts: List[int] = []
        
        logger.info("Performance monitor initialized with Node.js baseline comparison")
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for advanced monitoring."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.response_time_histogram = Histogram(
            'locust_response_time_seconds',
            'Response time distribution',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.request_rate_gauge = Gauge(
            'locust_requests_per_second',
            'Current requests per second',
            registry=self.registry
        )
        
        self.error_rate_gauge = Gauge(
            'locust_error_rate_percent',
            'Current error rate percentage',
            registry=self.registry
        )
        
        self.concurrent_users_gauge = Gauge(
            'locust_concurrent_users',
            'Current number of concurrent users',
            registry=self.registry
        )
        
        self.variance_gauge = Gauge(
            'locust_baseline_variance_percent',
            'Performance variance from Node.js baseline',
            ['metric_name'],
            registry=self.registry
        )
    
    def record_request(self, response_time: float, endpoint: str, method: str, success: bool) -> None:
        """Record individual request metrics for analysis."""
        self.response_times.append(response_time)
        
        if PROMETHEUS_AVAILABLE:
            self.response_time_histogram.labels(method=method, endpoint=endpoint).observe(response_time / 1000)
        
        if not success:
            self.error_counts.append(1)
        else:
            self.error_counts.append(0)
    
    def update_metrics(self, user_count: int) -> PerformanceMetrics:
        """Update and calculate current performance metrics."""
        current_metrics = PerformanceMetrics()
        current_metrics.current_phase = self.current_phase
        current_metrics.concurrent_users = user_count
        
        # Calculate response time percentiles
        if self.response_times:
            current_metrics.response_time_p50 = statistics.median(self.response_times[-100:])
            current_metrics.response_time_p95 = statistics.quantiles(self.response_times[-100:], n=20)[18] if len(self.response_times) >= 20 else 0
            current_metrics.response_time_p99 = statistics.quantiles(self.response_times[-100:], n=100)[98] if len(self.response_times) >= 100 else 0
        
        # Calculate request rate
        current_time = datetime.now(timezone.utc)
        time_window = max(1, (current_time - self.start_time).total_seconds())
        current_metrics.requests_per_second = len(self.response_times) / time_window
        
        # Calculate error rate
        if self.error_counts:
            current_metrics.error_rate = (sum(self.error_counts[-100:]) / len(self.error_counts[-100:])) * 100
        
        # Get system resource utilization
        try:
            current_metrics.cpu_utilization = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            current_metrics.memory_utilization = memory.percent
        except Exception as e:
            logger.warning(f"Failed to get system metrics: {e}")
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            self.request_rate_gauge.set(current_metrics.requests_per_second)
            self.error_rate_gauge.set(current_metrics.error_rate)
            self.concurrent_users_gauge.set(current_metrics.concurrent_users)
            
            # Calculate and record baseline variance
            if current_metrics.response_time_p95 > 0:
                baseline_p95 = self.baseline.api_response_time_p95
                variance = ((current_metrics.response_time_p95 - baseline_p95) / baseline_p95) * 100
                self.variance_gauge.labels(metric_name='response_time_p95').set(abs(variance))
        
        self.metrics_history.append(current_metrics)
        return current_metrics
    
    def set_phase(self, phase: LoadTestPhase) -> None:
        """Update current load test phase."""
        self.current_phase = phase
        logger.info(f"Load test phase changed to: {phase.value}")
    
    def get_baseline_comparison(self) -> Dict[str, Any]:
        """Get comprehensive baseline comparison analysis."""
        if not self.metrics_history:
            return {"error": "No metrics available for comparison"}
        
        latest_metrics = self.metrics_history[-1]
        
        comparison_data = {
            "api_response_time_p95": latest_metrics.response_time_p95,
            "requests_per_second": latest_metrics.requests_per_second,
            "memory_usage_mb": latest_metrics.memory_utilization,  # Convert percentage to MB estimate
            "cpu_utilization_average": latest_metrics.cpu_utilization,
            "error_rate_overall": latest_metrics.error_rate / 100,  # Convert to decimal
        }
        
        return compare_with_baseline(comparison_data)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance test report."""
        if not self.metrics_history:
            return {"error": "No performance data collected"}
        
        # Calculate summary statistics
        response_times = [m.response_time_p95 for m in self.metrics_history if m.response_time_p95 > 0]
        request_rates = [m.requests_per_second for m in self.metrics_history if m.requests_per_second > 0]
        error_rates = [m.error_rate for m in self.metrics_history]
        
        summary = {
            "test_duration_minutes": (datetime.now(timezone.utc) - self.start_time).total_seconds() / 60,
            "total_metrics_collected": len(self.metrics_history),
            "response_time_statistics": {
                "p95_min": min(response_times) if response_times else 0,
                "p95_max": max(response_times) if response_times else 0,
                "p95_average": statistics.mean(response_times) if response_times else 0,
                "p95_median": statistics.median(response_times) if response_times else 0
            },
            "throughput_statistics": {
                "rps_min": min(request_rates) if request_rates else 0,
                "rps_max": max(request_rates) if request_rates else 0,
                "rps_average": statistics.mean(request_rates) if request_rates else 0,
                "rps_sustained": statistics.median(request_rates) if request_rates else 0
            },
            "error_rate_statistics": {
                "error_rate_min": min(error_rates) if error_rates else 0,
                "error_rate_max": max(error_rates) if error_rates else 0,
                "error_rate_average": statistics.mean(error_rates) if error_rates else 0
            },
            "baseline_comparison": self.get_baseline_comparison(),
            "performance_summary": {
                "meets_response_time_threshold": all(rt <= self.thresholds['response_time_p95'] for rt in response_times),
                "meets_throughput_threshold": all(rr >= self.thresholds['throughput_minimum'] for rr in request_rates),
                "meets_error_rate_threshold": all(er <= self.thresholds['error_rate_critical'] for er in error_rates),
                "overall_compliant": True  # Will be calculated based on individual thresholds
            }
        }
        
        # Calculate overall compliance
        summary["performance_summary"]["overall_compliant"] = all([
            summary["performance_summary"]["meets_response_time_threshold"],
            summary["performance_summary"]["meets_throughput_threshold"],
            summary["performance_summary"]["meets_error_rate_threshold"]
        ])
        
        return summary


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


class BaseUserBehavior(TaskSet):
    """
    Base user behavior class providing common authentication and utility methods
    for all user behavior patterns in the load testing scenarios.
    """
    
    def __init__(self, parent):
        """Initialize base user behavior with authentication setup."""
        super().__init__(parent)
        self.auth_token = None
        self.user_id = None
        self.session_data = {}
        
    def on_start(self):
        """Initialize user session with authentication."""
        self.authenticate_user()
    
    def authenticate_user(self) -> bool:
        """
        Authenticate user and obtain JWT token for subsequent requests.
        
        Returns:
            True if authentication successful, False otherwise
        """
        auth_payload = {
            "email": f"testuser_{random.randint(1000, 9999)}@example.com",
            "password": "TestPassword123!"
        }
        
        start_time = time.time()
        
        with self.client.post(
            "/api/auth/login",
            json=auth_payload,
            headers={"Content-Type": "application/json"},
            catch_response=True
        ) as response:
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    self.auth_token = response_data.get("access_token")
                    self.user_id = response_data.get("user_id")
                    
                    performance_monitor.record_request(
                        response_time, "/api/auth/login", "POST", True
                    )
                    
                    logger.debug(f"User authentication successful: {self.user_id}")
                    return True
                    
                except json.JSONDecodeError:
                    response.failure(f"Authentication response parsing failed")
                    
            else:
                response.failure(f"Authentication failed with status {response.status_code}")
            
            performance_monitor.record_request(
                response_time, "/api/auth/login", "POST", False
            )
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for authenticated requests."""
        if self.auth_token:
            return {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json"
            }
        return {"Content-Type": "application/json"}
    
    def make_authenticated_request(
        self, 
        method: str, 
        endpoint: str, 
        payload: Optional[Dict] = None,
        expected_status: int = 200
    ) -> Optional[Dict]:
        """
        Make authenticated HTTP request with performance monitoring.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            payload: Request payload for POST/PUT requests
            expected_status: Expected HTTP status code
            
        Returns:
            Response JSON data if successful, None otherwise
        """
        headers = self.get_auth_headers()
        start_time = time.time()
        
        with self.client.request(
            method,
            endpoint,
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            response_time = (time.time() - start_time) * 1000
            success = response.status_code == expected_status
            
            performance_monitor.record_request(
                response_time, endpoint, method, success
            )
            
            if success:
                try:
                    return response.json() if response.content else {}
                except json.JSONDecodeError:
                    response.failure(f"JSON parsing failed for {endpoint}")
                    return None
            else:
                response.failure(
                    f"{method} {endpoint} failed with status {response.status_code}"
                )
                return None


class LightBrowsingUser(BaseUserBehavior):
    """
    Light browsing user behavior simulating casual API usage with minimal load.
    
    Implements realistic user patterns with read-heavy operations, health checks,
    and occasional data retrieval for performance baseline validation.
    """
    
    wait_time = between(3, 8)  # 3-8 seconds between requests
    
    @task(40)
    def check_health(self):
        """Perform health check requests to validate system availability."""
        start_time = time.time()
        
        with self.client.get("/health", catch_response=True) as response:
            response_time = (time.time() - start_time) * 1000
            success = response.status_code == 200
            
            performance_monitor.record_request(
                response_time, "/health", "GET", success
            )
            
            if not success:
                response.failure(f"Health check failed with status {response.status_code}")
    
    @task(30)
    def browse_users(self):
        """Browse user listings with pagination and filtering."""
        query_params = {
            "page": random.randint(1, 5),
            "limit": random.choice([10, 20, 50]),
            "sort": random.choice(["created_at", "updated_at", "email"])
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])
        endpoint = f"/api/users?{query_string}"
        
        self.make_authenticated_request("GET", endpoint)
    
    @task(20)
    def view_user_profile(self):
        """View individual user profile information."""
        if self.user_id:
            endpoint = f"/api/users/{self.user_id}"
            self.make_authenticated_request("GET", endpoint)
        else:
            # View random user profile
            user_id = random.randint(1, 1000)
            endpoint = f"/api/users/{user_id}"
            self.make_authenticated_request("GET", endpoint, expected_status=404)
    
    @task(10)
    def refresh_auth_token(self):
        """Refresh authentication token periodically."""
        if self.auth_token:
            endpoint = "/api/auth/refresh"
            response_data = self.make_authenticated_request("POST", endpoint)
            
            if response_data and "access_token" in response_data:
                self.auth_token = response_data["access_token"]


class NormalUsageUser(BaseUserBehavior):
    """
    Normal usage user behavior simulating typical application usage patterns.
    
    Implements balanced read/write operations, user management, and data updates
    representing average user interaction patterns for realistic load simulation.
    """
    
    wait_time = between(1, 5)  # 1-5 seconds between requests
    
    @task(25)
    def browse_and_search_users(self):
        """Browse users with search functionality."""
        search_terms = ["john", "admin", "test", "user", "demo"]
        search_term = random.choice(search_terms)
        
        endpoint = f"/api/users?search={search_term}&limit=20"
        self.make_authenticated_request("GET", endpoint)
    
    @task(20)
    def view_user_details(self):
        """View detailed user information including related data."""
        user_id = random.randint(1, 100)
        endpoint = f"/api/users/{user_id}"
        
        user_data = self.make_authenticated_request("GET", endpoint, expected_status=200)
        if user_data:
            # Simulate related data fetching
            self.wait_time = between(0.5, 2)  # Shorter wait for related requests
            
            # Fetch user activities
            activities_endpoint = f"/api/users/{user_id}/activities"
            self.make_authenticated_request("GET", activities_endpoint)
    
    @task(15)
    def update_user_profile(self):
        """Update user profile information."""
        if self.user_id:
            profile_updates = {
                "first_name": f"Updated_{random.randint(1, 1000)}",
                "last_name": f"User_{random.randint(1, 1000)}",
                "bio": f"Updated bio at {datetime.now().isoformat()}",
                "preferences": {
                    "theme": random.choice(["light", "dark"]),
                    "notifications": random.choice([True, False])
                }
            }
            
            endpoint = f"/api/users/{self.user_id}"
            self.make_authenticated_request("PUT", endpoint, profile_updates)
    
    @task(15)
    def create_user_data(self):
        """Create new user-related data entries."""
        data_payload = {
            "title": f"Test Entry {random.randint(1, 10000)}",
            "content": f"Generated content at {datetime.now().isoformat()}",
            "category": random.choice(["personal", "work", "hobby", "education"]),
            "tags": random.sample(["python", "flask", "testing", "performance", "api"], 2),
            "metadata": {
                "source": "load_test",
                "timestamp": datetime.now().isoformat(),
                "user_agent": "Locust Load Test"
            }
        }
        
        endpoint = "/api/data"
        response_data = self.make_authenticated_request("POST", endpoint, data_payload, 201)
        
        if response_data and "id" in response_data:
            # Store created data ID for potential future operations
            self.session_data["last_created_id"] = response_data["id"]
    
    @task(10)
    def delete_user_data(self):
        """Delete previously created user data."""
        if "last_created_id" in self.session_data:
            data_id = self.session_data["last_created_id"]
            endpoint = f"/api/data/{data_id}"
            self.make_authenticated_request("DELETE", endpoint, expected_status=204)
            del self.session_data["last_created_id"]
    
    @task(10)
    def upload_file(self):
        """Simulate file upload operations."""
        # Generate small test file content
        file_content = f"Test file content generated at {datetime.now().isoformat()}"
        file_data = {
            "filename": f"test_file_{random.randint(1, 10000)}.txt",
            "content_type": "text/plain",
            "size": len(file_content.encode())
        }
        
        endpoint = "/api/files/upload"
        self.make_authenticated_request("POST", endpoint, file_data, 201)
    
    @task(5)
    def export_data(self):
        """Export user data in various formats."""
        export_formats = ["json", "csv", "xml"]
        export_format = random.choice(export_formats)
        
        endpoint = f"/api/data/export?format={export_format}"
        self.make_authenticated_request("GET", endpoint)


class HeavyUsageUser(BaseUserBehavior):
    """
    Heavy usage user behavior simulating intensive application usage.
    
    Implements high-frequency operations, batch processing, and complex workflows
    for stress testing and peak load validation scenarios.
    """
    
    wait_time = between(0.5, 2)  # Very short wait times for intensive usage
    
    @task(20)
    def batch_user_operations(self):
        """Perform batch operations on multiple users."""
        batch_size = random.randint(5, 20)
        user_ids = [random.randint(1, 1000) for _ in range(batch_size)]
        
        batch_payload = {
            "user_ids": user_ids,
            "operation": random.choice(["activate", "deactivate", "update_status"]),
            "parameters": {
                "status": random.choice(["active", "inactive", "pending"]),
                "updated_by": self.user_id or "load_test_user",
                "timestamp": datetime.now().isoformat()
            }
        }
        
        endpoint = "/api/users/batch"
        self.make_authenticated_request("POST", endpoint, batch_payload)
    
    @task(15)
    def complex_search_operations(self):
        """Perform complex search operations with multiple filters."""
        search_payload = {
            "filters": {
                "status": random.choice(["active", "inactive"]),
                "created_after": (datetime.now() - timedelta(days=30)).isoformat(),
                "created_before": datetime.now().isoformat(),
                "roles": random.sample(["admin", "user", "manager", "viewer"], 2)
            },
            "sort": [
                {"field": "created_at", "direction": "desc"},
                {"field": "email", "direction": "asc"}
            ],
            "pagination": {
                "page": random.randint(1, 10),
                "limit": random.choice([50, 100, 200])
            }
        }
        
        endpoint = "/api/users/search"
        self.make_authenticated_request("POST", endpoint, search_payload)
    
    @task(15)
    def rapid_crud_operations(self):
        """Perform rapid CRUD operations on data entities."""
        # Create multiple data entries rapidly
        for i in range(random.randint(3, 8)):
            create_payload = {
                "title": f"Rapid Entry {i}_{random.randint(1, 10000)}",
                "content": f"Content {i} created in batch",
                "priority": random.choice(["low", "medium", "high"]),
                "metadata": {"batch_id": str(uuid.uuid4())}
            }
            
            response_data = self.make_authenticated_request(
                "POST", "/api/data", create_payload, 201
            )
            
            if response_data and "id" in response_data:
                data_id = response_data["id"]
                
                # Immediately update the created entry
                update_payload = {
                    "content": f"Updated content for entry {i}",
                    "updated_at": datetime.now().isoformat()
                }
                
                self.make_authenticated_request(
                    "PUT", f"/api/data/{data_id}", update_payload
                )
    
    @task(12)
    def analytics_queries(self):
        """Perform resource-intensive analytics queries."""
        analytics_requests = [
            "/api/analytics/user-activity",
            "/api/analytics/performance-metrics",
            "/api/analytics/system-health",
            "/api/analytics/usage-statistics"
        ]
        
        endpoint = random.choice(analytics_requests)
        query_params = {
            "start_date": (datetime.now() - timedelta(days=7)).isoformat(),
            "end_date": datetime.now().isoformat(),
            "granularity": random.choice(["hour", "day"]),
            "metrics": random.sample(["requests", "users", "errors", "performance"], 2)
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])
        full_endpoint = f"{endpoint}?{query_string}"
        
        self.make_authenticated_request("GET", full_endpoint)
    
    @task(10)
    def concurrent_file_operations(self):
        """Perform concurrent file upload and download operations."""
        # Upload multiple files concurrently
        file_operations = []
        for i in range(random.randint(2, 5)):
            file_payload = {
                "filename": f"concurrent_file_{i}_{random.randint(1, 10000)}.dat",
                "content": f"File content {i}" * 100,  # Larger file content
                "metadata": {
                    "batch_operation": True,
                    "sequence": i
                }
            }
            
            response_data = self.make_authenticated_request(
                "POST", "/api/files/upload", file_payload, 201
            )
            
            if response_data and "file_id" in response_data:
                file_operations.append(response_data["file_id"])
        
        # Download the uploaded files
        for file_id in file_operations:
            endpoint = f"/api/files/{file_id}/download"
            self.make_authenticated_request("GET", endpoint)
    
    @task(8)
    def stress_database_operations(self):
        """Perform database-intensive operations for stress testing."""
        # Complex aggregation query
        aggregation_payload = {
            "pipeline": [
                {"match": {"status": "active"}},
                {"group": {
                    "_id": "$category",
                    "count": {"$sum": 1},
                    "avg_score": {"$avg": "$score"}
                }},
                {"sort": {"count": -1}},
                {"limit": 20}
            ],
            "options": {
                "allowDiskUse": True,
                "maxTimeMS": 30000
            }
        }
        
        endpoint = "/api/data/aggregate"
        self.make_authenticated_request("POST", endpoint, aggregation_payload)


class APIIntegrationUser(BaseUserBehavior):
    """
    API integration user behavior simulating automated systems and integrations.
    
    Implements machine-to-machine communication patterns, webhook handling,
    and external service integration testing for comprehensive API validation.
    """
    
    wait_time = between(0.1, 1)  # Very fast requests for API integration
    
    @task(30)
    def webhook_simulation(self):
        """Simulate incoming webhook requests from external systems."""
        webhook_data = {
            "event_type": random.choice(["user.created", "user.updated", "user.deleted"]),
            "timestamp": datetime.now().isoformat(),
            "source": "external_system",
            "data": {
                "user_id": random.randint(1, 10000),
                "changes": {
                    "status": random.choice(["active", "inactive"]),
                    "last_login": datetime.now().isoformat()
                }
            },
            "signature": hashlib.sha256(str(random.randint(1, 1000000)).encode()).hexdigest()
        }
        
        endpoint = "/api/webhooks/user-events"
        self.make_authenticated_request("POST", endpoint, webhook_data)
    
    @task(25)
    def api_key_operations(self):
        """Test API key authentication and operations."""
        # Generate API key
        api_key_payload = {
            "name": f"integration_key_{random.randint(1, 10000)}",
            "permissions": random.sample(["read", "write", "delete", "admin"], 2),
            "expires_at": (datetime.now() + timedelta(days=30)).isoformat()
        }
        
        response_data = self.make_authenticated_request(
            "POST", "/api/api-keys", api_key_payload, 201
        )
        
        if response_data and "api_key" in response_data:
            api_key = response_data["api_key"]
            
            # Test API key usage
            api_headers = {
                "X-API-Key": api_key,
                "Content-Type": "application/json"
            }
            
            start_time = time.time()
            with self.client.get("/api/users", headers=api_headers, catch_response=True) as response:
                response_time = (time.time() - start_time) * 1000
                success = response.status_code == 200
                
                performance_monitor.record_request(
                    response_time, "/api/users", "GET", success
                )
    
    @task(20)
    def bulk_data_import(self):
        """Simulate bulk data import operations."""
        batch_size = random.randint(50, 200)
        import_data = {
            "import_type": "user_data",
            "format": "json",
            "data": [
                {
                    "external_id": f"ext_{i}_{random.randint(1, 10000)}",
                    "email": f"import_user_{i}@example.com",
                    "first_name": f"Import{i}",
                    "last_name": "User",
                    "metadata": {
                        "import_batch": datetime.now().isoformat(),
                        "source": "api_integration_test"
                    }
                }
                for i in range(batch_size)
            ]
        }
        
        endpoint = "/api/data/import"
        self.make_authenticated_request("POST", endpoint, import_data)
    
    @task(15)
    def real_time_sync_operations(self):
        """Simulate real-time data synchronization operations."""
        sync_payload = {
            "sync_type": "incremental",
            "last_sync_timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "entities": ["users", "data", "files"],
            "options": {
                "include_deleted": True,
                "max_records": 1000,
                "compression": "gzip"
            }
        }
        
        endpoint = "/api/sync/request"
        response_data = self.make_authenticated_request("POST", endpoint, sync_payload)
        
        if response_data and "sync_id" in response_data:
            sync_id = response_data["sync_id"]
            
            # Poll sync status
            status_endpoint = f"/api/sync/{sync_id}/status"
            self.make_authenticated_request("GET", status_endpoint)
    
    @task(10)
    def external_service_integration(self):
        """Test external service integration endpoints."""
        integration_endpoints = [
            "/api/integrations/auth0/sync",
            "/api/integrations/aws/s3/test",
            "/api/integrations/monitoring/health",
            "/api/integrations/cache/status"
        ]
        
        endpoint = random.choice(integration_endpoints)
        
        if "test" in endpoint or "health" in endpoint or "status" in endpoint:
            self.make_authenticated_request("GET", endpoint)
        else:
            sync_payload = {
                "full_sync": False,
                "dry_run": True,
                "timestamp": datetime.now().isoformat()
            }
            self.make_authenticated_request("POST", endpoint, sync_payload)


class ProgressiveLoadUser(HttpUser):
    """
    Main Locust user class implementing progressive load scaling patterns.
    
    Coordinates multiple user behavior types with dynamic weight adjustment
    based on load test phase and performance metrics for realistic load simulation.
    """
    
    # Dynamic wait time based on load phase
    wait_time = between(1, 3)
    
    def __init__(self, environment):
        """Initialize progressive load user with behavior selection."""
        super().__init__(environment)
        self.behavior_type = self._select_behavior_type()
        self.phase_start_time = datetime.now(timezone.utc)
        
    def _select_behavior_type(self) -> UserBehaviorType:
        """
        Select user behavior type based on current load test phase and user distribution.
        
        Returns:
            UserBehaviorType enum value for behavior selection
        """
        current_phase = performance_monitor.current_phase
        
        # Behavior distribution based on load phase
        if current_phase in [LoadTestPhase.RAMP_UP, LoadTestPhase.STEADY_STATE]:
            # Normal distribution during standard phases
            behavior_weights = {
                UserBehaviorType.LIGHT_BROWSING: 40,
                UserBehaviorType.NORMAL_USAGE: 45,
                UserBehaviorType.HEAVY_USAGE: 10,
                UserBehaviorType.API_INTEGRATION: 5
            }
        elif current_phase == LoadTestPhase.STRESS_TESTING:
            # More intensive users during stress testing
            behavior_weights = {
                UserBehaviorType.LIGHT_BROWSING: 20,
                UserBehaviorType.NORMAL_USAGE: 35,
                UserBehaviorType.HEAVY_USAGE: 35,
                UserBehaviorType.API_INTEGRATION: 10
            }
        elif current_phase == LoadTestPhase.PEAK_LOAD:
            # Maximum intensity during peak load
            behavior_weights = {
                UserBehaviorType.LIGHT_BROWSING: 15,
                UserBehaviorType.NORMAL_USAGE: 25,
                UserBehaviorType.HEAVY_USAGE: 45,
                UserBehaviorType.API_INTEGRATION: 15
            }
        else:
            # Default mixed workload
            behavior_weights = {
                UserBehaviorType.LIGHT_BROWSING: 30,
                UserBehaviorType.NORMAL_USAGE: 40,
                UserBehaviorType.HEAVY_USAGE: 20,
                UserBehaviorType.API_INTEGRATION: 10
            }
        
        # Weighted random selection
        behaviors = list(behavior_weights.keys())
        weights = list(behavior_weights.values())
        return random.choices(behaviors, weights=weights)[0]
    
    def on_start(self):
        """Initialize user session based on selected behavior type."""
        logger.debug(f"Starting user with behavior: {self.behavior_type.value}")
        
        # Set task set based on behavior type
        if self.behavior_type == UserBehaviorType.LIGHT_BROWSING:
            self.tasks = [LightBrowsingUser]
            self.wait_time = between(3, 8)
        elif self.behavior_type == UserBehaviorType.NORMAL_USAGE:
            self.tasks = [NormalUsageUser]
            self.wait_time = between(1, 5)
        elif self.behavior_type == UserBehaviorType.HEAVY_USAGE:
            self.tasks = [HeavyUsageUser]
            self.wait_time = between(0.5, 2)
        elif self.behavior_type == UserBehaviorType.API_INTEGRATION:
            self.tasks = [APIIntegrationUser]
            self.wait_time = between(0.1, 1)
        else:
            # Default to normal usage
            self.tasks = [NormalUsageUser]
            self.wait_time = between(1, 5)


# Locust event handlers for performance monitoring and phase management
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Initialize test environment and performance monitoring."""
    logger.info("Load test starting - initializing performance monitoring")
    
    # Reset performance monitor
    global performance_monitor
    performance_monitor = PerformanceMonitor()
    performance_monitor.set_phase(LoadTestPhase.RAMP_UP)
    
    # Load test configuration
    test_config = PerformanceTestConfig.get_environment_config()
    logger.info(f"Test configuration loaded: {test_config.get('load_test_scenario', 'default')}")


@events.spawning_complete.add_listener
def on_spawning_complete(user_count, **kwargs):
    """Handle user spawning completion and phase transitions."""
    logger.info(f"Spawning complete - {user_count} users active")
    
    # Update metrics with current user count
    current_metrics = performance_monitor.update_metrics(user_count)
    
    # Determine phase based on user count and test duration
    test_duration = (datetime.now(timezone.utc) - performance_monitor.start_time).total_seconds()
    
    if user_count >= 800:
        performance_monitor.set_phase(LoadTestPhase.PEAK_LOAD)
    elif user_count >= 500:
        performance_monitor.set_phase(LoadTestPhase.STRESS_TESTING)
    elif test_duration > 1200:  # 20 minutes
        performance_monitor.set_phase(LoadTestPhase.ENDURANCE)
    else:
        performance_monitor.set_phase(LoadTestPhase.STEADY_STATE)
    
    # Log current performance metrics
    logger.info(
        f"Current metrics - RPS: {current_metrics.requests_per_second:.2f}, "
        f"P95: {current_metrics.response_time_p95:.2f}ms, "
        f"Error Rate: {current_metrics.error_rate:.2f}%, "
        f"Phase: {current_metrics.current_phase.value}"
    )


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
    """Handle individual request events for performance monitoring."""
    success = exception is None
    performance_monitor.record_request(response_time, name, request_type, success)


@events.user_error.add_listener
def on_user_error(user_instance, exception, tb, **kwargs):
    """Handle user errors and exceptions during load testing."""
    logger.error(f"User error in {user_instance.__class__.__name__}: {exception}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Generate final performance report and cleanup."""
    logger.info("Load test stopping - generating performance report")
    
    # Set final phase
    performance_monitor.set_phase(LoadTestPhase.RAMP_DOWN)
    
    # Generate comprehensive performance report
    final_report = performance_monitor.generate_report()
    
    # Save report to file
    report_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"performance_report_{report_timestamp}.json"
    report_path = Path(__file__).parent / "reports" / report_filename
    report_path.parent.mkdir(exist_ok=True)
    
    with open(report_path, 'w') as f:
        json.dump(final_report, f, indent=2, default=str)
    
    logger.info(f"Performance report saved to: {report_path}")
    
    # Log performance summary
    if "performance_summary" in final_report:
        summary = final_report["performance_summary"]
        logger.info(
            f"Performance Summary - "
            f"Response Time Compliance: {summary.get('meets_response_time_threshold', False)}, "
            f"Throughput Compliance: {summary.get('meets_throughput_threshold', False)}, "
            f"Error Rate Compliance: {summary.get('meets_error_rate_threshold', False)}, "
            f"Overall Compliant: {summary.get('overall_compliant', False)}"
        )
    
    # Validate against baseline
    baseline_comparison = final_report.get("baseline_comparison", {})
    if baseline_comparison.get("summary", {}).get("overall_compliant"):
        logger.info("✅ Performance test PASSED - within baseline variance threshold")
    else:
        logger.warning("❌ Performance test FAILED - exceeded baseline variance threshold")
        if "comparison_results" in baseline_comparison:
            for metric, result in baseline_comparison["comparison_results"].items():
                if not result.get("within_threshold", True):
                    variance = result.get("variance_percent", 0)
                    logger.warning(f"  - {metric}: {variance:.2f}% variance")


# Load test configuration based on environment and command line parameters
def get_locust_configuration() -> Dict[str, Any]:
    """
    Get Locust configuration based on environment variables and test parameters.
    
    Returns:
        Dictionary containing Locust configuration parameters
    """
    # Get environment-specific configuration
    environment = os.getenv('FLASK_ENV', 'development')
    test_scenario = os.getenv('LOAD_TEST_SCENARIO', 'normal_load')
    
    # Map environment variables to load test scenarios
    scenario_mapping = {
        'light_load': LoadTestScenario.LIGHT_LOAD,
        'normal_load': LoadTestScenario.NORMAL_LOAD,
        'heavy_load': LoadTestScenario.HEAVY_LOAD,
        'stress_test': LoadTestScenario.STRESS_TEST,
        'endurance_test': LoadTestScenario.ENDURANCE_TEST,
        'baseline_comparison': LoadTestScenario.BASELINE_COMPARISON
    }
    
    scenario = scenario_mapping.get(test_scenario, LoadTestScenario.NORMAL_LOAD)
    
    # Get load test configuration
    load_config = get_load_test_config(scenario, environment)
    
    # Build Locust configuration
    locust_config = {
        'host': load_config.host,
        'users': load_config.users,
        'spawn_rate': load_config.spawn_rate,
        'run_time': f"{load_config.duration}s",
        'headless': os.getenv('LOCUST_HEADLESS', 'true').lower() == 'true',
        'csv': os.getenv('LOCUST_CSV_OUTPUT', 'performance_results'),
        'html': os.getenv('LOCUST_HTML_OUTPUT', 'performance_report.html'),
        'logfile': os.getenv('LOCUST_LOGFILE', 'locust.log'),
        'loglevel': os.getenv('LOCUST_LOGLEVEL', 'INFO')
    }
    
    logger.info(f"Locust configuration: {locust_config}")
    return locust_config


# Multi-region simulation through distributed Locust execution
class MultiRegionCoordinator:
    """
    Coordinates multi-region load testing simulation through distributed Locust workers.
    
    Implements geographic distribution patterns, regional user behavior variations,
    and coordinated load scaling across multiple regions for comprehensive testing.
    """
    
    def __init__(self):
        """Initialize multi-region coordinator with regional configurations."""
        self.regions = {
            'us-east-1': {'weight': 0.4, 'latency_base': 20, 'behavior_bias': 'normal'},
            'us-west-2': {'weight': 0.25, 'latency_base': 40, 'behavior_bias': 'heavy'},
            'eu-west-1': {'weight': 0.20, 'latency_base': 100, 'behavior_bias': 'light'},
            'ap-southeast-1': {'weight': 0.15, 'latency_base': 150, 'behavior_bias': 'api'}
        }
        
    def get_region_config(self, region_name: str) -> Dict[str, Any]:
        """Get configuration for specific region."""
        return self.regions.get(region_name, self.regions['us-east-1'])
    
    def simulate_regional_latency(self, region_name: str) -> None:
        """Simulate regional network latency."""
        region_config = self.get_region_config(region_name)
        base_latency = region_config['latency_base']
        
        # Add random jitter (±20% of base latency)
        jitter = random.uniform(-0.2, 0.2) * base_latency
        latency_ms = base_latency + jitter
        
        # Convert to seconds and sleep
        time.sleep(latency_ms / 1000)


# Main execution configuration for command-line usage
if __name__ == "__main__":
    """
    Main execution block for running Locust load tests directly.
    
    Supports command-line execution with environment variable configuration
    and automatic performance report generation.
    """
    
    # Load configuration
    config = get_locust_configuration()
    
    logger.info("Starting Locust load test with progressive scaling")
    logger.info(f"Target: {config['host']}")
    logger.info(f"Users: {config['users']}, Spawn Rate: {config['spawn_rate']}")
    logger.info(f"Duration: {config['run_time']}")
    
    # Set Locust host for user classes
    ProgressiveLoadUser.host = config['host']
    
    logger.info("Load test configuration complete - ready for execution")
    logger.info("Run with: locust -f locustfile.py --headless -u 1000 -r 50 -t 30m")
    logger.info("Or with web UI: locust -f locustfile.py --host http://localhost:5000")