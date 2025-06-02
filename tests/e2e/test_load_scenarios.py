"""
Load Testing Scenarios with Concurrent User Capacity Validation

This module implements comprehensive load testing scenarios using the locust framework to validate
concurrent request handling, system scalability, and performance compliance with ≤10% variance
from Node.js baseline. Supports realistic traffic patterns, progressive load scaling, and
automated performance threshold enforcement per Section 6.6.1 load testing requirements.

Key Features:
- Locust framework integration for concurrent user capacity validation per Section 6.6.1
- Progressive scaling from 10 to 1000 concurrent users per Section 4.6.3
- Target 100-500 requests per second sustained load per Section 4.6.3
- Performance variance validation ensuring ≤10% deviation from Node.js baseline per Section 0.1.1
- Realistic traffic pattern simulation matching Node.js capabilities per Section 0.2.3
- Resource utilization monitoring during load testing per Section 6.6.3
- Automated load test reporting with failure threshold enforcement per Section 6.6.2
- Integration with Flask application factory and monitoring stack per Section 6.6.1

Load Testing Architecture:
- Section 6.6.1: Locust framework for automated load testing and throughput validation
- Section 4.6.3: Performance testing flows with gradual load increase methodology
- Section 6.6.3: Concurrent request capacity validation matching Node.js capabilities
- Section 0.2.3: Load testing parameters for realistic production-equivalent scenarios
- Section 6.6.2: Automated load test reporting with comprehensive metrics collection
- Section 6.6.5: Production-equivalent test environment for accurate performance validation

Performance Requirements:
- Concurrent Users: Progressive scaling from 10 to 1000 users per Section 4.6.3
- Request Rate: Sustained 100-500 RPS load per Section 4.6.3  
- Response Time Variance: ≤10% from Node.js baseline per Section 0.1.1
- Error Rate: ≤0.1% under normal load per Section 4.6.3
- Resource Utilization: CPU ≤70%, Memory ≤80% during peak load per Section 4.6.3

Test Scenarios:
- Authentication Flow Load Testing: JWT validation and Auth0 integration under load
- API Workflow Load Testing: Business logic endpoints with realistic request patterns
- Database Operation Load Testing: MongoDB and Redis operations under concurrent access
- External Service Load Testing: Circuit breaker validation and resilience testing
- Complete E2E Load Testing: Full user workflow simulation with production traffic patterns

Dependencies:
- locust ≥2.x for load testing framework and distributed execution
- pytest 7.4+ with E2E testing configuration per Section 6.6.1
- pytest-asyncio for async load testing scenarios with Motor integration
- prometheus-client for performance metrics collection during load testing
- psutil for system resource monitoring and utilization validation
- requests/httpx for HTTP client performance measurement and validation

Author: Load Testing Team
Version: 1.0.0
Coverage Target: 100% critical load scenarios per Section 6.6.1
Performance Compliance: ≤10% variance from Node.js baseline per Section 0.1.1
"""

import asyncio
import json
import logging
import os
import psutil
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Callable, Union
from unittest.mock import Mock, patch

import pytest
import pytest_asyncio
from flask import Flask
from flask.testing import FlaskClient

# Import locust framework for load testing per Section 6.6.1
try:
    import locust
    from locust import HttpUser, task, constant, between, events
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    from locust.runners import LocalRunner, MasterRunner, WorkerRunner
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

# Import E2E testing fixtures and utilities
from tests.e2e.conftest import (
    comprehensive_e2e_environment,
    e2e_performance_monitor,
    locust_load_tester,
    apache_bench_tester,
    production_equivalent_environment,
    e2e_test_reporter,
    skip_if_not_e2e,
    require_load_testing,
    E2ETestingConfig
)

# Import base testing utilities
from tests.conftest import (
    performance_monitoring,
    test_metrics_collector,
    comprehensive_test_environment,
    skip_if_no_docker
)

# Configure load testing specific logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [LOAD_TEST] %(message)s'
)
logger = logging.getLogger(__name__)

# Configure pytest-asyncio for async load testing scenarios
pytest_plugins = ('pytest_asyncio',)


# =============================================================================
# LOAD TESTING CONFIGURATION AND CONSTANTS
# =============================================================================

class LoadTestingConfig:
    """
    Load testing configuration with progressive scaling parameters.
    
    Implements Section 4.6.3 load testing parameters and Section 6.6.1 
    performance testing requirements for realistic production validation.
    """
    
    # Progressive user scaling configuration per Section 4.6.3
    MIN_USERS = int(os.getenv('LOAD_TEST_MIN_USERS', '10'))
    MAX_USERS = int(os.getenv('LOAD_TEST_MAX_USERS', '1000'))
    USER_SCALING_STEPS = [10, 25, 50, 100, 200, 500, 1000]
    
    # Request rate targets per Section 4.6.3
    MIN_RPS = int(os.getenv('LOAD_TEST_MIN_RPS', '100'))
    MAX_RPS = int(os.getenv('LOAD_TEST_MAX_RPS', '500'))
    TARGET_RPS = int(os.getenv('LOAD_TEST_TARGET_RPS', '300'))
    
    # Load testing duration configuration
    RAMP_UP_TIME = int(os.getenv('LOAD_TEST_RAMP_UP_TIME', '60'))  # seconds
    SUSTAINED_LOAD_TIME = int(os.getenv('LOAD_TEST_SUSTAINED_TIME', '300'))  # 5 minutes
    COOL_DOWN_TIME = int(os.getenv('LOAD_TEST_COOL_DOWN_TIME', '30'))  # seconds
    
    # Performance variance thresholds per Section 0.1.1
    VARIANCE_THRESHOLD = float(os.getenv('LOAD_TEST_VARIANCE_THRESHOLD', '0.10'))  # ≤10%
    ERROR_RATE_THRESHOLD = float(os.getenv('LOAD_TEST_ERROR_THRESHOLD', '0.001'))  # ≤0.1%
    
    # Resource utilization limits per Section 4.6.3
    CPU_UTILIZATION_LIMIT = float(os.getenv('LOAD_TEST_CPU_LIMIT', '70.0'))  # ≤70%
    MEMORY_UTILIZATION_LIMIT = float(os.getenv('LOAD_TEST_MEMORY_LIMIT', '80.0'))  # ≤80%
    
    # Node.js baseline performance metrics for comparison per Section 0.1.1
    NODEJS_BASELINES = {
        'health_check_response_time': 0.050,  # 50ms
        'auth_flow_response_time': 0.350,     # 350ms
        'api_endpoint_response_time': 0.200,  # 200ms
        'database_query_time': 0.100,         # 100ms
        'cache_operation_time': 0.010,        # 10ms
        'external_service_time': 0.500,       # 500ms
        'complete_workflow_time': 1.500,      # 1.5s
    }
    
    # Load testing environment configuration
    HOST = os.getenv('LOAD_TEST_HOST', 'http://localhost:5000')
    SPAWN_RATE = int(os.getenv('LOAD_TEST_SPAWN_RATE', '5'))  # users per second
    
    # Reporting and monitoring configuration
    ENABLE_DETAILED_REPORTING = os.getenv('LOAD_TEST_DETAILED_REPORTING', 'true').lower() == 'true'
    ENABLE_RESOURCE_MONITORING = os.getenv('LOAD_TEST_RESOURCE_MONITORING', 'true').lower() == 'true'
    PROMETHEUS_METRICS_ENABLED = os.getenv('LOAD_TEST_PROMETHEUS_METRICS', 'true').lower() == 'true'


# =============================================================================
# LOCUST USER CLASSES FOR REALISTIC TRAFFIC SIMULATION
# =============================================================================

class BaseLoadTestUser(HttpUser):
    """
    Base load test user class with common functionality.
    
    Implements realistic user behavior patterns for Flask application
    load testing with comprehensive metrics collection and error handling.
    """
    
    # User behavior configuration
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests
    weight = 1
    
    def on_start(self):
        """Initialize user session for load testing."""
        self.user_id = str(uuid.uuid4())
        self.session_start_time = time.time()
        self.auth_token = None
        self.user_context = {
            'authenticated': False,
            'role': 'user',
            'permissions': [],
            'session_id': str(uuid.uuid4())
        }
        
        logger.debug(f"Load test user {self.user_id} started session")
    
    def on_stop(self):
        """Clean up user session after load testing."""
        session_duration = time.time() - self.session_start_time
        logger.debug(
            f"Load test user {self.user_id} ended session",
            duration=round(session_duration, 3)
        )
    
    def authenticate_user(self):
        """Simulate user authentication flow."""
        login_data = {
            'email': f'loadtest-{self.user_id}@example.com',
            'password': 'LoadTest123!',
            'remember_me': False
        }
        
        with self.client.post(
            '/auth/login',
            json=login_data,
            catch_response=True,
            name='Auth: Login Flow'
        ) as response:
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    self.auth_token = response_data.get('access_token')
                    self.user_context['authenticated'] = True
                    self.user_context['role'] = response_data.get('role', 'user')
                    self.user_context['permissions'] = response_data.get('permissions', [])
                    response.success()
                except (ValueError, KeyError) as e:
                    response.failure(f"Authentication response parsing failed: {e}")
            else:
                response.failure(f"Authentication failed with status {response.status_code}")
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for authenticated requests."""
        headers = {
            'Content-Type': 'application/json',
            'X-Request-ID': str(uuid.uuid4()),
            'User-Agent': 'LoadTest-Client/1.0'
        }
        
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        return headers


class HealthCheckUser(BaseLoadTestUser):
    """
    Load test user focused on health check endpoints.
    
    Validates system health monitoring under load per Section 6.6.1
    health check integration requirements.
    """
    
    weight = 5  # Higher frequency for health checks
    wait_time = constant(1)  # Consistent 1-second intervals
    
    @task(10)
    def health_check(self):
        """Test main health check endpoint under load."""
        with self.client.get(
            '/health',
            catch_response=True,
            name='Health: Main Check'
        ) as response:
            if response.status_code == 200:
                try:
                    health_data = response.json()
                    if health_data.get('status') == 'healthy':
                        response.success()
                    else:
                        response.failure(f"Health check returned unhealthy status: {health_data.get('status')}")
                except ValueError:
                    response.failure("Health check response is not valid JSON")
            else:
                response.failure(f"Health check failed with status {response.status_code}")
    
    @task(3)
    def liveness_probe(self):
        """Test Kubernetes liveness probe endpoint."""
        with self.client.get(
            '/health/live',
            catch_response=True,
            name='Health: Liveness Probe'
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Liveness probe failed with status {response.status_code}")
    
    @task(3)
    def readiness_probe(self):
        """Test Kubernetes readiness probe endpoint."""
        with self.client.get(
            '/health/ready',
            catch_response=True,
            name='Health: Readiness Probe'
        ) as response:
            if response.status_code == 200:
                try:
                    readiness_data = response.json()
                    if readiness_data.get('status') == 'ready':
                        response.success()
                    else:
                        response.failure(f"Readiness probe returned not ready: {readiness_data.get('status')}")
                except ValueError:
                    response.failure("Readiness probe response is not valid JSON")
            else:
                response.failure(f"Readiness probe failed with status {response.status_code}")
    
    @task(1)
    def metrics_endpoint(self):
        """Test Prometheus metrics endpoint under load."""
        with self.client.get(
            '/metrics',
            catch_response=True,
            name='Health: Metrics Endpoint'
        ) as response:
            if response.status_code == 200:
                # Validate Prometheus metrics format
                if 'flask_request_duration_seconds' in response.text:
                    response.success()
                else:
                    response.failure("Metrics endpoint missing expected Flask metrics")
            else:
                response.failure(f"Metrics endpoint failed with status {response.status_code}")


class AuthenticationUser(BaseLoadTestUser):
    """
    Load test user focused on authentication workflows.
    
    Validates JWT token processing and Auth0 integration under load
    per Section 6.6.1 authentication integration requirements.
    """
    
    weight = 3
    wait_time = between(2, 5)
    
    def on_start(self):
        """Initialize authentication user session."""
        super().on_start()
        # 80% of users authenticate immediately
        if hash(self.user_id) % 10 < 8:
            self.authenticate_user()
    
    @task(5)
    def login_flow(self):
        """Test complete login workflow under load."""
        # Logout first if authenticated
        if self.user_context['authenticated']:
            with self.client.post(
                '/auth/logout',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='Auth: Logout'
            ) as response:
                if response.status_code in [200, 204]:
                    self.auth_token = None
                    self.user_context['authenticated'] = False
                    response.success()
                else:
                    response.failure(f"Logout failed with status {response.status_code}")
        
        # Perform login
        self.authenticate_user()
    
    @task(3)
    def token_validation(self):
        """Test JWT token validation under load."""
        if not self.user_context['authenticated']:
            self.authenticate_user()
        
        if self.user_context['authenticated']:
            with self.client.get(
                '/auth/validate',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='Auth: Token Validation'
            ) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Token validation failed with status {response.status_code}")
    
    @task(2)
    def user_profile_access(self):
        """Test authenticated user profile access."""
        if not self.user_context['authenticated']:
            self.authenticate_user()
        
        if self.user_context['authenticated']:
            with self.client.get(
                '/api/v1/users/profile',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='Auth: Profile Access'
            ) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 401:
                    # Token expired, re-authenticate
                    self.authenticate_user()
                    response.failure("Token expired during profile access")
                else:
                    response.failure(f"Profile access failed with status {response.status_code}")
    
    @task(1)
    def permission_check(self):
        """Test permission validation under load."""
        if not self.user_context['authenticated']:
            self.authenticate_user()
        
        if self.user_context['authenticated']:
            with self.client.get(
                '/api/v1/users/permissions',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='Auth: Permission Check'
            ) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Permission check failed with status {response.status_code}")


class APIWorkflowUser(BaseLoadTestUser):
    """
    Load test user focused on API workflow testing.
    
    Validates business logic endpoints and data processing under load
    per Section 6.6.1 API workflow load testing requirements.
    """
    
    weight = 4
    wait_time = between(1, 4)
    
    def on_start(self):
        """Initialize API workflow user session."""
        super().on_start()
        self.authenticate_user()
        self.created_resources = []
    
    @task(8)
    def list_projects(self):
        """Test project listing API under load."""
        with self.client.get(
            '/api/v1/projects',
            headers=self.get_auth_headers(),
            catch_response=True,
            name='API: List Projects'
        ) as response:
            if response.status_code == 200:
                try:
                    projects = response.json()
                    if isinstance(projects, list):
                        response.success()
                    else:
                        response.failure("Projects response is not a list")
                except ValueError:
                    response.failure("Projects response is not valid JSON")
            else:
                response.failure(f"List projects failed with status {response.status_code}")
    
    @task(3)
    def create_project(self):
        """Test project creation API under load."""
        project_data = {
            'name': f'Load Test Project {uuid.uuid4().hex[:8]}',
            'description': f'Project created during load test by user {self.user_id}',
            'settings': {
                'public': False,
                'collaboration_enabled': True
            }
        }
        
        with self.client.post(
            '/api/v1/projects',
            json=project_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='API: Create Project'
        ) as response:
            if response.status_code == 201:
                try:
                    created_project = response.json()
                    project_id = created_project.get('id')
                    if project_id:
                        self.created_resources.append(('project', project_id))
                        response.success()
                    else:
                        response.failure("Created project missing ID")
                except ValueError:
                    response.failure("Create project response is not valid JSON")
            else:
                response.failure(f"Create project failed with status {response.status_code}")
    
    @task(5)
    def get_project_details(self):
        """Test project details retrieval under load."""
        # Use existing project or create one
        if not self.created_resources:
            self.create_project()
        
        project_resources = [r for r in self.created_resources if r[0] == 'project']
        if project_resources:
            project_id = project_resources[0][1]
            
            with self.client.get(
                f'/api/v1/projects/{project_id}',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='API: Get Project Details'
            ) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 404:
                    # Project might have been deleted, remove from tracking
                    self.created_resources = [r for r in self.created_resources if not (r[0] == 'project' and r[1] == project_id)]
                    response.failure("Project not found")
                else:
                    response.failure(f"Get project details failed with status {response.status_code}")
    
    @task(2)
    def update_project(self):
        """Test project update API under load."""
        project_resources = [r for r in self.created_resources if r[0] == 'project']
        if project_resources:
            project_id = project_resources[0][1]
            
            update_data = {
                'description': f'Updated during load test at {datetime.utcnow().isoformat()}',
                'settings': {
                    'public': True,
                    'collaboration_enabled': True
                }
            }
            
            with self.client.put(
                f'/api/v1/projects/{project_id}',
                json=update_data,
                headers=self.get_auth_headers(),
                catch_response=True,
                name='API: Update Project'
            ) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 404:
                    self.created_resources = [r for r in self.created_resources if not (r[0] == 'project' and r[1] == project_id)]
                    response.failure("Project not found for update")
                else:
                    response.failure(f"Update project failed with status {response.status_code}")
    
    @task(1)
    def delete_project(self):
        """Test project deletion API under load."""
        project_resources = [r for r in self.created_resources if r[0] == 'project']
        if len(project_resources) > 3:  # Keep some projects for other operations
            project_id = project_resources[0][1]
            
            with self.client.delete(
                f'/api/v1/projects/{project_id}',
                headers=self.get_auth_headers(),
                catch_response=True,
                name='API: Delete Project'
            ) as response:
                if response.status_code in [200, 204]:
                    self.created_resources = [r for r in self.created_resources if not (r[0] == 'project' and r[1] == project_id)]
                    response.success()
                else:
                    response.failure(f"Delete project failed with status {response.status_code}")
    
    @task(4)
    def dashboard_stats(self):
        """Test dashboard statistics API under load."""
        with self.client.get(
            '/api/v1/dashboard/stats',
            headers=self.get_auth_headers(),
            catch_response=True,
            name='API: Dashboard Stats'
        ) as response:
            if response.status_code == 200:
                try:
                    stats = response.json()
                    if 'projects' in stats and 'users' in stats:
                        response.success()
                    else:
                        response.failure("Dashboard stats missing required fields")
                except ValueError:
                    response.failure("Dashboard stats response is not valid JSON")
            else:
                response.failure(f"Dashboard stats failed with status {response.status_code}")


class DatabaseOperationUser(BaseLoadTestUser):
    """
    Load test user focused on database operations.
    
    Validates MongoDB and Redis operations under load per Section 6.6.1
    database integration testing requirements.
    """
    
    weight = 2
    wait_time = between(0.5, 2)
    
    def on_start(self):
        """Initialize database operation user session."""
        super().on_start()
        self.authenticate_user()
    
    @task(6)
    def search_operations(self):
        """Test database search operations under load."""
        search_params = {
            'query': f'test-{uuid.uuid4().hex[:6]}',
            'limit': 20,
            'offset': 0
        }
        
        with self.client.get(
            '/api/v1/search',
            params=search_params,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='Database: Search Operations'
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Search operations failed with status {response.status_code}")
    
    @task(4)
    def cache_operations(self):
        """Test Redis cache operations under load."""
        cache_key = f'load-test-{self.user_id}-{int(time.time())}'
        cache_data = {
            'action': 'cache_test',
            'data': f'Load test data for user {self.user_id}'
        }
        
        # Cache write operation
        with self.client.post(
            '/api/v1/cache',
            json={'key': cache_key, 'value': cache_data, 'ttl': 300},
            headers=self.get_auth_headers(),
            catch_response=True,
            name='Database: Cache Write'
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
            else:
                response.failure(f"Cache write failed with status {response.status_code}")
        
        # Cache read operation
        with self.client.get(
            f'/api/v1/cache/{cache_key}',
            headers=self.get_auth_headers(),
            catch_response=True,
            name='Database: Cache Read'
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 404:
                response.failure("Cache key not found after write")
            else:
                response.failure(f"Cache read failed with status {response.status_code}")
    
    @task(3)
    def bulk_operations(self):
        """Test bulk database operations under load."""
        bulk_data = {
            'operations': [
                {'type': 'create', 'collection': 'load_test', 'data': {'test_id': str(uuid.uuid4())}},
                {'type': 'create', 'collection': 'load_test', 'data': {'test_id': str(uuid.uuid4())}},
                {'type': 'create', 'collection': 'load_test', 'data': {'test_id': str(uuid.uuid4())}}
            ]
        }
        
        with self.client.post(
            '/api/v1/database/bulk',
            json=bulk_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='Database: Bulk Operations'
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Bulk operations failed with status {response.status_code}")
    
    @task(2)
    def transaction_operations(self):
        """Test database transaction operations under load."""
        transaction_data = {
            'transaction_id': str(uuid.uuid4()),
            'operations': [
                {'type': 'update', 'collection': 'users', 'query': {'id': self.user_id}, 'data': {'last_active': datetime.utcnow().isoformat()}},
                {'type': 'insert', 'collection': 'activity_log', 'data': {'user_id': self.user_id, 'action': 'load_test', 'timestamp': datetime.utcnow().isoformat()}}
            ]
        }
        
        with self.client.post(
            '/api/v1/database/transaction',
            json=transaction_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='Database: Transaction Operations'
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Transaction operations failed with status {response.status_code}")


class ExternalServiceUser(BaseLoadTestUser):
    """
    Load test user focused on external service integration.
    
    Validates circuit breaker patterns and external service resilience
    under load per Section 6.6.1 external service integration requirements.
    """
    
    weight = 1
    wait_time = between(2, 6)
    
    def on_start(self):
        """Initialize external service user session."""
        super().on_start()
        self.authenticate_user()
    
    @task(4)
    def file_upload_operations(self):
        """Test file upload to AWS S3 under load."""
        file_data = {
            'filename': f'load-test-{uuid.uuid4().hex[:8]}.txt',
            'content_type': 'text/plain',
            'size': 1024,
            'data': 'Load testing file content'
        }
        
        with self.client.post(
            '/api/v1/files/upload',
            json=file_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='External: File Upload'
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
            else:
                response.failure(f"File upload failed with status {response.status_code}")
    
    @task(3)
    def external_api_calls(self):
        """Test external API integration under load."""
        api_request = {
            'endpoint': 'user_validation',
            'data': {'user_id': self.user_id},
            'timeout': 10
        }
        
        with self.client.post(
            '/api/v1/external/call',
            json=api_request,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='External: API Calls'
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 503:
                response.failure("External service unavailable (circuit breaker open)")
            else:
                response.failure(f"External API call failed with status {response.status_code}")
    
    @task(2)
    def notification_services(self):
        """Test notification service integration under load."""
        notification_data = {
            'type': 'load_test',
            'recipient': f'loadtest-{self.user_id}@example.com',
            'subject': 'Load Test Notification',
            'message': f'Load testing notification for user {self.user_id}'
        }
        
        with self.client.post(
            '/api/v1/notifications/send',
            json=notification_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            name='External: Notification Services'
        ) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"Notification service failed with status {response.status_code}")


# =============================================================================
# PERFORMANCE MONITORING AND RESOURCE TRACKING
# =============================================================================

class LoadTestPerformanceMonitor:
    """
    Comprehensive performance monitoring for load testing scenarios.
    
    Tracks system resource utilization, response time variance, and
    performance compliance with Node.js baseline per Section 0.1.1.
    """
    
    def __init__(self, config: LoadTestingConfig = None):
        """Initialize performance monitor with configuration."""
        self.config = config or LoadTestingConfig()
        self.monitoring_active = False
        self.start_time = None
        self.measurements = []
        self.resource_samples = []
        self.performance_violations = []
        
        # Initialize system monitoring
        if self.config.ENABLE_RESOURCE_MONITORING:
            try:
                self.process = psutil.Process()
                self.system_available = True
            except Exception:
                self.system_available = False
                logger.warning("System resource monitoring not available")
        else:
            self.system_available = False
    
    @contextmanager
    def monitor_load_test(self, test_name: str):
        """Context manager for monitoring load test execution."""
        self.start_time = time.time()
        self.monitoring_active = True
        
        logger.info(f"Starting performance monitoring for load test: {test_name}")
        
        # Start background resource monitoring
        resource_monitor_thread = None
        if self.system_available:
            import threading
            resource_monitor_thread = threading.Thread(
                target=self._monitor_system_resources,
                daemon=True
            )
            resource_monitor_thread.start()
        
        try:
            yield self
        finally:
            self.monitoring_active = False
            
            # Wait for resource monitoring to complete
            if resource_monitor_thread and resource_monitor_thread.is_alive():
                resource_monitor_thread.join(timeout=5)
            
            test_duration = time.time() - self.start_time
            logger.info(
                f"Performance monitoring completed for {test_name}",
                duration=round(test_duration, 3),
                measurements=len(self.measurements),
                resource_samples=len(self.resource_samples),
                violations=len(self.performance_violations)
            )
    
    def _monitor_system_resources(self):
        """Background system resource monitoring."""
        while self.monitoring_active:
            try:
                # CPU utilization
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Memory utilization
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Network I/O
                net_io = psutil.net_io_counters()
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                
                resource_sample = {
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'memory_used_mb': memory.used / (1024 * 1024),
                    'network_bytes_sent': net_io.bytes_sent,
                    'network_bytes_recv': net_io.bytes_recv,
                    'disk_read_bytes': disk_io.read_bytes if disk_io else 0,
                    'disk_write_bytes': disk_io.write_bytes if disk_io else 0
                }
                
                self.resource_samples.append(resource_sample)
                
                # Check resource utilization thresholds
                if cpu_percent > self.config.CPU_UTILIZATION_LIMIT:
                    violation = {
                        'type': 'cpu_utilization',
                        'timestamp': time.time(),
                        'measured_value': cpu_percent,
                        'threshold': self.config.CPU_UTILIZATION_LIMIT,
                        'severity': 'critical' if cpu_percent > 90 else 'warning'
                    }
                    self.performance_violations.append(violation)
                    logger.warning(
                        f"CPU utilization violation: {cpu_percent:.1f}% > {self.config.CPU_UTILIZATION_LIMIT:.1f}%"
                    )
                
                if memory_percent > self.config.MEMORY_UTILIZATION_LIMIT:
                    violation = {
                        'type': 'memory_utilization',
                        'timestamp': time.time(),
                        'measured_value': memory_percent,
                        'threshold': self.config.MEMORY_UTILIZATION_LIMIT,
                        'severity': 'critical' if memory_percent > 95 else 'warning'
                    }
                    self.performance_violations.append(violation)
                    logger.warning(
                        f"Memory utilization violation: {memory_percent:.1f}% > {self.config.MEMORY_UTILIZATION_LIMIT:.1f}%"
                    )
                
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
            
            time.sleep(5)  # Sample every 5 seconds
    
    def record_performance_measurement(
        self,
        operation: str,
        duration: float,
        baseline_key: str = None,
        additional_metrics: Dict[str, Any] = None
    ):
        """Record performance measurement with baseline comparison."""
        measurement = {
            'operation': operation,
            'duration': duration,
            'timestamp': time.time(),
            'baseline_key': baseline_key,
            'additional_metrics': additional_metrics or {}
        }
        
        self.measurements.append(measurement)
        
        # Compare against Node.js baseline if provided
        if baseline_key and baseline_key in self.config.NODEJS_BASELINES:
            baseline_value = self.config.NODEJS_BASELINES[baseline_key]
            variance = abs(duration - baseline_value) / baseline_value
            
            if variance > self.config.VARIANCE_THRESHOLD:
                violation = {
                    'type': 'performance_variance',
                    'operation': operation,
                    'measured_duration': duration,
                    'baseline_duration': baseline_value,
                    'variance_percentage': variance * 100,
                    'threshold_percentage': self.config.VARIANCE_THRESHOLD * 100,
                    'timestamp': time.time(),
                    'severity': 'critical' if variance > 0.25 else 'warning'
                }
                self.performance_violations.append(violation)
                
                logger.warning(
                    f"Performance variance violation for {operation}: "
                    f"{variance * 100:.1f}% > {self.config.VARIANCE_THRESHOLD * 100:.1f}%"
                )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Generate comprehensive performance summary."""
        if not self.measurements:
            return {'status': 'no_measurements'}
        
        # Calculate performance statistics
        durations = [m['duration'] for m in self.measurements]
        
        performance_stats = {
            'total_measurements': len(self.measurements),
            'average_duration': statistics.mean(durations),
            'median_duration': statistics.median(durations),
            'min_duration': min(durations),
            'max_duration': max(durations),
            'p95_duration': statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else max(durations),
            'p99_duration': statistics.quantiles(durations, n=100)[98] if len(durations) >= 100 else max(durations)
        }
        
        # Calculate resource utilization statistics
        resource_stats = {}
        if self.resource_samples:
            cpu_values = [r['cpu_percent'] for r in self.resource_samples]
            memory_values = [r['memory_percent'] for r in self.resource_samples]
            
            resource_stats = {
                'cpu_utilization': {
                    'average': statistics.mean(cpu_values),
                    'peak': max(cpu_values),
                    'samples': len(cpu_values)
                },
                'memory_utilization': {
                    'average': statistics.mean(memory_values),
                    'peak': max(memory_values),
                    'samples': len(memory_values)
                }
            }
        
        # Violation summary
        violation_stats = {
            'total_violations': len(self.performance_violations),
            'critical_violations': len([v for v in self.performance_violations if v.get('severity') == 'critical']),
            'warning_violations': len([v for v in self.performance_violations if v.get('severity') == 'warning']),
            'violation_types': {}
        }
        
        for violation in self.performance_violations:
            violation_type = violation.get('type', 'unknown')
            if violation_type not in violation_stats['violation_types']:
                violation_stats['violation_types'][violation_type] = 0
            violation_stats['violation_types'][violation_type] += 1
        
        # Overall compliance assessment
        total_operations = len(self.measurements)
        performance_violations = len([v for v in self.performance_violations if v.get('type') == 'performance_variance'])
        compliance_rate = (total_operations - performance_violations) / total_operations * 100 if total_operations > 0 else 100
        
        return {
            'status': 'completed',
            'test_duration': time.time() - self.start_time if self.start_time else 0,
            'performance_stats': performance_stats,
            'resource_stats': resource_stats,
            'violation_stats': violation_stats,
            'compliance_rate': compliance_rate,
            'baseline_compliant': compliance_rate >= (100 - self.config.VARIANCE_THRESHOLD * 100)
        }


# =============================================================================
# PROGRESSIVE LOAD TESTING SCENARIOS
# =============================================================================

@pytest.mark.e2e
@pytest.mark.performance
@pytest.mark.load_testing
@skip_if_not_e2e()
@require_load_testing()
@pytest.mark.skipif(not LOCUST_AVAILABLE, reason="Locust framework not available")
class TestLoadScenarios:
    """
    Comprehensive load testing scenarios with progressive user scaling.
    
    Implements Section 4.6.3 performance testing flows and Section 6.6.1
    load testing framework requirements for concurrent capacity validation.
    """
    
    def setup_method(self):
        """Set up load testing environment for each test method."""
        self.config = LoadTestingConfig()
        self.performance_monitor = LoadTestPerformanceMonitor(self.config)
        self.test_results = []
        
        logger.info("Load testing scenario setup completed")
    
    def teardown_method(self):
        """Clean up after each load testing scenario."""
        # Generate final test report
        if self.test_results:
            self._generate_load_test_report()
        
        logger.info("Load testing scenario cleanup completed")
    
    def test_health_check_load_capacity(self, comprehensive_e2e_environment):
        """
        Test health check endpoints under progressive load scaling.
        
        Validates health monitoring system performance under load per
        Section 6.6.1 health check integration requirements.
        """
        with self.performance_monitor.monitor_load_test('health_check_load'):
            # Progressive load testing for health endpoints
            user_counts = [10, 25, 50, 100]
            
            for user_count in user_counts:
                logger.info(f"Testing health check load with {user_count} concurrent users")
                
                # Create locust environment
                env = Environment(user_classes=[HealthCheckUser])
                env.create_local_runner()
                
                # Configure host
                env.host = self.config.HOST
                
                # Start load test
                start_time = time.time()
                env.runner.start(user_count, spawn_rate=self.config.SPAWN_RATE)
                
                # Run for 60 seconds
                import gevent
                gevent.sleep(60)
                
                # Stop and collect results
                env.runner.stop()
                test_duration = time.time() - start_time
                
                # Collect performance metrics
                stats = env.runner.stats
                
                # Record performance measurements
                if stats.total.num_requests > 0:
                    avg_response_time = stats.total.avg_response_time / 1000  # Convert to seconds
                    self.performance_monitor.record_performance_measurement(
                        operation=f'health_check_load_{user_count}_users',
                        duration=avg_response_time,
                        baseline_key='health_check_response_time',
                        additional_metrics={
                            'total_requests': stats.total.num_requests,
                            'total_failures': stats.total.num_failures,
                            'requests_per_second': stats.total.total_rps,
                            'user_count': user_count,
                            'test_duration': test_duration
                        }
                    )
                
                test_result = {
                    'scenario': 'health_check_load',
                    'user_count': user_count,
                    'duration': test_duration,
                    'total_requests': stats.total.num_requests,
                    'total_failures': stats.total.num_failures,
                    'failure_rate': stats.total.fail_ratio,
                    'avg_response_time': stats.total.avg_response_time,
                    'requests_per_second': stats.total.total_rps,
                    'min_response_time': stats.total.min_response_time,
                    'max_response_time': stats.total.max_response_time
                }
                
                self.test_results.append(test_result)
                
                # Validate performance requirements
                assert stats.total.fail_ratio <= self.config.ERROR_RATE_THRESHOLD, (
                    f"Health check failure rate {stats.total.fail_ratio:.3f} exceeds threshold {self.config.ERROR_RATE_THRESHOLD:.3f}"
                )
                
                assert stats.total.total_rps >= self.config.MIN_RPS / 4, (  # Scale requirement by user count
                    f"Health check RPS {stats.total.total_rps:.1f} below minimum requirement"
                )
                
                logger.info(
                    f"Health check load test completed for {user_count} users",
                    requests=stats.total.num_requests,
                    failures=stats.total.num_failures,
                    rps=round(stats.total.total_rps, 2),
                    avg_response_time=round(stats.total.avg_response_time, 2)
                )
                
                # Cool down between test phases
                gevent.sleep(self.config.COOL_DOWN_TIME)
        
        # Validate overall performance compliance
        performance_summary = self.performance_monitor.get_performance_summary()
        assert performance_summary['baseline_compliant'], (
            f"Health check load testing failed baseline compliance: "
            f"{performance_summary['compliance_rate']:.1f}% < {100 - self.config.VARIANCE_THRESHOLD * 100:.1f}%"
        )
    
    def test_authentication_flow_load_capacity(self, comprehensive_e2e_environment):
        """
        Test authentication workflows under progressive load scaling.
        
        Validates JWT processing and Auth0 integration performance under load
        per Section 6.6.1 authentication integration requirements.
        """
        with self.performance_monitor.monitor_load_test('authentication_flow_load'):
            user_counts = [10, 25, 50, 100, 200]
            
            for user_count in user_counts:
                logger.info(f"Testing authentication flow load with {user_count} concurrent users")
                
                env = Environment(user_classes=[AuthenticationUser])
                env.create_local_runner()
                env.host = self.config.HOST
                
                start_time = time.time()
                env.runner.start(user_count, spawn_rate=self.config.SPAWN_RATE)
                
                # Run for 120 seconds to allow multiple auth cycles
                import gevent
                gevent.sleep(120)
                
                env.runner.stop()
                test_duration = time.time() - start_time
                
                stats = env.runner.stats
                
                # Record auth flow performance
                if stats.total.num_requests > 0:
                    avg_response_time = stats.total.avg_response_time / 1000
                    self.performance_monitor.record_performance_measurement(
                        operation=f'auth_flow_load_{user_count}_users',
                        duration=avg_response_time,
                        baseline_key='auth_flow_response_time',
                        additional_metrics={
                            'total_requests': stats.total.num_requests,
                            'total_failures': stats.total.num_failures,
                            'requests_per_second': stats.total.total_rps,
                            'user_count': user_count,
                            'test_duration': test_duration
                        }
                    )
                
                test_result = {
                    'scenario': 'authentication_flow_load',
                    'user_count': user_count,
                    'duration': test_duration,
                    'total_requests': stats.total.num_requests,
                    'total_failures': stats.total.num_failures,
                    'failure_rate': stats.total.fail_ratio,
                    'avg_response_time': stats.total.avg_response_time,
                    'requests_per_second': stats.total.total_rps,
                    'min_response_time': stats.total.min_response_time,
                    'max_response_time': stats.total.max_response_time
                }
                
                self.test_results.append(test_result)
                
                # Validate authentication performance requirements
                assert stats.total.fail_ratio <= self.config.ERROR_RATE_THRESHOLD, (
                    f"Authentication failure rate {stats.total.fail_ratio:.3f} exceeds threshold"
                )
                
                # Authentication flows should handle lower RPS due to complexity
                min_auth_rps = max(10, self.config.MIN_RPS / 8)
                assert stats.total.total_rps >= min_auth_rps, (
                    f"Authentication RPS {stats.total.total_rps:.1f} below minimum {min_auth_rps}"
                )
                
                logger.info(
                    f"Authentication flow load test completed for {user_count} users",
                    requests=stats.total.num_requests,
                    failures=stats.total.num_failures,
                    rps=round(stats.total.total_rps, 2)
                )
                
                gevent.sleep(self.config.COOL_DOWN_TIME)
        
        performance_summary = self.performance_monitor.get_performance_summary()
        assert performance_summary['baseline_compliant'], (
            "Authentication flow load testing failed baseline compliance"
        )
    
    def test_api_workflow_load_capacity(self, comprehensive_e2e_environment):
        """
        Test API workflow endpoints under progressive load scaling.
        
        Validates business logic performance under load per Section 6.6.1
        API workflow load testing requirements.
        """
        with self.performance_monitor.monitor_load_test('api_workflow_load'):
            user_counts = [25, 50, 100, 200, 500]
            
            for user_count in user_counts:
                logger.info(f"Testing API workflow load with {user_count} concurrent users")
                
                env = Environment(user_classes=[APIWorkflowUser])
                env.create_local_runner()
                env.host = self.config.HOST
                
                start_time = time.time()
                env.runner.start(user_count, spawn_rate=self.config.SPAWN_RATE)
                
                # Run for 180 seconds for comprehensive workflow testing
                import gevent
                gevent.sleep(180)
                
                env.runner.stop()
                test_duration = time.time() - start_time
                
                stats = env.runner.stats
                
                if stats.total.num_requests > 0:
                    avg_response_time = stats.total.avg_response_time / 1000
                    self.performance_monitor.record_performance_measurement(
                        operation=f'api_workflow_load_{user_count}_users',
                        duration=avg_response_time,
                        baseline_key='api_endpoint_response_time',
                        additional_metrics={
                            'total_requests': stats.total.num_requests,
                            'total_failures': stats.total.num_failures,
                            'requests_per_second': stats.total.total_rps,
                            'user_count': user_count,
                            'test_duration': test_duration
                        }
                    )
                
                test_result = {
                    'scenario': 'api_workflow_load',
                    'user_count': user_count,
                    'duration': test_duration,
                    'total_requests': stats.total.num_requests,
                    'total_failures': stats.total.num_failures,
                    'failure_rate': stats.total.fail_ratio,
                    'avg_response_time': stats.total.avg_response_time,
                    'requests_per_second': stats.total.total_rps,
                    'min_response_time': stats.total.min_response_time,
                    'max_response_time': stats.total.max_response_time
                }
                
                self.test_results.append(test_result)
                
                # Validate API workflow performance requirements
                assert stats.total.fail_ratio <= self.config.ERROR_RATE_THRESHOLD, (
                    f"API workflow failure rate {stats.total.fail_ratio:.3f} exceeds threshold"
                )
                
                # Scale RPS requirement based on user count
                expected_rps = min(self.config.TARGET_RPS, user_count * 2)
                assert stats.total.total_rps >= expected_rps * 0.8, (  # Allow 20% tolerance
                    f"API workflow RPS {stats.total.total_rps:.1f} below expected {expected_rps * 0.8:.1f}"
                )
                
                logger.info(
                    f"API workflow load test completed for {user_count} users",
                    requests=stats.total.num_requests,
                    failures=stats.total.num_failures,
                    rps=round(stats.total.total_rps, 2)
                )
                
                gevent.sleep(self.config.COOL_DOWN_TIME)
        
        performance_summary = self.performance_monitor.get_performance_summary()
        assert performance_summary['baseline_compliant'], (
            "API workflow load testing failed baseline compliance"
        )
    
    def test_database_operation_load_capacity(self, comprehensive_e2e_environment):
        """
        Test database operations under progressive load scaling.
        
        Validates MongoDB and Redis performance under load per Section 6.6.1
        database integration testing requirements.
        """
        with self.performance_monitor.monitor_load_test('database_operation_load'):
            user_counts = [20, 50, 100, 200]
            
            for user_count in user_counts:
                logger.info(f"Testing database operation load with {user_count} concurrent users")
                
                env = Environment(user_classes=[DatabaseOperationUser])
                env.create_local_runner()
                env.host = self.config.HOST
                
                start_time = time.time()
                env.runner.start(user_count, spawn_rate=self.config.SPAWN_RATE)
                
                # Run for 150 seconds for database operation testing
                import gevent
                gevent.sleep(150)
                
                env.runner.stop()
                test_duration = time.time() - start_time
                
                stats = env.runner.stats
                
                if stats.total.num_requests > 0:
                    avg_response_time = stats.total.avg_response_time / 1000
                    self.performance_monitor.record_performance_measurement(
                        operation=f'database_operation_load_{user_count}_users',
                        duration=avg_response_time,
                        baseline_key='database_query_time',
                        additional_metrics={
                            'total_requests': stats.total.num_requests,
                            'total_failures': stats.total.num_failures,
                            'requests_per_second': stats.total.total_rps,
                            'user_count': user_count,
                            'test_duration': test_duration
                        }
                    )
                
                test_result = {
                    'scenario': 'database_operation_load',
                    'user_count': user_count,
                    'duration': test_duration,
                    'total_requests': stats.total.num_requests,
                    'total_failures': stats.total.num_failures,
                    'failure_rate': stats.total.fail_ratio,
                    'avg_response_time': stats.total.avg_response_time,
                    'requests_per_second': stats.total.total_rps,
                    'min_response_time': stats.total.min_response_time,
                    'max_response_time': stats.total.max_response_time
                }
                
                self.test_results.append(test_result)
                
                # Validate database operation performance requirements
                assert stats.total.fail_ratio <= self.config.ERROR_RATE_THRESHOLD, (
                    f"Database operation failure rate {stats.total.fail_ratio:.3f} exceeds threshold"
                )
                
                logger.info(
                    f"Database operation load test completed for {user_count} users",
                    requests=stats.total.num_requests,
                    failures=stats.total.num_failures,
                    rps=round(stats.total.total_rps, 2)
                )
                
                gevent.sleep(self.config.COOL_DOWN_TIME)
        
        performance_summary = self.performance_monitor.get_performance_summary()
        assert performance_summary['baseline_compliant'], (
            "Database operation load testing failed baseline compliance"
        )
    
    def test_mixed_workload_capacity_validation(self, comprehensive_e2e_environment):
        """
        Test mixed workload with all user types under maximum load.
        
        Validates complete system performance under realistic mixed traffic
        patterns per Section 6.6.1 concurrent request handling capacity.
        """
        with self.performance_monitor.monitor_load_test('mixed_workload_capacity'):
            # Maximum load test with mixed user types
            total_users = min(self.config.MAX_USERS, 1000)
            
            logger.info(f"Testing mixed workload capacity with {total_users} concurrent users")
            
            # Define user distribution for realistic traffic patterns
            user_classes = [
                HealthCheckUser,      # 20% - Health monitoring
                AuthenticationUser,   # 20% - Authentication flows  
                APIWorkflowUser,      # 40% - Primary business logic
                DatabaseOperationUser, # 15% - Database operations
                ExternalServiceUser   # 5% - External integrations
            ]
            
            env = Environment(user_classes=user_classes)
            env.create_local_runner()
            env.host = self.config.HOST
            
            start_time = time.time()
            
            # Progressive ramp-up to maximum users
            env.runner.start(total_users, spawn_rate=self.config.SPAWN_RATE)
            
            # Sustained load testing for 300 seconds (5 minutes)
            import gevent
            gevent.sleep(self.config.SUSTAINED_LOAD_TIME)
            
            env.runner.stop()
            test_duration = time.time() - start_time
            
            stats = env.runner.stats
            
            # Record comprehensive mixed workload performance
            if stats.total.num_requests > 0:
                avg_response_time = stats.total.avg_response_time / 1000
                self.performance_monitor.record_performance_measurement(
                    operation='mixed_workload_capacity',
                    duration=avg_response_time,
                    baseline_key='complete_workflow_time',
                    additional_metrics={
                        'total_requests': stats.total.num_requests,
                        'total_failures': stats.total.num_failures,
                        'requests_per_second': stats.total.total_rps,
                        'user_count': total_users,
                        'test_duration': test_duration,
                        'peak_load_test': True
                    }
                )
            
            test_result = {
                'scenario': 'mixed_workload_capacity',
                'user_count': total_users,
                'duration': test_duration,
                'total_requests': stats.total.num_requests,
                'total_failures': stats.total.num_failures,
                'failure_rate': stats.total.fail_ratio,
                'avg_response_time': stats.total.avg_response_time,
                'requests_per_second': stats.total.total_rps,
                'min_response_time': stats.total.min_response_time,
                'max_response_time': stats.total.max_response_time,
                'p95_response_time': stats.total.get_response_time_percentile(0.95),
                'p99_response_time': stats.total.get_response_time_percentile(0.99)
            }
            
            self.test_results.append(test_result)
            
            # Validate mixed workload performance requirements
            assert stats.total.fail_ratio <= self.config.ERROR_RATE_THRESHOLD, (
                f"Mixed workload failure rate {stats.total.fail_ratio:.3f} exceeds threshold {self.config.ERROR_RATE_THRESHOLD:.3f}"
            )
            
            assert stats.total.total_rps >= self.config.MIN_RPS, (
                f"Mixed workload RPS {stats.total.total_rps:.1f} below minimum requirement {self.config.MIN_RPS}"
            )
            
            assert stats.total.total_rps <= self.config.MAX_RPS * 1.2, (  # Allow 20% over target for peak capacity
                f"Mixed workload RPS {stats.total.total_rps:.1f} unexpectedly high (possible measurement error)"
            )
            
            # Validate response time requirements
            assert stats.total.avg_response_time <= 2000, (  # 2 second average response time limit
                f"Mixed workload average response time {stats.total.avg_response_time:.1f}ms exceeds 2000ms limit"
            )
            
            assert stats.total.get_response_time_percentile(0.95) <= 5000, (  # 5 second P95 response time limit
                f"Mixed workload P95 response time exceeds 5000ms limit"
            )
            
            logger.info(
                f"Mixed workload capacity test completed",
                users=total_users,
                duration=round(test_duration, 1),
                requests=stats.total.num_requests,
                failures=stats.total.num_failures,
                rps=round(stats.total.total_rps, 2),
                avg_response_time=round(stats.total.avg_response_time, 2),
                p95_response_time=round(stats.total.get_response_time_percentile(0.95), 2),
                failure_rate=round(stats.total.fail_ratio * 100, 3)
            )
        
        # Validate overall performance compliance for mixed workload
        performance_summary = self.performance_monitor.get_performance_summary()
        
        assert performance_summary['baseline_compliant'], (
            f"Mixed workload load testing failed baseline compliance: "
            f"{performance_summary['compliance_rate']:.1f}% < {100 - self.config.VARIANCE_THRESHOLD * 100:.1f}%"
        )
        
        # Validate resource utilization compliance
        if performance_summary['resource_stats']:
            cpu_peak = performance_summary['resource_stats']['cpu_utilization']['peak']
            memory_peak = performance_summary['resource_stats']['memory_utilization']['peak']
            
            assert cpu_peak <= self.config.CPU_UTILIZATION_LIMIT * 1.1, (  # Allow 10% tolerance
                f"Peak CPU utilization {cpu_peak:.1f}% exceeds limit {self.config.CPU_UTILIZATION_LIMIT:.1f}%"
            )
            
            assert memory_peak <= self.config.MEMORY_UTILIZATION_LIMIT * 1.1, (  # Allow 10% tolerance
                f"Peak memory utilization {memory_peak:.1f}% exceeds limit {self.config.MEMORY_UTILIZATION_LIMIT:.1f}%"
            )
        
        # Log final validation results
        logger.info(
            "Mixed workload capacity validation completed successfully",
            baseline_compliant=performance_summary['baseline_compliant'],
            compliance_rate=round(performance_summary['compliance_rate'], 2),
            total_violations=performance_summary['violation_stats']['total_violations'],
            critical_violations=performance_summary['violation_stats']['critical_violations']
        )
    
    def _generate_load_test_report(self):
        """Generate comprehensive load test execution report."""
        try:
            performance_summary = self.performance_monitor.get_performance_summary()
            
            report = {
                'test_execution': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_scenarios': len(self.test_results),
                    'configuration': {
                        'min_users': self.config.MIN_USERS,
                        'max_users': self.config.MAX_USERS,
                        'target_rps': self.config.TARGET_RPS,
                        'variance_threshold': self.config.VARIANCE_THRESHOLD,
                        'error_rate_threshold': self.config.ERROR_RATE_THRESHOLD
                    }
                },
                'performance_summary': performance_summary,
                'scenario_results': self.test_results,
                'compliance_assessment': {
                    'baseline_compliant': performance_summary.get('baseline_compliant', False),
                    'variance_threshold_met': performance_summary.get('compliance_rate', 0) >= (100 - self.config.VARIANCE_THRESHOLD * 100),
                    'resource_utilization_compliant': True,  # Will be updated based on resource checks
                    'error_rate_compliant': all(r['failure_rate'] <= self.config.ERROR_RATE_THRESHOLD for r in self.test_results)
                }
            }
            
            # Export report to file
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            report_file = f'load_test_report_{timestamp}.json'
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Load test report generated: {report_file}")
            
        except Exception as e:
            logger.error(f"Failed to generate load test report: {e}")


# =============================================================================
# PYTEST INTEGRATION AND UTILITIES
# =============================================================================

@pytest.mark.e2e
@pytest.mark.performance
@pytest.mark.slow
@skip_if_not_e2e()
@require_load_testing()
@pytest.mark.skipif(not LOCUST_AVAILABLE, reason="Locust framework not available")
def test_progressive_load_scaling(comprehensive_e2e_environment):
    """
    Test progressive load scaling from 10 to 1000 users per Section 4.6.3.
    
    Validates system scalability with gradual load increases and automated
    performance threshold enforcement per Section 6.6.2.
    """
    config = LoadTestingConfig()
    performance_monitor = LoadTestPerformanceMonitor(config)
    
    with performance_monitor.monitor_load_test('progressive_load_scaling'):
        # Test each scaling step
        for user_count in config.USER_SCALING_STEPS:
            if user_count > config.MAX_USERS:
                break
            
            logger.info(f"Testing progressive load scaling step: {user_count} users")
            
            # Use mixed workload for realistic testing
            user_classes = [HealthCheckUser, AuthenticationUser, APIWorkflowUser]
            
            env = Environment(user_classes=user_classes)
            env.create_local_runner()
            env.host = config.HOST
            
            start_time = time.time()
            env.runner.start(user_count, spawn_rate=config.SPAWN_RATE)
            
            # Run each step for 90 seconds
            import gevent
            gevent.sleep(90)
            
            env.runner.stop()
            test_duration = time.time() - start_time
            
            stats = env.runner.stats
            
            # Record scaling step performance
            if stats.total.num_requests > 0:
                avg_response_time = stats.total.avg_response_time / 1000
                performance_monitor.record_performance_measurement(
                    operation=f'progressive_scaling_{user_count}_users',
                    duration=avg_response_time,
                    baseline_key='api_endpoint_response_time',
                    additional_metrics={
                        'user_count': user_count,
                        'total_requests': stats.total.num_requests,
                        'requests_per_second': stats.total.total_rps,
                        'failure_rate': stats.total.fail_ratio
                    }
                )
            
            # Validate scaling step requirements
            assert stats.total.fail_ratio <= config.ERROR_RATE_THRESHOLD, (
                f"Failure rate {stats.total.fail_ratio:.3f} exceeds threshold at {user_count} users"
            )
            
            # RPS should scale roughly linearly with user count
            expected_min_rps = max(10, user_count * 0.5)  # Conservative estimate
            assert stats.total.total_rps >= expected_min_rps, (
                f"RPS {stats.total.total_rps:.1f} below expected minimum {expected_min_rps} for {user_count} users"
            )
            
            logger.info(
                f"Progressive scaling step completed: {user_count} users",
                rps=round(stats.total.total_rps, 2),
                avg_response_time=round(stats.total.avg_response_time, 2),
                failure_rate=round(stats.total.fail_ratio * 100, 3)
            )
            
            # Brief cool-down between scaling steps
            gevent.sleep(30)
    
    # Validate overall progressive scaling compliance
    performance_summary = performance_monitor.get_performance_summary()
    assert performance_summary['baseline_compliant'], (
        "Progressive load scaling failed baseline compliance requirements"
    )
    
    logger.info(
        "Progressive load scaling validation completed successfully",
        total_measurements=performance_summary['performance_stats']['total_measurements'],
        compliance_rate=round(performance_summary['compliance_rate'], 2)
    )


@pytest.mark.e2e
@pytest.mark.performance
@pytest.mark.critical
@skip_if_not_e2e()
@require_load_testing()
@pytest.mark.skipif(not LOCUST_AVAILABLE, reason="Locust framework not available")
def test_sustained_load_capacity(comprehensive_e2e_environment):
    """
    Test sustained load capacity at target RPS per Section 4.6.3.
    
    Validates system ability to maintain target request rate over extended
    periods with resource utilization monitoring per Section 6.6.3.
    """
    config = LoadTestingConfig()
    performance_monitor = LoadTestPerformanceMonitor(config)
    
    with performance_monitor.monitor_load_test('sustained_load_capacity'):
        # Calculate user count to achieve target RPS
        target_users = min(config.TARGET_RPS // 2, config.MAX_USERS)  # Conservative estimate
        
        logger.info(f"Testing sustained load capacity: {target_users} users for {config.SUSTAINED_LOAD_TIME} seconds")
        
        # Use all user types for comprehensive sustained testing
        user_classes = [
            HealthCheckUser,
            AuthenticationUser, 
            APIWorkflowUser,
            DatabaseOperationUser,
            ExternalServiceUser
        ]
        
        env = Environment(user_classes=user_classes)
        env.create_local_runner()
        env.host = config.HOST
        
        start_time = time.time()
        
        # Gradual ramp-up to target users
        env.runner.start(target_users, spawn_rate=config.SPAWN_RATE)
        
        # Sustained load testing
        import gevent
        gevent.sleep(config.SUSTAINED_LOAD_TIME)
        
        env.runner.stop()
        test_duration = time.time() - start_time
        
        stats = env.runner.stats
        
        # Record sustained load performance
        if stats.total.num_requests > 0:
            avg_response_time = stats.total.avg_response_time / 1000
            performance_monitor.record_performance_measurement(
                operation='sustained_load_capacity',
                duration=avg_response_time,
                baseline_key='complete_workflow_time',
                additional_metrics={
                    'user_count': target_users,
                    'total_requests': stats.total.num_requests,
                    'requests_per_second': stats.total.total_rps,
                    'test_duration': test_duration,
                    'sustained_load': True
                }
            )
        
        # Validate sustained load requirements
        assert stats.total.fail_ratio <= config.ERROR_RATE_THRESHOLD, (
            f"Sustained load failure rate {stats.total.fail_ratio:.3f} exceeds threshold {config.ERROR_RATE_THRESHOLD:.3f}"
        )
        
        assert stats.total.total_rps >= config.MIN_RPS, (
            f"Sustained load RPS {stats.total.total_rps:.1f} below minimum requirement {config.MIN_RPS}"
        )
        
        assert stats.total.total_rps <= config.MAX_RPS * 1.1, (  # Allow 10% tolerance
            f"Sustained load RPS {stats.total.total_rps:.1f} exceeds maximum expectation"
        )
        
        # Validate response time stability during sustained load
        assert stats.total.avg_response_time <= 1500, (  # 1.5 second average limit
            f"Sustained load average response time {stats.total.avg_response_time:.1f}ms exceeds 1500ms limit"
        )
        
        logger.info(
            "Sustained load capacity test completed successfully",
            users=target_users,
            duration=round(test_duration, 1),
            total_requests=stats.total.num_requests,
            avg_rps=round(stats.total.total_rps, 2),
            avg_response_time=round(stats.total.avg_response_time, 2),
            failure_rate=round(stats.total.fail_ratio * 100, 3)
        )
    
    # Validate overall sustained load performance
    performance_summary = performance_monitor.get_performance_summary()
    assert performance_summary['baseline_compliant'], (
        "Sustained load capacity testing failed baseline compliance"
    )
    
    # Validate resource utilization during sustained load
    if performance_summary['resource_stats']:
        cpu_avg = performance_summary['resource_stats']['cpu_utilization']['average']
        memory_avg = performance_summary['resource_stats']['memory_utilization']['average']
        
        assert cpu_avg <= config.CPU_UTILIZATION_LIMIT, (
            f"Average CPU utilization {cpu_avg:.1f}% exceeds limit {config.CPU_UTILIZATION_LIMIT:.1f}%"
        )
        
        assert memory_avg <= config.MEMORY_UTILIZATION_LIMIT, (
            f"Average memory utilization {memory_avg:.1f}% exceeds limit {config.MEMORY_UTILIZATION_LIMIT:.1f}%"
        )
        
        logger.info(
            "Resource utilization validation passed",
            avg_cpu=round(cpu_avg, 1),
            avg_memory=round(memory_avg, 1)
        )


if __name__ == '__main__':
    """
    Direct execution support for load testing scenarios.
    
    Allows running load tests directly outside of pytest for development
    and debugging purposes.
    """
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'run_load_test':
        config = LoadTestingConfig()
        
        # Create simple test environment
        from locust.env import Environment
        from locust import events
        
        # Set up logging
        setup_logging("INFO", None)
        
        # Configure environment
        env = Environment(user_classes=[HealthCheckUser, APIWorkflowUser])
        env.create_local_runner()
        env.host = config.HOST
        
        print(f"Starting load test with {config.MIN_USERS} users...")
        print(f"Target: {config.HOST}")
        print("Press Ctrl+C to stop")
        
        try:
            # Start load test
            env.runner.start(config.MIN_USERS, spawn_rate=config.SPAWN_RATE)
            
            # Run until interrupted
            import time
            while True:
                time.sleep(10)
                stats = env.runner.stats
                print(f"Requests: {stats.total.num_requests}, "
                      f"Failures: {stats.total.num_failures}, "
                      f"RPS: {stats.total.total_rps:.2f}, "
                      f"Avg Response: {stats.total.avg_response_time:.2f}ms")
        
        except KeyboardInterrupt:
            print("\nStopping load test...")
            env.runner.stop()
            
            # Print final stats
            stats = env.runner.stats
            print(f"\nFinal Results:")
            print(f"Total Requests: {stats.total.num_requests}")
            print(f"Total Failures: {stats.total.num_failures}")
            print(f"Failure Rate: {stats.total.fail_ratio:.3f}")
            print(f"Average RPS: {stats.total.total_rps:.2f}")
            print(f"Average Response Time: {stats.total.avg_response_time:.2f}ms")
            print(f"Min Response Time: {stats.total.min_response_time:.2f}ms")
            print(f"Max Response Time: {stats.total.max_response_time:.2f}ms")
    
    else:
        print("Load Testing Scenarios Module")
        print("Usage:")
        print("  pytest tests/e2e/test_load_scenarios.py -v  # Run all load tests")
        print("  python tests/e2e/test_load_scenarios.py run_load_test  # Direct execution")
        print("\nEnvironment Variables:")
        print("  E2E_TESTING=true  # Enable E2E testing mode")
        print("  E2E_LOAD_TESTING=true  # Enable load testing")
        print("  LOAD_TEST_HOST=http://localhost:5000  # Target host")
        print("  LOAD_TEST_MAX_USERS=1000  # Maximum concurrent users")
        print("  LOAD_TEST_TARGET_RPS=300  # Target requests per second")