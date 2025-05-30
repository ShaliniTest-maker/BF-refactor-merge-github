"""
End-to-End API Workflow Testing for Flask Application

This module provides comprehensive end-to-end testing of all API endpoints and workflows,
covering complete request/response cycles from authentication through data persistence.
Tests all API endpoints with realistic user scenarios, validates response contracts,
and ensures 100% compatibility with Node.js implementation patterns.

Key Testing Areas:
- Complete authentication workflows from JWT validation through protected resource access
- Multi-endpoint journey testing simulating realistic user interactions
- API transaction flows maintaining identical response formats per F-004-RQ-004
- Error propagation testing across complete request processing pipeline
- Performance validation ensuring ≤10% variance from Node.js baseline
- API contract validation ensuring zero client-side changes per Section 0.1.4

Architecture Compliance:
- F-006-RQ-002: End-to-end testing of all API endpoints and workflows
- Section 0.1.4: Complete preservation of existing API contracts with zero client-side changes
- Section 0.1.1: Authentication workflows preserving JWT token validation patterns
- Section 6.4.2: Authentication flow testing from JWT validation through protected resource access
- Section 4.6.1: Multi-endpoint journey testing simulating realistic user interactions
- Section 4.2.3: Error propagation testing across complete request processing pipeline

Dependencies:
- tests.e2e.conftest: E2E testing infrastructure and fixtures
- tests.conftest: Global testing configuration and utilities
- src.app: Flask application factory for testing
- src.blueprints: API endpoint implementations
- src.auth.decorators: Authentication and authorization decorators

Author: Flask Migration System
Created: 2024
Version: 1.0.0
"""

import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask
from flask.testing import FlaskClient

# Import E2E testing infrastructure
from tests.e2e.conftest import (
    E2ETestConfig,
    PerformanceMetrics,
    E2ETestReporter,
    LocustLoadTester,
    ApacheBenchTester,
    NODEJS_BASELINE_METRICS,
    PERFORMANCE_BASELINE_THRESHOLD
)

# Import global testing utilities
from tests.conftest import *

# Performance and monitoring imports
import structlog

# Configure structured logging for E2E tests
logger = structlog.get_logger(__name__)


class TestCompleteAPIWorkflows:
    """
    Comprehensive end-to-end API workflow testing class implementing complete
    request/response cycle validation from authentication through data persistence.
    
    This test class validates:
    - Complete authentication workflows per Section 6.4.2
    - Multi-endpoint user journey scenarios per Section 4.6.1
    - API contract preservation per Section 0.1.4
    - Performance compliance with ≤10% variance requirement per Section 0.1.1
    - Error propagation patterns per Section 4.2.3
    - Business logic preservation per F-004-RQ-004
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics,
        e2e_test_reporter: E2ETestReporter
    ):
        """
        Automatically setup comprehensive E2E testing environment for each test.
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics collection
            e2e_test_reporter: Test execution reporting
        """
        self.app = e2e_comprehensive_environment['app']
        self.client = e2e_comprehensive_environment['client']
        self.test_data = e2e_comprehensive_environment['test_data']
        self.performance = e2e_comprehensive_environment['performance']
        self.external_services = e2e_comprehensive_environment['external_services']
        self.reporter = e2e_test_reporter
        self.baseline_metrics = e2e_comprehensive_environment['baseline_metrics']
        
        # Store performance monitor for test-specific metrics
        self.performance_monitor = performance_monitor
        
        # Configure test-specific settings
        self.test_session_id = str(uuid.uuid4())
        self.test_start_time = time.time()
        
        logger.info(
            "E2E test environment setup completed",
            test_session_id=self.test_session_id,
            app_config=self.app.config.get('ENV'),
            test_data_users=len(self.test_data.get('users', [])),
            performance_monitoring=bool(self.performance_monitor),
            baseline_metrics_available=bool(self.baseline_metrics)
        )
    
    def _record_request_performance(
        self,
        endpoint: str,
        method: str,
        response_time: float,
        status_code: int,
        success: bool = True
    ) -> None:
        """
        Record request performance metrics for baseline comparison.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            response_time: Response time in milliseconds
            status_code: HTTP status code
            success: Whether request was successful
        """
        self.performance_monitor.add_response_time(response_time)
        
        if not success or status_code >= 400:
            self.performance_monitor.add_error()
        
        logger.debug(
            "Request performance recorded",
            endpoint=endpoint,
            method=method,
            response_time_ms=response_time,
            status_code=status_code,
            success=success
        )
    
    def _make_authenticated_request(
        self,
        method: str,
        endpoint: str,
        token: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[requests.Response, float]:
        """
        Make authenticated HTTP request with performance tracking.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            endpoint: API endpoint path
            token: Authentication token
            data: Request data payload
            headers: Additional HTTP headers
            
        Returns:
            Tuple of (response, response_time_ms)
        """
        # Prepare headers with authentication
        request_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'E2E-Test-Client/1.0'
        }
        
        if headers:
            request_headers.update(headers)
        
        # Prepare request data
        json_data = json.dumps(data) if data else None
        
        # Record start time for performance measurement
        start_time = time.time()
        
        # Make request using Flask test client
        try:
            if method.upper() == 'GET':
                response = self.client.get(endpoint, headers=request_headers)
            elif method.upper() == 'POST':
                response = self.client.post(
                    endpoint, 
                    data=json_data, 
                    headers=request_headers,
                    content_type='application/json'
                )
            elif method.upper() == 'PUT':
                response = self.client.put(
                    endpoint, 
                    data=json_data, 
                    headers=request_headers,
                    content_type='application/json'
                )
            elif method.upper() == 'DELETE':
                response = self.client.delete(endpoint, headers=request_headers)
            elif method.upper() == 'PATCH':
                response = self.client.patch(
                    endpoint, 
                    data=json_data, 
                    headers=request_headers,
                    content_type='application/json'
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Calculate response time
            response_time_ms = (time.time() - start_time) * 1000
            
            # Record performance metrics
            self._record_request_performance(
                endpoint=endpoint,
                method=method,
                response_time=response_time_ms,
                status_code=response.status_code,
                success=response.status_code < 400
            )
            
            return response, response_time_ms
            
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(
                "Request failed with exception",
                endpoint=endpoint,
                method=method,
                error=str(e),
                response_time_ms=response_time_ms
            )
            
            # Record error in performance metrics
            self._record_request_performance(
                endpoint=endpoint,
                method=method,
                response_time=response_time_ms,
                status_code=500,
                success=False
            )
            
            raise
    
    def _validate_response_format(
        self,
        response,
        expected_status: int,
        required_fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Validate response format and extract JSON data with comprehensive validation.
        
        Args:
            response: HTTP response object
            expected_status: Expected HTTP status code
            required_fields: Required fields in response JSON
            
        Returns:
            Parsed JSON response data
            
        Raises:
            AssertionError: If response validation fails
        """
        # Validate status code
        assert response.status_code == expected_status, (
            f"Expected status {expected_status}, got {response.status_code}. "
            f"Response: {response.get_data(as_text=True)}"
        )
        
        # Validate content type for JSON responses
        if expected_status != 204:  # No content expected for 204
            content_type = response.headers.get('Content-Type', '')
            assert 'application/json' in content_type, (
                f"Expected JSON content type, got {content_type}"
            )
        
        # Parse JSON response
        try:
            response_data = response.get_json()
        except Exception as e:
            raise AssertionError(
                f"Failed to parse JSON response: {e}. "
                f"Response data: {response.get_data(as_text=True)}"
            )
        
        # Validate required fields
        if required_fields and response_data:
            missing_fields = [
                field for field in required_fields 
                if field not in response_data
            ]
            assert not missing_fields, (
                f"Missing required fields: {missing_fields}. "
                f"Response: {response_data}"
            )
        
        return response_data
    
    @pytest.mark.e2e
    @pytest.mark.performance
    def test_complete_authentication_workflow(
        self,
        jwt_token: str,
        auth0_mock: Mock
    ):
        """
        Test complete authentication workflow from JWT validation through protected resource access.
        
        Validates:
        - JWT token validation per Section 6.4.2
        - Authentication flow preservation per Section 0.1.1
        - Protected resource access patterns
        - Authentication error handling
        - Performance compliance with baseline
        
        Args:
            jwt_token: Valid JWT token for testing
            auth0_mock: Mocked Auth0 service
        """
        logger.info("Starting complete authentication workflow test")
        
        # Test 1: Authentication without token (should fail)
        start_time = time.time()
        response = self.client.get('/api/v1/users/profile')
        response_time = (time.time() - start_time) * 1000
        
        self._record_request_performance(
            endpoint='/api/v1/users/profile',
            method='GET',
            response_time=response_time,
            status_code=response.status_code,
            success=False
        )
        
        # Validate unauthorized response
        self._validate_response_format(response, 401, ['error'])
        response_data = response.get_json()
        assert 'token' in response_data['error'].lower() or 'authorization' in response_data['error'].lower()
        
        # Test 2: Authentication with invalid token (should fail)
        invalid_headers = {'Authorization': 'Bearer invalid_token_12345'}
        start_time = time.time()
        response = self.client.get('/api/v1/users/profile', headers=invalid_headers)
        response_time = (time.time() - start_time) * 1000
        
        self._record_request_performance(
            endpoint='/api/v1/users/profile',
            method='GET',
            response_time=response_time,
            status_code=response.status_code,
            success=False
        )
        
        self._validate_response_format(response, 401, ['error'])
        
        # Test 3: Successful authentication with valid token
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/users/profile',
            token=jwt_token
        )
        
        # Validate successful authentication response
        user_profile = self._validate_response_format(
            response, 200, ['user_id', 'email']
        )
        
        assert user_profile['user_id'] == 'test_user_123'
        assert user_profile['email'] == 'test@example.com'
        
        # Test 4: Access protected resource with authentication
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/protected-resource',
            token=jwt_token
        )
        
        protected_data = self._validate_response_format(
            response, 200, ['message', 'authenticated']
        )
        
        assert protected_data['authenticated'] is True
        assert 'access granted' in protected_data['message'].lower()
        
        # Validate performance against baseline
        avg_response_time = sum(self.performance_monitor.response_times) / len(self.performance_monitor.response_times)
        baseline_auth_time = self.baseline_metrics['response_times']['user_login']
        
        variance = (avg_response_time - baseline_auth_time) / baseline_auth_time
        assert abs(variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Authentication performance variance {variance:.2%} exceeds threshold "
            f"{PERFORMANCE_BASELINE_THRESHOLD:.2%}"
        )
        
        logger.info(
            "Complete authentication workflow test completed successfully",
            successful_requests=len([t for t in self.performance_monitor.response_times]),
            average_response_time=avg_response_time,
            performance_variance=f"{variance:.2%}",
            baseline_compliance=abs(variance) <= PERFORMANCE_BASELINE_THRESHOLD
        )
    
    @pytest.mark.e2e
    @pytest.mark.performance
    def test_multi_endpoint_user_journey(
        self,
        jwt_token: str,
        seeded_database: Dict[str, List[Dict[str, Any]]],
        auth0_mock: Mock
    ):
        """
        Test realistic multi-endpoint user journey simulating complete user interactions.
        
        Validates:
        - Multi-endpoint journey testing per Section 4.6.1
        - API transaction flows per F-004-RQ-004
        - Data persistence across endpoints
        - Business logic preservation
        - Performance across complete workflow
        
        Args:
            jwt_token: Valid JWT token for authentication
            seeded_database: Pre-populated test database
            auth0_mock: Mocked Auth0 service
        """
        logger.info("Starting multi-endpoint user journey test")
        
        user_journey_start = time.time()
        
        # Journey Step 1: Get user profile
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/users/profile',
            token=jwt_token
        )
        
        user_profile = self._validate_response_format(
            response, 200, ['user_id', 'email', 'name']
        )
        
        user_id = user_profile['user_id']
        logger.debug("Journey step 1 completed", step="get_profile", user_id=user_id)
        
        # Journey Step 2: Create a new project
        project_data = {
            'name': f'E2E Test Project {uuid.uuid4().hex[:8]}',
            'description': 'Project created during E2E testing workflow',
            'category': 'test',
            'tags': ['e2e', 'testing', 'automation'],
            'settings': {
                'visibility': 'private',
                'notifications': True
            }
        }
        
        response, response_time = self._make_authenticated_request(
            method='POST',
            endpoint='/api/v1/projects',
            token=jwt_token,
            data=project_data
        )
        
        created_project = self._validate_response_format(
            response, 201, ['id', 'name', 'description', 'owner_id', 'created_at']
        )
        
        project_id = created_project['id']
        assert created_project['name'] == project_data['name']
        assert created_project['description'] == project_data['description']
        assert created_project['owner_id'] == user_id
        
        logger.debug("Journey step 2 completed", step="create_project", project_id=project_id)
        
        # Journey Step 3: Update project details
        update_data = {
            'description': 'Updated project description during E2E workflow testing',
            'tags': ['e2e', 'testing', 'automation', 'updated'],
            'settings': {
                'visibility': 'public',
                'notifications': False
            }
        }
        
        response, response_time = self._make_authenticated_request(
            method='PUT',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token,
            data=update_data
        )
        
        updated_project = self._validate_response_format(
            response, 200, ['id', 'name', 'description', 'updated_at']
        )
        
        assert updated_project['id'] == project_id
        assert updated_project['description'] == update_data['description']
        assert 'updated' in updated_project['tags']
        
        logger.debug("Journey step 3 completed", step="update_project", project_id=project_id)
        
        # Journey Step 4: List user's projects
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/projects',
            token=jwt_token
        )
        
        projects_list = self._validate_response_format(
            response, 200, ['projects', 'total', 'page']
        )
        
        # Verify created project appears in list
        created_project_in_list = next(
            (p for p in projects_list['projects'] if p['id'] == project_id),
            None
        )
        
        assert created_project_in_list is not None, (
            f"Created project {project_id} not found in projects list"
        )
        
        assert created_project_in_list['description'] == update_data['description']
        
        logger.debug("Journey step 4 completed", step="list_projects", total_projects=projects_list['total'])
        
        # Journey Step 5: Add project collaborator
        collaborator_data = {
            'email': 'collaborator@example.com',
            'role': 'editor',
            'permissions': ['read', 'write']
        }
        
        response, response_time = self._make_authenticated_request(
            method='POST',
            endpoint=f'/api/v1/projects/{project_id}/collaborators',
            token=jwt_token,
            data=collaborator_data
        )
        
        collaboration = self._validate_response_format(
            response, 201, ['project_id', 'collaborator_email', 'role', 'added_at']
        )
        
        assert collaboration['project_id'] == project_id
        assert collaboration['collaborator_email'] == collaborator_data['email']
        assert collaboration['role'] == collaborator_data['role']
        
        logger.debug("Journey step 5 completed", step="add_collaborator", collaborator_email=collaborator_data['email'])
        
        # Journey Step 6: Get project details with collaborators
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        project_details = self._validate_response_format(
            response, 200, ['id', 'name', 'description', 'collaborators']
        )
        
        assert len(project_details['collaborators']) >= 1
        collaborator_emails = [c['email'] for c in project_details['collaborators']]
        assert collaborator_data['email'] in collaborator_emails
        
        logger.debug("Journey step 6 completed", step="get_project_details", collaborators_count=len(project_details['collaborators']))
        
        # Journey Step 7: Search projects
        search_params = {
            'q': 'E2E Test',
            'category': 'test',
            'limit': 10
        }
        
        search_endpoint = '/api/v1/projects/search?' + '&'.join([f'{k}={v}' for k, v in search_params.items()])
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=search_endpoint,
            token=jwt_token
        )
        
        search_results = self._validate_response_format(
            response, 200, ['results', 'total', 'query']
        )
        
        # Verify our project appears in search results
        found_project = next(
            (p for p in search_results['results'] if p['id'] == project_id),
            None
        )
        
        assert found_project is not None, "Created project not found in search results"
        
        logger.debug("Journey step 7 completed", step="search_projects", results_count=len(search_results['results']))
        
        # Journey Step 8: Delete project (cleanup)
        response, response_time = self._make_authenticated_request(
            method='DELETE',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        # Validate deletion response (204 No Content or 200 with confirmation)
        if response.status_code == 204:
            # No content response
            assert len(response.get_data()) == 0
        else:
            deletion_response = self._validate_response_format(
                response, 200, ['message']
            )
            assert 'deleted' in deletion_response['message'].lower()
        
        logger.debug("Journey step 8 completed", step="delete_project", project_id=project_id)
        
        # Journey Step 9: Verify project is deleted
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        # Should return 404 Not Found
        self._validate_response_format(response, 404, ['error'])
        
        # Calculate total journey performance
        total_journey_time = time.time() - user_journey_start
        avg_response_time = sum(self.performance_monitor.response_times) / len(self.performance_monitor.response_times)
        
        # Performance validation against baseline
        baseline_avg = self.baseline_metrics['response_times']['api_endpoint_avg']
        variance = (avg_response_time - baseline_avg) / baseline_avg
        
        assert abs(variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Multi-endpoint journey performance variance {variance:.2%} exceeds "
            f"threshold {PERFORMANCE_BASELINE_THRESHOLD:.2%}"
        )
        
        logger.info(
            "Multi-endpoint user journey test completed successfully",
            total_journey_time_seconds=total_journey_time,
            total_requests=len(self.performance_monitor.response_times),
            average_response_time_ms=avg_response_time,
            performance_variance=f"{variance:.2%}",
            baseline_compliance=abs(variance) <= PERFORMANCE_BASELINE_THRESHOLD,
            journey_steps_completed=9
        )
    
    @pytest.mark.e2e
    def test_comprehensive_error_propagation(
        self,
        jwt_token: str,
        e2e_external_services: Dict[str, Any]
    ):
        """
        Test error propagation across complete request processing pipeline.
        
        Validates:
        - Error propagation testing per Section 4.2.3
        - Consistent error response formats per F-005-RQ-001
        - HTTP status code accuracy per F-005-RQ-002
        - Error handling preservation from Node.js implementation
        - Graceful degradation patterns
        
        Args:
            jwt_token: Valid JWT token for authentication
            e2e_external_services: Mocked external services
        """
        logger.info("Starting comprehensive error propagation test")
        
        # Test 1: Authentication errors
        invalid_token_response = self.client.get(
            '/api/v1/users/profile',
            headers={'Authorization': 'Bearer invalid_token'}
        )
        
        auth_error = self._validate_response_format(invalid_token_response, 401, ['error'])
        assert 'invalid' in auth_error['error'].lower() or 'token' in auth_error['error'].lower()
        
        # Test 2: Authorization errors (access denied)
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/admin/users',  # Admin-only endpoint
            token=jwt_token  # Regular user token
        )
        
        if response.status_code == 403:  # Expected authorization failure
            auth_error = self._validate_response_format(response, 403, ['error'])
            assert 'permission' in auth_error['error'].lower() or 'forbidden' in auth_error['error'].lower()
        
        # Test 3: Validation errors (malformed data)
        invalid_project_data = {
            'name': '',  # Empty name should fail validation
            'description': 'A' * 2000,  # Too long description
            'category': 'invalid_category',  # Invalid category
            'tags': 'not_an_array',  # Tags should be array
        }
        
        response, response_time = self._make_authenticated_request(
            method='POST',
            endpoint='/api/v1/projects',
            token=jwt_token,
            data=invalid_project_data
        )
        
        validation_error = self._validate_response_format(response, 400, ['error'])
        assert 'validation' in validation_error['error'].lower() or 'invalid' in validation_error['error'].lower()
        
        # Verify detailed validation errors if provided
        if 'details' in validation_error:
            details = validation_error['details']
            assert isinstance(details, (dict, list)), "Validation details should be structured"
        
        # Test 4: Resource not found errors
        non_existent_id = str(uuid.uuid4())
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=f'/api/v1/projects/{non_existent_id}',
            token=jwt_token
        )
        
        not_found_error = self._validate_response_format(response, 404, ['error'])
        assert 'not found' in not_found_error['error'].lower() or 'does not exist' in not_found_error['error'].lower()
        
        # Test 5: Method not allowed errors
        response, response_time = self._make_authenticated_request(
            method='PATCH',
            endpoint='/api/v1/users/profile',  # Assuming PATCH not supported
            token=jwt_token,
            data={'test': 'data'}
        )
        
        # Method not allowed might return 405 or 404 depending on implementation
        if response.status_code == 405:
            method_error = self._validate_response_format(response, 405, ['error'])
            assert 'method' in method_error['error'].lower() or 'not allowed' in method_error['error'].lower()
        
        # Test 6: External service errors (simulate database failure)
        with patch('pymongo.MongoClient') as mock_mongo:
            mock_mongo.side_effect = Exception("Database connection failed")
            
            response, response_time = self._make_authenticated_request(
                method='GET',
                endpoint='/api/v1/projects',
                token=jwt_token
            )
            
            # Should return 500 Internal Server Error
            server_error = self._validate_response_format(response, 500, ['error'])
            assert 'server error' in server_error['error'].lower() or 'unavailable' in server_error['error'].lower()
            
            # Verify no sensitive information is exposed
            error_message = server_error['error']
            sensitive_terms = ['connection', 'database', 'pymongo', 'exception']
            exposed_terms = [term for term in sensitive_terms if term.lower() in error_message.lower()]
            assert len(exposed_terms) == 0, f"Sensitive information exposed in error: {exposed_terms}"
        
        # Test 7: Rate limiting errors (if implemented)
        # Make multiple rapid requests to trigger rate limiting
        rapid_requests = []
        for i in range(20):  # Exceed typical rate limits
            response = self.client.get(
                '/api/v1/users/profile',
                headers={'Authorization': f'Bearer {jwt_token}'}
            )
            rapid_requests.append(response)
            
            if response.status_code == 429:  # Rate limited
                rate_limit_error = self._validate_response_format(response, 429, ['error'])
                assert 'rate limit' in rate_limit_error['error'].lower() or 'too many' in rate_limit_error['error'].lower()
                
                # Check for retry-after header
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    assert retry_after.isdigit(), "Retry-After header should be numeric"
                
                break
        
        # Test 8: Content type errors
        response = self.client.post(
            '/api/v1/projects',
            data='invalid json content',
            headers={
                'Authorization': f'Bearer {jwt_token}',
                'Content-Type': 'application/json'
            }
        )
        
        if response.status_code == 400:  # JSON parsing error
            json_error = self._validate_response_format(response, 400, ['error'])
            assert 'json' in json_error['error'].lower() or 'format' in json_error['error'].lower()
        
        logger.info(
            "Comprehensive error propagation test completed successfully",
            error_scenarios_tested=8,
            authentication_errors=1,
            authorization_errors=1,
            validation_errors=1,
            not_found_errors=1,
            server_errors=1,
            error_format_consistency=True
        )
    
    @pytest.mark.e2e
    @pytest.mark.performance
    def test_api_contract_validation(
        self,
        jwt_token: str,
        apache_bench_tester: Optional[ApacheBenchTester]
    ):
        """
        Test API contract validation ensuring zero client-side changes per Section 0.1.4.
        
        Validates:
        - API contract preservation per Section 0.1.4
        - Response format consistency per F-004-RQ-004
        - HTTP method support per F-002-RQ-001
        - Content type handling per F-002-RQ-004
        - Performance baselines per Section 0.1.1
        
        Args:
            jwt_token: Valid JWT token for authentication
            apache_bench_tester: Apache Bench performance tester
        """
        logger.info("Starting API contract validation test")
        
        # Define expected API contracts for key endpoints
        api_contracts = {
            '/api/v1/users/profile': {
                'methods': ['GET'],
                'auth_required': True,
                'response_fields': ['user_id', 'email', 'name'],
                'content_type': 'application/json'
            },
            '/api/v1/projects': {
                'methods': ['GET', 'POST'],
                'auth_required': True,
                'response_fields': {
                    'GET': ['projects', 'total', 'page'],
                    'POST': ['id', 'name', 'description', 'owner_id', 'created_at']
                },
                'content_type': 'application/json'
            },
            '/api/v1/health': {
                'methods': ['GET'],
                'auth_required': False,
                'response_fields': ['status'],
                'content_type': 'application/json'
            }
        }
        
        contract_validation_results = []
        
        for endpoint, contract in api_contracts.items():
            logger.debug(f"Validating contract for {endpoint}")
            
            for method in contract['methods']:
                # Prepare request based on authentication requirement
                if contract['auth_required']:
                    response, response_time = self._make_authenticated_request(
                        method=method,
                        endpoint=endpoint,
                        token=jwt_token,
                        data={'name': 'Test Project', 'description': 'Test'} if method == 'POST' else None
                    )
                else:
                    # Make unauthenticated request
                    start_time = time.time()
                    if method == 'GET':
                        response = self.client.get(endpoint)
                    elif method == 'POST':
                        response = self.client.post(
                            endpoint,
                            json={'name': 'Test Project', 'description': 'Test'},
                            headers={'Content-Type': 'application/json'}
                        )
                    response_time = (time.time() - start_time) * 1000
                
                # Validate response contract
                expected_status = 200 if method == 'GET' else (201 if method == 'POST' else 200)
                
                # Handle different expected statuses for different scenarios
                if response.status_code in [200, 201]:
                    response_data = self._validate_response_format(
                        response, 
                        response.status_code,
                        contract['response_fields'][method] if isinstance(contract['response_fields'], dict) else contract['response_fields']
                    )
                    
                    # Validate content type
                    content_type = response.headers.get('Content-Type', '')
                    assert contract['content_type'] in content_type, (
                        f"Expected content type {contract['content_type']}, got {content_type}"
                    )
                    
                    contract_validation_results.append({
                        'endpoint': endpoint,
                        'method': method,
                        'status': 'valid',
                        'response_time': response_time,
                        'fields_present': all(
                            field in response_data 
                            for field in (contract['response_fields'][method] if isinstance(contract['response_fields'], dict) else contract['response_fields'])
                        )
                    })
                    
                    logger.debug(
                        f"Contract validation passed for {method} {endpoint}",
                        response_time=response_time,
                        status_code=response.status_code
                    )
                
                else:
                    # Handle error responses
                    contract_validation_results.append({
                        'endpoint': endpoint,
                        'method': method,
                        'status': 'error',
                        'response_time': response_time,
                        'status_code': response.status_code
                    })
        
        # Performance validation using Apache Bench if available
        if apache_bench_tester and apache_bench_tester.available:
            logger.info("Running Apache Bench performance validation")
            
            # Test key endpoints for performance
            performance_endpoints = ['/api/v1/health', '/api/v1/users/profile']
            
            for endpoint in performance_endpoints:
                headers = {}
                if 'users' in endpoint:  # Requires authentication
                    headers['Authorization'] = f'Bearer {jwt_token}'
                
                bench_results = apache_bench_tester.run_benchmark(
                    endpoint=endpoint,
                    requests=100,
                    concurrency=5,
                    headers=headers
                )
                
                if 'error' not in bench_results:
                    # Compare with baseline
                    baseline_comparison = apache_bench_tester.compare_with_baseline(
                        bench_results, 
                        self.baseline_metrics
                    )
                    
                    assert baseline_comparison['compliance_status'], (
                        f"Performance baseline not met for {endpoint}: "
                        f"Response time variance: {baseline_comparison['response_time_variance_percent']:.2f}%, "
                        f"Throughput variance: {baseline_comparison['throughput_variance_percent']:.2f}%"
                    )
                    
                    logger.info(
                        f"Apache Bench validation passed for {endpoint}",
                        mean_response_time=bench_results['mean_response_time_ms'],
                        requests_per_second=bench_results['requests_per_second'],
                        success_rate=bench_results.get('success_rate', 1.0),
                        compliance=baseline_comparison['compliance_status']
                    )
        
        # Validate overall contract compliance
        valid_contracts = [r for r in contract_validation_results if r['status'] == 'valid']
        contract_compliance_rate = len(valid_contracts) / len(contract_validation_results)
        
        assert contract_compliance_rate >= 0.95, (
            f"API contract compliance rate {contract_compliance_rate:.2%} below 95% threshold"
        )
        
        # Validate response time consistency
        response_times = [r['response_time'] for r in valid_contracts]
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            baseline_avg = self.baseline_metrics['response_times']['api_endpoint_avg']
            
            variance = (avg_response_time - baseline_avg) / baseline_avg
            assert abs(variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
                f"API contract performance variance {variance:.2%} exceeds threshold"
            )
        
        logger.info(
            "API contract validation test completed successfully",
            total_contracts_tested=len(contract_validation_results),
            valid_contracts=len(valid_contracts),
            compliance_rate=f"{contract_compliance_rate:.2%}",
            average_response_time=avg_response_time if response_times else 0,
            performance_variance=f"{variance:.2%}" if response_times else "N/A",
            apache_bench_available=apache_bench_tester.available if apache_bench_tester else False
        )
    
    @pytest.mark.e2e
    @pytest.mark.load_test
    @pytest.mark.performance
    def test_concurrent_user_workflows(
        self,
        jwt_token: str,
        locust_load_tester: Optional[LocustLoadTester],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test concurrent user workflows for load testing and performance validation.
        
        Validates:
        - Concurrent request handling capacity
        - System stability under load
        - Performance degradation patterns
        - Resource utilization efficiency
        - Error rate under load conditions
        
        Args:
            jwt_token: Valid JWT token for authentication
            locust_load_tester: Locust load testing framework
            performance_monitor: Performance metrics collection
        """
        logger.info("Starting concurrent user workflows test")
        
        if not locust_load_tester:
            pytest.skip("Locust load tester not available")
        
        # Configure load test parameters
        concurrent_users = 10  # Start with moderate load
        test_duration = 30  # 30 seconds test duration
        spawn_rate = 2.0  # 2 users per second spawn rate
        
        logger.info(
            "Configuring load test",
            concurrent_users=concurrent_users,
            duration_seconds=test_duration,
            spawn_rate=spawn_rate
        )
        
        # Execute load test
        load_test_results = locust_load_tester.run_load_test(
            users=concurrent_users,
            spawn_rate=spawn_rate,
            duration=test_duration
        )
        
        # Validate load test results
        assert 'total_requests' in load_test_results, "Load test results missing request count"
        assert load_test_results['total_requests'] > 0, "No requests were made during load test"
        
        total_requests = load_test_results['total_requests']
        total_failures = load_test_results.get('total_failures', 0)
        failure_rate = load_test_results.get('failure_rate', 0)
        avg_response_time = load_test_results.get('average_response_time', 0)
        requests_per_second = load_test_results.get('requests_per_second', 0)
        
        # Performance validation thresholds
        max_failure_rate = 0.05  # 5% maximum failure rate
        max_response_time = self.baseline_metrics['response_times']['api_endpoint_avg'] * 2  # 2x baseline
        min_throughput = self.baseline_metrics['throughput']['requests_per_second'] * 0.8  # 80% of baseline
        
        # Validate failure rate
        assert failure_rate <= max_failure_rate, (
            f"Failure rate {failure_rate:.2%} exceeds maximum threshold {max_failure_rate:.2%}"
        )
        
        # Validate response time
        assert avg_response_time <= max_response_time, (
            f"Average response time {avg_response_time:.2f}ms exceeds maximum {max_response_time:.2f}ms"
        )
        
        # Validate throughput
        assert requests_per_second >= min_throughput, (
            f"Throughput {requests_per_second:.2f} RPS below minimum {min_throughput:.2f} RPS"
        )
        
        # Analyze endpoint-specific performance
        endpoint_stats = load_test_results.get('endpoint_statistics', {})
        critical_endpoints = ['/api/v1/users/profile', '/api/v1/projects', '/health']
        
        for endpoint in critical_endpoints:
            if endpoint in endpoint_stats:
                endpoint_data = endpoint_stats[endpoint]
                endpoint_failure_rate = endpoint_data['failures'] / max(endpoint_data['requests'], 1)
                
                assert endpoint_failure_rate <= max_failure_rate, (
                    f"Endpoint {endpoint} failure rate {endpoint_failure_rate:.2%} exceeds threshold"
                )
                
                logger.debug(
                    f"Endpoint performance validation passed",
                    endpoint=endpoint,
                    requests=endpoint_data['requests'],
                    failures=endpoint_data['failures'],
                    avg_response_time=endpoint_data['avg_response_time'],
                    rps=endpoint_data['requests_per_second']
                )
        
        # Performance comparison with baseline
        baseline_rps = self.baseline_metrics['throughput']['requests_per_second']
        baseline_response_time = self.baseline_metrics['response_times']['api_endpoint_avg']
        
        throughput_variance = (requests_per_second - baseline_rps) / baseline_rps
        response_time_variance = (avg_response_time - baseline_response_time) / baseline_response_time
        
        # Log performance comparison
        logger.info(
            "Load test performance comparison",
            measured_rps=requests_per_second,
            baseline_rps=baseline_rps,
            throughput_variance=f"{throughput_variance:.2%}",
            measured_response_time=avg_response_time,
            baseline_response_time=baseline_response_time,
            response_time_variance=f"{response_time_variance:.2%}",
            total_requests=total_requests,
            failure_rate=f"{failure_rate:.2%}"
        )
        
        # Validate compliance with performance requirements
        performance_compliant = (
            abs(throughput_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            abs(response_time_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            failure_rate <= max_failure_rate
        )
        
        assert performance_compliant, (
            f"Load test performance not compliant: "
            f"Throughput variance: {throughput_variance:.2%}, "
            f"Response time variance: {response_time_variance:.2%}, "
            f"Failure rate: {failure_rate:.2%}"
        )
        
        logger.info(
            "Concurrent user workflows test completed successfully",
            concurrent_users=concurrent_users,
            test_duration=test_duration,
            total_requests=total_requests,
            requests_per_second=requests_per_second,
            average_response_time=avg_response_time,
            failure_rate=f"{failure_rate:.2%}",
            performance_compliant=performance_compliant,
            throughput_variance=f"{throughput_variance:.2%}",
            response_time_variance=f"{response_time_variance:.2%}"
        )
    
    @pytest.mark.e2e
    def test_database_integration_workflows(
        self,
        jwt_token: str,
        mongodb_client,
        redis_client
    ):
        """
        Test complete database integration workflows across create, read, update, delete operations.
        
        Validates:
        - Database connectivity and operations
        - Data persistence across requests
        - Transaction consistency
        - Cache integration patterns
        - Database error handling
        
        Args:
            jwt_token: Valid JWT token for authentication
            mongodb_client: MongoDB client for database operations
            redis_client: Redis client for cache operations
        """
        logger.info("Starting database integration workflows test")
        
        # Test 1: Create data with database persistence
        project_data = {
            'name': f'DB Integration Test {uuid.uuid4().hex[:8]}',
            'description': 'Testing database integration workflows',
            'category': 'integration_test',
            'metadata': {
                'test_type': 'database_integration',
                'created_by': 'e2e_test_suite',
                'timestamp': datetime.now().isoformat()
            }
        }
        
        response, response_time = self._make_authenticated_request(
            method='POST',
            endpoint='/api/v1/projects',
            token=jwt_token,
            data=project_data
        )
        
        created_project = self._validate_response_format(
            response, 201, ['id', 'name', 'description', 'created_at']
        )
        
        project_id = created_project['id']
        
        # Verify data exists in database directly
        db = mongodb_client.get_database('test_database')
        projects_collection = db.projects
        
        db_project = projects_collection.find_one({'_id': project_id})
        assert db_project is not None, f"Project {project_id} not found in database"
        assert db_project['name'] == project_data['name']
        assert db_project['description'] == project_data['description']
        
        logger.debug("Database create operation validated", project_id=project_id)
        
        # Test 2: Read data from database
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        retrieved_project = self._validate_response_format(
            response, 200, ['id', 'name', 'description']
        )
        
        assert retrieved_project['id'] == project_id
        assert retrieved_project['name'] == project_data['name']
        assert retrieved_project['description'] == project_data['description']
        
        logger.debug("Database read operation validated", project_id=project_id)
        
        # Test 3: Update data with cache invalidation
        update_data = {
            'description': 'Updated description for database integration testing',
            'metadata': {
                'test_type': 'database_integration',
                'updated_by': 'e2e_test_suite',
                'update_timestamp': datetime.now().isoformat()
            }
        }
        
        response, response_time = self._make_authenticated_request(
            method='PUT',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token,
            data=update_data
        )
        
        updated_project = self._validate_response_format(
            response, 200, ['id', 'description', 'updated_at']
        )
        
        assert updated_project['description'] == update_data['description']
        
        # Verify update in database
        db_project_updated = projects_collection.find_one({'_id': project_id})
        assert db_project_updated['description'] == update_data['description']
        assert 'updated_at' in db_project_updated
        
        logger.debug("Database update operation validated", project_id=project_id)
        
        # Test 4: Cache integration (if cache key patterns are predictable)
        cache_key = f"project:{project_id}"
        
        # Check if project is cached
        cached_data = redis_client.get(cache_key)
        if cached_data:
            # Verify cached data consistency
            cached_project = json.loads(cached_data)
            assert cached_project['id'] == project_id
            assert cached_project['description'] == update_data['description']
            
            logger.debug("Cache consistency validated", cache_key=cache_key)
        
        # Test 5: List operations with database queries
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint='/api/v1/projects?category=integration_test',
            token=jwt_token
        )
        
        projects_list = self._validate_response_format(
            response, 200, ['projects', 'total']
        )
        
        # Verify our test project appears in filtered list
        test_projects = [
            p for p in projects_list['projects'] 
            if p.get('category') == 'integration_test'
        ]
        
        assert len(test_projects) >= 1, "Test project not found in filtered list"
        
        test_project_in_list = next(
            (p for p in test_projects if p['id'] == project_id),
            None
        )
        
        assert test_project_in_list is not None, "Test project not found in list results"
        
        logger.debug("Database query operation validated", filtered_projects=len(test_projects))
        
        # Test 6: Transaction consistency (if supported)
        # Try to create multiple related records in a transaction-like manner
        batch_data = {
            'projects': [
                {
                    'name': f'Batch Project 1 {uuid.uuid4().hex[:6]}',
                    'description': 'Batch creation test 1',
                    'category': 'batch_test'
                },
                {
                    'name': f'Batch Project 2 {uuid.uuid4().hex[:6]}',
                    'description': 'Batch creation test 2',
                    'category': 'batch_test'
                }
            ]
        }
        
        response, response_time = self._make_authenticated_request(
            method='POST',
            endpoint='/api/v1/projects/batch',
            token=jwt_token,
            data=batch_data
        )
        
        # Handle both success and not-implemented scenarios
        if response.status_code == 201:
            batch_result = self._validate_response_format(
                response, 201, ['created_projects']
            )
            
            created_ids = [p['id'] for p in batch_result['created_projects']]
            assert len(created_ids) == 2, "Batch creation should create 2 projects"
            
            # Verify all projects exist in database
            for project_id_batch in created_ids:
                db_batch_project = projects_collection.find_one({'_id': project_id_batch})
                assert db_batch_project is not None, f"Batch project {project_id_batch} not in database"
            
            logger.debug("Batch transaction validated", created_projects=len(created_ids))
        
        elif response.status_code == 404:
            # Batch endpoint not implemented - skip transaction test
            logger.debug("Batch endpoint not implemented - skipping transaction test")
        
        # Test 7: Delete operation with cleanup
        response, response_time = self._make_authenticated_request(
            method='DELETE',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        # Validate deletion response
        if response.status_code in [200, 204]:
            # Verify deletion from database
            deleted_project = projects_collection.find_one({'_id': project_id})
            
            # Project should be either deleted or marked as deleted
            if deleted_project is not None:
                # Check if soft delete is used
                assert deleted_project.get('deleted', False) is True or deleted_project.get('status') == 'deleted'
            
            # Verify cache cleanup
            cached_data_after_delete = redis_client.get(cache_key)
            assert cached_data_after_delete is None, "Cache should be cleared after deletion"
            
            logger.debug("Database delete operation validated", project_id=project_id)
        
        # Test 8: Database error handling
        # Try to access deleted project
        response, response_time = self._make_authenticated_request(
            method='GET',
            endpoint=f'/api/v1/projects/{project_id}',
            token=jwt_token
        )
        
        self._validate_response_format(response, 404, ['error'])
        
        logger.info(
            "Database integration workflows test completed successfully",
            operations_tested=['create', 'read', 'update', 'list', 'delete'],
            database_consistency_validated=True,
            cache_integration_validated=True,
            transaction_patterns_tested=True,
            error_handling_validated=True
        )
    
    def teardown_method(self):
        """
        Clean up after each test method execution.
        
        Performs:
        - Performance metrics finalization
        - Test result reporting
        - Resource cleanup
        - Baseline compliance validation
        """
        if hasattr(self, 'performance_monitor'):
            # Finalize performance monitoring
            self.performance_monitor.end_time = time.time()
            
            # Validate performance compliance
            if self.performance_monitor.response_times:
                compliance = self.performance_monitor.validate_against_baseline(
                    self.baseline_metrics
                )
                
                logger.info(
                    "Test performance summary",
                    test_session_id=self.test_session_id,
                    total_requests=self.performance_monitor.request_count,
                    total_errors=self.performance_monitor.error_count,
                    baseline_compliance=compliance,
                    variance_analysis=self.performance_monitor.variance_analysis
                )
        
        # Additional cleanup if needed
        if hasattr(self, 'test_start_time'):
            total_test_time = time.time() - self.test_start_time
            logger.debug(
                "Test execution completed",
                test_session_id=self.test_session_id,
                total_execution_time=total_test_time
            )


class TestSpecificEndpointWorkflows:
    """
    Specific endpoint workflow testing for critical business operations.
    
    This class focuses on testing specific business workflows that are
    critical for application functionality and user experience.
    """
    
    @pytest.fixture(autouse=True)
    def setup_endpoint_test_environment(
        self,
        e2e_app: Flask,
        e2e_client: FlaskClient,
        jwt_token: str,
        performance_monitor: PerformanceMetrics
    ):
        """Setup for endpoint-specific testing."""
        self.app = e2e_app
        self.client = e2e_client
        self.jwt_token = jwt_token
        self.performance_monitor = performance_monitor
    
    @pytest.mark.e2e
    def test_user_management_workflow(self):
        """
        Test complete user management workflow including registration, profile updates, and deletion.
        """
        logger.info("Starting user management workflow test")
        
        # User registration workflow
        registration_data = {
            'email': f'test_user_{uuid.uuid4().hex[:8]}@example.com',
            'password': 'SecurePassword123!',
            'name': 'Test User Registration',
            'preferences': {
                'notifications': True,
                'theme': 'light'
            }
        }
        
        # Test user registration
        response = self.client.post(
            '/api/v1/auth/register',
            json=registration_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 201:
            registration_result = response.get_json()
            assert 'user_id' in registration_result
            assert 'access_token' in registration_result
            
            new_user_id = registration_result['user_id']
            new_user_token = registration_result['access_token']
            
            # Test profile retrieval
            profile_response = self.client.get(
                '/api/v1/users/profile',
                headers={'Authorization': f'Bearer {new_user_token}'}
            )
            
            assert profile_response.status_code == 200
            profile_data = profile_response.get_json()
            assert profile_data['email'] == registration_data['email']
            assert profile_data['name'] == registration_data['name']
            
            # Test profile update
            update_data = {
                'name': 'Updated Test User Name',
                'preferences': {
                    'notifications': False,
                    'theme': 'dark'
                }
            }
            
            update_response = self.client.put(
                '/api/v1/users/profile',
                json=update_data,
                headers={
                    'Authorization': f'Bearer {new_user_token}',
                    'Content-Type': 'application/json'
                }
            )
            
            if update_response.status_code == 200:
                updated_profile = update_response.get_json()
                assert updated_profile['name'] == update_data['name']
            
            logger.info(
                "User management workflow completed successfully",
                user_id=new_user_id,
                registration_successful=True,
                profile_update_successful=update_response.status_code == 200
            )
        
        else:
            # Registration might not be implemented or might require different flow
            logger.info("User registration endpoint not available or requires different implementation")
            pytest.skip("User registration workflow not available")
    
    @pytest.mark.e2e
    def test_health_check_workflow(self):
        """
        Test comprehensive health check workflow including all health endpoints.
        """
        logger.info("Starting health check workflow test")
        
        # Test basic health check
        health_response = self.client.get('/health')
        assert health_response.status_code == 200
        
        health_data = health_response.get_json()
        assert health_data['status'] in ['healthy', 'ok']
        
        # Test readiness check
        readiness_response = self.client.get('/health/ready')
        if readiness_response.status_code == 200:
            readiness_data = readiness_response.get_json()
            assert 'status' in readiness_data
            assert 'checks' in readiness_data
        
        # Test liveness check
        liveness_response = self.client.get('/health/live')
        if liveness_response.status_code == 200:
            liveness_data = liveness_response.get_json()
            assert 'status' in liveness_data
        
        logger.info(
            "Health check workflow completed successfully",
            basic_health=health_response.status_code == 200,
            readiness_check=readiness_response.status_code == 200,
            liveness_check=liveness_response.status_code == 200
        )


@pytest.mark.e2e
@pytest.mark.integration
class TestCrossServiceIntegration:
    """
    Cross-service integration testing for external service dependencies.
    
    Tests integration patterns with external services while maintaining
    API contract compatibility and performance requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_integration_environment(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        e2e_external_services: Dict[str, Any]
    ):
        """Setup for cross-service integration testing."""
        self.app = e2e_comprehensive_environment['app']
        self.client = e2e_comprehensive_environment['client']
        self.external_services = e2e_external_services
    
    @pytest.mark.e2e
    def test_auth0_integration_workflow(self, jwt_token: str):
        """
        Test Auth0 integration workflow for authentication and user management.
        """
        logger.info("Starting Auth0 integration workflow test")
        
        # Test JWT token validation through Auth0 integration
        auth_response = self.client.get(
            '/api/v1/auth/validate',
            headers={'Authorization': f'Bearer {jwt_token}'}
        )
        
        if auth_response.status_code == 200:
            auth_data = auth_response.get_json()
            assert 'valid' in auth_data
            assert auth_data['valid'] is True
            
            # Test user info retrieval through Auth0
            userinfo_response = self.client.get(
                '/api/v1/auth/userinfo',
                headers={'Authorization': f'Bearer {jwt_token}'}
            )
            
            if userinfo_response.status_code == 200:
                userinfo_data = userinfo_response.get_json()
                assert 'sub' in userinfo_data
                assert 'email' in userinfo_data
        
        logger.info("Auth0 integration workflow test completed")
    
    @pytest.mark.e2e
    def test_aws_service_integration(self, jwt_token: str):
        """
        Test AWS service integration including S3 operations.
        """
        logger.info("Starting AWS service integration test")
        
        # Test file upload to S3 (mocked)
        file_data = {
            'filename': 'test_file.txt',
            'content_type': 'text/plain',
            'size': 1024
        }
        
        upload_response = self.client.post(
            '/api/v1/files/upload',
            json=file_data,
            headers={
                'Authorization': f'Bearer {jwt_token}',
                'Content-Type': 'application/json'
            }
        )
        
        if upload_response.status_code in [200, 201]:
            upload_result = upload_response.get_json()
            assert 'file_id' in upload_result
            assert 'upload_url' in upload_result
            
            file_id = upload_result['file_id']
            
            # Test file retrieval
            download_response = self.client.get(
                f'/api/v1/files/{file_id}',
                headers={'Authorization': f'Bearer {jwt_token}'}
            )
            
            if download_response.status_code == 200:
                download_data = download_response.get_json()
                assert 'download_url' in download_data
        
        logger.info("AWS service integration test completed")


# Performance testing marker for CI/CD integration
pytestmark = [pytest.mark.e2e, pytest.mark.performance]