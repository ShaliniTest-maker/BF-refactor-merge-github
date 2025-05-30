"""
End-to-End User Journey Testing for Flask Application

This module provides comprehensive end-to-end testing of complete user workflows from 
authentication through complex business operations, ensuring functional equivalence with
Node.js implementation and ≤10% performance variance per Section 0.1.1.

Test Coverage:
- Authentication Workflows: Complete user authentication journey from login through secured 
  resource access per Section 4.6.1 and Section 6.4.2
- API Transaction Flows: Multi-step API operations involving authentication, validation, 
  business logic, and data persistence per Section 4.6.1 and Section 6.6.5
- Business Rule Validation: Complete business rule enforcement within user workflow contexts 
  per F-004-RQ-001 and Section 4.6.5
- Error Propagation Testing: Complete error handling validation from detection through 
  user-facing error responses per Section 4.6.6
- Session Management: Cross-request session handling and state management per Section 6.4.1
- Performance Validation: Response time and throughput comparison with Node.js baseline 
  per Section 0.1.1

Architecture Validation:
- Flask Blueprint integration and modular route organization per Section 6.1.1
- PyMongo/Motor database operations with connection pooling per Section 6.2.4
- Redis session management and caching performance per Section 6.4.1
- Auth0 authentication and JWT token validation per Section 6.4.2
- External service integration and circuit breaker patterns per Section 6.1.3
- Business logic processing with transaction management per Section 5.2.4

Test Environment:
- Testcontainers MongoDB and Redis for production-equivalent behavior per Section 6.6.1
- Auth0 service mocking for authentication isolation per Section 6.6.1
- Locust load testing integration for throughput validation per Section 6.6.1
- Apache Bench performance measurement for response time validation per Section 6.6.1
- Comprehensive error injection and recovery testing per Section 4.6.6

Author: Flask Migration Testing Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch

import pytest
import pytest_asyncio
from flask import Flask
from flask.testing import FlaskClient
import requests

# Import E2E testing infrastructure
from tests.e2e.conftest import (
    E2ETestConfig,
    PerformanceMetrics,
    LocustLoadTester,
    ApacheBenchTester,
    E2ETestReporter,
    NODEJS_BASELINE_METRICS,
    PERFORMANCE_BASELINE_THRESHOLD
)

# Import testing fixtures and utilities
from tests.conftest import (
    mongodb_client,
    redis_client,
    auth0_mock,
    jwt_token,
    performance_baseline
)

# Configure structured logging for user journey tests
logger = logging.getLogger(__name__)

# Test constants for user journey scenarios
TEST_USER_EMAIL = "journey.test@example.com"
TEST_USER_PASSWORD = "SecureTestPassword123!"
TEST_USER_NAME = "Journey Test User"
TEST_PROJECT_NAME = "E2E Test Project"
TEST_ORGANIZATION_NAME = "Test Organization"

# Performance validation thresholds
MAX_RESPONSE_TIME_MS = 500  # Maximum acceptable response time
MIN_THROUGHPUT_RPS = 50     # Minimum acceptable requests per second
MAX_ERROR_RATE = 0.01       # Maximum acceptable error rate (1%)

# Test data patterns for comprehensive validation
COMPREHENSIVE_TEST_DATA = {
    'users': [
        {
            'email': TEST_USER_EMAIL,
            'name': TEST_USER_NAME,
            'role': 'user',
            'permissions': ['read', 'write', 'create'],
            'created_at': datetime.now(timezone.utc).isoformat()
        },
        {
            'email': 'admin.test@example.com',
            'name': 'Admin Test User',
            'role': 'admin',
            'permissions': ['read', 'write', 'create', 'delete', 'admin'],
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    ],
    'projects': [
        {
            'name': TEST_PROJECT_NAME,
            'description': 'End-to-end testing project',
            'owner_email': TEST_USER_EMAIL,
            'status': 'active',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    ],
    'organizations': [
        {
            'name': TEST_ORGANIZATION_NAME,
            'description': 'Test organization for E2E scenarios',
            'admin_email': 'admin.test@example.com',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    ]
}


class UserJourneyTestHelper:
    """
    Helper class for user journey testing with performance monitoring and validation.
    
    Provides utilities for authentication, business operations, performance tracking,
    and comprehensive validation of user workflow scenarios per Section 6.6.5.
    """
    
    def __init__(
        self, 
        client: FlaskClient, 
        performance_monitor: PerformanceMetrics,
        reporter: E2ETestReporter
    ):
        """
        Initialize user journey test helper.
        
        Args:
            client: Flask test client for HTTP requests
            performance_monitor: Performance metrics tracking
            reporter: E2E test reporter for comprehensive results
        """
        self.client = client
        self.performance_monitor = performance_monitor
        self.reporter = reporter
        self.auth_token: Optional[str] = None
        self.user_id: Optional[str] = None
        self.session_data: Dict[str, Any] = {}
        
        logger.debug("User journey test helper initialized")
    
    def authenticate_user(
        self, 
        email: str = TEST_USER_EMAIL, 
        password: str = TEST_USER_PASSWORD,
        expect_success: bool = True
    ) -> Dict[str, Any]:
        """
        Perform user authentication with performance monitoring.
        
        Implements complete authentication workflow testing from login request
        through JWT token validation per Section 6.4.2 requirements.
        
        Args:
            email: User email for authentication
            password: User password for authentication
            expect_success: Whether to expect successful authentication
            
        Returns:
            Dictionary containing authentication result and metrics
        """
        start_time = time.time()
        
        login_data = {
            'email': email,
            'password': password
        }
        
        logger.info(f"Starting authentication workflow for user: {email}")
        
        # Perform login request
        response = self.client.post(
            '/auth/login',
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        self.performance_monitor.add_response_time(response_time)
        
        result = {
            'status_code': response.status_code,
            'response_time_ms': response_time,
            'success': False,
            'user_data': {},
            'auth_token': None,
            'error_message': None
        }
        
        if expect_success and response.status_code == 200:
            try:
                response_data = response.get_json()
                result.update({
                    'success': True,
                    'user_data': response_data.get('user', {}),
                    'auth_token': response_data.get('access_token'),
                    'refresh_token': response_data.get('refresh_token'),
                    'expires_in': response_data.get('expires_in', 3600)
                })
                
                # Store authentication data for subsequent requests
                self.auth_token = result['auth_token']
                self.user_id = result['user_data'].get('id') or result['user_data'].get('sub')
                
                logger.info(
                    "Authentication successful",
                    user_id=self.user_id,
                    response_time_ms=response_time,
                    token_expires_in=result['expires_in']
                )
                
            except Exception as e:
                result.update({
                    'success': False,
                    'error_message': f'Failed to parse authentication response: {str(e)}'
                })
                self.performance_monitor.add_error()
                logger.error(f"Authentication parsing failed: {e}")
        
        elif not expect_success and response.status_code in [400, 401, 403]:
            # Expected failure scenarios
            result['success'] = True  # Success in testing the failure case
            try:
                error_data = response.get_json()
                result['error_message'] = error_data.get('error', 'Authentication failed')
            except:
                result['error_message'] = 'Authentication failed'
                
            logger.info(
                "Expected authentication failure",
                status_code=response.status_code,
                response_time_ms=response_time
            )
        
        else:
            # Unexpected response
            self.performance_monitor.add_error()
            result['error_message'] = f'Unexpected response: {response.status_code}'
            
            logger.error(
                "Unexpected authentication response",
                status_code=response.status_code,
                expected_success=expect_success,
                response_time_ms=response_time
            )
        
        # Validate performance against baseline
        baseline_auth_time = NODEJS_BASELINE_METRICS['response_times']['user_login']
        if response_time > baseline_auth_time * (1 + PERFORMANCE_BASELINE_THRESHOLD):
            logger.warning(
                "Authentication performance degraded",
                measured_time_ms=response_time,
                baseline_time_ms=baseline_auth_time,
                variance=((response_time - baseline_auth_time) / baseline_auth_time)
            )
        
        return result
    
    def access_protected_resource(
        self, 
        endpoint: str, 
        method: str = 'GET',
        data: Optional[Dict[str, Any]] = None,
        expected_status: int = 200
    ) -> Dict[str, Any]:
        """
        Access protected resource with authentication validation.
        
        Tests secured resource access patterns with JWT token validation
        and performance monitoring per Section 6.4.2 requirements.
        
        Args:
            endpoint: API endpoint to access
            method: HTTP method for request
            data: Optional request data for POST/PUT requests
            expected_status: Expected HTTP status code
            
        Returns:
            Dictionary containing access result and performance metrics
        """
        start_time = time.time()
        
        headers = {}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        if data:
            headers['Content-Type'] = 'application/json'
        
        logger.debug(f"Accessing protected resource: {method} {endpoint}")
        
        # Perform request based on method
        if method.upper() == 'GET':
            response = self.client.get(endpoint, headers=headers)
        elif method.upper() == 'POST':
            response = self.client.post(endpoint, json=data, headers=headers)
        elif method.upper() == 'PUT':
            response = self.client.put(endpoint, json=data, headers=headers)
        elif method.upper() == 'DELETE':
            response = self.client.delete(endpoint, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        response_time = (time.time() - start_time) * 1000
        self.performance_monitor.add_response_time(response_time)
        
        result = {
            'endpoint': endpoint,
            'method': method,
            'status_code': response.status_code,
            'response_time_ms': response_time,
            'success': response.status_code == expected_status,
            'data': {},
            'error_message': None
        }
        
        # Parse response data
        try:
            if response.data:
                result['data'] = response.get_json() or {}
        except Exception as e:
            logger.debug(f"Could not parse response JSON: {e}")
            result['data'] = {'raw_response': response.data.decode('utf-8', errors='ignore')}
        
        # Validate response
        if response.status_code != expected_status:
            self.performance_monitor.add_error()
            result['error_message'] = f'Expected status {expected_status}, got {response.status_code}'
            
            logger.warning(
                "Protected resource access failed",
                endpoint=endpoint,
                expected_status=expected_status,
                actual_status=response.status_code,
                response_time_ms=response_time
            )
        else:
            logger.debug(
                "Protected resource access successful",
                endpoint=endpoint,
                status_code=response.status_code,
                response_time_ms=response_time
            )
        
        return result
    
    def perform_business_transaction(
        self,
        transaction_type: str,
        transaction_data: Dict[str, Any],
        validation_steps: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Perform complex business transaction with validation.
        
        Implements multi-step business operation testing with data persistence
        validation and business rule enforcement per F-004-RQ-001 and Section 4.6.5.
        
        Args:
            transaction_type: Type of business transaction
            transaction_data: Data for the transaction
            validation_steps: List of validation steps to perform
            
        Returns:
            Dictionary containing transaction result and validation outcomes
        """
        transaction_id = str(uuid.uuid4())
        start_time = time.time()
        
        logger.info(
            f"Starting business transaction: {transaction_type}",
            transaction_id=transaction_id,
            user_id=self.user_id
        )
        
        result = {
            'transaction_id': transaction_id,
            'transaction_type': transaction_type,
            'start_time': start_time,
            'steps_completed': [],
            'validation_results': [],
            'success': False,
            'error_message': None,
            'performance_metrics': {}
        }
        
        try:
            # Step 1: Create transaction record
            create_result = self.access_protected_resource(
                f'/api/transactions',
                method='POST',
                data={
                    'transaction_id': transaction_id,
                    'transaction_type': transaction_type,
                    'data': transaction_data,
                    'user_id': self.user_id
                },
                expected_status=201
            )
            
            if not create_result['success']:
                result['error_message'] = f"Transaction creation failed: {create_result['error_message']}"
                return result
            
            result['steps_completed'].append('transaction_created')
            
            # Step 2: Process business logic
            process_result = self.access_protected_resource(
                f'/api/transactions/{transaction_id}/process',
                method='POST',
                data={'action': 'process'},
                expected_status=200
            )
            
            if not process_result['success']:
                result['error_message'] = f"Transaction processing failed: {process_result['error_message']}"
                return result
            
            result['steps_completed'].append('business_logic_processed')
            
            # Step 3: Validate business rules
            for i, validation_step in enumerate(validation_steps):
                validation_result = self.access_protected_resource(
                    validation_step['endpoint'],
                    method=validation_step.get('method', 'GET'),
                    data=validation_step.get('data'),
                    expected_status=validation_step.get('expected_status', 200)
                )
                
                validation_outcome = {
                    'step_index': i,
                    'step_name': validation_step.get('name', f'validation_{i}'),
                    'success': validation_result['success'],
                    'response_time_ms': validation_result['response_time_ms'],
                    'data': validation_result['data']
                }
                
                if not validation_result['success']:
                    validation_outcome['error'] = validation_result['error_message']
                
                result['validation_results'].append(validation_outcome)
                result['steps_completed'].append(f"validation_{i}")
            
            # Step 4: Finalize transaction
            finalize_result = self.access_protected_resource(
                f'/api/transactions/{transaction_id}/finalize',
                method='POST',
                data={'status': 'completed'},
                expected_status=200
            )
            
            if not finalize_result['success']:
                result['error_message'] = f"Transaction finalization failed: {finalize_result['error_message']}"
                return result
            
            result['steps_completed'].append('transaction_finalized')
            result['success'] = True
            
            # Calculate performance metrics
            total_time = time.time() - start_time
            result['performance_metrics'] = {
                'total_time_seconds': total_time,
                'steps_count': len(result['steps_completed']),
                'validations_count': len(result['validation_results']),
                'average_step_time_ms': (total_time * 1000) / len(result['steps_completed']),
                'validation_success_rate': len([v for v in result['validation_results'] if v['success']]) / max(len(result['validation_results']), 1)
            }
            
            logger.info(
                f"Business transaction completed successfully",
                transaction_id=transaction_id,
                transaction_type=transaction_type,
                total_time_seconds=total_time,
                steps_completed=len(result['steps_completed'])
            )
            
        except Exception as e:
            result['error_message'] = f"Transaction failed with exception: {str(e)}"
            self.performance_monitor.add_error()
            
            logger.error(
                f"Business transaction failed",
                transaction_id=transaction_id,
                transaction_type=transaction_type,
                error=str(e)
            )
        
        return result
    
    def test_error_recovery(
        self, 
        error_scenarios: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Test error handling and recovery scenarios.
        
        Validates error propagation from detection through user-facing responses
        per Section 4.6.6 requirements with comprehensive error recovery testing.
        
        Args:
            error_scenarios: List of error scenarios to test
            
        Returns:
            Dictionary containing error testing results
        """
        logger.info("Starting error recovery testing")
        
        results = {
            'total_scenarios': len(error_scenarios),
            'scenarios_tested': [],
            'recovery_success_rate': 0.0,
            'error_response_consistency': True,
            'performance_impact': {},
            'overall_success': False
        }
        
        successful_recoveries = 0
        
        for i, scenario in enumerate(error_scenarios):
            scenario_start = time.time()
            scenario_name = scenario.get('name', f'error_scenario_{i}')
            
            logger.debug(f"Testing error scenario: {scenario_name}")
            
            scenario_result = {
                'name': scenario_name,
                'type': scenario.get('type', 'unknown'),
                'success': False,
                'recovery_time_ms': 0,
                'error_response': {},
                'recovery_response': {}
            }
            
            try:
                # Trigger error condition
                error_response = self.access_protected_resource(
                    scenario['error_endpoint'],
                    method=scenario.get('method', 'GET'),
                    data=scenario.get('error_data'),
                    expected_status=scenario.get('expected_error_status', 400)
                )
                
                scenario_result['error_response'] = error_response
                
                # Test recovery if specified
                if 'recovery_endpoint' in scenario:
                    recovery_start = time.time()
                    
                    recovery_response = self.access_protected_resource(
                        scenario['recovery_endpoint'],
                        method=scenario.get('recovery_method', 'GET'),
                        data=scenario.get('recovery_data'),
                        expected_status=scenario.get('expected_recovery_status', 200)
                    )
                    
                    recovery_time = (time.time() - recovery_start) * 1000
                    scenario_result['recovery_time_ms'] = recovery_time
                    scenario_result['recovery_response'] = recovery_response
                    scenario_result['success'] = recovery_response['success']
                    
                    if recovery_response['success']:
                        successful_recoveries += 1
                else:
                    # No recovery test, success is proper error handling
                    scenario_result['success'] = error_response['success']
                    if error_response['success']:
                        successful_recoveries += 1
                
                # Validate error response format consistency
                if 'error_response' in scenario_result and scenario_result['error_response'].get('data'):
                    error_data = scenario_result['error_response']['data']
                    required_error_fields = ['error', 'message', 'timestamp']
                    
                    for field in required_error_fields:
                        if field not in error_data:
                            results['error_response_consistency'] = False
                            logger.warning(f"Error response missing required field: {field}")
            
            except Exception as e:
                scenario_result['error_message'] = str(e)
                logger.error(f"Error scenario testing failed: {scenario_name} - {e}")
            
            finally:
                scenario_result['total_time_ms'] = (time.time() - scenario_start) * 1000
                results['scenarios_tested'].append(scenario_result)
        
        # Calculate overall results
        results['recovery_success_rate'] = successful_recoveries / max(len(error_scenarios), 1)
        results['overall_success'] = results['recovery_success_rate'] >= 0.8  # 80% success threshold
        
        # Calculate performance impact
        scenario_times = [s['total_time_ms'] for s in results['scenarios_tested'] if 'total_time_ms' in s]
        if scenario_times:
            results['performance_impact'] = {
                'average_error_handling_time_ms': sum(scenario_times) / len(scenario_times),
                'max_error_handling_time_ms': max(scenario_times),
                'min_error_handling_time_ms': min(scenario_times)
            }
        
        logger.info(
            "Error recovery testing completed",
            scenarios_tested=len(results['scenarios_tested']),
            recovery_success_rate=f"{results['recovery_success_rate']:.2%}",
            overall_success=results['overall_success']
        )
        
        return results


# =============================================================================
# Complete User Journey Test Cases
# =============================================================================

@pytest.mark.e2e
class TestCompleteUserJourneys:
    """
    Comprehensive end-to-end user journey testing class.
    
    Implements complete user workflow validation from authentication through
    complex business operations with performance monitoring and baseline
    comparison per Section 4.6.1 and Section 6.6.5 requirements.
    """
    
    def test_authentication_to_secured_access_journey(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test complete authentication workflow to secured resource access.
        
        Validates:
        - User authentication with Auth0 integration per Section 6.4.2
        - JWT token validation and session management per Section 6.4.1
        - Secured resource access with proper authorization per Section 6.4.2
        - Performance comparison with Node.js baseline per Section 0.1.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        helper = UserJourneyTestHelper(client, performance_monitor, reporter)
        
        logger.info("Starting authentication to secured access journey test")
        
        # Step 1: User Authentication
        auth_result = helper.authenticate_user(
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD,
            expect_success=True
        )
        
        assert auth_result['success'], f"Authentication failed: {auth_result['error_message']}"
        assert auth_result['auth_token'] is not None, "No auth token received"
        assert auth_result['user_data'], "No user data in authentication response"
        
        # Validate authentication performance
        baseline_auth_time = NODEJS_BASELINE_METRICS['response_times']['user_login']
        auth_variance = (auth_result['response_time_ms'] - baseline_auth_time) / baseline_auth_time
        
        assert abs(auth_variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Authentication performance variance {auth_variance:.2%} exceeds threshold "
            f"{PERFORMANCE_BASELINE_THRESHOLD:.2%}"
        )
        
        # Step 2: Access User Profile (Protected Resource)
        profile_result = helper.access_protected_resource(
            '/api/users/profile',
            method='GET',
            expected_status=200
        )
        
        assert profile_result['success'], f"Profile access failed: {profile_result['error_message']}"
        assert 'email' in profile_result['data'], "Profile data missing email"
        assert profile_result['data']['email'] == TEST_USER_EMAIL, "Profile email mismatch"
        
        # Step 3: Access Protected Business Data
        projects_result = helper.access_protected_resource(
            '/api/projects',
            method='GET',
            expected_status=200
        )
        
        assert projects_result['success'], f"Projects access failed: {projects_result['error_message']}"
        assert isinstance(projects_result['data'], (list, dict)), "Projects data format invalid"
        
        # Step 4: Validate Session Persistence
        session_check_result = helper.access_protected_resource(
            '/api/users/session',
            method='GET',
            expected_status=200
        )
        
        assert session_check_result['success'], f"Session validation failed: {session_check_result['error_message']}"
        
        # Calculate overall journey performance
        total_requests = 4
        average_response_time = (
            auth_result['response_time_ms'] +
            profile_result['response_time_ms'] +
            projects_result['response_time_ms'] +
            session_check_result['response_time_ms']
        ) / total_requests
        
        baseline_avg = NODEJS_BASELINE_METRICS['response_times']['api_endpoint_avg']
        overall_variance = (average_response_time - baseline_avg) / baseline_avg
        
        assert abs(overall_variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Overall journey performance variance {overall_variance:.2%} exceeds threshold"
        )
        
        logger.info(
            "Authentication to secured access journey completed successfully",
            total_requests=total_requests,
            average_response_time_ms=average_response_time,
            performance_variance=f"{overall_variance:.2%}"
        )
    
    def test_complete_business_transaction_journey(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test complete business transaction workflow with data persistence.
        
        Validates:
        - Multi-step business operations per Section 4.6.5
        - Data persistence across transaction steps per Section 6.2.4
        - Business rule validation throughout workflow per F-004-RQ-001
        - Transaction integrity and error handling per Section 4.6.6
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        helper = UserJourneyTestHelper(client, performance_monitor, reporter)
        
        logger.info("Starting complete business transaction journey test")
        
        # Step 1: Authenticate User
        auth_result = helper.authenticate_user()
        assert auth_result['success'], f"Authentication failed: {auth_result['error_message']}"
        
        # Step 2: Perform Complex Business Transaction
        transaction_data = {
            'project_name': f"{TEST_PROJECT_NAME} {uuid.uuid4().hex[:8]}",
            'project_description': 'E2E test project with comprehensive validation',
            'organization_id': 'test_org_001',
            'budget': 50000.00,
            'timeline_months': 6,
            'team_members': [
                {'email': TEST_USER_EMAIL, 'role': 'project_manager'},
                {'email': 'team.member@example.com', 'role': 'developer'}
            ],
            'metadata': {
                'test_scenario': 'complete_business_transaction',
                'validation_required': True
            }
        }
        
        validation_steps = [
            {
                'name': 'budget_validation',
                'endpoint': '/api/validation/budget',
                'method': 'POST',
                'data': {'amount': transaction_data['budget']},
                'expected_status': 200
            },
            {
                'name': 'team_member_validation',
                'endpoint': '/api/validation/team-members',
                'method': 'POST',
                'data': {'members': transaction_data['team_members']},
                'expected_status': 200
            },
            {
                'name': 'organization_access_validation',
                'endpoint': f'/api/organizations/{transaction_data["organization_id"]}/access',
                'method': 'GET',
                'expected_status': 200
            }
        ]
        
        transaction_result = helper.perform_business_transaction(
            transaction_type='project_creation',
            transaction_data=transaction_data,
            validation_steps=validation_steps
        )
        
        assert transaction_result['success'], f"Transaction failed: {transaction_result['error_message']}"
        assert len(transaction_result['steps_completed']) >= 4, "Insufficient transaction steps completed"
        assert len(transaction_result['validation_results']) == len(validation_steps), "Validation steps mismatch"
        
        # Validate all business rules passed
        validation_success_rate = transaction_result['performance_metrics']['validation_success_rate']
        assert validation_success_rate == 1.0, f"Business rule validation failed: {validation_success_rate:.2%} success rate"
        
        # Step 3: Verify Data Persistence
        transaction_id = transaction_result['transaction_id']
        
        # Verify project was created
        project_check_result = helper.access_protected_resource(
            f'/api/projects/search',
            method='POST',
            data={'name': transaction_data['project_name']},
            expected_status=200
        )
        
        assert project_check_result['success'], "Project persistence verification failed"
        projects_found = project_check_result['data'].get('projects', [])
        assert len(projects_found) > 0, "Created project not found in database"
        
        created_project = projects_found[0]
        assert created_project['name'] == transaction_data['project_name'], "Project name mismatch"
        assert created_project['budget'] == transaction_data['budget'], "Project budget mismatch"
        
        # Verify transaction audit trail
        audit_result = helper.access_protected_resource(
            f'/api/transactions/{transaction_id}/audit',
            method='GET',
            expected_status=200
        )
        
        assert audit_result['success'], "Transaction audit trail verification failed"
        audit_data = audit_result['data']
        assert audit_data['transaction_id'] == transaction_id, "Audit transaction ID mismatch"
        assert audit_data['status'] == 'completed', "Transaction status not completed"
        
        # Validate performance metrics
        total_time = transaction_result['performance_metrics']['total_time_seconds']
        baseline_transaction_time = 2.0  # 2 seconds baseline for complex transactions
        time_variance = (total_time - baseline_transaction_time) / baseline_transaction_time
        
        assert abs(time_variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Transaction time variance {time_variance:.2%} exceeds threshold"
        )
        
        logger.info(
            "Complete business transaction journey completed successfully",
            transaction_id=transaction_id,
            total_time_seconds=total_time,
            validation_success_rate=f"{validation_success_rate:.2%}",
            steps_completed=len(transaction_result['steps_completed'])
        )
    
    def test_user_registration_to_project_collaboration_journey(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test complete user journey from registration through project collaboration.
        
        Validates:
        - User registration and profile setup per Section 6.4.2
        - Project creation and configuration per Section 5.2.4
        - Team collaboration setup per Section 4.6.5
        - Cross-user workflow validation per Section 6.4.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        helper = UserJourneyTestHelper(client, performance_monitor, reporter)
        
        logger.info("Starting user registration to project collaboration journey test")
        
        # Generate unique test data
        unique_id = uuid.uuid4().hex[:8]
        new_user_email = f"newuser.{unique_id}@example.com"
        new_user_name = f"New Test User {unique_id}"
        project_name = f"Collaboration Project {unique_id}"
        
        # Step 1: User Registration
        registration_data = {
            'email': new_user_email,
            'name': new_user_name,
            'password': TEST_USER_PASSWORD,
            'confirm_password': TEST_USER_PASSWORD,
            'terms_accepted': True,
            'marketing_consent': False
        }
        
        registration_result = helper.access_protected_resource(
            '/auth/register',
            method='POST',
            data=registration_data,
            expected_status=201
        )
        
        assert registration_result['success'], f"User registration failed: {registration_result['error_message']}"
        assert 'user_id' in registration_result['data'], "Registration response missing user_id"
        
        new_user_id = registration_result['data']['user_id']
        
        # Step 2: Email Verification (simulated)
        verification_result = helper.access_protected_resource(
            f'/auth/verify-email',
            method='POST',
            data={'user_id': new_user_id, 'verification_code': 'TEST_CODE_123'},
            expected_status=200
        )
        
        assert verification_result['success'], f"Email verification failed: {verification_result['error_message']}"
        
        # Step 3: User Profile Setup
        profile_data = {
            'bio': f'Test user bio for {new_user_name}',
            'skills': ['Python', 'Flask', 'Testing'],
            'availability': 'full-time',
            'timezone': 'UTC',
            'preferences': {
                'notifications': True,
                'public_profile': False
            }
        }
        
        profile_setup_result = helper.access_protected_resource(
            f'/api/users/{new_user_id}/profile',
            method='PUT',
            data=profile_data,
            expected_status=200
        )
        
        assert profile_setup_result['success'], f"Profile setup failed: {profile_setup_result['error_message']}"
        
        # Step 4: Authenticate as New User
        new_user_auth = helper.authenticate_user(
            email=new_user_email,
            password=TEST_USER_PASSWORD
        )
        
        assert new_user_auth['success'], f"New user authentication failed: {new_user_auth['error_message']}"
        
        # Step 5: Create Collaboration Project
        project_data = {
            'name': project_name,
            'description': 'E2E test project for collaboration testing',
            'type': 'collaboration_test',
            'visibility': 'private',
            'collaboration_settings': {
                'allow_external_collaborators': True,
                'require_approval': False,
                'max_collaborators': 10
            },
            'initial_roles': [
                {'user_id': new_user_id, 'role': 'owner'},
                {'email': TEST_USER_EMAIL, 'role': 'collaborator'}
            ]
        }
        
        project_creation_result = helper.access_protected_resource(
            '/api/projects',
            method='POST',
            data=project_data,
            expected_status=201
        )
        
        assert project_creation_result['success'], f"Project creation failed: {project_creation_result['error_message']}"
        
        project_id = project_creation_result['data']['project_id']
        
        # Step 6: Invite Collaborator
        invitation_data = {
            'project_id': project_id,
            'invitee_email': TEST_USER_EMAIL,
            'role': 'collaborator',
            'message': 'Please join our E2E test project',
            'permissions': ['read', 'write', 'comment']
        }
        
        invitation_result = helper.access_protected_resource(
            '/api/projects/invitations',
            method='POST',
            data=invitation_data,
            expected_status=201
        )
        
        assert invitation_result['success'], f"Collaboration invitation failed: {invitation_result['error_message']}"
        
        invitation_id = invitation_result['data']['invitation_id']
        
        # Step 7: Accept Collaboration (as existing user)
        # First authenticate as existing user
        existing_user_auth = helper.authenticate_user(
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD
        )
        
        assert existing_user_auth['success'], "Existing user authentication failed"
        
        # Accept invitation
        acceptance_result = helper.access_protected_resource(
            f'/api/projects/invitations/{invitation_id}/accept',
            method='POST',
            data={'accept': True},
            expected_status=200
        )
        
        assert acceptance_result['success'], f"Invitation acceptance failed: {acceptance_result['error_message']}"
        
        # Step 8: Verify Collaboration Access
        collaboration_check_result = helper.access_protected_resource(
            f'/api/projects/{project_id}/collaborators',
            method='GET',
            expected_status=200
        )
        
        assert collaboration_check_result['success'], "Collaboration verification failed"
        
        collaborators = collaboration_check_result['data'].get('collaborators', [])
        collaborator_emails = [c.get('email') for c in collaborators]
        
        assert new_user_email in collaborator_emails, "New user not found in collaborators"
        assert TEST_USER_EMAIL in collaborator_emails, "Existing user not found in collaborators"
        
        # Step 9: Test Cross-User Workflow
        # Create a task as new user
        task_data = {
            'project_id': project_id,
            'title': 'E2E Test Task',
            'description': 'Task created during E2E collaboration testing',
            'assigned_to': TEST_USER_EMAIL,
            'priority': 'medium',
            'due_date': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        }
        
        # Switch back to new user context
        helper.auth_token = new_user_auth['auth_token']
        helper.user_id = new_user_id
        
        task_creation_result = helper.access_protected_resource(
            '/api/tasks',
            method='POST',
            data=task_data,
            expected_status=201
        )
        
        assert task_creation_result['success'], f"Task creation failed: {task_creation_result['error_message']}"
        
        task_id = task_creation_result['data']['task_id']
        
        # Switch to existing user and update task
        helper.auth_token = existing_user_auth['auth_token']
        helper.user_id = existing_user_auth['user_data'].get('id')
        
        task_update_result = helper.access_protected_resource(
            f'/api/tasks/{task_id}',
            method='PUT',
            data={'status': 'in_progress', 'progress': 25},
            expected_status=200
        )
        
        assert task_update_result['success'], f"Task update failed: {task_update_result['error_message']}"
        
        # Validate overall journey performance
        journey_steps = [
            registration_result, verification_result, profile_setup_result,
            new_user_auth, project_creation_result, invitation_result,
            existing_user_auth, acceptance_result, collaboration_check_result,
            task_creation_result, task_update_result
        ]
        
        total_response_time = sum(step['response_time_ms'] for step in journey_steps)
        average_response_time = total_response_time / len(journey_steps)
        
        baseline_avg = NODEJS_BASELINE_METRICS['response_times']['api_endpoint_avg']
        journey_variance = (average_response_time - baseline_avg) / baseline_avg
        
        assert abs(journey_variance) <= PERFORMANCE_BASELINE_THRESHOLD * 1.5, (
            f"Complex journey performance variance {journey_variance:.2%} exceeds extended threshold"
        )
        
        logger.info(
            "User registration to project collaboration journey completed successfully",
            new_user_id=new_user_id,
            project_id=project_id,
            task_id=task_id,
            total_steps=len(journey_steps),
            average_response_time_ms=average_response_time,
            performance_variance=f"{journey_variance:.2%}"
        )
    
    def test_error_propagation_and_recovery_journey(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test comprehensive error handling and recovery across user workflows.
        
        Validates:
        - Error detection and propagation per Section 4.6.6
        - User-facing error responses consistency per Section 4.6.6
        - Error recovery mechanisms per Section 4.6.6
        - System resilience under error conditions per Section 6.1.3
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        helper = UserJourneyTestHelper(client, performance_monitor, reporter)
        
        logger.info("Starting error propagation and recovery journey test")
        
        # Step 1: Authenticate User for Error Testing
        auth_result = helper.authenticate_user()
        assert auth_result['success'], f"Authentication failed: {auth_result['error_message']}"
        
        # Define comprehensive error scenarios
        error_scenarios = [
            {
                'name': 'invalid_input_validation',
                'type': 'validation_error',
                'error_endpoint': '/api/projects',
                'method': 'POST',
                'error_data': {
                    'name': '',  # Invalid empty name
                    'budget': -1000,  # Invalid negative budget
                    'email': 'invalid-email'  # Invalid email format
                },
                'expected_error_status': 400,
                'recovery_endpoint': '/api/projects',
                'recovery_method': 'POST',
                'recovery_data': {
                    'name': 'Valid Project Name',
                    'budget': 5000,
                    'email': 'valid@example.com'
                },
                'expected_recovery_status': 201
            },
            {
                'name': 'unauthorized_access',
                'type': 'authorization_error',
                'error_endpoint': '/api/admin/users',
                'method': 'GET',
                'expected_error_status': 403
            },
            {
                'name': 'resource_not_found',
                'type': 'not_found_error',
                'error_endpoint': '/api/projects/nonexistent-project-id',
                'method': 'GET',
                'expected_error_status': 404
            },
            {
                'name': 'duplicate_resource_creation',
                'type': 'conflict_error',
                'error_endpoint': '/api/projects',
                'method': 'POST',
                'error_data': {
                    'name': 'Duplicate Project Name',
                    'organization_id': 'test_org_001'
                },
                'expected_error_status': 409,
                'recovery_endpoint': '/api/projects',
                'recovery_method': 'POST',
                'recovery_data': {
                    'name': f'Unique Project Name {uuid.uuid4().hex[:8]}',
                    'organization_id': 'test_org_001'
                },
                'expected_recovery_status': 201
            },
            {
                'name': 'rate_limit_exceeded',
                'type': 'rate_limit_error',
                'error_endpoint': '/api/bulk-operations',
                'method': 'POST',
                'error_data': {
                    'operations': [{'type': 'test'} for _ in range(1000)]  # Exceed rate limit
                },
                'expected_error_status': 429
            },
            {
                'name': 'external_service_failure',
                'type': 'external_service_error',
                'error_endpoint': '/api/integrations/external-service/test',
                'method': 'POST',
                'error_data': {'trigger_failure': True},
                'expected_error_status': 502,
                'recovery_endpoint': '/api/integrations/external-service/test',
                'recovery_method': 'POST',
                'recovery_data': {'trigger_failure': False},
                'expected_recovery_status': 200
            }
        ]
        
        # Step 2: Create duplicate project for conflict testing
        helper.access_protected_resource(
            '/api/projects',
            method='POST',
            data={
                'name': 'Duplicate Project Name',
                'organization_id': 'test_org_001'
            },
            expected_status=201
        )
        
        # Step 3: Execute Error Recovery Testing
        error_test_results = helper.test_error_recovery(error_scenarios)
        
        assert error_test_results['overall_success'], (
            f"Error recovery testing failed: {error_test_results['recovery_success_rate']:.2%} success rate"
        )
        
        assert error_test_results['error_response_consistency'], (
            "Error response format inconsistency detected"
        )
        
        # Validate specific error scenarios
        scenarios_by_name = {s['name']: s for s in error_test_results['scenarios_tested']}
        
        # Validation Error Scenario
        validation_scenario = scenarios_by_name['invalid_input_validation']
        assert validation_scenario['success'], "Validation error recovery failed"
        assert validation_scenario['recovery_time_ms'] < 1000, "Validation recovery too slow"
        
        # Authorization Error Scenario  
        auth_scenario = scenarios_by_name['unauthorized_access']
        assert auth_scenario['success'], "Authorization error handling failed"
        
        # Not Found Error Scenario
        not_found_scenario = scenarios_by_name['resource_not_found']
        assert not_found_scenario['success'], "Not found error handling failed"
        
        # Conflict Error Scenario
        conflict_scenario = scenarios_by_name['duplicate_resource_creation']
        assert conflict_scenario['success'], "Conflict error recovery failed"
        
        # Step 4: Test Session Recovery After Errors
        session_recovery_result = helper.access_protected_resource(
            '/api/users/profile',
            method='GET',
            expected_status=200
        )
        
        assert session_recovery_result['success'], (
            "Session not recovered after error scenarios"
        )
        
        # Step 5: Validate Performance Impact of Error Handling
        avg_error_handling_time = error_test_results['performance_impact']['average_error_handling_time_ms']
        baseline_response_time = NODEJS_BASELINE_METRICS['response_times']['api_endpoint_avg']
        
        # Error handling should not be more than 2x baseline response time
        assert avg_error_handling_time <= baseline_response_time * 2, (
            f"Error handling performance degraded: {avg_error_handling_time}ms average "
            f"vs {baseline_response_time}ms baseline"
        )
        
        logger.info(
            "Error propagation and recovery journey completed successfully",
            scenarios_tested=error_test_results['total_scenarios'],
            recovery_success_rate=f"{error_test_results['recovery_success_rate']:.2%}",
            average_error_handling_time_ms=avg_error_handling_time,
            error_response_consistency=error_test_results['error_response_consistency']
        )


# =============================================================================
# Performance Validation Test Cases
# =============================================================================

@pytest.mark.performance
@pytest.mark.e2e
class TestUserJourneyPerformance:
    """
    Performance validation for user journey scenarios.
    
    Validates performance requirements and baseline comparison per Section 0.1.1
    with comprehensive load testing and throughput measurement per Section 6.6.1.
    """
    
    def test_concurrent_user_authentication_performance(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        locust_load_tester: Optional[LocustLoadTester],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test authentication performance under concurrent user load.
        
        Validates:
        - Concurrent authentication throughput per Section 6.6.1
        - Response time distribution under load per Section 0.1.1
        - System stability with multiple users per Section 6.6.1
        - Performance variance within acceptable thresholds per Section 0.1.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            locust_load_tester: Locust load testing integration
            performance_monitor: Performance metrics tracking
        """
        if not locust_load_tester:
            pytest.skip("Locust load testing not available")
        
        logger.info("Starting concurrent user authentication performance test")
        
        # Configure load test parameters
        concurrent_users = 25
        test_duration = 30  # seconds
        spawn_rate = 2.0  # users per second
        
        # Execute load test
        load_test_results = locust_load_tester.run_load_test(
            users=concurrent_users,
            spawn_rate=spawn_rate,
            duration=test_duration
        )
        
        # Validate load test executed successfully
        assert 'error' not in load_test_results, f"Load test failed: {load_test_results.get('error')}"
        assert load_test_results['total_requests'] > 0, "No requests executed in load test"
        
        # Performance validation
        average_response_time = load_test_results['average_response_time']
        requests_per_second = load_test_results['requests_per_second']
        failure_rate = load_test_results['failure_rate']
        
        # Compare with baseline metrics
        baseline_auth_time = NODEJS_BASELINE_METRICS['response_times']['user_login']
        baseline_throughput = NODEJS_BASELINE_METRICS['throughput']['requests_per_second']
        
        response_time_variance = (average_response_time - baseline_auth_time) / baseline_auth_time
        throughput_variance = (requests_per_second - baseline_throughput) / baseline_throughput
        
        # Assertions for performance requirements
        assert abs(response_time_variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Authentication response time variance {response_time_variance:.2%} exceeds threshold"
        )
        
        assert failure_rate <= MAX_ERROR_RATE, (
            f"Failure rate {failure_rate:.2%} exceeds maximum {MAX_ERROR_RATE:.2%}"
        )
        
        assert requests_per_second >= MIN_THROUGHPUT_RPS, (
            f"Throughput {requests_per_second:.1f} RPS below minimum {MIN_THROUGHPUT_RPS} RPS"
        )
        
        # Validate response time distribution
        p95_response_time = load_test_results['percentile_95']
        p99_response_time = load_test_results['percentile_99']
        
        assert p95_response_time <= MAX_RESPONSE_TIME_MS, (
            f"95th percentile response time {p95_response_time}ms exceeds maximum {MAX_RESPONSE_TIME_MS}ms"
        )
        
        assert p99_response_time <= MAX_RESPONSE_TIME_MS * 1.5, (
            f"99th percentile response time {p99_response_time}ms exceeds acceptable threshold"
        )
        
        logger.info(
            "Concurrent user authentication performance test completed",
            concurrent_users=concurrent_users,
            test_duration_seconds=test_duration,
            total_requests=load_test_results['total_requests'],
            average_response_time_ms=average_response_time,
            requests_per_second=requests_per_second,
            failure_rate=f"{failure_rate:.2%}",
            response_time_variance=f"{response_time_variance:.2%}",
            throughput_variance=f"{throughput_variance:.2%}"
        )
    
    def test_api_endpoint_performance_with_apache_bench(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        apache_bench_tester: ApacheBenchTester,
        performance_monitor: PerformanceMetrics
    ):
        """
        Test individual API endpoint performance using Apache Bench.
        
        Validates:
        - Single endpoint response time consistency per Section 6.6.1
        - Throughput measurement for critical endpoints per Section 0.1.1
        - Performance variance within Node.js baseline threshold per Section 0.1.1
        - HTTP server performance under sustained load per Section 6.6.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            apache_bench_tester: Apache Bench performance testing
            performance_monitor: Performance metrics tracking
        """
        if not apache_bench_tester.available:
            pytest.skip("Apache Bench not available for performance testing")
        
        logger.info("Starting API endpoint performance test with Apache Bench")
        
        client = e2e_comprehensive_environment['client']
        helper = UserJourneyTestHelper(client, performance_monitor, e2e_comprehensive_environment['reporter'])
        
        # Authenticate to get token for protected endpoints
        auth_result = helper.authenticate_user()
        assert auth_result['success'], "Authentication required for performance testing"
        
        # Define critical endpoints for performance testing
        endpoints_to_test = [
            {
                'endpoint': '/health',
                'description': 'Health check endpoint',
                'baseline_key': 'health_check',
                'requests': 1000,
                'concurrency': 10
            },
            {
                'endpoint': '/api/users/profile',
                'description': 'User profile endpoint',
                'baseline_key': 'user_profile',
                'requests': 500,
                'concurrency': 5,
                'headers': {'Authorization': f'Bearer {helper.auth_token}'}
            },
            {
                'endpoint': '/api/projects',
                'description': 'Projects listing endpoint',
                'baseline_key': 'api_endpoint_avg',
                'requests': 300,
                'concurrency': 5,
                'headers': {'Authorization': f'Bearer {helper.auth_token}'}
            }
        ]
        
        performance_results = []
        
        for endpoint_config in endpoints_to_test:
            logger.debug(f"Testing endpoint performance: {endpoint_config['endpoint']}")
            
            # Run Apache Bench test
            bench_result = apache_bench_tester.run_benchmark(
                endpoint=endpoint_config['endpoint'],
                requests=endpoint_config['requests'],
                concurrency=endpoint_config['concurrency'],
                headers=endpoint_config.get('headers', {})
            )
            
            # Check for errors
            if 'error' in bench_result:
                logger.warning(f"Apache Bench test failed for {endpoint_config['endpoint']}: {bench_result['error']}")
                continue
            
            # Compare with baseline
            baseline_comparison = apache_bench_tester.compare_with_baseline(
                bench_result,
                NODEJS_BASELINE_METRICS
            )
            
            # Store results
            endpoint_result = {
                'endpoint': endpoint_config['endpoint'],
                'description': endpoint_config['description'],
                'benchmark_results': bench_result,
                'baseline_comparison': baseline_comparison,
                'performance_requirements_met': baseline_comparison['meets_requirements']
            }
            
            performance_results.append(endpoint_result)
            
            # Validate performance requirements
            assert baseline_comparison['meets_requirements'], (
                f"Performance requirements not met for {endpoint_config['endpoint']}: "
                f"Response time variance: {baseline_comparison['response_time_variance_percent']:.1f}%, "
                f"Throughput variance: {baseline_comparison['throughput_variance_percent']:.1f}%"
            )
            
            logger.debug(
                f"Endpoint performance validated: {endpoint_config['endpoint']}",
                requests_per_second=bench_result.get('requests_per_second', 0),
                mean_response_time_ms=bench_result.get('mean_response_time_ms', 0),
                success_rate=bench_result.get('success_rate', 0)
            )
        
        # Validate overall performance results
        assert len(performance_results) > 0, "No successful performance tests executed"
        
        successful_tests = [r for r in performance_results if r['performance_requirements_met']]
        success_rate = len(successful_tests) / len(performance_results)
        
        assert success_rate >= 0.8, (
            f"Performance test success rate {success_rate:.2%} below minimum 80%"
        )
        
        # Calculate aggregate performance metrics
        total_requests = sum(r['benchmark_results'].get('completed_requests', 0) for r in performance_results)
        total_failures = sum(r['benchmark_results'].get('failed_requests', 0) for r in performance_results)
        overall_failure_rate = total_failures / max(total_requests, 1)
        
        assert overall_failure_rate <= MAX_ERROR_RATE, (
            f"Overall failure rate {overall_failure_rate:.2%} exceeds maximum {MAX_ERROR_RATE:.2%}"
        )
        
        logger.info(
            "API endpoint performance test completed successfully",
            endpoints_tested=len(performance_results),
            successful_tests=len(successful_tests),
            success_rate=f"{success_rate:.2%}",
            total_requests=total_requests,
            overall_failure_rate=f"{overall_failure_rate:.2%}"
        )


# =============================================================================
# Session Management and State Persistence Test Cases
# =============================================================================

@pytest.mark.e2e
class TestSessionManagementJourneys:
    """
    Session management and state persistence testing across user workflows.
    
    Validates session handling, state management, and persistence per Section 6.4.1
    with comprehensive cross-request validation and performance monitoring.
    """
    
    def test_session_persistence_across_complex_workflow(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test session persistence across complex multi-step workflow.
        
        Validates:
        - Session continuity across multiple requests per Section 6.4.1
        - State persistence in Redis backend per Section 6.4.1
        - Session data consistency across workflow steps per Section 6.4.1
        - Performance of session operations per Section 0.1.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        helper = UserJourneyTestHelper(client, performance_monitor, reporter)
        
        logger.info("Starting session persistence across complex workflow test")
        
        # Step 1: Initial Authentication and Session Creation
        auth_result = helper.authenticate_user()
        assert auth_result['success'], f"Authentication failed: {auth_result['error_message']}"
        
        initial_session_token = helper.auth_token
        
        # Step 2: Store Complex Session Data
        session_data = {
            'user_preferences': {
                'theme': 'dark',
                'language': 'en',
                'timezone': 'UTC',
                'notifications': True
            },
            'current_project': {
                'id': 'project_123',
                'name': 'Test Project',
                'last_accessed': datetime.now(timezone.utc).isoformat()
            },
            'workflow_state': {
                'current_step': 'data_entry',
                'completed_steps': ['authentication', 'profile_setup'],
                'workflow_id': str(uuid.uuid4())
            },
            'temporary_data': {
                'draft_content': 'This is draft content for testing',
                'form_state': {'field1': 'value1', 'field2': 'value2'},
                'calculations': {'total': 1500, 'tax': 150, 'final': 1650}
            }
        }
        
        session_store_result = helper.access_protected_resource(
            '/api/session/store',
            method='POST',
            data=session_data,
            expected_status=200
        )
        
        assert session_store_result['success'], f"Session data storage failed: {session_store_result['error_message']}"
        
        # Step 3: Perform Multiple Operations with Session Access
        operations = [
            {
                'name': 'profile_update',
                'endpoint': '/api/users/profile',
                'method': 'PUT',
                'data': {'last_login': datetime.now(timezone.utc).isoformat()}
            },
            {
                'name': 'project_access',
                'endpoint': '/api/projects/project_123',
                'method': 'GET'
            },
            {
                'name': 'workflow_progress',
                'endpoint': '/api/workflows/progress',
                'method': 'POST',
                'data': {'step': 'validation', 'progress': 75}
            },
            {
                'name': 'data_computation',
                'endpoint': '/api/compute/calculate',
                'method': 'POST',
                'data': {'operation': 'complex_calculation', 'input': [1, 2, 3, 4, 5]}
            }
        ]
        
        operation_results = []
        
        for operation in operations:
            result = helper.access_protected_resource(
                operation['endpoint'],
                method=operation['method'],
                data=operation.get('data'),
                expected_status=200
            )
            
            operation_results.append({
                'name': operation['name'],
                'success': result['success'],
                'response_time_ms': result['response_time_ms'],
                'session_maintained': helper.auth_token == initial_session_token
            })
            
            assert result['success'], f"Operation {operation['name']} failed: {result['error_message']}"
            assert helper.auth_token == initial_session_token, f"Session token changed during {operation['name']}"
        
        # Step 4: Retrieve and Validate Session Data
        session_retrieve_result = helper.access_protected_resource(
            '/api/session/retrieve',
            method='GET',
            expected_status=200
        )
        
        assert session_retrieve_result['success'], f"Session data retrieval failed: {session_retrieve_result['error_message']}"
        
        retrieved_session_data = session_retrieve_result['data']
        
        # Validate session data integrity
        assert retrieved_session_data['user_preferences'] == session_data['user_preferences'], "User preferences not preserved"
        assert retrieved_session_data['current_project']['id'] == session_data['current_project']['id'], "Current project not preserved"
        assert retrieved_session_data['workflow_state']['workflow_id'] == session_data['workflow_state']['workflow_id'], "Workflow state not preserved"
        assert retrieved_session_data['temporary_data']['calculations'] == session_data['temporary_data']['calculations'], "Temporary data not preserved"
        
        # Step 5: Test Session Expiration and Renewal
        # Simulate session near expiration
        session_refresh_result = helper.access_protected_resource(
            '/api/session/refresh',
            method='POST',
            expected_status=200
        )
        
        assert session_refresh_result['success'], f"Session refresh failed: {session_refresh_result['error_message']}"
        
        new_session_token = session_refresh_result['data'].get('access_token')
        assert new_session_token is not None, "No new session token received"
        assert new_session_token != initial_session_token, "Session token not renewed"
        
        # Update helper with new token
        helper.auth_token = new_session_token
        
        # Step 6: Validate Session Data Persists After Renewal
        post_renewal_retrieve = helper.access_protected_resource(
            '/api/session/retrieve',
            method='GET',
            expected_status=200
        )
        
        assert post_renewal_retrieve['success'], "Session data retrieval after renewal failed"
        
        post_renewal_data = post_renewal_retrieve['data']
        assert post_renewal_data['workflow_state']['workflow_id'] == session_data['workflow_state']['workflow_id'], "Session data lost after renewal"
        
        # Performance validation
        operation_times = [op['response_time_ms'] for op in operation_results]
        average_operation_time = sum(operation_times) / len(operation_times)
        
        baseline_time = NODEJS_BASELINE_METRICS['response_times']['api_endpoint_avg']
        performance_variance = (average_operation_time - baseline_time) / baseline_time
        
        assert abs(performance_variance) <= PERFORMANCE_BASELINE_THRESHOLD, (
            f"Session operation performance variance {performance_variance:.2%} exceeds threshold"
        )
        
        logger.info(
            "Session persistence across complex workflow test completed successfully",
            operations_completed=len(operation_results),
            session_renewals=1,
            average_operation_time_ms=average_operation_time,
            performance_variance=f"{performance_variance:.2%}",
            session_data_integrity_maintained=True
        )
    
    def test_concurrent_session_isolation(
        self,
        e2e_comprehensive_environment: Dict[str, Any],
        performance_monitor: PerformanceMetrics
    ):
        """
        Test session isolation between concurrent users.
        
        Validates:
        - Session data isolation between users per Section 6.4.1
        - No session data leakage per Section 6.4.1
        - Concurrent session performance per Section 0.1.1
        - Redis session backend scalability per Section 6.4.1
        
        Args:
            e2e_comprehensive_environment: Complete E2E testing environment
            performance_monitor: Performance metrics tracking
        """
        client = e2e_comprehensive_environment['client']
        reporter = e2e_comprehensive_environment['reporter']
        
        logger.info("Starting concurrent session isolation test")
        
        # Create multiple user contexts
        user_contexts = []
        
        for i in range(3):
            unique_id = uuid.uuid4().hex[:8]
            user_email = f"concurrent.user.{i}.{unique_id}@example.com"
            
            helper = UserJourneyTestHelper(client, performance_monitor, reporter)
            
            # Simulate user registration
            registration_result = helper.access_protected_resource(
                '/auth/register',
                method='POST',
                data={
                    'email': user_email,
                    'name': f'Concurrent User {i}',
                    'password': TEST_USER_PASSWORD
                },
                expected_status=201
            )
            
            if registration_result['success']:
                # Authenticate user
                auth_result = helper.authenticate_user(
                    email=user_email,
                    password=TEST_USER_PASSWORD
                )
                
                if auth_result['success']:
                    user_contexts.append({
                        'user_id': i,
                        'email': user_email,
                        'helper': helper,
                        'unique_data': f'user_{i}_data_{unique_id}'
                    })
        
        assert len(user_contexts) >= 2, "Insufficient user contexts created for isolation testing"
        
        # Step 1: Store Unique Session Data for Each User
        for context in user_contexts:
            session_data = {
                'user_identity': context['unique_data'],
                'private_settings': {
                    'secret_key': f"secret_{context['user_id']}_{uuid.uuid4().hex}",
                    'private_notes': f"Private notes for user {context['user_id']}",
                    'personal_data': {
                        'favorite_color': ['red', 'blue', 'green'][context['user_id'] % 3],
                        'user_number': context['user_id']
                    }
                }
            }
            
            store_result = context['helper'].access_protected_resource(
                '/api/session/store',
                method='POST',
                data=session_data,
                expected_status=200
            )
            
            assert store_result['success'], f"Session storage failed for user {context['user_id']}"
            context['stored_data'] = session_data
        
        # Step 2: Perform Concurrent Operations
        import threading
        import queue
        
        results_queue = queue.Queue()
        
        def user_operation_thread(context):
            """Execute user operations in separate thread."""
            try:
                # Perform multiple operations
                operations = [
                    ('session_retrieve', '/api/session/retrieve', 'GET', None),
                    ('profile_update', '/api/users/profile', 'PUT', {'last_active': datetime.now(timezone.utc).isoformat()}),
                    ('session_retrieve_again', '/api/session/retrieve', 'GET', None)
                ]
                
                thread_results = []
                
                for op_name, endpoint, method, data in operations:
                    result = context['helper'].access_protected_resource(
                        endpoint,
                        method=method,
                        data=data,
                        expected_status=200
                    )
                    
                    thread_results.append({
                        'user_id': context['user_id'],
                        'operation': op_name,
                        'success': result['success'],
                        'response_time_ms': result['response_time_ms'],
                        'data': result['data']
                    })
                
                results_queue.put(thread_results)
                
            except Exception as e:
                results_queue.put({'error': str(e), 'user_id': context['user_id']})
        
        # Execute concurrent operations
        threads = []
        for context in user_contexts:
            thread = threading.Thread(target=user_operation_thread, args=(context,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Collect results
        all_results = []
        while not results_queue.empty():
            result = results_queue.get()
            if 'error' in result:
                logger.error(f"Thread error for user {result['user_id']}: {result['error']}")
            else:
                all_results.extend(result)
        
        # Step 3: Validate Session Isolation
        session_retrievals = [r for r in all_results if r['operation'] in ['session_retrieve', 'session_retrieve_again']]
        
        # Group retrievals by user
        user_sessions = {}
        for retrieval in session_retrievals:
            user_id = retrieval['user_id']
            if user_id not in user_sessions:
                user_sessions[user_id] = []
            user_sessions[user_id].append(retrieval)
        
        # Validate each user only sees their own data
        for user_id, sessions in user_sessions.items():
            context = next(c for c in user_contexts if c['user_id'] == user_id)
            expected_data = context['stored_data']
            
            for session in sessions:
                if session['success'] and session['data']:
                    retrieved_data = session['data']
                    
                    # Validate user identity matches
                    assert retrieved_data['user_identity'] == expected_data['user_identity'], (
                        f"Session data leaked: User {user_id} seeing incorrect identity"
                    )
                    
                    # Validate private settings match
                    assert retrieved_data['private_settings']['secret_key'] == expected_data['private_settings']['secret_key'], (
                        f"Session data leaked: User {user_id} seeing incorrect secret"
                    )
                    
                    assert retrieved_data['private_settings']['personal_data']['user_number'] == user_id, (
                        f"Session data leaked: User {user_id} seeing incorrect user number"
                    )
        
        # Step 4: Cross-User Validation (Ensure No Data Leakage)
        all_secret_keys = []
        all_user_numbers = []
        
        for user_id, sessions in user_sessions.items():
            for session in sessions:
                if session['success'] and session['data']:
                    secret_key = session['data']['private_settings']['secret_key']
                    user_number = session['data']['private_settings']['personal_data']['user_number']
                    
                    all_secret_keys.append(secret_key)
                    all_user_numbers.append(user_number)
        
        # Validate no duplicate secrets (each user should have unique secrets)
        assert len(set(all_secret_keys)) == len(user_contexts), "Session data leaked: Duplicate secret keys found"
        
        # Validate user numbers match user IDs
        for user_number in all_user_numbers:
            assert user_number in [c['user_id'] for c in user_contexts], f"Invalid user number found: {user_number}"
        
        # Performance validation
        successful_operations = [r for r in all_results if r['success']]
        if successful_operations:
            average_response_time = sum(r['response_time_ms'] for r in successful_operations) / len(successful_operations)
            
            baseline_time = NODEJS_BASELINE_METRICS['response_times']['api_endpoint_avg']
            performance_variance = (average_response_time - baseline_time) / baseline_time
            
            assert abs(performance_variance) <= PERFORMANCE_BASELINE_THRESHOLD * 1.2, (
                f"Concurrent session performance variance {performance_variance:.2%} exceeds extended threshold"
            )
        
        logger.info(
            "Concurrent session isolation test completed successfully",
            concurrent_users=len(user_contexts),
            total_operations=len(all_results),
            successful_operations=len(successful_operations),
            session_isolation_verified=True,
            data_leakage_detected=False
        )


# =============================================================================
# Test Execution Markers and Configuration
# =============================================================================

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.timeout(300),  # 5 minute timeout for E2E tests
    pytest.mark.usefixtures("e2e_comprehensive_environment")
]

# Configure test execution order for optimal resource usage
pytest_collection_order = [
    'test_authentication_to_secured_access_journey',
    'test_session_persistence_across_complex_workflow',
    'test_complete_business_transaction_journey', 
    'test_user_registration_to_project_collaboration_journey',
    'test_concurrent_session_isolation',
    'test_error_propagation_and_recovery_journey',
    'test_concurrent_user_authentication_performance',
    'test_api_endpoint_performance_with_apache_bench'
]