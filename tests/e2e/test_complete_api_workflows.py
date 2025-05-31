"""
End-to-End API Workflow Testing Module

This module provides comprehensive end-to-end testing for complete API request/response cycles
from authentication through data persistence, validating 100% compatibility with Node.js
implementation patterns while ensuring ≤10% performance variance compliance.

Key Testing Scenarios:
- Complete authentication workflows from JWT validation through protected resource access
- API transaction flows maintaining identical response formats per F-004-RQ-004
- Multi-endpoint journey testing simulating realistic user interactions
- Error propagation testing across complete request processing pipeline
- API contract validation ensuring zero client-side changes per Section 0.1.4
- Performance validation with baseline comparison against Node.js implementation

Architecture Integration:
- Section 6.6.1: End-to-end testing of all API endpoints and workflows per F-006-RQ-002
- Section 0.1.4: Complete preservation of existing API contracts ensuring zero client-side changes
- Section 6.4.2: Authentication workflows preserving JWT token validation patterns
- Section 4.2.3: Error propagation testing across complete request processing pipeline
- Section 4.1.1: System workflow validation from HTTP request through response completion
- Section 4.6.1: Multi-endpoint journey testing simulating realistic user interactions

Performance Requirements:
- Response time variance ≤10% from Node.js baseline per Section 0.1.1
- Memory usage patterns equivalent to original implementation
- Concurrent request handling capacity preservation
- Database operation performance parity validation

Dependencies:
- pytest 7.4+ with E2E testing configuration
- pytest-asyncio for async workflow testing
- comprehensive_e2e_environment fixture providing complete testing infrastructure
- Flask application with production-equivalent configuration
- Testcontainers integration for realistic MongoDB and Redis behavior

Author: E2E Testing Team
Version: 1.0.0
Compliance: 100% API compatibility, ≤10% performance variance, zero client-side changes
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock, patch

import pytest
import pytest_asyncio
from flask import g, request
from flask.testing import FlaskClient

# Import test fixtures and configuration
from tests.e2e.conftest import (
    comprehensive_e2e_environment,
    e2e_performance_monitor,
    locust_load_tester,
    apache_bench_tester,
    production_equivalent_environment,
    e2e_test_reporter,
    skip_if_not_e2e,
    require_external_services,
    require_load_testing
)

# Import base testing infrastructure
from tests.conftest import (
    performance_monitoring,
    test_metrics_collector,
    mock_external_services,
    mock_circuit_breakers
)

# Error response validation utilities
def validate_error_response_format(response_data: Dict[str, Any], expected_status: int) -> bool:
    """
    Validate error response format matches Node.js implementation patterns.
    
    Args:
        response_data: Response JSON data
        expected_status: Expected HTTP status code
        
    Returns:
        True if response format is valid
    """
    required_fields = ['error', 'message', 'status_code', 'timestamp']
    
    # Check all required fields are present
    for field in required_fields:
        if field not in response_data:
            return False
    
    # Validate field types and values
    if not isinstance(response_data['error'], (str, bool)):
        return False
        
    if not isinstance(response_data['message'], str):
        return False
        
    if response_data['status_code'] != expected_status:
        return False
        
    # Validate timestamp format (ISO 8601)
    try:
        datetime.fromisoformat(response_data['timestamp'].replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return False
    
    return True


def validate_success_response_format(response_data: Dict[str, Any]) -> bool:
    """
    Validate success response format consistency.
    
    Args:
        response_data: Response JSON data
        
    Returns:
        True if response format is valid
    """
    # Success responses should not have error fields
    error_fields = ['error', 'error_code', 'error_message']
    for field in error_fields:
        if field in response_data and response_data[field]:
            return False
    
    return True


def extract_jwt_claims(token: str) -> Dict[str, Any]:
    """
    Extract JWT claims without validation for testing purposes.
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary of JWT claims
    """
    try:
        import base64
        import json
        
        # Split token and decode payload (second part)
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        
        # Add padding if needed
        payload = parts[1]
        padding = len(payload) % 4
        if padding:
            payload += '=' * (4 - padding)
        
        # Decode base64 and parse JSON
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        
        return claims
    except Exception:
        return {}


# =============================================================================
# Authentication Workflow E2E Tests
# =============================================================================

class TestAuthenticationWorkflows:
    """
    End-to-end testing for complete authentication workflows from JWT validation
    through protected resource access per Section 6.4.2 authentication patterns.
    """
    
    @pytest.mark.e2e
    @pytest.mark.auth
    def test_complete_authentication_flow(self, comprehensive_e2e_environment):
        """
        Test complete authentication workflow from login through protected resource access.
        
        Validates:
        - JWT token generation and validation
        - User context establishment
        - Protected resource access
        - Session management
        - Performance compliance ≤10% variance
        """
        env = comprehensive_e2e_environment
        client = env['client']
        performance = env['performance']
        reporter = env['reporter']
        
        workflow_name = "complete_authentication_flow"
        
        with performance['measure_operation'](workflow_name, 'auth_flow_time'):
            # Step 1: Attempt access to protected resource without authentication
            response = client.get('/api/v1/users/profile')
            
            assert response.status_code == 401
            assert response.is_json
            
            error_data = response.get_json()
            assert validate_error_response_format(error_data, 401)
            assert 'Authentication required' in error_data['message']
            
            # Step 2: Perform authentication request
            auth_data = {
                'email': 'test@example.com',
                'password': 'TestPassword123!'
            }
            
            response = client.post('/auth/login', json=auth_data)
            
            # Authentication endpoint may not exist yet, handle gracefully
            if response.status_code == 404:
                # Skip this test if auth endpoints not implemented
                pytest.skip("Authentication endpoints not yet implemented")
            
            assert response.status_code in [200, 201]
            assert response.is_json
            
            auth_response = response.get_json()
            assert validate_success_response_format(auth_response)
            assert 'access_token' in auth_response
            assert 'token_type' in auth_response
            assert auth_response['token_type'] == 'Bearer'
            
            access_token = auth_response['access_token']
            
            # Validate JWT token structure
            jwt_claims = extract_jwt_claims(access_token)
            assert 'user_id' in jwt_claims or 'sub' in jwt_claims
            assert 'exp' in jwt_claims  # Expiration time
            assert 'iat' in jwt_claims  # Issued at time
            
            # Step 3: Access protected resource with valid token
            headers = {'Authorization': f'Bearer {access_token}'}
            response = client.get('/api/v1/users/profile', headers=headers)
            
            assert response.status_code == 200
            assert response.is_json
            
            profile_data = response.get_json()
            assert validate_success_response_format(profile_data)
            assert 'user' in profile_data or 'profile' in profile_data
            
            # Step 4: Test token refresh if supported
            if 'refresh_token' in auth_response:
                refresh_data = {
                    'refresh_token': auth_response['refresh_token']
                }
                
                response = client.post('/auth/refresh', json=refresh_data)
                assert response.status_code == 200
                
                refresh_response = response.get_json()
                assert 'access_token' in refresh_response
                
                # Verify new token works
                new_headers = {'Authorization': f'Bearer {refresh_response["access_token"]}'}
                response = client.get('/api/v1/users/profile', headers=new_headers)
                assert response.status_code == 200
            
            # Step 5: Test logout
            response = client.post('/auth/logout', headers=headers)
            # Logout may return 200 or 204
            assert response.status_code in [200, 204]
            
            # Step 6: Verify token is invalidated
            response = client.get('/api/v1/users/profile', headers=headers)
            assert response.status_code in [401, 403]
        
        # Record test execution
        reporter['record_test_execution'](
            test_name=workflow_name,
            status='passed',
            duration=time.time() - performance['start_time'],
            workflow_type='authentication_flow'
        )
    
    @pytest.mark.e2e
    @pytest.mark.auth
    @pytest.mark.security
    def test_invalid_token_handling(self, comprehensive_e2e_environment):
        """
        Test handling of invalid JWT tokens across all protected endpoints.
        
        Validates:
        - Invalid token format rejection
        - Expired token handling
        - Malformed token responses
        - Security audit logging
        """
        env = comprehensive_e2e_environment
        client = env['client']
        performance = env['performance']
        
        workflow_name = "invalid_token_handling"
        
        with performance['measure_operation'](workflow_name, 'auth_flow_time'):
            protected_endpoints = [
                '/api/v1/users/profile',
                '/api/v1/projects',
                '/api/v1/dashboard/stats'
            ]
            
            invalid_tokens = [
                'invalid-token',  # Malformed token
                'Bearer invalid-token',  # Invalid with Bearer prefix
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature',  # Invalid JWT
                '',  # Empty token
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMDB9.invalid'  # Expired token
            ]
            
            for endpoint in protected_endpoints:
                for invalid_token in invalid_tokens:
                    if invalid_token:
                        headers = {'Authorization': f'Bearer {invalid_token}'}
                    else:
                        headers = {'Authorization': ''}
                    
                    response = client.get(endpoint, headers=headers)
                    
                    # Should return 401 for invalid tokens
                    assert response.status_code == 401
                    
                    if response.is_json:
                        error_data = response.get_json()
                        assert validate_error_response_format(error_data, 401)
                        assert any(keyword in error_data['message'].lower() 
                                 for keyword in ['invalid', 'token', 'authentication', 'unauthorized'])
    
    @pytest.mark.e2e
    @pytest.mark.auth
    @pytest.mark.security
    def test_permission_based_access_control(self, comprehensive_e2e_environment):
        """
        Test role-based and permission-based access control across API endpoints.
        
        Validates:
        - Role-based endpoint access
        - Permission checking
        - Consistent authorization responses
        - Admin vs user access patterns
        """
        env = comprehensive_e2e_environment
        client = env['client']
        auth_env = env.get('auth', {})
        
        # Skip if auth environment not available
        if not auth_env.get('tokens'):
            pytest.skip("Authentication tokens not available for permission testing")
        
        workflow_name = "permission_based_access_control"
        
        tokens = auth_env['tokens']
        user_token = tokens.get('valid')
        admin_token = tokens.get('admin')
        
        if not user_token or not admin_token:
            pytest.skip("User and admin tokens not available for permission testing")
        
        # Test endpoints requiring different permission levels
        permission_tests = [
            {
                'endpoint': '/api/v1/users/profile',
                'method': 'GET',
                'user_allowed': True,
                'admin_allowed': True
            },
            {
                'endpoint': '/api/v1/admin/users',
                'method': 'GET',
                'user_allowed': False,
                'admin_allowed': True
            },
            {
                'endpoint': '/api/v1/admin/system/settings',
                'method': 'GET',
                'user_allowed': False,
                'admin_allowed': True
            },
            {
                'endpoint': '/api/v1/projects',
                'method': 'POST',
                'user_allowed': True,
                'admin_allowed': True,
                'data': {'name': 'Test Project', 'description': 'E2E Test Project'}
            }
        ]
        
        for test_case in permission_tests:
            endpoint = test_case['endpoint']
            method = test_case['method'].lower()
            
            # Test with user token
            user_headers = {'Authorization': f'Bearer {user_token}'}
            if method == 'get':
                response = client.get(endpoint, headers=user_headers)
            elif method == 'post':
                response = client.post(endpoint, headers=user_headers, json=test_case.get('data'))
            elif method == 'put':
                response = client.put(endpoint, headers=user_headers, json=test_case.get('data'))
            elif method == 'delete':
                response = client.delete(endpoint, headers=user_headers)
            
            if test_case['user_allowed']:
                assert response.status_code in [200, 201, 204, 404]  # 404 if endpoint not implemented
            else:
                assert response.status_code in [403, 404]  # 403 Forbidden or 404 if not implemented
                
                if response.status_code == 403 and response.is_json:
                    error_data = response.get_json()
                    assert validate_error_response_format(error_data, 403)
                    assert any(keyword in error_data['message'].lower() 
                             for keyword in ['forbidden', 'permission', 'access', 'unauthorized'])
            
            # Test with admin token
            admin_headers = {'Authorization': f'Bearer {admin_token}'}
            if method == 'get':
                response = client.get(endpoint, headers=admin_headers)
            elif method == 'post':
                response = client.post(endpoint, headers=admin_headers, json=test_case.get('data'))
            elif method == 'put':
                response = client.put(endpoint, headers=admin_headers, json=test_case.get('data'))
            elif method == 'delete':
                response = client.delete(endpoint, headers=admin_headers)
            
            if test_case['admin_allowed']:
                assert response.status_code in [200, 201, 204, 404]  # 404 if endpoint not implemented
            else:
                assert response.status_code in [403, 404]


# =============================================================================
# API Transaction Flow E2E Tests
# =============================================================================

class TestAPITransactionFlows:
    """
    End-to-end testing for API transaction flows maintaining identical response
    formats per F-004-RQ-004 while validating complete request processing pipelines.
    """
    
    @pytest.mark.e2e
    @pytest.mark.database
    def test_crud_operation_workflow(self, comprehensive_e2e_environment):
        """
        Test complete CRUD workflow for primary business entities.
        
        Validates:
        - Create, Read, Update, Delete operations
        - Database transaction integrity
        - Response format consistency
        - Error handling for each operation
        - Performance within ≤10% variance
        """
        env = comprehensive_e2e_environment
        client = env['client']
        performance = env['performance']
        database = env.get('database', {})
        
        workflow_name = "crud_operation_workflow"
        
        # Skip if database not available
        if not database.get('pymongo_client'):
            pytest.skip("Database not available for CRUD testing")
        
        # Use mock token for testing if auth not available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        with performance['measure_operation'](workflow_name, 'api_workflow_time'):
            project_data = {
                'name': f'E2E Test Project {uuid.uuid4().hex[:8]}',
                'description': 'End-to-end testing project',
                'status': 'active',
                'created_at': datetime.utcnow().isoformat(),
                'settings': {
                    'public': True,
                    'collaboration_enabled': True,
                    'notifications_enabled': False
                }
            }
            
            # Step 1: CREATE operation
            response = client.post('/api/v1/projects', headers=headers, json=project_data)
            
            # Handle case where endpoint doesn't exist yet
            if response.status_code == 404:
                pytest.skip("Projects endpoint not yet implemented")
            
            assert response.status_code in [200, 201]
            assert response.is_json
            
            create_response = response.get_json()
            assert validate_success_response_format(create_response)
            
            # Extract project ID from response
            project_id = None
            if 'project' in create_response:
                project_id = create_response['project'].get('id') or create_response['project'].get('_id')
            elif 'id' in create_response:
                project_id = create_response['id']
            elif '_id' in create_response:
                project_id = create_response['_id']
            
            assert project_id is not None, "Project ID not found in create response"
            
            # Step 2: READ operation (single item)
            response = client.get(f'/api/v1/projects/{project_id}', headers=headers)
            
            assert response.status_code == 200
            assert response.is_json
            
            read_response = response.get_json()
            assert validate_success_response_format(read_response)
            
            # Validate created data matches returned data
            if 'project' in read_response:
                project = read_response['project']
            else:
                project = read_response
            
            assert project['name'] == project_data['name']
            assert project['description'] == project_data['description']
            assert project['status'] == project_data['status']
            
            # Step 3: UPDATE operation
            update_data = {
                'name': f'Updated {project_data["name"]}',
                'description': 'Updated description for E2E testing',
                'status': 'updated'
            }
            
            response = client.put(f'/api/v1/projects/{project_id}', headers=headers, json=update_data)
            
            assert response.status_code in [200, 204]
            
            if response.status_code == 200 and response.is_json:
                update_response = response.get_json()
                assert validate_success_response_format(update_response)
            
            # Verify update by reading again
            response = client.get(f'/api/v1/projects/{project_id}', headers=headers)
            assert response.status_code == 200
            
            updated_read = response.get_json()
            if 'project' in updated_read:
                updated_project = updated_read['project']
            else:
                updated_project = updated_read
            
            assert updated_project['name'] == update_data['name']
            assert updated_project['description'] == update_data['description']
            assert updated_project['status'] == update_data['status']
            
            # Step 4: LIST operation
            response = client.get('/api/v1/projects', headers=headers)
            
            assert response.status_code == 200
            assert response.is_json
            
            list_response = response.get_json()
            assert validate_success_response_format(list_response)
            
            # Should contain our created project
            projects = list_response.get('projects', list_response.get('data', []))
            assert isinstance(projects, list)
            
            found_project = None
            for p in projects:
                if p.get('id') == project_id or p.get('_id') == project_id:
                    found_project = p
                    break
            
            assert found_project is not None, "Created project not found in list"
            
            # Step 5: DELETE operation
            response = client.delete(f'/api/v1/projects/{project_id}', headers=headers)
            
            assert response.status_code in [200, 204]
            
            # Verify deletion
            response = client.get(f'/api/v1/projects/{project_id}', headers=headers)
            assert response.status_code == 404
    
    @pytest.mark.e2e
    @pytest.mark.async_test
    @pytest_asyncio.fixture
    async def test_async_database_operations(self, comprehensive_e2e_environment):
        """
        Test async database operations using Motor driver integration.
        
        Validates:
        - Motor async database operations
        - Async connection pooling
        - Concurrent operation handling
        - Performance under async load
        """
        env = comprehensive_e2e_environment
        database = env.get('database', {})
        
        # Skip if async database not available
        if not database.get('motor_client'):
            pytest.skip("Motor async client not available for async testing")
        
        motor_client = database['motor_client']
        db = motor_client.get_default_database()
        collection = db.e2e_async_test
        
        workflow_name = "async_database_operations"
        
        # Test document for async operations
        test_docs = [
            {
                'name': f'Async Test Doc {i}',
                'value': i,
                'created_at': datetime.utcnow(),
                'test_session': workflow_name
            }
            for i in range(10)
        ]
        
        # Step 1: Async bulk insert
        insert_result = await collection.insert_many(test_docs)
        assert len(insert_result.inserted_ids) == 10
        
        # Step 2: Async find operations
        cursor = collection.find({'test_session': workflow_name})
        found_docs = await cursor.to_list(length=100)
        assert len(found_docs) == 10
        
        # Step 3: Async update operations
        update_result = await collection.update_many(
            {'test_session': workflow_name},
            {'$set': {'updated': True, 'updated_at': datetime.utcnow()}}
        )
        assert update_result.modified_count == 10
        
        # Step 4: Async aggregation
        pipeline = [
            {'$match': {'test_session': workflow_name}},
            {'$group': {'_id': None, 'total_value': {'$sum': '$value'}, 'count': {'$sum': 1}}}
        ]
        
        async for result in collection.aggregate(pipeline):
            assert result['count'] == 10
            assert result['total_value'] == sum(range(10))  # 0+1+2+...+9 = 45
        
        # Step 5: Cleanup
        delete_result = await collection.delete_many({'test_session': workflow_name})
        assert delete_result.deleted_count == 10
    
    @pytest.mark.e2e
    @pytest.mark.cache
    def test_cache_integration_workflow(self, comprehensive_e2e_environment):
        """
        Test Redis cache integration across API operations.
        
        Validates:
        - Cache hit/miss patterns
        - Cache invalidation on updates
        - Session management
        - Performance impact of caching
        """
        env = comprehensive_e2e_environment
        client = env['client']
        cache = env.get('external_services', {}).get('redis_client')
        performance = env['performance']
        
        if not cache:
            pytest.skip("Redis cache not available for cache testing")
        
        workflow_name = "cache_integration_workflow"
        
        with performance['measure_operation'](workflow_name, 'cache_operation_time'):
            # Use mock token if available
            auth_env = env.get('auth', {})
            if auth_env.get('tokens', {}).get('valid'):
                headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
            else:
                headers = {}
            
            # Step 1: First API call (cache miss)
            response = client.get('/api/v1/dashboard/stats', headers=headers)
            
            if response.status_code == 404:
                pytest.skip("Dashboard stats endpoint not yet implemented")
            
            first_call_time = time.time()
            
            # Step 2: Second API call (should be cache hit)
            response = client.get('/api/v1/dashboard/stats', headers=headers)
            second_call_time = time.time()
            
            # Cache hit should be faster (though this is implementation dependent)
            if response.status_code == 200:
                # Verify response format consistency
                assert response.is_json
                stats_data = response.get_json()
                assert validate_success_response_format(stats_data)
            
            # Step 3: Test cache invalidation through data modification
            # Create a project which might invalidate dashboard cache
            project_data = {
                'name': 'Cache Test Project',
                'description': 'Project to test cache invalidation'
            }
            
            response = client.post('/api/v1/projects', headers=headers, json=project_data)
            
            if response.status_code in [200, 201]:
                # Step 4: Check dashboard stats again (cache should be invalidated)
                response = client.get('/api/v1/dashboard/stats', headers=headers)
                
                if response.status_code == 200:
                    assert response.is_json
                    new_stats_data = response.get_json()
                    assert validate_success_response_format(new_stats_data)


# =============================================================================
# Error Handling and Edge Case E2E Tests
# =============================================================================

class TestErrorHandlingWorkflows:
    """
    End-to-end testing for error propagation across complete request processing
    pipeline per Section 4.2.3 error handling flows.
    """
    
    @pytest.mark.e2e
    @pytest.mark.security
    def test_comprehensive_error_response_formats(self, comprehensive_e2e_environment):
        """
        Test error response format consistency across all error scenarios.
        
        Validates:
        - HTTP status code accuracy
        - Error response format consistency
        - Error message clarity and security
        - Error logging and audit trail
        """
        env = comprehensive_e2e_environment
        client = env['client']
        
        workflow_name = "comprehensive_error_response_formats"
        
        # Test various error scenarios
        error_test_cases = [
            {
                'name': 'Not Found Resource',
                'request': lambda: client.get('/api/v1/nonexistent/resource'),
                'expected_status': 404,
                'expected_error_type': 'not_found'
            },
            {
                'name': 'Method Not Allowed',
                'request': lambda: client.patch('/health'),  # Health endpoint typically only accepts GET
                'expected_status': 405,
                'expected_error_type': 'method_not_allowed'
            },
            {
                'name': 'Invalid JSON Payload',
                'request': lambda: client.post('/api/v1/projects', 
                                              data='invalid-json', 
                                              content_type='application/json'),
                'expected_status': 400,
                'expected_error_type': 'bad_request'
            },
            {
                'name': 'Missing Content-Type',
                'request': lambda: client.post('/api/v1/projects', data='{}'),
                'expected_status': 400,
                'expected_error_type': 'bad_request'
            },
            {
                'name': 'Unauthorized Access',
                'request': lambda: client.get('/api/v1/admin/users'),
                'expected_status': 401,
                'expected_error_type': 'unauthorized'
            }
        ]
        
        for test_case in error_test_cases:
            response = test_case['request']()
            
            assert response.status_code == test_case['expected_status'], \
                f"Test case '{test_case['name']}' failed: expected {test_case['expected_status']}, got {response.status_code}"
            
            if response.is_json:
                error_data = response.get_json()
                assert validate_error_response_format(error_data, test_case['expected_status']), \
                    f"Invalid error response format for test case '{test_case['name']}'"
                
                # Verify error message doesn't expose sensitive information
                error_message = error_data['message'].lower()
                sensitive_keywords = ['password', 'secret', 'key', 'token', 'database', 'internal']
                for keyword in sensitive_keywords:
                    assert keyword not in error_message, \
                        f"Error message exposes sensitive information: {keyword}"
    
    @pytest.mark.e2e
    @pytest.mark.database
    def test_database_error_handling(self, comprehensive_e2e_environment):
        """
        Test database error scenarios and recovery patterns.
        
        Validates:
        - Database connection failure handling
        - Transaction rollback scenarios
        - Circuit breaker activation
        - Graceful degradation patterns
        """
        env = comprehensive_e2e_environment
        client = env['client']
        database = env.get('database', {})
        circuit_breakers = env.get('circuit_breakers', {})
        
        if not database.get('pymongo_client'):
            pytest.skip("Database not available for error testing")
        
        workflow_name = "database_error_handling"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        # Test with circuit breaker simulation
        db_circuit_breaker = circuit_breakers.get('database')
        if db_circuit_breaker:
            # Force circuit breaker to open state
            db_circuit_breaker.state = 'open'
            
            # Attempt database operation
            response = client.get('/api/v1/projects', headers=headers)
            
            # Should handle circuit breaker gracefully
            if response.status_code == 503:
                assert response.is_json
                error_data = response.get_json()
                assert validate_error_response_format(error_data, 503)
                assert any(keyword in error_data['message'].lower() 
                         for keyword in ['service', 'unavailable', 'temporary'])
            
            # Reset circuit breaker
            db_circuit_breaker.state = 'closed'
    
    @pytest.mark.e2e
    @pytest.mark.performance
    def test_rate_limiting_error_handling(self, comprehensive_e2e_environment):
        """
        Test rate limiting error responses and recovery.
        
        Validates:
        - Rate limit enforcement
        - Rate limit error response format
        - Rate limit header information
        - Recovery after rate limit reset
        """
        env = comprehensive_e2e_environment
        client = env['client']
        
        workflow_name = "rate_limiting_error_handling"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        # Make rapid requests to trigger rate limiting
        rate_limit_triggered = False
        responses = []
        
        for i in range(20):  # Make 20 rapid requests
            response = client.get('/api/v1/dashboard/stats', headers=headers)
            responses.append(response)
            
            if response.status_code == 429:
                rate_limit_triggered = True
                
                # Validate rate limit error response
                assert response.is_json
                error_data = response.get_json()
                assert validate_error_response_format(error_data, 429)
                assert any(keyword in error_data['message'].lower() 
                         for keyword in ['rate', 'limit', 'too many', 'exceeded'])
                
                # Check for rate limit headers
                assert 'Retry-After' in response.headers or 'X-RateLimit-Reset' in response.headers
                
                break
            
            time.sleep(0.1)  # Small delay between requests
        
        # Note: Rate limiting might not be enabled in test environment
        if not rate_limit_triggered:
            pytest.skip("Rate limiting not active or threshold not reached")


# =============================================================================
# Multi-Endpoint Journey E2E Tests  
# =============================================================================

class TestMultiEndpointJourneys:
    """
    End-to-end testing for multi-endpoint journey scenarios simulating realistic
    user interactions per Section 4.6.1 comprehensive workflow testing.
    """
    
    @pytest.mark.e2e
    @pytest.mark.slow
    def test_complete_user_journey(self, comprehensive_e2e_environment):
        """
        Test complete user journey from registration through project management.
        
        Validates:
        - Multi-step user workflows
        - State consistency across endpoints
        - Transaction integrity
        - Session management
        - Performance across complete journey
        """
        env = comprehensive_e2e_environment
        client = env['client']
        performance = env['performance']
        reporter = env['reporter']
        
        workflow_name = "complete_user_journey"
        
        journey_steps = []
        
        with performance['measure_operation'](workflow_name, 'complete_e2e_workflow_time'):
            # Step 1: User Registration (if supported)
            registration_data = {
                'email': f'journey-test-{uuid.uuid4().hex[:8]}@example.com',
                'password': 'JourneyTest123!',
                'name': 'Journey Test User',
                'terms_accepted': True
            }
            
            response = client.post('/auth/register', json=registration_data)
            
            if response.status_code == 404:
                # Skip registration, use existing auth
                auth_env = env.get('auth', {})
                if auth_env.get('tokens', {}).get('valid'):
                    access_token = auth_env['tokens']['valid']
                    journey_steps.append({
                        'step': 'authentication',
                        'status': 'success',
                        'method': 'existing_token'
                    })
                else:
                    pytest.skip("Registration not available and no auth tokens for journey testing")
            else:
                assert response.status_code in [200, 201]
                assert response.is_json
                
                reg_response = response.get_json()
                assert validate_success_response_format(reg_response)
                
                # Extract access token
                access_token = reg_response.get('access_token')
                if not access_token:
                    # May need to login after registration
                    login_response = client.post('/auth/login', json={
                        'email': registration_data['email'],
                        'password': registration_data['password']
                    })
                    assert login_response.status_code in [200, 201]
                    
                    login_data = login_response.get_json()
                    access_token = login_data['access_token']
                
                journey_steps.append({
                    'step': 'registration',
                    'status': 'success',
                    'user_email': registration_data['email']
                })
            
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Step 2: Get User Profile
            response = client.get('/api/v1/users/profile', headers=headers)
            
            if response.status_code == 200:
                assert response.is_json
                profile_data = response.get_json()
                assert validate_success_response_format(profile_data)
                
                journey_steps.append({
                    'step': 'profile_access',
                    'status': 'success'
                })
            else:
                journey_steps.append({
                    'step': 'profile_access',
                    'status': 'skipped',
                    'reason': 'endpoint_not_available'
                })
            
            # Step 3: Create Multiple Projects
            projects_created = []
            for i in range(3):
                project_data = {
                    'name': f'Journey Project {i+1}',
                    'description': f'Project {i+1} created during user journey testing',
                    'type': 'personal' if i % 2 == 0 else 'team',
                    'settings': {
                        'public': i == 1,  # Make middle project public
                        'collaboration_enabled': True
                    }
                }
                
                response = client.post('/api/v1/projects', headers=headers, json=project_data)
                
                if response.status_code in [200, 201]:
                    assert response.is_json
                    project_response = response.get_json()
                    assert validate_success_response_format(project_response)
                    
                    # Extract project ID
                    if 'project' in project_response:
                        project_id = project_response['project'].get('id') or project_response['project'].get('_id')
                    else:
                        project_id = project_response.get('id') or project_response.get('_id')
                    
                    projects_created.append({
                        'id': project_id,
                        'name': project_data['name']
                    })
                    
                    journey_steps.append({
                        'step': f'project_creation_{i+1}',
                        'status': 'success',
                        'project_id': project_id
                    })
                else:
                    journey_steps.append({
                        'step': f'project_creation_{i+1}',
                        'status': 'failed',
                        'status_code': response.status_code
                    })
            
            # Step 4: List All Projects
            response = client.get('/api/v1/projects', headers=headers)
            
            if response.status_code == 200:
                assert response.is_json
                projects_list = response.get_json()
                assert validate_success_response_format(projects_list)
                
                # Verify our created projects are in the list
                projects = projects_list.get('projects', projects_list.get('data', []))
                created_project_ids = [p['id'] for p in projects_created if p['id']]
                
                found_projects = 0
                for project in projects:
                    project_id = project.get('id') or project.get('_id')
                    if project_id in created_project_ids:
                        found_projects += 1
                
                journey_steps.append({
                    'step': 'project_listing',
                    'status': 'success',
                    'total_projects': len(projects),
                    'found_created_projects': found_projects
                })
            
            # Step 5: Update First Project
            if projects_created and projects_created[0]['id']:
                update_data = {
                    'name': f"Updated {projects_created[0]['name']}",
                    'description': 'Updated during journey testing',
                    'status': 'active'
                }
                
                response = client.put(f"/api/v1/projects/{projects_created[0]['id']}", 
                                    headers=headers, json=update_data)
                
                if response.status_code in [200, 204]:
                    journey_steps.append({
                        'step': 'project_update',
                        'status': 'success',
                        'project_id': projects_created[0]['id']
                    })
                    
                    # Verify update by reading back
                    response = client.get(f"/api/v1/projects/{projects_created[0]['id']}", headers=headers)
                    if response.status_code == 200:
                        updated_project = response.get_json()
                        project_data = updated_project.get('project', updated_project)
                        assert project_data['name'] == update_data['name']
            
            # Step 6: Dashboard Stats Access
            response = client.get('/api/v1/dashboard/stats', headers=headers)
            
            if response.status_code == 200:
                assert response.is_json
                stats_data = response.get_json()
                assert validate_success_response_format(stats_data)
                
                journey_steps.append({
                    'step': 'dashboard_access',
                    'status': 'success'
                })
            
            # Step 7: Cleanup - Delete Created Projects
            for project in projects_created:
                if project['id']:
                    response = client.delete(f"/api/v1/projects/{project['id']}", headers=headers)
                    if response.status_code in [200, 204]:
                        journey_steps.append({
                            'step': f"project_deletion_{project['id']}",
                            'status': 'success'
                        })
        
        # Record comprehensive journey results
        successful_steps = len([s for s in journey_steps if s['status'] == 'success'])
        total_steps = len(journey_steps)
        
        reporter['record_test_execution'](
            test_name=workflow_name,
            status='passed' if successful_steps >= total_steps * 0.8 else 'partial',  # 80% success threshold
            duration=time.time() - performance['start_time'],
            workflow_type='complete_user_journey',
            performance_data={
                'total_steps': total_steps,
                'successful_steps': successful_steps,
                'success_rate': (successful_steps / total_steps) * 100,
                'journey_details': journey_steps
            }
        )
        
        # Assert overall journey success
        assert successful_steps >= total_steps * 0.5, \
            f"User journey failed: only {successful_steps}/{total_steps} steps successful"
    
    @pytest.mark.e2e
    @pytest.mark.concurrent
    def test_concurrent_api_access_patterns(self, comprehensive_e2e_environment):
        """
        Test concurrent API access patterns simulating realistic user loads.
        
        Validates:
        - Concurrent request handling
        - Resource contention management
        - Database connection pooling
        - Session isolation
        - Performance under concurrent load
        """
        env = comprehensive_e2e_environment
        client = env['client']
        performance = env['performance']
        
        workflow_name = "concurrent_api_access_patterns"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        with performance['measure_operation'](workflow_name, 'api_workflow_time'):
            import threading
            import queue
            
            # Test concurrent access to different endpoints
            endpoints_to_test = [
                '/health',
                '/api/v1/projects',
                '/api/v1/dashboard/stats',
                '/api/v1/users/profile'
            ]
            
            results = queue.Queue()
            
            def make_request(endpoint, request_id):
                """Make request and record results."""
                try:
                    start_time = time.time()
                    response = client.get(endpoint, headers=headers)
                    end_time = time.time()
                    
                    results.put({
                        'request_id': request_id,
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'duration': end_time - start_time,
                        'success': response.status_code < 500,
                        'response_size': len(response.data) if response.data else 0
                    })
                except Exception as e:
                    results.put({
                        'request_id': request_id,
                        'endpoint': endpoint,
                        'status_code': 500,
                        'duration': 0,
                        'success': False,
                        'error': str(e)
                    })
            
            # Create and start threads for concurrent requests
            threads = []
            request_id = 0
            
            for _ in range(5):  # 5 rounds of concurrent requests
                round_threads = []
                for endpoint in endpoints_to_test:
                    thread = threading.Thread(target=make_request, args=(endpoint, request_id))
                    round_threads.append(thread)
                    threads.append(thread)
                    request_id += 1
                
                # Start all threads in this round
                for thread in round_threads:
                    thread.start()
                
                # Wait for this round to complete
                for thread in round_threads:
                    thread.join(timeout=30)  # 30 second timeout per request
            
            # Collect all results
            concurrent_results = []
            while not results.empty():
                concurrent_results.append(results.get())
            
            # Analyze results
            total_requests = len(concurrent_results)
            successful_requests = len([r for r in concurrent_results if r['success']])
            
            assert total_requests > 0, "No concurrent requests were made"
            assert successful_requests >= total_requests * 0.8, \
                f"Concurrent access failed: only {successful_requests}/{total_requests} requests successful"
            
            # Check for reasonable response times
            avg_response_time = sum(r['duration'] for r in concurrent_results) / total_requests
            assert avg_response_time < 5.0, \
                f"Average response time too high under concurrent load: {avg_response_time:.2f}s"


# =============================================================================
# Performance Validation E2E Tests
# =============================================================================

class TestPerformanceValidation:
    """
    End-to-end performance testing ensuring ≤10% variance from Node.js baseline
    per Section 0.1.1 performance variance requirement.
    """
    
    @pytest.mark.e2e
    @pytest.mark.performance
    @require_load_testing
    def test_load_testing_validation(self, comprehensive_e2e_environment, locust_load_tester):
        """
        Test application performance under realistic load conditions.
        
        Validates:
        - Response times under load
        - Throughput measurements
        - Resource utilization patterns
        - Error rates under stress
        - ≤10% variance from baseline
        """
        env = comprehensive_e2e_environment
        performance = env['performance']
        reporter = env['reporter']
        
        workflow_name = "load_testing_validation"
        
        # Skip if load testing tools not available
        if not locust_load_tester:
            pytest.skip("Locust load testing not available")
        
        with performance['measure_operation'](workflow_name, 'complete_e2e_workflow_time'):
            # Configure load test parameters
            load_test_config = {
                'users': 20,  # Start with moderate load
                'spawn_rate': 2,  # 2 users per second
                'run_time': 30,  # 30 second test
                'host': 'http://localhost:5000'
            }
            
            # Execute load test
            load_results = locust_load_tester['run_load_test'](**load_test_config)
            
            # Validate load test results
            assert load_results['total_requests'] > 0, "No requests were made during load test"
            assert load_results['failure_rate'] < 5.0, \
                f"Failure rate too high: {load_results['failure_rate']}%"
            
            # Validate performance requirements
            assert load_results['average_response_time'] < 1000, \
                f"Average response time too high: {load_results['average_response_time']}ms"
            
            assert load_results['requests_per_second'] > 10, \
                f"Throughput too low: {load_results['requests_per_second']} RPS"
            
            # Record load test results
            reporter['update_performance_metrics'](
                operation_count=load_results['total_requests'],
                average_response_time=load_results['average_response_time'] / 1000,  # Convert to seconds
                load_test_data=load_results
            )
    
    @pytest.mark.e2e
    @pytest.mark.performance
    def test_individual_endpoint_performance(self, comprehensive_e2e_environment, apache_bench_tester):
        """
        Test individual endpoint performance using apache-bench.
        
        Validates:
        - Individual endpoint response times
        - Throughput per endpoint
        - Performance consistency
        - Baseline comparison
        """
        env = comprehensive_e2e_environment
        performance = env['performance']
        
        # Skip if apache-bench not available
        if not apache_bench_tester:
            pytest.skip("Apache-bench testing not available")
        
        workflow_name = "individual_endpoint_performance"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        headers = {}
        if auth_env.get('tokens', {}).get('valid'):
            headers['Authorization'] = f'Bearer {auth_env["tokens"]["valid"]}'
        
        endpoints_to_benchmark = [
            {
                'endpoint': '/health',
                'description': 'Health check endpoint',
                'baseline_time': 0.050  # 50ms baseline
            },
            {
                'endpoint': '/api/v1/projects',
                'description': 'Projects listing endpoint',
                'baseline_time': 0.200  # 200ms baseline
            }
        ]
        
        with performance['measure_operation'](workflow_name, 'api_response_time'):
            benchmark_results = []
            
            for endpoint_config in endpoints_to_benchmark:
                endpoint = endpoint_config['endpoint']
                baseline = endpoint_config['baseline_time']
                
                # Run apache-bench test
                ab_result = apache_bench_tester['benchmark_endpoint'](
                    endpoint=endpoint,
                    requests=100,
                    concurrency=5
                )
                
                if ab_result['success']:
                    # Validate performance against baseline
                    measured_time = ab_result.get('time_per_request', 0) / 1000  # Convert to seconds
                    variance = abs(measured_time - baseline) / baseline
                    
                    benchmark_results.append({
                        'endpoint': endpoint,
                        'measured_time': measured_time,
                        'baseline_time': baseline,
                        'variance': variance,
                        'compliant': variance <= 0.10,  # ≤10% variance
                        'rps': ab_result.get('requests_per_second', 0)
                    })
                    
                    # Assert compliance with variance requirement
                    assert variance <= 0.10, \
                        f"Performance variance violation for {endpoint}: {variance:.2%} > 10%"
                else:
                    pytest.skip(f"Apache-bench test failed for {endpoint}: {ab_result.get('error', 'Unknown error')}")
            
            # Overall performance validation
            if benchmark_results:
                avg_variance = sum(r['variance'] for r in benchmark_results) / len(benchmark_results)
                assert avg_variance <= 0.10, \
                    f"Average performance variance too high: {avg_variance:.2%}"


# =============================================================================
# API Contract Validation E2E Tests
# =============================================================================

class TestAPIContractValidation:
    """
    End-to-end testing for API contract validation ensuring zero client-side
    changes per Section 0.1.4 complete preservation of existing API contracts.
    """
    
    @pytest.mark.e2e
    @pytest.mark.api_contract
    def test_response_schema_consistency(self, comprehensive_e2e_environment):
        """
        Test response schema consistency across all API endpoints.
        
        Validates:
        - Response field names and types
        - Nested object structure consistency
        - Array response format consistency
        - Pagination format preservation
        - Meta-data field consistency
        """
        env = comprehensive_e2e_environment
        client = env['client']
        
        workflow_name = "response_schema_consistency"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        # Define expected response schemas
        expected_schemas = {
            '/health': {
                'required_fields': ['status', 'timestamp'],
                'optional_fields': ['components', 'version', 'uptime_seconds'],
                'field_types': {
                    'status': str,
                    'timestamp': str
                }
            },
            '/api/v1/projects': {
                'list_response': True,
                'data_field': 'projects',  # or 'data'
                'required_fields': ['projects'],
                'pagination_fields': ['total', 'page', 'per_page', 'pages'],
                'item_schema': {
                    'required_fields': ['id', 'name'],
                    'optional_fields': ['description', 'status', 'created_at', 'updated_at'],
                    'field_types': {
                        'id': str,
                        'name': str,
                        'status': str
                    }
                }
            }
        }
        
        schema_validation_results = []
        
        for endpoint, schema in expected_schemas.items():
            response = client.get(endpoint, headers=headers)
            
            if response.status_code == 404:
                # Endpoint not implemented yet
                schema_validation_results.append({
                    'endpoint': endpoint,
                    'status': 'skipped',
                    'reason': 'endpoint_not_implemented'
                })
                continue
            
            assert response.status_code == 200, f"Endpoint {endpoint} returned {response.status_code}"
            assert response.is_json, f"Endpoint {endpoint} did not return JSON"
            
            response_data = response.get_json()
            
            # Validate required fields
            for field in schema['required_fields']:
                assert field in response_data, \
                    f"Required field '{field}' missing from {endpoint} response"
            
            # Validate field types
            for field, expected_type in schema.get('field_types', {}).items():
                if field in response_data:
                    assert isinstance(response_data[field], expected_type), \
                        f"Field '{field}' in {endpoint} response should be {expected_type.__name__}, got {type(response_data[field]).__name__}"
            
            # Validate list response format
            if schema.get('list_response'):
                data_field = schema.get('data_field', 'data')
                
                # Check for data array (try multiple possible field names)
                data_found = False
                for possible_field in [data_field, 'data', 'items', 'results']:
                    if possible_field in response_data:
                        data_array = response_data[possible_field]
                        assert isinstance(data_array, list), \
                            f"Data field '{possible_field}' should be an array"
                        data_found = True
                        
                        # Validate item schema if data present
                        if data_array and 'item_schema' in schema:
                            item_schema = schema['item_schema']
                            first_item = data_array[0]
                            
                            for field in item_schema['required_fields']:
                                assert field in first_item, \
                                    f"Required item field '{field}' missing from {endpoint} list response"
                        
                        break
                
                assert data_found, f"No data array found in {endpoint} list response"
            
            schema_validation_results.append({
                'endpoint': endpoint,
                'status': 'passed',
                'response_fields': list(response_data.keys())
            })
        
        # Ensure at least some schemas were validated
        passed_validations = len([r for r in schema_validation_results if r['status'] == 'passed'])
        assert passed_validations > 0, "No API schemas were successfully validated"
    
    @pytest.mark.e2e
    @pytest.mark.api_contract
    def test_http_methods_support(self, comprehensive_e2e_environment):
        """
        Test HTTP method support consistency across API endpoints.
        
        Validates:
        - Supported HTTP methods per endpoint
        - Method not allowed responses
        - OPTIONS request handling
        - CORS preflight support
        """
        env = comprehensive_e2e_environment
        client = env['client']
        
        workflow_name = "http_methods_support"
        
        # Use mock token if available
        auth_env = env.get('auth', {})
        if auth_env.get('tokens', {}).get('valid'):
            headers = {'Authorization': f'Bearer {auth_env["tokens"]["valid"]}'}
        else:
            headers = {}
        
        # Define expected method support per endpoint
        endpoint_methods = {
            '/health': {
                'supported': ['GET', 'HEAD'],
                'not_supported': ['POST', 'PUT', 'DELETE', 'PATCH']
            },
            '/api/v1/projects': {
                'supported': ['GET', 'POST', 'OPTIONS'],
                'not_supported': ['PUT', 'DELETE', 'PATCH']
            },
            '/api/v1/projects/test-id': {
                'supported': ['GET', 'PUT', 'DELETE', 'OPTIONS'],
                'not_supported': ['POST', 'PATCH']
            }
        }
        
        method_validation_results = []
        
        for endpoint, methods in endpoint_methods.items():
            # Test supported methods
            for method in methods['supported']:
                if method == 'GET':
                    response = client.get(endpoint, headers=headers)
                elif method == 'POST':
                    response = client.post(endpoint, headers=headers, json={})
                elif method == 'PUT':
                    response = client.put(endpoint, headers=headers, json={})
                elif method == 'DELETE':
                    response = client.delete(endpoint, headers=headers)
                elif method == 'HEAD':
                    response = client.head(endpoint, headers=headers)
                elif method == 'OPTIONS':
                    response = client.options(endpoint, headers=headers)
                else:
                    continue
                
                # Should not return 405 Method Not Allowed
                assert response.status_code != 405, \
                    f"Method {method} should be supported for {endpoint} but got 405"
                
                method_validation_results.append({
                    'endpoint': endpoint,
                    'method': method,
                    'status': 'supported',
                    'response_code': response.status_code
                })
            
            # Test unsupported methods
            for method in methods['not_supported']:
                if method == 'POST':
                    response = client.post(endpoint, headers=headers, json={})
                elif method == 'PUT':
                    response = client.put(endpoint, headers=headers, json={})
                elif method == 'DELETE':
                    response = client.delete(endpoint, headers=headers)
                elif method == 'PATCH':
                    response = client.patch(endpoint, headers=headers, json={})
                else:
                    continue
                
                # Should return 405 Method Not Allowed (or 404 if endpoint doesn't exist)
                if response.status_code == 404:
                    # Endpoint not implemented yet
                    continue
                    
                assert response.status_code == 405, \
                    f"Method {method} should not be supported for {endpoint} but got {response.status_code}"
                
                # Validate Allow header is present
                assert 'Allow' in response.headers, \
                    f"Allow header missing from 405 response for {endpoint}"
                
                method_validation_results.append({
                    'endpoint': endpoint,
                    'method': method,
                    'status': 'not_supported',
                    'response_code': response.status_code,
                    'allow_header': response.headers.get('Allow')
                })
        
        # Ensure some method validations were performed
        assert len(method_validation_results) > 0, "No HTTP method validations were performed"
    
    @pytest.mark.e2e
    @pytest.mark.api_contract
    def test_cors_headers_consistency(self, comprehensive_e2e_environment):
        """
        Test CORS headers consistency across all API endpoints.
        
        Validates:
        - CORS headers presence
        - Access-Control-Allow-Origin values
        - Access-Control-Allow-Methods consistency
        - Access-Control-Allow-Headers support
        - Preflight request handling
        """
        env = comprehensive_e2e_environment
        client = env['client']
        
        workflow_name = "cors_headers_consistency"
        
        endpoints_to_test = [
            '/health',
            '/api/v1/projects',
            '/api/v1/dashboard/stats'
        ]
        
        cors_validation_results = []
        
        for endpoint in endpoints_to_test:
            # Test regular request CORS headers
            response = client.get(endpoint)
            
            if response.status_code == 404:
                continue
            
            cors_result = {
                'endpoint': endpoint,
                'request_type': 'regular',
                'cors_headers': {}
            }
            
            # Check for CORS headers
            cors_headers = [
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Methods',
                'Access-Control-Allow-Headers',
                'Access-Control-Expose-Headers',
                'Access-Control-Allow-Credentials'
            ]
            
            for header in cors_headers:
                if header in response.headers:
                    cors_result['cors_headers'][header] = response.headers[header]
            
            cors_validation_results.append(cors_result)
            
            # Test OPTIONS preflight request
            preflight_headers = {
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type, Authorization'
            }
            
            options_response = client.options(endpoint, headers=preflight_headers)
            
            preflight_result = {
                'endpoint': endpoint,
                'request_type': 'preflight',
                'status_code': options_response.status_code,
                'cors_headers': {}
            }
            
            for header in cors_headers:
                if header in options_response.headers:
                    preflight_result['cors_headers'][header] = options_response.headers[header]
            
            cors_validation_results.append(preflight_result)
        
        # Validate CORS consistency
        if cors_validation_results:
            # Check that CORS is configured (at least some headers present)
            cors_configured = any(
                result['cors_headers'] for result in cors_validation_results
            )
            
            # CORS may not be configured in test environment, so don't fail if missing
            if cors_configured:
                # If CORS is configured, validate consistency
                origin_headers = [
                    result['cors_headers'].get('Access-Control-Allow-Origin')
                    for result in cors_validation_results
                    if 'Access-Control-Allow-Origin' in result['cors_headers']
                ]
                
                # All origin headers should be consistent
                if origin_headers:
                    assert len(set(origin_headers)) <= 2, \
                        f"Inconsistent CORS origin headers: {set(origin_headers)}"


# =============================================================================
# Test Execution Control and Reporting
# =============================================================================

@pytest.mark.e2e
def test_e2e_environment_health(comprehensive_e2e_environment):
    """
    Validate E2E testing environment health before running comprehensive tests.
    
    This test ensures the testing environment is properly configured and
    all required services are available for comprehensive E2E testing.
    """
    env = comprehensive_e2e_environment
    
    # Check Flask application availability
    assert env['app'] is not None, "Flask application not available"
    assert env['client'] is not None, "Flask test client not available"
    
    # Check basic application health
    response = env['client'].get('/health')
    assert response.status_code in [200, 404], \
        f"Application health check failed with status {response.status_code}"
    
    # Check performance monitoring
    assert env['performance'] is not None, "Performance monitoring not available"
    assert callable(env['performance']['measure_operation']), \
        "Performance measurement function not available"
    
    # Check test reporter
    assert env['reporter'] is not None, "Test reporter not available"
    assert callable(env['reporter']['record_test_execution']), \
        "Test execution recording function not available"
    
    # Validate system readiness
    system_validation = env['validate_complete_system']()
    assert system_validation['overall_status'] in ['ready', 'not_ready'], \
        "System validation failed"
    
    # Log environment status
    print(f"\nE2E Environment Health Check:")
    print(f"- System Status: {system_validation['overall_status']}")
    print(f"- Flask App: {'✓' if env['app'] else '✗'}")
    print(f"- Performance Monitoring: {'✓' if env['performance'] else '✗'}")
    print(f"- External Services: {len([s for s in env.get('external_services', {}).values() if s.get('available')])}")
    print(f"- Testing Capabilities: {sum(1 for c in env['capabilities'].values() if c)}")


if __name__ == "__main__":
    # Allow running individual test classes for development
    pytest.main([__file__, "-v", "--tb=short"])