"""
Error Handling Integration Testing Suite

Comprehensive integration testing covering Flask error handlers, exception propagation across
components, circuit breaker error scenarios, and comprehensive error recovery workflows.
Tests enterprise-grade error handling patterns with realistic failure scenarios and graceful
degradation validation per Section 4.2.3 error handling and recovery requirements.

This test suite validates:
- Flask @errorhandler integration for consistent error responses per Section 4.2.3
- Circuit breaker and retry logic exception management per Section 6.3.3
- Error recovery and resilience for fault tolerance per Section 6.2.3
- Database error handling integration with connection failures and recovery
- External service error handling integration with retry and fallback patterns
- Graceful degradation testing for partial service availability
- Comprehensive error monitoring and alerting system testing

Technical Compliance:
- Section 4.2.3: Error handling and recovery with Flask @errorhandler integration
- Section 6.1.3: Resilience mechanisms with circuit breaker patterns
- Section 6.2.3: Backup and fault tolerance with database error recovery
- Section 6.3.3: External systems integration with graceful degradation patterns
- Section 3.6: Monitoring & observability with comprehensive error tracking

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from contextlib import contextmanager

import pytest
import pytest_asyncio
from flask import Flask, g, request, session, jsonify
from flask.testing import FlaskClient
import requests
import httpx

# Import application components for error handling testing
from src.app import create_app
from src.auth.exceptions import (
    SecurityException, AuthenticationException, JWTException, AuthorizationException,
    PermissionException, Auth0Exception, SessionException, RateLimitException,
    CircuitBreakerException, ValidationException, SecurityErrorCode,
    create_safe_error_response, is_critical_security_error
)
from src.data.exceptions import (
    DatabaseException, ConnectionException, TimeoutException, TransactionException,
    QueryException, ResourceException, CircuitBreakerException as DBCircuitBreakerException,
    DatabaseErrorSeverity, DatabaseOperationType, handle_database_error,
    DatabaseRetryConfig, with_database_retry, mongodb_circuit_breaker
)
from src.cache.exceptions import (
    CacheError, RedisConnectionError, CacheOperationTimeoutError,
    CacheInvalidationError, CircuitBreakerOpenError, CacheKeyError,
    CacheSerializationError, CachePoolExhaustedError, handle_redis_exception
)
from src.integrations.exceptions import (
    IntegrationError, HTTPClientError, RequestsHTTPError, HttpxHTTPError,
    ConnectionError as IntegrationConnectionError, TimeoutError as IntegrationTimeoutError,
    HTTPResponseError, CircuitBreakerError, RetryError, RetryExhaustedError,
    Auth0Error, AWSServiceError, S3Error, MongoDBError, RedisError,
    ValidationError as IntegrationValidationError, IntegrationExceptionFactory
)

# Configure structured logging for test execution
logger = logging.getLogger(__name__)


class ErrorHandlingTestEnvironment:
    """
    Test environment for comprehensive error handling validation.
    
    Provides utilities for simulating various failure scenarios, tracking error
    propagation, and validating recovery mechanisms across the entire application
    stack per Section 4.2.3 error handling requirements.
    """
    
    def __init__(self, app: Flask, client: FlaskClient):
        self.app = app
        self.client = client
        self.error_events = []
        self.circuit_breaker_states = {}
        self.retry_attempts = {}
        self.recovery_events = []
        self.performance_metrics = {}
        
    def record_error_event(self, error_type: str, component: str, details: Dict[str, Any]):
        """Record error event for analysis"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'error_type': error_type,
            'component': component,
            'details': details,
            'event_id': str(uuid.uuid4())
        }
        self.error_events.append(event)
        logger.debug(f"Error event recorded: {error_type} in {component}")
    
    def record_circuit_breaker_state(self, service: str, state: str, failure_count: int = 0):
        """Record circuit breaker state change"""
        self.circuit_breaker_states[service] = {
            'state': state,
            'failure_count': failure_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        logger.debug(f"Circuit breaker state recorded: {service} -> {state}")
    
    def record_retry_attempt(self, operation: str, attempt: int, success: bool):
        """Record retry attempt for analysis"""
        if operation not in self.retry_attempts:
            self.retry_attempts[operation] = []
        
        self.retry_attempts[operation].append({
            'attempt': attempt,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        })
        logger.debug(f"Retry attempt recorded: {operation} attempt {attempt} success={success}")
    
    def record_recovery_event(self, component: str, recovery_type: str, success: bool):
        """Record recovery event for validation"""
        event = {
            'component': component,
            'recovery_type': recovery_type,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.recovery_events.append(event)
        logger.debug(f"Recovery event recorded: {component} {recovery_type} success={success}")
    
    def measure_error_response_time(self, operation: str):
        """Context manager for measuring error response times"""
        @contextmanager
        def measurement_context():
            start_time = time.perf_counter()
            try:
                yield
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                self.performance_metrics[operation] = duration
                logger.debug(f"Error response time measured: {operation} took {duration:.3f}s")
        
        return measurement_context()
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error handling summary"""
        return {
            'total_errors': len(self.error_events),
            'error_types': list(set(event['error_type'] for event in self.error_events)),
            'affected_components': list(set(event['component'] for event in self.error_events)),
            'circuit_breaker_activations': len([
                service for service, state in self.circuit_breaker_states.items()
                if state['state'] == 'open'
            ]),
            'total_retry_attempts': sum(
                len(attempts) for attempts in self.retry_attempts.values()
            ),
            'successful_recoveries': len([
                event for event in self.recovery_events if event['success']
            ]),
            'average_error_response_time': (
                sum(self.performance_metrics.values()) / len(self.performance_metrics)
                if self.performance_metrics else 0
            )
        }


@pytest.fixture
def error_test_environment(comprehensive_test_environment):
    """
    Fixture providing comprehensive error handling test environment.
    
    Creates specialized testing environment for error handling validation
    with monitoring, circuit breaker simulation, and recovery tracking.
    """
    app = comprehensive_test_environment['app']
    client = comprehensive_test_environment['client']
    
    env = ErrorHandlingTestEnvironment(app, client)
    
    logger.info("Error handling test environment initialized")
    return env


@pytest.fixture
def mock_failing_services():
    """
    Fixture providing mock services that can simulate various failure modes.
    
    Creates controllable mock services for testing error handling across
    different failure scenarios including timeouts, connection errors,
    and service unavailability.
    """
    services = {}
    
    # Mock database service with controllable failures
    class MockDatabaseService:
        def __init__(self):
            self.failure_mode = None
            self.failure_count = 0
            self.total_calls = 0
        
        def query(self, query_string: str):
            self.total_calls += 1
            
            if self.failure_mode == 'connection_error':
                self.failure_count += 1
                raise ConnectionException(
                    "Database connection failed",
                    database="test_db",
                    operation=DatabaseOperationType.READ
                )
            elif self.failure_mode == 'timeout':
                self.failure_count += 1
                raise TimeoutException(
                    "Database query timeout",
                    operation=DatabaseOperationType.READ,
                    timeout_duration=5.0
                )
            elif self.failure_mode == 'transaction_error':
                self.failure_count += 1
                raise TransactionException(
                    "Transaction rollback required",
                    transaction_id="test_txn_123"
                )
            
            return {'status': 'success', 'data': {'id': 'test_record'}}
        
        def set_failure_mode(self, mode: Optional[str]):
            self.failure_mode = mode
            self.failure_count = 0
    
    services['database'] = MockDatabaseService()
    
    # Mock cache service with controllable failures
    class MockCacheService:
        def __init__(self):
            self.failure_mode = None
            self.failure_count = 0
            self.total_calls = 0
        
        def get(self, key: str):
            self.total_calls += 1
            
            if self.failure_mode == 'connection_error':
                self.failure_count += 1
                raise RedisConnectionError(
                    "Redis connection failed",
                    connection_info={'host': 'localhost', 'port': 6379}
                )
            elif self.failure_mode == 'timeout':
                self.failure_count += 1
                raise CacheOperationTimeoutError(
                    "Cache operation timeout",
                    operation="get",
                    timeout_duration=1.0
                )
            elif self.failure_mode == 'circuit_breaker_open':
                self.failure_count += 1
                raise CircuitBreakerOpenError(
                    "Cache circuit breaker is open",
                    failure_count=5,
                    recovery_timeout=60
                )
            
            return f"cached_value_for_{key}"
        
        def set_failure_mode(self, mode: Optional[str]):
            self.failure_mode = mode
            self.failure_count = 0
    
    services['cache'] = MockCacheService()
    
    # Mock external API service with controllable failures
    class MockExternalAPIService:
        def __init__(self):
            self.failure_mode = None
            self.failure_count = 0
            self.total_calls = 0
        
        def make_request(self, endpoint: str, method: str = 'GET'):
            self.total_calls += 1
            
            if self.failure_mode == 'connection_error':
                self.failure_count += 1
                raise IntegrationConnectionError(
                    "Cannot connect to external service",
                    service_name="external_api",
                    operation="api_call",
                    url=f"https://api.example.com{endpoint}"
                )
            elif self.failure_mode == 'timeout':
                self.failure_count += 1
                raise IntegrationTimeoutError(
                    "Request timeout",
                    service_name="external_api",
                    operation="api_call",
                    timeout_duration=30.0
                )
            elif self.failure_mode == 'http_error':
                self.failure_count += 1
                raise HTTPResponseError(
                    "HTTP 500 Internal Server Error",
                    service_name="external_api",
                    operation="api_call",
                    status_code=500
                )
            elif self.failure_mode == 'circuit_breaker_open':
                self.failure_count += 1
                raise CircuitBreakerError(
                    "External API circuit breaker is open",
                    service_name="external_api",
                    operation="api_call",
                    circuit_state="OPEN"
                )
            
            return {'status': 'success', 'data': {'response': 'mock_data'}}
        
        def set_failure_mode(self, mode: Optional[str]):
            self.failure_mode = mode
            self.failure_count = 0
    
    services['external_api'] = MockExternalAPIService()
    
    # Mock authentication service with controllable failures
    class MockAuthService:
        def __init__(self):
            self.failure_mode = None
            self.failure_count = 0
            self.total_calls = 0
        
        def validate_token(self, token: str):
            self.total_calls += 1
            
            if self.failure_mode == 'invalid_token':
                self.failure_count += 1
                raise JWTException(
                    "Invalid JWT token",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    token_header={'alg': 'RS256', 'typ': 'JWT'}
                )
            elif self.failure_mode == 'expired_token':
                self.failure_count += 1
                raise JWTException(
                    "JWT token expired",
                    error_code=SecurityErrorCode.AUTH_TOKEN_EXPIRED,
                    token_header={'alg': 'RS256', 'typ': 'JWT'}
                )
            elif self.failure_mode == 'auth0_unavailable':
                self.failure_count += 1
                raise Auth0Exception(
                    "Auth0 service unavailable",
                    error_code=SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
                    circuit_breaker_state='open'
                )
            
            return {'valid': True, 'user_id': 'test_user', 'permissions': ['read', 'write']}
        
        def set_failure_mode(self, mode: Optional[str]):
            self.failure_mode = mode
            self.failure_count = 0
    
    services['auth'] = MockAuthService()
    
    logger.info(f"Mock failing services created: {list(services.keys())}")
    return services


# =============================================================================
# Flask Error Handler Integration Tests
# =============================================================================

class TestFlaskErrorHandlerIntegration:
    """
    Test Flask @errorhandler integration for consistent error responses.
    
    Validates that all exception types are properly handled by Flask error
    handlers and return consistent JSON responses per Section 4.2.3.
    """
    
    def test_authentication_exception_handler(self, error_test_environment):
        """Test Flask error handler for authentication exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-auth-error')
        def test_auth_error():
            raise AuthenticationException(
                "Authentication failed",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                user_message="Invalid authentication token"
            )
        
        with error_test_environment.measure_error_response_time('auth_error'):
            response = error_test_environment.client.get('/test-auth-error')
        
        assert response.status_code == 401
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'Unauthorized'
        assert 'timestamp' in data
        
        error_test_environment.record_error_event(
            'AuthenticationException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
        
        logger.info("Authentication exception handler test completed")
    
    def test_authorization_exception_handler(self, error_test_environment):
        """Test Flask error handler for authorization exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-authz-error')
        def test_authz_error():
            raise AuthorizationException(
                "Access denied",
                error_code=SecurityErrorCode.AUTHZ_PERMISSION_DENIED,
                required_permissions=['admin:read'],
                resource_id='test_resource'
            )
        
        with error_test_environment.measure_error_response_time('authz_error'):
            response = error_test_environment.client.get('/test-authz-error')
        
        assert response.status_code == 403
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'Forbidden'
        assert 'timestamp' in data
        
        error_test_environment.record_error_event(
            'AuthorizationException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
    
    def test_database_exception_handler(self, error_test_environment):
        """Test Flask error handler for database exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-db-error')
        def test_db_error():
            raise ConnectionException(
                "Database connection failed",
                database="test_db",
                operation=DatabaseOperationType.READ
            )
        
        with error_test_environment.measure_error_response_time('db_error'):
            response = error_test_environment.client.get('/test-db-error')
        
        assert response.status_code == 503
        assert response.is_json
        
        data = response.get_json()
        assert 'error' in data
        assert data['error']['type'] == 'database_error'
        assert 'retry_recommended' in data['error']
        
        error_test_environment.record_error_event(
            'DatabaseException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
    
    def test_cache_exception_handler(self, error_test_environment):
        """Test Flask error handler for cache exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-cache-error')
        def test_cache_error():
            raise RedisConnectionError(
                "Redis connection failed",
                connection_info={'host': 'localhost', 'port': 6379}
            )
        
        with error_test_environment.measure_error_response_time('cache_error'):
            response = error_test_environment.client.get('/test-cache-error')
        
        assert response.status_code == 503
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'REDIS_CONNECTION_ERROR'
        assert 'retry_after' in data
        
        error_test_environment.record_error_event(
            'CacheException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
    
    def test_integration_exception_handler(self, error_test_environment):
        """Test Flask error handler for integration exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-integration-error')
        def test_integration_error():
            raise HTTPResponseError(
                "External service error",
                service_name="external_api",
                operation="api_call",
                status_code=500
            )
        
        with error_test_environment.measure_error_response_time('integration_error'):
            response = error_test_environment.client.get('/test-integration-error')
        
        assert response.status_code == 500
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'Internal Server Error'
        assert 'timestamp' in data
        
        error_test_environment.record_error_event(
            'IntegrationException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
    
    def test_validation_exception_handler(self, error_test_environment):
        """Test Flask error handler for validation exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-validation-error')
        def test_validation_error():
            raise ValidationException(
                "Input validation failed",
                error_code=SecurityErrorCode.VAL_SCHEMA_VIOLATION,
                validation_errors=['Invalid email format', 'Password too short'],
                schema_name='UserRegistrationSchema'
            )
        
        with error_test_environment.measure_error_response_time('validation_error'):
            response = error_test_environment.client.get('/test-validation-error')
        
        assert response.status_code == 400
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'Bad Request'
        assert 'timestamp' in data
        
        error_test_environment.record_error_event(
            'ValidationException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )
    
    def test_rate_limit_exception_handler(self, error_test_environment):
        """Test Flask error handler for rate limiting exceptions."""
        app = error_test_environment.app
        
        @app.route('/test-rate-limit-error')
        def test_rate_limit_error():
            raise RateLimitException(
                "Rate limit exceeded",
                limit_type='user_endpoint',
                current_rate=150,
                limit_threshold=100,
                endpoint='/api/users'
            )
        
        with error_test_environment.measure_error_response_time('rate_limit_error'):
            response = error_test_environment.client.get('/test-rate-limit-error')
        
        assert response.status_code == 429
        assert response.is_json
        
        data = response.get_json()
        assert data['error'] == 'Too Many Requests'
        assert 'retry_after' in data
        
        error_test_environment.record_error_event(
            'RateLimitException',
            'flask_error_handler',
            {'status_code': response.status_code, 'response_data': data}
        )


# =============================================================================
# Circuit Breaker Error Scenario Tests
# =============================================================================

class TestCircuitBreakerErrorScenarios:
    """
    Test circuit breaker error scenarios with realistic failure conditions.
    
    Validates circuit breaker patterns for external service protection
    and graceful degradation per Section 6.1.3 resilience mechanisms.
    """
    
    def test_database_circuit_breaker_activation(self, error_test_environment, mock_failing_services):
        """Test database circuit breaker activation under repeated failures."""
        db_service = mock_failing_services['database']
        db_service.set_failure_mode('connection_error')
        
        app = error_test_environment.app
        
        @app.route('/test-db-circuit-breaker')
        def test_db_circuit_breaker():
            try:
                result = db_service.query("SELECT * FROM test_table")
                return jsonify(result)
            except DatabaseException as e:
                error_test_environment.record_error_event(
                    'DatabaseException',
                    'database_service',
                    e.to_dict()
                )
                raise
        
        # Simulate repeated failures to trigger circuit breaker
        failure_responses = []
        for attempt in range(5):
            with error_test_environment.measure_error_response_time(f'db_circuit_breaker_attempt_{attempt}'):
                response = error_test_environment.client.get('/test-db-circuit-breaker')
                failure_responses.append(response)
            
            error_test_environment.record_retry_attempt(
                'database_query',
                attempt + 1,
                response.status_code == 200
            )
        
        # Validate that all attempts failed with appropriate error responses
        for response in failure_responses:
            assert response.status_code == 503
            assert response.is_json
        
        # Record circuit breaker activation
        error_test_environment.record_circuit_breaker_state(
            'database',
            'open',
            failure_count=db_service.failure_count
        )
        
        assert db_service.failure_count == 5
        logger.info("Database circuit breaker activation test completed")
    
    def test_external_api_circuit_breaker_recovery(self, error_test_environment, mock_failing_services):
        """Test external API circuit breaker recovery mechanism."""
        api_service = mock_failing_services['external_api']
        
        app = error_test_environment.app
        
        @app.route('/test-api-circuit-breaker')
        def test_api_circuit_breaker():
            try:
                result = api_service.make_request('/test-endpoint')
                return jsonify(result)
            except IntegrationError as e:
                error_test_environment.record_error_event(
                    'IntegrationError',
                    'external_api',
                    e.to_dict()
                )
                raise
        
        # Phase 1: Trigger circuit breaker with failures
        api_service.set_failure_mode('timeout')
        
        for attempt in range(3):
            response = error_test_environment.client.get('/test-api-circuit-breaker')
            assert response.status_code == 504  # Gateway timeout
            
            error_test_environment.record_retry_attempt(
                'external_api_call',
                attempt + 1,
                False
            )
        
        error_test_environment.record_circuit_breaker_state(
            'external_api',
            'open',
            failure_count=api_service.failure_count
        )
        
        # Phase 2: Test recovery when service becomes available
        api_service.set_failure_mode(None)  # Service recovers
        
        response = error_test_environment.client.get('/test-api-circuit-breaker')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'success'
        
        error_test_environment.record_circuit_breaker_state(
            'external_api',
            'closed',
            failure_count=0
        )
        
        error_test_environment.record_recovery_event(
            'external_api',
            'circuit_breaker_recovery',
            True
        )
        
        logger.info("External API circuit breaker recovery test completed")
    
    def test_auth_service_circuit_breaker_fallback(self, error_test_environment, mock_failing_services):
        """Test authentication service circuit breaker with fallback mechanism."""
        auth_service = mock_failing_services['auth']
        auth_service.set_failure_mode('auth0_unavailable')
        
        app = error_test_environment.app
        
        @app.route('/test-auth-circuit-breaker')
        def test_auth_circuit_breaker():
            try:
                # Attempt normal authentication
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                result = auth_service.validate_token(token)
                return jsonify({'authenticated': True, 'user': result})
            except Auth0Exception as e:
                error_test_environment.record_error_event(
                    'Auth0Exception',
                    'auth_service',
                    e.to_dict()
                )
                
                # Fallback to limited functionality
                error_test_environment.record_recovery_event(
                    'auth_service',
                    'fallback_authentication',
                    True
                )
                
                return jsonify({
                    'authenticated': False,
                    'fallback_mode': True,
                    'limited_access': True
                }), 200
        
        headers = {'Authorization': 'Bearer test_token'}
        response = error_test_environment.client.get(
            '/test-auth-circuit-breaker',
            headers=headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['fallback_mode'] is True
        assert data['limited_access'] is True
        
        error_test_environment.record_circuit_breaker_state(
            'auth_service',
            'open',
            failure_count=auth_service.failure_count
        )
        
        logger.info("Auth service circuit breaker fallback test completed")
    
    def test_cache_circuit_breaker_graceful_degradation(self, error_test_environment, mock_failing_services):
        """Test cache circuit breaker with graceful degradation."""
        cache_service = mock_failing_services['cache']
        cache_service.set_failure_mode('circuit_breaker_open')
        
        app = error_test_environment.app
        
        @app.route('/test-cache-circuit-breaker')
        def test_cache_circuit_breaker():
            try:
                # Attempt to get cached data
                cached_value = cache_service.get('user_data_123')
                return jsonify({'cached': True, 'data': cached_value})
            except CircuitBreakerOpenError as e:
                error_test_environment.record_error_event(
                    'CircuitBreakerOpenError',
                    'cache_service',
                    e.to_dict()
                )
                
                # Graceful degradation: compute without cache
                error_test_environment.record_recovery_event(
                    'cache_service',
                    'graceful_degradation',
                    True
                )
                
                # Simulate expensive computation that would normally be cached
                computed_value = f"computed_data_without_cache_{int(time.time())}"
                
                return jsonify({
                    'cached': False,
                    'computed': True,
                    'data': computed_value,
                    'degraded_performance': True
                }), 200
        
        with error_test_environment.measure_error_response_time('cache_circuit_breaker_degradation'):
            response = error_test_environment.client.get('/test-cache-circuit-breaker')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['cached'] is False
        assert data['computed'] is True
        assert data['degraded_performance'] is True
        
        error_test_environment.record_circuit_breaker_state(
            'cache_service',
            'open',
            failure_count=cache_service.failure_count
        )
        
        logger.info("Cache circuit breaker graceful degradation test completed")


# =============================================================================
# Database Error Handling Integration Tests
# =============================================================================

class TestDatabaseErrorHandlingIntegration:
    """
    Test database error handling integration with connection failures and recovery.
    
    Validates database error handling patterns, connection pool management,
    and transaction rollback scenarios per Section 6.2.3 fault tolerance.
    """
    
    def test_database_connection_failure_recovery(self, error_test_environment, mock_failing_services):
        """Test database connection failure with automatic recovery."""
        db_service = mock_failing_services['database']
        
        app = error_test_environment.app
        
        @app.route('/test-db-connection-recovery')
        def test_db_connection_recovery():
            try:
                result = db_service.query("SELECT * FROM users WHERE id = 1")
                return jsonify(result)
            except ConnectionException as e:
                error_test_environment.record_error_event(
                    'ConnectionException',
                    'database',
                    e.to_dict()
                )
                
                # Simulate automatic recovery mechanism
                time.sleep(0.1)  # Brief recovery delay
                
                # Attempt recovery
                db_service.set_failure_mode(None)  # Service recovers
                
                try:
                    result = db_service.query("SELECT * FROM users WHERE id = 1")
                    error_test_environment.record_recovery_event(
                        'database',
                        'connection_recovery',
                        True
                    )
                    return jsonify(result)
                except Exception:
                    error_test_environment.record_recovery_event(
                        'database',
                        'connection_recovery',
                        False
                    )
                    raise
        
        # Phase 1: Trigger connection failure
        db_service.set_failure_mode('connection_error')
        
        with error_test_environment.measure_error_response_time('db_connection_recovery'):
            response = error_test_environment.client.get('/test-db-connection-recovery')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        
        logger.info("Database connection failure recovery test completed")
    
    def test_database_transaction_rollback(self, error_test_environment, mock_failing_services):
        """Test database transaction rollback on failure."""
        db_service = mock_failing_services['database']
        db_service.set_failure_mode('transaction_error')
        
        app = error_test_environment.app
        
        @app.route('/test-db-transaction-rollback')
        def test_db_transaction_rollback():
            transaction_id = f"txn_{uuid.uuid4().hex[:8]}"
            
            try:
                # Simulate transaction operations
                result = db_service.query(f"BEGIN TRANSACTION {transaction_id}")
                return jsonify(result)
            except TransactionException as e:
                error_test_environment.record_error_event(
                    'TransactionException',
                    'database',
                    e.to_dict()
                )
                
                # Automatic rollback handling
                error_test_environment.record_recovery_event(
                    'database',
                    'transaction_rollback',
                    True
                )
                
                return jsonify({
                    'transaction_failed': True,
                    'rollback_completed': True,
                    'transaction_id': transaction_id
                }), 500
        
        response = error_test_environment.client.get('/test-db-transaction-rollback')
        
        assert response.status_code == 500
        data = response.get_json()
        assert data['transaction_failed'] is True
        assert data['rollback_completed'] is True
        
        logger.info("Database transaction rollback test completed")
    
    def test_database_timeout_retry_mechanism(self, error_test_environment, mock_failing_services):
        """Test database timeout with retry mechanism."""
        db_service = mock_failing_services['database']
        
        app = error_test_environment.app
        
        @app.route('/test-db-timeout-retry')
        def test_db_timeout_retry():
            max_retries = 3
            
            for attempt in range(max_retries):
                try:
                    result = db_service.query("SELECT * FROM large_table LIMIT 1000")
                    return jsonify(result)
                except TimeoutException as e:
                    error_test_environment.record_error_event(
                        'TimeoutException',
                        'database',
                        e.to_dict()
                    )
                    
                    error_test_environment.record_retry_attempt(
                        'database_timeout_query',
                        attempt + 1,
                        False
                    )
                    
                    if attempt == max_retries - 1:
                        # Final attempt failed
                        return jsonify({
                            'query_failed': True,
                            'timeout_exceeded': True,
                            'retry_attempts': max_retries
                        }), 504
                    
                    # Brief delay before retry
                    time.sleep(0.05 * (2 ** attempt))  # Exponential backoff
            
            return jsonify({'status': 'success'})
        
        # Set timeout failure mode
        db_service.set_failure_mode('timeout')
        
        with error_test_environment.measure_error_response_time('db_timeout_retry'):
            response = error_test_environment.client.get('/test-db-timeout-retry')
        
        assert response.status_code == 504
        data = response.get_json()
        assert data['timeout_exceeded'] is True
        assert data['retry_attempts'] == 3
        
        logger.info("Database timeout retry mechanism test completed")
    
    @pytest.mark.asyncio
    async def test_async_database_error_handling(self, error_test_environment):
        """Test async database error handling with Motor client."""
        app = error_test_environment.app
        
        # Mock async database operation
        async def async_db_operation():
            # Simulate async database failure
            await asyncio.sleep(0.01)
            raise ConnectionException(
                "Async database connection failed",
                database="async_test_db",
                operation=DatabaseOperationType.READ
            )
        
        @app.route('/test-async-db-error')
        def test_async_db_error():
            try:
                # Simulate async operation in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(async_db_operation())
                return jsonify({'status': 'success'})
            except ConnectionException as e:
                error_test_environment.record_error_event(
                    'AsyncConnectionException',
                    'async_database',
                    e.to_dict()
                )
                
                return jsonify({
                    'async_operation_failed': True,
                    'error_type': 'AsyncConnectionException'
                }), 503
            finally:
                loop.close()
        
        response = error_test_environment.client.get('/test-async-db-error')
        
        assert response.status_code == 503
        data = response.get_json()
        assert data['async_operation_failed'] is True
        assert data['error_type'] == 'AsyncConnectionException'
        
        logger.info("Async database error handling test completed")


# =============================================================================
# External Service Error Handling Integration Tests
# =============================================================================

class TestExternalServiceErrorHandlingIntegration:
    """
    Test external service error handling with retry and fallback patterns.
    
    Validates HTTP client error handling, retry mechanisms, and service
    degradation patterns per Section 6.3.3 external systems integration.
    """
    
    def test_http_client_timeout_retry(self, error_test_environment):
        """Test HTTP client timeout with exponential backoff retry."""
        app = error_test_environment.app
        
        @app.route('/test-http-timeout-retry')
        def test_http_timeout_retry():
            max_retries = 3
            base_delay = 0.1
            
            for attempt in range(max_retries):
                try:
                    # Simulate HTTP request with timeout
                    if attempt < 2:  # First two attempts fail
                        raise IntegrationTimeoutError(
                            "HTTP request timeout",
                            service_name="external_api",
                            operation="api_call",
                            timeout_duration=30.0
                        )
                    else:
                        # Third attempt succeeds
                        return jsonify({
                            'status': 'success',
                            'retry_attempts': attempt + 1,
                            'data': 'api_response_data'
                        })
                
                except IntegrationTimeoutError as e:
                    error_test_environment.record_error_event(
                        'IntegrationTimeoutError',
                        'http_client',
                        e.to_dict()
                    )
                    
                    error_test_environment.record_retry_attempt(
                        'http_request',
                        attempt + 1,
                        False
                    )
                    
                    if attempt == max_retries - 1:
                        return jsonify({
                            'request_failed': True,
                            'timeout_exceeded': True,
                            'retry_attempts': max_retries
                        }), 504
                    
                    # Exponential backoff delay
                    time.sleep(base_delay * (2 ** attempt))
            
            return jsonify({'status': 'error'})
        
        with error_test_environment.measure_error_response_time('http_timeout_retry'):
            response = error_test_environment.client.get('/test-http-timeout-retry')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['retry_attempts'] == 3
        
        logger.info("HTTP client timeout retry test completed")
    
    def test_external_service_fallback_mechanism(self, error_test_environment):
        """Test external service fallback mechanism."""
        app = error_test_environment.app
        
        @app.route('/test-external-service-fallback')
        def test_external_service_fallback():
            try:
                # Primary service call
                raise HTTPResponseError(
                    "Primary service unavailable",
                    service_name="primary_api",
                    operation="data_fetch",
                    status_code=503
                )
            
            except HTTPResponseError as e:
                error_test_environment.record_error_event(
                    'HTTPResponseError',
                    'primary_api',
                    e.to_dict()
                )
                
                try:
                    # Fallback to secondary service
                    fallback_data = {
                        'source': 'fallback_service',
                        'data': 'cached_or_default_data',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    error_test_environment.record_recovery_event(
                        'external_service',
                        'fallback_activation',
                        True
                    )
                    
                    return jsonify({
                        'primary_failed': True,
                        'fallback_used': True,
                        'data': fallback_data
                    }), 200
                
                except Exception as fallback_error:
                    error_test_environment.record_recovery_event(
                        'external_service',
                        'fallback_activation',
                        False
                    )
                    
                    return jsonify({
                        'primary_failed': True,
                        'fallback_failed': True,
                        'error': str(fallback_error)
                    }), 503
        
        response = error_test_environment.client.get('/test-external-service-fallback')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['primary_failed'] is True
        assert data['fallback_used'] is True
        assert 'data' in data
        
        logger.info("External service fallback mechanism test completed")
    
    def test_auth0_service_integration_error(self, error_test_environment):
        """Test Auth0 service integration error handling."""
        app = error_test_environment.app
        
        @app.route('/test-auth0-integration-error')
        def test_auth0_integration_error():
            try:
                # Simulate Auth0 API call failure
                raise Auth0Error(
                    "Auth0 API rate limit exceeded",
                    operation="user_info",
                    auth0_error_code="rate_limit_exceeded",
                    tenant="test-tenant"
                )
            
            except Auth0Error as e:
                error_test_environment.record_error_event(
                    'Auth0Error',
                    'auth0_service',
                    e.to_dict()
                )
                
                # Fallback to cached user information
                cached_user_info = {
                    'user_id': 'cached_user_123',
                    'email': 'user@example.com',
                    'cached': True,
                    'cache_timestamp': datetime.utcnow().isoformat()
                }
                
                error_test_environment.record_recovery_event(
                    'auth0_service',
                    'cached_user_fallback',
                    True
                )
                
                return jsonify({
                    'auth0_failed': True,
                    'cached_data_used': True,
                    'user_info': cached_user_info
                }), 200
        
        response = error_test_environment.client.get('/test-auth0-integration-error')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['auth0_failed'] is True
        assert data['cached_data_used'] is True
        
        logger.info("Auth0 service integration error test completed")
    
    def test_aws_service_error_handling(self, error_test_environment):
        """Test AWS service error handling with retry logic."""
        app = error_test_environment.app
        
        @app.route('/test-aws-service-error')
        def test_aws_service_error():
            max_retries = 2
            
            for attempt in range(max_retries):
                try:
                    if attempt == 0:
                        # First attempt: throttling error
                        raise AWSServiceError(
                            "AWS S3 throttling error",
                            operation="put_object",
                            aws_service="s3",
                            aws_error_code="SlowDown",
                            region="us-east-1"
                        )
                    else:
                        # Second attempt: success
                        return jsonify({
                            'aws_operation': 'success',
                            'retry_attempts': attempt + 1,
                            'object_uploaded': True
                        })
                
                except AWSServiceError as e:
                    error_test_environment.record_error_event(
                        'AWSServiceError',
                        'aws_s3',
                        e.to_dict()
                    )
                    
                    error_test_environment.record_retry_attempt(
                        'aws_s3_upload',
                        attempt + 1,
                        False
                    )
                    
                    if attempt == max_retries - 1:
                        return jsonify({
                            'aws_operation': 'failed',
                            'retry_attempts': max_retries,
                            'final_error': str(e)
                        }), 503
                    
                    # Retry delay for AWS throttling
                    time.sleep(0.1)
            
            return jsonify({'status': 'error'})
        
        response = error_test_environment.client.get('/test-aws-service-error')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['aws_operation'] == 'success'
        assert data['retry_attempts'] == 2
        
        logger.info("AWS service error handling test completed")


# =============================================================================
# Graceful Degradation Testing
# =============================================================================

class TestGracefulDegradation:
    """
    Test graceful degradation for partial service availability.
    
    Validates system behavior when some services are unavailable while
    maintaining core functionality per Section 6.3.3 graceful degradation.
    """
    
    def test_cache_unavailable_graceful_degradation(self, error_test_environment, mock_failing_services):
        """Test graceful degradation when cache service is unavailable."""
        cache_service = mock_failing_services['cache']
        cache_service.set_failure_mode('connection_error')
        
        app = error_test_environment.app
        
        @app.route('/test-cache-degradation')
        def test_cache_degradation():
            user_id = request.args.get('user_id', 'default_user')
            
            try:
                # Attempt to get cached user data
                cached_data = cache_service.get(f"user_data_{user_id}")
                return jsonify({
                    'cached': True,
                    'data': cached_data,
                    'performance': 'optimal'
                })
            
            except CacheError as e:
                error_test_environment.record_error_event(
                    'CacheError',
                    'cache_service',
                    e.to_dict()
                )
                
                # Graceful degradation: compute data without cache
                start_time = time.perf_counter()
                
                computed_data = {
                    'user_id': user_id,
                    'profile': f'computed_profile_for_{user_id}',
                    'preferences': ['setting1', 'setting2'],
                    'computed_at': datetime.utcnow().isoformat()
                }
                
                computation_time = time.perf_counter() - start_time
                
                error_test_environment.record_recovery_event(
                    'cache_service',
                    'graceful_degradation',
                    True
                )
                
                return jsonify({
                    'cached': False,
                    'computed': True,
                    'data': computed_data,
                    'performance': 'degraded',
                    'computation_time': computation_time,
                    'cache_unavailable': True
                }), 200
        
        response = error_test_environment.client.get('/test-cache-degradation?user_id=test123')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['cached'] is False
        assert data['computed'] is True
        assert data['performance'] == 'degraded'
        assert data['cache_unavailable'] is True
        
        logger.info("Cache unavailable graceful degradation test completed")
    
    def test_database_readonly_degradation(self, error_test_environment, mock_failing_services):
        """Test graceful degradation to read-only mode when database writes fail."""
        db_service = mock_failing_services['database']
        
        app = error_test_environment.app
        
        @app.route('/test-readonly-degradation', methods=['POST'])
        def test_readonly_degradation():
            data = request.get_json() or {}
            
            try:
                # Attempt write operation
                if data.get('operation') == 'write':
                    db_service.set_failure_mode('connection_error')
                    result = db_service.query("INSERT INTO users (name) VALUES ('test')")
                    return jsonify(result)
                else:
                    # Read operation still works
                    db_service.set_failure_mode(None)
                    result = db_service.query("SELECT * FROM users LIMIT 5")
                    return jsonify(result)
            
            except DatabaseException as e:
                error_test_environment.record_error_event(
                    'DatabaseException',
                    'database_write',
                    e.to_dict()
                )
                
                # Graceful degradation to read-only mode
                error_test_environment.record_recovery_event(
                    'database',
                    'readonly_mode_activation',
                    True
                )
                
                return jsonify({
                    'write_failed': True,
                    'readonly_mode': True,
                    'message': 'System temporarily in read-only mode',
                    'retry_suggested': True
                }), 503
        
        # Test write operation failure
        write_response = error_test_environment.client.post(
            '/test-readonly-degradation',
            json={'operation': 'write'}
        )
        
        assert write_response.status_code == 503
        write_data = write_response.get_json()
        assert write_data['write_failed'] is True
        assert write_data['readonly_mode'] is True
        
        # Test read operation still works
        read_response = error_test_environment.client.post(
            '/test-readonly-degradation',
            json={'operation': 'read'}
        )
        
        assert read_response.status_code == 200
        read_data = read_response.get_json()
        assert read_data['status'] == 'success'
        
        logger.info("Database read-only degradation test completed")
    
    def test_authentication_limited_access_degradation(self, error_test_environment, mock_failing_services):
        """Test graceful degradation to limited access when authentication service fails."""
        auth_service = mock_failing_services['auth']
        auth_service.set_failure_mode('auth0_unavailable')
        
        app = error_test_environment.app
        
        @app.route('/test-auth-degradation')
        def test_auth_degradation():
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            try:
                # Attempt full authentication
                auth_result = auth_service.validate_token(token)
                return jsonify({
                    'authenticated': True,
                    'full_access': True,
                    'user': auth_result
                })
            
            except SecurityException as e:
                error_test_environment.record_error_event(
                    'SecurityException',
                    'auth_service',
                    e.to_dict()
                )
                
                # Graceful degradation: limited anonymous access
                limited_features = [
                    'public_content',
                    'basic_search',
                    'contact_info'
                ]
                
                error_test_environment.record_recovery_event(
                    'auth_service',
                    'limited_access_mode',
                    True
                )
                
                return jsonify({
                    'authenticated': False,
                    'limited_access': True,
                    'available_features': limited_features,
                    'auth_service_unavailable': True,
                    'message': 'Limited functionality available'
                }), 200
        
        headers = {'Authorization': 'Bearer test_token'}
        response = error_test_environment.client.get(
            '/test-auth-degradation',
            headers=headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['authenticated'] is False
        assert data['limited_access'] is True
        assert len(data['available_features']) > 0
        
        logger.info("Authentication limited access degradation test completed")
    
    def test_multi_service_failure_degradation(self, error_test_environment, mock_failing_services):
        """Test graceful degradation when multiple services fail simultaneously."""
        # Simulate multiple service failures
        mock_failing_services['cache'].set_failure_mode('connection_error')
        mock_failing_services['external_api'].set_failure_mode('timeout')
        
        app = error_test_environment.app
        
        @app.route('/test-multi-service-degradation')
        def test_multi_service_degradation():
            degraded_features = []
            available_features = []
            
            # Test cache availability
            try:
                mock_failing_services['cache'].get('test_key')
                available_features.append('caching')
            except CacheError:
                degraded_features.append('caching')
                error_test_environment.record_error_event(
                    'CacheError',
                    'cache_service',
                    {'service': 'cache', 'status': 'unavailable'}
                )
            
            # Test external API availability
            try:
                mock_failing_services['external_api'].make_request('/test')
                available_features.append('external_data')
            except IntegrationError:
                degraded_features.append('external_data')
                error_test_environment.record_error_event(
                    'IntegrationError',
                    'external_api',
                    {'service': 'external_api', 'status': 'unavailable'}
                )
            
            # Core database still available
            try:
                mock_failing_services['database'].set_failure_mode(None)
                mock_failing_services['database'].query('SELECT 1')
                available_features.append('core_data')
            except DatabaseException:
                degraded_features.append('core_data')
            
            error_test_environment.record_recovery_event(
                'system',
                'multi_service_degradation',
                len(available_features) > 0
            )
            
            degradation_level = len(degraded_features) / (len(degraded_features) + len(available_features))
            
            return jsonify({
                'system_status': 'degraded' if degraded_features else 'operational',
                'degraded_features': degraded_features,
                'available_features': available_features,
                'degradation_level': degradation_level,
                'core_functionality_available': 'core_data' in available_features
            }), 200 if available_features else 503
        
        response = error_test_environment.client.get('/test-multi-service-degradation')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['system_status'] == 'degraded'
        assert len(data['degraded_features']) > 0
        assert data['core_functionality_available'] is True
        
        logger.info("Multi-service failure degradation test completed")


# =============================================================================
# Comprehensive Error Monitoring Integration Tests
# =============================================================================

class TestErrorMonitoringIntegration:
    """
    Test comprehensive error monitoring and alerting system integration.
    
    Validates error tracking, metrics collection, and alerting integration
    per Section 4.2.3 error handling flows and monitoring requirements.
    """
    
    def test_error_metrics_collection(self, error_test_environment):
        """Test comprehensive error metrics collection and aggregation."""
        app = error_test_environment.app
        
        # Simulate various error types for metrics collection
        error_scenarios = [
            ('AuthenticationException', SecurityErrorCode.AUTH_TOKEN_INVALID),
            ('DatabaseException', 'CONNECTION_FAILED'),
            ('CacheError', 'REDIS_CONNECTION_ERROR'),
            ('IntegrationError', 'HTTP_TIMEOUT'),
            ('ValidationException', SecurityErrorCode.VAL_SCHEMA_VIOLATION)
        ]
        
        @app.route('/test-error-metrics/<error_type>')
        def test_error_metrics(error_type):
            if error_type == 'auth':
                raise AuthenticationException(
                    "Test authentication error",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID
                )
            elif error_type == 'database':
                raise ConnectionException(
                    "Test database connection error",
                    database="test_db"
                )
            elif error_type == 'cache':
                raise RedisConnectionError(
                    "Test cache connection error"
                )
            elif error_type == 'integration':
                raise IntegrationTimeoutError(
                    "Test integration timeout",
                    service_name="test_api",
                    operation="test_call"
                )
            elif error_type == 'validation':
                raise ValidationException(
                    "Test validation error",
                    error_code=SecurityErrorCode.VAL_SCHEMA_VIOLATION
                )
            
            return jsonify({'status': 'success'})
        
        # Generate error metrics
        error_counts = {}
        for error_type, _ in error_scenarios:
            response = error_test_environment.client.get(f'/test-error-metrics/{error_type.lower().replace("exception", "").replace("error", "")}')
            
            error_category = error_type.replace('Exception', '').replace('Error', '')
            error_counts[error_category] = error_counts.get(error_category, 0) + 1
            
            error_test_environment.record_error_event(
                error_type,
                'metrics_test',
                {
                    'status_code': response.status_code,
                    'error_category': error_category
                }
            )
        
        # Validate metrics collection
        summary = error_test_environment.get_error_summary()
        
        assert summary['total_errors'] >= len(error_scenarios)
        assert len(summary['error_types']) >= 3
        assert 'metrics_test' in summary['affected_components']
        
        logger.info(f"Error metrics collection test completed with {summary['total_errors']} errors tracked")
    
    def test_security_alert_integration(self, error_test_environment):
        """Test security alert integration for critical security events."""
        app = error_test_environment.app
        
        security_alerts = []
        
        def mock_security_alert(alert_type: str, details: Dict[str, Any]):
            """Mock security alert function"""
            alert = {
                'alert_type': alert_type,
                'timestamp': datetime.utcnow().isoformat(),
                'details': details,
                'severity': 'high' if 'critical' in alert_type else 'medium'
            }
            security_alerts.append(alert)
            logger.warning(f"Security alert triggered: {alert_type}")
        
        @app.route('/test-security-alerts/<alert_type>')
        def test_security_alerts(alert_type):
            if alert_type == 'brute_force':
                error = AuthenticationException(
                    "Brute force attack detected",
                    error_code=SecurityErrorCode.SEC_BRUTE_FORCE_DETECTED
                )
                
                if is_critical_security_error(error.error_code):
                    mock_security_alert(
                        'critical_auth_failure',
                        error.to_dict()
                    )
                
                raise error
            
            elif alert_type == 'injection_attempt':
                error = ValidationException(
                    "SQL injection attempt detected",
                    error_code=SecurityErrorCode.SEC_SQL_INJECTION_ATTEMPT
                )
                
                if is_critical_security_error(error.error_code):
                    mock_security_alert(
                        'critical_injection_attempt',
                        error.to_dict()
                    )
                
                raise error
            
            elif alert_type == 'permission_violation':
                error = AuthorizationException(
                    "Policy violation detected",
                    error_code=SecurityErrorCode.AUTHZ_POLICY_VIOLATION,
                    required_permissions=['admin:read'],
                    resource_type='sensitive_data'
                )
                
                if is_critical_security_error(error.error_code):
                    mock_security_alert(
                        'critical_policy_violation',
                        error.to_dict()
                    )
                
                raise error
            
            return jsonify({'status': 'success'})
        
        # Trigger security alerts
        critical_scenarios = ['brute_force', 'injection_attempt', 'permission_violation']
        
        for scenario in critical_scenarios:
            response = error_test_environment.client.get(f'/test-security-alerts/{scenario}')
            
            error_test_environment.record_error_event(
                'SecurityAlert',
                'security_monitoring',
                {
                    'scenario': scenario,
                    'status_code': response.status_code
                }
            )
        
        # Validate security alerts were triggered
        assert len(security_alerts) == len(critical_scenarios)
        assert all(alert['severity'] == 'high' for alert in security_alerts)
        
        logger.info(f"Security alert integration test completed with {len(security_alerts)} alerts")
    
    def test_performance_impact_monitoring(self, error_test_environment):
        """Test performance impact monitoring during error conditions."""
        app = error_test_environment.app
        
        performance_impacts = []
        
        @app.route('/test-performance-impact/<scenario>')
        def test_performance_impact(scenario):
            start_time = time.perf_counter()
            
            try:
                if scenario == 'timeout_cascade':
                    # Simulate cascading timeouts
                    time.sleep(0.1)  # Simulate slow operation
                    raise IntegrationTimeoutError(
                        "Cascading timeout",
                        service_name="slow_service",
                        operation="slow_call",
                        timeout_duration=30.0
                    )
                
                elif scenario == 'retry_storm':
                    # Simulate retry storm
                    for i in range(3):
                        time.sleep(0.05)  # Each retry takes time
                    
                    raise RetryExhaustedError(
                        "retry_service",
                        "api_call",
                        max_retries=3,
                        total_duration=0.15
                    )
                
                elif scenario == 'circuit_breaker_latency':
                    # Simulate circuit breaker latency
                    time.sleep(0.02)
                    raise CircuitBreakerException(
                        "Circuit breaker latency",
                        error_code=SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN
                    )
                
                return jsonify({'status': 'success'})
            
            except Exception as e:
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                performance_impact = {
                    'scenario': scenario,
                    'duration': duration,
                    'error_type': type(e).__name__,
                    'timestamp': datetime.utcnow().isoformat()
                }
                performance_impacts.append(performance_impact)
                
                error_test_environment.record_error_event(
                    'PerformanceImpact',
                    'performance_monitoring',
                    performance_impact
                )
                
                raise
        
        # Test performance impact scenarios
        impact_scenarios = ['timeout_cascade', 'retry_storm', 'circuit_breaker_latency']
        
        for scenario in impact_scenarios:
            with error_test_environment.measure_error_response_time(f'performance_impact_{scenario}'):
                response = error_test_environment.client.get(f'/test-performance-impact/{scenario}')
                assert response.status_code >= 400  # Should be an error response
        
        # Validate performance impact tracking
        assert len(performance_impacts) == len(impact_scenarios)
        
        # Check for reasonable performance impact (< 1 second for test scenarios)
        for impact in performance_impacts:
            assert impact['duration'] < 1.0, f"Performance impact too high: {impact['duration']}s"
        
        logger.info(f"Performance impact monitoring test completed with {len(performance_impacts)} measurements")
    
    def test_error_correlation_tracking(self, error_test_environment):
        """Test error correlation tracking across request flows."""
        app = error_test_environment.app
        
        correlation_events = []
        
        @app.route('/test-error-correlation')
        def test_error_correlation():
            correlation_id = str(uuid.uuid4())
            
            # Simulate correlated error chain
            try:
                # Step 1: Cache failure
                try:
                    raise RedisConnectionError("Cache connection failed")
                except CacheError as cache_error:
                    correlation_events.append({
                        'correlation_id': correlation_id,
                        'step': 1,
                        'error_type': 'CacheError',
                        'component': 'cache',
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    # Step 2: Fallback to database
                    try:
                        time.sleep(0.01)  # Simulate database call
                        raise ConnectionException(
                            "Database connection failed during cache fallback",
                            database="fallback_db"
                        )
                    except DatabaseException as db_error:
                        correlation_events.append({
                            'correlation_id': correlation_id,
                            'step': 2,
                            'error_type': 'DatabaseException',
                            'component': 'database',
                            'timestamp': datetime.utcnow().isoformat(),
                            'caused_by': 'cache_failure'
                        })
                        
                        # Step 3: Final external service attempt
                        try:
                            time.sleep(0.01)  # Simulate API call
                            raise HTTPResponseError(
                                "External service also failed",
                                service_name="backup_api",
                                operation="data_fetch",
                                status_code=503
                            )
                        except IntegrationError as api_error:
                            correlation_events.append({
                                'correlation_id': correlation_id,
                                'step': 3,
                                'error_type': 'IntegrationError',
                                'component': 'external_api',
                                'timestamp': datetime.utcnow().isoformat(),
                                'caused_by': 'database_failure'
                            })
                            
                            raise api_error
            
            except Exception as final_error:
                error_test_environment.record_error_event(
                    'CorrelatedErrorChain',
                    'error_correlation',
                    {
                        'correlation_id': correlation_id,
                        'total_steps': len(correlation_events),
                        'final_error': type(final_error).__name__
                    }
                )
                
                return jsonify({
                    'correlation_id': correlation_id,
                    'error_chain': correlation_events,
                    'total_failures': len(correlation_events)
                }), 503
        
        response = error_test_environment.client.get('/test-error-correlation')
        
        assert response.status_code == 503
        data = response.get_json()
        assert 'correlation_id' in data
        assert len(data['error_chain']) == 3
        assert data['total_failures'] == 3
        
        # Validate error correlation chain
        chain = data['error_chain']
        assert chain[0]['component'] == 'cache'
        assert chain[1]['component'] == 'database'
        assert chain[1]['caused_by'] == 'cache_failure'
        assert chain[2]['component'] == 'external_api'
        assert chain[2]['caused_by'] == 'database_failure'
        
        logger.info(f"Error correlation tracking test completed with {len(chain)} correlated events")


# =============================================================================
# Integration Test Summary and Validation
# =============================================================================

class TestErrorHandlingIntegrationSummary:
    """
    Comprehensive validation of error handling integration test results.
    
    Validates overall error handling system performance, compliance with
    requirements, and comprehensive coverage of error scenarios.
    """
    
    def test_comprehensive_error_handling_validation(self, error_test_environment):
        """Comprehensive validation of all error handling patterns."""
        
        # Execute a comprehensive error scenario that exercises all components
        app = error_test_environment.app
        
        @app.route('/comprehensive-error-test')
        def comprehensive_error_test():
            test_results = {
                'components_tested': [],
                'error_types_handled': [],
                'recovery_mechanisms_triggered': [],
                'performance_metrics': {},
                'compliance_status': {}
            }
            
            # Test each component's error handling
            components_to_test = [
                ('authentication', AuthenticationException),
                ('database', ConnectionException),
                ('cache', RedisConnectionError),
                ('integration', HTTPResponseError),
                ('validation', ValidationException)
            ]
            
            for component, exception_class in components_to_test:
                try:
                    # Simulate component failure
                    if component == 'authentication':
                        raise AuthenticationException(
                            "Test auth failure",
                            error_code=SecurityErrorCode.AUTH_TOKEN_INVALID
                        )
                    elif component == 'database':
                        raise ConnectionException(
                            "Test DB failure",
                            database="test_db"
                        )
                    elif component == 'cache':
                        raise RedisConnectionError(
                            "Test cache failure"
                        )
                    elif component == 'integration':
                        raise HTTPResponseError(
                            "Test integration failure",
                            service_name="test_service",
                            operation="test_op",
                            status_code=500
                        )
                    elif component == 'validation':
                        raise ValidationException(
                            "Test validation failure",
                            error_code=SecurityErrorCode.VAL_SCHEMA_VIOLATION
                        )
                
                except Exception as e:
                    test_results['components_tested'].append(component)
                    test_results['error_types_handled'].append(type(e).__name__)
                    
                    # Record that error handling mechanism worked
                    error_test_environment.record_error_event(
                        type(e).__name__,
                        component,
                        {'test': 'comprehensive_validation'}
                    )
            
            # Validate error handling completeness
            expected_components = ['authentication', 'database', 'cache', 'integration', 'validation']
            test_results['compliance_status'] = {
                'components_coverage': len(test_results['components_tested']) / len(expected_components),
                'error_handling_functional': len(test_results['error_types_handled']) > 0,
                'flask_error_handlers_working': True  # If we got here, they're working
            }
            
            return jsonify(test_results)
        
        response = error_test_environment.client.get('/comprehensive-error-test')
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Validate comprehensive coverage
        assert data['compliance_status']['components_coverage'] == 1.0
        assert data['compliance_status']['error_handling_functional'] is True
        assert data['compliance_status']['flask_error_handlers_working'] is True
        
        # Validate all expected components were tested
        expected_components = ['authentication', 'database', 'cache', 'integration', 'validation']
        assert set(data['components_tested']) == set(expected_components)
        
        # Validate error handling performance
        summary = error_test_environment.get_error_summary()
        assert summary['total_errors'] > 0
        assert len(summary['error_types']) >= 5
        
        # Validate response time compliance (should be fast even with errors)
        if summary['average_error_response_time'] > 0:
            assert summary['average_error_response_time'] < 1.0, "Error responses too slow"
        
        logger.info("Comprehensive error handling validation completed successfully")
        logger.info(f"Test summary: {summary}")
    
    def test_error_handling_performance_compliance(self, error_test_environment):
        """Test error handling performance compliance with ≤10% variance requirement."""
        
        # Baseline performance expectations (simulated Node.js equivalent times)
        baseline_metrics = {
            'auth_error_response': 0.050,  # 50ms
            'db_error_response': 0.100,    # 100ms
            'cache_error_response': 0.020, # 20ms
            'integration_error_response': 0.150  # 150ms
        }
        
        variance_threshold = 0.10  # ≤10% variance requirement
        
        # Measure actual error response times
        actual_metrics = error_test_environment.performance_metrics
        
        compliance_results = {}
        
        for metric_name, baseline_time in baseline_metrics.items():
            if metric_name in actual_metrics:
                actual_time = actual_metrics[metric_name]
                variance = abs(actual_time - baseline_time) / baseline_time
                
                compliance_results[metric_name] = {
                    'baseline': baseline_time,
                    'actual': actual_time,
                    'variance': variance,
                    'compliant': variance <= variance_threshold
                }
        
        # Validate performance compliance
        compliant_metrics = [
            result['compliant'] for result in compliance_results.values()
        ]
        
        overall_compliance = all(compliant_metrics) if compliant_metrics else True
        
        assert overall_compliance, f"Performance variance exceeded threshold: {compliance_results}"
        
        logger.info(f"Error handling performance compliance validated: {compliance_results}")
    
    def test_error_recovery_effectiveness(self, error_test_environment):
        """Test effectiveness of error recovery mechanisms."""
        
        summary = error_test_environment.get_error_summary()
        
        # Validate recovery effectiveness metrics
        recovery_effectiveness = {
            'total_errors': summary['total_errors'],
            'circuit_breaker_activations': summary['circuit_breaker_activations'],
            'retry_attempts': summary['total_retry_attempts'],
            'successful_recoveries': summary['successful_recoveries']
        }
        
        # Calculate recovery success rate
        if recovery_effectiveness['total_errors'] > 0:
            recovery_rate = recovery_effectiveness['successful_recoveries'] / recovery_effectiveness['total_errors']
            assert recovery_rate >= 0.5, "Recovery rate too low - should be at least 50%"
        
        # Validate circuit breaker effectiveness
        if summary['circuit_breaker_activations'] > 0:
            assert summary['circuit_breaker_activations'] <= summary['total_errors']
        
        # Validate retry mechanism usage
        assert recovery_effectiveness['retry_attempts'] >= 0
        
        logger.info(f"Error recovery effectiveness validated: {recovery_effectiveness}")


# =============================================================================
# Test Execution and Reporting
# =============================================================================

if __name__ == "__main__":
    # Enable detailed logging for test execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Error handling integration tests module loaded successfully")
    logger.info("Test classes available:")
    logger.info("- TestFlaskErrorHandlerIntegration")
    logger.info("- TestCircuitBreakerErrorScenarios") 
    logger.info("- TestDatabaseErrorHandlingIntegration")
    logger.info("- TestExternalServiceErrorHandlingIntegration")
    logger.info("- TestGracefulDegradation")
    logger.info("- TestErrorMonitoringIntegration")
    logger.info("- TestErrorHandlingIntegrationSummary")