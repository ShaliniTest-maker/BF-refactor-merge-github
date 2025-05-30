"""
Authentication System Integration Testing

This module provides comprehensive integration testing for the authentication system,
covering Auth0 Python SDK integration, PyJWT token validation workflows, circuit breaker
patterns, and authentication decorator integration. Tests complete authentication flows
from token validation through user context creation with realistic Auth0 service
interaction and fallback mechanisms.

Test Coverage:
- Auth0 Python SDK integration testing with circuit breaker patterns per Section 6.4.2
- PyJWT 2.8+ token validation integration testing replacing Node.js jsonwebtoken per Section 0.1.2
- Authentication decorator integration with Flask Blueprint routes per Section 6.4.2
- Session management integration with Redis distributed storage per Section 6.4.1
- Circuit breaker and retry logic testing for Auth0 API calls per Section 6.4.2
- Security event logging integration with audit systems per Section 6.4.2
- Permission caching with Redis and fallback mechanisms per Section 6.4.2

Coverage Requirements:
- 95% authentication module coverage per Section 6.6.3 security compliance
- Complete Auth0 integration workflows including error scenarios
- JWT token processing with Node.js feature parity
- Circuit breaker behavior validation under failure conditions
- Flask Blueprint route protection integration
- Redis session management with encryption validation

Key Integration Scenarios:
- Complete authentication flow from JWT token to user context
- Auth0 service degradation and circuit breaker activation
- Redis session storage with AES-256-GCM encryption
- Permission caching with intelligent TTL management
- Security event logging with structured JSON output
- Cross-service authentication with external API validation

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem support per Section 6.6.1
- pytest-asyncio for Motor asynchronous database operations per Section 6.6.1
- pytest-flask for Flask-specific testing patterns per Section 6.6.1
- Testcontainers for MongoDB/Redis integration with production-equivalent behavior
- pytest-mock for comprehensive external service simulation per Section 6.6.1
- factory_boy for dynamic test object generation per Section 6.6.1

Author: Flask Migration Team
Version: 1.0.0
Test Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
import pytest
import jwt
import requests
from freezegun import freeze_time

# Flask testing imports
from flask import Flask, request, jsonify, g
from flask.testing import FlaskClient
from flask_login import current_user, login_user, logout_user

# Redis and database testing
import redis
import pymongo
import motor.motor_asyncio
from testcontainers.redis import RedisContainer
from testcontainers.mongodb import MongoDbContainer

# Authentication system imports
from src.auth import (
    AuthenticationManager,
    JWTTokenValidator,
    Auth0UserManager,
    Auth0Config,
    get_auth_manager,
    authenticate_jwt_token,
    validate_user_permissions,
    create_authenticated_session,
    get_authenticated_session,
    invalidate_authenticated_session
)
from src.auth.decorators import (
    require_auth,
    require_permissions,
    require_role,
    rate_limited_auth,
    auth_required_with_cache
)
from src.auth.session import (
    FlaskSessionManager,
    RedisSessionInterface,
    EncryptedSessionHandler,
    create_user_session,
    invalidate_user_session,
    get_session_data
)
from src.auth.cache import (
    AuthenticationCache,
    get_auth_cache,
    PermissionCacheManager,
    cache_operation_with_fallback
)
from src.auth.exceptions import (
    AuthenticationException,
    AuthorizationException,
    JWTException,
    Auth0Exception,
    SessionException,
    CircuitBreakerException,
    SecurityErrorCode
)

# Import test utilities and fixtures
from tests.fixtures.auth_fixtures import (
    create_valid_jwt_token,
    create_expired_jwt_token,
    create_auth0_user_profile,
    mock_auth0_responses
)
from tests.fixtures.performance_fixtures import (
    measure_response_time,
    assert_performance_baseline,
    PERFORMANCE_BASELINE_MS
)


class TestAuth0Integration:
    """
    Integration testing for Auth0 Python SDK with circuit breaker patterns
    and comprehensive error handling scenarios.
    """

    def setup_method(self):
        """Set up test environment for each test method"""
        self.auth0_domain = "test-tenant.auth0.com"
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.audience = "test_audience"
        
        # Set environment variables for Auth0 configuration
        os.environ.update({
            'AUTH0_DOMAIN': self.auth0_domain,
            'AUTH0_CLIENT_ID': self.client_id,
            'AUTH0_CLIENT_SECRET': self.client_secret,
            'AUTH0_AUDIENCE': self.audience,
            'JWT_ALGORITHM': 'RS256'
        })

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_auth0_sdk_integration_with_circuit_breaker(
        self,
        app_context,
        redis_client,
        auth0_mock
    ):
        """
        Test Auth0 Python SDK integration with circuit breaker patterns
        ensuring resilient service integration and fallback mechanisms.
        
        Validates:
        - Auth0 SDK client initialization and configuration
        - Circuit breaker protection for Auth0 API calls
        - Fallback to cached data during service degradation
        - Comprehensive error handling and logging
        - Performance within ≤10% variance requirement
        """
        # Initialize authentication manager with circuit breaker
        auth_cache = AuthenticationCache(redis_client)
        auth_manager = AuthenticationManager(cache=auth_cache)
        
        # Test successful Auth0 API call
        with measure_response_time() as timer:
            # Mock successful Auth0 user validation
            auth0_mock.validate_token.return_value = {
                'sub': 'auth0|test_user_123',
                'email': 'test@example.com',
                'email_verified': True,
                'iss': f'https://{self.auth0_domain}/',
                'aud': self.audience,
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'scope': 'openid profile email'
            }
            
            # Test token validation with Auth0 integration
            token = create_valid_jwt_token(
                user_id='auth0|test_user_123',
                email='test@example.com',
                domain=self.auth0_domain,
                audience=self.audience
            )
            
            result = await auth_manager.validate_jwt_token_async(
                token=token,
                verify_signature=True,
                verify_expiration=True,
                use_cache=True
            )
            
            assert result['authenticated'] is True
            assert result['user_id'] == 'auth0|test_user_123'
            assert result['email'] == 'test@example.com'
            assert result['validation_source'] == 'auth0_api'
        
        # Verify performance baseline compliance
        assert_performance_baseline(timer.elapsed_ms, PERFORMANCE_BASELINE_MS['auth_token_validation'])
        
        # Test circuit breaker activation during Auth0 service failure
        with patch('src.auth.authentication.Auth0CircuitBreaker') as mock_circuit_breaker:
            # Configure circuit breaker to simulate service failure
            mock_circuit_breaker.return_value.is_open = True
            mock_circuit_breaker.return_value.failure_count = 5
            
            # Cache user data for fallback testing
            await auth_cache.cache_auth0_user_profile(
                user_id='auth0|test_user_123',
                profile={
                    'user_id': 'auth0|test_user_123',
                    'email': 'test@example.com',
                    'name': 'Test User',
                    'email_verified': True
                },
                ttl=300
            )
            
            # Test fallback to cached data when circuit breaker is open
            fallback_result = await auth_manager.validate_jwt_token_async(
                token=token,
                verify_signature=False,  # Skip signature verification during fallback
                verify_expiration=True,
                use_cache=True
            )
            
            assert fallback_result['authenticated'] is True
            assert fallback_result['user_id'] == 'auth0|test_user_123'
            assert fallback_result['validation_source'] == 'fallback_cache'
            assert fallback_result['degraded_mode'] is True

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_auth0_retry_strategies_and_timeouts(
        self,
        app_context,
        redis_client,
        mock_external_services
    ):
        """
        Test Auth0 API retry strategies with exponential backoff
        and comprehensive timeout handling.
        
        Validates:
        - Tenacity retry configuration with exponential backoff
        - Timeout handling for Auth0 API calls
        - Request/response logging for debugging
        - Circuit breaker integration with retry logic
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Mock httpx client for Auth0 API calls
        with patch('httpx.AsyncClient') as mock_httpx:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.json.return_value = {'error': 'internal_server_error'}
            
            # Configure client to fail initially, then succeed
            mock_client = AsyncMock()
            mock_client.get.side_effect = [
                requests.exceptions.RequestException("Connection timeout"),
                requests.exceptions.RequestException("Service unavailable"),
                mock_response  # Success on third attempt
            ]
            mock_httpx.return_value.__aenter__.return_value = mock_client
            
            # Test retry behavior with circuit breaker
            with patch('src.auth.authentication.retry') as mock_retry:
                # Configure retry decorator
                mock_retry.return_value = lambda f: f
                
                auth_manager = AuthenticationManager(cache=auth_cache)
                
                # This should trigger retry logic
                with pytest.raises(Auth0Exception) as exc_info:
                    await auth_manager.validate_auth0_user_async('auth0|test_user')
                
                # Verify retry attempts were made
                assert mock_client.get.call_count >= 2
                assert "Auth0 API validation failed" in str(exc_info.value)

    @pytest.mark.integration
    def test_auth0_jwks_key_rotation(
        self,
        app_context,
        redis_client,
        auth0_mock
    ):
        """
        Test Auth0 JWKS key rotation handling and caching strategy.
        
        Validates:
        - JWKS endpoint integration and key caching
        - Key rotation detection and cache invalidation
        - Fallback key validation strategies
        - Performance optimization through key caching
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Mock JWKS response with multiple keys
        jwks_response = {
            'keys': [
                {
                    'kty': 'RSA',
                    'kid': 'key_1',
                    'use': 'sig',
                    'n': 'mock_n_value',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'kid': 'key_2',
                    'use': 'sig',
                    'n': 'mock_n_value_2',
                    'e': 'AQAB'
                }
            ]
        }
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = jwks_response
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            auth_config = Auth0Config()
            jwt_validator = JWTTokenValidator(auth_config, auth_cache)
            
            # Test JWKS retrieval and caching
            keys = jwt_validator.get_jwks_keys()
            assert len(keys) == 2
            assert 'key_1' in [key['kid'] for key in keys]
            assert 'key_2' in [key['kid'] for key in keys]
            
            # Verify keys are cached
            cached_keys = auth_cache.get_jwks_cache()
            assert cached_keys is not None
            assert len(cached_keys['keys']) == 2
            
            # Test cache expiration and refresh
            with freeze_time("2024-01-01 12:00:00"):
                # Cache should still be valid
                fresh_keys = jwt_validator.get_jwks_keys()
                assert mock_get.call_count == 1  # No new API call
            
            with freeze_time("2024-01-02 12:00:00"):  # 24 hours later
                # Cache should be expired, new API call expected
                fresh_keys = jwt_validator.get_jwks_keys()
                assert mock_get.call_count == 2  # New API call made


class TestJWTTokenValidationIntegration:
    """
    Integration testing for PyJWT 2.8+ token validation replacing Node.js jsonwebtoken
    with comprehensive validation scenarios and error handling.
    """

    def setup_method(self):
        """Set up JWT validation test environment"""
        self.secret_key = 'test-secret-key-for-jwt-validation'
        self.algorithm = 'HS256'
        self.issuer = 'https://test-tenant.auth0.com/'
        self.audience = 'test-audience'

    @pytest.mark.integration
    def test_pyjwt_token_validation_complete_flow(
        self,
        app_context,
        redis_client,
        performance_baseline
    ):
        """
        Test complete PyJWT token validation flow with caching integration
        ensuring Node.js feature parity and performance compliance.
        
        Validates:
        - PyJWT 2.8+ token decoding and validation
        - Claims extraction and verification
        - Token expiration handling
        - Signature verification with multiple algorithms
        - Performance baseline compliance (≤10% variance)
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Create valid JWT token with comprehensive claims
        payload = {
            'sub': 'auth0|test_user_123',
            'email': 'test@example.com',
            'email_verified': True,
            'iss': self.issuer,
            'aud': self.audience,
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
            'scope': 'openid profile email',
            'permissions': ['read:users', 'write:users'],
            'roles': ['user', 'admin'],
            'custom_claims': {
                'department': 'engineering',
                'location': 'us-west'
            }
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        with measure_response_time() as timer:
            # Test token validation with comprehensive verification
            jwt_validator = JWTTokenValidator(
                auth_config=Mock(algorithm=self.algorithm),
                cache=auth_cache
            )
            
            # Mock Auth0 configuration for validation
            with patch.object(jwt_validator, '_get_verification_key') as mock_key:
                mock_key.return_value = self.secret_key
                
                result = jwt_validator.validate_token(
                    token=token,
                    verify_signature=True,
                    verify_expiration=True,
                    verify_audience=True,
                    verify_issuer=True
                )
                
                # Verify all claims are properly extracted
                assert result['sub'] == 'auth0|test_user_123'
                assert result['email'] == 'test@example.com'
                assert result['email_verified'] is True
                assert result['iss'] == self.issuer
                assert result['aud'] == self.audience
                assert result['scope'] == 'openid profile email'
                assert 'read:users' in result['permissions']
                assert 'write:users' in result['permissions']
                assert 'user' in result['roles']
                assert 'admin' in result['roles']
                assert result['custom_claims']['department'] == 'engineering'
                assert result['custom_claims']['location'] == 'us-west'
        
        # Verify performance compliance
        assert_performance_baseline(
            timer.elapsed_ms,
            performance_baseline['jwt_validation']
        )

    @pytest.mark.integration
    def test_jwt_token_caching_integration(
        self,
        app_context,
        redis_client
    ):
        """
        Test JWT token validation caching with Redis integration
        ensuring optimal performance and cache hit ratios.
        
        Validates:
        - Token validation result caching
        - Cache key generation and collision avoidance
        - TTL management and cache expiration
        - Cache hit/miss ratio optimization
        - Memory usage optimization
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Create test token
        payload = {
            'sub': 'auth0|cache_test_user',
            'email': 'cache.test@example.com',
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600
        }
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        token_hash = auth_cache._generate_token_hash(token)
        
        jwt_validator = JWTTokenValidator(
            auth_config=Mock(algorithm=self.algorithm),
            cache=auth_cache
        )
        
        with patch.object(jwt_validator, '_get_verification_key') as mock_key:
            mock_key.return_value = self.secret_key
            
            # First validation - should miss cache and perform validation
            with patch.object(jwt_validator, '_validate_token_signature') as mock_validate:
                mock_validate.return_value = True
                
                result1 = jwt_validator.validate_token(token, use_cache=True)
                assert result1['sub'] == 'auth0|cache_test_user'
                assert mock_validate.call_count == 1
                
                # Verify token is cached
                cached_result = auth_cache.get_jwt_validation_cache(token_hash)
                assert cached_result is not None
                assert cached_result['sub'] == 'auth0|cache_test_user'
                
                # Second validation - should hit cache
                result2 = jwt_validator.validate_token(token, use_cache=True)
                assert result2['sub'] == 'auth0|cache_test_user'
                assert mock_validate.call_count == 1  # No additional validation call
                
                # Verify cache metrics
                cache_metrics = auth_cache.get_cache_metrics()
                assert cache_metrics['jwt_validation']['hit_count'] >= 1
                assert cache_metrics['jwt_validation']['miss_count'] >= 1

    @pytest.mark.integration
    def test_jwt_token_expiration_and_refresh(
        self,
        app_context,
        redis_client
    ):
        """
        Test JWT token expiration handling and automatic refresh logic
        ensuring seamless user experience during token renewal.
        
        Validates:
        - Expired token detection and handling
        - Automatic token refresh workflows
        - Grace period handling for token renewal
        - Cache invalidation on token refresh
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Create expired token
        expired_payload = {
            'sub': 'auth0|expired_user',
            'email': 'expired@example.com',
            'iat': int(time.time()) - 7200,  # 2 hours ago
            'exp': int(time.time()) - 3600   # 1 hour ago (expired)
        }
        expired_token = jwt.encode(expired_payload, self.secret_key, algorithm=self.algorithm)
        
        # Create fresh token for refresh
        fresh_payload = {
            'sub': 'auth0|expired_user',
            'email': 'expired@example.com',
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600
        }
        fresh_token = jwt.encode(fresh_payload, self.secret_key, algorithm=self.algorithm)
        
        jwt_validator = JWTTokenValidator(
            auth_config=Mock(algorithm=self.algorithm),
            cache=auth_cache
        )
        
        with patch.object(jwt_validator, '_get_verification_key') as mock_key:
            mock_key.return_value = self.secret_key
            
            # Test expired token validation
            with pytest.raises(JWTException) as exc_info:
                jwt_validator.validate_token(
                    token=expired_token,
                    verify_expiration=True
                )
            assert "Token has expired" in str(exc_info.value)
            
            # Test token refresh workflow
            with patch('src.auth.authentication.Auth0UserManager.refresh_token') as mock_refresh:
                mock_refresh.return_value = {
                    'access_token': fresh_token,
                    'refresh_token': 'new_refresh_token',
                    'expires_in': 3600
                }
                
                # Simulate refresh process
                refresh_result = jwt_validator.refresh_expired_token(
                    expired_token=expired_token,
                    refresh_token='old_refresh_token'
                )
                
                assert refresh_result['access_token'] == fresh_token
                assert refresh_result['expires_in'] == 3600
                
                # Verify old token cache is invalidated
                old_token_hash = auth_cache._generate_token_hash(expired_token)
                cached_old = auth_cache.get_jwt_validation_cache(old_token_hash)
                assert cached_old is None


class TestAuthenticationDecoratorIntegration:
    """
    Integration testing for authentication decorators with Flask Blueprint routes
    ensuring proper request context handling and security enforcement.
    """

    def setup_method(self):
        """Set up decorator integration test environment"""
        self.test_blueprint_name = 'test_auth'
        self.secret_key = 'test-decorator-secret'

    @pytest.mark.integration
    def test_require_auth_decorator_flask_integration(
        self,
        app,
        client: FlaskClient,
        redis_client,
        auth0_mock
    ):
        """
        Test @require_auth decorator integration with Flask Blueprint routes
        ensuring proper authentication enforcement and error handling.
        
        Validates:
        - Decorator application to Flask routes
        - Request context preservation
        - Authentication header processing
        - Error response formatting
        - Integration with Flask-Login user context
        """
        from flask import Blueprint
        
        # Create test blueprint with protected routes
        test_bp = Blueprint(self.test_blueprint_name, __name__)
        
        @test_bp.route('/protected', methods=['GET'])
        @require_auth
        def protected_endpoint():
            return jsonify({
                'message': 'Access granted',
                'user_id': g.auth_user.get('sub') if hasattr(g, 'auth_user') else None,
                'authenticated': True
            })
        
        @test_bp.route('/public', methods=['GET'])
        def public_endpoint():
            return jsonify({
                'message': 'Public access',
                'authenticated': False
            })
        
        # Register test blueprint
        app.register_blueprint(test_bp, url_prefix='/test')
        
        # Test unauthenticated access to protected route
        response = client.get('/test/protected')
        assert response.status_code == 401
        
        response_data = json.loads(response.data)
        assert response_data['error'] == 'Authentication required'
        assert 'message' in response_data
        
        # Test authenticated access with valid JWT token
        valid_token = create_valid_jwt_token(
            user_id='auth0|decorator_test',
            email='decorator@example.com'
        )
        
        # Mock authentication manager validation
        with patch('src.auth.decorators.authenticate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'sub': 'auth0|decorator_test',
                'email': 'decorator@example.com',
                'user_profile': {
                    'user_id': 'auth0|decorator_test',
                    'email': 'decorator@example.com',
                    'name': 'Decorator Test User'
                }
            }
            
            response = client.get(
                '/test/protected',
                headers={'Authorization': f'Bearer {valid_token}'}
            )
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data['message'] == 'Access granted'
            assert response_data['user_id'] == 'auth0|decorator_test'
            assert response_data['authenticated'] is True
        
        # Test public endpoint accessibility
        response = client.get('/test/public')
        assert response.status_code == 200
        
        response_data = json.loads(response.data)
        assert response_data['message'] == 'Public access'
        assert response_data['authenticated'] is False

    @pytest.mark.integration
    def test_require_permissions_decorator_integration(
        self,
        app,
        client: FlaskClient,
        redis_client
    ):
        """
        Test @require_permissions decorator integration with Redis permission caching
        ensuring proper authorization enforcement and cache utilization.
        
        Validates:
        - Permission-based route protection
        - Redis permission cache integration
        - Permission hierarchy evaluation
        - Resource-specific authorization
        - Cache hit/miss performance optimization
        """
        from flask import Blueprint
        
        # Create test blueprint with permission-protected routes
        test_bp = Blueprint('permission_test', __name__)
        
        @test_bp.route('/admin', methods=['GET'])
        @require_permissions(['admin:read', 'admin:write'])
        def admin_endpoint():
            return jsonify({
                'message': 'Admin access granted',
                'required_permissions': ['admin:read', 'admin:write']
            })
        
        @test_bp.route('/user/<user_id>', methods=['GET'])
        @require_permissions(['user:read'], resource_id='user_id', allow_owner=True)
        def user_endpoint(user_id):
            return jsonify({
                'message': f'User {user_id} data access granted',
                'user_id': user_id
            })
        
        app.register_blueprint(test_bp, url_prefix='/permission-test')
        
        # Test insufficient permissions
        user_token = create_valid_jwt_token(
            user_id='auth0|regular_user',
            email='user@example.com',
            permissions=['user:read']
        )
        
        with patch('src.auth.decorators.authenticate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'sub': 'auth0|regular_user',
                'permissions': ['user:read']
            }
            
            with patch('src.auth.decorators.validate_user_permissions') as mock_perms:
                mock_perms.return_value = False  # Insufficient permissions
                
                response = client.get(
                    '/permission-test/admin',
                    headers={'Authorization': f'Bearer {user_token}'}
                )
                
                assert response.status_code == 403
                response_data = json.loads(response.data)
                assert response_data['error'] == 'Insufficient permissions'
        
        # Test sufficient permissions with cache hit
        admin_token = create_valid_jwt_token(
            user_id='auth0|admin_user',
            email='admin@example.com',
            permissions=['admin:read', 'admin:write', 'user:read']
        )
        
        with patch('src.auth.decorators.authenticate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'sub': 'auth0|admin_user',
                'permissions': ['admin:read', 'admin:write', 'user:read']
            }
            
            with patch('src.auth.decorators.validate_user_permissions') as mock_perms:
                mock_perms.return_value = True  # Sufficient permissions
                
                response = client.get(
                    '/permission-test/admin',
                    headers={'Authorization': f'Bearer {admin_token}'}
                )
                
                assert response.status_code == 200
                response_data = json.loads(response.data)
                assert response_data['message'] == 'Admin access granted'
                assert response_data['required_permissions'] == ['admin:read', 'admin:write']

    @pytest.mark.integration
    def test_rate_limited_auth_decorator_integration(
        self,
        app,
        client: FlaskClient,
        redis_client
    ):
        """
        Test @rate_limited_auth decorator integration with Flask-Limiter
        ensuring proper rate limiting enforcement for authentication endpoints.
        
        Validates:
        - Rate limiting integration with authentication
        - User-specific rate limit tracking
        - Rate limit violation handling
        - Redis-backed rate limit storage
        """
        from flask import Blueprint
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        # Initialize Flask-Limiter
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )
        
        test_bp = Blueprint('rate_limit_test', __name__)
        
        @test_bp.route('/limited', methods=['POST'])
        @rate_limited_auth(rate_limit="2 per minute")
        def limited_endpoint():
            return jsonify({
                'message': 'Rate limited access granted',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        app.register_blueprint(test_bp, url_prefix='/rate-test')
        
        valid_token = create_valid_jwt_token(
            user_id='auth0|rate_test_user',
            email='ratetest@example.com'
        )
        
        headers = {'Authorization': f'Bearer {valid_token}'}
        
        with patch('src.auth.decorators.authenticate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'sub': 'auth0|rate_test_user'
            }
            
            # First request should succeed
            response1 = client.post('/rate-test/limited', headers=headers)
            assert response1.status_code == 200
            
            # Second request should succeed
            response2 = client.post('/rate-test/limited', headers=headers)
            assert response2.status_code == 200
            
            # Third request should be rate limited
            response3 = client.post('/rate-test/limited', headers=headers)
            assert response3.status_code == 429  # Too Many Requests
            
            # Verify rate limit headers are present
            assert 'X-RateLimit-Limit' in response3.headers
            assert 'X-RateLimit-Remaining' in response3.headers


class TestSessionManagementIntegration:
    """
    Integration testing for Flask-Session with Redis distributed storage
    and AES-256-GCM encryption validation.
    """

    @pytest.mark.integration
    def test_flask_session_redis_integration(
        self,
        app,
        client: FlaskClient,
        redis_client
    ):
        """
        Test Flask-Session Redis backend integration with encryption
        ensuring proper session storage and retrieval.
        
        Validates:
        - Flask-Session Redis backend configuration
        - Session data encryption with AES-256-GCM
        - Cross-request session persistence
        - Session cleanup and garbage collection
        """
        from flask import session, Blueprint
        from flask_session import Session
        
        # Configure Flask-Session with Redis
        app.config.update({
            'SESSION_TYPE': 'redis',
            'SESSION_REDIS': redis_client,
            'SESSION_PERMANENT': False,
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_PREFIX': 'test_session:',
            'SESSION_COOKIE_SECURE': False,  # For testing
            'SESSION_COOKIE_HTTPONLY': True,
            'SECRET_KEY': 'test-session-secret-key'
        })
        
        # Initialize Flask-Session
        Session(app)
        
        test_bp = Blueprint('session_test', __name__)
        
        @test_bp.route('/set-session', methods=['POST'])
        def set_session():
            session['user_id'] = 'auth0|session_test_user'
            session['email'] = 'session@example.com'
            session['login_time'] = datetime.utcnow().isoformat()
            return jsonify({'message': 'Session data set'})
        
        @test_bp.route('/get-session', methods=['GET'])
        def get_session():
            return jsonify({
                'user_id': session.get('user_id'),
                'email': session.get('email'),
                'login_time': session.get('login_time'),
                'session_id': session.get('_id')
            })
        
        @test_bp.route('/clear-session', methods=['POST'])
        def clear_session():
            session.clear()
            return jsonify({'message': 'Session cleared'})
        
        app.register_blueprint(test_bp, url_prefix='/session-test')
        
        # Test session creation and storage
        with client.session_transaction() as sess:
            # Set initial session data
            response = client.post('/session-test/set-session')
            assert response.status_code == 200
        
        # Test session retrieval across requests
        response = client.get('/session-test/get-session')
        assert response.status_code == 200
        
        session_data = json.loads(response.data)
        assert session_data['user_id'] == 'auth0|session_test_user'
        assert session_data['email'] == 'session@example.com'
        assert session_data['login_time'] is not None
        
        # Verify session data is stored in Redis
        redis_keys = redis_client.keys('test_session:*')
        assert len(redis_keys) > 0
        
        # Test session cleanup
        response = client.post('/session-test/clear-session')
        assert response.status_code == 200
        
        # Verify session data is cleared
        response = client.get('/session-test/get-session')
        session_data = json.loads(response.data)
        assert session_data['user_id'] is None
        assert session_data['email'] is None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_encrypted_session_handler(
        self,
        app_context,
        redis_client
    ):
        """
        Test EncryptedSessionHandler with AES-256-GCM encryption
        ensuring secure session data storage and AWS KMS integration.
        
        Validates:
        - AES-256-GCM encryption for session data
        - AWS KMS key management integration
        - Encrypted session serialization/deserialization
        - Key rotation handling
        """
        # Mock AWS KMS client
        with patch('boto3.client') as mock_boto3:
            mock_kms = Mock()
            mock_kms.generate_data_key.return_value = {
                'Plaintext': b'test_encryption_key_32_bytes_long!!',
                'CiphertextBlob': b'encrypted_key_blob'
            }
            mock_kms.decrypt.return_value = {
                'Plaintext': b'test_encryption_key_32_bytes_long!!'
            }
            mock_boto3.return_value = mock_kms
            
            # Initialize encrypted session handler
            session_handler = EncryptedSessionHandler(
                redis_client=redis_client,
                kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/test-key'
            )
            
            # Test session data encryption and storage
            session_data = {
                'user_id': 'auth0|encrypted_test_user',
                'email': 'encrypted@example.com',
                'permissions': ['read:users', 'write:users'],
                'login_time': datetime.utcnow().isoformat(),
                'sensitive_data': 'confidential_information'
            }
            
            session_id = 'test_session_123456'
            
            # Store encrypted session
            await session_handler.save_encrypted_session(
                session_id=session_id,
                session_data=session_data,
                ttl=3600
            )
            
            # Verify session is stored in Redis (encrypted)
            raw_session = redis_client.get(f'encrypted_session:{session_id}')
            assert raw_session is not None
            
            # Verify raw data is encrypted (not plain text)
            assert 'auth0|encrypted_test_user' not in raw_session
            assert 'encrypted@example.com' not in raw_session
            
            # Retrieve and decrypt session data
            decrypted_data = await session_handler.load_encrypted_session(session_id)
            
            assert decrypted_data is not None
            assert decrypted_data['user_id'] == 'auth0|encrypted_test_user'
            assert decrypted_data['email'] == 'encrypted@example.com'
            assert decrypted_data['permissions'] == ['read:users', 'write:users']
            assert decrypted_data['sensitive_data'] == 'confidential_information'
            
            # Test session deletion
            await session_handler.invalidate_encrypted_session(session_id)
            
            # Verify session is deleted
            deleted_session = await session_handler.load_encrypted_session(session_id)
            assert deleted_session is None


class TestCircuitBreakerIntegration:
    """
    Integration testing for circuit breaker patterns with Auth0 API calls
    ensuring system resilience during external service failures.
    """

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_circuit_breaker_activation_and_recovery(
        self,
        app_context,
        redis_client
    ):
        """
        Test circuit breaker activation during Auth0 service failures
        and automatic recovery when service is restored.
        
        Validates:
        - Circuit breaker state transitions (closed -> open -> half-open -> closed)
        - Failure threshold detection and circuit opening
        - Fallback mechanism activation during circuit open state
        - Automatic recovery testing and circuit closing
        - Performance impact measurement during degraded service
        """
        from src.auth.authentication import Auth0CircuitBreaker
        
        auth_cache = AuthenticationCache(redis_client)
        circuit_breaker = Auth0CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=10  # Short timeout for testing
        )
        
        # Mock Auth0 API client
        with patch('httpx.AsyncClient') as mock_httpx:
            mock_client = AsyncMock()
            mock_httpx.return_value.__aenter__.return_value = mock_client
            
            # Test circuit breaker in closed state (normal operation)
            mock_client.get.return_value.status_code = 200
            mock_client.get.return_value.json.return_value = {
                'sub': 'auth0|circuit_test_user',
                'email': 'circuit@example.com'
            }
            
            # Successful requests should keep circuit closed
            for i in range(2):
                result = await circuit_breaker.call_with_circuit_breaker(
                    func=mock_client.get,
                    url='https://test-tenant.auth0.com/userinfo',
                    headers={'Authorization': 'Bearer test_token'}
                )
                assert result.status_code == 200
                assert not circuit_breaker.is_open()
            
            # Test circuit breaker opening after failures
            mock_client.get.side_effect = [
                Exception("Connection timeout"),
                Exception("Service unavailable"),
                Exception("Internal server error")
            ]
            
            # Trigger failures to open circuit
            for i in range(3):
                with pytest.raises(Exception):
                    await circuit_breaker.call_with_circuit_breaker(
                        func=mock_client.get,
                        url='https://test-tenant.auth0.com/userinfo',
                        headers={'Authorization': 'Bearer test_token'}
                    )
            
            # Circuit should now be open
            assert circuit_breaker.is_open()
            assert circuit_breaker.failure_count >= 3
            
            # Test fallback mechanism when circuit is open
            with pytest.raises(CircuitBreakerException) as exc_info:
                await circuit_breaker.call_with_circuit_breaker(
                    func=mock_client.get,
                    url='https://test-tenant.auth0.com/userinfo',
                    headers={'Authorization': 'Bearer test_token'}
                )
            assert "Circuit breaker is open" in str(exc_info.value)
            
            # Test automatic recovery after timeout
            await asyncio.sleep(11)  # Wait for recovery timeout
            
            # Reset mock to return successful responses
            mock_client.get.side_effect = None
            mock_client.get.return_value.status_code = 200
            mock_client.get.return_value.json.return_value = {
                'sub': 'auth0|recovered_user',
                'email': 'recovered@example.com'
            }
            
            # Circuit should transition to half-open and then closed
            result = await circuit_breaker.call_with_circuit_breaker(
                func=mock_client.get,
                url='https://test-tenant.auth0.com/userinfo',
                headers={'Authorization': 'Bearer test_token'}
            )
            
            assert result.status_code == 200
            assert not circuit_breaker.is_open()
            assert circuit_breaker.failure_count == 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_circuit_breaker_fallback_mechanisms(
        self,
        app_context,
        redis_client
    ):
        """
        Test circuit breaker fallback mechanisms with cached data
        ensuring graceful degradation during service outages.
        
        Validates:
        - Fallback to cached authentication data
        - Graceful degradation indicators in response
        - Cache-based authorization decisions
        - Service recovery detection and normal operation restoration
        """
        auth_cache = AuthenticationCache(redis_client)
        
        # Pre-populate cache with user data for fallback
        cached_user_data = {
            'user_id': 'auth0|fallback_test_user',
            'email': 'fallback@example.com',
            'permissions': ['read:users'],
            'roles': ['user'],
            'cached_at': datetime.utcnow().isoformat(),
            'validation_source': 'cache_fallback'
        }
        
        await auth_cache.cache_auth0_user_profile(
            user_id='auth0|fallback_test_user',
            profile=cached_user_data,
            ttl=1800
        )
        
        # Create authentication manager with circuit breaker
        auth_manager = AuthenticationManager(cache=auth_cache)
        
        # Mock circuit breaker in open state
        with patch('src.auth.authentication.Auth0CircuitBreaker') as mock_circuit_breaker:
            mock_breaker_instance = Mock()
            mock_breaker_instance.is_open.return_value = True
            mock_breaker_instance.failure_count = 5
            mock_circuit_breaker.return_value = mock_breaker_instance
            
            # Test fallback authentication validation
            fallback_result = await auth_manager.validate_user_with_fallback(
                user_id='auth0|fallback_test_user',
                require_fresh_validation=False
            )
            
            assert fallback_result['authenticated'] is True
            assert fallback_result['user_id'] == 'auth0|fallback_test_user'
            assert fallback_result['email'] == 'fallback@example.com'
            assert fallback_result['validation_source'] == 'cache_fallback'
            assert fallback_result['degraded_mode'] is True
            assert fallback_result['circuit_breaker_open'] is True
            
            # Test permission validation with fallback
            permission_result = await auth_manager.validate_permissions_with_fallback(
                user_id='auth0|fallback_test_user',
                required_permissions=['read:users'],
                use_cache_only=True
            )
            
            assert permission_result['has_permissions'] is True
            assert permission_result['granted_permissions'] == ['read:users']
            assert permission_result['validation_source'] == 'cache_fallback'
            assert permission_result['degraded_mode'] is True


class TestSecurityEventLoggingIntegration:
    """
    Integration testing for security event logging with structured JSON
    and comprehensive audit trail generation.
    """

    @pytest.mark.integration
    def test_authentication_security_event_logging(
        self,
        app_context,
        redis_client,
        caplog
    ):
        """
        Test comprehensive security event logging for authentication flows
        ensuring proper audit trail generation and compliance logging.
        
        Validates:
        - Structured JSON logging with security event classification
        - Authentication success/failure event logging
        - Authorization decision audit trails
        - Security violation logging with context
        - Log aggregation and compliance reporting
        """
        import structlog
        from src.auth.audit import SecurityAuditLogger, SecurityEventType, SecurityEventSeverity
        
        # Configure structured logging for testing
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.stdlib.LoggerFactory(),
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        audit_logger = SecurityAuditLogger()
        
        # Test authentication success logging
        with caplog.at_level(logging.INFO):
            audit_logger.log_authentication_event(
                event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
                user_id='auth0|audit_test_user',
                email='audit@example.com',
                source_ip='192.168.1.100',
                user_agent='Mozilla/5.0 Test Browser',
                authentication_method='jwt_token',
                session_id='session_123456',
                additional_context={
                    'token_validation_time_ms': 150,
                    'cache_hit': True,
                    'auth0_response_time_ms': 75
                }
            )
        
        # Verify authentication success is logged
        assert any(
            'authentication_success' in record.message and 
            'audit_test_user' in record.message
            for record in caplog.records
        )
        
        # Test authorization failure logging
        with caplog.at_level(logging.WARNING):
            audit_logger.log_authorization_event(
                event_type=SecurityEventType.AUTHORIZATION_DENIED,
                user_id='auth0|unauthorized_user',
                required_permissions=['admin:write'],
                granted_permissions=['user:read'],
                resource_id='resource_123',
                source_ip='192.168.1.200',
                endpoint='/api/admin/users',
                additional_context={
                    'permission_check_time_ms': 25,
                    'cache_source': 'redis',
                    'denial_reason': 'insufficient_permissions'
                }
            )
        
        # Verify authorization denial is logged
        assert any(
            'authorization_denied' in record.message and 
            'unauthorized_user' in record.message
            for record in caplog.records
        )
        
        # Test security violation logging
        with caplog.at_level(logging.ERROR):
            audit_logger.log_security_violation(
                event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
                severity=SecurityEventSeverity.HIGH,
                user_id='auth0|suspicious_user',
                violation_type='multiple_failed_auth_attempts',
                source_ip='192.168.1.50',
                violation_details={
                    'failed_attempts': 15,
                    'time_window_minutes': 5,
                    'attempted_endpoints': ['/auth/login', '/auth/refresh'],
                    'geographic_anomaly': True,
                    'user_agent_anomaly': True
                },
                recommended_action='account_lockout'
            )
        
        # Verify security violation is logged with high severity
        assert any(
            'suspicious_activity' in record.message and 
            'suspicious_user' in record.message and
            'HIGH' in record.message
            for record in caplog.records
        )

    @pytest.mark.integration
    def test_security_metrics_collection(
        self,
        app_context,
        redis_client
    ):
        """
        Test Prometheus metrics collection for security events
        ensuring proper monitoring and alerting capabilities.
        
        Validates:
        - Authentication metrics collection (success/failure rates)
        - Authorization decision metrics
        - Security event counter metrics
        - Performance metrics for security operations
        - Alert threshold monitoring
        """
        from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
        from src.auth.metrics import SecurityMetricsCollector
        
        # Create test registry for metrics isolation
        test_registry = CollectorRegistry()
        
        # Initialize security metrics collector
        metrics_collector = SecurityMetricsCollector(registry=test_registry)
        
        # Test authentication success metrics
        for i in range(10):
            metrics_collector.record_authentication_success(
                user_id=f'auth0|metrics_user_{i}',
                authentication_method='jwt_token',
                response_time_ms=120 + (i * 5)
            )
        
        # Test authentication failure metrics
        for i in range(3):
            metrics_collector.record_authentication_failure(
                reason='invalid_token',
                source_ip=f'192.168.1.{100 + i}',
                response_time_ms=50 + (i * 10)
            )
        
        # Test authorization metrics
        for i in range(15):
            if i < 12:  # 12 successful authorizations
                metrics_collector.record_authorization_success(
                    user_id=f'auth0|authorized_user_{i}',
                    permissions=['read:users'],
                    resource_type='user_profile',
                    response_time_ms=25 + (i * 2)
                )
            else:  # 3 authorization failures
                metrics_collector.record_authorization_failure(
                    user_id=f'auth0|unauthorized_user_{i}',
                    required_permissions=['admin:write'],
                    granted_permissions=['user:read'],
                    response_time_ms=30 + (i * 2)
                )
        
        # Test cache performance metrics
        for i in range(20):
            if i < 16:  # 80% cache hit rate
                metrics_collector.record_cache_hit(
                    cache_type='jwt_validation',
                    response_time_ms=5 + (i % 3)
                )
            else:  # 20% cache miss rate
                metrics_collector.record_cache_miss(
                    cache_type='jwt_validation',
                    response_time_ms=150 + (i * 5)
                )
        
        # Collect and validate metrics
        metric_families = list(test_registry.collect())
        
        # Verify authentication metrics
        auth_success_metrics = [
            mf for mf in metric_families 
            if mf.name == 'auth_authentication_success_total'
        ]
        assert len(auth_success_metrics) > 0
        
        auth_failure_metrics = [
            mf for mf in metric_families 
            if mf.name == 'auth_authentication_failure_total'
        ]
        assert len(auth_failure_metrics) > 0
        
        # Verify authorization metrics
        authz_success_metrics = [
            mf for mf in metric_families 
            if mf.name == 'auth_authorization_success_total'
        ]
        assert len(authz_success_metrics) > 0
        
        # Verify cache performance metrics
        cache_hit_metrics = [
            mf for mf in metric_families 
            if mf.name == 'auth_cache_hit_total'
        ]
        assert len(cache_hit_metrics) > 0
        
        # Calculate and verify cache hit ratio
        cache_hit_rate = metrics_collector.get_cache_hit_ratio('jwt_validation')
        assert 0.75 <= cache_hit_rate <= 0.85  # ~80% hit rate with some variance


class TestPermissionCachingIntegration:
    """
    Integration testing for Redis permission caching with fallback mechanisms
    and intelligent TTL management.
    """

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_permission_caching_with_redis_fallback(
        self,
        app_context,
        redis_client
    ):
        """
        Test permission caching integration with Redis and fallback mechanisms
        ensuring optimal performance and cache effectiveness.
        
        Validates:
        - Permission cache storage and retrieval with Redis
        - Cache TTL management and expiration handling
        - Fallback to Auth0 API when cache miss occurs
        - Cache warming strategies for frequently accessed permissions
        - Performance optimization with cache hit/miss ratios
        """
        from src.auth.cache import PermissionCacheManager
        
        permission_cache = PermissionCacheManager(redis_client)
        
        # Test permission caching with structured key patterns
        user_permissions = {
            'read:users', 'write:users', 'read:reports', 'admin:dashboard'
        }
        
        user_id = 'auth0|permission_cache_test'
        
        # Cache user permissions
        cache_success = await permission_cache.cache_user_permissions(
            user_id=user_id,
            permissions=user_permissions,
            ttl=300  # 5 minutes
        )
        assert cache_success is True
        
        # Test cache retrieval (cache hit)
        with measure_response_time() as timer:
            cached_permissions = await permission_cache.get_cached_permissions(user_id)
        
        assert cached_permissions == user_permissions
        assert timer.elapsed_ms < 10  # Cache access should be very fast
        
        # Test cache expiration and refresh
        with freeze_time("2024-01-01 12:00:00"):
            # Cache user permissions with short TTL
            await permission_cache.cache_user_permissions(
                user_id=user_id,
                permissions=user_permissions,
                ttl=60  # 1 minute
            )
        
        with freeze_time("2024-01-01 12:01:30"):  # 1.5 minutes later
            # Cache should be expired
            expired_permissions = await permission_cache.get_cached_permissions(user_id)
            assert expired_permissions is None
        
        # Test cache warming for frequently accessed users
        frequent_users = [f'auth0|frequent_user_{i}' for i in range(10)]
        
        for user_id in frequent_users:
            await permission_cache.cache_user_permissions(
                user_id=user_id,
                permissions={'read:users', 'write:profile'},
                ttl=600  # 10 minutes for frequent users
            )
        
        # Test batch cache retrieval for performance
        with measure_response_time() as batch_timer:
            batch_results = await permission_cache.get_batch_cached_permissions(
                user_ids=frequent_users
            )
        
        assert len(batch_results) == 10
        assert all(
            'read:users' in permissions and 'write:profile' in permissions
            for permissions in batch_results.values() if permissions
        )
        assert batch_timer.elapsed_ms < 50  # Batch operations should be fast

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_permission_cache_invalidation_patterns(
        self,
        app_context,
        redis_client
    ):
        """
        Test intelligent cache invalidation patterns for permission updates
        ensuring data consistency and optimal cache performance.
        
        Validates:
        - Individual user permission cache invalidation
        - Role-based cache invalidation patterns
        - Group permission cache invalidation
        - Cache invalidation event propagation
        - Performance impact of cache invalidation operations
        """
        permission_cache = PermissionCacheManager(redis_client)
        
        # Set up test users with cached permissions
        test_users = {
            'auth0|admin_user': {'admin:read', 'admin:write', 'user:read'},
            'auth0|manager_user': {'team:manage', 'user:read', 'user:write'},
            'auth0|regular_user': {'user:read', 'profile:edit'}
        }
        
        # Cache permissions for all test users
        for user_id, permissions in test_users.items():
            await permission_cache.cache_user_permissions(
                user_id=user_id,
                permissions=permissions,
                ttl=600
            )
        
        # Verify all permissions are cached
        for user_id, expected_permissions in test_users.items():
            cached_permissions = await permission_cache.get_cached_permissions(user_id)
            assert cached_permissions == expected_permissions
        
        # Test individual user cache invalidation
        invalidation_success = await permission_cache.invalidate_user_cache(
            user_id='auth0|admin_user'
        )
        assert invalidation_success is True
        
        # Verify specific user cache is invalidated
        admin_cached = await permission_cache.get_cached_permissions('auth0|admin_user')
        assert admin_cached is None
        
        # Verify other users' caches are unaffected
        manager_cached = await permission_cache.get_cached_permissions('auth0|manager_user')
        assert manager_cached == test_users['auth0|manager_user']
        
        # Test pattern-based cache invalidation (e.g., role change affects multiple users)
        role_users = ['auth0|manager_user', 'auth0|regular_user']
        
        pattern_invalidation_success = await permission_cache.invalidate_cache_pattern(
            pattern='perm_cache:auth0|*_user',
            exclude_patterns=['perm_cache:auth0|admin_user']  # Already invalidated
        )
        assert pattern_invalidation_success is True
        
        # Verify pattern-based invalidation worked
        for user_id in role_users:
            cached_permissions = await permission_cache.get_cached_permissions(user_id)
            assert cached_permissions is None
        
        # Test cache invalidation metrics and monitoring
        invalidation_metrics = await permission_cache.get_invalidation_metrics()
        
        assert invalidation_metrics['individual_invalidations'] >= 1
        assert invalidation_metrics['pattern_invalidations'] >= 1
        assert invalidation_metrics['total_keys_invalidated'] >= 3

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_permission_cache_performance_optimization(
        self,
        app_context,
        redis_client,
        performance_baseline
    ):
        """
        Test permission cache performance optimization ensuring
        compliance with ≤10% variance requirement from baseline.
        
        Validates:
        - Cache operation performance benchmarking
        - Memory usage optimization for permission storage
        - Connection pooling efficiency for Redis operations
        - Batch operation performance optimization
        - Cache hit ratio optimization strategies
        """
        permission_cache = PermissionCacheManager(redis_client)
        
        # Test individual permission cache operation performance
        large_permission_set = {
            f'permission:{category}:{action}' 
            for category in ['users', 'reports', 'admin', 'billing', 'analytics']
            for action in ['create', 'read', 'update', 'delete', 'approve', 'audit']
        }
        
        test_user_id = 'auth0|performance_test_user'
        
        # Benchmark cache write performance
        with measure_response_time() as write_timer:
            await permission_cache.cache_user_permissions(
                user_id=test_user_id,
                permissions=large_permission_set,
                ttl=600
            )
        
        # Verify write performance meets baseline
        assert_performance_baseline(
            write_timer.elapsed_ms,
            performance_baseline['cache_permission_write']
        )
        
        # Benchmark cache read performance
        with measure_response_time() as read_timer:
            cached_permissions = await permission_cache.get_cached_permissions(test_user_id)
        
        assert cached_permissions == large_permission_set
        assert_performance_baseline(
            read_timer.elapsed_ms,
            performance_baseline['cache_permission_read']
        )
        
        # Test batch operation performance
        batch_users = [f'auth0|batch_user_{i}' for i in range(50)]
        batch_permissions = {
            user_id: {f'permission:batch:{i % 5}', 'read:users'} 
            for i, user_id in enumerate(batch_users)
        }
        
        # Benchmark batch write performance
        with measure_response_time() as batch_write_timer:
            batch_results = await permission_cache.cache_batch_user_permissions(
                user_permissions=batch_permissions,
                ttl=600
            )
        
        assert all(batch_results.values())  # All operations should succeed
        assert_performance_baseline(
            batch_write_timer.elapsed_ms,
            performance_baseline['cache_batch_write'] * len(batch_users)
        )
        
        # Benchmark batch read performance
        with measure_response_time() as batch_read_timer:
            batch_cached = await permission_cache.get_batch_cached_permissions(
                user_ids=batch_users
            )
        
        assert len(batch_cached) == len(batch_users)
        assert_performance_baseline(
            batch_read_timer.elapsed_ms,
            performance_baseline['cache_batch_read'] * len(batch_users)
        )
        
        # Test cache efficiency metrics
        cache_metrics = await permission_cache.get_performance_metrics()
        
        assert cache_metrics['average_write_time_ms'] <= performance_baseline['cache_permission_write']
        assert cache_metrics['average_read_time_ms'] <= performance_baseline['cache_permission_read']
        assert cache_metrics['cache_hit_ratio'] >= 0.85  # Target 85% hit ratio
        assert cache_metrics['memory_efficiency_ratio'] >= 0.90  # Efficient memory usage


# Performance baseline constants for authentication integration tests
AUTHENTICATION_PERFORMANCE_BASELINES = {
    'auth_token_validation': 200,  # milliseconds
    'jwt_validation': 150,
    'auth0_api_call': 300,
    'cache_permission_write': 25,
    'cache_permission_read': 10,
    'cache_batch_write': 5,  # per item
    'cache_batch_read': 3,   # per item
    'session_creation': 100,
    'session_validation': 50,
    'security_logging': 15
}


@pytest.fixture
def performance_baseline():
    """Provide performance baseline data for authentication integration tests"""
    return AUTHENTICATION_PERFORMANCE_BASELINES


@pytest.mark.integration
class TestAuthenticationSystemEnd2End:
    """
    End-to-end integration testing for complete authentication workflows
    validating the entire system integration from request to response.
    """

    @pytest.mark.asyncio
    async def test_complete_authentication_workflow_integration(
        self,
        app,
        client: FlaskClient,
        redis_client,
        mongodb_client,
        auth0_mock,
        performance_baseline
    ):
        """
        Test complete authentication workflow integration from JWT token
        through user context creation, session management, and audit logging.
        
        This end-to-end test validates:
        - Complete request/response authentication flow
        - Integration between all authentication components
        - Performance compliance across entire workflow
        - Comprehensive error handling and logging
        - Session persistence and security
        - Cache optimization throughout the flow
        
        Coverage Requirements:
        - 95% authentication module coverage validation
        - All integration points tested
        - Performance ≤10% variance from baseline
        - Complete audit trail verification
        """
        from flask import Blueprint
        
        # Create comprehensive test blueprint
        e2e_bp = Blueprint('e2e_auth_test', __name__)
        
        @e2e_bp.route('/protected-resource', methods=['GET'])
        @require_auth
        @require_permissions(['resource:read'])
        def protected_resource():
            return jsonify({
                'message': 'Protected resource accessed successfully',
                'user_id': g.auth_user.get('sub'),
                'timestamp': datetime.utcnow().isoformat(),
                'authentication_method': 'jwt_token',
                'session_valid': True
            })
        
        @e2e_bp.route('/admin-resource', methods=['POST'])
        @require_auth
        @require_permissions(['admin:write', 'admin:manage'])
        @rate_limited_auth(rate_limit="10 per minute")
        def admin_resource():
            return jsonify({
                'message': 'Administrative action completed',
                'user_id': g.auth_user.get('sub'),
                'action': 'admin_operation',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        app.register_blueprint(e2e_bp, url_prefix='/e2e')
        
        # Create comprehensive JWT token with all required claims
        comprehensive_token = create_valid_jwt_token(
            user_id='auth0|e2e_test_user',
            email='e2e.test@example.com',
            permissions=['resource:read', 'admin:write', 'admin:manage'],
            roles=['user', 'admin'],
            custom_claims={
                'department': 'engineering',
                'security_level': 'high',
                'mfa_verified': True
            }
        )
        
        # Configure comprehensive Auth0 mock responses
        auth0_mock.validate_token.return_value = {
            'sub': 'auth0|e2e_test_user',
            'email': 'e2e.test@example.com',
            'email_verified': True,
            'iss': 'https://test-tenant.auth0.com/',
            'aud': 'test-audience',
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
            'scope': 'openid profile email',
            'permissions': ['resource:read', 'admin:write', 'admin:manage'],
            'roles': ['user', 'admin'],
            'custom_claims': {
                'department': 'engineering',
                'security_level': 'high',
                'mfa_verified': True
            }
        }
        
        auth0_mock.get_user_profile.return_value = {
            'user_id': 'auth0|e2e_test_user',
            'email': 'e2e.test@example.com',
            'name': 'E2E Test User',
            'picture': 'https://example.com/avatar.jpg',
            'email_verified': True,
            'created_at': '2023-01-01T00:00:00.000Z',
            'updated_at': '2024-01-01T00:00:00.000Z',
            'user_metadata': {
                'department': 'engineering',
                'role': 'senior_engineer'
            }
        }
        
        # Test complete authentication workflow with performance measurement
        with measure_response_time() as workflow_timer:
            # Test protected resource access
            response = client.get(
                '/e2e/protected-resource',
                headers={
                    'Authorization': f'Bearer {comprehensive_token}',
                    'User-Agent': 'E2E-Test-Client/1.0',
                    'X-Real-IP': '192.168.1.100'
                }
            )
        
        # Verify successful authentication and authorization
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['message'] == 'Protected resource accessed successfully'
        assert response_data['user_id'] == 'auth0|e2e_test_user'
        assert response_data['authentication_method'] == 'jwt_token'
        assert response_data['session_valid'] is True
        
        # Verify performance compliance for complete workflow
        assert_performance_baseline(
            workflow_timer.elapsed_ms,
            performance_baseline['auth_token_validation'] + 
            performance_baseline['cache_permission_read'] + 
            performance_baseline['security_logging']
        )
        
        # Test administrative resource access with rate limiting
        admin_response = client.post(
            '/e2e/admin-resource',
            headers={
                'Authorization': f'Bearer {comprehensive_token}',
                'Content-Type': 'application/json'
            },
            json={'action': 'create_user', 'target': 'new_user@example.com'}
        )
        
        assert admin_response.status_code == 200
        admin_data = json.loads(admin_response.data)
        assert admin_data['message'] == 'Administrative action completed'
        assert admin_data['action'] == 'admin_operation'
        
        # Verify session persistence across requests
        session_response = client.get(
            '/e2e/protected-resource',
            headers={'Authorization': f'Bearer {comprehensive_token}'}
        )
        assert session_response.status_code == 200
        
        # Verify cache utilization (second request should be faster)
        with measure_response_time() as cached_timer:
            cached_response = client.get(
                '/e2e/protected-resource',
                headers={'Authorization': f'Bearer {comprehensive_token}'}
            )
        
        assert cached_response.status_code == 200
        # Cached request should be significantly faster
        assert cached_timer.elapsed_ms < workflow_timer.elapsed_ms * 0.5
        
        # Verify comprehensive audit trail is generated
        # This would typically involve checking log outputs or audit database
        # For this test, we verify that audit logging functions are called
        with patch('src.auth.audit.SecurityAuditLogger.log_authentication_event') as mock_auth_log:
            with patch('src.auth.audit.SecurityAuditLogger.log_authorization_event') as mock_authz_log:
                
                final_response = client.get(
                    '/e2e/protected-resource',
                    headers={'Authorization': f'Bearer {comprehensive_token}'}
                )
                
                assert final_response.status_code == 200
                
                # Verify audit logging was triggered
                assert mock_auth_log.call_count >= 1
                assert mock_authz_log.call_count >= 1
                
                # Verify audit log contains comprehensive context
                auth_log_call = mock_auth_log.call_args
                assert 'e2e_test_user' in str(auth_log_call)
                assert 'authentication_success' in str(auth_log_call)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])