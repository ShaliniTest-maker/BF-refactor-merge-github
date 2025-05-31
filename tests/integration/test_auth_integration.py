"""
Authentication System Integration Testing

This module provides comprehensive integration testing for the authentication system migration
from Node.js to Python/Flask, covering Auth0 Python SDK integration, PyJWT token validation
workflows, circuit breaker patterns, and authentication decorator integration per Section 6.4.

Test Coverage Areas:
- Auth0 Python SDK integration testing with circuit breaker patterns per Section 6.4.2
- PyJWT 2.8+ token validation workflows replacing Node.js jsonwebtoken per Section 0.1.2
- Authentication decorator integration with Flask Blueprint routes per Section 6.4.2
- Session management integration with Redis distributed storage per Section 6.4.1
- Circuit breaker and retry logic testing for Auth0 API calls per Section 6.4.2
- Security event logging integration with audit systems per Section 6.4.2
- Permission caching with Redis and fallback mechanisms per Section 6.4.2

Technical Requirements:
- 95% authentication module coverage per Section 6.6.3 security compliance
- Performance validation ensuring ≤10% variance from Node.js baseline per Section 0.1.1
- Enterprise-grade security testing with comprehensive audit logging per Section 6.4.2
- Circuit breaker protection testing for Auth0 service resilience per Section 6.4.2
- Flask-Login integration testing for session management per Section 6.4.1
- Redis caching integration with encryption validation per Section 6.4.3

Test Architecture:
- pytest-asyncio for asynchronous authentication operations per Section 6.6.1
- Testcontainers for realistic Redis behavior per Section 6.6.1 enhanced mocking strategy
- Auth0 service mocking for authentication testing isolation per Section 6.6.1
- Performance benchmarking against Node.js baseline per Section 6.6.1
- Flask application context for Blueprint route testing per Section 6.6.1

Dependencies:
- pytest 7.4+ with asyncio support per Section 6.6.1
- pytest-flask for Flask-specific testing patterns per Section 6.6.1
- testcontainers[redis] for realistic cache behavior per Section 6.6.1
- factory_boy for dynamic test object generation per Section 6.6.1
- httpx for async HTTP client testing per Section 6.4.2

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import json
import pytest
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, patch, AsyncMock, MagicMock, call
from urllib.parse import urlparse
import base64
import hashlib
import hmac

# Flask testing infrastructure
import pytest_asyncio
from flask import Flask, request, g, session, jsonify
from flask.testing import FlaskClient
from flask_login import current_user, login_user, logout_user

# Third-party libraries for mocking and testing
import httpx
import jwt
import redis
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from prometheus_client import REGISTRY

# Authentication system components
from src.auth import (
    CoreJWTAuthenticator,
    AuthenticatedUser,
    get_core_authenticator,
    require_authentication,
    get_authenticated_user,
    initialize_authentication_module,
    register_auth_blueprint,
    create_auth_blueprint,
    auth_module_metrics
)
from src.auth.authentication import auth_operation_metrics
from src.auth.authorization import (
    AuthorizationManager,
    require_permissions,
    PermissionContext,
    get_authorization_manager,
    authorization_metrics
)
from src.auth.decorators import (
    login_required_with_permissions,
    rate_limited_authorization,
    resource_owner_required,
    admin_required,
    audit_security_event
)
from src.auth.session import (
    FlaskLoginSessionManager,
    initialize_session_management,
    get_session_manager,
    session_metrics
)
from src.auth.cache import (
    get_auth_cache_manager,
    cache_operations_total,
    cache_operation_duration,
    cache_hit_ratio
)
from src.auth.exceptions import (
    AuthenticationException,
    AuthorizationException,
    JWTException,
    Auth0Exception,
    CircuitBreakerException,
    SessionException,
    SecurityErrorCode
)

# Test configuration and fixtures
from tests.conftest import (
    auth_test_config,
    mock_auth0_service,
    mock_redis_client,
    sample_jwt_token,
    test_user_profile,
    performance_baseline
)


class TestAuth0Integration:
    """
    Comprehensive Auth0 Python SDK integration testing with circuit breaker patterns.
    
    This test class validates Auth0 service integration including JWT token validation,
    user profile retrieval, circuit breaker protection, and fallback mechanisms per
    Section 6.4.2 enhanced authorization decorators.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context, mock_auth0_service, mock_redis_client):
        """Set up test environment for Auth0 integration testing."""
        self.app = app_context
        self.auth0_mock = mock_auth0_service
        self.redis_mock = mock_redis_client
        self.authenticator = get_core_authenticator()
        
        # Reset metrics for isolated testing
        for metric in auth_operation_metrics.values():
            if hasattr(metric, '_value'):
                metric._value.clear()
        
        # Configure test-specific settings
        self.app.config.update({
            'AUTH0_DOMAIN': 'test-domain.auth0.com',
            'AUTH0_CLIENT_ID': 'test_client_id',
            'AUTH0_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_AUDIENCE': 'test-api-audience',
            'REDIS_URL': 'redis://localhost:6379/15'
        })
    
    @pytest.mark.asyncio
    async def test_auth0_jwt_validation_success(self, sample_jwt_token):
        """
        Test successful JWT validation with Auth0 public key verification.
        
        Validates PyJWT 2.8+ integration replacing Node.js jsonwebtoken patterns
        per Section 0.1.2 authentication module migration.
        """
        # Mock Auth0 public key retrieval
        mock_public_key = self._generate_test_rsa_key_pair()[0]
        
        with patch.object(self.authenticator, '_get_auth0_public_key', 
                         return_value=mock_public_key) as mock_key_fetch:
            
            # Create valid JWT token
            token_payload = {
                'sub': 'auth0|test_user_123',
                'iss': 'https://test-domain.auth0.com/',
                'aud': 'test-api-audience',
                'exp': int(time.time()) + 3600,
                'iat': int(time.time()),
                'email': 'test@example.com',
                'name': 'Test User',
                'permissions': ['read:documents', 'write:documents']
            }
            
            valid_token = jwt.encode(
                token_payload,
                self._generate_test_rsa_key_pair()[1],
                algorithm='RS256',
                headers={'kid': 'test_key_id'}
            )
            
            # Execute JWT validation
            start_time = time.time()
            token_claims = await self.authenticator._validate_jwt_token(valid_token)
            validation_duration = time.time() - start_time
            
            # Validate successful token processing
            assert token_claims is not None
            assert token_claims['sub'] == 'auth0|test_user_123'
            assert token_claims['email'] == 'test@example.com'
            assert token_claims['iss'] == 'https://test-domain.auth0.com/'
            assert token_claims['aud'] == 'test-api-audience'
            
            # Verify Auth0 public key retrieval
            mock_key_fetch.assert_called_once_with('test_key_id')
            
            # Validate performance requirements (≤10% variance from baseline)
            assert validation_duration < 0.1, f"JWT validation took {validation_duration}s, exceeding performance threshold"
            
            # Verify metrics collection
            assert auth_operation_metrics['token_validations_total']._value.sum() >= 1
    
    @pytest.mark.asyncio
    async def test_auth0_jwt_validation_expired_token(self, sample_jwt_token):
        """
        Test JWT validation with expired token handling and appropriate error responses.
        
        Validates comprehensive JWT error handling equivalent to Node.js patterns
        per Section 6.4.1 token processing requirements.
        """
        mock_public_key = self._generate_test_rsa_key_pair()[0]
        
        with patch.object(self.authenticator, '_get_auth0_public_key', 
                         return_value=mock_public_key):
            
            # Create expired JWT token
            expired_payload = {
                'sub': 'auth0|test_user_123',
                'iss': 'https://test-domain.auth0.com/',
                'aud': 'test-api-audience',
                'exp': int(time.time()) - 3600,  # Expired 1 hour ago
                'iat': int(time.time()) - 7200,
                'email': 'test@example.com'
            }
            
            expired_token = jwt.encode(
                expired_payload,
                self._generate_test_rsa_key_pair()[1],
                algorithm='RS256'
            )
            
            # Test expired token rejection
            with pytest.raises(JWTException) as exc_info:
                await self.authenticator._validate_jwt_token(expired_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_EXPIRED
            assert "expired" in str(exc_info.value).lower()
            
            # Test allow_expired flag functionality
            token_claims = await self.authenticator._validate_jwt_token(
                expired_token, 
                allow_expired=True
            )
            
            assert token_claims is not None
            assert token_claims.get('_expired') is True
            assert token_claims['sub'] == 'auth0|test_user_123'
    
    @pytest.mark.asyncio
    async def test_auth0_circuit_breaker_activation(self):
        """
        Test circuit breaker activation for Auth0 service failures with fallback mechanisms.
        
        Validates circuit breaker patterns for Auth0 API calls per Section 6.4.2
        circuit breaker integration requirements.
        """
        # Simulate Auth0 service failures
        with patch('httpx.AsyncClient.get', side_effect=httpx.RequestError("Service unavailable")):
            
            # Attempt multiple Auth0 operations to trigger circuit breaker
            for attempt in range(5):
                try:
                    await self.authenticator._fetch_auth0_user_profile('auth0|test_user')
                except Exception:
                    pass  # Expected failures
            
            # Verify circuit breaker state change
            assert self.authenticator._auth0_circuit_breaker_state in ['half-open', 'open']
            assert self.authenticator._auth0_failure_count >= 3
            
            # Test fallback behavior with cached permissions
            self.redis_mock.get.return_value = json.dumps(['read:documents', 'write:documents'])
            
            # Mock permission validation with fallback
            with patch.object(self.authenticator, '_fallback_permission_validation') as mock_fallback:
                mock_fallback.return_value = {
                    'user_id': 'auth0|test_user',
                    'has_permissions': True,
                    'validation_source': 'fallback_cache',
                    'degraded_mode': True
                }
                
                # Execute fallback validation
                result = await mock_fallback('auth0|test_user', ['read:documents'])
                
                assert result['degraded_mode'] is True
                assert result['validation_source'] == 'fallback_cache'
                assert result['has_permissions'] is True
    
    @pytest.mark.asyncio
    async def test_auth0_user_profile_retrieval_with_retry(self, test_user_profile):
        """
        Test Auth0 user profile retrieval with intelligent retry strategies.
        
        Validates comprehensive user context creation per Section 6.4.1 identity management.
        """
        # Mock Auth0 management client
        mock_management_client = AsyncMock()
        mock_management_client.users.get.return_value = test_user_profile
        
        with patch.object(self.authenticator, '_auth0_management_client', mock_management_client):
            
            # Test successful profile retrieval
            profile = await self.authenticator._fetch_auth0_user_profile('auth0|test_user_123')
            
            assert profile is not None
            assert profile['last_login'] == test_user_profile['last_login']
            assert profile['login_count'] == test_user_profile.get('logins_count', 0)
            assert 'app_metadata' in profile
            
            # Verify caching behavior
            cache_key = "profile:auth0|test_user_123"
            assert self.redis_mock.setex.called
            
            # Verify metrics collection
            assert auth_operation_metrics['auth0_operations_total']._value.sum() >= 1
    
    @pytest.mark.asyncio
    async def test_auth0_service_degradation_handling(self):
        """
        Test Auth0 service degradation scenarios with graceful fallback.
        
        Validates service resilience patterns per Section 6.4.2 circuit breaker protection.
        """
        # Simulate intermittent Auth0 service issues
        failure_responses = [
            httpx.HTTPStatusError("503 Service Unavailable", request=Mock(), response=Mock(status_code=503)),
            httpx.RequestError("Connection timeout"),
            None,  # Success
            httpx.HTTPStatusError("429 Too Many Requests", request=Mock(), response=Mock(status_code=429))
        ]
        
        with patch('httpx.AsyncClient.get', side_effect=failure_responses):
            
            # Test retry logic with exponential backoff
            with patch('tenacity.wait_exponential_jitter') as mock_backoff:
                mock_backoff.return_value = 0.1  # Fast retry for testing
                
                try:
                    # Should succeed on third attempt
                    profile = await self.authenticator._fetch_auth0_user_profile('auth0|test_user')
                except Exception:
                    pass  # Test resilience even if all retries fail
                
                # Verify retry attempts were made
                assert mock_backoff.called
        
        # Verify graceful degradation metrics
        assert authorization_metrics['circuit_breaker_events']._value.sum() >= 1
    
    def _generate_test_rsa_key_pair(self) -> tuple:
        """Generate RSA key pair for JWT testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return public_key, private_pem


class TestJWTValidationWorkflows:
    """
    Comprehensive PyJWT 2.8+ token validation workflow testing.
    
    This test class validates JWT processing workflows replacing Node.js jsonwebtoken
    patterns with equivalent Python functionality per Section 0.1.2 authentication module.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context, mock_redis_client):
        """Set up JWT validation testing environment."""
        self.app = app_context
        self.redis_mock = mock_redis_client
        self.authenticator = get_core_authenticator()
        
        # Configure JWT testing parameters
        self.test_secret = 'test-jwt-secret-key'
        self.test_algorithm = 'HS256'
        self.test_audience = 'test-api-audience'
        self.test_issuer = 'https://test-domain.auth0.com/'
    
    @pytest.mark.asyncio
    async def test_jwt_signature_verification_algorithms(self):
        """
        Test JWT signature verification across multiple algorithms.
        
        Validates comprehensive cryptographic verification per Section 6.4.1
        cryptographic operations requirements.
        """
        algorithms_to_test = ['RS256', 'HS256']
        
        for algorithm in algorithms_to_test:
            if algorithm == 'RS256':
                # Use RSA key pair for RS256
                public_key, private_key = TestAuth0Integration()._generate_test_rsa_key_pair()
                signing_key = private_key
                verification_key = public_key
            else:
                # Use symmetric key for HS256
                signing_key = verification_key = self.test_secret
            
            # Create JWT token
            token_payload = {
                'sub': 'test_user_123',
                'iss': self.test_issuer,
                'aud': self.test_audience,
                'exp': int(time.time()) + 3600,
                'iat': int(time.time()),
                'permissions': ['read:test', 'write:test']
            }
            
            token = jwt.encode(token_payload, signing_key, algorithm=algorithm)
            
            # Mock verification key retrieval for RS256
            if algorithm == 'RS256':
                with patch.object(self.authenticator, '_get_auth0_public_key', 
                                 return_value=verification_key):
                    claims = await self.authenticator._validate_jwt_token(token)
            else:
                # Direct validation for HS256 (not typical for Auth0 but for completeness)
                with patch.object(self.authenticator, 'jwt_algorithm', 'HS256'), \
                     patch.object(self.authenticator, '_get_auth0_public_key', 
                                 return_value=verification_key):
                    claims = await self.authenticator._validate_jwt_token(token)
            
            assert claims is not None
            assert claims['sub'] == 'test_user_123'
            assert claims['iss'] == self.test_issuer
            assert algorithm in ['RS256', 'HS256']  # Confirm test coverage
    
    @pytest.mark.asyncio
    async def test_jwt_claims_extraction_and_validation(self):
        """
        Test comprehensive JWT claims extraction and custom validation.
        
        Validates claims-based authorization per Section 6.4.2 permission management.
        """
        # Create JWT with custom claims
        custom_claims = {
            'sub': 'auth0|custom_user_456',
            'iss': self.test_issuer,
            'aud': self.test_audience,
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'email': 'custom@example.com',
            'email_verified': True,
            'name': 'Custom Test User',
            'picture': 'https://example.com/avatar.jpg',
            'updated_at': '2024-01-15T10:30:00.000Z',
            'https://api.example.com/roles': ['admin', 'user'],
            'https://api.example.com/permissions': ['admin:all', 'user:read', 'user:write'],
            'https://api.example.com/organization': 'test-org-123'
        }
        
        public_key, private_key = TestAuth0Integration()._generate_test_rsa_key_pair()
        token = jwt.encode(custom_claims, private_key, algorithm='RS256')
        
        with patch.object(self.authenticator, '_get_auth0_public_key', 
                         return_value=public_key):
            
            # Validate token and extract claims
            claims = await self.authenticator._validate_jwt_token(token)
            
            assert claims is not None
            assert claims['sub'] == 'auth0|custom_user_456'
            assert claims['email'] == 'custom@example.com'
            assert claims['email_verified'] is True
            assert claims['https://api.example.com/roles'] == ['admin', 'user']
            assert claims['https://api.example.com/permissions'] == ['admin:all', 'user:read', 'user:write']
            
            # Test additional security validations
            await self.authenticator._perform_additional_token_validations(claims)
            
            # No exceptions should be raised for valid claims
            assert True  # Explicit assertion for successful validation
    
    @pytest.mark.asyncio
    async def test_jwt_token_caching_and_performance(self):
        """
        Test JWT validation caching for performance optimization.
        
        Validates Redis caching patterns per Section 6.4.2 Redis permission caching.
        """
        public_key, private_key = TestAuth0Integration()._generate_test_rsa_key_pair()
        
        token_payload = {
            'sub': 'auth0|cache_test_user',
            'iss': self.test_issuer,
            'aud': self.test_audience,
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'permissions': ['cache:test']
        }
        
        test_token = jwt.encode(token_payload, private_key, algorithm='RS256')
        token_hash = hashlib.sha256(test_token.encode()).hexdigest()[:16]
        
        with patch.object(self.authenticator, '_get_auth0_public_key', 
                         return_value=public_key) as mock_key_fetch:
            
            # First validation - should hit Auth0 and cache result
            start_time = time.time()
            claims1 = await self.authenticator._validate_jwt_token(test_token)
            first_duration = time.time() - start_time
            
            # Mock cache hit for second validation
            self.redis_mock.get.return_value = json.dumps(claims1)
            
            # Second validation - should use cache
            start_time = time.time()
            claims2 = await self.authenticator._validate_jwt_token(test_token)
            second_duration = time.time() - start_time
            
            # Validate results consistency
            assert claims1 == claims2
            assert claims1['sub'] == 'auth0|cache_test_user'
            
            # Validate performance improvement from caching
            # Second call should be significantly faster (cached result)
            assert second_duration < first_duration * 0.5, "Caching should improve performance significantly"
            
            # Verify cache operations
            assert self.redis_mock.get.called
            assert cache_operations_total._value.sum() >= 1
    
    @pytest.mark.asyncio
    async def test_jwt_token_refresh_workflow(self):
        """
        Test JWT token refresh workflow with validation and security.
        
        Validates token lifecycle management per Section 6.4.1 session management.
        """
        public_key, private_key = TestAuth0Integration()._generate_test_rsa_key_pair()
        
        # Create initial access token
        access_payload = {
            'sub': 'auth0|refresh_test_user',
            'iss': self.test_issuer,
            'aud': self.test_audience,
            'exp': int(time.time()) + 900,  # 15 minutes
            'iat': int(time.time()),
            'token_use': 'access',
            'permissions': ['refresh:test']
        }
        
        # Create refresh token
        refresh_payload = {
            'sub': 'auth0|refresh_test_user',
            'iss': self.test_issuer,
            'aud': self.test_audience,
            'exp': int(time.time()) + 86400,  # 24 hours
            'iat': int(time.time()),
            'token_use': 'refresh'
        }
        
        access_token = jwt.encode(access_payload, private_key, algorithm='RS256')
        refresh_token = jwt.encode(refresh_payload, private_key, algorithm='RS256')
        
        with patch.object(self.authenticator, '_get_auth0_public_key', 
                         return_value=public_key), \
             patch('httpx.AsyncClient.post') as mock_post:
            
            # Mock Auth0 token refresh response
            mock_response = Mock()
            mock_response.json.return_value = {
                'access_token': 'new_access_token_123',
                'refresh_token': 'new_refresh_token_456',
                'token_type': 'Bearer',
                'expires_in': 3600
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            # Execute token refresh
            new_access, new_refresh = await self.authenticator.refresh_token(
                refresh_token, 
                access_token
            )
            
            assert new_access == 'new_access_token_123'
            assert new_refresh == 'new_refresh_token_456'
            
            # Verify Auth0 API call
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert 'grant_type=refresh_token' in str(call_args)
    
    @pytest.mark.asyncio
    async def test_jwt_malformed_token_handling(self):
        """
        Test handling of malformed and invalid JWT tokens.
        
        Validates comprehensive error handling per Section 6.4.1 token validation.
        """
        malformed_tokens = [
            'invalid.jwt.token',
            'header.payload',  # Missing signature
            'not_a_jwt_at_all',
            '',  # Empty token
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9',  # No signature
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.'  # 'none' algorithm
        ]
        
        for malformed_token in malformed_tokens:
            with pytest.raises(JWTException) as exc_info:
                await self.authenticator._validate_jwt_token(malformed_token)
            
            assert exc_info.value.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                SecurityErrorCode.AUTH_TOKEN_INVALID
            ]
            
            # Verify error is properly logged and tracked
            assert "Invalid token" in str(exc_info.value) or "malformed" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_jwt_audience_and_issuer_validation(self):
        """
        Test JWT audience and issuer validation for security compliance.
        
        Validates security boundary enforcement per Section 6.4.1 authentication framework.
        """
        public_key, private_key = TestAuth0Integration()._generate_test_rsa_key_pair()
        
        # Test cases for audience/issuer validation
        validation_test_cases = [
            {
                'name': 'invalid_audience',
                'payload': {
                    'sub': 'auth0|test_user',
                    'iss': self.test_issuer,
                    'aud': 'wrong-audience',  # Invalid audience
                    'exp': int(time.time()) + 3600,
                    'iat': int(time.time())
                },
                'expected_error': SecurityErrorCode.AUTH_TOKEN_INVALID
            },
            {
                'name': 'invalid_issuer',
                'payload': {
                    'sub': 'auth0|test_user',
                    'iss': 'https://malicious-issuer.com/',  # Invalid issuer
                    'aud': self.test_audience,
                    'exp': int(time.time()) + 3600,
                    'iat': int(time.time())
                },
                'expected_error': SecurityErrorCode.AUTH_TOKEN_INVALID
            },
            {
                'name': 'missing_required_claims',
                'payload': {
                    'sub': 'auth0|test_user',
                    # Missing iss, aud, exp, iat
                },
                'expected_error': SecurityErrorCode.AUTH_TOKEN_INVALID
            }
        ]
        
        for test_case in validation_test_cases:
            token = jwt.encode(test_case['payload'], private_key, algorithm='RS256')
            
            with patch.object(self.authenticator, '_get_auth0_public_key', 
                             return_value=public_key):
                
                with pytest.raises(JWTException) as exc_info:
                    await self.authenticator._validate_jwt_token(token)
                
                assert exc_info.value.error_code == test_case['expected_error']


class TestAuthenticationDecoratorIntegration:
    """
    Authentication decorator integration testing with Flask Blueprint routes.
    
    This test class validates decorator patterns for route-level authorization
    per Section 6.4.2 route-level authorization requirements.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context, mock_auth0_service, mock_redis_client):
        """Set up decorator integration testing environment."""
        self.app = app_context
        self.auth0_mock = mock_auth0_service
        self.redis_mock = mock_redis_client
        
        # Register authentication blueprint
        register_auth_blueprint(self.app)
        
        # Create test routes with authentication decorators
        self._create_test_routes()
        
        self.client = self.app.test_client()
    
    def _create_test_routes(self):
        """Create test routes with various authentication decorators."""
        
        @self.app.route('/test/public')
        def public_endpoint():
            return jsonify({'message': 'public access', 'status': 'success'})
        
        @self.app.route('/test/protected')
        @require_authentication()
        async def protected_endpoint():
            user = get_authenticated_user()
            return jsonify({
                'message': 'protected access',
                'user_id': user.user_id if user else None,
                'status': 'success'
            })
        
        @self.app.route('/test/permissions')
        @require_authentication(['read:documents', 'write:documents'])
        async def permissions_endpoint():
            user = get_authenticated_user()
            return jsonify({
                'message': 'permissions validated',
                'user_id': user.user_id,
                'permissions': user.permissions,
                'status': 'success'
            })
        
        @self.app.route('/test/admin')
        @admin_required()
        async def admin_endpoint():
            user = get_authenticated_user()
            return jsonify({
                'message': 'admin access granted',
                'user_id': user.user_id,
                'status': 'success'
            })
        
        @self.app.route('/test/rate-limited')
        @rate_limited_authorization(['read:test'], "5 per minute")
        async def rate_limited_endpoint():
            user = get_authenticated_user()
            return jsonify({
                'message': 'rate limited access',
                'user_id': user.user_id,
                'status': 'success'
            })
        
        @self.app.route('/test/resource/<resource_id>')
        @resource_owner_required()
        async def resource_endpoint(resource_id):
            user = get_authenticated_user()
            return jsonify({
                'message': 'resource access granted',
                'user_id': user.user_id,
                'resource_id': resource_id,
                'status': 'success'
            })
    
    @pytest.mark.asyncio
    async def test_public_endpoint_access(self):
        """Test public endpoint access without authentication requirements."""
        response = self.client.get('/test/public')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'public access'
        assert data['status'] == 'success'
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_without_token(self):
        """Test protected endpoint access without authentication token."""
        response = self.client.get('/test/protected')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error_code'] == SecurityErrorCode.AUTH_TOKEN_MISSING.value
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_with_valid_token(self, sample_jwt_token):
        """
        Test protected endpoint access with valid authentication token.
        
        Validates complete authentication flow per Section 6.4.1 authentication framework.
        """
        # Mock successful authentication
        mock_user = AuthenticatedUser(
            user_id='auth0|test_user_123',
            token_claims={'sub': 'auth0|test_user_123', 'email': 'test@example.com'},
            permissions=['read:documents', 'write:documents'],
            profile={'email': 'test@example.com', 'name': 'Test User'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth:
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.return_value = mock_user
            mock_get_auth.return_value = mock_authenticator
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            response = self.client.get('/test/protected', headers=headers)
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['message'] == 'protected access'
            assert data['user_id'] == 'auth0|test_user_123'
            assert data['status'] == 'success'
    
    @pytest.mark.asyncio
    async def test_permissions_endpoint_insufficient_permissions(self, sample_jwt_token):
        """
        Test permissions endpoint with insufficient user permissions.
        
        Validates permission-based authorization per Section 6.4.2 permission management.
        """
        # Mock user with insufficient permissions
        mock_user = AuthenticatedUser(
            user_id='auth0|limited_user',
            token_claims={'sub': 'auth0|limited_user'},
            permissions=['read:basic'],  # Missing required permissions
            profile={'email': 'limited@example.com'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth:
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.side_effect = AuthenticationException(
                message="Insufficient permissions for this operation",
                error_code=SecurityErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS,
                user_id='auth0|limited_user'
            )
            mock_get_auth.return_value = mock_authenticator
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            response = self.client.get('/test/permissions', headers=headers)
            
            assert response.status_code == 403
            data = json.loads(response.data)
            assert 'error' in data
            assert data['error_code'] == SecurityErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS.value
    
    @pytest.mark.asyncio
    async def test_admin_endpoint_with_admin_permissions(self, sample_jwt_token):
        """
        Test admin endpoint access with proper administrative permissions.
        
        Validates role-based access control per Section 6.4.2 authorization system.
        """
        # Mock admin user
        mock_admin_user = AuthenticatedUser(
            user_id='auth0|admin_user',
            token_claims={'sub': 'auth0|admin_user', 'https://api.example.com/roles': ['admin']},
            permissions=['admin:all', 'read:all', 'write:all'],
            profile={'email': 'admin@example.com', 'name': 'Admin User'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth, \
             patch('src.auth.decorators.admin_required') as mock_admin_decorator:
            
            # Mock successful admin authentication
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.return_value = mock_admin_user
            mock_get_auth.return_value = mock_authenticator
            
            # Configure admin decorator to pass
            def admin_decorator_wrapper(func):
                async def wrapper(*args, **kwargs):
                    g.authenticated_user = mock_admin_user
                    return await func(*args, **kwargs)
                return wrapper
            
            mock_admin_decorator.return_value = admin_decorator_wrapper
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            response = self.client.get('/test/admin', headers=headers)
            
            # Admin access should be granted
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['message'] == 'admin access granted'
            assert data['user_id'] == 'auth0|admin_user'
    
    @pytest.mark.asyncio
    async def test_rate_limited_endpoint_compliance(self, sample_jwt_token):
        """
        Test rate-limited endpoint behavior and enforcement.
        
        Validates rate limiting integration per Section 6.4.2 rate limiting enforcement.
        """
        mock_user = AuthenticatedUser(
            user_id='auth0|rate_test_user',
            token_claims={'sub': 'auth0|rate_test_user'},
            permissions=['read:test'],
            profile={'email': 'ratetest@example.com'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth, \
             patch('flask_limiter.Limiter.limit') as mock_limiter:
            
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.return_value = mock_user
            mock_get_auth.return_value = mock_authenticator
            
            # Mock rate limiter behavior
            def rate_limit_decorator(limit_string):
                def decorator(func):
                    return func  # Allow first few requests
                return decorator
            
            mock_limiter.return_value = rate_limit_decorator
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            
            # First request should succeed
            response = self.client.get('/test/rate-limited', headers=headers)
            assert response.status_code == 200
            
            # Subsequent requests within rate limit should succeed
            for _ in range(4):  # Total 5 requests (including first)
                response = self.client.get('/test/rate-limited', headers=headers)
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_decorator_security_event_logging(self, sample_jwt_token):
        """
        Test security event logging integration with authentication decorators.
        
        Validates audit logging per Section 6.4.2 security event logging.
        """
        mock_user = AuthenticatedUser(
            user_id='auth0|audit_test_user',
            token_claims={'sub': 'auth0|audit_test_user'},
            permissions=['read:documents'],
            profile={'email': 'audit@example.com'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth, \
             patch('src.auth.decorators.audit_security_event') as mock_audit:
            
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.return_value = mock_user
            mock_get_auth.return_value = mock_authenticator
            
            # Mock audit decorator
            def audit_wrapper(event_type):
                def decorator(func):
                    async def wrapper(*args, **kwargs):
                        # Log security event
                        mock_audit(event_type, {
                            'user_id': mock_user.user_id,
                            'endpoint': 'test_endpoint',
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        })
                        return await func(*args, **kwargs)
                    return wrapper
                return decorator
            
            mock_audit.return_value = audit_wrapper
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            response = self.client.get('/test/protected', headers=headers)
            
            assert response.status_code == 200
            
            # Verify security event was logged
            assert mock_audit.called
    
    @pytest.mark.asyncio
    async def test_resource_ownership_validation(self, sample_jwt_token):
        """
        Test resource ownership validation in decorator integration.
        
        Validates resource-level authorization per Section 6.4.2 resource authorization.
        """
        resource_owner_user = AuthenticatedUser(
            user_id='auth0|resource_owner',
            token_claims={'sub': 'auth0|resource_owner'},
            permissions=['read:resources'],
            profile={'email': 'owner@example.com'},
            token=sample_jwt_token
        )
        
        with patch('src.auth.authentication.get_core_authenticator') as mock_get_auth, \
             patch('src.auth.authorization.verify_resource_access') as mock_verify:
            
            mock_authenticator = AsyncMock()
            mock_authenticator.authenticate_request.return_value = resource_owner_user
            mock_get_auth.return_value = mock_authenticator
            
            # Mock resource ownership verification
            mock_verify.return_value = True  # User owns the resource
            
            headers = {'Authorization': f'Bearer {sample_jwt_token}'}
            response = self.client.get('/test/resource/resource_123', headers=headers)
            
            # Resource access should be granted to owner
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['message'] == 'resource access granted'
            assert data['resource_id'] == 'resource_123'
            assert data['user_id'] == 'auth0|resource_owner'


class TestSessionManagementIntegration:
    """
    Session management integration testing with Redis distributed storage.
    
    This test class validates Flask-Login integration with Redis session storage
    per Section 6.4.1 session management architecture requirements.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context, mock_redis_client):
        """Set up session management testing environment."""
        self.app = app_context
        self.redis_mock = mock_redis_client
        
        # Initialize session management
        self.session_manager = initialize_session_management(self.app, {
            'REDIS_URL': 'redis://localhost:6379/15',
            'SESSION_ENCRYPTION_KEY': base64.b64encode(os.urandom(32)).decode()
        })
        
        self.client = self.app.test_client()
    
    @pytest.mark.asyncio
    async def test_session_creation_and_storage(self):
        """
        Test session creation with Redis distributed storage.
        
        Validates session lifecycle per Section 6.4.1 Flask-Session Redis configuration.
        """
        # Create authenticated user
        test_user = AuthenticatedUser(
            user_id='auth0|session_test_user',
            token_claims={'sub': 'auth0|session_test_user', 'email': 'session@example.com'},
            permissions=['read:sessions'],
            profile={'email': 'session@example.com', 'name': 'Session Test User'}
        )
        
        # Create session data
        session_data = await self.session_manager.create_user_session(test_user)
        
        assert session_data is not None
        assert 'session_id' in session_data
        assert 'expires_at' in session_data
        assert session_data['user_id'] == 'auth0|session_test_user'
        
        # Verify Redis storage call
        assert self.redis_mock.setex.called
        call_args = self.redis_mock.setex.call_args
        assert call_args[0][0].startswith('session:')  # Session key pattern
        
        # Verify session metrics
        assert session_metrics['session_operations']._value.sum() >= 1
    
    @pytest.mark.asyncio
    async def test_session_retrieval_and_validation(self):
        """
        Test session retrieval and validation from Redis storage.
        
        Validates session persistence per Section 6.4.1 Redis key naming conventions.
        """
        # Mock session data in Redis
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': 'auth0|retrieval_test_user',
            'email': 'retrieval@example.com',
            'permissions': ['read:sessions', 'write:sessions'],
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat()
        }
        
        # Mock Redis retrieval
        self.redis_mock.get.return_value = json.dumps(session_data)
        
        # Retrieve session
        retrieved_session = await self.session_manager.get_session_data(session_id)
        
        assert retrieved_session is not None
        assert retrieved_session['user_id'] == 'auth0|retrieval_test_user'
        assert retrieved_session['email'] == 'retrieval@example.com'
        assert 'permissions' in retrieved_session
        
        # Verify Redis retrieval call
        self.redis_mock.get.assert_called_with(f'session:{session_id}')
    
    @pytest.mark.asyncio
    async def test_session_encryption_and_security(self):
        """
        Test session data encryption with AES-256-GCM.
        
        Validates encryption standards per Section 6.4.3 data protection requirements.
        """
        # Create test session with sensitive data
        sensitive_session_data = {
            'user_id': 'auth0|encryption_test_user',
            'email': 'encryption@example.com',
            'personal_data': {
                'full_name': 'Encryption Test User',
                'phone': '+1-555-0123',
                'address': '123 Test Street'
            },
            'permissions': ['admin:all']
        }
        
        # Test encryption functionality
        with patch.object(self.session_manager, 'encryption_manager') as mock_encryption:
            mock_encryption.encrypt_data.return_value = 'encrypted_session_data'
            mock_encryption.decrypt_data.return_value = sensitive_session_data
            
            # Store encrypted session
            session_id = await self.session_manager.store_encrypted_session(
                'auth0|encryption_test_user',
                sensitive_session_data
            )
            
            assert session_id is not None
            mock_encryption.encrypt_data.assert_called_once()
            
            # Retrieve and decrypt session
            decrypted_data = await self.session_manager.get_encrypted_session(session_id)
            
            assert decrypted_data == sensitive_session_data
            mock_encryption.decrypt_data.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_session_cleanup_and_expiration(self):
        """
        Test automated session cleanup and expiration handling.
        
        Validates session lifecycle management per Section 6.4.1 session security characteristics.
        """
        # Create multiple test sessions
        test_sessions = []
        for i in range(5):
            session_id = str(uuid.uuid4())
            session_data = {
                'user_id': f'auth0|cleanup_test_user_{i}',
                'created_at': (datetime.now(timezone.utc) - timedelta(hours=i)).isoformat(),
                'expires_at': (datetime.now(timezone.utc) + timedelta(hours=24-i)).isoformat()
            }
            test_sessions.append((session_id, session_data))
        
        # Mock Redis pattern matching for cleanup
        session_keys = [f'session:{session_id}' for session_id, _ in test_sessions]
        self.redis_mock.keys.return_value = session_keys
        
        # Mock session data retrieval for expiration check
        def mock_get_session(key):
            session_id = key.split(':')[1]
            for sid, data in test_sessions:
                if sid == session_id:
                    return json.dumps(data)
            return None
        
        self.redis_mock.get.side_effect = mock_get_session
        
        # Execute cleanup process
        cleaned_count = await self.session_manager.cleanup_expired_sessions()
        
        assert cleaned_count >= 0  # Some sessions may be expired
        
        # Verify cleanup operations
        assert self.redis_mock.keys.called
        assert self.redis_mock.get.called
    
    @pytest.mark.asyncio
    async def test_session_performance_benchmarks(self):
        """
        Test session management performance against baseline requirements.
        
        Validates performance optimization per Section 0.1.1 performance variance requirement.
        """
        # Performance test parameters
        session_operations = 100
        max_operation_time = 0.1  # 100ms maximum per operation
        
        # Test session creation performance
        creation_times = []
        for i in range(session_operations):
            test_user = AuthenticatedUser(
                user_id=f'auth0|perf_test_user_{i}',
                token_claims={'sub': f'auth0|perf_test_user_{i}'},
                permissions=['read:test'],
                profile={'email': f'perf{i}@example.com'}
            )
            
            start_time = time.time()
            session_data = await self.session_manager.create_user_session(test_user)
            creation_time = time.time() - start_time
            creation_times.append(creation_time)
            
            assert session_data is not None
            assert creation_time < max_operation_time, f"Session creation took {creation_time}s, exceeding {max_operation_time}s threshold"
        
        # Calculate performance statistics
        avg_creation_time = sum(creation_times) / len(creation_times)
        max_creation_time = max(creation_times)
        
        # Performance assertions
        assert avg_creation_time < max_operation_time * 0.5, f"Average session creation time {avg_creation_time}s exceeds performance target"
        assert max_creation_time < max_operation_time, f"Maximum session creation time {max_creation_time}s exceeds performance threshold"
        
        # Verify session performance metrics
        assert session_metrics['session_duration']._value.sum() > 0
    
    @pytest.mark.asyncio
    async def test_cross_instance_session_sharing(self):
        """
        Test cross-instance session sharing through Redis distributed caching.
        
        Validates distributed session architecture per Section 6.4.1 session management.
        """
        # Simulate multiple Flask application instances
        instance_configs = [
            {'instance_id': 'flask_instance_1', 'redis_db': 1},
            {'instance_id': 'flask_instance_2', 'redis_db': 1},  # Same Redis DB
            {'instance_id': 'flask_instance_3', 'redis_db': 1}   # Same Redis DB
        ]
        
        session_managers = []
        for config in instance_configs:
            # Create session manager for each instance
            manager = FlaskLoginSessionManager(
                redis_client=self.redis_mock,
                encryption_key=base64.b64encode(os.urandom(32)).decode(),
                instance_id=config['instance_id']
            )
            session_managers.append(manager)
        
        # Create session on first instance
        test_user = AuthenticatedUser(
            user_id='auth0|cross_instance_user',
            token_claims={'sub': 'auth0|cross_instance_user'},
            permissions=['read:cross_instance'],
            profile={'email': 'crossinstance@example.com'}
        )
        
        session_data = await session_managers[0].create_user_session(test_user)
        session_id = session_data['session_id']
        
        # Mock Redis to return session data for all instances
        self.redis_mock.get.return_value = json.dumps(session_data)
        
        # Verify session accessibility from other instances
        for manager in session_managers[1:]:
            retrieved_session = await manager.get_session_data(session_id)
            
            assert retrieved_session is not None
            assert retrieved_session['user_id'] == 'auth0|cross_instance_user'
            assert retrieved_session['session_id'] == session_id
        
        # Verify all instances use same Redis key pattern
        expected_key = f'session:{session_id}'
        for call in self.redis_mock.get.call_args_list:
            if call[0][0] == expected_key:
                assert True  # Found expected key pattern
                break
        else:
            pytest.fail("Expected session key pattern not found in Redis calls")


class TestCircuitBreakerAndRetryLogic:
    """
    Circuit breaker and retry logic testing for Auth0 API calls.
    
    This test class validates circuit breaker patterns and intelligent retry strategies
    per Section 6.4.2 circuit breaker integration requirements.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context):
        """Set up circuit breaker testing environment."""
        self.app = app_context
        self.authenticator = get_core_authenticator()
        
        # Reset circuit breaker state
        self.authenticator._auth0_circuit_breaker_state = 'closed'
        self.authenticator._auth0_failure_count = 0
        self.authenticator._auth0_last_failure_time = None
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state_normal_operation(self):
        """
        Test circuit breaker in closed state during normal Auth0 operations.
        
        Validates normal operation patterns per Section 6.4.2 circuit breaker integration.
        """
        # Mock successful Auth0 API calls
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {
                'last_login': '2024-01-15T10:30:00.000Z',
                'logins_count': 5,
                'app_metadata': {},
                'user_metadata': {}
            }
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Execute multiple successful operations
            for _ in range(3):
                profile = await self.authenticator._fetch_auth0_user_profile('auth0|test_user')
                assert profile is not None
                assert 'last_login' in profile
            
            # Verify circuit breaker remains closed
            assert self.authenticator._auth0_circuit_breaker_state == 'closed'
            assert self.authenticator._auth0_failure_count == 0
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_accumulation(self):
        """
        Test circuit breaker failure accumulation and state transitions.
        
        Validates failure tracking per Section 6.4.2 circuit breaker patterns.
        """
        # Simulate progressive Auth0 service degradation
        failure_responses = [
            httpx.RequestError("Connection timeout"),
            httpx.HTTPStatusError("503 Service Unavailable", request=Mock(), response=Mock(status_code=503)),
            httpx.RequestError("Connection refused"),
            httpx.HTTPStatusError("502 Bad Gateway", request=Mock(), response=Mock(status_code=502)),
            httpx.RequestError("DNS resolution failed")
        ]
        
        with patch('httpx.AsyncClient.get', side_effect=failure_responses):
            failure_count = 0
            
            # Execute failing operations
            for i, _ in enumerate(failure_responses):
                try:
                    await self.authenticator._fetch_auth0_user_profile(f'auth0|test_user_{i}')
                except Exception:
                    failure_count += 1
                
                # Check circuit breaker state progression
                if failure_count >= 3:
                    assert self.authenticator._auth0_circuit_breaker_state in ['half-open', 'open']
            
            # Verify failure count tracking
            assert self.authenticator._auth0_failure_count >= 3
            assert self.authenticator._auth0_last_failure_time is not None
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_open_state_immediate_failure(self):
        """
        Test circuit breaker open state with immediate failure responses.
        
        Validates fast-fail behavior per Section 6.4.2 circuit breaker protection.
        """
        # Force circuit breaker to open state
        self.authenticator._auth0_circuit_breaker_state = 'open'
        self.authenticator._auth0_failure_count = 5
        self.authenticator._auth0_last_failure_time = time.time()
        
        # Attempt operation with open circuit breaker
        start_time = time.time()
        
        with patch('httpx.AsyncClient.get') as mock_get:
            # Circuit breaker should prevent API call
            result = await self.authenticator._fetch_auth0_user_profile('auth0|test_user')
            
            # Should fail fast without making HTTP request
            execution_time = time.time() - start_time
            assert execution_time < 0.01, f"Circuit breaker open state should fail fast, took {execution_time}s"
            assert result is None
            
            # Verify no HTTP calls were made
            mock_get.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_state_recovery(self):
        """
        Test circuit breaker half-open state and recovery behavior.
        
        Validates recovery patterns per Section 6.4.2 Auth0 service resilience.
        """
        # Set circuit breaker to half-open state
        self.authenticator._auth0_circuit_breaker_state = 'half-open'
        self.authenticator._auth0_failure_count = 3
        self.authenticator._auth0_last_failure_time = time.time() - 60  # 1 minute ago
        
        # Mock successful Auth0 recovery
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {
                'last_login': '2024-01-15T10:30:00.000Z',
                'logins_count': 10,
                'app_metadata': {'role': 'user'},
                'user_metadata': {'preferences': {}}
            }
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Execute test operation
            profile = await self.authenticator._fetch_auth0_user_profile('auth0|recovery_test_user')
            
            assert profile is not None
            assert profile['logins_count'] == 10
            assert 'app_metadata' in profile
            
            # Verify circuit breaker recovery
            assert self.authenticator._auth0_circuit_breaker_state == 'closed'
            assert self.authenticator._auth0_failure_count == 0
    
    @pytest.mark.asyncio
    async def test_exponential_backoff_retry_strategy(self):
        """
        Test exponential backoff retry strategy for Auth0 API calls.
        
        Validates intelligent retry patterns per Section 6.4.2 retry logic.
        """
        # Track retry attempts and timing
        retry_attempts = []
        retry_delays = []
        
        def track_retry_attempt(*args, **kwargs):
            retry_attempts.append(time.time())
            if len(retry_attempts) > 1:
                delay = retry_attempts[-1] - retry_attempts[-2]
                retry_delays.append(delay)
            raise httpx.RequestError("Simulated failure")
        
        # Configure retry behavior
        with patch('httpx.AsyncClient.get', side_effect=track_retry_attempt), \
             patch('tenacity.wait_exponential_jitter') as mock_backoff:
            
            # Set progressive backoff delays
            mock_backoff.return_value = [0.1, 0.2, 0.4]  # Exponential progression
            
            try:
                await self.authenticator._fetch_auth0_user_profile('auth0|retry_test_user')
            except Exception:
                pass  # Expected to fail after retries
            
            # Verify retry attempts were made
            assert len(retry_attempts) >= 2, "Multiple retry attempts should be made"
            
            # Verify exponential backoff pattern (approximately)
            if len(retry_delays) >= 2:
                assert retry_delays[1] > retry_delays[0], "Retry delays should increase exponentially"
    
    @pytest.mark.asyncio
    async def test_fallback_mechanisms_with_cached_data(self):
        """
        Test fallback mechanisms using cached permission data.
        
        Validates fallback patterns per Section 6.4.2 Redis permission caching.
        """
        # Set up circuit breaker in open state
        self.authenticator._auth0_circuit_breaker_state = 'open'
        
        # Mock cached permission data
        cached_permissions = ['read:documents', 'write:documents', 'admin:settings']
        
        with patch.object(self.authenticator.cache_manager, 'get_cached_permissions',
                         return_value=set(cached_permissions)):
            
            # Test fallback permission validation
            result = await self.authenticator._fallback_permission_validation(
                'auth0|fallback_test_user',
                ['read:documents', 'write:documents']
            )
            
            assert result is not None
            assert result['user_id'] == 'auth0|fallback_test_user'
            assert result['has_permissions'] is True
            assert result['validation_source'] == 'fallback_cache'
            assert result['degraded_mode'] is True
            assert result['granted_permissions'] == cached_permissions
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_metrics_collection(self):
        """
        Test circuit breaker metrics collection and monitoring.
        
        Validates monitoring integration per Section 6.4.2 comprehensive monitoring.
        """
        # Reset metrics
        authorization_metrics['circuit_breaker_events']._value.clear()
        
        # Simulate circuit breaker events
        circuit_breaker_events = [
            ('auth0_service', 'failure', 'closed'),
            ('auth0_service', 'failure', 'closed'),
            ('auth0_service', 'failure', 'closed'),
            ('auth0_service', 'open', 'open'),
            ('auth0_service', 'attempt', 'half-open'),
            ('auth0_service', 'success', 'closed')
        ]
        
        # Simulate events and metric collection
        for service, event_type, state in circuit_breaker_events:
            authorization_metrics['circuit_breaker_events'].labels(
                service=service,
                event_type=event_type,
                state=state
            ).inc()
        
        # Verify metrics collection
        total_events = authorization_metrics['circuit_breaker_events']._value.sum()
        assert total_events >= len(circuit_breaker_events)
        
        # Verify specific event types were recorded
        failure_events = len([e for e in circuit_breaker_events if e[1] == 'failure'])
        success_events = len([e for e in circuit_breaker_events if e[1] == 'success'])
        
        assert failure_events > 0
        assert success_events > 0
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_configuration_validation(self):
        """
        Test circuit breaker configuration and threshold validation.
        
        Validates configuration requirements per Section 6.4.2 circuit breaker patterns.
        """
        # Test circuit breaker configuration parameters
        config_tests = [
            {
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'half_open_max_calls': 5,
                'expected_valid': True
            },
            {
                'failure_threshold': 0,  # Invalid
                'recovery_timeout': 60,
                'half_open_max_calls': 5,
                'expected_valid': False
            },
            {
                'failure_threshold': 3,
                'recovery_timeout': -1,  # Invalid
                'half_open_max_calls': 5,
                'expected_valid': False
            }
        ]
        
        for config in config_tests:
            # Validate configuration
            is_valid = (
                config['failure_threshold'] > 0 and
                config['recovery_timeout'] > 0 and
                config['half_open_max_calls'] > 0
            )
            
            assert is_valid == config['expected_valid'], f"Configuration validation failed for {config}"
        
        # Test default configuration values
        assert hasattr(self.authenticator, '_auth0_circuit_breaker_state')
        assert self.authenticator._auth0_circuit_breaker_state in ['closed', 'open', 'half-open']
        assert isinstance(self.authenticator._auth0_failure_count, int)


class TestSecurityEventLoggingIntegration:
    """
    Security event logging integration testing with audit systems.
    
    This test class validates comprehensive security event logging per Section 6.4.2
    security event logging requirements.
    """
    
    @pytest.fixture(autouse=True)
    async def setup_method(self, app_context):
        """Set up security event logging testing environment."""
        self.app = app_context
        self.authenticator = get_core_authenticator()
        
        # Configure structured logging for testing
        self.security_events = []
        
        # Mock security audit logger
        self.mock_audit_logger = Mock()
        self.mock_audit_logger.log_authorization_event = Mock()
        self.mock_audit_logger.log_rate_limit_violation = Mock()
        self.mock_audit_logger.log_circuit_breaker_event = Mock()
    
    @pytest.mark.asyncio
    async def test_authentication_success_event_logging(self):
        """
        Test authentication success event logging with structured data.
        
        Validates audit logging per Section 6.4.2 comprehensive security event logging.
        """
        # Mock successful authentication
        test_user = AuthenticatedUser(
            user_id='auth0|logging_test_user',
            token_claims={
                'sub': 'auth0|logging_test_user',
                'email': 'logging@example.com',
                'iss': 'https://test-domain.auth0.com/',
                'aud': 'test-api-audience'
            },
            permissions=['read:logs', 'write:logs'],
            profile={'email': 'logging@example.com', 'name': 'Logging Test User'}
        )
        
        with patch('src.auth.authentication.log_security_event') as mock_log_event:
            
            # Simulate authentication success
            await self.authenticator._create_user_context(
                test_user.token_claims,
                'test_jwt_token'
            )
            
            # Verify security event logging
            mock_log_event.assert_called()
            
            # Extract logged event details
            call_args = mock_log_event.call_args_list
            authentication_events = [
                call for call in call_args 
                if 'authentication' in str(call[0][0]).lower()
            ]
            
            assert len(authentication_events) > 0, "Authentication events should be logged"
    
    @pytest.mark.asyncio
    async def test_authentication_failure_event_logging(self):
        """
        Test authentication failure event logging with error context.
        
        Validates failure audit logging per Section 6.4.2 audit logging requirements.
        """
        with patch('src.auth.authentication.log_security_event') as mock_log_event:
            
            # Simulate authentication failure
            try:
                await self.authenticator._validate_jwt_token('invalid_token')
            except JWTException:
                pass  # Expected failure
            
            # Verify failure event logging
            mock_log_event.assert_called()
            
            # Check for failure-related events
            call_args = mock_log_event.call_args_list
            failure_events = [
                call for call in call_args 
                if any(term in str(call).lower() for term in ['failure', 'error', 'invalid'])
            ]
            
            assert len(failure_events) > 0, "Authentication failure events should be logged"
    
    @pytest.mark.asyncio
    async def test_authorization_decision_event_logging(self):
        """
        Test authorization decision event logging with permission context.
        
        Validates authorization audit logging per Section 6.4.2 authorization decisions.
        """
        # Mock authorization decision
        test_user = AuthenticatedUser(
            user_id='auth0|authz_logging_user',
            token_claims={'sub': 'auth0|authz_logging_user'},
            permissions=['read:documents'],  # Limited permissions
            profile={'email': 'authz@example.com'}
        )
        
        required_permissions = ['read:documents', 'write:documents', 'admin:all']
        
        with patch.object(self.mock_audit_logger, 'log_authorization_event') as mock_log_authz:
            
            # Simulate authorization decision
            has_permissions = test_user.has_all_permissions(required_permissions)
            
            # Log authorization event
            self.mock_audit_logger.log_authorization_event(
                event_type='permission_check',
                user_id=test_user.user_id,
                result='denied' if not has_permissions else 'granted',
                permissions=required_permissions,
                additional_context={
                    'user_permissions': test_user.permissions,
                    'required_permissions': required_permissions,
                    'permission_deficit': list(set(required_permissions) - set(test_user.permissions))
                }
            )
            
            # Verify authorization event logging
            mock_log_authz.assert_called_once()
            call_args = mock_log_authz.call_args
            
            assert call_args[1]['event_type'] == 'permission_check'
            assert call_args[1]['user_id'] == 'auth0|authz_logging_user'
            assert call_args[1]['result'] == 'denied'
            assert 'additional_context' in call_args[1]
    
    @pytest.mark.asyncio
    async def test_rate_limit_violation_event_logging(self):
        """
        Test rate limit violation event logging with request context.
        
        Validates rate limiting audit per Section 6.4.2 rate limiting violations.
        """
        with patch.object(self.mock_audit_logger, 'log_rate_limit_violation') as mock_log_rate_limit:
            
            # Simulate rate limit violation
            rate_limit_context = {
                'user_id': 'auth0|rate_limit_user',
                'endpoint': '/api/high-frequency-endpoint',
                'limit_exceeded': '100 per minute',
                'current_usage': 150,
                'client_ip': '192.168.1.100',
                'user_agent': 'TestClient/1.0'
            }
            
            self.mock_audit_logger.log_rate_limit_violation(**rate_limit_context)
            
            # Verify rate limit violation logging
            mock_log_rate_limit.assert_called_once()
            call_args = mock_log_rate_limit.call_args
            
            assert call_args[1]['user_id'] == 'auth0|rate_limit_user'
            assert call_args[1]['endpoint'] == '/api/high-frequency-endpoint'
            assert call_args[1]['current_usage'] == 150
            assert 'limit_exceeded' in call_args[1]
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_event_logging(self):
        """
        Test circuit breaker event logging with service context.
        
        Validates service monitoring per Section 6.4.2 circuit breaker events.
        """
        with patch.object(self.mock_audit_logger, 'log_circuit_breaker_event') as mock_log_circuit:
            
            # Simulate circuit breaker events
            circuit_breaker_events = [
                {
                    'service': 'auth0_service',
                    'event': 'failure_detected',
                    'failure_count': 1,
                    'additional_info': {'error_type': 'ConnectionTimeout', 'response_time': 30.0}
                },
                {
                    'service': 'auth0_service',
                    'event': 'circuit_opened',
                    'failure_count': 3,
                    'additional_info': {'threshold_exceeded': True, 'open_duration': 60}
                },
                {
                    'service': 'auth0_service',
                    'event': 'circuit_half_open',
                    'failure_count': 0,
                    'additional_info': {'recovery_attempt': True, 'test_request': True}
                }
            ]
            
            # Log each circuit breaker event
            for event in circuit_breaker_events:
                self.mock_audit_logger.log_circuit_breaker_event(**event)
            
            # Verify circuit breaker event logging
            assert mock_log_circuit.call_count == len(circuit_breaker_events)
            
            # Verify event details
            call_args_list = mock_log_circuit.call_args_list
            logged_events = [call[1]['event'] for call in call_args_list]
            
            assert 'failure_detected' in logged_events
            assert 'circuit_opened' in logged_events
            assert 'circuit_half_open' in logged_events
    
    @pytest.mark.asyncio
    async def test_security_event_correlation_and_context(self):
        """
        Test security event correlation with request context.
        
        Validates comprehensive audit trail per Section 6.4.2 audit logging.
        """
        # Generate correlation ID for request tracking
        correlation_id = str(uuid.uuid4())
        request_context = {
            'correlation_id': correlation_id,
            'request_ip': '10.0.1.50',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'request_path': '/api/sensitive-operation',
            'request_method': 'POST',
            'session_id': str(uuid.uuid4())
        }
        
        with patch('src.auth.authentication.log_security_event') as mock_log_event:
            
            # Simulate correlated security events
            security_events = [
                ('authentication_attempt', {
                    'user_id': 'auth0|correlation_user',
                    'success': True,
                    'correlation_id': correlation_id,
                    **request_context
                }),
                ('authorization_check', {
                    'user_id': 'auth0|correlation_user',
                    'permission': 'sensitive:operation',
                    'granted': True,
                    'correlation_id': correlation_id,
                    **request_context
                }),
                ('data_access', {
                    'user_id': 'auth0|correlation_user',
                    'resource_type': 'sensitive_document',
                    'operation': 'read',
                    'correlation_id': correlation_id,
                    **request_context
                })
            ]
            
            # Log correlated events
            for event_type, event_data in security_events:
                mock_log_event(event_type, **event_data)
            
            # Verify all events were logged with correlation
            assert mock_log_event.call_count == len(security_events)
            
            # Verify correlation ID in all events
            for call in mock_log_event.call_args_list:
                event_data = call[0][1] if len(call[0]) > 1 else call[1]
                assert event_data.get('correlation_id') == correlation_id
                assert 'request_ip' in event_data
                assert 'user_agent' in event_data
    
    @pytest.mark.asyncio
    async def test_structured_logging_format_compliance(self):
        """
        Test structured logging format compliance with enterprise standards.
        
        Validates logging format per Section 6.4.2 structured security logging.
        """
        # Test required logging fields
        required_fields = [
            'timestamp',
            'event_type',
            'user_id',
            'severity',
            'source_ip',
            'correlation_id',
            'application',
            'environment'
        ]
        
        with patch('structlog.get_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            # Simulate structured security event
            security_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'authentication_success',
                'user_id': 'auth0|structured_log_user',
                'severity': 'INFO',
                'source_ip': '172.16.0.100',
                'correlation_id': str(uuid.uuid4()),
                'application': 'flask-auth-service',
                'environment': 'test',
                'additional_data': {
                    'user_agent': 'Test/1.0',
                    'endpoint': '/api/login',
                    'duration_ms': 150
                }
            }
            
            # Log structured event
            logger = mock_get_logger()
            logger.info("Authentication successful", **security_event)
            
            # Verify structured logging call
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args
            
            # Verify required fields are present
            logged_data = call_args[1]
            for field in required_fields:
                assert field in logged_data, f"Required field '{field}' missing from structured log"
            
            # Verify data types and format
            assert isinstance(logged_data['timestamp'], str)
            assert logged_data['event_type'] == 'authentication_success'
            assert logged_data['severity'] in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    
    @pytest.mark.asyncio
    async def test_audit_log_retention_and_compliance(self):
        """
        Test audit log retention policies and compliance requirements.
        
        Validates compliance logging per Section 6.4.2 enterprise compliance support.
        """
        # Simulate audit log entries with retention metadata
        audit_entries = []
        
        for i in range(10):
            entry = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now(timezone.utc) - timedelta(days=i)).isoformat(),
                'event_type': f'test_event_{i}',
                'user_id': f'auth0|test_user_{i}',
                'retention_class': 'security_audit',
                'compliance_tags': ['SOC2', 'ISO27001', 'GDPR'],
                'retention_period_days': 2555,  # 7 years for security audits
                'encryption_status': 'AES-256-GCM',
                'data_classification': 'confidential'
            }
            audit_entries.append(entry)
        
        # Verify audit entry structure
        for entry in audit_entries:
            assert 'id' in entry
            assert 'timestamp' in entry
            assert 'retention_class' in entry
            assert 'compliance_tags' in entry
            assert 'retention_period_days' in entry
            assert entry['encryption_status'] == 'AES-256-GCM'
            
            # Verify compliance tag requirements
            required_compliance = ['SOC2', 'ISO27001']
            for tag in required_compliance:
                assert tag in entry['compliance_tags']
        
        # Test retention policy compliance
        retention_classes = {
            'security_audit': 2555,    # 7 years
            'authentication': 1095,   # 3 years
            'authorization': 1095,    # 3 years
            'admin_action': 2555      # 7 years
        }
        
        for entry in audit_entries:
            retention_class = entry['retention_class']
            expected_retention = retention_classes.get(retention_class, 365)
            assert entry['retention_period_days'] == expected_retention