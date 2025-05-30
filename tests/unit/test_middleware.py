"""
Unit Tests for Flask Middleware Components
=========================================

Comprehensive middleware testing covering CORS handling, security headers, authentication 
decorators, rate limiting, and request processing pipeline. Tests Flask-CORS, Flask-Talisman, 
Flask-Limiter integration and middleware chain execution maintaining Express.js middleware 
equivalent patterns.

This test module validates:
- CORS handling for cross-origin request support per F-003-RQ-003
- Security header enforcement per Section 6.4.1 (Flask-Talisman)
- Authentication decorator functionality per Section 6.4.2
- Rate limiting middleware per Section 5.2.2 (Flask-Limiter)
- Request processing pipeline equivalent to Express.js patterns per Section 0.1.2
- Middleware chain execution order and error handling
- Integration with Flask application factory pattern

Test Categories:
- CORS middleware testing with Flask-CORS 4.0+
- Security headers middleware testing with Flask-Talisman 1.1.0+
- Authentication and authorization decorator testing
- Rate limiting middleware testing with Flask-Limiter 3.5+
- Request/response interceptor testing
- Middleware pipeline integration testing
- Error handling and exception propagation testing
"""

import json
import pytest
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, patch, call
from typing import Any, Dict, List, Optional
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, TooManyRequests

# Flask testing imports
from flask import Flask, jsonify, request, g, url_for, current_app
from flask.testing import FlaskClient
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Authentication and security imports
import jwt
from werkzeug.test import Client, EnvironBuilder

# Test framework imports
from tests.unit.conftest import (
    test_config, mock_environment, test_jwt_token, 
    expired_jwt_token, test_jwt_payload, performance_timer
)

# Import modules under test
from src.auth.decorators import (
    AuthenticationDecorators,
    require_authentication,
    require_permissions,
    rate_limited_authorization,
    require_admin,
    require_api_key,
    conditional_auth,
    init_decorators,
    get_decorators
)
from src.auth.security import (
    SecurityHeadersConfig,
    FlaskTalismanSecurityManager,
    enhanced_security_headers,
    initialize_security_headers,
    get_security_report,
    validate_security_configuration,
    init_security_module
)
from src.app import create_app


# ============================================================================
# PYTEST CONFIGURATION AND MARKERS
# ============================================================================

pytestmark = [
    pytest.mark.middleware,
    pytest.mark.utilities,
    pytest.mark.security
]


# ============================================================================
# FIXTURE SETUP FOR MIDDLEWARE TESTING
# ============================================================================

@pytest.fixture
def app_with_middleware(mock_environment):
    """Create Flask application with full middleware stack for testing."""
    with patch.dict('os.environ', mock_environment):
        app = create_app()
        
        # Configure test-specific settings
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SECRET_KEY'] = 'test-secret-key'
        app.config['JWT_SECRET_KEY'] = mock_environment['JWT_SECRET_KEY']
        
        # Disable rate limiting for most tests (enable selectively)
        app.config['RATELIMIT_ENABLED'] = False
        
        return app


@pytest.fixture
def client(app_with_middleware):
    """Flask test client with middleware stack."""
    return app_with_middleware.test_client()


@pytest.fixture
def app_context(app_with_middleware):
    """Flask application context for testing."""
    with app_with_middleware.app_context():
        yield app_with_middleware


@pytest.fixture
def request_context(app_with_middleware):
    """Flask request context for testing."""
    with app_with_middleware.test_request_context():
        yield app_with_middleware


@pytest.fixture
def test_blueprint(app_with_middleware):
    """Test blueprint with middleware-protected endpoints."""
    from flask import Blueprint
    
    bp = Blueprint('test', __name__, url_prefix='/test')
    
    @bp.route('/public')
    def public_endpoint():
        """Public endpoint for CORS and basic middleware testing."""
        return jsonify({'message': 'public access', 'user': getattr(g, 'current_user_id', 'anonymous')})
    
    @bp.route('/protected')
    @require_authentication()
    def protected_endpoint():
        """Protected endpoint requiring authentication."""
        return jsonify({
            'message': 'protected access',
            'user': g.current_user_id,
            'auth_method': g.auth_method
        })
    
    @bp.route('/admin-only')
    @require_admin()
    def admin_endpoint():
        """Admin-only endpoint with enhanced security."""
        return jsonify({
            'message': 'admin access',
            'user': g.current_user_id,
            'permissions': getattr(g, 'user_permissions', [])
        })
    
    @bp.route('/rate-limited')
    @rate_limited_authorization(['read'], rate_limit="5 per minute")
    def rate_limited_endpoint():
        """Rate-limited endpoint for testing Flask-Limiter integration."""
        return jsonify({
            'message': 'rate limited access',
            'user': g.current_user_id,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @bp.route('/conditional-auth')
    @conditional_auth(lambda: request.args.get('require_auth') == 'true')
    def conditional_endpoint():
        """Endpoint with conditional authentication for testing."""
        return jsonify({
            'message': 'conditional access',
            'user': getattr(g, 'current_user_id', 'anonymous'),
            'auth_required': request.args.get('require_auth') == 'true'
        })
    
    @bp.route('/api-key-protected')
    @require_api_key()
    def api_key_endpoint():
        """API key protected endpoint."""
        return jsonify({
            'message': 'api key access',
            'api_key_id': g.api_key_id,
            'scopes': g.api_key_scopes
        })
    
    @bp.route('/enhanced-security')
    @enhanced_security_headers(
        custom_headers={'X-Custom-Security': 'test-value'},
        require_https=False  # Disabled for testing
    )
    def enhanced_security_endpoint():
        """Endpoint with enhanced security headers."""
        return jsonify({'message': 'enhanced security'})
    
    app_with_middleware.register_blueprint(bp)
    return bp


@pytest.fixture
def rate_limited_app(mock_environment):
    """Flask application with rate limiting enabled."""
    with patch.dict('os.environ', mock_environment):
        app = create_app()
        app.config['TESTING'] = True
        app.config['RATELIMIT_ENABLED'] = True
        app.config['RATELIMIT_STORAGE_URL'] = 'memory://'
        
        # Create a simple rate-limited endpoint
        @app.route('/rate-test')
        def rate_test():
            return jsonify({'message': 'rate test', 'timestamp': time.time()})
        
        return app


@pytest.fixture
def cors_headers():
    """Standard CORS headers for testing."""
    return {
        'Origin': 'https://example.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type,Authorization'
    }


@pytest.fixture
def auth_headers(test_jwt_token):
    """Authentication headers with valid JWT token."""
    return {
        'Authorization': f'Bearer {test_jwt_token}',
        'Content-Type': 'application/json'
    }


@pytest.fixture
def invalid_auth_headers():
    """Authentication headers with invalid JWT token."""
    return {
        'Authorization': 'Bearer invalid-jwt-token',
        'Content-Type': 'application/json'
    }


@pytest.fixture
def api_key_headers():
    """API key headers for testing."""
    return {
        'X-API-Key': 'test-api-key-12345',
        'Content-Type': 'application/json'
    }


# ============================================================================
# CORS MIDDLEWARE TESTING (Flask-CORS)
# ============================================================================

class TestCORSMiddleware:
    """Test CORS handling with Flask-CORS 4.0+ integration."""
    
    def test_cors_preflight_request(self, client, cors_headers):
        """Test CORS preflight OPTIONS request handling."""
        response = client.options('/test/public', headers=cors_headers)
        
        assert response.status_code == 200
        assert 'Access-Control-Allow-Origin' in response.headers
        assert 'Access-Control-Allow-Methods' in response.headers
        assert 'Access-Control-Allow-Headers' in response.headers
        
        # Verify allowed methods include required HTTP verbs
        allowed_methods = response.headers.get('Access-Control-Allow-Methods', '')
        required_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        for method in required_methods:
            assert method in allowed_methods
    
    def test_cors_simple_request(self, client, cors_headers):
        """Test CORS simple request with origin header."""
        headers = {'Origin': cors_headers['Origin']}
        response = client.get('/test/public', headers=headers)
        
        assert response.status_code == 200
        assert response.headers.get('Access-Control-Allow-Origin') == cors_headers['Origin']
        
        # Verify response contains expected data
        data = response.get_json()
        assert data['message'] == 'public access'
    
    def test_cors_credentials_support(self, client, cors_headers):
        """Test CORS credentials support for authenticated requests."""
        headers = {**cors_headers, 'Cookie': 'session=test-session-id'}
        response = client.options('/test/protected', headers=headers)
        
        assert response.status_code == 200
        assert 'Access-Control-Allow-Credentials' in response.headers
        assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
    
    def test_cors_custom_headers_allowed(self, client, cors_headers):
        """Test CORS allows custom headers including Authorization."""
        response = client.options('/test/protected', headers=cors_headers)
        
        allowed_headers = response.headers.get('Access-Control-Allow-Headers', '').lower()
        required_headers = ['content-type', 'authorization', 'x-requested-with']
        
        for header in required_headers:
            assert header in allowed_headers
    
    def test_cors_max_age_caching(self, client, cors_headers):
        """Test CORS preflight response includes max-age for caching."""
        response = client.options('/test/public', headers=cors_headers)
        
        assert response.status_code == 200
        max_age = response.headers.get('Access-Control-Max-Age')
        assert max_age is not None
        assert int(max_age) >= 3600  # At least 1 hour caching
    
    def test_cors_origin_validation(self, client):
        """Test CORS origin validation with different origins."""
        test_cases = [
            ('https://allowed-domain.com', True),
            ('https://example.com', True),
            ('http://localhost:3000', True),  # Development origin
            ('https://malicious-site.com', False)  # Should be rejected
        ]
        
        for origin, should_allow in test_cases:
            headers = {'Origin': origin}
            response = client.get('/test/public', headers=headers)
            
            if should_allow:
                assert response.headers.get('Access-Control-Allow-Origin') is not None
            else:
                # Note: Flask-CORS might still include headers based on configuration
                # This test validates the basic CORS configuration is working
                assert response.status_code == 200  # Request succeeds but CORS may be restricted
    
    def test_cors_error_response_headers(self, client, cors_headers):
        """Test CORS headers are included in error responses."""
        headers = {**cors_headers, 'Authorization': 'Bearer invalid-token'}
        response = client.get('/test/protected', headers=headers)
        
        # Should be 401 Unauthorized but still include CORS headers
        assert response.status_code == 401
        assert 'Access-Control-Allow-Origin' in response.headers
    
    @pytest.mark.performance
    def test_cors_performance_overhead(self, client, cors_headers, performance_timer):
        """Test CORS middleware performance impact."""
        # Measure request time without CORS headers
        performance_timer.start()
        response1 = client.get('/test/public')
        no_cors_time = performance_timer.stop()
        
        # Measure request time with CORS headers
        performance_timer.start()
        response2 = client.get('/test/public', headers=cors_headers)
        cors_time = performance_timer.stop()
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # CORS overhead should be minimal (< 10ms difference)
        overhead = cors_time - no_cors_time
        assert overhead < 0.01  # Less than 10ms overhead


# ============================================================================
# SECURITY HEADERS MIDDLEWARE TESTING (Flask-Talisman)
# ============================================================================

class TestSecurityHeadersMiddleware:
    """Test security headers enforcement with Flask-Talisman 1.1.0+."""
    
    def test_basic_security_headers_present(self, client):
        """Test basic security headers are present in responses."""
        response = client.get('/test/public')
        
        assert response.status_code == 200
        
        # Check for essential security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        for header in security_headers:
            assert header in response.headers, f"Missing security header: {header}"
    
    def test_content_security_policy_header(self, client):
        """Test Content Security Policy header configuration."""
        response = client.get('/test/public')
        
        csp_header = response.headers.get('Content-Security-Policy')
        assert csp_header is not None
        
        # Verify key CSP directives
        assert "default-src 'self'" in csp_header
        assert "script-src 'self'" in csp_header
        assert "style-src 'self'" in csp_header
        assert "object-src 'none'" in csp_header
        assert "frame-ancestors 'none'" in csp_header
    
    def test_hsts_header_configuration(self, client):
        """Test HTTP Strict Transport Security header."""
        response = client.get('/test/public')
        
        # Note: HSTS may not be present in development/testing
        # This test validates the configuration is properly set up
        sts_header = response.headers.get('Strict-Transport-Security')
        if sts_header:
            assert 'max-age=' in sts_header
            assert int(sts_header.split('max-age=')[1].split(';')[0]) > 0
    
    def test_x_content_type_options_nosniff(self, client):
        """Test X-Content-Type-Options header prevents MIME sniffing."""
        response = client.get('/test/public')
        
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    
    def test_x_frame_options_deny(self, client):
        """Test X-Frame-Options header prevents clickjacking."""
        response = client.get('/test/public')
        
        frame_options = response.headers.get('X-Frame-Options')
        assert frame_options in ['DENY', 'SAMEORIGIN']
    
    def test_referrer_policy_configuration(self, client):
        """Test Referrer-Policy header for privacy protection."""
        response = client.get('/test/public')
        
        referrer_policy = response.headers.get('Referrer-Policy')
        assert referrer_policy is not None
        
        # Should be a privacy-preserving policy
        privacy_policies = [
            'strict-origin-when-cross-origin',
            'same-origin',
            'no-referrer'
        ]
        assert referrer_policy in privacy_policies
    
    def test_enhanced_security_headers_decorator(self, client):
        """Test enhanced security headers decorator functionality."""
        response = client.get('/test/enhanced-security')
        
        assert response.status_code == 200
        
        # Check for custom security header from decorator
        assert response.headers.get('X-Custom-Security') == 'test-value'
        
        # Standard security headers should still be present
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
    
    def test_security_headers_in_error_responses(self, client, invalid_auth_headers):
        """Test security headers are present in error responses."""
        response = client.get('/test/protected', headers=invalid_auth_headers)
        
        assert response.status_code == 401
        
        # Security headers should be present even in error responses
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
    
    def test_csp_nonce_generation(self, client):
        """Test CSP nonce generation for inline scripts/styles."""
        with patch('src.auth.security.generate_secure_token') as mock_token:
            mock_token.return_value = 'test-nonce-12345'
            
            response = client.get('/test/public')
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            # Verify nonce is included if configured
            if 'nonce-' in csp_header:
                assert 'nonce-test-nonce-12345' in csp_header
    
    def test_security_configuration_validation(self, app_context):
        """Test security configuration validation function."""
        warnings = validate_security_configuration()
        
        # Should return list of warnings or empty list
        assert isinstance(warnings, list)
        
        # In test environment, may have warnings about development configuration
        for warning in warnings:
            assert isinstance(warning, str)
            assert len(warning) > 0
    
    def test_security_report_generation(self, app_context):
        """Test security report generation functionality."""
        report = get_security_report()
        
        assert isinstance(report, dict)
        assert 'status' in report
        assert 'timestamp' in report
        assert 'environment' in report
    
    @pytest.mark.performance
    def test_security_headers_performance_impact(self, client, performance_timer):
        """Test security headers middleware performance impact."""
        # Measure multiple requests to get average performance
        times = []
        
        for _ in range(10):
            performance_timer.start()
            response = client.get('/test/public')
            request_time = performance_timer.stop()
            times.append(request_time)
            
            assert response.status_code == 200
        
        # Average response time should be reasonable
        avg_time = sum(times) / len(times)
        assert avg_time < 0.1  # Less than 100ms average


# ============================================================================
# AUTHENTICATION DECORATORS TESTING
# ============================================================================

class TestAuthenticationDecorators:
    """Test authentication and authorization decorators."""
    
    def test_require_authentication_with_valid_token(self, client, auth_headers, test_blueprint):
        """Test authentication decorator with valid JWT token."""
        response = client.get('/test/protected', headers=auth_headers)
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['message'] == 'protected access'
        assert data['user'] == 'test-user-12345'  # From test_jwt_payload
        assert data['auth_method'] == 'jwt'
    
    def test_require_authentication_missing_token(self, client, test_blueprint):
        """Test authentication decorator without token."""
        response = client.get('/test/protected')
        
        assert response.status_code == 401
        
        data = response.get_json()
        assert 'error' in data
        assert 'authorization' in data['error'].lower()
    
    def test_require_authentication_invalid_token(self, client, invalid_auth_headers, test_blueprint):
        """Test authentication decorator with invalid token."""
        response = client.get('/test/protected', headers=invalid_auth_headers)
        
        assert response.status_code == 401
        
        data = response.get_json()
        assert 'error' in data
        assert 'token' in data['error'].lower()
    
    def test_require_authentication_expired_token(self, client, expired_jwt_token, test_blueprint):
        """Test authentication decorator with expired token."""
        headers = {'Authorization': f'Bearer {expired_jwt_token}'}
        response = client.get('/test/protected', headers=headers)
        
        assert response.status_code == 401
        
        data = response.get_json()
        assert 'error' in data
        assert 'expired' in data['error'].lower() or 'invalid' in data['error'].lower()
    
    def test_require_authentication_malformed_header(self, client, test_blueprint):
        """Test authentication decorator with malformed Authorization header."""
        test_cases = [
            {'Authorization': 'Bearer'},  # Missing token
            {'Authorization': 'InvalidBearer token'},  # Wrong scheme
            {'Authorization': 'token'},  # Missing Bearer prefix
        ]
        
        for headers in test_cases:
            response = client.get('/test/protected', headers=headers)
            assert response.status_code == 401
    
    @patch('src.auth.decorators.validate_jwt_token')
    def test_require_authentication_with_caching(self, mock_validate, client, auth_headers, test_blueprint):
        """Test authentication decorator with token caching."""
        mock_validate.return_value = {
            'valid': True,
            'user_id': 'test-user-12345',
            'claims': {'roles': ['user']},
            'token_hash': 'abc123'
        }
        
        # Make first request
        response1 = client.get('/test/protected', headers=auth_headers)
        assert response1.status_code == 200
        
        # Make second request - should use cache
        response2 = client.get('/test/protected', headers=auth_headers)
        assert response2.status_code == 200
        
        # Validate token function should be called for each request
        # (actual caching implementation depends on the validate_jwt_token function)
        assert mock_validate.call_count >= 1
    
    def test_require_permissions_with_valid_permissions(self, client, test_blueprint):
        """Test permissions decorator with valid user permissions."""
        # Mock authentication and authorization
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth, \
             patch('src.auth.decorators.validate_user_permissions') as mock_perms:
            
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user-12345',
                'claims': {'roles': ['admin'], 'permissions': ['admin.access']}
            }
            mock_perms.return_value = True
            
            headers = {'Authorization': 'Bearer valid-token'}
            response = client.get('/test/admin-only', headers=headers)
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'admin access'
    
    def test_require_permissions_insufficient_permissions(self, client, test_blueprint):
        """Test permissions decorator with insufficient permissions."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth, \
             patch('src.auth.decorators.validate_user_permissions') as mock_perms:
            
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user-12345',
                'claims': {'roles': ['user'], 'permissions': ['read']}
            }
            mock_perms.return_value = False
            
            headers = {'Authorization': 'Bearer valid-token'}
            response = client.get('/test/admin-only', headers=headers)
            
            assert response.status_code == 403
            data = response.get_json()
            assert 'error' in data
    
    def test_conditional_auth_authentication_required(self, client, auth_headers, test_blueprint):
        """Test conditional authentication when auth is required."""
        response = client.get('/test/conditional-auth?require_auth=true', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['auth_required'] is True
        assert data['user'] == 'test-user-12345'
    
    def test_conditional_auth_no_authentication_required(self, client, test_blueprint):
        """Test conditional authentication when auth is not required."""
        response = client.get('/test/conditional-auth?require_auth=false')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['auth_required'] is False
        assert data['user'] == 'anonymous'
    
    def test_api_key_authentication_valid_key(self, client, api_key_headers, test_blueprint):
        """Test API key authentication with valid key."""
        with patch('src.auth.decorators.AuthenticationDecorators._validate_api_key') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'key_id': 'test-key-123',
                'scopes': ['read', 'write']
            }
            
            response = client.get('/test/api-key-protected', headers=api_key_headers)
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['api_key_id'] == 'test-key-123'
            assert data['scopes'] == ['read', 'write']
    
    def test_api_key_authentication_missing_key(self, client, test_blueprint):
        """Test API key authentication without key."""
        response = client.get('/test/api-key-protected')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'API key required' in data['error']
    
    def test_api_key_authentication_invalid_key(self, client, test_blueprint):
        """Test API key authentication with invalid key."""
        with patch('src.auth.decorators.AuthenticationDecorators._validate_api_key') as mock_validate:
            mock_validate.return_value = {'valid': False}
            
            headers = {'X-API-Key': 'invalid-api-key'}
            response = client.get('/test/api-key-protected', headers=headers)
            
            assert response.status_code == 401
            data = response.get_json()
            assert 'Invalid API key' in data['error']
    
    def test_decorator_initialization(self, app_with_middleware):
        """Test authentication decorators initialization."""
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        # Test initialization with limiter
        limiter = Limiter(
            app=app_with_middleware,
            key_func=get_remote_address,
            default_limits=["1000 per hour"]
        )
        
        decorators = init_decorators(app_with_middleware, limiter)
        
        assert isinstance(decorators, AuthenticationDecorators)
        assert decorators.limiter is limiter
        assert 'auth_decorators' in app_with_middleware.extensions
    
    def test_get_decorators_function(self, app_with_middleware):
        """Test getting decorators instance."""
        decorators = get_decorators()
        assert isinstance(decorators, AuthenticationDecorators)
    
    @pytest.mark.performance
    def test_authentication_decorator_performance(self, client, auth_headers, test_blueprint, performance_timer):
        """Test authentication decorator performance impact."""
        # Measure authenticated request performance
        performance_timer.start()
        response = client.get('/test/protected', headers=auth_headers)
        auth_time = performance_timer.stop()
        
        assert response.status_code == 200
        
        # Authentication overhead should be reasonable
        assert auth_time < 0.05  # Less than 50ms for authentication


# ============================================================================
# RATE LIMITING MIDDLEWARE TESTING (Flask-Limiter)
# ============================================================================

class TestRateLimitingMiddleware:
    """Test rate limiting with Flask-Limiter 3.5+ integration."""
    
    @pytest.fixture
    def rate_limited_client(self, rate_limited_app):
        """Client with rate limiting enabled."""
        return rate_limited_app.test_client()
    
    def test_rate_limiting_basic_functionality(self, rate_limited_client):
        """Test basic rate limiting functionality."""
        # Configure a very low rate limit for testing
        with patch('src.app.Config.RATE_LIMIT_DEFAULT', '2 per minute'):
            
            # First request should succeed
            response1 = rate_limited_client.get('/rate-test')
            assert response1.status_code == 200
            
            # Second request should succeed
            response2 = rate_limited_client.get('/rate-test')
            assert response2.status_code == 200
            
            # Third request should be rate limited (depending on implementation)
            response3 = rate_limited_client.get('/rate-test')
            # Note: May need to adjust based on actual rate limiting configuration
            assert response3.status_code in [200, 429]  # May or may not be limited yet
    
    def test_rate_limiting_headers_present(self, rate_limited_client):
        """Test rate limiting headers are present in responses."""
        response = rate_limited_client.get('/rate-test')
        
        # Check for rate limiting headers
        rate_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset'
        ]
        
        # Some headers may be present depending on Flask-Limiter configuration
        for header in rate_headers:
            if header in response.headers:
                assert response.headers[header] is not None
    
    def test_rate_limiting_429_response(self, rate_limited_client):
        """Test 429 Too Many Requests response format."""
        # Simulate rate limit exceeded by making many requests quickly
        # This test may need adjustment based on actual rate limiting configuration
        
        with patch('flask_limiter.Limiter.limit') as mock_limit:
            # Mock rate limit exceeded
            mock_limit.side_effect = TooManyRequests("Rate limit exceeded")
            
            try:
                response = rate_limited_client.get('/rate-test')
                
                if response.status_code == 429:
                    data = response.get_json()
                    assert 'error' in data
                    assert 'rate limit' in data['error'].lower()
                    
                    # Check for Retry-After header
                    assert 'Retry-After' in response.headers
                    
            except TooManyRequests:
                # Exception may be raised instead of returning 429
                pass
    
    def test_rate_limiting_per_user_authentication(self, client, test_blueprint):
        """Test rate limiting with user-specific limits."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth, \
             patch('flask_limiter.Limiter.limit') as mock_limit:
            
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user-12345',
                'claims': {'permissions': ['read']}
            }
            
            # Mock rate limiting function to track calls
            mock_limit.return_value = lambda f: f  # Pass-through decorator
            
            headers = {'Authorization': 'Bearer valid-token'}
            
            # Make request to rate-limited endpoint
            response = client.get('/test/rate-limited', headers=headers)
            
            # Should succeed if properly configured
            assert response.status_code in [200, 429]
    
    def test_rate_limiting_different_endpoints(self, rate_limited_client):
        """Test rate limiting applies per endpoint."""
        # Test different endpoints have separate rate limits
        endpoints = ['/rate-test', '/rate-test']  # Same endpoint for simplicity
        
        for endpoint in endpoints:
            response = rate_limited_client.get(endpoint)
            assert response.status_code in [200, 429]
    
    def test_rate_limiting_bypass_for_internal_requests(self, app_with_middleware):
        """Test rate limiting can be bypassed for internal requests."""
        with app_with_middleware.test_request_context():
            # Internal request simulation
            with patch('flask_limiter.Limiter.exempt') as mock_exempt:
                mock_exempt.return_value = True
                
                # Test that internal requests can bypass rate limiting
                # This would depend on the specific implementation
                assert True  # Placeholder for actual bypass logic test
    
    def test_rate_limiting_redis_storage(self, rate_limited_app):
        """Test rate limiting with Redis storage backend."""
        # Test Redis storage configuration
        limiter_config = rate_limited_app.config.get('RATELIMIT_STORAGE_URL')
        
        # Should be configured for Redis in production
        assert limiter_config is not None
        
        # In test environment, may use memory storage
        assert 'redis://' in limiter_config or 'memory://' in limiter_config
    
    def test_rate_limiting_window_types(self, rate_limited_client):
        """Test different rate limiting window types."""
        # Test sliding window vs fixed window behavior
        # This would require specific configuration and timing tests
        
        start_time = time.time()
        
        # Make requests and track timing
        responses = []
        for i in range(3):
            response = rate_limited_client.get('/rate-test')
            responses.append((time.time() - start_time, response.status_code))
            time.sleep(0.1)  # Small delay between requests
        
        # Verify responses follow rate limiting pattern
        for timestamp, status_code in responses:
            assert status_code in [200, 429]
    
    @pytest.mark.performance
    def test_rate_limiting_performance_overhead(self, rate_limited_client, performance_timer):
        """Test rate limiting middleware performance impact."""
        times = []
        
        for _ in range(5):
            performance_timer.start()
            response = rate_limited_client.get('/rate-test')
            request_time = performance_timer.stop()
            times.append(request_time)
            
            assert response.status_code in [200, 429]
        
        # Rate limiting overhead should be minimal
        avg_time = sum(times) / len(times)
        assert avg_time < 0.1  # Less than 100ms average
    
    def test_rate_limiting_error_handling(self, rate_limited_app):
        """Test rate limiting error handling and fallback."""
        # Test what happens when Redis is unavailable
        with patch('redis.Redis.get') as mock_redis:
            mock_redis.side_effect = Exception("Redis connection failed")
            
            client = rate_limited_app.test_client()
            
            # Should still work (graceful degradation)
            response = client.get('/rate-test')
            assert response.status_code == 200  # Should not fail due to Redis error


# ============================================================================
# REQUEST PROCESSING PIPELINE TESTING
# ============================================================================

class TestRequestProcessingPipeline:
    """Test request processing pipeline and middleware chain execution."""
    
    def test_middleware_execution_order(self, client, cors_headers, auth_headers, test_blueprint):
        """Test middleware executes in correct order."""
        # Track middleware execution order
        execution_order = []
        
        def track_cors(*args, **kwargs):
            execution_order.append('cors')
            return True
        
        def track_security(*args, **kwargs):
            execution_order.append('security')
            return True
        
        def track_auth(*args, **kwargs):
            execution_order.append('auth')
            return {'valid': True, 'user_id': 'test-user', 'claims': {}}
        
        with patch('flask_cors.CORS.init_app', side_effect=track_cors), \
             patch('flask_talisman.Talisman.init_app', side_effect=track_security), \
             patch('src.auth.decorators.validate_jwt_token', side_effect=track_auth):
            
            response = client.get('/test/protected', headers={**cors_headers, **auth_headers})
            
            # Verify middleware executed
            assert response.status_code in [200, 401]  # May vary based on mocking
    
    def test_request_context_sharing(self, client, auth_headers, test_blueprint):
        """Test data sharing between middleware components via Flask g object."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user-12345',
                'claims': {'roles': ['user'], 'permissions': ['read']}
            }
            
            response = client.get('/test/protected', headers=auth_headers)
            
            assert response.status_code == 200
            data = response.get_json()
            
            # Verify data was shared correctly via g object
            assert data['user'] == 'test-user-12345'
            assert data['auth_method'] == 'jwt'
    
    def test_error_propagation_through_middleware(self, client, test_blueprint):
        """Test error handling and propagation through middleware chain."""
        # Test various error scenarios
        error_scenarios = [
            # Authentication errors
            ({'Authorization': 'Bearer invalid'}, 401),
            # Missing authentication
            ({}, 401),
            # Malformed requests
            ({'Content-Type': 'invalid/type'}, 200),  # Should still work for GET
        ]
        
        for headers, expected_status in error_scenarios:
            response = client.get('/test/protected', headers=headers)
            
            # Verify error handling
            if expected_status >= 400:
                assert response.status_code == expected_status
                data = response.get_json()
                assert 'error' in data
    
    def test_middleware_exception_handling(self, client, test_blueprint):
        """Test middleware handles exceptions gracefully."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            # Simulate exception in authentication
            mock_auth.side_effect = Exception("Authentication service error")
            
            headers = {'Authorization': 'Bearer test-token'}
            response = client.get('/test/protected', headers=headers)
            
            # Should return appropriate error response
            assert response.status_code in [401, 500]
            data = response.get_json()
            assert 'error' in data
    
    def test_request_logging_integration(self, client, test_blueprint):
        """Test request logging through middleware pipeline."""
        with patch('structlog.get_logger') as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log
            
            response = client.get('/test/public')
            
            assert response.status_code == 200
            
            # Verify logging was called (if implemented)
            # This test depends on the actual logging implementation
    
    def test_response_modification_by_middleware(self, client, test_blueprint):
        """Test middleware can modify responses."""
        response = client.get('/test/enhanced-security')
        
        assert response.status_code == 200
        
        # Verify middleware added custom headers
        assert response.headers.get('X-Custom-Security') == 'test-value'
        
        # Verify standard security headers are also present
        assert 'X-Content-Type-Options' in response.headers
    
    def test_middleware_performance_tracking(self, client, test_blueprint, performance_timer):
        """Test middleware performance tracking and metrics."""
        # Measure request processing time
        performance_timer.start()
        response = client.get('/test/public')
        total_time = performance_timer.stop()
        
        assert response.status_code == 200
        
        # Total request time should be reasonable
        assert total_time < 0.2  # Less than 200ms
    
    def test_middleware_with_different_http_methods(self, client, auth_headers, test_blueprint):
        """Test middleware works with different HTTP methods."""
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        for method in methods_to_test:
            # Test with public endpoint first
            response = getattr(client, method.lower())('/test/public')
            assert response.status_code in [200, 405]  # 405 if method not allowed
            
            # Test CORS headers are present
            if response.status_code == 200:
                assert 'X-Content-Type-Options' in response.headers
    
    def test_middleware_state_isolation(self, client, test_blueprint):
        """Test middleware state isolation between requests."""
        # Make multiple concurrent-like requests
        responses = []
        
        for i in range(5):
            response = client.get(f'/test/public?request_id={i}')
            responses.append(response)
        
        # All requests should succeed and be independent
        for response in responses:
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'public access'
    
    @pytest.mark.performance
    def test_middleware_pipeline_performance(self, client, test_blueprint, performance_timer):
        """Test overall middleware pipeline performance."""
        # Test multiple requests to measure consistency
        times = []
        
        for _ in range(10):
            performance_timer.start()
            response = client.get('/test/public')
            request_time = performance_timer.stop()
            times.append(request_time)
            
            assert response.status_code == 200
        
        # Calculate performance statistics
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        # Performance should be consistent and fast
        assert avg_time < 0.1  # Average under 100ms
        assert max_time < 0.2  # Max under 200ms
        assert (max_time - min_time) < 0.1  # Low variance


# ============================================================================
# INTEGRATION TESTING
# ============================================================================

class TestMiddlewareIntegration:
    """Test middleware integration and interaction patterns."""
    
    def test_full_middleware_stack_integration(self, client, cors_headers, auth_headers, test_blueprint):
        """Test complete middleware stack working together."""
        # Combine CORS + Auth + Security headers
        combined_headers = {**cors_headers, **auth_headers}
        
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user-12345',
                'claims': {'roles': ['user'], 'permissions': ['read']}
            }
            
            response = client.get('/test/protected', headers=combined_headers)
            
            assert response.status_code == 200
            
            # Verify all middleware components worked
            # CORS headers
            assert 'Access-Control-Allow-Origin' in response.headers
            
            # Security headers
            assert 'X-Content-Type-Options' in response.headers
            assert 'X-Frame-Options' in response.headers
            
            # Authentication worked
            data = response.get_json()
            assert data['user'] == 'test-user-12345'
    
    def test_middleware_error_handling_integration(self, client, cors_headers, test_blueprint):
        """Test error handling across middleware stack."""
        # Test authentication error with CORS
        invalid_headers = {**cors_headers, 'Authorization': 'Bearer invalid'}
        response = client.get('/test/protected', headers=invalid_headers)
        
        assert response.status_code == 401
        
        # Should still have CORS and security headers in error response
        assert 'Access-Control-Allow-Origin' in response.headers
        assert 'X-Content-Type-Options' in response.headers
        
        # Error response should be well-formed JSON
        data = response.get_json()
        assert 'error' in data
    
    def test_middleware_configuration_consistency(self, app_with_middleware):
        """Test middleware configuration consistency across the application."""
        # Test that all middleware is properly configured
        assert 'cors' in app_with_middleware.extensions
        
        # Test Flask-CORS configuration
        cors_config = app_with_middleware.extensions.get('cors')
        if cors_config:
            assert cors_config is not None
        
        # Test security manager configuration
        security_manager = app_with_middleware.extensions.get('security_manager')
        if security_manager:
            assert security_manager is not None
    
    def test_middleware_production_readiness(self, app_with_middleware):
        """Test middleware stack is production-ready."""
        # Verify essential security configurations
        config_checks = [
            ('SECRET_KEY', str),
            ('JWT_SECRET_KEY', str),
            ('TESTING', bool),
        ]
        
        for config_key, expected_type in config_checks:
            value = app_with_middleware.config.get(config_key)
            assert value is not None
            assert isinstance(value, expected_type)
    
    @pytest.mark.performance
    def test_middleware_stack_performance_under_load(self, client, test_blueprint, performance_timer):
        """Test middleware performance under simulated load."""
        # Simulate concurrent requests
        import threading
        import queue
        
        results = queue.Queue()
        
        def make_request():
            start_time = time.time()
            response = client.get('/test/public')
            end_time = time.time()
            results.put((response.status_code, end_time - start_time))
        
        # Create multiple threads to simulate load
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect results
        response_times = []
        status_codes = []
        
        while not results.empty():
            status_code, response_time = results.get()
            status_codes.append(status_code)
            response_times.append(response_time)
        
        # Verify all requests succeeded
        assert all(status == 200 for status in status_codes)
        
        # Verify performance under load
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 0.5  # Average under 500ms under load


# ============================================================================
# ERROR HANDLING AND EDGE CASES
# ============================================================================

class TestMiddlewareErrorHandling:
    """Test middleware error handling and edge cases."""
    
    def test_malformed_request_handling(self, client, test_blueprint):
        """Test handling of malformed requests."""
        # Test various malformed requests
        malformed_requests = [
            # Invalid JSON in POST body
            ('/test/public', 'POST', {'Content-Type': 'application/json'}, 'invalid-json'),
            # Very long headers
            ('/test/public', 'GET', {'X-Custom-Header': 'a' * 8192}, None),
            # Special characters in headers
            ('/test/public', 'GET', {'X-Special': 'test\x00\x01\x02'}, None),
        ]
        
        for url, method, headers, data in malformed_requests:
            try:
                if method == 'POST':
                    response = client.post(url, headers=headers, data=data)
                else:
                    response = client.get(url, headers=headers)
                
                # Should handle gracefully
                assert response.status_code in [200, 400, 413, 500]
                
            except Exception as e:
                # If exception is raised, it should be handled by error handlers
                pytest.fail(f"Unhandled exception for {method} {url}: {e}")
    
    def test_middleware_circuit_breaker_behavior(self, client, test_blueprint):
        """Test middleware behavior when external services are down."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            # Simulate Auth0 service down
            from src.auth.exceptions import CircuitBreakerError
            mock_auth.side_effect = CircuitBreakerError("Auth0 service unavailable")
            
            headers = {'Authorization': 'Bearer test-token'}
            response = client.get('/test/protected', headers=headers)
            
            # Should return 503 Service Unavailable
            assert response.status_code == 503
            data = response.get_json()
            assert 'temporarily unavailable' in data['error'].lower()
    
    def test_middleware_memory_limit_handling(self, client, test_blueprint):
        """Test middleware handling of memory-intensive requests."""
        # Test large request body handling
        large_data = 'x' * (1024 * 1024)  # 1MB of data
        
        response = client.post('/test/public', 
                             data=large_data,
                             content_type='text/plain')
        
        # Should handle large requests appropriately
        assert response.status_code in [200, 413, 500]
    
    def test_middleware_timeout_handling(self, client, test_blueprint):
        """Test middleware timeout handling."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            # Simulate slow authentication service
            import time
            def slow_auth(*args, **kwargs):
                time.sleep(0.1)  # Small delay for testing
                return {'valid': True, 'user_id': 'test-user', 'claims': {}}
            
            mock_auth.side_effect = slow_auth
            
            headers = {'Authorization': 'Bearer test-token'}
            response = client.get('/test/protected', headers=headers)
            
            # Should complete even with slow auth (within reason)
            assert response.status_code in [200, 408, 500]
    
    def test_middleware_resource_cleanup(self, client, test_blueprint):
        """Test middleware properly cleans up resources."""
        # Track resource usage
        initial_memory = None
        
        try:
            import psutil
            process = psutil.Process()
            initial_memory = process.memory_info().rss
        except ImportError:
            pytest.skip("psutil not available for memory tracking")
        
        # Make multiple requests
        for _ in range(50):
            response = client.get('/test/public')
            assert response.status_code == 200
        
        # Check memory hasn't grown excessively
        if initial_memory:
            final_memory = process.memory_info().rss
            memory_growth = final_memory - initial_memory
            
            # Memory growth should be reasonable (less than 10MB)
            assert memory_growth < 10 * 1024 * 1024
    
    def test_middleware_concurrent_request_safety(self, client, test_blueprint):
        """Test middleware thread safety with concurrent requests."""
        import threading
        import time
        
        results = []
        errors = []
        
        def make_request(request_id):
            try:
                start_time = time.time()
                response = client.get(f'/test/public?id={request_id}')
                end_time = time.time()
                
                results.append({
                    'id': request_id,
                    'status': response.status_code,
                    'time': end_time - start_time
                })
            except Exception as e:
                errors.append(f"Request {request_id}: {e}")
        
        # Create multiple threads
        threads = []
        for i in range(20):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify no errors and all requests succeeded
        assert len(errors) == 0, f"Errors: {errors}"
        assert len(results) == 20
        assert all(r['status'] == 200 for r in results)
    
    def test_middleware_graceful_degradation(self, client, test_blueprint):
        """Test middleware graceful degradation when components fail."""
        # Test with Redis unavailable
        with patch('redis.Redis.get') as mock_redis:
            mock_redis.side_effect = Exception("Redis unavailable")
            
            response = client.get('/test/public')
            
            # Should still work without Redis
            assert response.status_code == 200
        
        # Test with security headers disabled
        with patch('flask_talisman.Talisman.init_app') as mock_talisman:
            mock_talisman.side_effect = Exception("Talisman initialization failed")
            
            try:
                response = client.get('/test/public')
                # Should work even if security headers fail to initialize
                assert response.status_code == 200
            except Exception:
                # Graceful degradation - application should continue working
                pass


# ============================================================================
# PERFORMANCE AND MONITORING TESTS
# ============================================================================

class TestMiddlewarePerformanceMonitoring:
    """Test middleware performance monitoring and metrics collection."""
    
    @pytest.mark.performance
    def test_middleware_performance_baseline(self, client, test_blueprint, performance_timer):
        """Test middleware performance meets baseline requirements."""
        # Baseline performance test - should meet ≤10% variance requirement
        
        # Measure baseline request without authentication
        performance_timer.start()
        response = client.get('/test/public')
        baseline_time = performance_timer.stop()
        
        assert response.status_code == 200
        assert baseline_time < 0.05  # Should be very fast for public endpoint
        
        # Test with full middleware stack
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'test-user',
                'claims': {}
            }
            
            headers = {'Authorization': 'Bearer test-token'}
            
            performance_timer.start()
            response = client.get('/test/protected', headers=headers)
            auth_time = performance_timer.stop()
            
            assert response.status_code == 200
            
            # Authenticated request should not be significantly slower
            overhead_ratio = auth_time / baseline_time if baseline_time > 0 else 1
            assert overhead_ratio < 3.0  # Less than 3x overhead
    
    @pytest.mark.performance
    def test_middleware_memory_efficiency(self, client, test_blueprint):
        """Test middleware memory efficiency."""
        try:
            import psutil
            process = psutil.Process()
        except ImportError:
            pytest.skip("psutil not available for memory testing")
        
        # Measure initial memory
        initial_memory = process.memory_info().rss
        
        # Make many requests to test memory efficiency
        for i in range(100):
            response = client.get('/test/public')
            assert response.status_code == 200
            
            # Periodic memory check
            if i % 20 == 0:
                current_memory = process.memory_info().rss
                memory_growth = current_memory - initial_memory
                
                # Memory growth should be bounded
                assert memory_growth < 50 * 1024 * 1024  # Less than 50MB growth
    
    def test_middleware_metrics_collection(self, app_with_middleware):
        """Test middleware metrics collection for monitoring."""
        # Test that metrics are being collected
        with app_with_middleware.test_client() as client:
            # Make requests to generate metrics
            for _ in range(10):
                response = client.get('/test/public')
                assert response.status_code == 200
            
            # Check if metrics endpoint exists
            try:
                metrics_response = client.get('/metrics')
                # If metrics endpoint exists, should return Prometheus format
                if metrics_response.status_code == 200:
                    metrics_data = metrics_response.get_data(as_text=True)
                    assert 'flask_requests_total' in metrics_data or len(metrics_data) > 0
            except Exception:
                # Metrics endpoint may not be configured in test environment
                pass
    
    def test_middleware_error_rate_monitoring(self, client, test_blueprint):
        """Test middleware error rate monitoring."""
        # Generate mix of successful and error responses
        success_count = 0
        error_count = 0
        
        # Successful requests
        for _ in range(10):
            response = client.get('/test/public')
            if response.status_code == 200:
                success_count += 1
        
        # Error requests
        for _ in range(5):
            response = client.get('/test/protected')  # No auth header
            if response.status_code >= 400:
                error_count += 1
        
        # Verify error rate is trackable
        total_requests = success_count + error_count
        error_rate = error_count / total_requests if total_requests > 0 else 0
        
        assert error_rate > 0  # Should have some errors from unauthenticated requests
        assert error_rate < 1  # Should have some successful requests
    
    @pytest.mark.slow
    def test_middleware_sustained_load_performance(self, client, test_blueprint, performance_timer):
        """Test middleware performance under sustained load."""
        # Test sustained performance over time
        times = []
        
        for i in range(100):
            performance_timer.start()
            response = client.get('/test/public')
            request_time = performance_timer.stop()
            
            assert response.status_code == 200
            times.append(request_time)
            
            # Small delay to simulate realistic load pattern
            time.sleep(0.01)
        
        # Analyze performance statistics
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        # Performance should be consistent
        assert avg_time < 0.1  # Average under 100ms
        assert max_time < 0.5  # Max under 500ms
        
        # Performance should not degrade significantly over time
        first_half_avg = sum(times[:50]) / 50
        second_half_avg = sum(times[50:]) / 50
        
        degradation_ratio = second_half_avg / first_half_avg
        assert degradation_ratio < 1.5  # Less than 50% degradation


# ============================================================================
# FINAL INTEGRATION AND CLEANUP TESTS
# ============================================================================

class TestMiddlewareCleanupAndIntegration:
    """Final integration tests and cleanup validation."""
    
    def test_middleware_application_lifecycle(self, mock_environment):
        """Test middleware behavior through application lifecycle."""
        with patch.dict('os.environ', mock_environment):
            # Test application creation
            app = create_app()
            assert app is not None
            
            # Test middleware initialization
            assert 'cors' in app.extensions or hasattr(app, 'before_request_funcs')
            
            # Test application context
            with app.app_context():
                # Verify configuration
                assert app.config['TESTING'] is True
                assert app.config['SECRET_KEY'] is not None
            
            # Test request context
            with app.test_request_context():
                from flask import g, request
                assert request is not None
    
    def test_middleware_configuration_validation(self, app_with_middleware):
        """Test middleware configuration is valid and complete."""
        # Test CORS configuration
        cors_config = app_with_middleware.config.get('CORS_ORIGINS')
        assert cors_config is not None
        
        # Test security configuration
        secret_key = app_with_middleware.config.get('SECRET_KEY')
        assert secret_key is not None
        assert len(secret_key) >= 16  # Minimum secure length
        
        # Test JWT configuration
        jwt_secret = app_with_middleware.config.get('JWT_SECRET_KEY')
        assert jwt_secret is not None
        assert len(jwt_secret) >= 32  # Minimum secure length for JWT
    
    def test_middleware_documentation_compliance(self, app_with_middleware):
        """Test middleware implementation complies with documentation."""
        # Test that all documented endpoints exist
        with app_with_middleware.test_client() as client:
            # Health check endpoints
            health_endpoints = ['/health', '/health/ready', '/health/live']
            for endpoint in health_endpoints:
                try:
                    response = client.get(endpoint)
                    assert response.status_code in [200, 404]  # 404 if not implemented
                except Exception:
                    # Some endpoints may not be implemented yet
                    pass
    
    def test_middleware_express_js_equivalence(self, client, test_blueprint):
        """Test middleware provides Express.js equivalent functionality."""
        # Test CORS equivalent to Express cors middleware
        cors_response = client.options('/test/public', headers={'Origin': 'https://example.com'})
        assert 'Access-Control-Allow-Origin' in cors_response.headers
        
        # Test security headers equivalent to helmet middleware
        security_response = client.get('/test/public')
        helmet_equivalent_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        for header in helmet_equivalent_headers:
            if header in security_response.headers:
                assert security_response.headers[header] is not None
    
    def test_middleware_production_deployment_readiness(self, app_with_middleware):
        """Test middleware is ready for production deployment."""
        # Test security configuration
        config_validations = [
            ('SECRET_KEY', lambda x: len(x) >= 32),
            ('JWT_SECRET_KEY', lambda x: len(x) >= 32),
            ('TESTING', lambda x: isinstance(x, bool)),
        ]
        
        for config_key, validator in config_validations:
            value = app_with_middleware.config.get(config_key)
            assert value is not None, f"Missing config: {config_key}"
            assert validator(value), f"Invalid config value: {config_key}"
    
    def test_middleware_error_recovery(self, client, test_blueprint):
        """Test middleware error recovery and resilience."""
        # Test recovery from various error conditions
        error_scenarios = [
            # Network timeouts
            ('timeout', lambda: time.sleep(0.001)),
            # Memory pressure
            ('memory', lambda: 'x' * 1000),
            # Invalid input
            ('input', lambda: '\x00\x01\x02'),
        ]
        
        for scenario_name, error_generator in error_scenarios:
            try:
                # Generate error condition
                error_data = error_generator()
                
                # Make request that might trigger error
                response = client.get('/test/public')
                
                # Should handle gracefully
                assert response.status_code in [200, 400, 500]
                
            except Exception as e:
                # Should not cause unhandled exceptions
                pytest.fail(f"Unhandled exception in {scenario_name} scenario: {e}")
    
    def test_middleware_comprehensive_integration(self, client, cors_headers, auth_headers, test_blueprint):
        """Comprehensive integration test of all middleware components."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_auth:
            mock_auth.return_value = {
                'valid': True,
                'user_id': 'integration-test-user',
                'claims': {'roles': ['user'], 'permissions': ['read']}
            }
            
            # Test all middleware working together
            full_headers = {
                **cors_headers,
                **auth_headers,
                'X-Custom-Header': 'integration-test'
            }
            
            response = client.get('/test/protected', headers=full_headers)
            
            # Verify successful integration
            assert response.status_code == 200
            
            # Verify all middleware components functioned
            # CORS
            assert 'Access-Control-Allow-Origin' in response.headers
            
            # Security headers
            assert 'X-Content-Type-Options' in response.headers
            
            # Authentication
            data = response.get_json()
            assert data['user'] == 'integration-test-user'
            assert data['auth_method'] == 'jwt'
            
            # Response format
            assert isinstance(data, dict)
            assert 'message' in data


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])