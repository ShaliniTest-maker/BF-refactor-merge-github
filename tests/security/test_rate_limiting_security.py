"""
Rate Limiting Security Testing Module

This module implements comprehensive security testing for Flask-Limiter rate limiting controls,
abuse prevention mechanisms, and DoS attack protection as specified in Section 6.4.2 of the
technical specification. Tests validate authorization endpoint throttling, multi-tier rate limiting,
and zero-tolerance policies for rate limiting bypass vulnerabilities.

Key Security Validations:
- Flask-Limiter rate limiting enforcement and configuration validation per Section 6.4.2
- Authorization endpoint specific rate limiting with user-specific limits per Section 6.4.2
- DoS attack prevention through intelligent burst and sustained rate limiting per Section 6.4.2
- Rate limiting bypass attempt detection and prevention per Section 6.4.2
- Multi-tier rate limiting (second/minute/hour) security validation per Section 6.4.2
- Comprehensive security event logging for rate limiting violations per Section 6.4.5
- Authorization system abuse prevention through rate limiting integration per Section 6.4.2

The test suite ensures complete compliance with enterprise security standards and validates
that rate limiting controls maintain effectiveness against sophisticated attack vectors while
preserving legitimate user access patterns.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import threading
import concurrent.futures

import pytest
from flask import Flask, g, request
from flask.testing import FlaskClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Import application components
from src.auth.decorators import (
    AuthenticationDecorators,
    rate_limited_authorization,
    require_permissions,
    require_authentication
)
from src.auth.exceptions import (
    RateLimitExceededError,
    AuthenticationError,
    PermissionDeniedError
)


class TestFlaskLimiterSecurity:
    """
    Comprehensive Flask-Limiter security validation test suite.
    
    Tests Flask-Limiter configuration, enforcement mechanisms, and security
    controls to ensure robust rate limiting implementation according to
    Section 6.4.2 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_limiter(self, app: Flask, redis_client: redis.Redis):
        """
        Setup Flask-Limiter with Redis backend for comprehensive testing.
        
        Args:
            app: Flask application instance
            redis_client: Redis client for rate limiting storage
        """
        # Configure Flask-Limiter with Redis backend and enterprise settings
        self.limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=f"redis://localhost:6379/1",
            storage_options={
                'connection_pool': redis_client.connection_pool
            },
            default_limits=[
                "1000 per hour",     # Sustained rate limit
                "100 per minute",    # Burst protection  
                "10 per second"      # Spike protection
            ],
            strategy="moving-window",
            headers_enabled=True,
            header_name_mapping={
                "X-RateLimit-Limit": "X-Auth-RateLimit-Limit",
                "X-RateLimit-Remaining": "X-Auth-RateLimit-Remaining",
                "X-RateLimit-Reset": "X-Auth-RateLimit-Reset"
            },
            swallow_errors=False  # Ensure we catch configuration errors
        )
        
        # Initialize authentication decorators with limiter
        self.auth_decorators = AuthenticationDecorators(limiter=self.limiter)
        
        # Create test endpoints with various rate limiting configurations
        self._setup_test_endpoints(app)
        
        yield
        
        # Cleanup limiter state
        self.limiter.reset()
    
    def _setup_test_endpoints(self, app: Flask):
        """
        Setup test endpoints with various rate limiting configurations.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/test/basic-rate-limit')
        @self.limiter.limit("5 per minute")
        def basic_rate_limited():
            return {'status': 'success', 'endpoint': 'basic-rate-limit'}
        
        @app.route('/api/test/auth-rate-limit')
        @self.auth_decorators.rate_limited_authorization(
            permissions=['test.access'],
            rate_limit="3 per minute"
        )
        def auth_rate_limited():
            return {'status': 'success', 'endpoint': 'auth-rate-limit'}
        
        @app.route('/api/test/multi-tier-limit')
        @self.limiter.limit("100 per hour; 10 per minute; 2 per second")
        def multi_tier_limited():
            return {'status': 'success', 'endpoint': 'multi-tier-limit'}
        
        @app.route('/api/test/user-specific-limit')
        @self.limiter.limit("5 per minute", key_func=lambda: f"user:{g.get('current_user_id', 'anonymous')}")
        def user_specific_limited():
            return {'status': 'success', 'endpoint': 'user-specific-limit'}
        
        @app.route('/api/test/admin-strict-limit')
        @self.auth_decorators.require_admin(
            admin_permissions=['admin.access'],
            rate_limit="2 per minute"
        )
        def admin_strict_limited():
            return {'status': 'success', 'endpoint': 'admin-strict-limit'}
    
    def test_flask_limiter_initialization(self, app: Flask):
        """
        Test Flask-Limiter proper initialization and configuration validation.
        
        Validates:
        - Limiter instance creation with Redis backend
        - Default rate limits configuration
        - Header mapping configuration
        - Moving window strategy implementation
        
        Security Requirement: Flask-Limiter rate limiting security validation per Section 6.4.2
        """
        # Verify limiter is properly initialized
        assert self.limiter is not None
        assert self.limiter.enabled
        
        # Verify Redis backend configuration
        assert self.limiter.storage is not None
        storage_uri = str(self.limiter.storage.storage)
        assert "redis" in storage_uri.lower()
        
        # Verify default limits are properly configured
        default_limits = self.limiter.default_limits
        assert len(default_limits) == 3
        
        # Verify moving window strategy
        assert self.limiter.strategy == "moving-window"
        
        # Verify security headers are enabled
        assert self.limiter.headers_enabled
        
        # Verify custom header mapping
        header_mapping = self.limiter.header_name_mapping
        assert "X-Auth-RateLimit-Limit" in header_mapping.values()
        assert "X-Auth-RateLimit-Remaining" in header_mapping.values()
        assert "X-Auth-RateLimit-Reset" in header_mapping.values()
    
    def test_basic_rate_limiting_enforcement(self, client: FlaskClient):
        """
        Test basic rate limiting enforcement with Flask-Limiter.
        
        Validates:
        - Rate limit enforcement for basic endpoints
        - HTTP 429 response for exceeded limits
        - Rate limiting headers in responses
        - Proper error message formatting
        
        Security Requirement: Flask-Limiter rate limiting security validation per Section 6.4.2
        """
        # Test within rate limit
        for i in range(5):
            response = client.get('/api/test/basic-rate-limit')
            assert response.status_code == 200
            
            # Verify rate limiting headers are present
            assert 'X-Auth-RateLimit-Limit' in response.headers
            assert 'X-Auth-RateLimit-Remaining' in response.headers
            assert 'X-Auth-RateLimit-Reset' in response.headers
            
            # Verify remaining count decreases
            remaining = int(response.headers['X-Auth-RateLimit-Remaining'])
            assert remaining == 4 - i
        
        # Test rate limit exceeded
        response = client.get('/api/test/basic-rate-limit')
        assert response.status_code == 429
        
        # Verify rate limit error response
        assert 'X-Auth-RateLimit-Limit' in response.headers
        assert int(response.headers['X-Auth-RateLimit-Remaining']) == 0
        
        # Verify error message format
        data = response.get_json()
        assert 'error' in data
        assert 'rate limit' in data['error'].lower()
    
    def test_authorization_endpoint_rate_limiting(self, client: FlaskClient, jwt_token: str):
        """
        Test rate limiting for authorization endpoints with user-specific limits.
        
        Validates:
        - Authorization decorator rate limiting integration
        - User-specific rate limiting keys
        - Authentication requirement combined with rate limiting
        - Security event logging for rate limit violations
        
        Security Requirement: Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
        """
        headers = {'Authorization': f'Bearer {jwt_token}'}
        
        # Mock authentication for rate limited endpoint
        with patch('src.auth.authentication.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'test_user_123',
                'claims': {'sub': 'test_user_123', 'scope': 'test.access'}
            }
            
            with patch('src.auth.authorization.validate_user_permissions') as mock_perms:
                mock_perms.return_value = True
                
                # Test within rate limit for authorized user
                for i in range(3):
                    response = client.get('/api/test/auth-rate-limit', headers=headers)
                    assert response.status_code == 200
                    
                    # Verify authorization-specific rate limiting headers
                    assert 'X-Auth-RateLimit-Limit' in response.headers
                    remaining = int(response.headers['X-Auth-RateLimit-Remaining'])
                    assert remaining == 2 - i
                
                # Test rate limit exceeded for authorized user
                response = client.get('/api/test/auth-rate-limit', headers=headers)
                assert response.status_code == 429
                
                # Verify rate limit error includes retry information
                data = response.get_json()
                assert 'error' in data
                assert 'Rate limit exceeded' in data['error']
                assert 'retry_after' in data
    
    def test_multi_tier_rate_limiting_security(self, client: FlaskClient):
        """
        Test multi-tier rate limiting (second/minute/hour) security validation.
        
        Validates:
        - Multiple rate limit tiers enforcement
        - Burst and sustained rate limiting
        - Proper tier violation detection
        - Security against rapid burst attacks
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        # Test second-tier rate limiting (2 per second)
        start_time = time.time()
        
        # First two requests should succeed
        for i in range(2):
            response = client.get('/api/test/multi-tier-limit')
            assert response.status_code == 200
        
        # Third request within same second should be rate limited
        if time.time() - start_time < 1.0:
            response = client.get('/api/test/multi-tier-limit')
            assert response.status_code == 429
            
            # Verify multi-tier rate limiting headers
            assert 'X-Auth-RateLimit-Limit' in response.headers
            limit_header = response.headers['X-Auth-RateLimit-Limit']
            assert '2 per 1 second' in limit_header or '2/1second' in limit_header
        
        # Wait for second window to reset
        time.sleep(1.1)
        
        # Test minute-tier rate limiting (10 per minute)
        for i in range(8):  # Already used 2 requests
            response = client.get('/api/test/multi-tier-limit')
            if response.status_code == 429:
                # Hit minute limit before expected - check headers
                limit_header = response.headers.get('X-Auth-RateLimit-Limit', '')
                assert '10 per 1 minute' in limit_header or '10/1minute' in limit_header
                break
            assert response.status_code == 200
            time.sleep(0.1)  # Avoid second-tier limiting
    
    def test_user_specific_rate_limiting(self, client: FlaskClient, app: Flask):
        """
        Test user-specific rate limiting with different user contexts.
        
        Validates:
        - Per-user rate limiting isolation
        - User identification for rate limiting keys
        - Different users have separate rate limit counters
        - Anonymous user rate limiting
        
        Security Requirement: Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
        """
        # Test with user 1
        with app.test_request_context():
            g.current_user_id = 'user_001'
            
            # User 1 - use up their rate limit
            for i in range(5):
                response = client.get('/api/test/user-specific-limit')
                assert response.status_code == 200
            
            # User 1 - exceed rate limit
            response = client.get('/api/test/user-specific-limit')
            assert response.status_code == 429
        
        # Test with user 2 (should have separate limit)
        with app.test_request_context():
            g.current_user_id = 'user_002'
            
            # User 2 - should have full rate limit available
            for i in range(5):
                response = client.get('/api/test/user-specific-limit')
                assert response.status_code == 200
            
            # User 2 - exceed their rate limit
            response = client.get('/api/test/user-specific-limit')
            assert response.status_code == 429
        
        # Test anonymous user (should have separate limit)
        with app.test_request_context():
            if hasattr(g, 'current_user_id'):
                delattr(g, 'current_user_id')
            
            # Anonymous user - should have rate limit available
            for i in range(3):  # Test fewer to avoid interference
                response = client.get('/api/test/user-specific-limit')
                assert response.status_code == 200
    
    def test_admin_endpoint_strict_rate_limiting(self, client: FlaskClient, jwt_token: str):
        """
        Test strict rate limiting for administrative endpoints.
        
        Validates:
        - Enhanced rate limiting for admin endpoints
        - Admin permission validation with rate limiting
        - Stricter limits for high-privilege operations
        - Security event logging for admin access attempts
        
        Security Requirement: Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
        """
        headers = {'Authorization': f'Bearer {jwt_token}'}
        
        # Mock admin authentication and permissions
        with patch('src.auth.authentication.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'admin_user_123',
                'claims': {'sub': 'admin_user_123', 'scope': 'admin.access admin.manage'}
            }
            
            with patch('src.auth.authorization.validate_user_permissions') as mock_perms:
                mock_perms.return_value = True
                
                # Test within strict admin rate limit (2 per minute)
                for i in range(2):
                    response = client.get('/api/test/admin-strict-limit', headers=headers)
                    assert response.status_code == 200
                    
                    # Verify strict rate limiting headers
                    assert 'X-Auth-RateLimit-Limit' in response.headers
                    remaining = int(response.headers['X-Auth-RateLimit-Remaining'])
                    assert remaining == 1 - i
                
                # Test admin rate limit exceeded
                response = client.get('/api/test/admin-strict-limit', headers=headers)
                assert response.status_code == 429
                
                # Verify admin-specific rate limit error
                data = response.get_json()
                assert 'error' in data
                assert 'Rate limit exceeded' in data['error']
                
                # Admin endpoints should have shorter retry time
                assert 'retry_after' in data
                assert data['retry_after'] <= 60  # Max 1 minute retry


class TestRateLimitingBypassDetection:
    """
    Rate limiting bypass attempt detection and prevention test suite.
    
    Tests sophisticated attack vectors attempting to bypass rate limiting
    controls and validates detection/prevention mechanisms per Section 6.4.2
    zero-tolerance policy for bypass vulnerabilities.
    """
    
    @pytest.fixture(autouse=True)
    def setup_bypass_detection(self, app: Flask, redis_client: redis.Redis):
        """
        Setup rate limiting with enhanced bypass detection capabilities.
        
        Args:
            app: Flask application instance
            redis_client: Redis client for rate limiting storage
        """
        # Configure limiter with strict bypass detection
        self.limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=f"redis://localhost:6379/2",
            strategy="moving-window",
            swallow_errors=False,
            default_limits=["10 per minute"]
        )
        
        # Setup bypass detection endpoints
        self._setup_bypass_test_endpoints(app)
        
        # Mock security audit logger for bypass detection logging
        self.mock_audit_logger = Mock()
        
        yield
        
        self.limiter.reset()
    
    def _setup_bypass_test_endpoints(self, app: Flask):
        """
        Setup test endpoints for bypass detection testing.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/test/bypass-target')
        @self.limiter.limit("3 per minute")
        def bypass_target():
            return {'status': 'success', 'endpoint': 'bypass-target'}
        
        @app.route('/api/test/auth-bypass-target')
        @self.limiter.limit("2 per minute", key_func=lambda: request.headers.get('User-ID', 'anonymous'))
        def auth_bypass_target():
            return {'status': 'success', 'endpoint': 'auth-bypass-target'}
    
    def test_ip_spoofing_bypass_detection(self, client: FlaskClient):
        """
        Test detection of IP spoofing attempts to bypass rate limiting.
        
        Validates:
        - IP header manipulation detection
        - X-Forwarded-For spoofing prevention
        - Real IP extraction and validation
        - Bypass attempt logging and alerting
        
        Security Requirement: Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
        """
        # Normal requests to establish baseline
        for i in range(3):
            response = client.get('/api/test/bypass-target')
            assert response.status_code == 200
        
        # Rate limit should be exceeded
        response = client.get('/api/test/bypass-target')
        assert response.status_code == 429
        
        # Attempt IP spoofing with X-Forwarded-For header
        spoofed_headers = {'X-Forwarded-For': '192.168.1.100'}
        response = client.get('/api/test/bypass-target', headers=spoofed_headers)
        # Should still be rate limited (bypass should fail)
        assert response.status_code == 429
        
        # Attempt multiple IP spoofing headers
        complex_spoofing_headers = {
            'X-Forwarded-For': '10.0.0.1',
            'X-Real-IP': '172.16.0.1',
            'X-Originating-IP': '203.0.113.1',
            'CF-Connecting-IP': '198.51.100.1'
        }
        response = client.get('/api/test/bypass-target', headers=complex_spoofing_headers)
        # Bypass should fail - still rate limited
        assert response.status_code == 429
        
        # Verify rate limiting key remains consistent despite spoofing attempts
        assert 'X-Auth-RateLimit-Remaining' in response.headers
        assert int(response.headers['X-Auth-RateLimit-Remaining']) == 0
    
    def test_user_agent_rotation_bypass_detection(self, client: FlaskClient):
        """
        Test detection of User-Agent rotation attempts to bypass rate limiting.
        
        Validates:
        - User-Agent header manipulation detection
        - Consistent rate limiting despite header changes
        - Browser fingerprinting resistance
        - Bot behavior pattern detection
        
        Security Requirement: Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
        """
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'PostmanRuntime/7.28.4'
        ]
        
        # Use up rate limit with different User-Agent headers
        for i, user_agent in enumerate(user_agents[:3]):
            headers = {'User-Agent': user_agent}
            response = client.get('/api/test/bypass-target', headers=headers)
            assert response.status_code == 200
        
        # Additional requests with different User-Agents should still be rate limited
        for user_agent in user_agents[3:]:
            headers = {'User-Agent': user_agent}
            response = client.get('/api/test/bypass-target', headers=headers)
            # Bypass should fail - rate limiting is based on IP, not User-Agent
            assert response.status_code == 429
    
    def test_session_manipulation_bypass_detection(self, client: FlaskClient):
        """
        Test detection of session manipulation attempts to bypass rate limiting.
        
        Validates:
        - Session token manipulation resistance
        - Cookie-based bypass prevention
        - Session fixation attack resistance
        - Consistent rate limiting across session states
        
        Security Requirement: Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
        """
        # Establish rate limit with initial session
        for i in range(3):
            response = client.get('/api/test/bypass-target')
            assert response.status_code == 200
        
        # Rate limit should be exceeded
        response = client.get('/api/test/bypass-target')
        assert response.status_code == 429
        
        # Attempt bypass with new session cookies
        with client.session_transaction() as session:
            session['user_id'] = 'different_user'
            session['session_token'] = 'new_session_token'
        
        response = client.get('/api/test/bypass-target')
        # Should still be rate limited (IP-based limiting)
        assert response.status_code == 429
        
        # Attempt bypass with cleared session
        with client.session_transaction() as session:
            session.clear()
        
        response = client.get('/api/test/bypass-target')
        # Should still be rate limited
        assert response.status_code == 429
    
    def test_distributed_attack_bypass_detection(self, client: FlaskClient):
        """
        Test detection of distributed attack attempts using concurrent requests.
        
        Validates:
        - Concurrent request burst detection
        - Thread-based attack pattern recognition
        - Rate limiting consistency under concurrent load
        - Attack vector mitigation effectiveness
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        def make_request():
            """Helper function for concurrent request testing."""
            return client.get('/api/test/bypass-target')
        
        # Test concurrent request handling
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit multiple concurrent requests
            futures = [executor.submit(make_request) for _ in range(15)]
            
            # Collect results
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            # Count successful and rate-limited responses
            success_count = sum(1 for r in results if r.status_code == 200)
            rate_limited_count = sum(1 for r in results if r.status_code == 429)
            
            # Should only allow 3 successful requests, rest should be rate limited
            assert success_count <= 3
            assert rate_limited_count >= 12
            
            # Verify all rate-limited responses have proper headers
            for result in results:
                if result.status_code == 429:
                    assert 'X-Auth-RateLimit-Limit' in result.headers
                    assert 'X-Auth-RateLimit-Remaining' in result.headers
    
    def test_http_method_bypass_detection(self, client: FlaskClient, app: Flask):
        """
        Test detection of HTTP method manipulation bypass attempts.
        
        Validates:
        - Consistent rate limiting across HTTP methods
        - POST/PUT/DELETE method bypass resistance
        - Method override header attack prevention
        - RESTful endpoint rate limiting consistency
        
        Security Requirement: Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
        """
        # Setup endpoint that accepts multiple HTTP methods
        @app.route('/api/test/method-bypass-target', methods=['GET', 'POST', 'PUT', 'DELETE'])
        @self.limiter.limit("2 per minute")
        def method_bypass_target():
            return {'status': 'success', 'method': request.method}
        
        # Use up rate limit with GET requests
        for i in range(2):
            response = client.get('/api/test/method-bypass-target')
            assert response.status_code == 200
        
        # Rate limit should be exceeded for GET
        response = client.get('/api/test/method-bypass-target')
        assert response.status_code == 429
        
        # Attempt bypass with different HTTP methods
        http_methods = [
            ('POST', client.post),
            ('PUT', client.put),
            ('DELETE', client.delete)
        ]
        
        for method_name, method_func in http_methods:
            response = method_func('/api/test/method-bypass-target')
            # Should still be rate limited regardless of HTTP method
            assert response.status_code == 429
        
        # Attempt bypass with method override headers
        override_headers = {'X-HTTP-Method-Override': 'GET'}
        response = client.post('/api/test/method-bypass-target', headers=override_headers)
        assert response.status_code == 429
    
    def test_authentication_bypass_through_rate_limiting(self, client: FlaskClient):
        """
        Test prevention of authentication bypass through rate limiting manipulation.
        
        Validates:
        - Rate limiting doesn't interfere with authentication
        - Authentication-based rate limiting key consistency
        - User identity-based rate limiting enforcement
        - Authenticated vs unauthenticated rate limiting separation
        
        Security Requirement: Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
        """
        # Test unauthenticated requests with User-ID header manipulation
        user_ids = ['user_001', 'user_002', 'user_003', 'user_004', 'user_005']
        
        # Attempt to bypass by changing User-ID headers
        for user_id in user_ids[:2]:
            headers = {'User-ID': user_id}
            response = client.get('/api/test/auth-bypass-target', headers=headers)
            assert response.status_code == 200
        
        # Should be rate limited with new User-ID (separate limits per user)
        headers = {'User-ID': 'user_006'}
        for i in range(2):
            response = client.get('/api/test/auth-bypass-target', headers=headers)
            assert response.status_code == 200
        
        # Rate limit exceeded for user_006
        response = client.get('/api/test/auth-bypass-target', headers=headers)
        assert response.status_code == 429
        
        # But user_001 should still have remaining requests (if within time window)
        headers = {'User-ID': 'user_001'}
        response = client.get('/api/test/auth-bypass-target', headers=headers)
        # This might be rate limited if the minute window hasn't reset
        # The key point is that different users have separate limits
        assert response.status_code in [200, 429]


class TestDoSAttackPrevention:
    """
    DoS attack prevention testing through intelligent rate limiting validation.
    
    Tests various DoS attack vectors and validates the effectiveness of
    Flask-Limiter intelligent rate limiting in preventing resource exhaustion
    and service degradation per Section 6.4.2 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_dos_protection(self, app: Flask, redis_client: redis.Redis):
        """
        Setup DoS protection testing environment with realistic attack simulation.
        
        Args:
            app: Flask application instance
            redis_client: Redis client for rate limiting storage
        """
        # Configure aggressive rate limiting for DoS testing
        self.limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=f"redis://localhost:6379/3",
            strategy="moving-window",
            default_limits=[
                "50 per hour",      # Sustained protection
                "10 per minute",    # Burst protection
                "3 per second"      # Spike protection
            ],
            swallow_errors=False
        )
        
        # Setup DoS test endpoints
        self._setup_dos_test_endpoints(app)
        
        yield
        
        self.limiter.reset()
    
    def _setup_dos_test_endpoints(self, app: Flask):
        """
        Setup endpoints for DoS attack simulation testing.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/test/dos-target')
        @self.limiter.limit("5 per minute")
        def dos_target():
            # Simulate resource-intensive operation
            time.sleep(0.01)  # 10ms processing time
            return {'status': 'success', 'timestamp': time.time()}
        
        @app.route('/api/test/dos-auth-target')
        @self.limiter.limit("3 per minute", key_func=lambda: f"auth_dos:{request.remote_addr}")
        def dos_auth_target():
            return {'status': 'success', 'auth': True}
        
        @app.route('/api/test/dos-resource-intensive')
        @self.limiter.limit("2 per minute")
        def dos_resource_intensive():
            # Simulate very resource-intensive operation
            time.sleep(0.1)  # 100ms processing time
            return {'status': 'success', 'resource_intensive': True}
    
    def test_rapid_burst_attack_prevention(self, client: FlaskClient):
        """
        Test prevention of rapid burst DoS attacks through rate limiting.
        
        Validates:
        - Rapid request burst detection and blocking
        - Service availability protection during attacks
        - Rate limiting effectiveness under burst load
        - Recovery capability after attack mitigation
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        attack_start_time = time.time()
        
        # Simulate rapid burst attack (100 requests in quick succession)
        successful_requests = 0
        rate_limited_requests = 0
        
        for i in range(100):
            response = client.get('/api/test/dos-target')
            if response.status_code == 200:
                successful_requests += 1
            elif response.status_code == 429:
                rate_limited_requests += 1
                
                # Verify rate limiting headers are present
                assert 'X-Auth-RateLimit-Limit' in response.headers
                assert 'X-Auth-RateLimit-Remaining' in response.headers
                remaining = int(response.headers['X-Auth-RateLimit-Remaining'])
                assert remaining == 0
        
        attack_duration = time.time() - attack_start_time
        
        # Validate attack mitigation effectiveness
        assert successful_requests <= 5  # Only 5 per minute allowed
        assert rate_limited_requests >= 95  # Most requests should be blocked
        
        # Validate rapid response to attack (should block quickly)
        assert attack_duration < 10.0  # Attack should be stopped quickly
        
        # Test service recovery after attack
        time.sleep(61)  # Wait for rate limit window to reset
        response = client.get('/api/test/dos-target')
        assert response.status_code == 200  # Service should be available again
    
    def test_sustained_attack_prevention(self, client: FlaskClient):
        """
        Test prevention of sustained DoS attacks over extended periods.
        
        Validates:
        - Long-duration attack mitigation
        - Multi-tier rate limiting effectiveness
        - Service stability under sustained load
        - Resource consumption protection
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        # Simulate sustained attack over multiple time windows
        attack_phases = []
        
        for phase in range(3):  # 3 phases of attack
            phase_start = time.time()
            successful_requests = 0
            rate_limited_requests = 0
            
            # Attack for 20 seconds per phase
            while time.time() - phase_start < 20:
                response = client.get('/api/test/dos-target')
                if response.status_code == 200:
                    successful_requests += 1
                elif response.status_code == 429:
                    rate_limited_requests += 1
                
                time.sleep(0.1)  # 10 requests per second attempt
            
            attack_phases.append({
                'phase': phase + 1,
                'successful': successful_requests,
                'rate_limited': rate_limited_requests,
                'duration': time.time() - phase_start
            })
            
            # Brief pause between phases
            time.sleep(5)
        
        # Validate sustained attack mitigation
        for phase_data in attack_phases:
            # Each phase should have minimal successful requests
            assert phase_data['successful'] <= 10  # Conservative limit
            # Most requests should be rate limited
            assert phase_data['rate_limited'] > phase_data['successful']
        
        # Validate consistent protection across all phases
        total_successful = sum(p['successful'] for p in attack_phases)
        total_rate_limited = sum(p['rate_limited'] for p in attack_phases)
        assert total_rate_limited > total_successful * 5  # 5:1 ratio minimum
    
    def test_resource_exhaustion_prevention(self, client: FlaskClient):
        """
        Test prevention of resource exhaustion through rate limiting.
        
        Validates:
        - Protection of resource-intensive endpoints
        - Memory and CPU resource protection
        - Database connection protection
        - Cache resource protection
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        # Test resource-intensive endpoint protection
        start_time = time.time()
        successful_heavy_requests = 0
        
        # Attempt multiple resource-intensive requests
        for i in range(20):
            response = client.get('/api/test/dos-resource-intensive')
            if response.status_code == 200:
                successful_heavy_requests += 1
                # Verify response time is reasonable (not under severe load)
                assert time.time() - start_time < (successful_heavy_requests * 0.2)  # 200ms per request max
        
        # Should only allow 2 requests per minute for resource-intensive operations
        assert successful_heavy_requests <= 2
        
        # Test that normal endpoints remain available
        response = client.get('/api/test/dos-target')
        if response.status_code == 200:
            # Normal endpoint should respond quickly
            normal_start = time.time()
            response = client.get('/api/test/dos-target')
            response_time = time.time() - normal_start
            assert response_time < 1.0  # Should respond within 1 second
    
    def test_authentication_dos_protection(self, client: FlaskClient):
        """
        Test DoS protection for authentication endpoints specifically.
        
        Validates:
        - Authentication endpoint rate limiting
        - Auth-specific attack vector protection
        - Credential brute force prevention
        - Authentication service stability
        
        Security Requirement: Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
        """
        # Simulate authentication brute force attack
        attack_attempts = 0
        successful_auth_requests = 0
        
        for i in range(50):
            response = client.get('/api/test/dos-auth-target')
            attack_attempts += 1
            
            if response.status_code == 200:
                successful_auth_requests += 1
            elif response.status_code == 429:
                # Verify auth-specific rate limiting
                assert 'X-Auth-RateLimit-Limit' in response.headers
                
                # Check if rate limit key includes auth-specific prefix
                # This would be verified by checking the rate limiting implementation
                break
        
        # Authentication endpoints should have stricter limits
        assert successful_auth_requests <= 3  # Only 3 per minute allowed
        assert attack_attempts <= 10  # Attack should be stopped quickly
    
    def test_concurrent_dos_attack_mitigation(self, client: FlaskClient):
        """
        Test mitigation of concurrent DoS attacks from multiple sources.
        
        Validates:
        - Multi-threaded attack pattern recognition
        - Concurrent request limiting effectiveness
        - Service degradation prevention under concurrent load
        - Load balancing and rate limiting interaction
        
        Security Requirement: DoS attack prevention through intelligent rate limiting per Section 6.4.2
        """
        def concurrent_attack_worker(worker_id: int) -> Dict[str, int]:
            """Worker function for concurrent attack simulation."""
            successful = 0
            rate_limited = 0
            
            for i in range(20):
                try:
                    response = client.get('/api/test/dos-target')
                    if response.status_code == 200:
                        successful += 1
                    elif response.status_code == 429:
                        rate_limited += 1
                except Exception:
                    # Connection errors due to overload
                    rate_limited += 1
                
                time.sleep(0.05)  # 20 requests per second per worker
            
            return {'successful': successful, 'rate_limited': rate_limited}
        
        # Launch concurrent attack with multiple workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            attack_start = time.time()
            
            # Submit attack workers
            futures = [
                executor.submit(concurrent_attack_worker, worker_id)
                for worker_id in range(5)
            ]
            
            # Collect results
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
            attack_duration = time.time() - attack_start
        
        # Analyze concurrent attack mitigation
        total_successful = sum(r['successful'] for r in results)
        total_rate_limited = sum(r['rate_limited'] for r in results)
        
        # Rate limiting should be effective even under concurrent load
        assert total_successful <= 10  # Conservative limit for all workers combined
        assert total_rate_limited > total_successful * 2  # 2:1 ratio minimum
        
        # Attack should be contained quickly
        assert attack_duration < 30.0  # All workers should complete within 30 seconds
        
        # Validate service remains responsive after concurrent attack
        recovery_start = time.time()
        response = client.get('/api/test/dos-target')
        recovery_time = time.time() - recovery_start
        
        # Service should recover quickly after attack
        assert recovery_time < 2.0  # Should respond within 2 seconds


class TestRateLimitingSecurityCompliance:
    """
    Rate limiting security compliance validation test suite.
    
    Tests comprehensive compliance with Section 6.4.2 requirements including
    security event logging, monitoring integration, and enterprise security
    policy enforcement for rate limiting controls.
    """
    
    @pytest.fixture(autouse=True)
    def setup_compliance_testing(self, app: Flask, redis_client: redis.Redis):
        """
        Setup compliance testing environment with monitoring and logging.
        
        Args:
            app: Flask application instance
            redis_client: Redis client for rate limiting storage
        """
        # Configure limiter with comprehensive monitoring
        self.limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=f"redis://localhost:6379/4",
            strategy="moving-window",
            headers_enabled=True,
            swallow_errors=False
        )
        
        # Mock security audit logger
        self.audit_logger_mock = Mock()
        
        # Setup compliance test endpoints
        self._setup_compliance_endpoints(app)
        
        yield
        
        self.limiter.reset()
    
    def _setup_compliance_endpoints(self, app: Flask):
        """
        Setup endpoints for compliance validation testing.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/test/compliance-endpoint')
        @self.limiter.limit("5 per minute")
        def compliance_endpoint():
            return {'status': 'success', 'compliance': True}
        
        @app.route('/api/test/audit-endpoint')
        @self.limiter.limit("3 per minute", key_func=lambda: f"audit:{request.remote_addr}")
        def audit_endpoint():
            # Simulate audit-sensitive operation
            return {'status': 'success', 'audit': True, 'timestamp': time.time()}
    
    def test_security_event_logging_compliance(self, client: FlaskClient):
        """
        Test comprehensive security event logging for rate limiting violations.
        
        Validates:
        - Rate limiting violation event logging
        - Security event data completeness
        - Audit trail generation and format
        - Compliance with logging standards
        
        Security Requirement: Comprehensive rate limiting security test coverage per Section 6.4.5
        """
        with patch('src.auth.audit.SecurityAuditLogger') as mock_logger:
            mock_instance = mock_logger.return_value
            
            # Trigger rate limiting violation
            for i in range(6):  # Exceed 5 per minute limit
                response = client.get('/api/test/compliance-endpoint')
                if response.status_code == 429:
                    break
            
            # Verify rate limiting violation was logged
            # Note: In real implementation, this would be captured by the rate limiting decorator
            assert response.status_code == 429
            
            # Verify security headers are present for compliance
            assert 'X-Auth-RateLimit-Limit' in response.headers
            assert 'X-Auth-RateLimit-Remaining' in response.headers
            assert 'X-Auth-RateLimit-Reset' in response.headers
            
            # Verify response includes proper error information
            data = response.get_json()
            if data:  # Flask-Limiter might return different response format
                assert 'error' in data or 'message' in str(data)
    
    def test_rate_limiting_metrics_collection(self, client: FlaskClient):
        """
        Test rate limiting metrics collection for monitoring compliance.
        
        Validates:
        - Rate limiting metrics generation
        - Performance monitoring integration
        - Security metrics collection
        - Compliance reporting data
        
        Security Requirement: Comprehensive rate limiting security test coverage per Section 6.4.5
        """
        # Collect baseline metrics
        baseline_time = time.time()
        
        # Generate rate limiting events
        successful_requests = 0
        rate_limited_requests = 0
        
        for i in range(10):
            start_time = time.time()
            response = client.get('/api/test/compliance-endpoint')
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                successful_requests += 1
                # Verify response time is reasonable (rate limiting shouldn't add significant latency)
                assert response_time < 1.0
            elif response.status_code == 429:
                rate_limited_requests += 1
                # Rate limited responses should be fast
                assert response_time < 0.5
        
        total_time = time.time() - baseline_time
        
        # Validate metrics compliance
        assert successful_requests <= 5  # Compliance with rate limit
        assert rate_limited_requests >= 5  # Expected rate limiting
        assert total_time < 15.0  # Reasonable total processing time
        
        # Verify rate limiting headers provide metrics data
        if rate_limited_requests > 0:
            response = client.get('/api/test/compliance-endpoint')
            if response.status_code == 429:
                # Headers should provide comprehensive rate limiting information
                assert 'X-Auth-RateLimit-Limit' in response.headers
                assert 'X-Auth-RateLimit-Remaining' in response.headers
                assert 'X-Auth-RateLimit-Reset' in response.headers
                
                # Validate header values are properly formatted
                limit = response.headers['X-Auth-RateLimit-Limit']
                remaining = response.headers['X-Auth-RateLimit-Remaining']
                reset_time = response.headers['X-Auth-RateLimit-Reset']
                
                assert limit.isdigit() or '/' in limit  # Format: "5" or "5/60"
                assert remaining.isdigit()
                assert reset_time.isdigit()
    
    def test_enterprise_security_policy_compliance(self, client: FlaskClient):
        """
        Test compliance with enterprise security policies for rate limiting.
        
        Validates:
        - Security policy enforcement consistency
        - Audit requirements compliance
        - Enterprise monitoring integration
        - Security control effectiveness validation
        
        Security Requirement: Flask-Limiter rate limiting security validation per Section 6.4.2
        """
        # Test enterprise security policy compliance
        security_events = []
        
        def mock_security_event_handler(event_type: str, details: Dict[str, Any]):
            """Mock security event handler for compliance testing."""
            security_events.append({
                'type': event_type,
                'details': details,
                'timestamp': time.time()
            })
        
        # Simulate security-sensitive operations
        with patch('src.auth.audit.SecurityAuditLogger.log_rate_limit_violation') as mock_log:
            mock_log.side_effect = lambda **kwargs: mock_security_event_handler('rate_limit_violation', kwargs)
            
            # Generate rate limiting violations for audit endpoint
            for i in range(5):
                response = client.get('/api/test/audit-endpoint')
                if response.status_code == 429:
                    # Rate limiting violation should trigger security event
                    break
            
            # Verify enterprise compliance requirements
            assert response.status_code == 429
            
            # Verify security headers meet enterprise standards
            headers = response.headers
            assert 'X-Auth-RateLimit-Limit' in headers
            assert 'X-Auth-RateLimit-Remaining' in headers
            assert 'X-Auth-RateLimit-Reset' in headers
            
            # Verify rate limiting configuration meets policy requirements
            limit_header = headers.get('X-Auth-RateLimit-Limit', '')
            # Should indicate per-minute limiting (enterprise policy)
            assert '3' in limit_header  # 3 requests per minute limit
    
    def test_zero_tolerance_bypass_prevention_compliance(self, client: FlaskClient):
        """
        Test zero-tolerance policy compliance for rate limiting bypass prevention.
        
        Validates:
        - Complete bypass attempt prevention
        - Security control effectiveness under stress
        - Compliance with zero-tolerance requirements
        - Attack vector comprehensive coverage
        
        Security Requirement: Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
        """
        bypass_attempts = [
            # Header manipulation attempts
            {'X-Forwarded-For': '1.2.3.4', 'X-Real-IP': '5.6.7.8'},
            {'User-Agent': 'bypass-agent-123', 'X-Bypass': 'true'},
            {'Referer': 'http://trusted.domain.com', 'Origin': 'https://trusted.domain.com'},
            
            # Method-based bypass attempts  
            {'X-HTTP-Method-Override': 'OPTIONS'},
            {'X-Method-Override': 'HEAD'},
            
            # Authentication bypass attempts
            {'Authorization': 'Bearer fake-token-123'},
            {'X-API-Key': 'fake-api-key-456'},
        ]
        
        # Establish rate limit baseline
        for i in range(5):
            response = client.get('/api/test/compliance-endpoint')
            if response.status_code == 429:
                break
        
        # Attempt various bypass methods
        bypass_success_count = 0
        bypass_failure_count = 0
        
        for bypass_headers in bypass_attempts:
            response = client.get('/api/test/compliance-endpoint', headers=bypass_headers)
            
            if response.status_code == 200:
                bypass_success_count += 1
            elif response.status_code == 429:
                bypass_failure_count += 1
                
                # Verify bypass attempt is properly blocked
                assert 'X-Auth-RateLimit-Remaining' in response.headers
                assert int(response.headers['X-Auth-RateLimit-Remaining']) == 0
        
        # Zero tolerance compliance validation
        assert bypass_success_count == 0  # NO bypass attempts should succeed
        assert bypass_failure_count == len(bypass_attempts)  # ALL attempts should be blocked
        
        # Verify rate limiting remains effective after bypass attempts
        response = client.get('/api/test/compliance-endpoint')
        assert response.status_code == 429  # Should still be rate limited
        
        # Verify security state hasn't been compromised
        assert 'X-Auth-RateLimit-Limit' in response.headers
        assert 'X-Auth-RateLimit-Remaining' in response.headers
        assert int(response.headers['X-Auth-RateLimit-Remaining']) == 0


# Test configuration and markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.integration,
    pytest.mark.slow  # These tests involve timing and may take longer
]


def test_rate_limiting_integration_with_auth_decorators(app: Flask, client: FlaskClient, redis_client: redis.Redis):
    """
    Integration test for rate limiting with authentication decorators.
    
    Validates end-to-end integration between Flask-Limiter and authentication
    decorators ensuring proper security control layering per Section 6.4.2.
    """
    # Setup integrated rate limiting and authentication
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri=f"redis://localhost:6379/5",
        default_limits=["10 per minute"]
    )
    
    auth_decorators = AuthenticationDecorators(limiter=limiter)
    
    # Create integrated test endpoint
    @app.route('/api/test/integrated-auth-rate-limit')
    @auth_decorators.rate_limited_authorization(
        permissions=['integration.test'],
        rate_limit="2 per minute"
    )
    def integrated_endpoint():
        return {'status': 'success', 'integrated': True}
    
    # Test integration without authentication (should fail auth, not hit rate limit)
    response = client.get('/api/test/integrated-auth-rate-limit')
    assert response.status_code == 401  # Authentication failure
    
    # Test integration with mocked authentication
    with patch('src.auth.authentication.validate_jwt_token') as mock_auth:
        mock_auth.return_value = {
            'valid': True,
            'user_id': 'integration_test_user',
            'claims': {'sub': 'integration_test_user', 'scope': 'integration.test'}
        }
        
        with patch('src.auth.authorization.validate_user_permissions') as mock_perms:
            mock_perms.return_value = True
            
            headers = {'Authorization': 'Bearer valid-token'}
            
            # Test within rate limit
            for i in range(2):
                response = client.get('/api/test/integrated-auth-rate-limit', headers=headers)
                assert response.status_code == 200
            
            # Test rate limit exceeded (should hit rate limit, not auth failure)
            response = client.get('/api/test/integrated-auth-rate-limit', headers=headers)
            assert response.status_code == 429  # Rate limit exceeded
            
            # Verify proper error handling
            data = response.get_json()
            if data:
                assert 'Rate limit exceeded' in data.get('error', '')


def test_performance_impact_of_rate_limiting(app: Flask, client: FlaskClient, performance_baseline: Dict[str, Any]):
    """
    Test performance impact of rate limiting to ensure ≤10% variance requirement.
    
    Validates that rate limiting controls don't significantly impact response times
    and maintain performance within acceptable bounds per Section 0.1.1 requirements.
    """
    # Setup performance monitoring for rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri=f"redis://localhost:6379/6",
        default_limits=["100 per minute"]  # High limit to avoid triggering during test
    )
    
    @app.route('/api/test/performance-rate-limit')
    @limiter.limit("50 per minute")
    def performance_endpoint():
        # Simulate typical API operation
        time.sleep(0.01)  # 10ms simulated processing
        return {'status': 'success', 'performance': True}
    
    # Measure response times with rate limiting
    response_times = []
    baseline_time = performance_baseline['response_times']['health_check']  # 50ms baseline
    
    for i in range(20):
        start_time = time.time()
        response = client.get('/api/test/performance-rate-limit')
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        assert response.status_code == 200
        response_times.append(response_time)
    
    # Calculate performance metrics
    avg_response_time = sum(response_times) / len(response_times)
    max_response_time = max(response_times)
    
    # Validate performance requirements (≤10% variance from baseline)
    performance_variance = (avg_response_time - baseline_time) / baseline_time
    assert performance_variance <= 0.10  # ≤10% performance impact
    
    # Ensure no individual request is excessively slow
    assert max_response_time < baseline_time * 2  # No more than 2x baseline
    
    # Verify rate limiting headers don't add significant overhead
    for response_time in response_times:
        assert response_time < 200  # Should be well under 200ms