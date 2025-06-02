"""
Comprehensive middleware and decorator testing module for Flask application.

This module provides comprehensive testing for Flask middleware components including 
CORS handling, security headers, authentication decorators, rate limiting, and 
request processing pipeline. Tests ensure Express.js middleware equivalent patterns 
are properly implemented in Flask with enterprise-grade security and performance.

Key Test Coverage:
- Flask-CORS 4.0+ cross-origin request handling per Section 3.2.1
- Flask-Talisman 1.1.0+ security header enforcement per Section 6.4.1  
- Authentication decorator testing per Section 6.4.2
- Flask-Limiter 3.5+ rate limiting protection per Section 5.2.2
- Request/response interceptor testing per Section 5.2.1
- Middleware chain execution maintaining Express.js patterns per Section 0.1.2

Dependencies:
- pytest 7.4+ with pytest-flask integration for Flask application testing
- Flask 2.3+ application factory pattern with Blueprint testing support
- pytest-mock for external service mocking and middleware isolation
- factory_boy for dynamic test object generation with varied scenarios  
- structlog 23.1+ for enterprise audit logging during testing

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10 testing standards
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import uuid

import pytest
import structlog
from flask import Flask, request, jsonify, g, session, current_app
from flask.testing import FlaskClient
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.exceptions import TooManyRequests, Forbidden, Unauthorized

# Test imports with fallback handling
try:
    from src.auth.decorators import (
        require_permissions, rate_limited_authorization, require_roles,
        require_resource_ownership, circuit_breaker_protected, 
        audit_security_event, admin_required, high_security_endpoint,
        api_endpoint_protection, DecoratorConfig, FlaskLoginIntegration,
        AuthenticatedUser, init_auth_decorators
    )
    from src.auth.security import (
        SecurityHeaderManager, SecurityMiddleware, CSPViolationHandler,
        configure_security_headers, get_csp_nonce, generate_security_report,
        log_csp_violation, security_metrics, SecurityHeaderException
    )
    from src.app import create_app
except ImportError as e:
    pytest.skip(f"Required modules not available: {e}", allow_module_level=True)

# Configure structured logging for test execution
logger = structlog.get_logger("tests.unit.test_middleware")


class TestFlaskCORSMiddleware:
    """
    Comprehensive test suite for Flask-CORS 4.0+ middleware testing.
    
    Tests cross-origin request handling, preflight validation, credential handling,
    and security-focused origin policies per Section 3.2.1 requirements.
    """
    
    def test_cors_simple_request_allowed_origin(self, app: Flask, client: FlaskClient):
        """Test CORS simple request with allowed origin."""
        # Configure CORS with specific allowed origins
        CORS(app, origins=['https://example.com', 'https://app.company.com'])
        
        @app.route('/api/test')
        def test_endpoint():
            return jsonify({'message': 'success'})
        
        # Test request from allowed origin
        response = client.get('/api/test', headers={
            'Origin': 'https://example.com'
        })
        
        assert response.status_code == 200
        assert response.headers.get('Access-Control-Allow-Origin') == 'https://example.com'
        assert 'Access-Control-Allow-Credentials' in response.headers
        
        logger.info(
            "CORS simple request test passed",
            origin="https://example.com",
            status_code=response.status_code
        )
    
    def test_cors_simple_request_blocked_origin(self, app: Flask, client: FlaskClient):
        """Test CORS simple request with blocked origin."""
        # Configure CORS with specific allowed origins
        CORS(app, origins=['https://example.com'])
        
        @app.route('/api/test')
        def test_endpoint():
            return jsonify({'message': 'success'})
        
        # Test request from blocked origin
        response = client.get('/api/test', headers={
            'Origin': 'https://malicious.com'
        })
        
        assert response.status_code == 200  # Request succeeds but no CORS headers
        assert 'Access-Control-Allow-Origin' not in response.headers
        
        logger.info(
            "CORS blocked origin test passed",
            origin="https://malicious.com",
            cors_headers_present=False
        )
    
    def test_cors_preflight_request_success(self, app: Flask, client: FlaskClient):
        """Test CORS preflight request with valid configuration."""
        # Configure CORS with comprehensive settings
        CORS(app, 
             origins=['https://app.company.com'],
             methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
             allow_headers=['Authorization', 'Content-Type', 'X-Requested-With'],
             expose_headers=['X-Auth-Token', 'X-Request-ID'],
             supports_credentials=True,
             max_age=600
        )
        
        @app.route('/api/data', methods=['POST'])
        def data_endpoint():
            return jsonify({'data': 'created'})
        
        # Test preflight request
        response = client.options('/api/data', headers={
            'Origin': 'https://app.company.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Authorization, Content-Type'
        })
        
        assert response.status_code == 200
        assert response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert 'POST' in response.headers.get('Access-Control-Allow-Methods', '')
        assert 'Authorization' in response.headers.get('Access-Control-Allow-Headers', '')
        assert response.headers.get('Access-Control-Max-Age') == '600'
        assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
        
        logger.info(
            "CORS preflight test passed",
            origin="https://app.company.com",
            methods="POST",
            headers="Authorization, Content-Type"
        )
    
    def test_cors_preflight_request_invalid_method(self, app: Flask, client: FlaskClient):
        """Test CORS preflight request with disallowed method."""
        # Configure CORS with limited methods
        CORS(app, 
             origins=['https://app.company.com'],
             methods=['GET', 'POST']
        )
        
        @app.route('/api/data', methods=['GET', 'POST', 'DELETE'])
        def data_endpoint():
            return jsonify({'data': 'success'})
        
        # Test preflight request with disallowed method
        response = client.options('/api/data', headers={
            'Origin': 'https://app.company.com',
            'Access-Control-Request-Method': 'DELETE'
        })
        
        # Should not include DELETE in allowed methods
        allowed_methods = response.headers.get('Access-Control-Allow-Methods', '')
        assert 'DELETE' not in allowed_methods
        
        logger.info(
            "CORS invalid method test passed",
            requested_method="DELETE",
            allowed_methods=allowed_methods
        )
    
    def test_cors_credentials_handling(self, app: Flask, client: FlaskClient):
        """Test CORS credentials handling with authentication."""
        # Configure CORS with credentials support
        CORS(app, 
             origins=['https://app.company.com'],
             supports_credentials=True
        )
        
        @app.route('/api/protected')
        def protected_endpoint():
            return jsonify({'user': 'authenticated'})
        
        # Test request with credentials
        response = client.get('/api/protected', headers={
            'Origin': 'https://app.company.com',
            'Authorization': 'Bearer test-token'
        })
        
        assert response.status_code == 200
        assert response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
        
        logger.info(
            "CORS credentials test passed",
            credentials_supported=True,
            origin="https://app.company.com"
        )
    
    def test_cors_expose_headers_configuration(self, app: Flask, client: FlaskClient):
        """Test CORS exposed headers configuration."""
        # Configure CORS with exposed headers
        CORS(app,
             origins=['https://app.company.com'],
             expose_headers=['X-Auth-Token', 'X-Request-ID', 'X-Rate-Limit-Remaining']
        )
        
        @app.route('/api/info')
        def info_endpoint():
            response = jsonify({'info': 'data'})
            response.headers['X-Auth-Token'] = 'new-token'
            response.headers['X-Request-ID'] = 'req-123'
            response.headers['X-Rate-Limit-Remaining'] = '99'
            return response
        
        # Test request to check exposed headers
        response = client.get('/api/info', headers={
            'Origin': 'https://app.company.com'
        })
        
        assert response.status_code == 200
        exposed_headers = response.headers.get('Access-Control-Expose-Headers', '')
        assert 'X-Auth-Token' in exposed_headers
        assert 'X-Request-ID' in exposed_headers
        assert 'X-Rate-Limit-Remaining' in exposed_headers
        
        logger.info(
            "CORS expose headers test passed",
            exposed_headers=exposed_headers
        )
    
    def test_cors_resource_specific_configuration(self, app: Flask, client: FlaskClient):
        """Test CORS resource-specific configuration patterns."""
        # Configure CORS with resource-specific settings
        CORS(app, resources={
            r"/api/auth/*": {
                "origins": ["https://app.company.com"],
                "methods": ["POST", "GET", "OPTIONS"],
                "allow_headers": ["Authorization", "Content-Type"],
                "supports_credentials": True,
                "max_age": 300
            },
            r"/api/public/*": {
                "origins": "*",
                "methods": ["GET", "OPTIONS"],
                "supports_credentials": False,
                "max_age": 600
            }
        })
        
        @app.route('/api/auth/login', methods=['POST'])
        def auth_login():
            return jsonify({'token': 'auth-token'})
        
        @app.route('/api/public/info')
        def public_info():
            return jsonify({'info': 'public'})
        
        # Test auth endpoint with restricted CORS
        auth_response = client.options('/api/auth/login', headers={
            'Origin': 'https://app.company.com',
            'Access-Control-Request-Method': 'POST'
        })
        
        assert auth_response.status_code == 200
        assert auth_response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert auth_response.headers.get('Access-Control-Max-Age') == '300'
        
        # Test public endpoint with permissive CORS
        public_response = client.options('/api/public/info', headers={
            'Origin': 'https://external.com',
            'Access-Control-Request-Method': 'GET'
        })
        
        assert public_response.status_code == 200
        assert public_response.headers.get('Access-Control-Allow-Origin') == '*'
        assert public_response.headers.get('Access-Control-Max-Age') == '600'
        
        logger.info(
            "CORS resource-specific configuration test passed",
            auth_max_age=300,
            public_max_age=600
        )


class TestFlaskTalismanSecurityHeaders:
    """
    Comprehensive test suite for Flask-Talisman 1.1.0+ security header enforcement.
    
    Tests HTTP security headers, Content Security Policy, HSTS configuration,
    and comprehensive web application protection per Section 6.4.1 requirements.
    """
    
    def test_basic_security_headers_enforcement(self, app: Flask, client: FlaskClient):
        """Test basic security headers enforcement with Flask-Talisman."""
        # Configure Talisman with basic security settings
        Talisman(app,
                 force_https=False,  # Disabled for testing
                 strict_transport_security=True,
                 content_security_policy={
                     'default-src': "'self'",
                     'script-src': "'self' 'unsafe-inline'",
                     'style-src': "'self' 'unsafe-inline'"
                 },
                 referrer_policy='strict-origin-when-cross-origin',
                 session_cookie_secure=True,
                 session_cookie_http_only=True,
                 session_cookie_samesite='Strict'
        )
        
        @app.route('/test')
        def test_endpoint():
            return jsonify({'message': 'test'})
        
        response = client.get('/test')
        
        assert response.status_code == 200
        
        # Check HSTS header
        assert 'Strict-Transport-Security' in response.headers
        
        # Check CSP header
        csp_header = response.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp_header
        assert "script-src 'self' 'unsafe-inline'" in csp_header
        
        # Check X-Frame-Options
        assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
        
        # Check X-Content-Type-Options
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        
        # Check Referrer Policy
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
        
        logger.info(
            "Basic security headers test passed",
            csp_present=bool(csp_header),
            hsts_present='Strict-Transport-Security' in response.headers
        )
    
    def test_content_security_policy_nonce_generation(self, app: Flask, client: FlaskClient):
        """Test CSP nonce generation and injection."""
        # Configure Talisman with nonce support
        Talisman(app,
                 force_https=False,
                 content_security_policy={
                     'default-src': "'self'",
                     'script-src': "'self'",
                     'style-src': "'self'"
                 },
                 content_security_policy_nonce_in=['script-src', 'style-src']
        )
        
        @app.route('/test')
        def test_endpoint():
            return jsonify({'message': 'test'})
        
        response = client.get('/test')
        
        assert response.status_code == 200
        
        csp_header = response.headers.get('Content-Security-Policy', '')
        
        # Check that nonce is present in CSP
        assert "'nonce-" in csp_header
        assert "script-src 'self' 'nonce-" in csp_header
        assert "style-src 'self' 'nonce-" in csp_header
        
        logger.info(
            "CSP nonce generation test passed",
            csp_header=csp_header[:100] + "..." if len(csp_header) > 100 else csp_header
        )
    
    def test_hsts_configuration_options(self, app: Flask, client: FlaskClient):
        """Test HSTS configuration with various options."""
        # Configure Talisman with comprehensive HSTS settings
        Talisman(app,
                 force_https=False,
                 strict_transport_security=True,
                 strict_transport_security_max_age=31536000,  # 1 year
                 strict_transport_security_include_subdomains=True,
                 strict_transport_security_preload=True
        )
        
        @app.route('/test')
        def test_endpoint():
            return jsonify({'message': 'test'})
        
        response = client.get('/test')
        
        assert response.status_code == 200
        
        hsts_header = response.headers.get('Strict-Transport-Security', '')
        
        # Check HSTS components
        assert 'max-age=31536000' in hsts_header
        assert 'includeSubDomains' in hsts_header
        assert 'preload' in hsts_header
        
        logger.info(
            "HSTS configuration test passed",
            hsts_header=hsts_header
        )
    
    def test_feature_policy_configuration(self, app: Flask, client: FlaskClient):
        """Test Feature Policy/Permissions Policy configuration."""
        # Configure Talisman with feature policy
        Talisman(app,
                 force_https=False,
                 feature_policy={
                     'geolocation': "'none'",
                     'microphone': "'none'",
                     'camera': "'none'",
                     'accelerometer': "'none'",
                     'gyroscope': "'none'",
                     'magnetometer': "'none'",
                     'payment': "'none'",
                     'usb': "'none'"
                 }
        )
        
        @app.route('/test')
        def test_endpoint():
            return jsonify({'message': 'test'})
        
        response = client.get('/test')
        
        assert response.status_code == 200
        
        # Check for Feature Policy or Permissions Policy header
        feature_policy = response.headers.get('Feature-Policy', '')
        permissions_policy = response.headers.get('Permissions-Policy', '')
        
        # Either header should be present with our policies
        policy_present = bool(feature_policy or permissions_policy)
        assert policy_present
        
        if feature_policy:
            assert "geolocation 'none'" in feature_policy
            assert "microphone 'none'" in feature_policy
        
        logger.info(
            "Feature policy test passed",
            feature_policy_present=bool(feature_policy),
            permissions_policy_present=bool(permissions_policy)
        )
    
    def test_csp_violation_reporting(self, app: Flask, client: FlaskClient):
        """Test CSP violation reporting configuration."""
        # Configure Talisman with violation reporting
        Talisman(app,
                 force_https=False,
                 content_security_policy={
                     'default-src': "'self'",
                     'script-src': "'self'",
                     'report-uri': '/api/security/csp-violation'
                 }
        )
        
        @app.route('/test')
        def test_endpoint():
            return jsonify({'message': 'test'})
        
        @app.route('/api/security/csp-violation', methods=['POST'])
        def csp_violation_handler():
            return jsonify({'status': 'received'})
        
        response = client.get('/test')
        
        assert response.status_code == 200
        
        csp_header = response.headers.get('Content-Security-Policy', '')
        assert 'report-uri /api/security/csp-violation' in csp_header
        
        # Test CSP violation reporting endpoint
        violation_response = client.post('/api/security/csp-violation',
                                       json={'violated-directive': 'script-src'},
                                       content_type='application/json')
        
        assert violation_response.status_code == 200
        
        logger.info(
            "CSP violation reporting test passed",
            csp_header_present=bool(csp_header),
            violation_endpoint_working=True
        )
    
    def test_session_cookie_security_settings(self, app: Flask, client: FlaskClient):
        """Test session cookie security configuration."""
        # Configure Talisman with secure cookie settings
        Talisman(app,
                 force_https=False,
                 session_cookie_secure=False,  # Disabled for testing
                 session_cookie_http_only=True,
                 session_cookie_samesite='Strict'
        )
        
        @app.route('/set-session')
        def set_session():
            session['user_id'] = 'test-user'
            return jsonify({'session': 'set'})
        
        @app.route('/get-session')
        def get_session():
            return jsonify({'user_id': session.get('user_id')})
        
        # Set session cookie
        response = client.get('/set-session')
        assert response.status_code == 200
        
        # Check cookie security attributes
        set_cookie_header = response.headers.get('Set-Cookie', '')
        if set_cookie_header:
            assert 'HttpOnly' in set_cookie_header
            assert 'SameSite=Strict' in set_cookie_header
        
        # Verify session persists
        session_response = client.get('/get-session')
        assert session_response.status_code == 200
        assert session_response.json.get('user_id') == 'test-user'
        
        logger.info(
            "Session cookie security test passed",
            set_cookie_header=set_cookie_header[:100] + "..." if len(set_cookie_header) > 100 else set_cookie_header
        )


class TestAuthenticationDecorators:
    """
    Comprehensive test suite for authentication decorators and middleware.
    
    Tests route-level authorization, permission validation, role-based access control,
    and security event logging per Section 6.4.2 requirements.
    """
    
    def test_require_permissions_decorator_success(self, app: Flask, client: FlaskClient, 
                                                  mock_auth_user, valid_jwt_token):
        """Test require_permissions decorator with valid permissions."""
        
        # Mock authentication context
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators.validate_user_permissions', return_value=True):
            
            @app.route('/api/protected')
            @require_permissions('document.read', 'document.write')
            def protected_endpoint():
                return jsonify({'message': 'access granted'})
            
            response = client.get('/api/protected', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 200
            assert response.json['message'] == 'access granted'
            
            logger.info(
                "require_permissions success test passed",
                permissions=['document.read', 'document.write'],
                user_id=mock_auth_user.id
            )
    
    def test_require_permissions_decorator_failure(self, app: Flask, client: FlaskClient,
                                                  mock_auth_user, valid_jwt_token):
        """Test require_permissions decorator with insufficient permissions."""
        
        # Mock authentication context with insufficient permissions
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators.validate_user_permissions', return_value=False):
            
            @app.route('/api/protected')
            @require_permissions('admin.system.write')
            def protected_endpoint():
                return jsonify({'message': 'access granted'})
            
            response = client.get('/api/protected', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 403
            assert 'error' in response.json
            
            logger.info(
                "require_permissions failure test passed",
                permissions=['admin.system.write'],
                user_id=mock_auth_user.id,
                status_code=403
            )
    
    def test_require_permissions_unauthenticated(self, app: Flask, client: FlaskClient):
        """Test require_permissions decorator with unauthenticated user."""
        
        # Mock unauthenticated user
        mock_user = Mock()
        mock_user.is_authenticated = False
        
        with patch('src.auth.decorators.current_user', mock_user):
            
            @app.route('/api/protected')
            @require_permissions('document.read')
            def protected_endpoint():
                return jsonify({'message': 'access granted'})
            
            response = client.get('/api/protected')
            
            assert response.status_code == 401
            assert 'error' in response.json
            
            logger.info(
                "require_permissions unauthenticated test passed",
                status_code=401
            )
    
    def test_rate_limited_authorization_decorator(self, app: Flask, client: FlaskClient,
                                                 mock_auth_user, valid_jwt_token):
        """Test rate_limited_authorization decorator functionality."""
        
        # Configure rate limiter
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["100 per hour"]
        )
        
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators.validate_user_permissions', return_value=True), \
             patch('src.auth.decorators.current_app') as mock_current_app:
            
            mock_current_app.limiter = limiter
            
            @app.route('/api/admin/action')
            @rate_limited_authorization('admin.action', rate_limit="5 per minute")
            def admin_action():
                return jsonify({'message': 'action completed'})
            
            # Test first request succeeds
            response = client.get('/api/admin/action', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 200
            assert response.json['message'] == 'action completed'
            
            logger.info(
                "rate_limited_authorization test passed",
                rate_limit="5 per minute",
                permissions=['admin.action']
            )
    
    def test_require_roles_decorator_success(self, app: Flask, client: FlaskClient,
                                           mock_admin_user, admin_jwt_token):
        """Test require_roles decorator with valid roles."""
        
        with patch('src.auth.decorators.current_user', mock_admin_user):
            
            @app.route('/api/admin/dashboard')
            @require_roles('admin', 'super_admin', require_all=False)
            def admin_dashboard():
                return jsonify({'dashboard': 'admin_data'})
            
            response = client.get('/api/admin/dashboard', headers={
                'Authorization': f'Bearer {admin_jwt_token}'
            })
            
            assert response.status_code == 200
            assert response.json['dashboard'] == 'admin_data'
            
            logger.info(
                "require_roles success test passed",
                roles=['admin', 'super_admin'],
                user_roles=list(mock_admin_user.roles)
            )
    
    def test_require_roles_decorator_failure(self, app: Flask, client: FlaskClient,
                                           mock_auth_user, valid_jwt_token):
        """Test require_roles decorator with insufficient roles."""
        
        with patch('src.auth.decorators.current_user', mock_auth_user):
            
            @app.route('/api/admin/dashboard')
            @require_roles('admin', 'super_admin', require_all=True)
            def admin_dashboard():
                return jsonify({'dashboard': 'admin_data'})
            
            response = client.get('/api/admin/dashboard', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 403
            assert 'error' in response.json
            
            logger.info(
                "require_roles failure test passed",
                required_roles=['admin', 'super_admin'],
                user_roles=mock_auth_user.get_roles(),
                status_code=403
            )
    
    def test_require_resource_ownership_decorator(self, app: Flask, client: FlaskClient,
                                                 mock_auth_user, valid_jwt_token):
        """Test require_resource_ownership decorator functionality."""
        
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators._validate_resource_ownership', return_value=True):
            
            @app.route('/api/documents/<document_id>/edit')
            @require_resource_ownership('document_id', 'document', allow_admin=True)
            def edit_document(document_id: str):
                return jsonify({'document_id': document_id, 'status': 'edited'})
            
            response = client.get('/api/documents/doc-123/edit', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 200
            assert response.json['document_id'] == 'doc-123'
            assert response.json['status'] == 'edited'
            
            logger.info(
                "require_resource_ownership test passed",
                resource_id="doc-123",
                resource_type="document",
                user_id=mock_auth_user.id
            )
    
    def test_circuit_breaker_protected_decorator(self, app: Flask, client: FlaskClient,
                                               mock_auth_user):
        """Test circuit_breaker_protected decorator functionality."""
        
        @app.route('/api/external-service')
        @circuit_breaker_protected(service_name="test_service", failure_threshold=2)
        def external_service_call():
            # Simulate external service call
            return jsonify({'service': 'available'})
        
        # Test successful call
        response = client.get('/api/external-service')
        assert response.status_code == 200
        assert response.json['service'] == 'available'
        
        logger.info(
            "circuit_breaker_protected test passed",
            service_name="test_service",
            failure_threshold=2
        )
    
    def test_audit_security_event_decorator(self, app: Flask, client: FlaskClient,
                                          mock_auth_user, valid_jwt_token):
        """Test audit_security_event decorator functionality."""
        
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators.get_audit_logger') as mock_audit_logger:
            
            mock_logger = Mock()
            mock_audit_logger.return_value = mock_logger
            
            @app.route('/api/sensitive-data')
            @audit_security_event(event_type='DATA_READ_ACCESS', severity='info')
            def get_sensitive_data():
                return jsonify({'data': 'sensitive_info'})
            
            response = client.get('/api/sensitive-data', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            
            assert response.status_code == 200
            assert response.json['data'] == 'sensitive_info'
            
            # Verify audit logging was called
            mock_logger.log_security_event.assert_called()
            
            logger.info(
                "audit_security_event test passed",
                event_type='DATA_READ_ACCESS',
                user_id=mock_auth_user.id
            )


class TestFlaskLimiterRateLimit:
    """
    Comprehensive test suite for Flask-Limiter 3.5+ rate limiting middleware.
    
    Tests rate limiting protection, burst control, per-user limits, and 
    abuse prevention per Section 5.2.2 requirements.
    """
    
    def test_basic_rate_limiting(self, app: Flask, client: FlaskClient):
        """Test basic rate limiting functionality."""
        # Configure rate limiter with strict limits for testing
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["2 per minute"]
        )
        
        @app.route('/api/limited')
        def limited_endpoint():
            return jsonify({'message': 'success'})
        
        # First two requests should succeed
        response1 = client.get('/api/limited')
        assert response1.status_code == 200
        
        response2 = client.get('/api/limited')
        assert response2.status_code == 200
        
        # Third request should be rate limited
        response3 = client.get('/api/limited')
        assert response3.status_code == 429
        assert 'error' in response3.json or 'message' in response3.json
        
        logger.info(
            "Basic rate limiting test passed",
            limit="2 per minute",
            requests_made=3,
            rate_limited=True
        )
    
    def test_rate_limit_headers(self, app: Flask, client: FlaskClient):
        """Test rate limit response headers."""
        # Configure rate limiter with headers enabled
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["5 per minute"],
            headers_enabled=True
        )
        
        @app.route('/api/headers-test')
        def headers_test_endpoint():
            return jsonify({'message': 'success'})
        
        response = client.get('/api/headers-test')
        
        assert response.status_code == 200
        
        # Check rate limit headers
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        assert 'X-RateLimit-Reset' in response.headers
        
        limit = response.headers.get('X-RateLimit-Limit')
        remaining = response.headers.get('X-RateLimit-Remaining')
        
        assert int(limit) > 0
        assert int(remaining) >= 0
        
        logger.info(
            "Rate limit headers test passed",
            limit=limit,
            remaining=remaining
        )
    
    def test_per_route_rate_limiting(self, app: Flask, client: FlaskClient):
        """Test per-route rate limiting configuration."""
        # Configure rate limiter
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["10 per minute"]
        )
        
        @app.route('/api/normal')
        def normal_endpoint():
            return jsonify({'message': 'normal'})
        
        @app.route('/api/strict')
        @limiter.limit("1 per minute")
        def strict_endpoint():
            return jsonify({'message': 'strict'})
        
        # Test normal endpoint (should use default limit)
        response1 = client.get('/api/normal')
        assert response1.status_code == 200
        
        # Test strict endpoint - first request
        response2 = client.get('/api/strict')
        assert response2.status_code == 200
        
        # Test strict endpoint - second request should be limited
        response3 = client.get('/api/strict')
        assert response3.status_code == 429
        
        logger.info(
            "Per-route rate limiting test passed",
            normal_limit="10 per minute",
            strict_limit="1 per minute"
        )
    
    def test_user_specific_rate_limiting(self, app: Flask, client: FlaskClient,
                                       mock_auth_user, valid_jwt_token):
        """Test user-specific rate limiting with authentication."""
        
        def get_user_id():
            # Mock user identification for rate limiting
            return getattr(mock_auth_user, 'id', 'anonymous')
        
        # Configure rate limiter with user-specific key function
        limiter = Limiter(
            app=app,
            key_func=get_user_id,
            default_limits=["2 per minute"]
        )
        
        with patch('src.auth.decorators.current_user', mock_auth_user):
            
            @app.route('/api/user-limited')
            def user_limited_endpoint():
                return jsonify({'user_id': mock_auth_user.id})
            
            # First two requests should succeed
            response1 = client.get('/api/user-limited', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            assert response1.status_code == 200
            
            response2 = client.get('/api/user-limited', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            assert response2.status_code == 200
            
            # Third request should be rate limited
            response3 = client.get('/api/user-limited', headers={
                'Authorization': f'Bearer {valid_jwt_token}'
            })
            assert response3.status_code == 429
            
            logger.info(
                "User-specific rate limiting test passed",
                user_id=mock_auth_user.id,
                limit="2 per minute"
            )
    
    def test_rate_limit_exemption(self, app: Flask, client: FlaskClient):
        """Test rate limit exemption functionality."""
        # Configure rate limiter with exemption
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1 per minute"]
        )
        
        @app.route('/api/exempt')
        @limiter.exempt
        def exempt_endpoint():
            return jsonify({'message': 'exempt'})
        
        @app.route('/api/limited')
        def limited_endpoint():
            return jsonify({'message': 'limited'})
        
        # Test exempt endpoint - multiple requests should succeed
        response1 = client.get('/api/exempt')
        assert response1.status_code == 200
        
        response2 = client.get('/api/exempt')
        assert response2.status_code == 200
        
        response3 = client.get('/api/exempt')
        assert response3.status_code == 200
        
        # Test limited endpoint - second request should fail
        limited_response1 = client.get('/api/limited')
        assert limited_response1.status_code == 200
        
        limited_response2 = client.get('/api/limited')
        assert limited_response2.status_code == 429
        
        logger.info(
            "Rate limit exemption test passed",
            exempt_requests=3,
            limited_after=1
        )
    
    def test_burst_and_sustained_rate_limiting(self, app: Flask, client: FlaskClient):
        """Test burst and sustained rate limiting patterns."""
        # Configure rate limiter with multiple limits
        limiter = Limiter(
            app=app,
            key_func=get_remote_address
        )
        
        @app.route('/api/burst-limited')
        @limiter.limit("10 per minute; 2 per second")
        def burst_limited_endpoint():
            return jsonify({'message': 'success'})
        
        # Test burst limit (2 per second)
        response1 = client.get('/api/burst-limited')
        assert response1.status_code == 200
        
        response2 = client.get('/api/burst-limited')
        assert response2.status_code == 200
        
        # Third request within same second should be limited
        response3 = client.get('/api/burst-limited')
        assert response3.status_code == 429
        
        logger.info(
            "Burst and sustained rate limiting test passed",
            burst_limit="2 per second",
            sustained_limit="10 per minute"
        )


class TestMiddlewarePipeline:
    """
    Comprehensive test suite for middleware pipeline execution and request processing.
    
    Tests middleware chain execution, request/response interceptors, and
    Express.js equivalent patterns per Section 5.2.1 and 0.1.2 requirements.
    """
    
    def test_middleware_execution_order(self, app: Flask, client: FlaskClient):
        """Test middleware execution order and request processing pipeline."""
        execution_order = []
        
        @app.before_request
        def before_request_middleware1():
            execution_order.append('before1')
            g.request_start_time = time.time()
        
        @app.before_request
        def before_request_middleware2():
            execution_order.append('before2')
            g.middleware_executed = True
        
        @app.after_request
        def after_request_middleware1(response):
            execution_order.append('after1')
            response.headers['X-Middleware-1'] = 'executed'
            return response
        
        @app.after_request
        def after_request_middleware2(response):
            execution_order.append('after2')
            response.headers['X-Middleware-2'] = 'executed'
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                response.headers['X-Request-Duration'] = str(duration)
            return response
        
        @app.route('/test-pipeline')
        def test_endpoint():
            execution_order.append('endpoint')
            return jsonify({'pipeline': 'test'})
        
        response = client.get('/test-pipeline')
        
        assert response.status_code == 200
        assert response.json['pipeline'] == 'test'
        
        # Check execution order
        expected_order = ['before1', 'before2', 'endpoint', 'after2', 'after1']
        assert execution_order == expected_order
        
        # Check middleware headers
        assert response.headers.get('X-Middleware-1') == 'executed'
        assert response.headers.get('X-Middleware-2') == 'executed'
        assert 'X-Request-Duration' in response.headers
        
        logger.info(
            "Middleware execution order test passed",
            execution_order=execution_order,
            middleware_headers_present=True
        )
    
    def test_request_context_sharing(self, app: Flask, client: FlaskClient):
        """Test request context sharing between middleware components."""
        
        @app.before_request
        def set_request_context():
            g.request_id = str(uuid.uuid4())
            g.user_agent = request.headers.get('User-Agent', 'unknown')
            g.start_time = datetime.utcnow()
        
        @app.after_request
        def add_context_headers(response):
            if hasattr(g, 'request_id'):
                response.headers['X-Request-ID'] = g.request_id
            if hasattr(g, 'user_agent'):
                response.headers['X-User-Agent-Captured'] = g.user_agent
            if hasattr(g, 'start_time'):
                duration = (datetime.utcnow() - g.start_time).total_seconds()
                response.headers['X-Processing-Time'] = str(duration)
            return response
        
        @app.route('/context-test')
        def context_endpoint():
            return jsonify({
                'request_id': getattr(g, 'request_id', None),
                'user_agent': getattr(g, 'user_agent', None),
                'has_start_time': hasattr(g, 'start_time')
            })
        
        response = client.get('/context-test', headers={
            'User-Agent': 'TestClient/1.0'
        })
        
        assert response.status_code == 200
        
        data = response.json
        assert data['request_id'] is not None
        assert data['user_agent'] == 'TestClient/1.0'
        assert data['has_start_time'] is True
        
        # Check context headers
        assert 'X-Request-ID' in response.headers
        assert response.headers.get('X-User-Agent-Captured') == 'TestClient/1.0'
        assert 'X-Processing-Time' in response.headers
        
        logger.info(
            "Request context sharing test passed",
            request_id=data['request_id'],
            user_agent=data['user_agent']
        )
    
    def test_error_handling_middleware(self, app: Flask, client: FlaskClient):
        """Test error handling in middleware pipeline."""
        
        @app.before_request
        def error_prone_middleware():
            if request.path == '/trigger-error':
                raise ValueError("Middleware error")
        
        @app.errorhandler(ValueError)
        def handle_value_error(error):
            return jsonify({
                'error': 'middleware_error',
                'message': str(error)
            }), 500
        
        @app.route('/normal')
        def normal_endpoint():
            return jsonify({'status': 'normal'})
        
        @app.route('/trigger-error')
        def error_endpoint():
            return jsonify({'status': 'should not reach'})
        
        # Test normal request
        normal_response = client.get('/normal')
        assert normal_response.status_code == 200
        assert normal_response.json['status'] == 'normal'
        
        # Test error in middleware
        error_response = client.get('/trigger-error')
        assert error_response.status_code == 500
        assert error_response.json['error'] == 'middleware_error'
        assert 'Middleware error' in error_response.json['message']
        
        logger.info(
            "Error handling middleware test passed",
            normal_status=200,
            error_status=500
        )
    
    def test_conditional_middleware_execution(self, app: Flask, client: FlaskClient):
        """Test conditional middleware execution based on request properties."""
        
        @app.before_request
        def conditional_middleware():
            if request.path.startswith('/api/'):
                g.api_request = True
                g.api_version = request.headers.get('API-Version', 'v1')
            else:
                g.api_request = False
        
        @app.before_request
        def api_only_middleware():
            if getattr(g, 'api_request', False):
                g.api_processing = True
                if g.api_version not in ['v1', 'v2']:
                    return jsonify({'error': 'unsupported_api_version'}), 400
        
        @app.after_request
        def add_api_headers(response):
            if getattr(g, 'api_request', False):
                response.headers['X-API-Request'] = 'true'
                response.headers['X-API-Version'] = getattr(g, 'api_version', 'v1')
            return response
        
        @app.route('/api/test')
        def api_endpoint():
            return jsonify({
                'api_request': getattr(g, 'api_request', False),
                'api_processing': getattr(g, 'api_processing', False),
                'api_version': getattr(g, 'api_version', None)
            })
        
        @app.route('/web/test')
        def web_endpoint():
            return jsonify({
                'api_request': getattr(g, 'api_request', False),
                'api_processing': getattr(g, 'api_processing', False)
            })
        
        # Test API request
        api_response = client.get('/api/test', headers={'API-Version': 'v2'})
        assert api_response.status_code == 200
        assert api_response.json['api_request'] is True
        assert api_response.json['api_processing'] is True
        assert api_response.json['api_version'] == 'v2'
        assert api_response.headers.get('X-API-Request') == 'true'
        assert api_response.headers.get('X-API-Version') == 'v2'
        
        # Test web request
        web_response = client.get('/web/test')
        assert web_response.status_code == 200
        assert web_response.json['api_request'] is False
        assert web_response.json['api_processing'] is False
        assert 'X-API-Request' not in web_response.headers
        
        # Test unsupported API version
        unsupported_response = client.get('/api/test', headers={'API-Version': 'v3'})
        assert unsupported_response.status_code == 400
        assert unsupported_response.json['error'] == 'unsupported_api_version'
        
        logger.info(
            "Conditional middleware execution test passed",
            api_processing=True,
            web_processing=True,
            version_validation=True
        )
    
    def test_middleware_performance_monitoring(self, app: Flask, client: FlaskClient):
        """Test middleware performance monitoring and metrics collection."""
        
        middleware_metrics = {
            'request_count': 0,
            'total_duration': 0,
            'avg_duration': 0
        }
        
        @app.before_request
        def performance_monitoring_start():
            g.perf_start = time.perf_counter()
            middleware_metrics['request_count'] += 1
        
        @app.after_request
        def performance_monitoring_end(response):
            if hasattr(g, 'perf_start'):
                duration = time.perf_counter() - g.perf_start
                middleware_metrics['total_duration'] += duration
                middleware_metrics['avg_duration'] = (
                    middleware_metrics['total_duration'] / middleware_metrics['request_count']
                )
                
                response.headers['X-Request-Duration-Ms'] = str(round(duration * 1000, 2))
                response.headers['X-Avg-Duration-Ms'] = str(
                    round(middleware_metrics['avg_duration'] * 1000, 2)
                )
                
            return response
        
        @app.route('/performance-test')
        def performance_endpoint():
            # Simulate some processing time
            time.sleep(0.001)  # 1ms
            return jsonify({'message': 'performance test'})
        
        # Make multiple requests to test performance monitoring
        for i in range(3):
            response = client.get('/performance-test')
            assert response.status_code == 200
            assert 'X-Request-Duration-Ms' in response.headers
            assert 'X-Avg-Duration-Ms' in response.headers
            
            duration_ms = float(response.headers['X-Request-Duration-Ms'])
            assert duration_ms > 0
        
        # Check final metrics
        assert middleware_metrics['request_count'] == 3
        assert middleware_metrics['total_duration'] > 0
        assert middleware_metrics['avg_duration'] > 0
        
        logger.info(
            "Middleware performance monitoring test passed",
            request_count=middleware_metrics['request_count'],
            avg_duration_ms=round(middleware_metrics['avg_duration'] * 1000, 2)
        )


class TestIntegratedMiddlewareStack:
    """
    Comprehensive integration test suite for complete middleware stack.
    
    Tests integrated CORS, security headers, authentication, rate limiting,
    and request pipeline working together as a complete middleware stack.
    """
    
    def test_complete_middleware_stack_integration(self, app: Flask, client: FlaskClient,
                                                  mock_auth_user, valid_jwt_token):
        """Test complete middleware stack integration with all components."""
        
        # Configure CORS
        CORS(app, 
             origins=['https://app.company.com'],
             supports_credentials=True)
        
        # Configure Talisman security headers
        Talisman(app,
                 force_https=False,
                 strict_transport_security=True,
                 content_security_policy={'default-src': "'self'"},
                 session_cookie_secure=False,  # Disabled for testing
                 session_cookie_http_only=True)
        
        # Configure rate limiter
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["10 per minute"])
        
        # Add authentication middleware
        @app.before_request
        def auth_middleware():
            if request.path.startswith('/api/protected'):
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'authentication_required'}), 401
                g.authenticated_user = mock_auth_user
        
        # Add request tracking middleware
        @app.before_request
        def request_tracking():
            g.request_id = str(uuid.uuid4())
            g.start_time = time.perf_counter()
        
        @app.after_request
        def response_enhancement(response):
            if hasattr(g, 'request_id'):
                response.headers['X-Request-ID'] = g.request_id
            if hasattr(g, 'start_time'):
                duration = time.perf_counter() - g.start_time
                response.headers['X-Response-Time'] = str(round(duration * 1000, 2))
            return response
        
        with patch('src.auth.decorators.current_user', mock_auth_user), \
             patch('src.auth.decorators.validate_user_permissions', return_value=True):
            
            @app.route('/api/protected/data')
            @require_permissions('data.read')
            def protected_data():
                return jsonify({
                    'data': 'protected_content',
                    'user_id': g.authenticated_user.id,
                    'request_id': g.request_id
                })
        
        # Test complete stack with CORS preflight
        preflight_response = client.options('/api/protected/data', headers={
            'Origin': 'https://app.company.com',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Authorization'
        })
        
        assert preflight_response.status_code == 200
        assert preflight_response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert 'GET' in preflight_response.headers.get('Access-Control-Allow-Methods', '')
        
        # Test actual request with all middleware
        response = client.get('/api/protected/data', headers={
            'Origin': 'https://app.company.com',
            'Authorization': f'Bearer {valid_jwt_token}'
        })
        
        assert response.status_code == 200
        
        # Check response data
        data = response.json
        assert data['data'] == 'protected_content'
        assert data['user_id'] == mock_auth_user.id
        assert 'request_id' in data
        
        # Check CORS headers
        assert response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
        
        # Check security headers
        assert 'Strict-Transport-Security' in response.headers
        assert 'Content-Security-Policy' in response.headers
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        
        # Check rate limit headers
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        
        # Check custom middleware headers
        assert 'X-Request-ID' in response.headers
        assert 'X-Response-Time' in response.headers
        
        logger.info(
            "Complete middleware stack integration test passed",
            cors_working=True,
            security_headers_present=True,
            authentication_working=True,
            rate_limiting_active=True,
            custom_middleware_active=True
        )
    
    def test_middleware_error_handling_integration(self, app: Flask, client: FlaskClient):
        """Test error handling across integrated middleware stack."""
        
        # Configure basic middleware stack
        CORS(app, origins=['https://app.company.com'])
        Talisman(app, force_https=False)
        
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1 per minute"])
        
        @app.before_request
        def error_injection_middleware():
            if request.args.get('inject_error') == 'middleware':
                raise RuntimeError("Injected middleware error")
        
        @app.errorhandler(RuntimeError)
        def handle_runtime_error(error):
            return jsonify({
                'error': 'runtime_error',
                'message': str(error),
                'error_source': 'middleware'
            }), 500
        
        @app.errorhandler(429)
        def handle_rate_limit_error(error):
            return jsonify({
                'error': 'rate_limit_exceeded',
                'message': 'Too many requests',
                'retry_after': getattr(error, 'retry_after', None)
            }), 429
        
        @app.route('/error-test')
        def error_test_endpoint():
            if request.args.get('inject_error') == 'endpoint':
                raise ValueError("Injected endpoint error")
            return jsonify({'message': 'success'})
        
        # Test normal request
        normal_response = client.get('/error-test', headers={
            'Origin': 'https://app.company.com'
        })
        assert normal_response.status_code == 200
        assert normal_response.json['message'] == 'success'
        
        # Test middleware error
        middleware_error_response = client.get('/error-test?inject_error=middleware', headers={
            'Origin': 'https://app.company.com'
        })
        assert middleware_error_response.status_code == 500
        assert middleware_error_response.json['error'] == 'runtime_error'
        assert middleware_error_response.json['error_source'] == 'middleware'
        
        # Test rate limit error (second request should be limited)
        rate_limit_response = client.get('/error-test', headers={
            'Origin': 'https://app.company.com'
        })
        assert rate_limit_response.status_code == 429
        assert rate_limit_response.json['error'] == 'rate_limit_exceeded'
        
        # Check that CORS and security headers are present even in error responses
        assert middleware_error_response.headers.get('Access-Control-Allow-Origin') == 'https://app.company.com'
        assert 'Content-Security-Policy' in middleware_error_response.headers
        
        logger.info(
            "Middleware error handling integration test passed",
            normal_response=True,
            middleware_error_handling=True,
            rate_limit_error_handling=True,
            headers_preserved_in_errors=True
        )
    
    def test_middleware_performance_under_load(self, app: Flask, client: FlaskClient):
        """Test middleware performance under simulated load conditions."""
        
        # Configure lightweight middleware stack for performance testing
        CORS(app, origins=['*'])
        
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["100 per minute"])
        
        request_metrics = {
            'total_requests': 0,
            'total_duration': 0,
            'max_duration': 0,
            'min_duration': float('inf')
        }
        
        @app.before_request
        def performance_tracking():
            g.start_time = time.perf_counter()
        
        @app.after_request
        def performance_measurement(response):
            if hasattr(g, 'start_time'):
                duration = time.perf_counter() - g.start_time
                request_metrics['total_requests'] += 1
                request_metrics['total_duration'] += duration
                request_metrics['max_duration'] = max(request_metrics['max_duration'], duration)
                request_metrics['min_duration'] = min(request_metrics['min_duration'], duration)
                
                response.headers['X-Duration-Ms'] = str(round(duration * 1000, 2))
            return response
        
        @app.route('/load-test')
        def load_test_endpoint():
            # Simulate minimal processing
            return jsonify({'processed': True})
        
        # Simulate load with multiple requests
        num_requests = 20
        durations = []
        
        for i in range(num_requests):
            response = client.get('/load-test')
            assert response.status_code == 200
            
            duration_ms = float(response.headers.get('X-Duration-Ms', 0))
            durations.append(duration_ms)
        
        # Calculate performance metrics
        avg_duration = request_metrics['total_duration'] / request_metrics['total_requests']
        max_duration = request_metrics['max_duration']
        min_duration = request_metrics['min_duration']
        
        # Performance assertions (adjust thresholds as needed)
        assert avg_duration < 0.1  # Average request should be under 100ms
        assert max_duration < 0.2   # Max request should be under 200ms
        
        logger.info(
            "Middleware performance under load test passed",
            num_requests=num_requests,
            avg_duration_ms=round(avg_duration * 1000, 2),
            max_duration_ms=round(max_duration * 1000, 2),
            min_duration_ms=round(min_duration * 1000, 2)
        )


# Integration test markers for pytest
pytestmark = [
    pytest.mark.unit,
    pytest.mark.middleware,
    pytest.mark.security
]


def test_middleware_module_imports():
    """Test that all required middleware modules can be imported."""
    try:
        from src.auth.decorators import require_permissions, rate_limited_authorization
        from src.auth.security import configure_security_headers, SecurityHeaderManager
        from flask_cors import CORS
        from flask_limiter import Limiter
        from flask_talisman import Talisman
        
        logger.info("All middleware modules imported successfully")
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import required middleware modules: {e}")


def test_middleware_configuration_validation():
    """Test middleware configuration validation and setup."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    try:
        # Test CORS configuration
        CORS(app, origins=['https://test.com'])
        
        # Test Talisman configuration
        Talisman(app, force_https=False)
        
        # Test Limiter configuration  
        Limiter(app=app, key_func=get_remote_address)
        
        logger.info("Middleware configuration validation passed")
        assert True
    except Exception as e:
        pytest.fail(f"Middleware configuration validation failed: {e}")


if __name__ == '__main__':
    # Run tests if module is executed directly
    pytest.main([__file__, '-v', '--tb=short'])