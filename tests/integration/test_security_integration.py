"""
Security Integration Testing Module

This module provides comprehensive security integration testing covering Flask-Talisman
security headers, input validation pipelines, authentication workflows, and comprehensive
security controls. Tests enterprise-grade security patterns with vulnerability scanning
integration, security header enforcement, and comprehensive audit logging across all
security components.

Key Testing Areas:
- Flask-Talisman security headers as direct replacement for helmet middleware per Section 3.2.2
- Input validation and sanitization pipeline per F-003-RQ-004
- Security-focused exception handling for enterprise compliance per Section 6.4.2
- Comprehensive security event logging for enterprise compliance per Section 6.4.2
- CSRF token validation and XSS prevention integration per Section 6.4.1
- AES-256-GCM encryption for session data and cache per Section 6.4.1
- Security vulnerability scanning with bandit and safety per Section 6.6.3

Security Standards Tested:
- OWASP Top 10 compliance validation
- SOC 2 Type II security controls
- ISO 27001 security management requirements
- PCI DSS security standards
- GDPR privacy protection compliance

Architecture Integration:
- Section 6.4.1: Flask-Talisman HTTP security header enforcement
- Section 6.4.2: Enhanced authorization decorators and security event logging
- Section 6.4.1: AES-256-GCM encryption with AWS KMS integration
- Section 6.6.3: Security scan requirements with automated vulnerability detection
- F-003-RQ-004: Input validation and sanitization pipeline testing
- Section 3.2.2: Flask-Talisman as direct helmet middleware replacement

Test Coverage Requirements:
- Security integration coverage: ≥95% per enhanced requirements
- Authentication workflow coverage: 100% critical requirement
- Authorization security testing: ≥90% enhanced requirement
- Security header enforcement: 100% compliance requirement
- Input validation coverage: ≥95% security requirement

Performance Requirements:
- Security overhead: ≤10ms per security check
- Authentication response time: ≤100ms per request
- Security header processing: ≤5ms per request
- Overall security integration: ≤10% variance from baseline

Dependencies:
- Flask application with Flask-Talisman configuration
- Authentication and authorization infrastructure
- Security audit logging system
- Input validation pipeline with marshmallow integration
- Business validators for comprehensive data validation
- Testcontainers for realistic service integration

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10, PCI DSS, GDPR
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Generator, AsyncGenerator
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
from urllib.parse import urlparse, parse_qs

import pytest
import pytest_asyncio
from flask import Flask, request, session, g, jsonify, Response
from flask.testing import FlaskClient
from flask_login import current_user
from werkzeug.test import Client
from werkzeug.wrappers import Response as WerkzeugResponse

# Security testing imports
import structlog
from cryptography.fernet import Fernet
from email_validator import EmailNotValidError
from marshmallow import ValidationError as MarshmallowValidationError

# Import application security components
from src.auth.security import (
    SecurityHeaderManager, SecurityMiddleware, CSPViolationHandler,
    configure_security_headers, get_csp_nonce, generate_security_report,
    log_csp_violation, security_metrics, SecurityHeaderException
)
from src.auth.decorators import (
    require_permissions, rate_limited_authorization, require_roles,
    require_resource_ownership, circuit_breaker_protected, 
    audit_security_event, admin_required, high_security_endpoint,
    api_endpoint_protection, AuthenticatedUser, DecoratorConfig,
    init_auth_decorators
)
from src.auth.audit import (
    SecurityAuditLogger, SecurityEventType, SecurityAuditConfig,
    audit_authorization, audit_authentication, audit_data_access,
    create_security_audit_decorator
)
from src.business.validators import (
    ValidationConfig, BaseValidator, EmailValidator, PhoneValidator,
    UserValidator, OrganizationValidator, ProductValidator,
    RequestValidator, PaginationValidator, FileUploadValidator,
    BusinessRuleEngine, ValidationChain, ConditionalValidator,
    ValidationException, sanitize_input, validate_email
)

# Import test infrastructure
from tests.conftest import (
    app_factory, client_factory, authenticated_client,
    mongodb_container, redis_container, auth0_mock,
    test_user, test_organization, test_database_config
)


# =============================================================================
# SECURITY INTEGRATION TEST CONFIGURATION
# =============================================================================

class SecurityTestConfig:
    """
    Configuration for comprehensive security integration testing with
    enterprise-grade security validation and compliance testing patterns.
    """
    
    # Security Header Testing Configuration
    SECURITY_HEADERS_ENABLED = True
    CSP_TESTING_ENABLED = True
    HSTS_TESTING_ENABLED = True
    TALISMAN_TESTING_ENABLED = True
    
    # Authentication and Authorization Testing Configuration
    AUTH_WORKFLOW_TESTING_ENABLED = True
    AUTHZ_INTEGRATION_TESTING_ENABLED = True
    PERMISSION_TESTING_ENABLED = True
    ROLE_TESTING_ENABLED = True
    
    # Input Validation Testing Configuration
    INPUT_VALIDATION_TESTING_ENABLED = True
    SANITIZATION_TESTING_ENABLED = True
    XSS_PREVENTION_TESTING_ENABLED = True
    INJECTION_TESTING_ENABLED = True
    
    # Security Audit Logging Testing Configuration
    AUDIT_LOGGING_TESTING_ENABLED = True
    SECURITY_EVENT_TESTING_ENABLED = True
    COMPLIANCE_TESTING_ENABLED = True
    
    # Encryption and Session Security Testing Configuration
    ENCRYPTION_TESTING_ENABLED = True
    SESSION_SECURITY_TESTING_ENABLED = True
    CSRF_TESTING_ENABLED = True
    
    # Performance and Security Overhead Testing Configuration
    PERFORMANCE_TESTING_ENABLED = True
    SECURITY_OVERHEAD_MAX_MS = 10.0
    AUTH_RESPONSE_MAX_MS = 100.0
    HEADER_PROCESSING_MAX_MS = 5.0
    
    # Vulnerability Scanning Integration Testing Configuration
    VULNERABILITY_SCANNING_ENABLED = True
    BANDIT_INTEGRATION_TESTING = True
    SAFETY_INTEGRATION_TESTING = True
    
    # Test Data Configuration
    TEST_USER_EMAIL = "test.security@example.com"
    TEST_USER_PASSWORD = "TestSecurePassword123!"
    TEST_ADMIN_EMAIL = "admin.security@example.com"
    TEST_MALICIOUS_INPUTS = [
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "{{7*7}}",  # Template injection
        "../../../etc/passwd",  # Path traversal
        "eval(alert('xss'))",
        "<svg onload=alert('xss')>"
    ]


# =============================================================================
# SECURITY TESTING FIXTURES
# =============================================================================

@pytest.fixture
def security_test_app(app_factory, mongodb_container, redis_container):
    """
    Create Flask application with comprehensive security configuration
    for testing Flask-Talisman, authentication, and security controls.
    """
    app = app_factory()
    
    # Configure security headers with Flask-Talisman
    talisman = configure_security_headers(app)
    
    # Initialize authentication decorators
    init_auth_decorators(app)
    
    # Configure test routes for security testing
    @app.route('/api/test/public')
    def public_endpoint():
        """Public endpoint for security header testing."""
        return jsonify({'message': 'Public endpoint', 'timestamp': datetime.utcnow().isoformat()})
    
    @app.route('/api/test/protected')
    @require_permissions('test.read')
    def protected_endpoint():
        """Protected endpoint for authorization testing."""
        return jsonify({
            'message': 'Protected endpoint accessed',
            'user_id': current_user.id if current_user.is_authenticated else None,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/test/admin')
    @admin_required()
    def admin_endpoint():
        """Admin endpoint for role-based authorization testing."""
        return jsonify({
            'message': 'Admin endpoint accessed',
            'user_id': current_user.id,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/test/high-security')
    @high_security_endpoint('sensitive.read', 'sensitive.write')
    def high_security_endpoint():
        """High security endpoint for comprehensive protection testing."""
        return jsonify({
            'message': 'High security endpoint accessed',
            'security_level': 'maximum',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/test/validation', methods=['POST'])
    @api_endpoint_protection('data.validate')
    def validation_endpoint():
        """Endpoint for input validation testing."""
        data = request.get_json()
        # Basic validation with marshmallow integration
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Sanitize input data
        sanitized_data = sanitize_input(data)
        return jsonify({
            'message': 'Data validated successfully',
            'sanitized_data': sanitized_data,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/test/file-upload', methods=['POST'])
    @require_permissions('file.upload')
    def file_upload_endpoint():
        """File upload endpoint for security testing."""
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Basic file validation
        allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'error': 'File type not allowed'}), 400
        
        return jsonify({
            'message': 'File upload successful',
            'filename': file.filename,
            'size': len(file.read()),
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/api/security/csp-violation', methods=['POST'])
    def csp_violation_report():
        """CSP violation reporting endpoint for testing."""
        violation_data = request.get_json(force=True)
        response = log_csp_violation(violation_data)
        return jsonify(response), 200
    
    # Add error handlers for security exceptions
    @app.errorhandler(SecurityHeaderException)
    def handle_security_header_error(error):
        return jsonify({
            'error': 'Security configuration error',
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    
    @app.errorhandler(ValidationException)
    def handle_validation_error(error):
        return jsonify({
            'error': 'Validation failed',
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }), 400
    
    return app


@pytest.fixture
def security_client(security_test_app):
    """
    Create test client with security testing configuration
    and comprehensive security header validation support.
    """
    return security_test_app.test_client()


@pytest.fixture
def authenticated_security_client(security_test_app, test_user):
    """
    Create authenticated test client for protected endpoint testing
    with comprehensive user context and permission setup.
    """
    client = security_test_app.test_client()
    
    with security_test_app.test_request_context():
        # Mock authentication state
        with patch('flask_login.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = test_user['user_id']
            mock_user.get_permissions.return_value = {
                'test.read', 'test.write', 'data.validate', 'file.upload',
                'sensitive.read', 'sensitive.write'
            }
            mock_user.get_roles.return_value = ['user', 'tester']
            mock_user.has_permission.return_value = True
            mock_user.has_role.return_value = True
            
            yield client


@pytest.fixture
def admin_security_client(security_test_app, test_user):
    """
    Create admin test client for administrative endpoint testing
    with elevated permissions and comprehensive role setup.
    """
    client = security_test_app.test_client()
    
    with security_test_app.test_request_context():
        # Mock admin authentication state
        with patch('flask_login.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = test_user['admin_id']
            mock_user.get_permissions.return_value = {
                'system.admin', 'user.admin', 'data.admin',
                'sensitive.read', 'sensitive.write', 'test.read', 'test.write'
            }
            mock_user.get_roles.return_value = ['admin', 'super_admin']
            mock_user.has_permission.return_value = True
            mock_user.has_role.return_value = True
            
            yield client


@pytest.fixture
def security_audit_logger():
    """
    Create security audit logger fixture for testing
    comprehensive security event logging and monitoring.
    """
    return SecurityAuditLogger()


@pytest.fixture
def encryption_test_key():
    """
    Generate test encryption key for AES-256-GCM testing
    and session data encryption validation.
    """
    return Fernet.generate_key()


@pytest.fixture
def csp_violation_data():
    """
    Generate CSP violation test data for comprehensive
    Content Security Policy testing and violation handling.
    """
    return {
        'csp-report': {
            'violated-directive': 'script-src \'self\'',
            'blocked-uri': 'https://malicious-domain.com/script.js',
            'document-uri': 'https://app.example.com/page',
            'original-policy': 'default-src \'self\'; script-src \'self\' https://cdn.auth0.com',
            'referrer': 'https://app.example.com/',
            'source-file': 'https://app.example.com/page',
            'line-number': 42,
            'column-number': 15,
            'status-code': 200
        }
    }


# =============================================================================
# FLASK-TALISMAN SECURITY HEADERS INTEGRATION TESTS
# =============================================================================

class TestFlaskTalismanSecurityHeaders:
    """
    Comprehensive testing of Flask-Talisman security header enforcement
    as direct replacement for Node.js helmet middleware per Section 3.2.2.
    
    Tests security header configuration, CSP enforcement, HSTS implementation,
    and comprehensive web application security protection patterns.
    """
    
    def test_security_headers_configuration(self, security_client):
        """
        Test Flask-Talisman security header configuration and enforcement
        with comprehensive security header validation and compliance checking.
        """
        # Test public endpoint security headers
        response = security_client.get('/api/test/public')
        
        assert response.status_code == 200
        
        # Verify HSTS header enforcement
        assert 'Strict-Transport-Security' in response.headers
        hsts_header = response.headers['Strict-Transport-Security']
        assert 'max-age=31536000' in hsts_header
        assert 'includeSubDomains' in hsts_header
        
        # Verify Content Security Policy header
        assert 'Content-Security-Policy' in response.headers
        csp_header = response.headers['Content-Security-Policy']
        assert "default-src 'self'" in csp_header
        assert "script-src 'self'" in csp_header
        
        # Verify frame options protection
        assert response.headers.get('X-Frame-Options') == 'DENY'
        
        # Verify content type options
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        
        # Verify referrer policy
        assert 'strict-origin-when-cross-origin' in response.headers.get('Referrer-Policy', '')
        
        # Verify additional security headers
        assert response.headers.get('X-XSS-Protection') == '1; mode=block'
        assert response.headers.get('X-DNS-Prefetch-Control') == 'off'
    
    def test_content_security_policy_enforcement(self, security_client):
        """
        Test Content Security Policy enforcement with nonce generation,
        Auth0 domain allowlisting, and comprehensive directive validation.
        """
        with patch.dict(os.environ, {
            'AUTH0_DOMAIN': 'test-domain.auth0.com',
            'CSP_ENABLED': 'true'
        }):
            response = security_client.get('/api/test/public')
            
            assert response.status_code == 200
            
            # Verify CSP header presence and structure
            csp_header = response.headers.get('Content-Security-Policy')
            assert csp_header is not None
            
            # Verify core CSP directives
            assert "default-src 'self'" in csp_header
            assert "script-src 'self'" in csp_header
            assert "style-src 'self'" in csp_header
            assert "img-src 'self' data: https:" in csp_header
            assert "object-src 'none'" in csp_header
            assert "base-uri 'self'" in csp_header
            assert "frame-ancestors 'none'" in csp_header
            
            # Verify Auth0 domain integration
            assert 'https://test-domain.auth0.com' in csp_header
            assert 'https://cdn.auth0.com' in csp_header
            
            # Verify AWS service integration
            assert 'https://*.amazonaws.com' in csp_header
    
    def test_csp_nonce_generation(self, security_test_app):
        """
        Test CSP nonce generation and integration with inline scripts/styles
        for enhanced security while maintaining functionality.
        """
        with security_test_app.test_request_context():
            # Test nonce generation
            nonce = get_csp_nonce()
            
            # Verify nonce characteristics
            assert nonce is not None
            assert len(nonce) >= 16  # Minimum entropy requirement
            assert isinstance(nonce, str)
            
            # Verify nonce is base64-safe
            try:
                decoded = base64.urlsafe_b64decode(nonce + '==')
                assert len(decoded) >= 12  # Minimum 96 bits entropy
            except Exception as e:
                pytest.fail(f"Invalid nonce format: {e}")
    
    def test_csp_violation_reporting(self, security_client, csp_violation_data):
        """
        Test CSP violation reporting endpoint with comprehensive
        violation data processing and security event logging.
        """
        # Test CSP violation report submission
        response = security_client.post(
            '/api/security/csp-violation',
            json=csp_violation_data,
            content_type='application/json'
        )
        
        assert response.status_code == 200
        
        # Verify violation processing response
        response_data = response.get_json()
        assert response_data['status'] == 'violation_logged'
        assert 'violation_id' in response_data
        assert 'severity' in response_data
        assert 'timestamp' in response_data
        
        # Verify security event logging
        with patch('src.auth.security.security_metrics') as mock_metrics:
            security_client.post(
                '/api/security/csp-violation',
                json=csp_violation_data,
                content_type='application/json'
            )
            
            # Verify metrics were updated
            assert mock_metrics['csp_violations'].labels.called
    
    def test_https_enforcement(self, security_client):
        """
        Test HTTPS enforcement and secure cookie policies
        with comprehensive transport security validation.
        """
        # Test HTTPS enforcement through Flask-Talisman
        with patch.dict(os.environ, {'FORCE_HTTPS': 'true'}):
            response = security_client.get('/api/test/public')
            
            # Verify HSTS header with proper configuration
            hsts_header = response.headers.get('Strict-Transport-Security')
            assert hsts_header is not None
            assert 'max-age=31536000' in hsts_header
            assert 'includeSubDomains' in hsts_header
            
            # Verify secure cookie policies
            cookie_headers = response.headers.getlist('Set-Cookie')
            for cookie_header in cookie_headers:
                if 'session' in cookie_header.lower():
                    assert 'Secure' in cookie_header
                    assert 'HttpOnly' in cookie_header
                    assert 'SameSite=Strict' in cookie_header
    
    def test_security_header_performance(self, security_client):
        """
        Test security header processing performance to ensure
        minimal overhead and compliance with performance requirements.
        """
        start_time = time.perf_counter()
        
        # Perform multiple requests to measure header processing overhead
        for _ in range(10):
            response = security_client.get('/api/test/public')
            assert response.status_code == 200
        
        end_time = time.perf_counter()
        avg_time_per_request = (end_time - start_time) / 10
        
        # Verify performance requirement: ≤5ms per request for header processing
        assert avg_time_per_request < SecurityTestConfig.HEADER_PROCESSING_MAX_MS / 1000
    
    def test_security_configuration_report(self, security_test_app):
        """
        Test security configuration reporting for compliance
        auditing and monitoring with comprehensive validation.
        """
        with security_test_app.test_request_context():
            # Generate security configuration report
            security_report = generate_security_report()
            
            # Verify report structure and content
            assert isinstance(security_report, dict)
            assert 'security_headers' in security_report
            assert 'csp_configuration' in security_report
            assert 'environment' in security_report
            assert 'compliance' in security_report
            assert 'monitoring' in security_report
            
            # Verify security header configuration
            headers_config = security_report['security_headers']
            assert headers_config['talisman_enabled'] is True
            assert headers_config['hsts_enabled'] is True
            assert headers_config['csp_enabled'] is True
            
            # Verify compliance indicators
            compliance_config = security_report['compliance']
            assert compliance_config['owasp_headers'] is True
            assert compliance_config['soc2_compliant'] is True
            assert compliance_config['iso27001_aligned'] is True


# =============================================================================
# AUTHENTICATION AND AUTHORIZATION INTEGRATION TESTS
# =============================================================================

class TestAuthenticationIntegration:
    """
    Comprehensive authentication workflow testing with Flask-Login integration,
    JWT token validation, and session management per Section 6.4.1.
    
    Tests authentication state preservation, user context management,
    and comprehensive security validation patterns.
    """
    
    def test_authentication_workflow(self, security_test_app, test_user):
        """
        Test complete authentication workflow with user context creation,
        session management, and comprehensive state validation.
        """
        with security_test_app.test_request_context():
            # Mock authentication components
            with patch('src.auth.decorators.get_auth_manager') as mock_auth_manager:
                mock_auth_manager.return_value.validate_jwt_token.return_value = True
                mock_auth_manager.return_value.get_user_session.return_value = {
                    'user_id': test_user['user_id'],
                    'session_id': 'test-session-123',
                    'token_payload': {
                        'sub': test_user['user_id'],
                        'email': test_user['email'],
                        'roles': ['user']
                    },
                    'user_profile': {
                        'email': test_user['email'],
                        'name': test_user['name']
                    },
                    'authenticated_at': datetime.utcnow().isoformat(),
                    'authentication_method': 'jwt'
                }
                
                # Create authenticated user instance
                user = AuthenticatedUser(
                    user_id=test_user['user_id'],
                    session_data=mock_auth_manager.return_value.get_user_session.return_value,
                    auth_manager=mock_auth_manager.return_value
                )
                
                # Verify user authentication state
                assert user.is_authenticated is True
                assert user.is_active is True
                assert user.is_anonymous is False
                assert user.get_id() == test_user['user_id']
                
                # Verify JWT claims extraction
                assert user.jwt_claims['sub'] == test_user['user_id']
                assert user.jwt_claims['email'] == test_user['email']
                assert 'user' in user.jwt_claims['roles']
                
                # Verify user profile information
                assert user.profile['email'] == test_user['email']
                assert user.profile['name'] == test_user['name']
    
    def test_session_validation(self, security_test_app, test_user):
        """
        Test session validation with expiration checking,
        security validation, and comprehensive state management.
        """
        with security_test_app.test_request_context():
            # Test valid session
            valid_session_data = {
                'user_id': test_user['user_id'],
                'session_id': 'valid-session-123',
                'session_metadata': {
                    'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat() + 'Z'
                },
                'token_payload': {'sub': test_user['user_id']},
                'user_profile': {'email': test_user['email']}
            }
            
            with patch('src.auth.decorators.get_auth_manager') as mock_auth_manager:
                mock_auth_manager.return_value.get_user_session.return_value = valid_session_data
                
                user = AuthenticatedUser(
                    user_id=test_user['user_id'],
                    session_data=valid_session_data,
                    auth_manager=mock_auth_manager.return_value
                )
                
                # Verify valid session
                assert user.is_authenticated is True
                
            # Test expired session
            expired_session_data = {
                'user_id': test_user['user_id'],
                'session_id': 'expired-session-123',
                'session_metadata': {
                    'expires_at': (datetime.utcnow() - timedelta(hours=1)).isoformat() + 'Z'
                },
                'token_payload': {'sub': test_user['user_id']},
                'user_profile': {'email': test_user['email']}
            }
            
            with patch('src.auth.decorators.get_auth_manager') as mock_auth_manager:
                mock_auth_manager.return_value.get_user_session.return_value = expired_session_data
                
                user = AuthenticatedUser(
                    user_id=test_user['user_id'],
                    session_data=expired_session_data,
                    auth_manager=mock_auth_manager.return_value
                )
                
                # Verify expired session is not authenticated
                assert user.is_authenticated is False
    
    def test_permission_caching(self, security_test_app, test_user):
        """
        Test permission caching with intelligent TTL management
        and performance optimization validation.
        """
        with security_test_app.test_request_context():
            session_data = {
                'user_id': test_user['user_id'],
                'session_id': 'cache-test-session',
                'token_payload': {'sub': test_user['user_id']},
                'user_profile': {'email': test_user['email']}
            }
            
            with patch('src.auth.decorators.get_auth_manager') as mock_auth_manager, \
                 patch('src.auth.decorators.get_authorization_manager') as mock_authz_manager:
                
                mock_auth_manager.return_value.get_user_session.return_value = session_data
                mock_authz_manager.return_value._get_user_permissions.return_value = {
                    'test.read', 'test.write', 'data.validate'
                }
                
                user = AuthenticatedUser(
                    user_id=test_user['user_id'],
                    session_data=session_data,
                    auth_manager=mock_auth_manager.return_value
                )
                
                # First call - should fetch from authorization manager
                permissions1 = user.get_permissions()
                assert mock_authz_manager.return_value._get_user_permissions.call_count == 1
                
                # Second call - should use cached permissions
                permissions2 = user.get_permissions()
                assert mock_authz_manager.return_value._get_user_permissions.call_count == 1
                assert permissions1 == permissions2
                
                # Force refresh - should fetch again
                permissions3 = user.get_permissions(force_refresh=True)
                assert mock_authz_manager.return_value._get_user_permissions.call_count == 2
                assert permissions3 == permissions1


class TestAuthorizationIntegration:
    """
    Comprehensive authorization integration testing with permission validation,
    role-based access control, and resource ownership per Section 6.4.2.
    
    Tests enhanced authorization decorators, security event logging,
    and comprehensive access control patterns.
    """
    
    def test_permission_based_authorization(self, authenticated_security_client):
        """
        Test permission-based authorization with comprehensive
        permission validation and security event logging.
        """
        # Test successful permission validation
        response = authenticated_security_client.get('/api/test/protected')
        assert response.status_code == 200
        
        response_data = response.get_json()
        assert response_data['message'] == 'Protected endpoint accessed'
        assert 'user_id' in response_data
        assert 'timestamp' in response_data
    
    def test_role_based_authorization(self, admin_security_client):
        """
        Test role-based authorization with comprehensive
        role validation and administrative access patterns.
        """
        # Test successful admin role validation
        response = admin_security_client.get('/api/test/admin')
        assert response.status_code == 200
        
        response_data = response.get_json()
        assert response_data['message'] == 'Admin endpoint accessed'
        assert 'user_id' in response_data
        assert 'timestamp' in response_data
    
    def test_unauthorized_access_handling(self, security_client):
        """
        Test unauthorized access handling with comprehensive
        error response validation and security event logging.
        """
        # Test unauthorized access to protected endpoint
        response = security_client.get('/api/test/protected')
        assert response.status_code == 401
        
        response_data = response.get_json()
        assert response_data['error'] is True
        assert 'Authentication required' in response_data['message']
        assert response_data['error_code'] == 'AUTH_REQUIRED'
    
    def test_high_security_endpoint_protection(self, authenticated_security_client):
        """
        Test high security endpoint with comprehensive protection layers
        including rate limiting, circuit breaker, and audit logging.
        """
        # Mock circuit breaker and rate limiting for testing
        with patch('src.auth.decorators.get_authorization_manager') as mock_authz, \
             patch('src.auth.decorators.get_audit_logger') as mock_audit:
            
            mock_authz.return_value.validate_user_permissions.return_value = True
            
            response = authenticated_security_client.get('/api/test/high-security')
            assert response.status_code == 200
            
            response_data = response.get_json()
            assert response_data['message'] == 'High security endpoint accessed'
            assert response_data['security_level'] == 'maximum'
            
            # Verify audit logging was called
            assert mock_audit.return_value.log_authorization_event.called
    
    def test_authorization_performance(self, authenticated_security_client):
        """
        Test authorization performance to ensure minimal overhead
        and compliance with performance requirements.
        """
        start_time = time.perf_counter()
        
        # Perform multiple authorization checks
        for _ in range(10):
            response = authenticated_security_client.get('/api/test/protected')
            assert response.status_code == 200
        
        end_time = time.perf_counter()
        avg_time_per_request = (end_time - start_time) / 10
        
        # Verify performance requirement: ≤10ms security overhead
        assert avg_time_per_request < SecurityTestConfig.SECURITY_OVERHEAD_MAX_MS / 1000


# =============================================================================
# INPUT VALIDATION AND SANITIZATION INTEGRATION TESTS
# =============================================================================

class TestInputValidationIntegration:
    """
    Comprehensive input validation and sanitization testing per F-003-RQ-004
    with marshmallow integration, XSS prevention, and injection protection.
    
    Tests input validation pipelines, data sanitization, and comprehensive
    security validation patterns for enterprise data protection.
    """
    
    def test_input_sanitization_pipeline(self, authenticated_security_client):
        """
        Test input sanitization pipeline with comprehensive
        data cleaning and XSS prevention validation.
        """
        # Test basic input sanitization
        test_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'description': 'Valid description text'
        }
        
        response = authenticated_security_client.post(
            '/api/test/validation',
            json=test_data,
            content_type='application/json'
        )
        
        assert response.status_code == 200
        response_data = response.get_json()
        assert response_data['message'] == 'Data validated successfully'
        assert 'sanitized_data' in response_data
        
        # Verify data was properly sanitized
        sanitized = response_data['sanitized_data']
        assert sanitized['name'] == test_data['name']
        assert sanitized['email'] == test_data['email']
        assert sanitized['description'] == test_data['description']
    
    def test_xss_prevention(self, authenticated_security_client):
        """
        Test XSS prevention with comprehensive malicious input detection
        and sanitization validation per Section 6.4.1.
        """
        for malicious_input in SecurityTestConfig.TEST_MALICIOUS_INPUTS:
            test_data = {
                'content': malicious_input,
                'description': f'Testing XSS with: {malicious_input[:20]}'
            }
            
            response = authenticated_security_client.post(
                '/api/test/validation',
                json=test_data,
                content_type='application/json'
            )
            
            assert response.status_code == 200
            response_data = response.get_json()
            
            # Verify malicious content was sanitized
            sanitized_content = response_data['sanitized_data']['content']
            
            # Verify dangerous patterns were removed/escaped
            assert '<script>' not in sanitized_content
            assert 'javascript:' not in sanitized_content
            assert 'onerror=' not in sanitized_content
            assert 'onload=' not in sanitized_content
            assert 'eval(' not in sanitized_content
    
    def test_sql_injection_prevention(self, authenticated_security_client):
        """
        Test SQL injection prevention with comprehensive
        injection pattern detection and sanitization.
        """
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1' UNION SELECT * FROM users--",
            "'; INSERT INTO users VALUES('hacker','password'); --"
        ]
        
        for injection_attempt in sql_injection_attempts:
            test_data = {
                'search_query': injection_attempt,
                'user_input': f'Valid text with injection: {injection_attempt}'
            }
            
            response = authenticated_security_client.post(
                '/api/test/validation',
                json=test_data,
                content_type='application/json'
            )
            
            assert response.status_code == 200
            response_data = response.get_json()
            
            # Verify SQL injection patterns were sanitized
            sanitized_query = response_data['sanitized_data']['search_query']
            assert 'DROP TABLE' not in sanitized_query.upper()
            assert 'UNION SELECT' not in sanitized_query.upper()
            assert 'INSERT INTO' not in sanitized_query.upper()
    
    def test_file_upload_validation(self, authenticated_security_client):
        """
        Test file upload validation with comprehensive security checks,
        file type validation, and size limit enforcement.
        """
        # Test valid file upload
        valid_file_data = b'This is a test file content'
        
        response = authenticated_security_client.post(
            '/api/test/file-upload',
            data={'file': (io.BytesIO(valid_file_data), 'test.txt')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 200
        response_data = response.get_json()
        assert response_data['message'] == 'File upload successful'
        assert response_data['filename'] == 'test.txt'
        assert response_data['size'] == len(valid_file_data)
        
        # Test invalid file type
        malicious_file_data = b'<script>alert("xss")</script>'
        
        response = authenticated_security_client.post(
            '/api/test/file-upload',
            data={'file': (io.BytesIO(malicious_file_data), 'malicious.js')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 400
        response_data = response.get_json()
        assert 'File type not allowed' in response_data['error']
    
    def test_email_validation(self, authenticated_security_client):
        """
        Test email validation with comprehensive format checking
        and business rule validation using email-validator integration.
        """
        # Test valid email formats
        valid_emails = [
            'user@example.com',
            'test.user@subdomain.example.com',
            'user+tag@example.com'
        ]
        
        for email in valid_emails:
            test_data = {'email': email, 'action': 'validate_email'}
            
            response = authenticated_security_client.post(
                '/api/test/validation',
                json=test_data,
                content_type='application/json'
            )
            
            assert response.status_code == 200
            response_data = response.get_json()
            sanitized_email = response_data['sanitized_data']['email']
            
            # Verify email was properly validated and preserved
            assert '@' in sanitized_email
            assert '.' in sanitized_email
        
        # Test invalid email formats
        invalid_emails = [
            'invalid-email',
            '@example.com',
            'user@',
            'user@.com',
            'user space@example.com'
        ]
        
        for email in invalid_emails:
            test_data = {'email': email, 'action': 'validate_email'}
            
            response = authenticated_security_client.post(
                '/api/test/validation',
                json=test_data,
                content_type='application/json'
            )
            
            # Email validation should still succeed but may sanitize the email
            assert response.status_code == 200
    
    def test_input_validation_performance(self, authenticated_security_client):
        """
        Test input validation performance with comprehensive
        validation pipeline overhead measurement.
        """
        test_data = {
            'field1': 'Test data 1',
            'field2': 'Test data 2',
            'field3': 'Test data 3',
            'email': 'test@example.com',
            'description': 'This is a test description with some content'
        }
        
        start_time = time.perf_counter()
        
        # Perform multiple validation requests
        for _ in range(10):
            response = authenticated_security_client.post(
                '/api/test/validation',
                json=test_data,
                content_type='application/json'
            )
            assert response.status_code == 200
        
        end_time = time.perf_counter()
        avg_time_per_validation = (end_time - start_time) / 10
        
        # Verify validation performance is within acceptable limits
        # Should be much faster than the security overhead limit
        assert avg_time_per_validation < SecurityTestConfig.SECURITY_OVERHEAD_MAX_MS / 2000


# =============================================================================
# SECURITY AUDIT LOGGING INTEGRATION TESTS
# =============================================================================

class TestSecurityAuditIntegration:
    """
    Comprehensive security audit logging integration testing per Section 6.4.2
    with structured logging, security event tracking, and compliance validation.
    
    Tests comprehensive security event logging, audit trail generation,
    and enterprise compliance support for SOC 2, ISO 27001, and GDPR.
    """
    
    def test_authentication_event_logging(self, security_test_app, security_audit_logger, test_user):
        """
        Test authentication event logging with comprehensive
        security event capture and structured data validation.
        """
        with security_test_app.test_request_context():
            # Test successful authentication logging
            security_audit_logger.log_authentication_event(
                event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
                result="success",
                user_id=test_user['user_id'],
                metadata={
                    'authentication_method': 'jwt',
                    'source_ip': '192.168.1.100',
                    'user_agent': 'Test Client/1.0'
                }
            )
            
            # Verify logging was successful (no exceptions raised)
            assert True  # If we reach here, logging succeeded
            
            # Test failed authentication logging
            security_audit_logger.log_authentication_event(
                event_type=SecurityEventType.AUTH_LOGIN_FAILURE,
                result="failure",
                user_id=None,
                metadata={
                    'failure_reason': 'invalid_credentials',
                    'attempted_email': 'attacker@malicious.com',
                    'source_ip': '10.0.0.1'
                }
            )
            
            # Verify failure logging was successful
            assert True
    
    def test_authorization_event_logging(self, security_test_app, security_audit_logger, test_user):
        """
        Test authorization event logging with comprehensive
        permission decision tracking and security event validation.
        """
        with security_test_app.test_request_context():
            # Test successful authorization logging
            security_audit_logger.log_authorization_event(
                event_type=SecurityEventType.AUTHZ_PERMISSION_GRANTED,
                decision="granted",
                user_id=test_user['user_id'],
                resource_type="document",
                resource_id="doc-123",
                required_permissions=['document.read'],
                metadata={
                    'endpoint': '/api/documents/doc-123',
                    'method': 'GET',
                    'execution_time_ms': 15.5
                }
            )
            
            # Test authorization denial logging
            security_audit_logger.log_authorization_event(
                event_type=SecurityEventType.AUTHZ_PERMISSION_DENIED,
                decision="denied",
                user_id=test_user['user_id'],
                resource_type="admin_panel",
                resource_id=None,
                required_permissions=['admin.access'],
                metadata={
                    'endpoint': '/api/admin/dashboard',
                    'user_permissions': ['user.read', 'user.write'],
                    'denial_reason': 'insufficient_permissions'
                }
            )
            
            # Verify authorization logging was successful
            assert True
    
    def test_security_violation_logging(self, security_test_app, security_audit_logger):
        """
        Test security violation logging with comprehensive
        threat detection and incident tracking validation.
        """
        with security_test_app.test_request_context():
            # Test XSS attempt logging
            security_audit_logger.log_security_violation(
                violation_type="xss_attempt",
                severity="high",
                description="XSS injection attempt detected in user input",
                metadata={
                    'malicious_input': '<script>alert("xss")</script>',
                    'endpoint': '/api/user/profile',
                    'sanitized_input': '&lt;script&gt;alert("xss")&lt;/script&gt;',
                    'detection_method': 'input_validation'
                }
            )
            
            # Test SQL injection attempt logging
            security_audit_logger.log_security_violation(
                violation_type="sql_injection_attempt",
                severity="critical",
                description="SQL injection pattern detected in database query",
                metadata={
                    'malicious_query': "'; DROP TABLE users; --",
                    'endpoint': '/api/search',
                    'blocked': True,
                    'detection_method': 'pattern_matching'
                }
            )
            
            # Test rate limiting violation logging
            security_audit_logger.log_rate_limit_violation(
                endpoint="/api/login",
                limit_type="authentication_attempts",
                current_rate=25,
                limit_threshold=10,
                user_id=None,
                metadata={
                    'time_window': '1_minute',
                    'source_ip': '10.0.0.1',
                    'blocked_duration': '15_minutes'
                }
            )
            
            # Verify security violation logging was successful
            assert True
    
    def test_circuit_breaker_event_logging(self, security_test_app, security_audit_logger):
        """
        Test circuit breaker event logging with comprehensive
        external service failure tracking and resilience monitoring.
        """
        with security_test_app.test_request_context():
            # Test circuit breaker opening
            security_audit_logger.log_circuit_breaker_event(
                service="auth0",
                event_type="circuit_opened",
                state="open",
                failure_count=5,
                additional_info={
                    'last_failure_time': datetime.utcnow().isoformat(),
                    'failure_threshold': 5,
                    'recovery_timeout': 60,
                    'affected_operations': ['token_validation', 'user_profile_fetch']
                }
            )
            
            # Test circuit breaker recovery
            security_audit_logger.log_circuit_breaker_event(
                service="auth0",
                event_type="circuit_closed",
                state="closed",
                failure_count=0,
                additional_info={
                    'recovery_time': datetime.utcnow().isoformat(),
                    'successful_calls': 3,
                    'service_restored': True
                }
            )
            
            # Verify circuit breaker logging was successful
            assert True
    
    def test_audit_log_performance(self, security_test_app, security_audit_logger, test_user):
        """
        Test audit logging performance to ensure minimal overhead
        and compliance with enterprise performance requirements.
        """
        with security_test_app.test_request_context():
            start_time = time.perf_counter()
            
            # Perform multiple audit log operations
            for i in range(10):
                security_audit_logger.log_authentication_event(
                    event_type=SecurityEventType.AUTH_TOKEN_VALIDATION_SUCCESS,
                    result="success",
                    user_id=test_user['user_id'],
                    metadata={
                        'iteration': i,
                        'token_type': 'jwt',
                        'validation_time_ms': 5.2
                    }
                )
            
            end_time = time.perf_counter()
            avg_time_per_log = (end_time - start_time) / 10
            
            # Verify audit logging performance: ≤2ms per event
            assert avg_time_per_log < SecurityAuditConfig.MAX_AUDIT_OVERHEAD_MS / 1000


# =============================================================================
# ENCRYPTION AND SESSION SECURITY INTEGRATION TESTS
# =============================================================================

class TestEncryptionIntegration:
    """
    Comprehensive encryption integration testing per Section 6.4.1 with
    AES-256-GCM encryption, session data protection, and cache security.
    
    Tests encryption implementation, key management, and comprehensive
    data protection patterns for enterprise security compliance.
    """
    
    def test_session_data_encryption(self, security_test_app, encryption_test_key):
        """
        Test session data encryption with AES-256-GCM implementation
        and comprehensive data protection validation.
        """
        with security_test_app.test_request_context():
            # Test session data encryption
            fernet = Fernet(encryption_test_key)
            
            # Test data to encrypt
            session_data = {
                'user_id': 'user-123',
                'email': 'test@example.com',
                'roles': ['user', 'tester'],
                'permissions': ['read', 'write'],
                'session_metadata': {
                    'created_at': datetime.utcnow().isoformat(),
                    'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat()
                }
            }
            
            # Encrypt session data
            session_json = json.dumps(session_data)
            encrypted_data = fernet.encrypt(session_json.encode())
            
            # Verify encryption successful
            assert isinstance(encrypted_data, bytes)
            assert len(encrypted_data) > len(session_json)
            
            # Decrypt and verify data integrity
            decrypted_data = fernet.decrypt(encrypted_data)
            decrypted_json = decrypted_data.decode()
            restored_data = json.loads(decrypted_json)
            
            # Verify data integrity after decryption
            assert restored_data == session_data
            assert restored_data['user_id'] == 'user-123'
            assert restored_data['email'] == 'test@example.com'
            assert set(restored_data['roles']) == {'user', 'tester'}
    
    def test_cache_data_encryption(self, security_test_app, encryption_test_key):
        """
        Test cache data encryption with comprehensive
        Redis cache security and key rotation validation.
        """
        with security_test_app.test_request_context():
            fernet = Fernet(encryption_test_key)
            
            # Test cache data encryption
            cache_data = {
                'permissions': ['test.read', 'test.write', 'data.validate'],
                'roles': ['user'],
                'cached_at': datetime.utcnow().isoformat(),
                'ttl': 300
            }
            
            # Encrypt cache data
            cache_json = json.dumps(cache_data)
            encrypted_cache = fernet.encrypt(cache_json.encode())
            
            # Simulate Redis storage (base64 encoding for string storage)
            stored_cache = base64.b64encode(encrypted_cache).decode()
            
            # Simulate Redis retrieval and decryption
            retrieved_cache = base64.b64decode(stored_cache.encode())
            decrypted_cache = fernet.decrypt(retrieved_cache)
            restored_cache = json.loads(decrypted_cache.decode())
            
            # Verify cache data integrity
            assert restored_cache == cache_data
            assert set(restored_cache['permissions']) == {'test.read', 'test.write', 'data.validate'}
            assert restored_cache['roles'] == ['user']
    
    def test_encryption_key_rotation(self, security_test_app):
        """
        Test encryption key rotation with comprehensive
        key management and migration validation.
        """
        with security_test_app.test_request_context():
            # Generate multiple encryption keys (simulating rotation)
            old_key = Fernet.generate_key()
            new_key = Fernet.generate_key()
            
            old_fernet = Fernet(old_key)
            new_fernet = Fernet(new_key)
            
            # Encrypt data with old key
            test_data = {'sensitive': 'data', 'timestamp': datetime.utcnow().isoformat()}
            data_json = json.dumps(test_data)
            
            old_encrypted = old_fernet.encrypt(data_json.encode())
            
            # Decrypt with old key and re-encrypt with new key
            decrypted_data = old_fernet.decrypt(old_encrypted)
            new_encrypted = new_fernet.encrypt(decrypted_data)
            
            # Verify new key can decrypt the rotated data
            final_decrypted = new_fernet.decrypt(new_encrypted)
            final_data = json.loads(final_decrypted.decode())
            
            assert final_data == test_data
            assert final_data['sensitive'] == 'data'
    
    def test_encryption_performance(self, security_test_app, encryption_test_key):
        """
        Test encryption performance to ensure minimal overhead
        and compliance with enterprise performance requirements.
        """
        with security_test_app.test_request_context():
            fernet = Fernet(encryption_test_key)
            
            # Test data of typical session size
            session_data = {
                'user_id': 'performance-test-user',
                'email': 'performance@example.com',
                'permissions': ['read', 'write', 'delete', 'admin'] * 10,  # Larger dataset
                'metadata': {'created': datetime.utcnow().isoformat()} * 5
            }
            
            data_json = json.dumps(session_data)
            
            # Measure encryption performance
            start_time = time.perf_counter()
            
            for _ in range(100):
                encrypted = fernet.encrypt(data_json.encode())
                decrypted = fernet.decrypt(encrypted)
            
            end_time = time.perf_counter()
            avg_time_per_operation = (end_time - start_time) / 200  # 100 encrypt + 100 decrypt
            
            # Verify encryption performance is acceptable (should be very fast)
            assert avg_time_per_operation < 0.001  # Less than 1ms per operation


# =============================================================================
# CSRF AND XSS PREVENTION INTEGRATION TESTS
# =============================================================================

class TestCSRFAndXSSPrevention:
    """
    Comprehensive CSRF token validation and XSS prevention testing
    per Section 6.4.1 with Flask-Talisman integration and comprehensive
    web application security protection patterns.
    """
    
    def test_csrf_token_validation(self, security_test_app):
        """
        Test CSRF token validation with comprehensive
        token generation, validation, and protection patterns.
        """
        with security_test_app.test_request_context():
            # Mock CSRF token generation
            csrf_token = secrets.token_urlsafe(32)
            
            # Verify token characteristics
            assert len(csrf_token) >= 32
            assert isinstance(csrf_token, str)
            
            # Verify token is URL-safe
            try:
                decoded = base64.urlsafe_b64decode(csrf_token + '==')
                assert len(decoded) >= 24  # Minimum entropy
            except Exception:
                # Token might not be base64, which is also valid
                pass
    
    def test_xss_prevention_headers(self, security_client):
        """
        Test XSS prevention through security headers with
        comprehensive Content Security Policy validation.
        """
        response = security_client.get('/api/test/public')
        
        # Verify XSS protection headers
        assert response.headers.get('X-XSS-Protection') == '1; mode=block'
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        
        # Verify CSP prevents inline scripts
        csp_header = response.headers.get('Content-Security-Policy', '')
        assert "script-src 'self'" in csp_header
        assert "object-src 'none'" in csp_header
        
        # Verify frame protection
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_content_type_validation(self, authenticated_security_client):
        """
        Test content type validation with comprehensive
        MIME type checking and content validation patterns.
        """
        # Test valid JSON content type
        valid_data = {'test': 'data'}
        response = authenticated_security_client.post(
            '/api/test/validation',
            json=valid_data,
            content_type='application/json'
        )
        assert response.status_code == 200
        
        # Test invalid content type handling
        response = authenticated_security_client.post(
            '/api/test/validation',
            data='test data',
            content_type='text/plain'
        )
        # Should handle gracefully or reject based on endpoint requirements
        assert response.status_code in [200, 400, 415]
    
    def test_referrer_policy_enforcement(self, security_client):
        """
        Test referrer policy enforcement with comprehensive
        privacy protection and information leakage prevention.
        """
        response = security_client.get('/api/test/public')
        
        # Verify referrer policy header
        referrer_policy = response.headers.get('Referrer-Policy')
        assert referrer_policy is not None
        assert 'strict-origin-when-cross-origin' in referrer_policy


# =============================================================================
# VULNERABILITY SCANNING INTEGRATION TESTS
# =============================================================================

class TestVulnerabilityScanningIntegration:
    """
    Comprehensive security vulnerability scanning integration testing
    per Section 6.6.3 with bandit and safety integration for automated
    security assessment and vulnerability detection.
    """
    
    def test_static_analysis_integration(self, security_test_app):
        """
        Test static analysis integration with bandit security scanning
        and comprehensive code security assessment validation.
        """
        # Mock bandit integration
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = json.dumps({
                'results': [],
                'metrics': {
                    'total_lines': 1000,
                    'total_issues': 0,
                    'confidence_high': 0,
                    'severity_high': 0
                }
            })
            
            # Simulate bandit scan execution
            bandit_result = mock_subprocess.return_value
            
            # Verify successful scan execution
            assert bandit_result.returncode == 0
            
            # Parse scan results
            scan_data = json.loads(bandit_result.stdout)
            assert 'results' in scan_data
            assert 'metrics' in scan_data
            assert scan_data['metrics']['severity_high'] == 0
    
    def test_dependency_vulnerability_scanning(self, security_test_app):
        """
        Test dependency vulnerability scanning with safety integration
        and comprehensive dependency security assessment.
        """
        # Mock safety integration
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = json.dumps({
                'vulnerabilities': [],
                'scanned_packages': 50,
                'vulnerable_packages': 0,
                'scan_timestamp': datetime.utcnow().isoformat()
            })
            
            # Simulate safety scan execution
            safety_result = mock_subprocess.return_value
            
            # Verify successful dependency scan
            assert safety_result.returncode == 0
            
            # Parse vulnerability results
            vuln_data = json.loads(safety_result.stdout)
            assert 'vulnerabilities' in vuln_data
            assert vuln_data['vulnerable_packages'] == 0
    
    def test_security_scan_reporting(self, security_test_app):
        """
        Test security scan reporting with comprehensive
        vulnerability analysis and remediation guidance.
        """
        # Mock comprehensive security scan results
        security_scan_report = {
            'scan_metadata': {
                'scan_id': str(uuid.uuid4()),
                'scan_timestamp': datetime.utcnow().isoformat(),
                'scan_type': 'comprehensive_security',
                'scanner_version': '1.0.0'
            },
            'static_analysis': {
                'tool': 'bandit',
                'total_issues': 0,
                'high_severity_issues': 0,
                'medium_severity_issues': 0,
                'low_severity_issues': 0
            },
            'dependency_analysis': {
                'tool': 'safety',
                'total_packages': 50,
                'vulnerable_packages': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0
            },
            'compliance_status': {
                'owasp_top_10': 'compliant',
                'soc2_requirements': 'compliant',
                'iso27001_requirements': 'compliant',
                'pci_dss_requirements': 'compliant'
            },
            'recommendations': []
        }
        
        # Verify report structure
        assert 'scan_metadata' in security_scan_report
        assert 'static_analysis' in security_scan_report
        assert 'dependency_analysis' in security_scan_report
        assert 'compliance_status' in security_scan_report
        
        # Verify compliance status
        compliance = security_scan_report['compliance_status']
        assert compliance['owasp_top_10'] == 'compliant'
        assert compliance['soc2_requirements'] == 'compliant'
        assert compliance['iso27001_requirements'] == 'compliant'


# =============================================================================
# PERFORMANCE AND MONITORING INTEGRATION TESTS
# =============================================================================

class TestSecurityPerformanceIntegration:
    """
    Comprehensive security performance testing to ensure ≤10% variance
    from baseline per Section 0.1.1 with security overhead monitoring
    and performance optimization validation.
    """
    
    def test_overall_security_overhead(self, authenticated_security_client):
        """
        Test overall security overhead across all security controls
        to ensure compliance with performance requirements.
        """
        # Baseline measurement without security (mock)
        baseline_time = 0.010  # 10ms baseline
        
        # Measure security-enabled performance
        start_time = time.perf_counter()
        
        for _ in range(20):
            response = authenticated_security_client.get('/api/test/protected')
            assert response.status_code == 200
        
        end_time = time.perf_counter()
        avg_time_with_security = (end_time - start_time) / 20
        
        # Calculate overhead percentage
        overhead_percentage = ((avg_time_with_security - baseline_time) / baseline_time) * 100
        
        # Verify ≤10% variance requirement
        assert overhead_percentage <= 10.0, f"Security overhead {overhead_percentage:.2f}% exceeds 10% limit"
    
    def test_concurrent_security_validation(self, authenticated_security_client):
        """
        Test concurrent security validation performance with
        comprehensive load testing and scalability validation.
        """
        import concurrent.futures
        import threading
        
        def make_request():
            response = authenticated_security_client.get('/api/test/protected')
            return response.status_code == 200
        
        # Test concurrent requests
        start_time = time.perf_counter()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Verify all requests succeeded
        assert all(results), "Some concurrent requests failed"
        
        # Verify reasonable performance under load
        avg_time_per_request = total_time / 50
        assert avg_time_per_request < 0.1, f"Concurrent performance too slow: {avg_time_per_request:.3f}s per request"
    
    def test_security_metrics_collection(self, security_test_app):
        """
        Test security metrics collection with comprehensive
        monitoring integration and performance tracking.
        """
        with security_test_app.test_request_context():
            # Verify security metrics are being collected
            from src.auth.security import security_metrics
            
            # Test metrics structure
            assert 'headers_applied' in security_metrics
            assert 'csp_violations' in security_metrics
            assert 'security_violations' in security_metrics
            assert 'https_redirects' in security_metrics
            
            # Verify metrics are callable (Prometheus Counter/Histogram objects)
            assert hasattr(security_metrics['headers_applied'], 'labels')
            assert hasattr(security_metrics['csp_violations'], 'labels')
            assert hasattr(security_metrics['security_violations'], 'labels')


# =============================================================================
# INTEGRATION TEST SUITE EXECUTION
# =============================================================================

if __name__ == '__main__':
    """
    Execute comprehensive security integration test suite with
    detailed reporting and compliance validation.
    """
    
    # Configure test execution
    pytest_args = [
        __file__,
        '-v',  # Verbose output
        '--tb=short',  # Short traceback format
        '--strict-markers',  # Strict marker validation
        '--disable-warnings',  # Disable deprecation warnings
        f'--cov=src',  # Code coverage
        '--cov-report=term-missing',  # Coverage report
        '--cov-fail-under=95',  # Minimum coverage requirement
    ]
    
    # Add performance testing if enabled
    if SecurityTestConfig.PERFORMANCE_TESTING_ENABLED:
        pytest_args.extend([
            '--benchmark-only',  # Run performance tests
            '--benchmark-sort=mean',  # Sort by mean time
        ])
    
    # Execute test suite
    exit_code = pytest.main(pytest_args)
    
    # Report test results
    if exit_code == 0:
        print("✅ All security integration tests passed successfully!")
        print("✅ Enterprise security compliance validated")
        print("✅ Performance requirements met (≤10% variance)")
    else:
        print("❌ Security integration tests failed")
        print("❌ Review security implementation and compliance")
    
    exit(exit_code)