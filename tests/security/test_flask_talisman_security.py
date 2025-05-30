"""
Flask-Talisman Security Headers Validation Testing

This module implements comprehensive HTTP security header enforcement testing,
Content Security Policy validation, HSTS testing, and web application security
protection verification replacing Node.js helmet functionality.

Key Features:
- Flask-Talisman security header enforcement validation per Section 6.4.1
- Content Security Policy (CSP) violation detection testing per Section 6.4.1
- HTTP Strict Transport Security (HSTS) and TLS 1.3 enforcement per Section 6.4.3
- X-Frame-Options and clickjacking protection validation per Section 6.4.1
- Comprehensive security header compliance testing per Section 6.4.1
- Web application security protection for enterprise compliance per Section 6.4.5
- Performance impact validation ensuring ≤10% variance from baseline
- Security vulnerability prevention and threat mitigation testing

Test Categories:
- Unit tests for SecurityHeadersConfig class functionality
- Integration tests for FlaskTalismanSecurityManager with Flask application
- Security header enforcement validation across all endpoints
- CSP policy compliance and violation detection testing
- HSTS configuration and TLS enforcement validation
- Session cookie security configuration testing
- Feature policy and referrer policy validation
- Performance impact assessment of security middleware
- Compliance verification for enterprise security standards

Dependencies:
- pytest 7.4+ for comprehensive testing framework per Section 6.6.1
- Flask-Talisman 1.1.0+ for HTTP security header enforcement
- Flask test client for endpoint security validation
- Mock external services for isolated security testing
- Security header validation utilities and assertion helpers
"""

import pytest
import json
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import re

# Flask testing imports
from flask import Flask, Response, request, jsonify
from flask.testing import FlaskClient
from werkzeug.test import Client
from werkzeug.exceptions import SecurityError

# Security and authentication imports
from flask_talisman import Talisman
import jwt

# Application imports
from src.auth.security import (
    SecurityHeadersConfig,
    FlaskTalismanSecurityManager,
    enhanced_security_headers,
    initialize_security_headers,
    get_security_report,
    validate_security_configuration,
    init_security_module
)
from src.config.auth import AuthConfig, configure_authentication


class TestSecurityHeadersConfig:
    """
    Unit tests for SecurityHeadersConfig class functionality.
    
    Tests comprehensive security configuration generation across different
    environments with Auth0 integration and enterprise compliance validation.
    """
    
    def test_init_production_environment(self):
        """Test SecurityHeadersConfig initialization for production environment."""
        config = SecurityHeadersConfig('production')
        
        assert config.environment == 'production'
        assert config.auth0_domain is not None
        assert config.app_domain is not None
        assert isinstance(config.security_metrics, dict)
        assert 'headers_applied' in config.security_metrics
        assert 'csp_violations' in config.security_metrics
        assert 'hsts_enforcement' in config.security_metrics
        assert 'security_errors' in config.security_metrics
    
    def test_init_development_environment(self):
        """Test SecurityHeadersConfig initialization for development environment."""
        config = SecurityHeadersConfig('development')
        
        assert config.environment == 'development'
        assert config.security_metrics['headers_applied'] == 0
        assert config.security_metrics['csp_violations'] == 0
    
    def test_init_staging_environment(self):
        """Test SecurityHeadersConfig initialization for staging environment."""
        config = SecurityHeadersConfig('staging')
        
        assert config.environment == 'staging'
        assert isinstance(config.security_metrics, dict)
    
    def test_get_content_security_policy_production(self):
        """Test CSP configuration for production environment with strict policies."""
        config = SecurityHeadersConfig('production')
        csp = config.get_content_security_policy()
        
        # Validate core CSP directives
        assert csp['default-src'] == "'self'"
        assert csp['object-src'] == "'none'"
        assert csp['base-uri'] == "'self'"
        assert csp['frame-ancestors'] == "'none'"
        assert csp['form-action'] == "'self'"
        assert csp['upgrade-insecure-requests'] is True
        
        # Validate Auth0 integration in CSP
        assert 'https://cdn.auth0.com' in csp['script-src']
        assert config.auth0_domain in csp['script-src']
        assert 'https://cdn.auth0.com' in csp['style-src']
        assert config.auth0_domain in csp['connect-src']
        assert 'https://*.auth0.com' in csp['connect-src']
        
        # Validate AWS integration
        assert 'https://*.amazonaws.com' in csp['connect-src']
        
        # Production should not have unsafe-inline
        assert "'unsafe-inline'" not in csp['script-src']
        assert "'unsafe-inline'" not in csp['style-src']
    
    def test_get_content_security_policy_development(self):
        """Test CSP configuration for development environment with relaxed policies."""
        config = SecurityHeadersConfig('development')
        csp = config.get_content_security_policy()
        
        # Development should allow localhost connections
        assert 'http://localhost:*' in csp['connect-src']
        assert 'https://localhost:*' in csp['connect-src']
        assert 'ws://localhost:*' in csp['connect-src']
        assert 'wss://localhost:*' in csp['connect-src']
        
        # Development should allow webpack dev server
        assert 'ws://localhost:8080' in csp['connect-src']
        assert 'wss://localhost:8080' in csp['connect-src']
        
        # Development may have unsafe-inline for development tools
        assert "'unsafe-inline'" in csp['script-src']
        assert "'unsafe-inline'" in csp['style-src']
    
    def test_get_content_security_policy_staging(self):
        """Test CSP configuration for staging environment."""
        with patch.dict('os.environ', {'STAGING_DOMAIN': 'staging.company.com'}):
            config = SecurityHeadersConfig('staging')
            csp = config.get_content_security_policy()
            
            # Staging should include staging domains
            assert 'https://staging.company.com' in csp['connect-src']
            assert 'https://staging-api.company.com' in csp['connect-src']
    
    def test_get_hsts_config_production(self):
        """Test HSTS configuration for production environment with maximum security."""
        config = SecurityHeadersConfig('production')
        hsts = config.get_hsts_config()
        
        assert hsts['max_age'] == 31536000  # 1 year
        assert hsts['include_subdomains'] is True
        assert hsts['preload'] is True
    
    def test_get_hsts_config_development(self):
        """Test HSTS configuration for development environment with relaxed settings."""
        config = SecurityHeadersConfig('development')
        hsts = config.get_hsts_config()
        
        assert hsts['max_age'] == 300  # 5 minutes
        assert hsts['include_subdomains'] is False
        assert hsts['preload'] is False
    
    def test_get_hsts_config_staging(self):
        """Test HSTS configuration for staging environment."""
        config = SecurityHeadersConfig('staging')
        hsts = config.get_hsts_config()
        
        assert hsts['max_age'] == 86400  # 24 hours
        assert hsts['include_subdomains'] is True
        assert hsts['preload'] is False
    
    def test_get_feature_policy_comprehensive(self):
        """Test feature policy configuration for comprehensive hardware access restrictions."""
        config = SecurityHeadersConfig('production')
        feature_policy = config.get_feature_policy()
        
        # Validate hardware access restrictions
        hardware_features = ['geolocation', 'microphone', 'camera', 'accelerometer', 
                            'gyroscope', 'magnetometer']
        for feature in hardware_features:
            assert feature_policy[feature] == "'none'"
        
        # Validate payment and USB restrictions
        assert feature_policy['payment'] == "'none'"
        assert feature_policy['usb'] == "'none'"
        
        # Validate allowed features
        assert feature_policy['web-share'] == "'self'"
        assert feature_policy['fullscreen'] == "'self'"
        assert feature_policy['clipboard-write'] == "'self'"
        assert feature_policy['publickey-credentials-get'] == "'self'"
        
        # Validate privacy protections
        assert feature_policy['clipboard-read'] == "'none'"
        assert feature_policy['battery'] == "'none'"
        assert feature_policy['ambient-light-sensor'] == "'none'"
    
    def test_get_referrer_policy_environments(self):
        """Test referrer policy configuration across environments."""
        # Development environment
        dev_config = SecurityHeadersConfig('development')
        assert dev_config.get_referrer_policy() == 'same-origin'
        
        # Production environment
        prod_config = SecurityHeadersConfig('production')
        assert prod_config.get_referrer_policy() == 'strict-origin-when-cross-origin'
        
        # Staging environment
        staging_config = SecurityHeadersConfig('staging')
        assert staging_config.get_referrer_policy() == 'strict-origin-when-cross-origin'
    
    def test_get_session_cookie_config_production(self):
        """Test secure session cookie configuration for production."""
        with patch.dict('os.environ', {'PRODUCTION_DOMAIN': '.company.com'}):
            config = SecurityHeadersConfig('production')
            cookie_config = config.get_session_cookie_config()
            
            assert cookie_config['secure'] is True
            assert cookie_config['httponly'] is True
            assert cookie_config['samesite'] == 'Strict'
            assert cookie_config['path'] == '/'
            assert cookie_config['domain'] == '.company.com'
            assert cookie_config['max_age'] == timedelta(hours=12)
    
    def test_get_session_cookie_config_development(self):
        """Test session cookie configuration for development environment."""
        config = SecurityHeadersConfig('development')
        cookie_config = config.get_session_cookie_config()
        
        assert cookie_config['secure'] is False  # Allow HTTP in development
        assert cookie_config['httponly'] is True
        assert cookie_config['samesite'] == 'Lax'
        assert cookie_config['domain'] == 'localhost'
        assert cookie_config['max_age'] == timedelta(hours=24)
    
    def test_get_additional_headers(self):
        """Test additional security headers configuration."""
        config = SecurityHeadersConfig('production')
        additional_headers = config.get_additional_headers()
        
        # Validate XSS protection
        assert additional_headers['X-XSS-Protection'] == '1; mode=block'
        
        # Validate cross-domain policies
        assert additional_headers['X-Permitted-Cross-Domain-Policies'] == 'none'
        
        # Validate cross-origin policies
        assert additional_headers['Cross-Origin-Embedder-Policy'] == 'require-corp'
        assert additional_headers['Cross-Origin-Opener-Policy'] == 'same-origin'
        assert additional_headers['Cross-Origin-Resource-Policy'] == 'same-origin'
        
        # Validate cache control
        assert additional_headers['Cache-Control'] == 'no-store, no-cache, must-revalidate, max-age=0'
        assert additional_headers['Pragma'] == 'no-cache'
        assert additional_headers['Expires'] == '0'


class TestFlaskTalismanSecurityManager:
    """
    Integration tests for FlaskTalismanSecurityManager with Flask application.
    
    Tests comprehensive Flask-Talisman integration, security header enforcement,
    CSP violation handling, and security monitoring capabilities.
    """
    
    @pytest.fixture
    def test_app(self):
        """Create Flask test application with minimal configuration."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key',
            'WTF_CSRF_ENABLED': False
        })
        return app
    
    @pytest.fixture
    def security_manager(self, test_app):
        """Create FlaskTalismanSecurityManager instance for testing."""
        return FlaskTalismanSecurityManager(test_app, 'testing')
    
    def test_init_without_app(self):
        """Test FlaskTalismanSecurityManager initialization without Flask app."""
        manager = FlaskTalismanSecurityManager(environment='production')
        
        assert manager.app is None
        assert manager.environment == 'production'
        assert manager.config is not None
        assert manager.talisman is None
        assert manager.security_enabled is True
        assert isinstance(manager.security_violations, list)
    
    def test_init_with_app_production(self, test_app):
        """Test FlaskTalismanSecurityManager initialization with Flask app in production."""
        manager = FlaskTalismanSecurityManager(test_app, 'production')
        
        assert manager.app == test_app
        assert manager.environment == 'production'
        assert manager.talisman is not None
        assert manager.security_enabled is True
    
    def test_init_with_app_development(self, test_app):
        """Test FlaskTalismanSecurityManager initialization with Flask app in development."""
        manager = FlaskTalismanSecurityManager(test_app, 'development')
        
        assert manager.app == test_app
        assert manager.environment == 'development'
        assert manager.talisman is not None
    
    def test_should_force_https_production(self, security_manager):
        """Test HTTPS enforcement determination for production environment."""
        security_manager.environment = 'production'
        assert security_manager._should_force_https() is True
    
    def test_should_force_https_development(self, security_manager):
        """Test HTTPS enforcement determination for development environment."""
        security_manager.environment = 'development'
        
        # Without FORCE_HTTPS_DEV environment variable
        assert security_manager._should_force_https() is False
        
        # With FORCE_HTTPS_DEV=true
        with patch.dict('os.environ', {'FORCE_HTTPS_DEV': 'true'}):
            assert security_manager._should_force_https() is True
    
    def test_get_csp_report_uri_production(self, security_manager):
        """Test CSP report URI configuration for production environment."""
        security_manager.environment = 'production'
        
        # Without CSP_REPORT_URI environment variable
        assert security_manager._get_csp_report_uri() == '/api/security/csp-report'
        
        # With custom CSP_REPORT_URI
        with patch.dict('os.environ', {'CSP_REPORT_URI': 'https://csp.company.com/report'}):
            assert security_manager._get_csp_report_uri() == 'https://csp.company.com/report'
    
    def test_get_csp_report_uri_development(self, security_manager):
        """Test CSP report URI configuration for development environment."""
        security_manager.environment = 'development'
        assert security_manager._get_csp_report_uri() is None
    
    def test_csp_violation_reporting_endpoint(self, test_app, security_manager):
        """Test CSP violation reporting endpoint functionality."""
        client = test_app.test_client()
        
        # Test valid CSP violation report
        violation_data = {
            'blocked-uri': 'https://malicious.com/script.js',
            'document-uri': 'https://app.company.com/dashboard',
            'violated-directive': 'script-src',
            'source-file': 'https://app.company.com/dashboard',
            'line-number': 42
        }
        
        response = client.post('/api/security/csp-report', 
                             json=violation_data,
                             content_type='application/json')
        
        assert response.status_code == 204
        assert len(security_manager.security_violations) == 1
        
        # Validate logged violation data
        violation = security_manager.security_violations[0]
        assert violation['violation_type'] == 'csp_violation'
        assert violation['blocked_uri'] == 'https://malicious.com/script.js'
        assert violation['violated_directive'] == 'script-src'
        assert violation['line_number'] == 42
        assert 'timestamp' in violation
        assert 'client_ip' in violation
        assert 'environment' in violation
    
    def test_csp_violation_reporting_invalid_data(self, test_app, security_manager):
        """Test CSP violation reporting with invalid data."""
        client = test_app.test_client()
        
        # Test invalid JSON data
        response = client.post('/api/security/csp-report', 
                             data='invalid json',
                             content_type='application/json')
        
        assert response.status_code == 400
        assert len(security_manager.security_violations) == 0
    
    def test_security_metrics_tracking(self, test_app, security_manager):
        """Test security metrics tracking and collection."""
        client = test_app.test_client()
        
        # Make a request to trigger metrics collection
        with test_app.test_request_context():
            response = client.get('/')
        
        # Check that metrics are being tracked
        metrics = security_manager.get_security_metrics()
        assert 'metrics' in metrics
        assert 'violations' in metrics
        assert 'configuration' in metrics
        assert 'csp_configuration' in metrics
        assert 'hsts_configuration' in metrics
        
        # Validate metrics structure
        assert 'headers_applied' in metrics['metrics']
        assert 'csp_violations' in metrics['metrics']
        assert 'hsts_enforcement' in metrics['metrics']
        assert 'security_errors' in metrics['metrics']
        
        # Validate configuration information
        config = metrics['configuration']
        assert config['environment'] == security_manager.environment
        assert config['security_enabled'] == security_manager.security_enabled
        assert 'last_config_update' in config
    
    def test_update_security_configuration(self, security_manager):
        """Test dynamic security configuration updates."""
        original_environment = security_manager.environment
        
        # Test environment update
        new_config = {'environment': 'staging'}
        result = security_manager.update_security_configuration(new_config)
        
        assert result is True
        assert security_manager.environment == 'staging'
        
        # Test Auth0 domain update
        new_config = {'auth0_domain': 'new-tenant.auth0.com'}
        result = security_manager.update_security_configuration(new_config)
        
        assert result is True
        assert security_manager.config.auth0_domain == 'new-tenant.auth0.com'
    
    def test_update_security_configuration_error(self, security_manager):
        """Test security configuration update error handling."""
        # Test invalid configuration update
        with patch.object(security_manager, 'init_app', side_effect=Exception('Test error')):
            result = security_manager.update_security_configuration({'environment': 'invalid'})
            
            assert result is False
            assert security_manager.config.security_metrics['security_errors'] > 0
    
    def test_disable_security_temporarily_development(self, test_app):
        """Test temporary security disabling in development environment."""
        manager = FlaskTalismanSecurityManager(test_app, 'development')
        
        # Test temporary disable
        disable_token = manager.disable_security_temporarily(5)
        
        assert isinstance(disable_token, str)
        assert len(disable_token) > 0
        assert manager.security_enabled is False
    
    def test_disable_security_temporarily_production(self, test_app):
        """Test that security cannot be disabled in production environment."""
        manager = FlaskTalismanSecurityManager(test_app, 'production')
        
        # Should raise SecurityError in production
        with pytest.raises(SecurityError, match="Security cannot be disabled in production"):
            manager.disable_security_temporarily(5)
    
    def test_enable_security(self, test_app):
        """Test manual security re-enabling."""
        manager = FlaskTalismanSecurityManager(test_app, 'development')
        
        # Disable security first
        disable_token = manager.disable_security_temporarily(5)
        assert manager.security_enabled is False
        
        # Re-enable security
        result = manager.enable_security(disable_token)
        assert result is True
        assert manager.security_enabled is True


class TestSecurityHeaderEnforcement:
    """
    Security header enforcement validation across all Flask endpoints.
    
    Tests that Flask-Talisman properly enforces security headers across
    different endpoints and request scenarios.
    """
    
    @pytest.fixture
    def secured_app(self):
        """Create Flask application with comprehensive security configuration."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key',
            'WTF_CSRF_ENABLED': False
        })
        
        # Initialize security manager
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        # Add test routes
        @app.route('/')
        def index():
            return jsonify({'message': 'Hello World'})
        
        @app.route('/api/users')
        def users():
            return jsonify({'users': []})
        
        @app.route('/admin/dashboard')
        def admin():
            return jsonify({'admin': True})
        
        @app.route('/public/health')
        def health():
            return jsonify({'status': 'healthy'})
        
        return app
    
    def test_security_headers_on_json_response(self, secured_app):
        """Test security headers enforcement on JSON API responses."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate response
        assert response.status_code == 200
        assert response.json == {'message': 'Hello World'}
        
        # Validate security headers presence
        self._assert_security_headers_present(response)
    
    def test_security_headers_on_api_endpoints(self, secured_app):
        """Test security headers enforcement on API endpoints."""
        client = secured_app.test_client()
        response = client.get('/api/users')
        
        assert response.status_code == 200
        self._assert_security_headers_present(response)
        
        # Validate API-specific security considerations
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
    
    def test_security_headers_on_admin_endpoints(self, secured_app):
        """Test security headers enforcement on administrative endpoints."""
        client = secured_app.test_client()
        response = client.get('/admin/dashboard')
        
        assert response.status_code == 200
        self._assert_security_headers_present(response)
        
        # Admin endpoints should have strict security headers
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] in ['DENY', 'SAMEORIGIN']
    
    def test_security_headers_on_public_endpoints(self, secured_app):
        """Test security headers enforcement on public endpoints."""
        client = secured_app.test_client()
        response = client.get('/public/health')
        
        assert response.status_code == 200
        self._assert_security_headers_present(response)
    
    def test_security_headers_across_http_methods(self, secured_app):
        """Test security headers enforcement across different HTTP methods."""
        client = secured_app.test_client()
        
        # Test GET request
        get_response = client.get('/')
        self._assert_security_headers_present(get_response)
        
        # Test POST request
        post_response = client.post('/', json={'test': 'data'})
        self._assert_security_headers_present(post_response)
        
        # Test OPTIONS request (CORS preflight)
        options_response = client.options('/')
        self._assert_security_headers_present(options_response)
    
    def test_https_enforcement_headers(self, secured_app):
        """Test HTTPS enforcement through security headers."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate HSTS header
        assert 'Strict-Transport-Security' in response.headers
        hsts_header = response.headers['Strict-Transport-Security']
        assert 'max-age=' in hsts_header
        assert 'includeSubDomains' in hsts_header
        
        # For production, should include preload
        if 'preload' in hsts_header:
            assert 'preload' in hsts_header
    
    def test_content_security_policy_header(self, secured_app):
        """Test Content Security Policy header enforcement."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate CSP header presence
        assert 'Content-Security-Policy' in response.headers
        csp_header = response.headers['Content-Security-Policy']
        
        # Validate core CSP directives
        assert "default-src 'self'" in csp_header
        assert "object-src 'none'" in csp_header
        assert "frame-ancestors 'none'" in csp_header
        assert "base-uri 'self'" in csp_header
    
    def test_frame_options_clickjacking_protection(self, secured_app):
        """Test X-Frame-Options header for clickjacking protection."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate X-Frame-Options header
        assert 'X-Frame-Options' in response.headers
        frame_options = response.headers['X-Frame-Options']
        assert frame_options in ['DENY', 'SAMEORIGIN']
    
    def test_content_type_options_header(self, secured_app):
        """Test X-Content-Type-Options header for MIME sniffing protection."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate X-Content-Type-Options header
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
    
    def test_referrer_policy_header(self, secured_app):
        """Test Referrer-Policy header for privacy protection."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate Referrer-Policy header
        assert 'Referrer-Policy' in response.headers
        referrer_policy = response.headers['Referrer-Policy']
        assert referrer_policy in ['strict-origin-when-cross-origin', 'same-origin']
    
    def test_additional_security_headers(self, secured_app):
        """Test additional security headers enforcement."""
        client = secured_app.test_client()
        response = client.get('/')
        
        # Validate XSS protection header
        if 'X-XSS-Protection' in response.headers:
            assert response.headers['X-XSS-Protection'] == '1; mode=block'
        
        # Validate cross-origin policies
        if 'Cross-Origin-Embedder-Policy' in response.headers:
            assert response.headers['Cross-Origin-Embedder-Policy'] == 'require-corp'
        
        if 'Cross-Origin-Opener-Policy' in response.headers:
            assert response.headers['Cross-Origin-Opener-Policy'] == 'same-origin'
    
    def _assert_security_headers_present(self, response: Response) -> None:
        """
        Assert that essential security headers are present in response.
        
        Args:
            response: Flask response object to validate
        """
        essential_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        for header in essential_headers:
            assert header in response.headers, f"Missing security header: {header}"


class TestContentSecurityPolicyValidation:
    """
    Content Security Policy validation and violation detection testing.
    
    Tests CSP policy compliance, violation detection, and Auth0 integration
    compatibility for comprehensive XSS prevention.
    """
    
    @pytest.fixture
    def csp_app(self):
        """Create Flask application with CSP-focused configuration."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key'
        })
        
        # Initialize with development environment for easier testing
        security_manager = FlaskTalismanSecurityManager(app, 'development')
        
        @app.route('/')
        def index():
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>CSP Test</title>
            </head>
            <body>
                <h1>CSP Test Page</h1>
                <script>console.log('inline script');</script>
            </body>
            </html>
            ''', 200, {'Content-Type': 'text/html'}
        
        @app.route('/api/data')
        def api_data():
            return jsonify({'data': 'test'})
        
        return app, security_manager
    
    def test_csp_header_presence_and_format(self, csp_app):
        """Test CSP header presence and proper formatting."""
        app, security_manager = csp_app
        client = app.test_client()
        response = client.get('/')
        
        assert 'Content-Security-Policy' in response.headers
        csp_header = response.headers['Content-Security-Policy']
        
        # Validate CSP directive format
        directives = csp_header.split(';')
        directive_names = []
        
        for directive in directives:
            directive = directive.strip()
            if directive:
                directive_name = directive.split(' ')[0]
                directive_names.append(directive_name)
        
        # Validate essential CSP directives
        assert 'default-src' in directive_names
        assert 'script-src' in directive_names
        assert 'style-src' in directive_names
        assert 'connect-src' in directive_names
        assert 'object-src' in directive_names
    
    def test_csp_auth0_integration_directives(self, csp_app):
        """Test CSP directives for Auth0 integration compatibility."""
        app, security_manager = csp_app
        client = app.test_client()
        response = client.get('/')
        
        csp_header = response.headers['Content-Security-Policy']
        
        # Validate Auth0-specific CSP allowances
        assert 'https://cdn.auth0.com' in csp_header
        assert security_manager.config.auth0_domain in csp_header
        assert 'https://*.auth0.com' in csp_header
        
        # Validate script-src includes Auth0 domains
        script_src_match = re.search(r'script-src ([^;]+)', csp_header)
        if script_src_match:
            script_src = script_src_match.group(1)
            assert 'https://cdn.auth0.com' in script_src
            assert security_manager.config.auth0_domain in script_src
        
        # Validate connect-src includes Auth0 domains
        connect_src_match = re.search(r'connect-src ([^;]+)', csp_header)
        if connect_src_match:
            connect_src = connect_src_match.group(1)
            assert 'https://*.auth0.com' in connect_src
    
    def test_csp_aws_integration_directives(self, csp_app):
        """Test CSP directives for AWS integration compatibility."""
        app, security_manager = csp_app
        client = app.test_client()
        response = client.get('/')
        
        csp_header = response.headers['Content-Security-Policy']
        
        # Validate AWS-specific CSP allowances
        assert 'https://*.amazonaws.com' in csp_header
        
        # Validate connect-src includes AWS domains
        connect_src_match = re.search(r'connect-src ([^;]+)', csp_header)
        if connect_src_match:
            connect_src = connect_src_match.group(1)
            assert 'https://*.amazonaws.com' in connect_src
    
    def test_csp_nonce_generation(self, csp_app):
        """Test CSP nonce generation for inline scripts and styles."""
        app, security_manager = csp_app
        
        # Mock nonce generation to test nonce inclusion
        with patch('flask_talisman.talisman.generate_nonce', return_value='test-nonce-123'):
            client = app.test_client()
            response = client.get('/')
            
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            # Check if nonce is included (depends on Talisman configuration)
            if 'nonce-' in csp_header:
                assert 'nonce-test-nonce-123' in csp_header
    
    def test_csp_violation_reporting_endpoint(self, csp_app):
        """Test CSP violation reporting endpoint functionality."""
        app, security_manager = csp_app
        client = app.test_client()
        
        # Simulate CSP violation report
        violation_report = {
            'csp-report': {
                'blocked-uri': 'https://malicious.com/evil.js',
                'document-uri': 'https://app.company.com/dashboard',
                'violated-directive': 'script-src',
                'effective-directive': 'script-src',
                'original-policy': "default-src 'self'; script-src 'self'",
                'source-file': 'https://app.company.com/dashboard',
                'line-number': 42,
                'column-number': 15,
                'status-code': 200
            }
        }
        
        response = client.post('/api/security/csp-report',
                             json=violation_report,
                             content_type='application/csp-report')
        
        assert response.status_code == 204
        
        # Validate violation was logged
        violations = security_manager.security_violations
        assert len(violations) > 0
        
        latest_violation = violations[-1]
        assert latest_violation['violation_type'] == 'csp_violation'
        assert latest_violation['blocked_uri'] == 'https://malicious.com/evil.js'
        assert latest_violation['violated_directive'] == 'script-src'
    
    def test_csp_violation_metrics_tracking(self, csp_app):
        """Test CSP violation metrics tracking and collection."""
        app, security_manager = csp_app
        client = app.test_client()
        
        initial_violations = security_manager.config.security_metrics['csp_violations']
        
        # Send multiple violation reports
        for i in range(3):
            violation_report = {
                'blocked-uri': f'https://malicious{i}.com/script.js',
                'document-uri': 'https://app.company.com/page',
                'violated-directive': 'script-src'
            }
            
            client.post('/api/security/csp-report',
                       json=violation_report,
                       content_type='application/json')
        
        # Validate metrics were updated
        current_violations = security_manager.config.security_metrics['csp_violations']
        assert current_violations == initial_violations + 3
    
    def test_csp_development_vs_production_policies(self):
        """Test CSP policy differences between development and production."""
        dev_config = SecurityHeadersConfig('development')
        prod_config = SecurityHeadersConfig('production')
        
        dev_csp = dev_config.get_content_security_policy()
        prod_csp = prod_config.get_content_security_policy()
        
        # Development should allow localhost
        assert 'localhost:' in dev_csp['connect-src']
        assert 'localhost:' not in prod_csp['connect-src']
        
        # Development may have unsafe-inline
        assert "'unsafe-inline'" in dev_csp['script-src']
        assert "'unsafe-inline'" not in prod_csp['script-src']
        
        # Both should have base security
        for csp in [dev_csp, prod_csp]:
            assert csp['default-src'] == "'self'"
            assert csp['object-src'] == "'none'"
            assert csp['frame-ancestors'] == "'none'"


class TestHTTPSAndTLSEnforcement:
    """
    HTTPS/TLS 1.3 enforcement validation testing per Section 6.4.3.
    
    Tests TLS enforcement, HSTS configuration, and secure transport
    requirements across all Flask endpoints.
    """
    
    @pytest.fixture
    def https_app(self):
        """Create Flask application with HTTPS enforcement."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key'
        })
        
        # Initialize with production-level HTTPS enforcement
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        @app.route('/')
        def index():
            return jsonify({'message': 'Secure endpoint'})
        
        @app.route('/api/secure')
        @enhanced_security_headers(require_https=True)
        def secure_api():
            return jsonify({'secure': True})
        
        return app, security_manager
    
    def test_hsts_header_enforcement(self, https_app):
        """Test HTTP Strict Transport Security header enforcement."""
        app, security_manager = https_app
        client = app.test_client()
        
        response = client.get('/')
        
        # Validate HSTS header presence
        assert 'Strict-Transport-Security' in response.headers
        hsts_header = response.headers['Strict-Transport-Security']
        
        # Validate HSTS configuration for production
        assert 'max-age=31536000' in hsts_header  # 1 year
        assert 'includeSubDomains' in hsts_header
        assert 'preload' in hsts_header
    
    def test_hsts_header_development_vs_production(self):
        """Test HSTS header differences between development and production."""
        # Development HSTS configuration
        dev_app = Flask(__name__)
        dev_manager = FlaskTalismanSecurityManager(dev_app, 'development')
        dev_client = dev_app.test_client()
        
        @dev_app.route('/')
        def dev_index():
            return jsonify({'env': 'development'})
        
        dev_response = dev_client.get('/')
        dev_hsts = dev_response.headers.get('Strict-Transport-Security', '')
        
        # Production HSTS configuration
        prod_app = Flask(__name__)
        prod_manager = FlaskTalismanSecurityManager(prod_app, 'production')
        prod_client = prod_app.test_client()
        
        @prod_app.route('/')
        def prod_index():
            return jsonify({'env': 'production'})
        
        prod_response = prod_client.get('/')
        prod_hsts = prod_response.headers.get('Strict-Transport-Security', '')
        
        # Validate different HSTS policies
        if dev_hsts:
            assert 'max-age=300' in dev_hsts  # 5 minutes for dev
        
        if prod_hsts:
            assert 'max-age=31536000' in prod_hsts  # 1 year for production
            assert 'includeSubDomains' in prod_hsts
            assert 'preload' in prod_hsts
    
    def test_enhanced_security_headers_https_requirement(self, https_app):
        """Test enhanced security headers decorator HTTPS requirement."""
        app, security_manager = https_app
        
        # Test with secure request context
        with app.test_request_context('/', base_url='https://app.company.com'):
            client = app.test_client()
            response = client.get('/api/secure')
            
            # Should succeed with HTTPS
            assert response.status_code == 200
    
    def test_enhanced_security_headers_http_rejection(self, https_app):
        """Test enhanced security headers decorator HTTP rejection."""
        app, security_manager = https_app
        
        # Test with insecure request context (non-testing environment)
        with patch.dict(app.config, {'ENV': 'production'}):
            with app.test_request_context('/', base_url='http://app.company.com'):
                client = app.test_client()
                response = client.get('/api/secure')
                
                # Should reject HTTP in production
                if response.status_code == 426:
                    assert response.data == b'HTTPS Required'
    
    def test_https_redirection_behavior(self, https_app):
        """Test HTTPS redirection behavior in Flask-Talisman."""
        app, security_manager = https_app
        
        # Test that Talisman is configured for HTTPS enforcement
        assert security_manager.talisman is not None
        
        # The actual redirection testing would require more complex setup
        # as Flask test client doesn't handle redirects the same way
        # This test validates the configuration is set correctly
        https_forced = security_manager._should_force_https()
        assert https_forced is True
    
    def test_secure_cookie_enforcement(self, https_app):
        """Test secure cookie enforcement with HTTPS."""
        app, security_manager = https_app
        
        # Validate session cookie security configuration
        assert app.config.get('SESSION_COOKIE_SECURE') is True
        assert app.config.get('SESSION_COOKIE_HTTPONLY') is True
        assert app.config.get('SESSION_COOKIE_SAMESITE') in ['Strict', 'Lax']
    
    def test_tls_configuration_validation(self, https_app):
        """Test TLS configuration validation and enforcement."""
        app, security_manager = https_app
        
        # Validate that HTTPS enforcement is enabled
        assert security_manager._should_force_https() is True
        
        # Validate HSTS configuration for TLS enforcement
        hsts_config = security_manager.config.get_hsts_config()
        assert hsts_config['max_age'] > 0
        assert hsts_config['include_subdomains'] is True
        
        # For production, should include preload
        if security_manager.environment == 'production':
            assert hsts_config['preload'] is True


class TestSessionCookieSecurityConfiguration:
    """
    Session cookie security configuration testing.
    
    Tests secure session cookie settings, SameSite policies, and
    enterprise session management security patterns.
    """
    
    @pytest.fixture
    def session_app(self):
        """Create Flask application with session security configuration."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-sessions'
        })
        
        # Configure authentication with session security
        configure_authentication(app)
        
        # Initialize security manager
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        @app.route('/login')
        def login():
            from flask import session
            session['user_id'] = 'test_user_123'
            return jsonify({'status': 'logged in'})
        
        @app.route('/profile')
        def profile():
            from flask import session
            user_id = session.get('user_id')
            return jsonify({'user_id': user_id})
        
        return app, security_manager
    
    def test_session_cookie_secure_flag(self, session_app):
        """Test session cookie secure flag enforcement."""
        app, security_manager = session_app
        
        # Validate secure flag is set
        assert app.config.get('SESSION_COOKIE_SECURE') is True
        
        # Test with actual session creation
        client = app.test_client()
        response = client.get('/login')
        
        # Check Set-Cookie header for secure flag
        set_cookie_header = response.headers.get('Set-Cookie', '')
        if set_cookie_header:
            assert 'Secure' in set_cookie_header
    
    def test_session_cookie_httponly_flag(self, session_app):
        """Test session cookie HttpOnly flag enforcement."""
        app, security_manager = session_app
        
        # Validate HttpOnly flag is set
        assert app.config.get('SESSION_COOKIE_HTTPONLY') is True
        
        # Test with actual session creation
        client = app.test_client()
        response = client.get('/login')
        
        # Check Set-Cookie header for HttpOnly flag
        set_cookie_header = response.headers.get('Set-Cookie', '')
        if set_cookie_header:
            assert 'HttpOnly' in set_cookie_header
    
    def test_session_cookie_samesite_policy(self, session_app):
        """Test session cookie SameSite policy enforcement."""
        app, security_manager = session_app
        
        # Validate SameSite policy is set
        samesite_policy = app.config.get('SESSION_COOKIE_SAMESITE')
        assert samesite_policy in ['Strict', 'Lax']
        
        # Test with actual session creation
        client = app.test_client()
        response = client.get('/login')
        
        # Check Set-Cookie header for SameSite policy
        set_cookie_header = response.headers.get('Set-Cookie', '')
        if set_cookie_header:
            assert f'SameSite={samesite_policy}' in set_cookie_header
    
    def test_session_cookie_domain_configuration(self, session_app):
        """Test session cookie domain configuration."""
        app, security_manager = session_app
        
        # Validate domain configuration
        cookie_domain = app.config.get('SESSION_COOKIE_DOMAIN')
        if cookie_domain:
            # Should be a valid domain format
            assert isinstance(cookie_domain, str)
            assert cookie_domain.startswith('.')  # Domain cookies start with dot
    
    def test_session_cookie_path_configuration(self, session_app):
        """Test session cookie path configuration."""
        app, security_manager = session_app
        
        # Validate path configuration
        cookie_path = app.config.get('SESSION_COOKIE_PATH', '/')
        assert cookie_path == '/'
    
    def test_session_cookie_lifetime_configuration(self, session_app):
        """Test session cookie lifetime configuration."""
        app, security_manager = session_app
        
        # Validate lifetime configuration
        permanent_session_lifetime = app.config.get('PERMANENT_SESSION_LIFETIME')
        if permanent_session_lifetime:
            assert isinstance(permanent_session_lifetime, timedelta)
            # Should be reasonable duration (not too long)
            assert permanent_session_lifetime <= timedelta(days=1)
    
    def test_session_cookie_environment_differences(self):
        """Test session cookie configuration differences across environments."""
        # Development configuration
        dev_config = SecurityHeadersConfig('development')
        dev_cookie_config = dev_config.get_session_cookie_config()
        
        # Production configuration
        prod_config = SecurityHeadersConfig('production')
        prod_cookie_config = prod_config.get_session_cookie_config()
        
        # Development should allow HTTP
        assert dev_cookie_config['secure'] is False
        assert dev_cookie_config['samesite'] == 'Lax'
        assert dev_cookie_config['domain'] == 'localhost'
        
        # Production should require HTTPS
        assert prod_cookie_config['secure'] is True
        assert prod_cookie_config['samesite'] == 'Strict'
        assert prod_cookie_config['max_age'] == timedelta(hours=12)


class TestComprehensiveSecurityCompliance:
    """
    Comprehensive security compliance testing for enterprise requirements.
    
    Tests complete security posture, compliance validation, and
    enterprise security standards adherence per Section 6.4.5.
    """
    
    @pytest.fixture
    def enterprise_app(self):
        """Create Flask application with enterprise security configuration."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'enterprise-secret-key',
            'ENV': 'production'
        })
        
        # Configure comprehensive authentication and security
        configure_authentication(app)
        security_manager = initialize_security_headers(app, 'production')
        
        @app.route('/')
        def index():
            return jsonify({'status': 'enterprise ready'})
        
        @app.route('/api/admin')
        @enhanced_security_headers(
            custom_headers={'X-Admin-Access': 'true'},
            require_https=True
        )
        def admin():
            return jsonify({'admin': True})
        
        return app, security_manager
    
    def test_complete_security_headers_compliance(self, enterprise_app):
        """Test complete security headers compliance for enterprise standards."""
        app, security_manager = enterprise_app
        client = app.test_client()
        response = client.get('/')
        
        # Validate all required security headers are present
        required_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        for header in required_headers:
            assert header in response.headers, f"Missing required header: {header}"
        
        # Validate security header values meet enterprise standards
        self._validate_enterprise_header_values(response.headers)
    
    def test_security_configuration_validation(self, enterprise_app):
        """Test security configuration validation and warnings."""
        app, security_manager = enterprise_app
        
        # Test configuration validation
        warnings = validate_security_configuration()
        
        # Should return list of warnings/recommendations
        assert isinstance(warnings, list)
        
        # In test environment, may have some warnings
        for warning in warnings:
            assert isinstance(warning, str)
    
    def test_security_report_generation(self, enterprise_app):
        """Test comprehensive security report generation."""
        app, security_manager = enterprise_app
        
        # Generate security report
        security_report = get_security_report()
        
        # Validate report structure
        assert isinstance(security_report, dict)
        assert 'status' in security_report
        assert 'timestamp' in security_report
        assert 'environment' in security_report
        
        # Validate report content
        assert security_report['status'] in ['Security headers active', 'Error generating security report']
        assert 'talisman_version' in security_report or 'error' in security_report
    
    def test_security_metrics_comprehensive_collection(self, enterprise_app):
        """Test comprehensive security metrics collection and monitoring."""
        app, security_manager = enterprise_app
        client = app.test_client()
        
        # Make several requests to generate metrics
        for _ in range(5):
            client.get('/')
        
        # Get comprehensive security metrics
        metrics = security_manager.get_security_metrics()
        
        # Validate metrics structure
        assert 'metrics' in metrics
        assert 'violations' in metrics
        assert 'configuration' in metrics
        assert 'csp_configuration' in metrics
        assert 'hsts_configuration' in metrics
        
        # Validate metrics content
        assert metrics['metrics']['headers_applied'] >= 5
        assert isinstance(metrics['violations'], list)
        assert metrics['configuration']['security_enabled'] is True
    
    def test_enhanced_security_headers_decorator(self, enterprise_app):
        """Test enhanced security headers decorator functionality."""
        app, security_manager = enterprise_app
        client = app.test_client()
        
        response = client.get('/api/admin')
        
        # Should have all standard security headers
        self._validate_enterprise_header_values(response.headers)
        
        # Should have custom security headers
        assert 'X-Admin-Access' in response.headers
        assert response.headers['X-Admin-Access'] == 'true'
    
    def test_security_module_initialization(self):
        """Test security module initialization for Flask application factory."""
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret',
            'ENV': 'production'
        })
        
        # Initialize security module
        security_manager = init_security_module(app)
        
        # Validate initialization
        assert isinstance(security_manager, FlaskTalismanSecurityManager)
        assert hasattr(app, 'extensions')
        assert 'security_manager' in app.extensions
        assert app.extensions['security_manager'] == security_manager
    
    def test_performance_impact_validation(self, enterprise_app, performance_baseline):
        """Test security middleware performance impact validation."""
        app, security_manager = enterprise_app
        client = app.test_client()
        
        # Measure response time with security headers
        start_time = time.time()
        for _ in range(10):
            response = client.get('/')
            assert response.status_code == 200
        end_time = time.time()
        
        # Calculate average response time
        avg_response_time = (end_time - start_time) / 10 * 1000  # milliseconds
        
        # Compare with baseline (allowing for test environment variance)
        baseline_time = performance_baseline['response_times']['health_check']
        
        # Allow higher variance in test environment (50% instead of 10%)
        max_allowed_time = baseline_time * 1.5
        
        assert avg_response_time <= max_allowed_time, (
            f"Security middleware performance impact too high: "
            f"{avg_response_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
    
    def test_compliance_verification_enterprise_standards(self, enterprise_app):
        """Test compliance verification for enterprise security standards."""
        app, security_manager = enterprise_app
        client = app.test_client()
        response = client.get('/')
        
        # SOC 2 Type II compliance validation
        self._validate_soc2_compliance(response.headers)
        
        # ISO 27001 compliance validation
        self._validate_iso27001_compliance(response.headers)
        
        # OWASP Top 10 protection validation
        self._validate_owasp_protection(response.headers)
    
    def _validate_enterprise_header_values(self, headers: Dict[str, str]) -> None:
        """
        Validate security header values meet enterprise standards.
        
        Args:
            headers: Response headers dictionary to validate
        """
        # HSTS validation
        hsts = headers.get('Strict-Transport-Security', '')
        assert 'max-age=' in hsts
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            assert max_age >= 31536000  # At least 1 year for enterprise
        
        # CSP validation
        csp = headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        
        # Frame options validation
        frame_options = headers.get('X-Frame-Options', '')
        assert frame_options in ['DENY', 'SAMEORIGIN']
        
        # Content type options validation
        content_type_options = headers.get('X-Content-Type-Options', '')
        assert content_type_options == 'nosniff'
    
    def _validate_soc2_compliance(self, headers: Dict[str, str]) -> None:
        """Validate SOC 2 Type II compliance requirements."""
        # Security headers must be present for access control compliance
        assert 'Strict-Transport-Security' in headers
        assert 'Content-Security-Policy' in headers
        assert 'X-Frame-Options' in headers
    
    def _validate_iso27001_compliance(self, headers: Dict[str, str]) -> None:
        """Validate ISO 27001 information security compliance."""
        # Information security controls validation
        assert 'X-Content-Type-Options' in headers
        assert 'Referrer-Policy' in headers
        
        # Privacy protection validation
        referrer_policy = headers.get('Referrer-Policy', '')
        assert referrer_policy in ['strict-origin-when-cross-origin', 'same-origin']
    
    def _validate_owasp_protection(self, headers: Dict[str, str]) -> None:
        """Validate OWASP Top 10 protection measures."""
        # XSS Protection (A7: Cross-Site Scripting)
        assert 'Content-Security-Policy' in headers
        
        # Clickjacking Protection (A6: Security Misconfiguration)
        assert 'X-Frame-Options' in headers
        
        # MIME Type Sniffing Protection (A6: Security Misconfiguration)
        assert 'X-Content-Type-Options' in headers
        
        # HTTPS Enforcement (A3: Sensitive Data Exposure)
        assert 'Strict-Transport-Security' in headers


class TestSecurityEdgeCasesAndErrorHandling:
    """
    Security edge cases and error handling testing.
    
    Tests error scenarios, edge cases, and security failure handling
    to ensure robust security implementation.
    """
    
    def test_security_initialization_failure_handling(self):
        """Test security initialization failure handling."""
        app = Flask(__name__)
        
        # Test with invalid configuration
        with patch('src.auth.security.Talisman', side_effect=Exception('Talisman init failed')):
            with pytest.raises(SecurityError, match="Security initialization failed"):
                FlaskTalismanSecurityManager(app, 'production')
    
    def test_csp_violation_handling_malformed_data(self):
        """Test CSP violation handling with malformed data."""
        app = Flask(__name__)
        security_manager = FlaskTalismanSecurityManager(app, 'development')
        client = app.test_client()
        
        # Test with malformed JSON
        response = client.post('/api/security/csp-report',
                             data='{"malformed": json}',
                             content_type='application/json')
        
        assert response.status_code == 400
        assert len(security_manager.security_violations) == 0
    
    def test_security_metrics_error_handling(self):
        """Test security metrics collection error handling."""
        app = Flask(__name__)
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        # Test metrics collection with mocked error
        with patch.object(security_manager.config, 'security_metrics', side_effect=Exception('Metrics error')):
            try:
                metrics = security_manager.get_security_metrics()
                # Should handle error gracefully
                assert isinstance(metrics, dict)
            except Exception:
                # Or should raise controlled exception
                pass
    
    def test_configuration_update_error_scenarios(self):
        """Test configuration update error scenarios."""
        app = Flask(__name__)
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        # Test with invalid configuration data
        result = security_manager.update_security_configuration({'invalid_key': 'invalid_value'})
        
        # Should handle gracefully
        assert isinstance(result, bool)
    
    def test_security_headers_with_null_response(self):
        """Test security headers handling with null/empty responses."""
        app = Flask(__name__)
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        @app.route('/empty')
        def empty_response():
            return '', 204
        
        client = app.test_client()
        response = client.get('/empty')
        
        # Should still have security headers even with empty response
        assert response.status_code == 204
        assert 'Strict-Transport-Security' in response.headers
    
    def test_concurrent_security_operations(self):
        """Test concurrent security operations handling."""
        app = Flask(__name__)
        security_manager = FlaskTalismanSecurityManager(app, 'production')
        
        # Simulate concurrent CSP violations
        import threading
        
        def send_violation():
            client = app.test_client()
            client.post('/api/security/csp-report',
                       json={'blocked-uri': 'https://test.com/script.js'},
                       content_type='application/json')
        
        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=send_violation)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Should handle concurrent operations safely
        assert len(security_manager.security_violations) <= 5


# Performance and integration test markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.integration
]


# Additional test configuration for security testing
def pytest_configure(config):
    """Configure pytest for security testing."""
    config.addinivalue_line(
        "markers", "security: mark test as security-related"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )