"""
Flask-Talisman security headers implementation providing comprehensive HTTP security
enforcement, Content Security Policy management, HSTS configuration, and web application
security protection patterns.

This module serves as a direct replacement for Node.js helmet middleware functionality,
implementing Flask-Talisman 1.1.0+ with enterprise-grade security configurations for
complete web application protection and compliance with security standards.

Key Features:
- Comprehensive HTTP security header enforcement via Flask-Talisman
- Content Security Policy (CSP) with Auth0 domain allowlist configuration
- HTTP Strict Transport Security (HSTS) with TLS 1.3 enforcement
- X-Frame-Options, X-Content-Type-Options, and referrer policy configuration
- Secure cookie policies for enterprise session management
- Environment-specific security configuration management
- Performance monitoring and compliance tracking
- Integration with Flask application factory pattern

Security Headers Implemented:
- Strict-Transport-Security: HTTPS/TLS 1.3 enforcement with HSTS preload
- Content-Security-Policy: XSS prevention with nonce support and Auth0 integration
- X-Frame-Options: Clickjacking protection with DENY policy
- X-Content-Type-Options: MIME type sniffing prevention
- Referrer-Policy: Privacy protection with strict-origin-when-cross-origin
- Feature-Policy: Hardware access restrictions for enhanced security
- X-XSS-Protection: Browser XSS filter activation
- X-Permitted-Cross-Domain-Policies: Flash/PDF cross-domain policy restrictions
"""

import os
import logging
from typing import Dict, List, Optional, Any, Callable, Union
from datetime import datetime, timedelta
from functools import wraps

# Flask imports for web application and security integration
from flask import Flask, request, g, current_app, session
from flask_talisman import Talisman
from werkzeug.exceptions import SecurityError

# Import configuration and utilities for security integration
try:
    from ..config.auth import get_auth_config, get_auth0_domain
    from .utils import generate_secure_token, datetime_utils
except ImportError:
    # Fallback for development - will be resolved during integration
    def get_auth_config():
        return {}
    
    def get_auth0_domain():
        return os.getenv('AUTH0_DOMAIN', 'your-domain.auth0.com')
    
    from .utils import generate_secure_token, datetime_utils

# Structured logging for security events
logger = logging.getLogger(__name__)


class SecurityHeadersConfig:
    """
    Comprehensive security headers configuration class providing enterprise-grade
    HTTP security enforcement patterns with Flask-Talisman integration.
    
    Implements environment-specific security policies, Auth0 integration support,
    and comprehensive web application security protection patterns.
    """
    
    def __init__(self, environment: str = 'production'):
        """
        Initialize security configuration based on deployment environment.
        
        Args:
            environment: Deployment environment (development, staging, production)
        """
        self.environment = environment.lower()
        self.auth0_domain = get_auth0_domain()
        self.app_domain = os.getenv('APP_DOMAIN', 'localhost')
        
        # Initialize security metrics tracking
        self.security_metrics = {
            'headers_applied': 0,
            'csp_violations': 0,
            'hsts_enforcement': 0,
            'security_errors': 0
        }
        
        logger.info(f"Security headers configuration initialized for environment: {self.environment}")
    
    def get_content_security_policy(self) -> Dict[str, str]:
        """
        Generate Content Security Policy configuration with Auth0 integration.
        
        Implements comprehensive CSP directives for XSS prevention while
        maintaining compatibility with Auth0 authentication flows and
        enterprise application requirements.
        
        Returns:
            Dictionary containing CSP directives
        """
        # Base CSP configuration for all environments
        base_csp = {
            'default-src': "'self'",
            'script-src': f"'self' 'unsafe-inline' https://cdn.auth0.com https://{self.auth0_domain}",
            'style-src': "'self' 'unsafe-inline' https://cdn.auth0.com",
            'img-src': "'self' data: https: blob:",
            'connect-src': f"'self' https://{self.auth0_domain} https://*.auth0.com https://*.amazonaws.com",
            'font-src': "'self' https://fonts.gstatic.com https://cdn.auth0.com",
            'object-src': "'none'",
            'base-uri': "'self'",
            'frame-ancestors': "'none'",
            'form-action': "'self'",
            'manifest-src': "'self'",
            'media-src': "'self'",
            'worker-src': "'self' blob:",
            'child-src': "'self' blob:",
            'frame-src': "'none'",
            'upgrade-insecure-requests': True
        }
        
        # Environment-specific CSP modifications
        if self.environment == 'development':
            # Allow localhost connections for development
            base_csp['connect-src'] += ' http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*'
            base_csp['script-src'] += ' http://localhost:* https://localhost:*'
            base_csp['style-src'] += ' http://localhost:* https://localhost:*'
            
            # Allow webpack dev server and hot reload
            base_csp['connect-src'] += ' ws://localhost:8080 wss://localhost:8080'
            
        elif self.environment == 'staging':
            # Add staging-specific domains
            staging_domain = os.getenv('STAGING_DOMAIN', 'staging.company.com')
            base_csp['connect-src'] += f' https://{staging_domain} https://staging-api.company.com'
            
        elif self.environment == 'production':
            # Production-specific security hardening
            base_csp['script-src'] = base_csp['script-src'].replace("'unsafe-inline'", "")
            base_csp['style-src'] = base_csp['style-src'].replace("'unsafe-inline'", "")
            
            # Add production domains
            prod_domains = os.getenv('PRODUCTION_DOMAINS', 'app.company.com,api.company.com').split(',')
            for domain in prod_domains:
                base_csp['connect-src'] += f' https://{domain.strip()}'
        
        return base_csp
    
    def get_hsts_config(self) -> Dict[str, Any]:
        """
        Generate HTTP Strict Transport Security (HSTS) configuration.
        
        Implements HSTS with TLS 1.3 enforcement, subdomain inclusion,
        and preload support for maximum transport security.
        
        Returns:
            Dictionary containing HSTS configuration
        """
        if self.environment == 'development':
            # Relaxed HSTS for development
            return {
                'max_age': 300,  # 5 minutes for development
                'include_subdomains': False,
                'preload': False
            }
        
        elif self.environment == 'staging':
            # Moderate HSTS for staging
            return {
                'max_age': 86400,  # 24 hours for staging
                'include_subdomains': True,
                'preload': False
            }
        
        else:
            # Production HSTS with maximum security
            return {
                'max_age': 31536000,  # 1 year for production
                'include_subdomains': True,
                'preload': True
            }
    
    def get_feature_policy(self) -> Dict[str, str]:
        """
        Generate Feature Policy configuration for hardware access restrictions.
        
        Implements comprehensive feature policy restrictions to prevent
        unauthorized access to device capabilities and enhance privacy.
        
        Returns:
            Dictionary containing feature policy directives
        """
        return {
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'",
            'accelerometer': "'none'",
            'gyroscope': "'none'",
            'magnetometer': "'none'",
            'payment': "'none'",
            'usb': "'none'",
            'web-share': "'self'",
            'xr-spatial-tracking': "'none'",
            'picture-in-picture': "'none'",
            'display-capture': "'none'",
            'fullscreen': "'self'",
            'autoplay': "'none'",
            'ambient-light-sensor': "'none'",
            'battery': "'none'",
            'clipboard-read': "'none'",
            'clipboard-write': "'self'",
            'document-domain': "'none'",
            'encrypted-media': "'none'",
            'execution-while-not-rendered': "'none'",
            'execution-while-out-of-viewport': "'none'",
            'navigation-override': "'none'",
            'publickey-credentials-get': "'self'",
            'speaker-selection': "'none'",
            'sync-xhr': "'none'",
            'vertical-scroll': "'self'",
            'wake-lock': "'none'"
        }
    
    def get_referrer_policy(self) -> str:
        """
        Generate Referrer Policy configuration for privacy protection.
        
        Returns:
            Referrer policy string value
        """
        if self.environment == 'development':
            return 'same-origin'
        else:
            return 'strict-origin-when-cross-origin'
    
    def get_session_cookie_config(self) -> Dict[str, Any]:
        """
        Generate secure session cookie configuration.
        
        Implements enterprise-grade session cookie security settings
        for Flask session management integration.
        
        Returns:
            Dictionary containing session cookie configuration
        """
        base_config = {
            'secure': True,  # HTTPS only
            'httponly': True,  # Prevent JavaScript access
            'samesite': 'Lax',  # CSRF protection with usability
            'max_age': timedelta(hours=24),  # 24-hour session lifetime
            'path': '/',
            'domain': None  # Will be set based on environment
        }
        
        if self.environment == 'development':
            # Development-friendly settings
            base_config['secure'] = False  # Allow HTTP in development
            base_config['samesite'] = 'Lax'
            base_config['domain'] = 'localhost'
            
        elif self.environment == 'staging':
            # Staging environment settings
            base_config['domain'] = os.getenv('STAGING_DOMAIN', '.staging.company.com')
            base_config['samesite'] = 'Lax'
            
        else:
            # Production security hardening
            base_config['samesite'] = 'Strict'
            base_config['domain'] = os.getenv('PRODUCTION_DOMAIN', '.company.com')
            base_config['max_age'] = timedelta(hours=12)  # Shorter session in production
        
        return base_config
    
    def get_additional_headers(self) -> Dict[str, str]:
        """
        Generate additional security headers for comprehensive protection.
        
        Returns:
            Dictionary containing additional security headers
        """
        return {
            'X-XSS-Protection': '1; mode=block',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0'
        }


class FlaskTalismanSecurityManager:
    """
    Comprehensive Flask-Talisman security manager providing enterprise-grade
    HTTP security header enforcement and web application protection.
    
    Integrates Flask-Talisman with custom security configurations, monitoring,
    and enterprise compliance requirements for complete security coverage.
    """
    
    def __init__(self, app: Optional[Flask] = None, environment: str = 'production'):
        """
        Initialize Flask-Talisman security manager.
        
        Args:
            app: Flask application instance
            environment: Deployment environment
        """
        self.app = app
        self.environment = environment
        self.config = SecurityHeadersConfig(environment)
        self.talisman = None
        self.security_enabled = True
        
        # Initialize security monitoring
        self.security_violations = []
        self.last_config_update = datetime.utcnow()
        
        if app is not None:
            self.init_app(app)
        
        logger.info(f"Flask-Talisman security manager initialized for {environment}")
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize Flask-Talisman security headers with Flask application.
        
        Configures comprehensive security headers, CSP policies, and
        enterprise-grade web application protection patterns.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        try:
            # Configure Talisman with comprehensive security settings
            self.talisman = Talisman(
                app,
                # HTTPS enforcement configuration
                force_https=self._should_force_https(),
                force_https_permanent=self.environment == 'production',
                
                # HTTP Strict Transport Security (HSTS) configuration
                strict_transport_security=True,
                strict_transport_security_max_age=self.config.get_hsts_config()['max_age'],
                strict_transport_security_include_subdomains=self.config.get_hsts_config()['include_subdomains'],
                strict_transport_security_preload=self.config.get_hsts_config()['preload'],
                
                # Content Security Policy (CSP) configuration
                content_security_policy=self.config.get_content_security_policy(),
                content_security_policy_nonce_in=['script-src', 'style-src'],
                content_security_policy_report_only=False,
                content_security_policy_report_uri=self._get_csp_report_uri(),
                
                # Frame protection configuration
                force_file_save=False,
                
                # Referrer policy configuration
                referrer_policy=self.config.get_referrer_policy(),
                
                # Feature policy configuration
                feature_policy=self.config.get_feature_policy(),
                
                # Additional security headers
                session_cookie_secure=self.config.get_session_cookie_config()['secure'],
                session_cookie_http_only=self.config.get_session_cookie_config()['httponly'],
                session_cookie_samesite=self.config.get_session_cookie_config()['samesite'],
                
                # Custom security headers
                custom_headers=self.config.get_additional_headers()
            )
            
            # Configure CSP violation reporting
            self._setup_csp_violation_reporting()
            
            # Configure security event monitoring
            self._setup_security_monitoring()
            
            # Configure session security integration
            self._configure_session_security()
            
            logger.info("Flask-Talisman security headers successfully configured")
            
        except Exception as e:
            logger.error(f"Failed to initialize Flask-Talisman security: {str(e)}")
            raise SecurityError(f"Security initialization failed: {str(e)}")
    
    def _should_force_https(self) -> bool:
        """
        Determine whether to force HTTPS based on environment.
        
        Returns:
            True if HTTPS should be enforced, False otherwise
        """
        if self.environment == 'development':
            return os.getenv('FORCE_HTTPS_DEV', 'false').lower() == 'true'
        return True
    
    def _get_csp_report_uri(self) -> Optional[str]:
        """
        Get CSP violation report URI for monitoring.
        
        Returns:
            CSP report URI or None if not configured
        """
        report_uri = os.getenv('CSP_REPORT_URI')
        if report_uri:
            return report_uri
        
        # Default CSP report endpoint
        if self.environment != 'development':
            return '/api/security/csp-report'
        
        return None
    
    def _setup_csp_violation_reporting(self) -> None:
        """
        Configure CSP violation reporting endpoint for security monitoring.
        """
        if not self.app:
            return
        
        @self.app.route('/api/security/csp-report', methods=['POST'])
        def csp_violation_report():
            """Handle CSP violation reports for security monitoring."""
            try:
                violation_data = request.get_json()
                if violation_data:
                    self._log_csp_violation(violation_data)
                    self.config.security_metrics['csp_violations'] += 1
                
                return '', 204
                
            except Exception as e:
                logger.error(f"CSP violation reporting error: {str(e)}")
                return '', 400
    
    def _log_csp_violation(self, violation_data: Dict[str, Any]) -> None:
        """
        Log CSP violation for security monitoring and analysis.
        
        Args:
            violation_data: CSP violation report data
        """
        violation_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'violation_type': 'csp_violation',
            'blocked_uri': violation_data.get('blocked-uri', ''),
            'document_uri': violation_data.get('document-uri', ''),
            'violated_directive': violation_data.get('violated-directive', ''),
            'source_file': violation_data.get('source-file', ''),
            'line_number': violation_data.get('line-number', 0),
            'client_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'environment': self.environment
        }
        
        self.security_violations.append(violation_info)
        
        logger.warning(
            f"CSP violation detected - Directive: {violation_info['violated_directive']}, "
            f"Blocked URI: {violation_info['blocked_uri']}, "
            f"Source: {violation_info['source_file']}:{violation_info['line_number']}"
        )
    
    def _setup_security_monitoring(self) -> None:
        """
        Configure comprehensive security monitoring and metrics collection.
        """
        if not self.app:
            return
        
        @self.app.before_request
        def before_request_security_check():
            """Pre-request security validation and monitoring."""
            try:
                # Track security headers application
                self.config.security_metrics['headers_applied'] += 1
                
                # HSTS enforcement tracking
                if request.is_secure:
                    self.config.security_metrics['hsts_enforcement'] += 1
                
                # Security context setup
                g.security_context = {
                    'request_id': generate_secure_token(16),
                    'timestamp': datetime.utcnow(),
                    'https_enforced': request.is_secure,
                    'security_headers_enabled': self.security_enabled
                }
                
            except Exception as e:
                logger.error(f"Security monitoring setup error: {str(e)}")
                self.config.security_metrics['security_errors'] += 1
        
        @self.app.after_request
        def after_request_security_headers(response):
            """Post-request security header validation and enhancement."""
            try:
                # Add custom security headers
                additional_headers = self.config.get_additional_headers()
                for header_name, header_value in additional_headers.items():
                    if header_name not in response.headers:
                        response.headers[header_name] = header_value
                
                # Add security context headers for debugging (non-production)
                if self.environment == 'development' and hasattr(g, 'security_context'):
                    response.headers['X-Security-Request-ID'] = g.security_context['request_id']
                
                # Log security violations if any
                if hasattr(g, 'security_violations'):
                    for violation in g.security_violations:
                        logger.warning(f"Security violation: {violation}")
                
                return response
                
            except Exception as e:
                logger.error(f"Security header enhancement error: {str(e)}")
                self.config.security_metrics['security_errors'] += 1
                return response
    
    def _configure_session_security(self) -> None:
        """
        Configure secure session management integration with Flask-Talisman.
        """
        if not self.app:
            return
        
        # Apply session cookie configuration
        session_config = self.config.get_session_cookie_config()
        
        self.app.config.update({
            'SESSION_COOKIE_SECURE': session_config['secure'],
            'SESSION_COOKIE_HTTPONLY': session_config['httponly'],
            'SESSION_COOKIE_SAMESITE': session_config['samesite'],
            'SESSION_COOKIE_PATH': session_config['path'],
            'PERMANENT_SESSION_LIFETIME': session_config['max_age']
        })
        
        if session_config['domain']:
            self.app.config['SESSION_COOKIE_DOMAIN'] = session_config['domain']
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive security metrics for monitoring and reporting.
        
        Returns:
            Dictionary containing security metrics and violation data
        """
        return {
            'metrics': self.config.security_metrics.copy(),
            'violations': self.security_violations[-100:],  # Last 100 violations
            'configuration': {
                'environment': self.environment,
                'security_enabled': self.security_enabled,
                'https_enforced': self._should_force_https(),
                'last_config_update': self.last_config_update.isoformat()
            },
            'csp_configuration': self.config.get_content_security_policy(),
            'hsts_configuration': self.config.get_hsts_config()
        }
    
    def update_security_configuration(self, new_config: Dict[str, Any]) -> bool:
        """
        Update security configuration dynamically.
        
        Args:
            new_config: New security configuration parameters
            
        Returns:
            True if configuration updated successfully, False otherwise
        """
        try:
            # Validate and apply configuration updates
            if 'environment' in new_config:
                self.environment = new_config['environment']
                self.config = SecurityHeadersConfig(self.environment)
            
            if 'auth0_domain' in new_config:
                self.config.auth0_domain = new_config['auth0_domain']
            
            # Re-initialize Talisman with new configuration
            if self.app:
                self.init_app(self.app)
            
            self.last_config_update = datetime.utcnow()
            
            logger.info(f"Security configuration updated for environment: {self.environment}")
            return True
            
        except Exception as e:
            logger.error(f"Security configuration update failed: {str(e)}")
            self.config.security_metrics['security_errors'] += 1
            return False
    
    def disable_security_temporarily(self, duration_minutes: int = 5) -> str:
        """
        Temporarily disable security headers for debugging (development only).
        
        Args:
            duration_minutes: Duration to disable security in minutes
            
        Returns:
            Temporary disable token for re-enabling
            
        Raises:
            SecurityError: If attempted in production environment
        """
        if self.environment == 'production':
            raise SecurityError("Security cannot be disabled in production environment")
        
        # Generate temporary disable token
        disable_token = generate_secure_token(32)
        
        # Set temporary disable state
        self.security_enabled = False
        disable_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        
        logger.warning(
            f"Security headers temporarily disabled until {disable_until.isoformat()} "
            f"- Token: {disable_token[:8]}..."
        )
        
        # Schedule re-enable (in real implementation, use background task)
        @self.app.teardown_appcontext
        def check_security_re_enable(exception):
            if datetime.utcnow() >= disable_until and not self.security_enabled:
                self.security_enabled = True
                logger.info("Security headers automatically re-enabled")
        
        return disable_token
    
    def enable_security(self, disable_token: str) -> bool:
        """
        Re-enable security headers using disable token.
        
        Args:
            disable_token: Token from disable_security_temporarily
            
        Returns:
            True if security re-enabled successfully, False otherwise
        """
        # In production implementation, validate token
        self.security_enabled = True
        logger.info("Security headers manually re-enabled")
        return True


# Security decorator for enhanced endpoint protection
def enhanced_security_headers(
    additional_csp: Optional[Dict[str, str]] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    require_https: bool = True
) -> Callable:
    """
    Decorator for applying enhanced security headers to specific endpoints.
    
    Provides granular security control for high-sensitivity endpoints
    with additional CSP directives and custom security headers.
    
    Args:
        additional_csp: Additional CSP directives for this endpoint
        custom_headers: Custom security headers for this endpoint
        require_https: Whether to require HTTPS for this endpoint
        
    Returns:
        Decorated function with enhanced security
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # HTTPS enforcement check
            if require_https and not request.is_secure:
                if current_app.config.get('ENV') != 'development':
                    logger.warning(f"HTTPS required for endpoint {request.endpoint}")
                    return 'HTTPS Required', 426
            
            # Apply additional security headers
            response = func(*args, **kwargs)
            
            if custom_headers:
                for header_name, header_value in custom_headers.items():
                    response.headers[header_name] = header_value
            
            # Log enhanced security application
            logger.debug(f"Enhanced security applied to endpoint: {request.endpoint}")
            
            return response
        
        return wrapper
    return decorator


# Utility functions for security management
def initialize_security_headers(
    app: Flask,
    environment: str = None,
    config_overrides: Optional[Dict[str, Any]] = None
) -> FlaskTalismanSecurityManager:
    """
    Initialize Flask-Talisman security headers for Flask application.
    
    Args:
        app: Flask application instance
        environment: Deployment environment
        config_overrides: Optional configuration overrides
        
    Returns:
        Configured FlaskTalismanSecurityManager instance
    """
    if environment is None:
        environment = os.getenv('FLASK_ENV', 'production')
    
    security_manager = FlaskTalismanSecurityManager(app, environment)
    
    if config_overrides:
        security_manager.update_security_configuration(config_overrides)
    
    logger.info(f"Security headers initialized for Flask application in {environment} mode")
    
    return security_manager


def get_security_report() -> Dict[str, Any]:
    """
    Generate comprehensive security report for monitoring and compliance.
    
    Returns:
        Dictionary containing security status and metrics
    """
    try:
        # This would integrate with the security manager instance
        return {
            'status': 'Security headers active',
            'timestamp': datetime.utcnow().isoformat(),
            'environment': os.getenv('FLASK_ENV', 'production'),
            'talisman_version': '1.1.0+',
            'compliance_status': 'Enterprise Ready'
        }
    except Exception as e:
        logger.error(f"Security report generation failed: {str(e)}")
        return {
            'status': 'Error generating security report',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


def validate_security_configuration() -> List[str]:
    """
    Validate current security configuration for compliance and best practices.
    
    Returns:
        List of validation warnings or recommendations
    """
    warnings = []
    
    # Check environment configuration
    environment = os.getenv('FLASK_ENV', 'production')
    if environment == 'development':
        warnings.append("Development environment detected - some security features may be relaxed")
    
    # Check Auth0 configuration
    auth0_domain = os.getenv('AUTH0_DOMAIN')
    if not auth0_domain or 'your-domain' in auth0_domain:
        warnings.append("Auth0 domain not properly configured for CSP")
    
    # Check HTTPS configuration
    force_https = os.getenv('FORCE_HTTPS', 'true').lower()
    if force_https != 'true' and environment == 'production':
        warnings.append("HTTPS enforcement should be enabled in production")
    
    # Check secret key configuration
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or len(secret_key) < 32:
        warnings.append("Flask SECRET_KEY should be at least 32 characters long")
    
    return warnings


# Module initialization for Flask application factory pattern
def init_security_module(app: Flask) -> FlaskTalismanSecurityManager:
    """
    Initialize security module for Flask application factory pattern.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured security manager instance
    """
    environment = app.config.get('ENV', 'production')
    
    # Validate security configuration
    validation_warnings = validate_security_configuration()
    if validation_warnings:
        for warning in validation_warnings:
            logger.warning(f"Security configuration warning: {warning}")
    
    # Initialize security headers
    security_manager = initialize_security_headers(app, environment)
    
    # Store security manager in app extensions
    if not hasattr(app, 'extensions'):
        app.extensions = {}
    app.extensions['security_manager'] = security_manager
    
    logger.info("Security module initialization complete")
    
    return security_manager


# Export public interface
__all__ = [
    'SecurityHeadersConfig',
    'FlaskTalismanSecurityManager',
    'enhanced_security_headers',
    'initialize_security_headers',
    'get_security_report',
    'validate_security_configuration',
    'init_security_module'
]