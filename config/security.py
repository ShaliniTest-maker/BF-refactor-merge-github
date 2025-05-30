"""
Security configuration module implementing Flask-Talisman 1.1.0+ for HTTP security headers,
CORS policies, rate limiting, input validation, and comprehensive security controls.

This module replaces Node.js helmet middleware and security configurations with equivalent
Python/Flask security implementations per Section 6.4 Security Architecture requirements.

Dependencies:
- Flask-Talisman 1.1.0+ for HTTP security header enforcement
- Flask-CORS 4.0+ for cross-origin request support
- Flask-Limiter 3.5+ for request throttling
- marshmallow 3.20+ and bleach 6.0+ for input validation and XSS prevention
"""

import os
import re
from typing import Dict, List, Optional, Any, Union
from datetime import timedelta
from flask import Flask, request
from flask_talisman import Talisman
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import bleach
from marshmallow import Schema, fields, ValidationError
from email_validator import validate_email, EmailNotValidError
import logging

# Configure logging for security module
logger = logging.getLogger(__name__)


class SecurityConfig:
    """
    Comprehensive security configuration class implementing enterprise-grade
    security controls for Flask applications per Section 6.4.3 requirements.
    """
    
    # Flask-Talisman security headers configuration
    TALISMAN_CONFIG = {
        'force_https': True,
        'force_https_permanent': True,
        'strict_transport_security': True,
        'strict_transport_security_max_age': 31536000,  # 1 year
        'strict_transport_security_include_subdomains': True,
        'strict_transport_security_preload': True,
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' https://cdn.auth0.com",
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data: https:",
            'connect-src': "'self' https://*.auth0.com https://*.amazonaws.com",
            'font-src': "'self'",
            'object-src': "'none'",
            'base-uri': "'self'",
            'frame-ancestors': "'none'",
            'upgrade-insecure-requests': True
        },
        'content_security_policy_nonce_in': ['script-src', 'style-src'],
        'referrer_policy': 'strict-origin-when-cross-origin',
        'feature_policy': {
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'",
            'accelerometer': "'none'",
            'gyroscope': "'none'"
        },
        'session_cookie_secure': True,
        'session_cookie_http_only': True,
        'session_cookie_samesite': 'Strict'
    }
    
    # Flask-CORS configuration for cross-origin request support
    CORS_CONFIG = {
        'origins': [],  # Populated dynamically based on environment
        'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allow_headers': [
            'Authorization',
            'Content-Type',
            'X-Requested-With',
            'X-CSRF-Token',
            'X-Auth-Token',
            'Accept',
            'Origin'
        ],
        'expose_headers': [
            'X-Auth-RateLimit-Limit',
            'X-Auth-RateLimit-Remaining',
            'X-Auth-RateLimit-Reset',
            'X-Permission-Status'
        ],
        'supports_credentials': True,
        'max_age': 600,  # 10 minutes preflight cache
        'send_wildcard': False,
        'vary_header': True
    }
    
    # Flask-Limiter rate limiting configuration
    RATE_LIMITING_CONFIG = {
        'storage_uri': None,  # Set dynamically from Redis configuration
        'storage_options': {},
        'default_limits': [
            '1000 per hour',    # Sustained rate limit
            '100 per minute',   # Burst protection
            '10 per second'     # Spike protection
        ],
        'strategy': 'moving-window',
        'headers_enabled': True,
        'header_name_mapping': {
            'X-RateLimit-Limit': 'X-Auth-RateLimit-Limit',
            'X-RateLimit-Remaining': 'X-Auth-RateLimit-Remaining',
            'X-RateLimit-Reset': 'X-Auth-RateLimit-Reset'
        }
    }
    
    # Input validation and sanitization configuration
    HTML_SANITIZATION_CONFIG = {
        'tags': [
            'a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
            'em', 'i', 'li', 'ol', 'strong', 'ul', 'p', 'br'
        ],
        'attributes': {
            'a': ['href', 'title'],
            'abbr': ['title'],
            'acronym': ['title']
        },
        'protocols': ['http', 'https', 'mailto'],
        'strip': True,
        'strip_comments': True
    }
    
    # Password and input validation patterns
    VALIDATION_PATTERNS = {
        'password_minimum_length': 12,
        'password_complexity_regex': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
        'sql_injection_patterns': [
            r'(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b)',
            r'(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+',
            r'[\'\"]\s*;\s*--',
            r'[\'\"]\s*\|\|\s*[\'\"]\s*\d+\s*=\s*\d+'
        ],
        'xss_patterns': [
            r'<script[\s\S]*?>[\s\S]*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[\s\S]*?>',
            r'<object[\s\S]*?>'
        ]
    }

    @classmethod
    def get_cors_origins(cls) -> List[str]:
        """
        Get CORS origins based on environment configuration.
        
        Returns:
            List of allowed CORS origins for the current environment
        """
        environment = os.getenv('FLASK_ENV', 'production')
        
        base_origins = [
            'https://app.company.com',
            'https://admin.company.com'
        ]
        
        if environment == 'development':
            base_origins.extend([
                'https://localhost:3000',
                'https://localhost:8080',
                'https://dev.company.com'
            ])
        elif environment == 'staging':
            base_origins.extend([
                'https://staging.company.com',
                'https://staging-admin.company.com'
            ])
        
        # Allow custom origins from environment variable
        custom_origins = os.getenv('CORS_ALLOWED_ORIGINS', '')
        if custom_origins:
            base_origins.extend(custom_origins.split(','))
        
        return base_origins


class SecurityValidationSchema(Schema):
    """
    Comprehensive input validation schema using marshmallow 3.20+
    for request validation and sanitization per Section 6.4.3.
    """
    
    # Common field validation
    email = fields.Email(required=False, validate=lambda x: validate_email_input(x))
    password = fields.Str(required=False, validate=lambda x: validate_password_strength(x))
    username = fields.Str(required=False, validate=lambda x: validate_username_format(x))
    
    # Text fields with XSS protection
    title = fields.Str(required=False, validate=lambda x: sanitize_html_input(x))
    description = fields.Str(required=False, validate=lambda x: sanitize_html_input(x))
    content = fields.Str(required=False, validate=lambda x: sanitize_html_input(x))
    
    # Numeric validation
    page = fields.Integer(required=False, validate=lambda x: x > 0 and x <= 10000)
    limit = fields.Integer(required=False, validate=lambda x: x > 0 and x <= 1000)
    
    # Date/time validation
    created_at = fields.DateTime(required=False, format='iso8601')
    updated_at = fields.DateTime(required=False, format='iso8601')


def validate_email_input(email: str) -> str:
    """
    Validate email input using email-validator 2.1+ with comprehensive checks.
    
    Args:
        email: Email address to validate
        
    Returns:
        Validated and normalized email address
        
    Raises:
        ValidationError: When email format is invalid
    """
    try:
        # Use email-validator for comprehensive validation
        valid_email = validate_email(email)
        normalized_email = valid_email.email
        
        # Additional security checks
        if len(normalized_email) > 254:  # RFC 5321 limit
            raise ValidationError('Email address too long')
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[<>"\']',  # HTML/script injection attempts
            r'javascript:',  # JavaScript injection
            r'data:',  # Data URI injection
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, normalized_email, re.IGNORECASE):
                raise ValidationError('Email contains invalid characters')
        
        return normalized_email
        
    except EmailNotValidError as e:
        raise ValidationError(f'Invalid email format: {str(e)}')


def validate_password_strength(password: str) -> str:
    """
    Validate password strength against enterprise security requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Validated password
        
    Raises:
        ValidationError: When password doesn't meet requirements
    """
    min_length = SecurityConfig.VALIDATION_PATTERNS['password_minimum_length']
    complexity_pattern = SecurityConfig.VALIDATION_PATTERNS['password_complexity_regex']
    
    if len(password) < min_length:
        raise ValidationError(f'Password must be at least {min_length} characters long')
    
    if not re.match(complexity_pattern, password):
        raise ValidationError(
            'Password must contain uppercase, lowercase, number, and special character'
        )
    
    # Check for common weak patterns
    weak_patterns = [
        r'(.)\1{3,}',  # Repeated characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            raise ValidationError('Password contains weak patterns')
    
    return password


def validate_username_format(username: str) -> str:
    """
    Validate username format for security compliance.
    
    Args:
        username: Username to validate
        
    Returns:
        Validated username
        
    Raises:
        ValidationError: When username format is invalid
    """
    if not username:
        raise ValidationError('Username cannot be empty')
    
    if len(username) < 3 or len(username) > 50:
        raise ValidationError('Username must be between 3 and 50 characters')
    
    # Allow alphanumeric, underscore, hyphen, and dot
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValidationError('Username contains invalid characters')
    
    # Check for injection attempts
    injection_patterns = SecurityConfig.VALIDATION_PATTERNS['sql_injection_patterns']
    for pattern in injection_patterns:
        if re.search(pattern, username, re.IGNORECASE):
            raise ValidationError('Username contains prohibited patterns')
    
    return username


def sanitize_html_input(text: str) -> str:
    """
    Sanitize HTML input using bleach 6.0+ for XSS prevention.
    
    Args:
        text: Text input to sanitize
        
    Returns:
        Sanitized text with HTML tags removed or escaped
        
    Raises:
        ValidationError: When text contains malicious content
    """
    if not text:
        return text
    
    # Check for XSS patterns
    xss_patterns = SecurityConfig.VALIDATION_PATTERNS['xss_patterns']
    for pattern in xss_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValidationError('Input contains potentially malicious content')
    
    # Sanitize HTML using bleach
    config = SecurityConfig.HTML_SANITIZATION_CONFIG
    sanitized_text = bleach.clean(
        text,
        tags=config['tags'],
        attributes=config['attributes'],
        protocols=config['protocols'],
        strip=config['strip'],
        strip_comments=config['strip_comments']
    )
    
    # Additional length validation
    if len(sanitized_text) > 10000:  # Prevent large payload attacks
        raise ValidationError('Input text too long')
    
    return sanitized_text


def detect_sql_injection(input_text: str) -> bool:
    """
    Detect potential SQL injection attempts in input text.
    
    Args:
        input_text: Text to analyze for SQL injection patterns
        
    Returns:
        True if potential SQL injection detected, False otherwise
    """
    if not input_text:
        return False
    
    injection_patterns = SecurityConfig.VALIDATION_PATTERNS['sql_injection_patterns']
    
    for pattern in injection_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            logger.warning(
                'Potential SQL injection detected',
                extra={
                    'input_text': input_text[:100],  # Log first 100 chars
                    'pattern_matched': pattern,
                    'source_ip': getattr(request, 'remote_addr', 'unknown'),
                    'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown'
                }
            )
            return True
    
    return False


def create_redis_client_for_limiter() -> redis.Redis:
    """
    Create Redis client for Flask-Limiter with proper configuration.
    
    Returns:
        Configured Redis client for rate limiting
    """
    return redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD'),
        db=int(os.getenv('REDIS_LIMITER_DB', 2)),
        decode_responses=True,
        max_connections=50,
        retry_on_timeout=True,
        socket_timeout=30.0,
        socket_connect_timeout=10.0,
        health_check_interval=30
    )


def configure_security_extensions(app: Flask) -> Dict[str, Any]:
    """
    Configure all security extensions for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Dictionary containing configured security extension instances
    """
    security_extensions = {}
    
    try:
        # Configure Flask-Talisman for HTTP security headers
        talisman = Talisman(app, **SecurityConfig.TALISMAN_CONFIG)
        security_extensions['talisman'] = talisman
        logger.info('Flask-Talisman security headers configured successfully')
        
        # Configure Flask-CORS for cross-origin requests
        cors_config = SecurityConfig.CORS_CONFIG.copy()
        cors_config['origins'] = SecurityConfig.get_cors_origins()
        
        # Environment-specific CORS configuration
        cors = CORS(app, **cors_config)
        
        # Specific CORS configuration for API routes
        CORS(app, resources={
            r'/api/auth/*': {
                'origins': [
                    'https://app.company.com',
                    'https://admin.company.com'
                ],
                'methods': ['POST', 'GET', 'OPTIONS'],
                'allow_headers': ['Authorization', 'Content-Type'],
                'supports_credentials': True,
                'max_age': 300
            },
            r'/api/permissions/*': {
                'origins': ['https://app.company.com'],
                'methods': ['GET', 'OPTIONS'],
                'allow_headers': ['Authorization', 'Content-Type'],
                'supports_credentials': True,
                'max_age': 600
            },
            r'/api/admin/*': {
                'origins': ['https://admin.company.com'],
                'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                'allow_headers': [
                    'Authorization',
                    'Content-Type',
                    'X-Admin-Token'
                ],
                'supports_credentials': True,
                'max_age': 120
            }
        })
        
        security_extensions['cors'] = cors
        logger.info('Flask-CORS cross-origin policies configured successfully')
        
        # Configure Flask-Limiter for rate limiting
        redis_client = create_redis_client_for_limiter()
        
        limiter_config = SecurityConfig.RATE_LIMITING_CONFIG.copy()
        limiter_config['storage_uri'] = f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}/{os.getenv('REDIS_LIMITER_DB', 2)}"
        limiter_config['storage_options'] = {'connection_pool': redis_client.connection_pool}
        
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            **limiter_config
        )
        
        security_extensions['limiter'] = limiter
        logger.info('Flask-Limiter rate limiting configured successfully')
        
        # Configure request validation middleware
        @app.before_request
        def security_validation_middleware():
            """
            Pre-request security validation middleware for input sanitization.
            """
            # Skip validation for static files and health checks
            if request.endpoint in ['static', 'health_check']:
                return
            
            # Log security-relevant request information
            logger.info(
                'Security middleware processing request',
                extra={
                    'method': request.method,
                    'endpoint': request.endpoint,
                    'source_ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'content_length': request.content_length
                }
            )
            
            # Check for oversized requests
            max_content_length = app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB
            if request.content_length and request.content_length > max_content_length:
                logger.warning('Request size exceeds maximum allowed limit')
                from flask import abort
                abort(413)  # Payload Too Large
            
            # Validate request data for common injection attempts
            if request.is_json and request.get_json():
                try:
                    json_data = request.get_json()
                    _validate_json_input_security(json_data)
                except ValidationError as e:
                    logger.warning(f'Request validation failed: {str(e)}')
                    from flask import abort
                    abort(400)  # Bad Request
        
        logger.info('Security validation middleware configured successfully')
        
    except Exception as e:
        logger.error(f'Failed to configure security extensions: {str(e)}')
        raise
    
    return security_extensions


def _validate_json_input_security(data: Any, max_depth: int = 10, current_depth: int = 0) -> None:
    """
    Recursively validate JSON input for security threats.
    
    Args:
        data: JSON data to validate
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
        
    Raises:
        ValidationError: When security threats are detected
    """
    if current_depth > max_depth:
        raise ValidationError('JSON structure too deeply nested')
    
    if isinstance(data, dict):
        if len(data) > 1000:  # Prevent large object attacks
            raise ValidationError('JSON object has too many keys')
        
        for key, value in data.items():
            if isinstance(key, str):
                if detect_sql_injection(key):
                    raise ValidationError('JSON key contains potential SQL injection')
            
            _validate_json_input_security(value, max_depth, current_depth + 1)
    
    elif isinstance(data, list):
        if len(data) > 10000:  # Prevent large array attacks
            raise ValidationError('JSON array too large')
        
        for item in data:
            _validate_json_input_security(item, max_depth, current_depth + 1)
    
    elif isinstance(data, str):
        if len(data) > 100000:  # Prevent large string attacks
            raise ValidationError('JSON string too long')
        
        if detect_sql_injection(data):
            raise ValidationError('JSON value contains potential SQL injection')


def configure_environment_specific_security(app: Flask, environment: str) -> None:
    """
    Configure environment-specific security settings.
    
    Args:
        app: Flask application instance
        environment: Environment name (development, staging, production)
    """
    if environment == 'production':
        # Production security hardening
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
        
        # Disable debug mode and testing
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        
        logger.info('Production security configuration applied')
        
    elif environment == 'staging':
        # Staging security with some relaxations for testing
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
        
        logger.info('Staging security configuration applied')
        
    elif environment == 'development':
        # Development security with relaxations for local testing
        app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP in development
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
        
        logger.info('Development security configuration applied')
    
    else:
        logger.warning(f'Unknown environment: {environment}, using production defaults')
        configure_environment_specific_security(app, 'production')


def get_security_headers_status() -> Dict[str, bool]:
    """
    Get current security headers configuration status for monitoring.
    
    Returns:
        Dictionary containing security headers status
    """
    return {
        'https_enforced': SecurityConfig.TALISMAN_CONFIG['force_https'],
        'hsts_enabled': SecurityConfig.TALISMAN_CONFIG['strict_transport_security'],
        'csp_enabled': bool(SecurityConfig.TALISMAN_CONFIG['content_security_policy']),
        'frame_options_enabled': True,  # Always enabled by Talisman
        'content_type_options_enabled': True,  # Always enabled by Talisman
        'referrer_policy_enabled': bool(SecurityConfig.TALISMAN_CONFIG['referrer_policy']),
        'feature_policy_enabled': bool(SecurityConfig.TALISMAN_CONFIG['feature_policy'])
    }


def log_security_event(event_type: str, details: Dict[str, Any]) -> None:
    """
    Log security events for audit and monitoring purposes.
    
    Args:
        event_type: Type of security event
        details: Event details and context
    """
    logger.warning(
        f'Security event: {event_type}',
        extra={
            'event_type': event_type,
            'timestamp': details.get('timestamp'),
            'source_ip': details.get('source_ip', getattr(request, 'remote_addr', 'unknown')),
            'user_agent': details.get('user_agent', request.headers.get('User-Agent', 'unknown') if request else 'unknown'),
            'endpoint': details.get('endpoint', getattr(request, 'endpoint', 'unknown')),
            'method': details.get('method', getattr(request, 'method', 'unknown')),
            'details': details
        }
    )


# Export security configuration and utilities
__all__ = [
    'SecurityConfig',
    'SecurityValidationSchema',
    'configure_security_extensions',
    'configure_environment_specific_security',
    'validate_email_input',
    'validate_password_strength',
    'validate_username_format',
    'sanitize_html_input',
    'detect_sql_injection',
    'get_security_headers_status',
    'log_security_event'
]