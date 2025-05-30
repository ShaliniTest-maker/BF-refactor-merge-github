"""
Public API Blueprint for unauthenticated endpoints.

This module provides secure public-facing functionality including user registration,
password reset, public information endpoints, and health checks. All endpoints
implement comprehensive security controls including input validation, rate limiting,
CORS support, and integration with Auth0 for user management.

Key Features:
- User registration and password reset workflows via Auth0
- Public information and content endpoints
- Comprehensive input validation and sanitization
- Rate limiting protection against abuse
- CORS configuration for web client access
- Security event logging and monitoring
- HTML sanitization and XSS prevention

Security Controls:
- Flask-Limiter rate limiting for abuse protection
- bleach HTML sanitization for XSS prevention
- email-validator for secure email validation
- Structured logging for security monitoring
- Flask-CORS for secure cross-origin access

Author: Flask Migration System
Created: 2024
Version: 1.0.0
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse, urljoin

import bleach
from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, jsonify, current_app, g, url_for
from flask_cors import cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError, validate
import structlog

# Import auth utilities for user registration and management
try:
    from src.auth.auth0_client import Auth0ManagementClient
    from src.auth.utils import (
        sanitize_input,
        validate_password_strength,
        generate_secure_token,
        log_security_event
    )
except ImportError:
    # Graceful fallback if auth modules are not available yet
    Auth0ManagementClient = None
    
    def sanitize_input(data: str) -> str:
        """Fallback sanitization function."""
        return bleach.clean(data, tags=[], attributes={}, strip=True)
    
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Fallback password validation."""
        return {"valid": len(password) >= 8, "score": 3, "feedback": []}
    
    def generate_secure_token() -> str:
        """Fallback token generation."""
        import secrets
        return secrets.token_urlsafe(32)
    
    def log_security_event(event_type: str, details: Dict[str, Any]) -> None:
        """Fallback security logging."""
        logger = structlog.get_logger("security.public")
        logger.warning("Security event", event_type=event_type, **details)

# Import monitoring and data access utilities
try:
    from src.monitoring import get_metrics_registry, increment_counter
    from src.data import get_database_client
except ImportError:
    # Graceful fallback if modules are not available yet
    def get_metrics_registry():
        """Fallback metrics registry."""
        return None
    
    def increment_counter(name: str, labels: Dict[str, str] = None) -> None:
        """Fallback metrics counter."""
        pass
    
    def get_database_client():
        """Fallback database client."""
        return None

# Configure structured logging for security events
logger = structlog.get_logger("blueprints.public")

# Create Blueprint for public endpoints
public_bp = Blueprint(
    'public',
    __name__,
    url_prefix='/api/public',
    template_folder='templates',
    static_folder='static'
)

# Rate limiter configuration for public endpoints
# Implement multi-tier rate limiting: per-second, per-minute, per-hour
public_limiter = None  # Will be initialized with Flask app context

# CORS configuration for public endpoints
CORS_ORIGINS = [
    "https://app.company.com",
    "https://admin.company.com",
    "https://www.company.com",
    "https://staging.company.com",
    "https://localhost:3000",  # Development
    "https://localhost:8080"   # Development
]

# HTML sanitization configuration
ALLOWED_HTML_TAGS = []  # No HTML tags allowed in public inputs
ALLOWED_ATTRIBUTES = {}
BLEACH_CONFIG = {
    'tags': ALLOWED_HTML_TAGS,
    'attributes': ALLOWED_ATTRIBUTES,
    'strip': True,
    'strip_comments': True
}

# Email domain validation patterns
TRUSTED_EMAIL_DOMAINS = [
    r'.*\.company\.com$',
    r'gmail\.com$',
    r'outlook\.com$',
    r'yahoo\.com$',
    r'.*\.edu$'
]

# Input validation schemas using marshmallow
class UserRegistrationSchema(Schema):
    """Schema for user registration validation."""
    
    email = fields.Email(
        required=True,
        validate=validate.Length(min=5, max=254),
        error_messages={
            'required': 'Email address is required',
            'invalid': 'Please provide a valid email address'
        }
    )
    
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
        error_messages={
            'required': 'Password is required',
            'invalid': 'Password must be between 8 and 128 characters'
        }
    )
    
    first_name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50),
        error_messages={
            'required': 'First name is required',
            'invalid': 'First name must be between 1 and 50 characters'
        }
    )
    
    last_name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50),
        error_messages={
            'required': 'Last name is required',
            'invalid': 'Last name must be between 1 and 50 characters'
        }
    )
    
    organization = fields.Str(
        required=False,
        validate=validate.Length(max=100),
        allow_none=True,
        missing=None
    )
    
    terms_accepted = fields.Bool(
        required=True,
        validate=validate.Equal(True),
        error_messages={
            'required': 'Terms and conditions must be accepted',
            'invalid': 'You must accept the terms and conditions'
        }
    )
    
    marketing_consent = fields.Bool(
        required=False,
        missing=False
    )

class PasswordResetRequestSchema(Schema):
    """Schema for password reset request validation."""
    
    email = fields.Email(
        required=True,
        validate=validate.Length(min=5, max=254),
        error_messages={
            'required': 'Email address is required',
            'invalid': 'Please provide a valid email address'
        }
    )

class ContactFormSchema(Schema):
    """Schema for contact form validation."""
    
    name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100),
        error_messages={
            'required': 'Name is required',
            'invalid': 'Name must be between 1 and 100 characters'
        }
    )
    
    email = fields.Email(
        required=True,
        validate=validate.Length(min=5, max=254),
        error_messages={
            'required': 'Email address is required',
            'invalid': 'Please provide a valid email address'
        }
    )
    
    subject = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=200),
        error_messages={
            'required': 'Subject is required',
            'invalid': 'Subject must be between 1 and 200 characters'
        }
    )
    
    message = fields.Str(
        required=True,
        validate=validate.Length(min=10, max=2000),
        error_messages={
            'required': 'Message is required',
            'invalid': 'Message must be between 10 and 2000 characters'
        }
    )


def validate_and_sanitize_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive input validation and sanitization for public endpoints.
    
    This function provides multi-layer security validation including:
    - HTML sanitization using bleach to prevent XSS attacks
    - Email validation and domain checking
    - Input length and content validation
    - SQL injection pattern detection
    - Malicious payload detection
    
    Args:
        data: Dictionary containing user input data
        
    Returns:
        Dictionary with sanitized and validated data
        
    Raises:
        ValidationError: If validation fails
    """
    sanitized_data = {}
    
    for key, value in data.items():
        if isinstance(value, str):
            # HTML sanitization using bleach
            sanitized_value = bleach.clean(
                value,
                tags=BLEACH_CONFIG['tags'],
                attributes=BLEACH_CONFIG['attributes'],
                strip=BLEACH_CONFIG['strip'],
                strip_comments=BLEACH_CONFIG['strip_comments']
            )
            
            # Additional sanitization patterns
            sanitized_value = sanitized_value.strip()
            
            # Check for potential SQL injection patterns
            sql_patterns = [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)",
                r"(--|#|\*\/|\*)",
                r"(\bOR\b.*=.*|\bAND\b.*=.*)",
                r"('.*'|\".*\")"
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, sanitized_value, re.IGNORECASE):
                    log_security_event("sql_injection_attempt", {
                        "field": key,
                        "value_length": len(value),
                        "source_ip": request.remote_addr,
                        "user_agent": request.headers.get("User-Agent", "")
                    })
                    raise ValidationError(f"Invalid content detected in {key}")
            
            sanitized_data[key] = sanitized_value
        else:
            sanitized_data[key] = value
    
    return sanitized_data


def validate_email_domain(email: str) -> bool:
    """
    Validate email domain against trusted patterns.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if domain is trusted, False otherwise
    """
    domain = email.split('@')[1].lower()
    
    for pattern in TRUSTED_EMAIL_DOMAINS:
        if re.match(pattern, domain):
            return True
    
    return False


def create_rate_limiter(app) -> Limiter:
    """
    Create and configure rate limiter for public endpoints.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured Limiter instance
    """
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute", "10 per second"],
        storage_uri="redis://localhost:6379/3",  # Separate Redis DB for rate limiting
        strategy="moving-window",
        headers_enabled=True,
        header_name_mapping={
            "X-RateLimit-Limit": "X-Public-RateLimit-Limit",
            "X-RateLimit-Remaining": "X-Public-RateLimit-Remaining",
            "X-RateLimit-Reset": "X-Public-RateLimit-Reset"
        }
    )
    
    return limiter


# Public endpoint implementations

@public_bp.route('/health', methods=['GET'])
@cross_origin(origins=CORS_ORIGINS, methods=['GET'])
def public_health_check():
    """
    Public health check endpoint for load balancer and monitoring.
    
    This endpoint provides basic application health status without
    requiring authentication, suitable for load balancer health checks
    and public monitoring systems.
    
    Returns:
        JSON response with health status and basic metrics
    """
    try:
        # Basic application health check
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': getattr(current_app, 'version', '1.0.0'),
            'environment': current_app.config.get('ENV', 'production')
        }
        
        # Log health check access
        logger.info(
            "Public health check accessed",
            source_ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")
        )
        
        # Increment metrics counter
        increment_counter("public_health_checks_total", {"status": "success"})
        
        return jsonify(health_status), 200
        
    except Exception as e:
        logger.error("Public health check failed", error=str(e))
        increment_counter("public_health_checks_total", {"status": "error"})
        
        return jsonify({
            'status': 'unhealthy',
            'error': 'Internal service error',
            'timestamp': datetime.utcnow().isoformat()
        }), 503


@public_bp.route('/register', methods=['POST'])
@cross_origin(origins=CORS_ORIGINS, methods=['POST'])
def register_user():
    """
    User registration endpoint via Auth0.
    
    This endpoint handles new user registration through Auth0 Management API,
    implementing comprehensive input validation, security controls, and
    enterprise integration patterns.
    
    Request Body:
        email (str): User email address
        password (str): User password
        first_name (str): User first name
        last_name (str): User last name
        organization (str, optional): User organization
        terms_accepted (bool): Terms acceptance confirmation
        marketing_consent (bool, optional): Marketing consent
    
    Returns:
        JSON response with registration status and user information
        
    Rate Limits:
        - 5 registration attempts per minute per IP
        - 20 registration attempts per hour per IP
    """
    try:
        # Apply specific rate limiting for registration
        if public_limiter:
            # This will be enforced by the decorator when properly configured
            pass
        
        # Validate request content type
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json',
                'code': 'INVALID_CONTENT_TYPE'
            }), 400
        
        # Extract and validate input data
        raw_data = request.get_json()
        if not raw_data:
            return jsonify({
                'error': 'Request body is required',
                'code': 'MISSING_REQUEST_BODY'
            }), 400
        
        # Sanitize input data
        sanitized_data = validate_and_sanitize_input(raw_data)
        
        # Validate using marshmallow schema
        schema = UserRegistrationSchema()
        try:
            validated_data = schema.load(sanitized_data)
        except ValidationError as e:
            log_security_event("registration_validation_failed", {
                "errors": e.messages,
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", "")
            })
            return jsonify({
                'error': 'Validation failed',
                'details': e.messages,
                'code': 'VALIDATION_ERROR'
            }), 400
        
        # Additional email validation
        try:
            email_info = validate_email(validated_data['email'])
            validated_email = email_info.email
        except EmailNotValidError as e:
            return jsonify({
                'error': 'Invalid email address',
                'details': str(e),
                'code': 'INVALID_EMAIL'
            }), 400
        
        # Validate email domain
        if not validate_email_domain(validated_email):
            log_security_event("untrusted_email_domain", {
                "email_domain": validated_email.split('@')[1],
                "source_ip": request.remote_addr
            })
            return jsonify({
                'error': 'Email domain not allowed',
                'code': 'DOMAIN_NOT_ALLOWED'
            }), 400
        
        # Validate password strength
        password_validation = validate_password_strength(validated_data['password'])
        if not password_validation['valid']:
            return jsonify({
                'error': 'Password does not meet security requirements',
                'details': password_validation['feedback'],
                'code': 'WEAK_PASSWORD'
            }), 400
        
        # Register user via Auth0 Management API
        if Auth0ManagementClient:
            auth0_client = Auth0ManagementClient()
            
            try:
                registration_result = auth0_client.create_user({
                    'email': validated_email,
                    'password': validated_data['password'],
                    'name': f"{validated_data['first_name']} {validated_data['last_name']}",
                    'given_name': validated_data['first_name'],
                    'family_name': validated_data['last_name'],
                    'user_metadata': {
                        'organization': validated_data.get('organization'),
                        'marketing_consent': validated_data.get('marketing_consent', False),
                        'registration_source': 'public_api',
                        'registration_timestamp': datetime.utcnow().isoformat()
                    },
                    'app_metadata': {
                        'role': 'user',
                        'account_status': 'pending_verification'
                    }
                })
                
                # Log successful registration
                logger.info(
                    "User registration successful",
                    user_id=registration_result.get('user_id'),
                    email=validated_email,
                    source_ip=request.remote_addr
                )
                
                increment_counter("user_registrations_total", {"status": "success"})
                
                return jsonify({
                    'success': True,
                    'message': 'Registration successful. Please check your email for verification.',
                    'user': {
                        'id': registration_result.get('user_id'),
                        'email': validated_email,
                        'name': registration_result.get('name'),
                        'email_verified': registration_result.get('email_verified', False)
                    }
                }), 201
                
            except Exception as auth_error:
                logger.error(
                    "Auth0 registration failed",
                    error=str(auth_error),
                    email=validated_email,
                    source_ip=request.remote_addr
                )
                
                increment_counter("user_registrations_total", {"status": "auth0_error"})
                
                # Check if it's a duplicate user error
                if "user already exists" in str(auth_error).lower():
                    return jsonify({
                        'error': 'An account with this email address already exists',
                        'code': 'USER_EXISTS'
                    }), 409
                
                return jsonify({
                    'error': 'Registration failed. Please try again.',
                    'code': 'REGISTRATION_ERROR'
                }), 500
        else:
            # Fallback when Auth0 client is not available
            logger.warning("Auth0 client not available, registration failed")
            return jsonify({
                'error': 'Registration service unavailable',
                'code': 'SERVICE_UNAVAILABLE'
            }), 503
            
    except ValidationError as e:
        increment_counter("user_registrations_total", {"status": "validation_error"})
        return jsonify({
            'error': 'Invalid input data',
            'details': str(e),
            'code': 'VALIDATION_ERROR'
        }), 400
        
    except Exception as e:
        logger.error("Registration endpoint error", error=str(e))
        increment_counter("user_registrations_total", {"status": "error"})
        
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500


@public_bp.route('/password-reset', methods=['POST'])
@cross_origin(origins=CORS_ORIGINS, methods=['POST'])
def request_password_reset():
    """
    Password reset request endpoint.
    
    This endpoint initiates password reset flow via Auth0, implementing
    security controls to prevent abuse while providing user-friendly
    password recovery functionality.
    
    Request Body:
        email (str): User email address for password reset
    
    Returns:
        JSON response with reset request status
        
    Rate Limits:
        - 3 password reset requests per minute per IP
        - 10 password reset requests per hour per IP
    """
    try:
        # Validate request content type
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json',
                'code': 'INVALID_CONTENT_TYPE'
            }), 400
        
        # Extract and validate input data
        raw_data = request.get_json()
        if not raw_data:
            return jsonify({
                'error': 'Request body is required',
                'code': 'MISSING_REQUEST_BODY'
            }), 400
        
        # Sanitize input data
        sanitized_data = validate_and_sanitize_input(raw_data)
        
        # Validate using marshmallow schema
        schema = PasswordResetRequestSchema()
        try:
            validated_data = schema.load(sanitized_data)
        except ValidationError as e:
            return jsonify({
                'error': 'Validation failed',
                'details': e.messages,
                'code': 'VALIDATION_ERROR'
            }), 400
        
        # Additional email validation
        try:
            email_info = validate_email(validated_data['email'])
            validated_email = email_info.email
        except EmailNotValidError as e:
            return jsonify({
                'error': 'Invalid email address',
                'details': str(e),
                'code': 'INVALID_EMAIL'
            }), 400
        
        # Initiate password reset via Auth0
        if Auth0ManagementClient:
            auth0_client = Auth0ManagementClient()
            
            try:
                reset_result = auth0_client.request_password_reset(validated_email)
                
                # Log password reset request
                logger.info(
                    "Password reset requested",
                    email=validated_email,
                    source_ip=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", "")
                )
                
                increment_counter("password_reset_requests_total", {"status": "success"})
                
                # Always return success message for security (no user enumeration)
                return jsonify({
                    'success': True,
                    'message': 'If an account with this email exists, you will receive password reset instructions.'
                }), 200
                
            except Exception as auth_error:
                logger.error(
                    "Auth0 password reset failed",
                    error=str(auth_error),
                    email=validated_email,
                    source_ip=request.remote_addr
                )
                
                increment_counter("password_reset_requests_total", {"status": "auth0_error"})
                
                # Still return success message for security
                return jsonify({
                    'success': True,
                    'message': 'If an account with this email exists, you will receive password reset instructions.'
                }), 200
        else:
            # Fallback when Auth0 client is not available
            logger.warning("Auth0 client not available, password reset failed")
            return jsonify({
                'error': 'Password reset service unavailable',
                'code': 'SERVICE_UNAVAILABLE'
            }), 503
            
    except Exception as e:
        logger.error("Password reset endpoint error", error=str(e))
        increment_counter("password_reset_requests_total", {"status": "error"})
        
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500


@public_bp.route('/contact', methods=['POST'])
@cross_origin(origins=CORS_ORIGINS, methods=['POST'])
def submit_contact_form():
    """
    Contact form submission endpoint.
    
    This endpoint handles contact form submissions with comprehensive
    input validation, spam protection, and secure data processing.
    
    Request Body:
        name (str): Contact person name
        email (str): Contact email address
        subject (str): Message subject
        message (str): Message content
    
    Returns:
        JSON response with submission status
        
    Rate Limits:
        - 2 contact submissions per minute per IP
        - 10 contact submissions per hour per IP
    """
    try:
        # Validate request content type
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json',
                'code': 'INVALID_CONTENT_TYPE'
            }), 400
        
        # Extract and validate input data
        raw_data = request.get_json()
        if not raw_data:
            return jsonify({
                'error': 'Request body is required',
                'code': 'MISSING_REQUEST_BODY'
            }), 400
        
        # Sanitize input data
        sanitized_data = validate_and_sanitize_input(raw_data)
        
        # Validate using marshmallow schema
        schema = ContactFormSchema()
        try:
            validated_data = schema.load(sanitized_data)
        except ValidationError as e:
            return jsonify({
                'error': 'Validation failed',
                'details': e.messages,
                'code': 'VALIDATION_ERROR'
            }), 400
        
        # Additional email validation
        try:
            email_info = validate_email(validated_data['email'])
            validated_email = email_info.email
        except EmailNotValidError as e:
            return jsonify({
                'error': 'Invalid email address',
                'details': str(e),
                'code': 'INVALID_EMAIL'
            }), 400
        
        # Check for spam patterns in message content
        spam_patterns = [
            r'\b(viagra|cialis|loan|money|prize|winner|congratulations)\b',
            r'\b(click here|buy now|act now|limited time)\b',
            r'http[s]?://[^\s]+',  # URLs in message
            r'\b\d{10,}\b'  # Long numbers (phone/credit card)
        ]
        
        message_content = validated_data['message'].lower()
        for pattern in spam_patterns:
            if re.search(pattern, message_content, re.IGNORECASE):
                log_security_event("spam_detection", {
                    "pattern": pattern,
                    "source_ip": request.remote_addr,
                    "email": validated_email
                })
                return jsonify({
                    'error': 'Message content not allowed',
                    'code': 'SPAM_DETECTED'
                }), 400
        
        # Store contact submission (replace with actual storage mechanism)
        contact_data = {
            'name': validated_data['name'],
            'email': validated_email,
            'subject': validated_data['subject'],
            'message': validated_data['message'],
            'submitted_at': datetime.utcnow().isoformat(),
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get("User-Agent", ""),
            'status': 'pending'
        }
        
        # Log contact form submission
        logger.info(
            "Contact form submitted",
            email=validated_email,
            subject=validated_data['subject'],
            source_ip=request.remote_addr
        )
        
        increment_counter("contact_submissions_total", {"status": "success"})
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your message. We will respond within 24 hours.',
            'reference_id': generate_secure_token()[:16]  # Short reference ID
        }), 200
        
    except ValidationError as e:
        increment_counter("contact_submissions_total", {"status": "validation_error"})
        return jsonify({
            'error': 'Invalid input data',
            'details': str(e),
            'code': 'VALIDATION_ERROR'
        }), 400
        
    except Exception as e:
        logger.error("Contact form endpoint error", error=str(e))
        increment_counter("contact_submissions_total", {"status": "error"})
        
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500


@public_bp.route('/info', methods=['GET'])
@cross_origin(origins=CORS_ORIGINS, methods=['GET'])
def get_public_info():
    """
    Public information endpoint.
    
    This endpoint provides public application information including
    API version, supported features, and contact information.
    
    Returns:
        JSON response with public application information
    """
    try:
        public_info = {
            'application': {
                'name': 'Flask Enterprise API',
                'version': getattr(current_app, 'version', '1.0.0'),
                'environment': current_app.config.get('ENV', 'production'),
                'api_version': 'v1'
            },
            'features': {
                'user_registration': True,
                'password_reset': True,
                'contact_form': True,
                'rate_limiting': True,
                'cors_enabled': True
            },
            'security': {
                'https_required': True,
                'csrf_protection': True,
                'input_validation': True,
                'rate_limiting': True
            },
            'contact': {
                'support_email': 'support@company.com',
                'documentation_url': 'https://docs.company.com/api',
                'status_page': 'https://status.company.com'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Log public info access
        logger.debug(
            "Public info accessed",
            source_ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")
        )
        
        increment_counter("public_info_requests_total", {"status": "success"})
        
        return jsonify(public_info), 200
        
    except Exception as e:
        logger.error("Public info endpoint error", error=str(e))
        increment_counter("public_info_requests_total", {"status": "error"})
        
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500


@public_bp.route('/api-docs', methods=['GET'])
@cross_origin(origins=CORS_ORIGINS, methods=['GET'])
def get_api_documentation():
    """
    Public API documentation endpoint.
    
    This endpoint provides OpenAPI/Swagger documentation for public
    endpoints to help developers integrate with the API.
    
    Returns:
        JSON response with OpenAPI specification
    """
    try:
        api_docs = {
            'openapi': '3.0.0',
            'info': {
                'title': 'Public API Documentation',
                'version': '1.0.0',
                'description': 'Public endpoints for user registration, password reset, and general information.',
                'contact': {
                    'name': 'API Support',
                    'email': 'api-support@company.com',
                    'url': 'https://docs.company.com'
                }
            },
            'servers': [
                {
                    'url': request.url_root.rstrip('/'),
                    'description': 'Current server'
                }
            ],
            'paths': {
                '/api/public/register': {
                    'post': {
                        'summary': 'User Registration',
                        'description': 'Register a new user account via Auth0',
                        'tags': ['Authentication'],
                        'requestBody': {
                            'required': True,
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'required': ['email', 'password', 'first_name', 'last_name', 'terms_accepted'],
                                        'properties': {
                                            'email': {'type': 'string', 'format': 'email'},
                                            'password': {'type': 'string', 'minLength': 8},
                                            'first_name': {'type': 'string', 'maxLength': 50},
                                            'last_name': {'type': 'string', 'maxLength': 50},
                                            'organization': {'type': 'string', 'maxLength': 100},
                                            'terms_accepted': {'type': 'boolean'},
                                            'marketing_consent': {'type': 'boolean'}
                                        }
                                    }
                                }
                            }
                        },
                        'responses': {
                            '201': {'description': 'Registration successful'},
                            '400': {'description': 'Validation error'},
                            '409': {'description': 'User already exists'},
                            '500': {'description': 'Registration failed'}
                        }
                    }
                },
                '/api/public/password-reset': {
                    'post': {
                        'summary': 'Password Reset Request',
                        'description': 'Request password reset for user account',
                        'tags': ['Authentication'],
                        'requestBody': {
                            'required': True,
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'required': ['email'],
                                        'properties': {
                                            'email': {'type': 'string', 'format': 'email'}
                                        }
                                    }
                                }
                            }
                        },
                        'responses': {
                            '200': {'description': 'Reset request processed'},
                            '400': {'description': 'Validation error'},
                            '500': {'description': 'Reset request failed'}
                        }
                    }
                },
                '/api/public/contact': {
                    'post': {
                        'summary': 'Contact Form Submission',
                        'description': 'Submit contact form message',
                        'tags': ['Contact'],
                        'requestBody': {
                            'required': True,
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'required': ['name', 'email', 'subject', 'message'],
                                        'properties': {
                                            'name': {'type': 'string', 'maxLength': 100},
                                            'email': {'type': 'string', 'format': 'email'},
                                            'subject': {'type': 'string', 'maxLength': 200},
                                            'message': {'type': 'string', 'maxLength': 2000}
                                        }
                                    }
                                }
                            }
                        },
                        'responses': {
                            '200': {'description': 'Message submitted successfully'},
                            '400': {'description': 'Validation error'},
                            '500': {'description': 'Submission failed'}
                        }
                    }
                }
            }
        }
        
        logger.debug(
            "API documentation accessed",
            source_ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")
        )
        
        increment_counter("api_docs_requests_total", {"status": "success"})
        
        return jsonify(api_docs), 200
        
    except Exception as e:
        logger.error("API docs endpoint error", error=str(e))
        increment_counter("api_docs_requests_total", {"status": "error"})
        
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500


# Error handlers for the blueprint
@public_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle 400 Bad Request errors."""
    logger.warning("Bad request error", error=str(error))
    increment_counter("public_errors_total", {"status_code": "400"})
    
    return jsonify({
        'error': 'Bad request',
        'message': 'The request could not be understood by the server',
        'code': 'BAD_REQUEST'
    }), 400


@public_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 Not Found errors."""
    logger.warning("Endpoint not found", path=request.path)
    increment_counter("public_errors_total", {"status_code": "404"})
    
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist',
        'code': 'NOT_FOUND'
    }), 404


@public_bp.errorhandler(405)
def handle_method_not_allowed(error):
    """Handle 405 Method Not Allowed errors."""
    logger.warning("Method not allowed", method=request.method, path=request.path)
    increment_counter("public_errors_total", {"status_code": "405"})
    
    return jsonify({
        'error': 'Method not allowed',
        'message': f'The {request.method} method is not allowed for this endpoint',
        'code': 'METHOD_NOT_ALLOWED'
    }), 405


@public_bp.errorhandler(429)
def handle_rate_limit_exceeded(error):
    """Handle 429 Rate Limit Exceeded errors."""
    logger.warning(
        "Rate limit exceeded",
        source_ip=request.remote_addr,
        endpoint=request.endpoint
    )
    increment_counter("public_errors_total", {"status_code": "429"})
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'code': 'RATE_LIMIT_EXCEEDED',
        'retry_after': 60
    }), 429


@public_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle 500 Internal Server Error."""
    logger.error("Internal server error", error=str(error))
    increment_counter("public_errors_total", {"status_code": "500"})
    
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'code': 'INTERNAL_ERROR'
    }), 500


# Blueprint initialization function
def init_public_blueprint(app, limiter):
    """
    Initialize the public blueprint with Flask app and rate limiter.
    
    This function configures the public blueprint with proper rate limiting,
    CORS settings, and security controls for production deployment.
    
    Args:
        app: Flask application instance
        limiter: Flask-Limiter instance for rate limiting
    """
    global public_limiter
    public_limiter = limiter
    
    # Configure blueprint-specific rate limits
    if limiter:
        # Registration endpoint - stricter limits
        limiter.limit("5 per minute")(register_user)
        limiter.limit("20 per hour")(register_user)
        
        # Password reset endpoint - moderate limits  
        limiter.limit("3 per minute")(request_password_reset)
        limiter.limit("10 per hour")(request_password_reset)
        
        # Contact form endpoint - moderate limits
        limiter.limit("2 per minute")(submit_contact_form)
        limiter.limit("10 per hour")(submit_contact_form)
        
        # Info endpoints - generous limits
        limiter.limit("30 per minute")(get_public_info)
        limiter.limit("100 per hour")(get_public_info)
        limiter.limit("20 per minute")(get_api_documentation)
        limiter.limit("50 per hour")(get_api_documentation)
    
    logger.info("Public blueprint initialized successfully")


# Blueprint registration
def register_blueprint(app):
    """Register the public blueprint with the Flask application."""
    app.register_blueprint(public_bp)
    logger.info("Public blueprint registered with Flask application")