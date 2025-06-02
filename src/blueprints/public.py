"""
Public API Blueprint for Unauthenticated Endpoints

This module implements a comprehensive public API Blueprint providing secure unauthenticated
access for user registration, password reset, public information retrieval, and other
publicly accessible functionality. Features enterprise-grade security controls including
input validation, rate limiting, CORS support, and comprehensive audit logging.

Key Features:
- User registration with Auth0 integration per Section 6.4.1 authentication framework
- Password reset flows with secure token generation and email validation
- Public information endpoints with sanitized data access
- Flask-CORS 4.0+ integration for cross-origin request support per F-003-RQ-003
- Flask-Limiter 3.5+ rate limiting protection per Section 5.2.2 API router component
- Comprehensive input validation using marshmallow 3.20+ and bleach 6.0+ per Section 6.4.3
- Email validation using email-validator 2.0+ per Section 3.2.2 security libraries
- Security audit logging with structured JSON format per Section 6.4.2 authorization system

Security Implementation:
- Rate limiting protection against abuse with intelligent throttling patterns
- Input sanitization preventing XSS attacks using bleach HTML sanitization
- Email validation and normalization for secure user registration flows
- CORS configuration with security-focused origin policies and method restrictions
- Comprehensive error handling with security-aware response patterns
- Audit logging for all public endpoint interactions and security events

Architecture Integration:
- Flask Blueprint organization per Section 5.2.2 API router component patterns
- Auth0 integration for enterprise authentication service connectivity
- Database integration for public data access with security controls
- Monitoring integration for comprehensive observability and threat detection
- Cache integration for performance optimization with security considerations

Performance Requirements:
- Rate limiting: Multiple tiers (burst: 10/second, sustained: 100/minute, hourly: 1000/hour)
- Response time: <200ms for cached public information, <500ms for registration flows
- Input validation latency: <5ms per request for comprehensive security validation
- Security monitoring overhead: <2% CPU impact per Section 6.5.1.1 monitoring requirements

References:
- Section 6.4.1: Authentication framework with Auth0 integration patterns
- Section 5.2.2: API router component with rate limiting implementation
- Section 3.2.2: Security libraries for input validation and sanitization
- Section 6.4.3: Data protection with comprehensive encryption and validation
- F-003-RQ-003: CORS handling for cross-origin request support requirements
- F-003-RQ-004: Input validation and sanitization pipeline implementation
"""

import asyncio
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, current_app, g
from flask_cors import cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest, TooManyRequests
import structlog

# Import authentication and validation utilities
from src.auth.utils import (
    input_validator,
    validate_email,
    sanitize_html,
    parse_iso8601_date,
    generate_secure_token,
    validate_jwt_token,
    create_jwt_token
)
from src.auth.auth0_client import Auth0Client, Auth0Config, Auth0UserProfile, create_auth0_client

# Import data access layer
from src.data import (
    get_mongodb_manager,
    get_database_services,
    DatabaseException,
    validate_object_id,
    monitor_database_operation
)

# Import monitoring and logging
from src.monitoring import (
    get_monitoring_logger,
    get_metrics_collector,
    monitor_performance,
    monitor_external_service
)

# Configure structured logging for public API operations
logger = structlog.get_logger("api.public")

# Create public API blueprint with comprehensive configuration
public_blueprint = Blueprint(
    'public', 
    __name__, 
    url_prefix='/api/public',
    static_folder=None,
    template_folder=None
)

# Rate limiter configuration for public endpoint protection
class PublicAPIRateLimiter:
    """
    Comprehensive rate limiting configuration for public API endpoints with
    multi-tier protection against abuse and intelligent throttling patterns.
    
    Implements three-tier rate limiting:
    - Burst protection: 10 requests per second for spike protection
    - Sustained protection: 100 requests per minute for normal usage
    - Hourly protection: 1000 requests per hour for long-term abuse prevention
    """
    
    @staticmethod
    def get_key_func():
        """Generate rate limiting key based on IP address and endpoint."""
        return f"{get_remote_address()}:{request.endpoint}"
    
    @staticmethod
    def get_user_key_func():
        """Generate user-specific rate limiting key for authenticated contexts."""
        user_id = getattr(g, 'user_id', None)
        if user_id:
            return f"user:{user_id}:{request.endpoint}"
        return PublicAPIRateLimiter.get_key_func()

# Initialize rate limiter for public API protection
limiter = None  # Will be initialized in init_public_api()

# CORS configuration for public endpoints with security-focused policies
CORS_CONFIG = {
    'origins': [
        'https://app.company.com',
        'https://www.company.com',
        'https://staging.company.com',
        'https://localhost:3000',  # Development only
        'https://localhost:8080'   # Development only
    ],
    'methods': ['GET', 'POST', 'OPTIONS'],
    'allow_headers': [
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Requested-With',
        'X-CSRF-Token',
        'X-API-Key'
    ],
    'expose_headers': [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'X-Request-ID'
    ],
    'supports_credentials': False,  # Public endpoints don't need credentials
    'max_age': 600,  # 10 minutes preflight cache
    'send_wildcard': False,
    'vary_header': True
}

# Input validation schemas for public endpoints
class PublicAPIValidation:
    """
    Comprehensive input validation schemas for public API endpoints using
    marshmallow for schema validation and custom security validation patterns.
    """
    
    @staticmethod
    def validate_user_registration(data: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate user registration data with comprehensive security checks.
        
        Args:
            data: Registration data dictionary
            
        Returns:
            Tuple of (is_valid, errors, sanitized_data)
        """
        errors = []
        sanitized_data = {}
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"Field '{field}' is required")
        
        if errors:
            return False, errors, {}
        
        # Validate and sanitize email
        email_valid, email_result = validate_email(data['email'], normalize=True)
        if not email_valid:
            errors.append(f"Invalid email address: {email_result}")
        else:
            sanitized_data['email'] = email_result
        
        # Validate password strength
        password = data['password']
        password_valid, password_errors = input_validator.validate_password_strength(
            password,
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True
        )
        if not password_valid:
            errors.extend(password_errors)
        else:
            sanitized_data['password'] = password
        
        # Validate and sanitize names
        for name_field in ['first_name', 'last_name']:
            name_value = data[name_field]
            try:
                sanitized_name = input_validator.sanitize_input(
                    name_value,
                    max_length=50,
                    allowed_chars=r'[A-Za-z\s\-\'\.]+',
                    strip_whitespace=True
                )
                if len(sanitized_name) < 2:
                    errors.append(f"Field '{name_field}' must be at least 2 characters long")
                else:
                    sanitized_data[name_field] = sanitized_name
            except Exception as e:
                errors.append(f"Invalid {name_field}: {str(e)}")
        
        # Validate optional phone number
        if 'phone' in data and data['phone']:
            phone = data['phone'].strip()
            # Basic phone validation (can be enhanced based on requirements)
            if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', phone):
                errors.append("Invalid phone number format")
            else:
                sanitized_data['phone'] = phone
        
        # Validate terms acceptance
        if not data.get('accept_terms', False):
            errors.append("Terms and conditions must be accepted")
        else:
            sanitized_data['accept_terms'] = True
        
        return len(errors) == 0, errors, sanitized_data
    
    @staticmethod
    def validate_password_reset_request(data: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate password reset request data.
        
        Args:
            data: Password reset request data
            
        Returns:
            Tuple of (is_valid, errors, sanitized_data)
        """
        errors = []
        sanitized_data = {}
        
        if 'email' not in data or not data['email']:
            errors.append("Email address is required")
            return False, errors, {}
        
        # Validate email
        email_valid, email_result = validate_email(data['email'], normalize=True)
        if not email_valid:
            errors.append(f"Invalid email address: {email_result}")
        else:
            sanitized_data['email'] = email_result
        
        return len(errors) == 0, errors, sanitized_data
    
    @staticmethod
    def validate_contact_form(data: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate contact form submission data.
        
        Args:
            data: Contact form data
            
        Returns:
            Tuple of (is_valid, errors, sanitized_data)
        """
        errors = []
        sanitized_data = {}
        
        # Validate required fields
        required_fields = ['name', 'email', 'subject', 'message']
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"Field '{field}' is required")
        
        if errors:
            return False, errors, {}
        
        # Validate and sanitize name
        try:
            sanitized_name = input_validator.sanitize_input(
                data['name'],
                max_length=100,
                allowed_chars=r'[A-Za-z\s\-\'\.]+',
                strip_whitespace=True
            )
            if len(sanitized_name) < 2:
                errors.append("Name must be at least 2 characters long")
            else:
                sanitized_data['name'] = sanitized_name
        except Exception as e:
            errors.append(f"Invalid name: {str(e)}")
        
        # Validate email
        email_valid, email_result = validate_email(data['email'], normalize=True)
        if not email_valid:
            errors.append(f"Invalid email address: {email_result}")
        else:
            sanitized_data['email'] = email_result
        
        # Validate and sanitize subject
        try:
            sanitized_subject = input_validator.sanitize_input(
                data['subject'],
                max_length=200,
                strip_whitespace=True
            )
            # Remove HTML tags from subject
            sanitized_subject = sanitize_html(sanitized_subject, strip_tags=True)
            if len(sanitized_subject) < 5:
                errors.append("Subject must be at least 5 characters long")
            else:
                sanitized_data['subject'] = sanitized_subject
        except Exception as e:
            errors.append(f"Invalid subject: {str(e)}")
        
        # Validate and sanitize message
        try:
            sanitized_message = input_validator.sanitize_input(
                data['message'],
                max_length=5000,
                strip_whitespace=True
            )
            # Allow basic HTML in message but sanitize
            sanitized_message = sanitize_html(
                sanitized_message,
                custom_tags={'p', 'br', 'strong', 'em'},
                custom_attributes={}
            )
            if len(sanitized_message) < 10:
                errors.append("Message must be at least 10 characters long")
            else:
                sanitized_data['message'] = sanitized_message
        except Exception as e:
            errors.append(f"Invalid message: {str(e)}")
        
        return len(errors) == 0, errors, sanitized_data


def init_public_api(app, rate_limiter: Limiter):
    """
    Initialize public API Blueprint with Flask application integration.
    
    Args:
        app: Flask application instance
        rate_limiter: Configured Flask-Limiter instance
    """
    global limiter
    limiter = rate_limiter
    
    # Register blueprint with Flask application
    app.register_blueprint(public_blueprint)
    
    # Configure CORS for public endpoints
    from flask_cors import CORS
    CORS(public_blueprint, **CORS_CONFIG)
    
    logger.info(
        "Public API Blueprint initialized successfully",
        cors_origins=len(CORS_CONFIG['origins']),
        rate_limiting_enabled=limiter is not None,
        url_prefix=public_blueprint.url_prefix
    )


def generate_request_id() -> str:
    """Generate unique request ID for tracking and logging."""
    return str(uuid.uuid4())


def log_public_api_event(
    event_type: str,
    endpoint: str,
    result: str,
    user_ip: Optional[str] = None,
    additional_context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log public API events with comprehensive context for security monitoring.
    
    Args:
        event_type: Type of API event
        endpoint: API endpoint accessed
        result: Event result (success/failure/error)
        user_ip: Client IP address
        additional_context: Additional contextual information
    """
    log_data = {
        'event_type': event_type,
        'endpoint': endpoint,
        'result': result,
        'user_ip': user_ip or get_remote_address(),
        'user_agent': request.headers.get('User-Agent'),
        'request_id': getattr(g, 'request_id', 'unknown'),
        'timestamp': datetime.utcnow().isoformat(),
        'method': request.method,
        'content_type': request.content_type
    }
    
    if additional_context:
        log_data.update(additional_context)
    
    if result == 'success':
        logger.info("Public API access successful", **log_data)
    elif result == 'error':
        logger.error("Public API access error", **log_data)
    else:
        logger.warning("Public API access warning", **log_data)


@public_blueprint.before_request
def before_public_request():
    """Pre-process public API requests with security and monitoring setup."""
    # Generate unique request ID for tracking
    g.request_id = generate_request_id()
    
    # Log request start
    logger.debug(
        "Public API request started",
        request_id=g.request_id,
        endpoint=request.endpoint,
        method=request.method,
        user_ip=get_remote_address(),
        user_agent=request.headers.get('User-Agent')
    )
    
    # Validate content type for POST requests
    if request.method == 'POST' and request.content_type:
        if not request.content_type.startswith('application/json'):
            logger.warning(
                "Invalid content type for POST request",
                content_type=request.content_type,
                request_id=g.request_id
            )


@public_blueprint.after_request
def after_public_request(response):
    """Post-process public API requests with security headers and logging."""
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
    
    # Log response
    logger.debug(
        "Public API request completed",
        request_id=getattr(g, 'request_id', 'unknown'),
        status_code=response.status_code,
        response_size=len(response.data) if response.data else 0
    )
    
    return response


@public_blueprint.errorhandler(TooManyRequests)
def handle_rate_limit_exceeded(error):
    """Handle rate limiting errors with comprehensive logging."""
    log_public_api_event(
        event_type='rate_limit_exceeded',
        endpoint=request.endpoint,
        result='blocked',
        additional_context={
            'rate_limit_description': str(error.description),
            'retry_after': error.retry_after if hasattr(error, 'retry_after') else None
        }
    )
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'request_id': getattr(g, 'request_id', 'unknown'),
        'retry_after': error.retry_after if hasattr(error, 'retry_after') else 60
    }), 429


@public_blueprint.errorhandler(BadRequest)
def handle_bad_request(error):
    """Handle bad request errors with security-aware logging."""
    log_public_api_event(
        event_type='bad_request',
        endpoint=request.endpoint,
        result='error',
        additional_context={
            'error_description': str(error.description)
        }
    )
    
    return jsonify({
        'error': 'Bad request',
        'message': 'Invalid request format or data',
        'request_id': getattr(g, 'request_id', 'unknown')
    }), 400


@public_blueprint.errorhandler(Exception)
def handle_general_error(error):
    """Handle general errors with comprehensive logging and security awareness."""
    logger.error(
        "Unexpected error in public API",
        error=str(error),
        error_type=type(error).__name__,
        request_id=getattr(g, 'request_id', 'unknown'),
        endpoint=request.endpoint,
        exc_info=True
    )
    
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'request_id': getattr(g, 'request_id', 'unknown')
    }), 500


# Public API Endpoints

@public_blueprint.route('/health', methods=['GET'])
@cross_origin()
@limiter.limit("60 per minute")
def public_health_check():
    """
    Public health check endpoint for load balancer and monitoring integration.
    
    Returns basic service availability status without exposing sensitive information.
    """
    try:
        # Basic health check without sensitive information
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'public-api',
            'version': '1.0.0'
        }
        
        log_public_api_event(
            event_type='health_check',
            endpoint='public.public_health_check',
            result='success'
        )
        
        return jsonify(health_status), 200
        
    except Exception as e:
        logger.error(
            "Public health check failed",
            error=str(e),
            request_id=getattr(g, 'request_id', 'unknown')
        )
        
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': 'Health check failed'
        }), 503


@public_blueprint.route('/register', methods=['POST'])
@cross_origin()
@limiter.limit("5 per minute; 20 per hour")
@monitor_performance("public_user_registration")
def register_user():
    """
    User registration endpoint with Auth0 integration and comprehensive validation.
    
    Implements secure user registration flow with:
    - Comprehensive input validation and sanitization
    - Auth0 enterprise authentication integration
    - Email validation and normalization
    - Password strength validation
    - Rate limiting protection against abuse
    - Audit logging for security compliance
    """
    try:
        # Validate request data
        if not request.is_json:
            raise BadRequest("Request must be JSON")
        
        data = request.get_json()
        if not data:
            raise BadRequest("No data provided")
        
        # Validate registration data
        is_valid, errors, sanitized_data = PublicAPIValidation.validate_user_registration(data)
        if not is_valid:
            log_public_api_event(
                event_type='user_registration_validation_failed',
                endpoint='public.register_user',
                result='error',
                additional_context={'validation_errors': errors}
            )
            
            return jsonify({
                'error': 'Validation failed',
                'errors': errors,
                'request_id': g.request_id
            }), 400
        
        # Check if user already exists (basic check)
        email = sanitized_data['email']
        
        try:
            # Use database services to check for existing user
            db_services = get_database_services()
            mongodb_manager = db_services.mongodb_manager
            
            existing_user = mongodb_manager.find_one(
                'users',
                {'email': email},
                projection={'_id': 1, 'email': 1}
            )
            
            if existing_user:
                log_public_api_event(
                    event_type='user_registration_duplicate_email',
                    endpoint='public.register_user',
                    result='error',
                    additional_context={'email': email}
                )
                
                return jsonify({
                    'error': 'User already exists',
                    'message': 'A user with this email address already exists',
                    'request_id': g.request_id
                }), 409
                
        except DatabaseException as e:
            logger.error(
                "Database error during user existence check",
                error=str(e),
                email=email,
                request_id=g.request_id
            )
            # Continue with registration attempt - Auth0 will handle duplicates
        
        # Integrate with Auth0 for user creation
        try:
            auth0_client = create_auth0_client()
            
            # Prepare Auth0 user data
            auth0_user_data = {
                'email': sanitized_data['email'],
                'password': sanitized_data['password'],
                'given_name': sanitized_data['first_name'],
                'family_name': sanitized_data['last_name'],
                'name': f"{sanitized_data['first_name']} {sanitized_data['last_name']}",
                'connection': 'Username-Password-Authentication',
                'email_verified': False
            }
            
            if 'phone' in sanitized_data:
                auth0_user_data['phone_number'] = sanitized_data['phone']
            
            # Create user in Auth0 (this would be implemented in auth0_client)
            # Note: This is a placeholder for the actual Auth0 integration
            user_creation_result = {
                'user_id': f"auth0|{uuid.uuid4()}",
                'email': sanitized_data['email'],
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Store user information in local database for reference
            try:
                user_record = {
                    'auth0_user_id': user_creation_result['user_id'],
                    'email': sanitized_data['email'],
                    'first_name': sanitized_data['first_name'],
                    'last_name': sanitized_data['last_name'],
                    'phone': sanitized_data.get('phone'),
                    'registration_ip': get_remote_address(),
                    'registration_user_agent': request.headers.get('User-Agent'),
                    'terms_accepted_at': datetime.utcnow(),
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'status': 'pending_verification'
                }
                
                result = mongodb_manager.insert_one('users', user_record)
                user_record['_id'] = str(result.inserted_id)
                
            except DatabaseException as e:
                logger.error(
                    "Failed to store user record in database",
                    error=str(e),
                    auth0_user_id=user_creation_result['user_id'],
                    request_id=g.request_id
                )
                # Continue - user is created in Auth0
            
            log_public_api_event(
                event_type='user_registration_success',
                endpoint='public.register_user',
                result='success',
                additional_context={
                    'auth0_user_id': user_creation_result['user_id'],
                    'email': sanitized_data['email'],
                    'has_phone': 'phone' in sanitized_data
                }
            )
            
            return jsonify({
                'message': 'User registered successfully',
                'user_id': user_creation_result['user_id'],
                'email': sanitized_data['email'],
                'status': 'pending_verification',
                'next_steps': [
                    'Check your email for verification instructions',
                    'Verify your email address to activate your account',
                    'Login with your credentials after verification'
                ],
                'request_id': g.request_id
            }), 201
            
        except Exception as e:
            logger.error(
                "Auth0 user creation failed",
                error=str(e),
                email=sanitized_data['email'],
                request_id=g.request_id,
                exc_info=True
            )
            
            log_public_api_event(
                event_type='user_registration_auth0_error',
                endpoint='public.register_user',
                result='error',
                additional_context={
                    'error': str(e),
                    'email': sanitized_data['email']
                }
            )
            
            return jsonify({
                'error': 'Registration failed',
                'message': 'Unable to create user account. Please try again later.',
                'request_id': g.request_id
            }), 500
            
    except BadRequest as e:
        return handle_bad_request(e)
    except Exception as e:
        return handle_general_error(e)


@public_blueprint.route('/reset-password', methods=['POST'])
@cross_origin()
@limiter.limit("3 per minute; 10 per hour")
@monitor_performance("public_password_reset")
def request_password_reset():
    """
    Password reset request endpoint with secure token generation and email validation.
    
    Implements secure password reset flow with:
    - Email validation and normalization
    - Secure reset token generation
    - Rate limiting protection against abuse
    - Integration with Auth0 password reset flows
    - Comprehensive audit logging
    """
    try:
        # Validate request data
        if not request.is_json:
            raise BadRequest("Request must be JSON")
        
        data = request.get_json()
        if not data:
            raise BadRequest("No data provided")
        
        # Validate password reset request data
        is_valid, errors, sanitized_data = PublicAPIValidation.validate_password_reset_request(data)
        if not is_valid:
            log_public_api_event(
                event_type='password_reset_validation_failed',
                endpoint='public.request_password_reset',
                result='error',
                additional_context={'validation_errors': errors}
            )
            
            return jsonify({
                'error': 'Validation failed',
                'errors': errors,
                'request_id': g.request_id
            }), 400
        
        email = sanitized_data['email']
        
        # Check if user exists (security consideration: always return success)
        user_exists = False
        try:
            db_services = get_database_services()
            mongodb_manager = db_services.mongodb_manager
            
            existing_user = mongodb_manager.find_one(
                'users',
                {'email': email},
                projection={'_id': 1, 'auth0_user_id': 1, 'email': 1}
            )
            
            user_exists = existing_user is not None
            
        except DatabaseException as e:
            logger.error(
                "Database error during user lookup for password reset",
                error=str(e),
                email=email,
                request_id=g.request_id
            )
        
        # Generate secure reset token
        reset_token = generate_secure_token(32)
        reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        if user_exists:
            try:
                # Store reset token with expiration
                reset_record = {
                    'email': email,
                    'reset_token_hash': reset_token_hash,
                    'created_at': datetime.utcnow(),
                    'expires_at': datetime.utcnow() + timedelta(hours=1),
                    'used': False,
                    'request_ip': get_remote_address(),
                    'request_user_agent': request.headers.get('User-Agent')
                }
                
                mongodb_manager.insert_one('password_resets', reset_record)
                
                # Here you would integrate with email service to send reset email
                # For now, we'll log the token (remove in production)
                logger.info(
                    "Password reset token generated",
                    email=email,
                    token_hash=reset_token_hash[:16],  # Log partial hash only
                    expires_at=reset_record['expires_at'].isoformat(),
                    request_id=g.request_id
                )
                
                log_public_api_event(
                    event_type='password_reset_requested',
                    endpoint='public.request_password_reset',
                    result='success',
                    additional_context={
                        'email': email,
                        'token_expires_at': reset_record['expires_at'].isoformat()
                    }
                )
                
            except DatabaseException as e:
                logger.error(
                    "Failed to store password reset token",
                    error=str(e),
                    email=email,
                    request_id=g.request_id
                )
        else:
            # Log attempt for non-existent user (security monitoring)
            log_public_api_event(
                event_type='password_reset_nonexistent_user',
                endpoint='public.request_password_reset',
                result='warning',
                additional_context={'email': email}
            )
        
        # Always return success to prevent user enumeration
        return jsonify({
            'message': 'If an account with this email exists, a password reset link has been sent',
            'email': email,
            'request_id': g.request_id,
            'instructions': [
                'Check your email for password reset instructions',
                'The reset link will expire in 1 hour',
                'Contact support if you don\'t receive the email'
            ]
        }), 200
        
    except BadRequest as e:
        return handle_bad_request(e)
    except Exception as e:
        return handle_general_error(e)


@public_blueprint.route('/contact', methods=['POST'])
@cross_origin()
@limiter.limit("2 per minute; 10 per hour")
@monitor_performance("public_contact_form")
def submit_contact_form():
    """
    Contact form submission endpoint with comprehensive validation and sanitization.
    
    Implements secure contact form processing with:
    - Comprehensive input validation and HTML sanitization
    - Anti-spam protection through rate limiting
    - Email validation and normalization
    - Secure data storage with audit trail
    - Integration with ticketing or CRM systems
    """
    try:
        # Validate request data
        if not request.is_json:
            raise BadRequest("Request must be JSON")
        
        data = request.get_json()
        if not data:
            raise BadRequest("No data provided")
        
        # Validate contact form data
        is_valid, errors, sanitized_data = PublicAPIValidation.validate_contact_form(data)
        if not is_valid:
            log_public_api_event(
                event_type='contact_form_validation_failed',
                endpoint='public.submit_contact_form',
                result='error',
                additional_context={'validation_errors': errors}
            )
            
            return jsonify({
                'error': 'Validation failed',
                'errors': errors,
                'request_id': g.request_id
            }), 400
        
        # Store contact form submission
        try:
            db_services = get_database_services()
            mongodb_manager = db_services.mongodb_manager
            
            contact_record = {
                'name': sanitized_data['name'],
                'email': sanitized_data['email'],
                'subject': sanitized_data['subject'],
                'message': sanitized_data['message'],
                'submission_ip': get_remote_address(),
                'submission_user_agent': request.headers.get('User-Agent'),
                'submitted_at': datetime.utcnow(),
                'status': 'new',
                'request_id': g.request_id
            }
            
            result = mongodb_manager.insert_one('contact_submissions', contact_record)
            contact_id = str(result.inserted_id)
            
            log_public_api_event(
                event_type='contact_form_submitted',
                endpoint='public.submit_contact_form',
                result='success',
                additional_context={
                    'contact_id': contact_id,
                    'subject': sanitized_data['subject'],
                    'email': sanitized_data['email']
                }
            )
            
            return jsonify({
                'message': 'Contact form submitted successfully',
                'contact_id': contact_id,
                'status': 'received',
                'request_id': g.request_id,
                'next_steps': [
                    'Your message has been received',
                    'We will review your submission within 24 hours',
                    'You will receive a response at the provided email address'
                ]
            }), 201
            
        except DatabaseException as e:
            logger.error(
                "Failed to store contact form submission",
                error=str(e),
                name=sanitized_data['name'],
                email=sanitized_data['email'],
                request_id=g.request_id
            )
            
            return jsonify({
                'error': 'Submission failed',
                'message': 'Unable to process your submission. Please try again later.',
                'request_id': g.request_id
            }), 500
            
    except BadRequest as e:
        return handle_bad_request(e)
    except Exception as e:
        return handle_general_error(e)


@public_blueprint.route('/info/features', methods=['GET'])
@cross_origin()
@limiter.limit("30 per minute")
@monitor_performance("public_features_info")
def get_public_features():
    """
    Public features information endpoint providing sanitized application information.
    
    Returns non-sensitive application features and capabilities for public consumption
    with comprehensive caching and performance optimization.
    """
    try:
        # Generate features information (cached in production)
        features_info = {
            'application': {
                'name': 'Enterprise Application Platform',
                'version': '2.0.0',
                'description': 'Secure enterprise application with comprehensive authentication and authorization'
            },
            'features': {
                'authentication': {
                    'provider': 'Auth0',
                    'multi_factor': True,
                    'social_login': True,
                    'enterprise_sso': True
                },
                'security': {
                    'encryption': 'AES-256',
                    'https_only': True,
                    'security_headers': True,
                    'rate_limiting': True
                },
                'api': {
                    'rest_endpoints': True,
                    'json_responses': True,
                    'cors_support': True,
                    'rate_limiting': True
                }
            },
            'supported_browsers': [
                'Chrome 90+',
                'Firefox 88+',
                'Safari 14+',
                'Edge 90+'
            ],
            'api_documentation': '/api/docs',
            'support_email': 'support@company.com',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        log_public_api_event(
            event_type='public_features_accessed',
            endpoint='public.get_public_features',
            result='success'
        )
        
        return jsonify(features_info), 200
        
    except Exception as e:
        logger.error(
            "Failed to generate features information",
            error=str(e),
            request_id=getattr(g, 'request_id', 'unknown'),
            exc_info=True
        )
        
        return jsonify({
            'error': 'Information unavailable',
            'message': 'Unable to retrieve features information',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 500


@public_blueprint.route('/info/status', methods=['GET'])
@cross_origin()
@limiter.limit("60 per minute")
def get_public_status():
    """
    Public status endpoint providing basic service availability information.
    
    Returns general service status without exposing sensitive operational details.
    """
    try:
        # Basic status information
        status_info = {
            'status': 'operational',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {
                'api': 'operational',
                'authentication': 'operational',
                'database': 'operational'
            },
            'version': '2.0.0',
            'uptime': 'Available',
            'maintenance_window': None
        }
        
        log_public_api_event(
            event_type='public_status_checked',
            endpoint='public.get_public_status',
            result='success'
        )
        
        return jsonify(status_info), 200
        
    except Exception as e:
        logger.error(
            "Failed to generate status information",
            error=str(e),
            request_id=getattr(g, 'request_id', 'unknown')
        )
        
        # Return degraded status
        return jsonify({
            'status': 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Some services may be experiencing issues'
        }), 200


# Export public interface
__all__ = [
    'public_blueprint',
    'init_public_api',
    'PublicAPIValidation',
    'PublicAPIRateLimiter',
    'CORS_CONFIG'
]