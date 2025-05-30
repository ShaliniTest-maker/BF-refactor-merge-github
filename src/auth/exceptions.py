"""
Authentication and Authorization Exception Classes

This module provides comprehensive exception handling for the Flask authentication system,
implementing enterprise-grade security patterns with security-focused error handling,
Flask error handler integration, and comprehensive audit logging support.

The exception hierarchy is designed to:
- Provide specific exception types for different failure scenarios
- Prevent information disclosure through security-focused error messages
- Support enterprise compliance and audit requirements
- Integrate seamlessly with Flask error handlers and monitoring systems
- Maintain equivalent functionality to Node.js authentication patterns

Dependencies:
- typing: Type annotations for enterprise code quality
- enum: Error code categorization and standardization
- datetime: Timestamp generation for audit logging
- uuid: Unique error identifier generation

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

from typing import Optional, Dict, Any, Union, List
from enum import Enum
from datetime import datetime
import uuid


class SecurityErrorCode(Enum):
    """
    Standardized security error codes for enterprise compliance and monitoring.
    
    These codes provide consistent categorization of security failures for:
    - Security Information and Event Management (SIEM) integration
    - Prometheus metrics collection and alerting
    - Audit logging and compliance reporting
    - Incident response and threat analysis
    """
    
    # Authentication Error Codes (1000-1999)
    AUTH_TOKEN_MISSING = "AUTH_1001"
    AUTH_TOKEN_INVALID = "AUTH_1002"
    AUTH_TOKEN_EXPIRED = "AUTH_1003"
    AUTH_TOKEN_MALFORMED = "AUTH_1004"
    AUTH_CREDENTIALS_INVALID = "AUTH_1005"
    AUTH_USER_NOT_FOUND = "AUTH_1006"
    AUTH_ACCOUNT_LOCKED = "AUTH_1007"
    AUTH_MFA_REQUIRED = "AUTH_1008"
    AUTH_MFA_INVALID = "AUTH_1009"
    AUTH_SESSION_EXPIRED = "AUTH_1010"
    AUTH_SESSION_INVALID = "AUTH_1011"
    
    # Authorization Error Codes (2000-2999)
    AUTHZ_PERMISSION_DENIED = "AUTHZ_2001"
    AUTHZ_INSUFFICIENT_PERMISSIONS = "AUTHZ_2002"
    AUTHZ_RESOURCE_ACCESS_DENIED = "AUTHZ_2003"
    AUTHZ_ROLE_INSUFFICIENT = "AUTHZ_2004"
    AUTHZ_SCOPE_INVALID = "AUTHZ_2005"
    AUTHZ_POLICY_VIOLATION = "AUTHZ_2006"
    AUTHZ_RESOURCE_NOT_FOUND = "AUTHZ_2007"
    AUTHZ_OWNERSHIP_REQUIRED = "AUTHZ_2008"
    
    # External Service Error Codes (3000-3999)
    EXT_AUTH0_UNAVAILABLE = "EXT_3001"
    EXT_AUTH0_TIMEOUT = "EXT_3002"
    EXT_AUTH0_API_ERROR = "EXT_3003"
    EXT_AUTH0_RATE_LIMITED = "EXT_3004"
    EXT_CIRCUIT_BREAKER_OPEN = "EXT_3005"
    EXT_SERVICE_DEGRADED = "EXT_3006"
    EXT_AWS_KMS_ERROR = "EXT_3007"
    EXT_REDIS_UNAVAILABLE = "EXT_3008"
    
    # Validation Error Codes (4000-4999)
    VAL_INPUT_INVALID = "VAL_4001"
    VAL_SCHEMA_VIOLATION = "VAL_4002"
    VAL_DATA_INTEGRITY = "VAL_4003"
    VAL_FORMAT_ERROR = "VAL_4004"
    VAL_SANITIZATION_FAILED = "VAL_4005"
    
    # Security Violation Error Codes (5000-5999)
    SEC_RATE_LIMIT_EXCEEDED = "SEC_5001"
    SEC_BRUTE_FORCE_DETECTED = "SEC_5002"
    SEC_SUSPICIOUS_ACTIVITY = "SEC_5003"
    SEC_IP_BLOCKED = "SEC_5004"
    SEC_SECURITY_HEADERS_VIOLATION = "SEC_5005"
    SEC_CSRF_TOKEN_INVALID = "SEC_5006"
    SEC_XSS_ATTEMPT_DETECTED = "SEC_5007"
    SEC_SQL_INJECTION_ATTEMPT = "SEC_5008"


class SecurityException(Exception):
    """
    Base exception class for all authentication and authorization failures.
    
    This class provides the foundation for enterprise-grade security exception handling
    with comprehensive audit logging, error categorization, and security-focused
    error messaging that prevents information disclosure.
    
    Features:
    - Unique error identifier generation for tracking and correlation
    - Standardized error codes for consistent categorization
    - Timestamp generation for audit trail requirements
    - Security-focused error messages that prevent information leakage
    - Metadata collection for comprehensive security monitoring
    - Integration hooks for Prometheus metrics and SIEM systems
    
    Args:
        message: Human-readable error description for logging and debugging
        error_code: Standardized security error code for categorization
        user_message: Safe message for client response (prevents info disclosure)
        metadata: Additional context for audit logging and analysis
        
    Example:
        try:
            validate_jwt_token(token)
        except SecurityException as e:
            log_security_event(e.error_code, e.metadata)
            return create_error_response(e.user_message, e.http_status)
    """
    
    def __init__(
        self, 
        message: str,
        error_code: SecurityErrorCode,
        user_message: str = "Access denied",
        metadata: Optional[Dict[str, Any]] = None,
        http_status: int = 403
    ) -> None:
        super().__init__(message)
        
        self.error_id = str(uuid.uuid4())
        self.error_code = error_code
        self.user_message = user_message
        self.metadata = metadata or {}
        self.http_status = http_status
        self.timestamp = datetime.utcnow()
        
        # Enhance metadata with security context
        self.metadata.update({
            'error_id': self.error_id,
            'error_code': self.error_code.value,
            'timestamp': self.timestamp.isoformat(),
            'exception_type': self.__class__.__name__,
            'security_event': True
        })


class AuthenticationException(SecurityException):
    """
    Exception class for authentication failures and JWT token validation errors.
    
    This exception handles all authentication-related failures including JWT token
    validation, user credential verification, session management, and Auth0 integration
    issues. It provides equivalent functionality to Node.js authentication error patterns
    while implementing enterprise security standards.
    
    Features:
    - JWT token validation error handling equivalent to Node.js jsonwebtoken errors
    - Auth0 integration failure management with circuit breaker support
    - Session management error handling for Flask-Login and Flask-Session
    - Multi-factor authentication failure handling
    - Account lockout and security policy enforcement
    
    Args:
        message: Detailed error description for logging and debugging
        error_code: Specific authentication error code for categorization
        user_message: Safe error message for client response
        token_claims: JWT token claims for audit logging (optional)
        user_id: User identifier for security event correlation (optional)
        
    Example:
        if not verify_jwt_signature(token):
            raise AuthenticationException(
                message="JWT signature verification failed",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                user_message="Invalid authentication token",
                metadata={'token_issuer': token.get('iss'), 'user_id': user_id}
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        user_message: str = "Authentication failed",
        token_claims: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        **kwargs
    ) -> None:
        # Default to 401 Unauthorized for authentication failures
        kwargs.setdefault('http_status', 401)
        
        super().__init__(message, error_code, user_message, **kwargs)
        
        # Add authentication-specific metadata
        if token_claims:
            # Sanitize token claims to prevent sensitive data leakage
            safe_claims = {
                'sub': token_claims.get('sub'),
                'iss': token_claims.get('iss'),
                'aud': token_claims.get('aud'),
                'exp': token_claims.get('exp'),
                'iat': token_claims.get('iat'),
                'jti': token_claims.get('jti')
            }
            self.metadata['token_claims'] = safe_claims
            
        if user_id:
            self.metadata['user_id'] = user_id
            
        self.metadata['auth_failure_category'] = 'authentication'


class JWTException(AuthenticationException):
    """
    Specialized exception for JWT token processing errors.
    
    This exception class provides equivalent functionality to Node.js jsonwebtoken
    library errors, handling all JWT-specific validation failures including signature
    verification, token expiration, malformed tokens, and cryptographic errors.
    
    Features:
    - Direct equivalent to Node.js JsonWebTokenError patterns
    - PyJWT 2.8+ integration with comprehensive error mapping
    - Cryptographic validation error handling
    - Token structure and format validation
    - Issuer and audience validation failures
    - Key rotation and signature verification errors
    
    Args:
        message: Detailed JWT error description for debugging
        jwt_error: Original PyJWT exception for technical analysis
        token_header: JWT header claims for audit logging
        validation_context: Additional validation context
        
    Example:
        try:
            decoded_token = jwt.decode(token, key, algorithms=['RS256'])
        except jwt.ExpiredSignatureError as e:
            raise JWTException(
                message=f"JWT token expired: {str(e)}",
                error_code=SecurityErrorCode.AUTH_TOKEN_EXPIRED,
                jwt_error=e,
                token_header=jwt.get_unverified_header(token)
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        jwt_error: Optional[Exception] = None,
        token_header: Optional[Dict[str, Any]] = None,
        validation_context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Invalid or expired authentication token')
        super().__init__(message, error_code, **kwargs)
        
        # Add JWT-specific metadata
        self.metadata.update({
            'jwt_failure_category': 'token_validation',
            'original_error_type': type(jwt_error).__name__ if jwt_error else None,
            'original_error_message': str(jwt_error) if jwt_error else None
        })
        
        if token_header:
            # Sanitize header to prevent sensitive data exposure
            safe_header = {
                'typ': token_header.get('typ'),
                'alg': token_header.get('alg'),
                'kid': token_header.get('kid')
            }
            self.metadata['token_header'] = safe_header
            
        if validation_context:
            self.metadata['validation_context'] = validation_context


class AuthorizationException(SecurityException):
    """
    Exception class for authorization and permission failures.
    
    This exception handles all authorization-related failures including role-based
    access control violations, resource permission denials, and policy enforcement
    failures. It supports enterprise-grade authorization patterns with comprehensive
    audit logging and security monitoring integration.
    
    Features:
    - Role-based access control (RBAC) violation handling
    - Resource-level permission checking and enforcement
    - Dynamic permission evaluation with context awareness
    - Policy violation tracking and reporting
    - Owner-based access control with delegation support
    - Hierarchical permission structure validation
    
    Args:
        message: Detailed authorization error description
        error_code: Specific authorization error code
        required_permissions: List of permissions required for the operation
        user_permissions: User's current permission set for analysis
        resource_id: Identifier of the protected resource
        resource_type: Type/category of the protected resource
        
    Example:
        if not has_permission(user, 'document.read', document_id):
            raise AuthorizationException(
                message=f"User {user_id} lacks permission to read document {document_id}",
                error_code=SecurityErrorCode.AUTHZ_PERMISSION_DENIED,
                required_permissions=['document.read'],
                user_permissions=user.permissions,
                resource_id=document_id,
                resource_type='document'
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        required_permissions: Optional[List[str]] = None,
        user_permissions: Optional[List[str]] = None,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[str] = None,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Insufficient permissions for this operation')
        super().__init__(message, error_code, **kwargs)
        
        # Add authorization-specific metadata
        self.metadata.update({
            'authz_failure_category': 'permission_denied',
            'required_permissions': required_permissions or [],
            'resource_id': resource_id,
            'resource_type': resource_type,
            'user_id': user_id
        })
        
        # Add user permissions for audit analysis (excluding sensitive permissions)
        if user_permissions:
            # Filter out sensitive admin permissions from logs
            safe_permissions = [
                perm for perm in user_permissions 
                if not any(sensitive in perm.lower() 
                          for sensitive in ['admin', 'root', 'super', 'system'])
            ]
            self.metadata['user_permissions_sample'] = safe_permissions[:10]  # Limit size


class Auth0Exception(SecurityException):
    """
    Exception class for Auth0 integration and external service failures.
    
    This exception handles Auth0 service integration failures, API communication
    errors, circuit breaker activations, and external authentication service
    degradation. It provides comprehensive resilience patterns and fallback
    mechanism support for enterprise authentication workflows.
    
    Features:
    - Auth0 API communication failure handling
    - Circuit breaker pattern integration for service resilience
    - Retry strategy failure reporting and analysis
    - External service timeout and rate limiting handling
    - Fallback mechanism trigger conditions
    - Service degradation and recovery monitoring
    
    Args:
        message: Detailed Auth0 service error description
        error_code: Specific external service error code
        service_response: Auth0 API response for technical analysis
        circuit_breaker_state: Current circuit breaker state
        retry_attempts: Number of retry attempts made
        fallback_used: Whether fallback mechanism was triggered
        
    Example:
        try:
            user_info = auth0_client.get_user_info(token)
        except Auth0ServiceException as e:
            raise Auth0Exception(
                message=f"Auth0 service unavailable: {str(e)}",
                error_code=SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
                service_response={'status_code': e.status_code},
                circuit_breaker_state='open',
                fallback_used=True
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        service_response: Optional[Dict[str, Any]] = None,
        circuit_breaker_state: Optional[str] = None,
        retry_attempts: Optional[int] = None,
        fallback_used: bool = False,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Authentication service temporarily unavailable')
        kwargs.setdefault('http_status', 503)  # Service Unavailable
        super().__init__(message, error_code, **kwargs)
        
        # Add Auth0-specific metadata
        self.metadata.update({
            'service_failure_category': 'external_auth_service',
            'service_name': 'auth0',
            'circuit_breaker_state': circuit_breaker_state,
            'retry_attempts': retry_attempts,
            'fallback_used': fallback_used
        })
        
        if service_response:
            # Sanitize service response to prevent sensitive data leakage
            safe_response = {
                'status_code': service_response.get('status_code'),
                'error_code': service_response.get('error_code'),
                'rate_limit_remaining': service_response.get('rate_limit_remaining')
            }
            self.metadata['service_response'] = safe_response


class PermissionException(AuthorizationException):
    """
    Specialized exception for granular permission validation failures.
    
    This exception provides detailed permission checking with support for
    hierarchical permissions, resource ownership validation, and context-aware
    authorization decisions. It integrates with enterprise RBAC systems and
    supports dynamic permission evaluation patterns.
    
    Features:
    - Granular permission checking with hierarchy support
    - Resource ownership and delegation validation
    - Context-aware permission evaluation
    - Time-based and conditional permission handling
    - Permission inheritance and role composition
    - Dynamic permission assignment and revocation tracking
    
    Args:
        message: Detailed permission failure description
        permission_name: Specific permission that was denied
        permission_scope: Scope or context of the permission check
        ownership_required: Whether resource ownership is required
        delegation_available: Whether permission can be delegated
        
    Example:
        if not check_resource_permission(user, 'document.delete', document_id):
            raise PermissionException(
                message=f"Delete permission denied for document {document_id}",
                error_code=SecurityErrorCode.AUTHZ_RESOURCE_ACCESS_DENIED,
                permission_name='document.delete',
                permission_scope=f'resource:{document_id}',
                ownership_required=True
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        permission_name: str,
        permission_scope: Optional[str] = None,
        ownership_required: bool = False,
        delegation_available: bool = False,
        **kwargs
    ) -> None:
        kwargs.setdefault('required_permissions', [permission_name])
        super().__init__(message, error_code, **kwargs)
        
        # Add permission-specific metadata
        self.metadata.update({
            'permission_failure_category': 'granular_permission',
            'permission_name': permission_name,
            'permission_scope': permission_scope,
            'ownership_required': ownership_required,
            'delegation_available': delegation_available
        })


class SessionException(AuthenticationException):
    """
    Exception class for session management and Flask-Session failures.
    
    This exception handles Flask-Login and Flask-Session integration failures,
    including session expiration, invalid session states, session encryption
    errors, and distributed session management issues with Redis backend.
    
    Features:
    - Flask-Login session state validation
    - Flask-Session Redis backend error handling
    - Session encryption and decryption failure management
    - Cross-instance session sharing failure handling
    - Session timeout and expiration management
    - Session security violation detection and reporting
    
    Args:
        message: Detailed session error description
        session_id: Session identifier for tracking and correlation
        session_state: Current session state for analysis
        encryption_error: Session encryption/decryption error details
        redis_error: Redis backend error information
        
    Example:
        try:
            session_data = decrypt_session_data(encrypted_session)
        except EncryptionError as e:
            raise SessionException(
                message=f"Session decryption failed: {str(e)}",
                error_code=SecurityErrorCode.AUTH_SESSION_INVALID,
                session_id=session.sid,
                encryption_error=str(e)
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        session_id: Optional[str] = None,
        session_state: Optional[str] = None,
        encryption_error: Optional[str] = None,
        redis_error: Optional[str] = None,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Session expired or invalid')
        super().__init__(message, error_code, **kwargs)
        
        # Add session-specific metadata
        self.metadata.update({
            'session_failure_category': 'session_management',
            'session_id': session_id,
            'session_state': session_state,
            'encryption_error': encryption_error,
            'redis_error': redis_error
        })


class RateLimitException(SecurityException):
    """
    Exception class for rate limiting and abuse prevention failures.
    
    This exception handles Flask-Limiter rate limiting violations, security
    throttling, and abuse prevention mechanisms. It supports enterprise-grade
    rate limiting with comprehensive monitoring and threat detection capabilities.
    
    Features:
    - Flask-Limiter integration with Redis backend
    - User-specific and endpoint-specific rate limiting
    - Burst and sustained rate limiting pattern enforcement
    - Security throttling for authentication endpoints
    - Abuse detection and suspicious activity reporting
    - Rate limiting metrics and monitoring integration
    
    Args:
        message: Detailed rate limiting error description
        limit_type: Type of rate limit that was exceeded
        current_rate: Current request rate for analysis
        limit_threshold: Rate limit threshold that was exceeded
        reset_time: When the rate limit will reset
        endpoint: API endpoint where rate limit was triggered
        
    Example:
        if rate_limiter.is_rate_limited(user_id, endpoint):
            raise RateLimitException(
                message=f"Rate limit exceeded for user {user_id} on {endpoint}",
                error_code=SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED,
                limit_type='user_endpoint',
                current_rate=current_requests_per_minute,
                limit_threshold=100,
                endpoint=endpoint
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode = SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED,
        limit_type: Optional[str] = None,
        current_rate: Optional[Union[int, float]] = None,
        limit_threshold: Optional[Union[int, float]] = None,
        reset_time: Optional[datetime] = None,
        endpoint: Optional[str] = None,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Rate limit exceeded. Please try again later.')
        kwargs.setdefault('http_status', 429)  # Too Many Requests
        super().__init__(message, error_code, **kwargs)
        
        # Add rate limiting metadata
        self.metadata.update({
            'rate_limit_failure_category': 'rate_limiting',
            'limit_type': limit_type,
            'current_rate': current_rate,
            'limit_threshold': limit_threshold,
            'reset_time': reset_time.isoformat() if reset_time else None,
            'endpoint': endpoint
        })


class CircuitBreakerException(SecurityException):
    """
    Exception class for circuit breaker pattern failures.
    
    This exception handles circuit breaker activations for external service
    integration, providing comprehensive resilience patterns and fallback
    mechanism coordination for enterprise-grade service reliability.
    
    Features:
    - Circuit breaker state management and reporting
    - External service health monitoring integration
    - Fallback mechanism coordination and activation
    - Service degradation pattern implementation
    - Recovery detection and circuit closing logic
    - Comprehensive service resilience monitoring
    
    Args:
        message: Detailed circuit breaker error description
        service_name: Name of the service with circuit breaker activation
        circuit_state: Current circuit breaker state (open/half-open/closed)
        failure_count: Number of consecutive failures
        threshold: Failure threshold for circuit activation
        timeout: Circuit breaker timeout before retry attempts
        
    Example:
        if circuit_breaker.is_open('auth0_service'):
            raise CircuitBreakerException(
                message="Auth0 service circuit breaker is open",
                error_code=SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN,
                service_name='auth0_service',
                circuit_state='open',
                failure_count=5,
                threshold=5
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode = SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN,
        service_name: Optional[str] = None,
        circuit_state: Optional[str] = None,
        failure_count: Optional[int] = None,
        threshold: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Service temporarily unavailable')
        kwargs.setdefault('http_status', 503)  # Service Unavailable
        super().__init__(message, error_code, **kwargs)
        
        # Add circuit breaker metadata
        self.metadata.update({
            'circuit_breaker_failure_category': 'service_resilience',
            'service_name': service_name,
            'circuit_state': circuit_state,
            'failure_count': failure_count,
            'threshold': threshold,
            'timeout_seconds': timeout
        })


class ValidationException(SecurityException):
    """
    Exception class for input validation and schema enforcement failures.
    
    This exception handles marshmallow and pydantic validation failures,
    providing comprehensive input validation error handling with security-focused
    sanitization and enterprise-grade data integrity enforcement.
    
    Features:
    - Marshmallow 3.20+ schema validation error handling
    - Pydantic 2.3+ model validation integration
    - Input sanitization failure reporting
    - XSS and injection attempt detection
    - Data format and structure validation
    - Security-focused validation error messaging
    
    Args:
        message: Detailed validation error description
        validation_errors: List of specific validation failures
        schema_name: Name of the validation schema that failed
        field_errors: Field-specific validation error details
        sanitization_failed: Whether input sanitization failed
        
    Example:
        try:
            validated_data = schema.load(request_data)
        except marshmallow.ValidationError as e:
            raise ValidationException(
                message=f"Input validation failed: {str(e)}",
                error_code=SecurityErrorCode.VAL_SCHEMA_VIOLATION,
                validation_errors=e.messages,
                schema_name='UserRegistrationSchema'
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: SecurityErrorCode,
        validation_errors: Optional[List[str]] = None,
        schema_name: Optional[str] = None,
        field_errors: Optional[Dict[str, List[str]]] = None,
        sanitization_failed: bool = False,
        **kwargs
    ) -> None:
        kwargs.setdefault('user_message', 'Invalid input data provided')
        kwargs.setdefault('http_status', 400)  # Bad Request
        super().__init__(message, error_code, **kwargs)
        
        # Add validation-specific metadata
        self.metadata.update({
            'validation_failure_category': 'input_validation',
            'schema_name': schema_name,
            'validation_error_count': len(validation_errors) if validation_errors else 0,
            'field_error_count': len(field_errors) if field_errors else 0,
            'sanitization_failed': sanitization_failed
        })
        
        # Sanitize error messages to prevent information disclosure
        if validation_errors:
            # Limit error message details and remove sensitive information
            safe_errors = [
                error[:100] for error in validation_errors[:5]  # Limit count and length
                if not any(sensitive in error.lower() 
                          for sensitive in ['password', 'secret', 'key', 'token'])
            ]
            self.metadata['validation_errors_sample'] = safe_errors


# Exception mapping for Flask error handler integration
EXCEPTION_HTTP_STATUS_MAP = {
    AuthenticationException: 401,
    JWTException: 401,
    AuthorizationException: 403,
    PermissionException: 403,
    Auth0Exception: 503,
    SessionException: 401,
    RateLimitException: 429,
    CircuitBreakerException: 503,
    ValidationException: 400,
    SecurityException: 403
}

# Security error codes for quick lookup and categorization
AUTHENTICATION_ERROR_CODES = {
    SecurityErrorCode.AUTH_TOKEN_MISSING,
    SecurityErrorCode.AUTH_TOKEN_INVALID,
    SecurityErrorCode.AUTH_TOKEN_EXPIRED,
    SecurityErrorCode.AUTH_TOKEN_MALFORMED,
    SecurityErrorCode.AUTH_CREDENTIALS_INVALID,
    SecurityErrorCode.AUTH_USER_NOT_FOUND,
    SecurityErrorCode.AUTH_ACCOUNT_LOCKED,
    SecurityErrorCode.AUTH_MFA_REQUIRED,
    SecurityErrorCode.AUTH_MFA_INVALID,
    SecurityErrorCode.AUTH_SESSION_EXPIRED,
    SecurityErrorCode.AUTH_SESSION_INVALID
}

AUTHORIZATION_ERROR_CODES = {
    SecurityErrorCode.AUTHZ_PERMISSION_DENIED,
    SecurityErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS,
    SecurityErrorCode.AUTHZ_RESOURCE_ACCESS_DENIED,
    SecurityErrorCode.AUTHZ_ROLE_INSUFFICIENT,
    SecurityErrorCode.AUTHZ_SCOPE_INVALID,
    SecurityErrorCode.AUTHZ_POLICY_VIOLATION,
    SecurityErrorCode.AUTHZ_RESOURCE_NOT_FOUND,
    SecurityErrorCode.AUTHZ_OWNERSHIP_REQUIRED
}

EXTERNAL_SERVICE_ERROR_CODES = {
    SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
    SecurityErrorCode.EXT_AUTH0_TIMEOUT,
    SecurityErrorCode.EXT_AUTH0_API_ERROR,
    SecurityErrorCode.EXT_AUTH0_RATE_LIMITED,
    SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN,
    SecurityErrorCode.EXT_SERVICE_DEGRADED,
    SecurityErrorCode.EXT_AWS_KMS_ERROR,
    SecurityErrorCode.EXT_REDIS_UNAVAILABLE
}

SECURITY_VIOLATION_ERROR_CODES = {
    SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED,
    SecurityErrorCode.SEC_BRUTE_FORCE_DETECTED,
    SecurityErrorCode.SEC_SUSPICIOUS_ACTIVITY,
    SecurityErrorCode.SEC_IP_BLOCKED,
    SecurityErrorCode.SEC_SECURITY_HEADERS_VIOLATION,
    SecurityErrorCode.SEC_CSRF_TOKEN_INVALID,
    SecurityErrorCode.SEC_XSS_ATTEMPT_DETECTED,
    SecurityErrorCode.SEC_SQL_INJECTION_ATTEMPT
}


def get_error_category(error_code: SecurityErrorCode) -> str:
    """
    Get the category for a security error code.
    
    This function provides error categorization for monitoring, alerting,
    and security analysis purposes. It supports SIEM integration and
    comprehensive security event classification.
    
    Args:
        error_code: Security error code to categorize
        
    Returns:
        String category name for the error code
        
    Example:
        category = get_error_category(SecurityErrorCode.AUTH_TOKEN_EXPIRED)
        # Returns: "authentication"
    """
    if error_code in AUTHENTICATION_ERROR_CODES:
        return "authentication"
    elif error_code in AUTHORIZATION_ERROR_CODES:
        return "authorization"
    elif error_code in EXTERNAL_SERVICE_ERROR_CODES:
        return "external_service"
    elif error_code in SECURITY_VIOLATION_ERROR_CODES:
        return "security_violation"
    elif error_code.value.startswith("VAL_"):
        return "validation"
    else:
        return "unknown"


def is_critical_security_error(error_code: SecurityErrorCode) -> bool:
    """
    Determine if an error code represents a critical security failure.
    
    This function identifies high-priority security failures that require
    immediate attention, escalation, or automated response actions. It supports
    incident response automation and security alerting systems.
    
    Args:
        error_code: Security error code to evaluate
        
    Returns:
        Boolean indicating if the error is critical
        
    Example:
        if is_critical_security_error(error_code):
            trigger_security_alert(error_code, metadata)
            escalate_to_security_team(incident_details)
    """
    critical_codes = {
        SecurityErrorCode.SEC_BRUTE_FORCE_DETECTED,
        SecurityErrorCode.SEC_SUSPICIOUS_ACTIVITY,
        SecurityErrorCode.SEC_XSS_ATTEMPT_DETECTED,
        SecurityErrorCode.SEC_SQL_INJECTION_ATTEMPT,
        SecurityErrorCode.AUTHZ_POLICY_VIOLATION,
        SecurityErrorCode.AUTH_ACCOUNT_LOCKED
    }
    return error_code in critical_codes


def create_safe_error_response(exception: SecurityException) -> Dict[str, Any]:
    """
    Create a safe error response for client consumption.
    
    This function generates security-focused error responses that prevent
    information disclosure while providing sufficient detail for legitimate
    client applications. It implements enterprise security standards for
    error response formatting.
    
    Args:
        exception: Security exception to convert to response
        
    Returns:
        Dictionary containing safe error response data
        
    Example:
        try:
            authenticate_user(credentials)
        except SecurityException as e:
            response_data = create_safe_error_response(e)
            return jsonify(response_data), e.http_status
    """
    return {
        'error': True,
        'error_code': exception.error_code.value,
        'message': exception.user_message,
        'error_id': exception.error_id,
        'timestamp': exception.timestamp.isoformat(),
        'category': get_error_category(exception.error_code)
    }