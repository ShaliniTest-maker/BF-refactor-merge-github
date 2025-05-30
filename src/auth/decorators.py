"""
Authentication and Authorization Decorators

This module provides comprehensive route-level security decorators for Flask endpoints,
implementing enterprise-grade authentication and authorization patterns with extensive
type hints, security event logging, and integration with Flask-Login, Flask-Limiter,
and circuit breaker patterns.

The decorators implement the following security controls:
- JWT token validation with Auth0 integration
- Role-based access control (RBAC) with permission validation
- Resource-specific authorization with owner validation
- Rate limiting integration for high-security endpoints
- Circuit breaker protection for Auth0 API calls
- Comprehensive security event logging with structured formatting
- Integration with Flask-Login for authentication state management

All decorators maintain complete API compatibility while providing enhanced security
features equivalent to Node.js middleware patterns adapted for Python/Flask.
"""

import asyncio
import functools
import inspect
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Union, TypeVar, cast

from flask import current_app, g, jsonify, request, Response
from flask_login import current_user, login_required
from flask_limiter import Limiter
from werkzeug.exceptions import Forbidden, Unauthorized

# Type variable for decorated functions
F = TypeVar('F', bound=Callable[..., Any])

# Import authentication and authorization components
from .authentication import (
    validate_jwt_token,
    extract_user_claims,
    get_current_user_id,
    is_user_authenticated
)
from .authorization import (
    validate_user_permissions,
    check_resource_ownership,
    get_user_permissions,
    evaluate_permission_hierarchy,
    PermissionContext
)
from .audit import SecurityAuditLogger
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    PermissionDeniedError,
    CircuitBreakerError,
    RateLimitExceededError,
    ResourceAccessDeniedError
)


class AuthenticationDecorators:
    """
    Comprehensive authentication and authorization decorators with enterprise-grade
    security controls, type hints, and integration with Flask security ecosystem.
    
    This class provides decorators for:
    - Route-level authentication validation
    - Permission-based authorization
    - Rate limiting with authorization integration
    - Resource-specific access control
    - Security event logging and monitoring
    """
    
    def __init__(self, limiter: Optional[Limiter] = None):
        """
        Initialize authentication decorators with optional rate limiter integration.
        
        Args:
            limiter: Flask-Limiter instance for rate limiting integration
        """
        self.limiter = limiter
        self.audit_logger = SecurityAuditLogger()
    
    def require_authentication(
        self,
        allow_refresh: bool = True,
        cache_validation: bool = True
    ) -> Callable[[F], F]:
        """
        Decorator requiring valid JWT authentication for route access.
        
        This decorator validates JWT tokens with Auth0, implements token caching
        for performance optimization, and provides comprehensive error handling
        with security event logging.
        
        Args:
            allow_refresh: Whether to allow automatic token refresh
            cache_validation: Whether to use Redis cache for token validation
            
        Returns:
            Decorated function with authentication enforcement
            
        Raises:
            AuthenticationError: When authentication fails
            CircuitBreakerError: When Auth0 service is unavailable
            
        Example:
            @app.route('/api/protected')
            @require_authentication()
            def protected_endpoint():
                return jsonify({'message': 'Access granted'})
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    # Check if user is already authenticated via Flask-Login
                    if not current_user.is_authenticated:
                        # Extract JWT token from request headers
                        auth_header = request.headers.get('Authorization', '')
                        if not auth_header.startswith('Bearer '):
                            self.audit_logger.log_authentication_event(
                                event_type='authentication_failed',
                                reason='missing_token',
                                endpoint=request.endpoint,
                                ip_address=request.remote_addr
                            )
                            raise AuthenticationError('Missing or invalid authorization header')
                        
                        token = auth_header.split(' ', 1)[1]
                        
                        # Validate JWT token with caching support
                        validation_result = validate_jwt_token(
                            token=token,
                            use_cache=cache_validation,
                            allow_refresh=allow_refresh
                        )
                        
                        if not validation_result.get('valid', False):
                            self.audit_logger.log_authentication_event(
                                event_type='authentication_failed',
                                reason='invalid_token',
                                endpoint=request.endpoint,
                                ip_address=request.remote_addr,
                                token_hash=validation_result.get('token_hash')
                            )
                            raise AuthenticationError('Invalid or expired token')
                        
                        # Store user context for request processing
                        g.current_user_id = validation_result['user_id']
                        g.user_claims = validation_result['claims']
                        g.auth_method = 'jwt'
                    else:
                        # User authenticated via Flask-Login session
                        g.current_user_id = current_user.id
                        g.user_claims = getattr(current_user, 'auth0_profile', {})
                        g.auth_method = 'session'
                    
                    # Log successful authentication
                    self.audit_logger.log_authentication_event(
                        event_type='authentication_success',
                        user_id=g.current_user_id,
                        auth_method=g.auth_method,
                        endpoint=request.endpoint,
                        ip_address=request.remote_addr
                    )
                    
                    return func(*args, **kwargs)
                    
                except CircuitBreakerError:
                    # Auth0 service unavailable, implement fallback
                    self.audit_logger.log_circuit_breaker_event(
                        service='auth0',
                        event='circuit_open',
                        endpoint=request.endpoint
                    )
                    return jsonify({
                        'error': 'Authentication service temporarily unavailable',
                        'retry_after': 60
                    }), 503
                    
                except AuthenticationError as e:
                    return jsonify({'error': str(e)}), 401
                    
                except Exception as e:
                    current_app.logger.error(f'Authentication error: {str(e)}')
                    return jsonify({'error': 'Authentication failed'}), 401
            
            return cast(F, wrapper)
        return decorator
    
    def require_permissions(
        self,
        permissions: Union[str, List[str]],
        resource_id_param: Optional[str] = None,
        allow_owner: bool = True,
        require_all: bool = True
    ) -> Callable[[F], F]:
        """
        Decorator for enforcing route-level authorization with comprehensive permission checking.
        
        This decorator validates user permissions against required permissions for the decorated
        route, supports resource-specific authorization, and implements owner-based access control
        with complete audit logging and circuit breaker protection for Auth0 API calls.
        
        Args:
            permissions: Single permission string or list of required permissions
            resource_id_param: URL parameter name containing resource ID for ownership checks
            allow_owner: Whether to allow resource owners regardless of explicit permissions
            require_all: Whether all permissions are required (AND) or any permission (OR)
            
        Returns:
            Decorated function with authorization enforcement
            
        Raises:
            PermissionDeniedError: When user lacks required permissions
            AuthenticationError: When user is not properly authenticated
            CircuitBreakerError: When Auth0 service is unavailable
            
        Example:
            @app.route('/api/documents/<document_id>')
            @require_authentication()
            @require_permissions(['document.read', 'document.write'], resource_id_param='document_id')
            def get_document(document_id: str) -> Response:
                return jsonify({"document": load_document(document_id)})
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            @self.require_authentication()
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    user_id = g.current_user_id
                    user_claims = g.user_claims
                    
                    # Normalize permissions to list
                    perm_list = [permissions] if isinstance(permissions, str) else permissions
                    
                    # Extract resource ID if specified
                    resource_id = None
                    if resource_id_param and resource_id_param in kwargs:
                        resource_id = kwargs[resource_id_param]
                    
                    # Create permission context for evaluation
                    permission_context = PermissionContext(
                        user_id=user_id,
                        user_claims=user_claims,
                        required_permissions=perm_list,
                        resource_id=resource_id,
                        resource_type=self._extract_resource_type(request.endpoint),
                        request_context={
                            'endpoint': request.endpoint,
                            'method': request.method,
                            'ip_address': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent')
                        }
                    )
                    
                    # Check resource ownership if enabled and resource ID is present
                    is_owner = False
                    if allow_owner and resource_id:
                        is_owner = check_resource_ownership(
                            user_id=user_id,
                            resource_id=resource_id,
                            resource_type=permission_context.resource_type
                        )
                    
                    # Validate user permissions with circuit breaker protection
                    has_permissions = validate_user_permissions(
                        context=permission_context,
                        require_all=require_all
                    )
                    
                    # Grant access if user has permissions or is owner
                    if has_permissions or is_owner:
                        # Log successful authorization
                        self.audit_logger.log_authorization_event(
                            event_type='authorization_granted',
                            user_id=user_id,
                            permissions=perm_list,
                            resource_id=resource_id,
                            is_owner=is_owner,
                            endpoint=request.endpoint,
                            method=request.method
                        )
                        
                        # Store authorization context for downstream processing
                        g.authorization_context = permission_context
                        g.is_resource_owner = is_owner
                        
                        return func(*args, **kwargs)
                    else:
                        # Access denied - log security event
                        self.audit_logger.log_authorization_event(
                            event_type='authorization_denied',
                            user_id=user_id,
                            permissions=perm_list,
                            resource_id=resource_id,
                            reason='insufficient_permissions',
                            endpoint=request.endpoint,
                            method=request.method
                        )
                        
                        raise PermissionDeniedError(
                            f'Insufficient permissions. Required: {", ".join(perm_list)}'
                        )
                        
                except CircuitBreakerError:
                    # Auth0 service unavailable during permission check
                    self.audit_logger.log_circuit_breaker_event(
                        service='auth0_permissions',
                        event='circuit_open',
                        user_id=user_id,
                        endpoint=request.endpoint
                    )
                    return jsonify({
                        'error': 'Permission validation service temporarily unavailable',
                        'retry_after': 60
                    }), 503
                    
                except PermissionDeniedError as e:
                    return jsonify({'error': str(e)}), 403
                    
                except ResourceAccessDeniedError as e:
                    return jsonify({'error': str(e)}), 403
                    
                except Exception as e:
                    current_app.logger.error(f'Authorization error: {str(e)}')
                    self.audit_logger.log_authorization_event(
                        event_type='authorization_error',
                        user_id=getattr(g, 'current_user_id', 'unknown'),
                        permissions=perm_list,
                        error=str(e),
                        endpoint=request.endpoint
                    )
                    return jsonify({'error': 'Authorization check failed'}), 500
            
            return cast(F, wrapper)
        return decorator
    
    def rate_limited_authorization(
        self,
        permissions: Union[str, List[str]],
        rate_limit: str = "100 per minute",
        key_func: Optional[Callable[[], str]] = None,
        error_message: Optional[str] = None
    ) -> Callable[[F], F]:
        """
        Combined authorization and rate limiting decorator for high-security endpoints.
        
        This decorator combines permission validation with rate limiting specifically
        designed for authorization-sensitive endpoints, preventing both unauthorized
        access and authorization system abuse through intelligent rate limiting.
        
        Args:
            permissions: Required permissions for endpoint access
            rate_limit: Rate limit specification in Flask-Limiter format
            key_func: Custom function to generate rate limiting key
            error_message: Custom error message for rate limit violations
            
        Returns:
            Decorated function with authorization and rate limiting
            
        Example:
            @app.route('/api/admin/users')
            @rate_limited_authorization(['admin.users.read'], "10 per minute")
            def list_users() -> Response:
                return jsonify({"users": get_all_users()})
        """
        def decorator(func: F) -> F:
            # Default rate limiting key function
            def default_key_func() -> str:
                user_id = getattr(g, 'current_user_id', 'anonymous')
                endpoint = request.endpoint or 'unknown'
                return f"auth_rate_limit:{user_id}:{endpoint}"
            
            # Apply rate limiting first if limiter is available
            if self.limiter:
                rate_limited_func = self.limiter.limit(
                    rate_limit,
                    key_func=key_func or default_key_func,
                    error_message=error_message or 'Rate limit exceeded for this authorization endpoint'
                )(func)
            else:
                rate_limited_func = func
            
            # Apply authorization on top of rate limiting
            @functools.wraps(rate_limited_func)
            @self.require_permissions(permissions)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return rate_limited_func(*args, **kwargs)
                except Exception as e:
                    # Check if this is a rate limiting error
                    if 'rate limit' in str(e).lower():
                        user_id = getattr(g, 'current_user_id', 'unknown')
                        self.audit_logger.log_rate_limit_violation(
                            user_id=user_id,
                            endpoint=request.endpoint or 'unknown',
                            limit_exceeded=rate_limit,
                            permissions=permissions if isinstance(permissions, list) else [permissions]
                        )
                        return jsonify({
                            'error': 'Rate limit exceeded',
                            'retry_after': self._calculate_retry_after(rate_limit)
                        }), 429
                    raise
            
            return cast(F, wrapper)
        return decorator
    
    def require_admin(
        self,
        admin_permissions: Optional[List[str]] = None,
        rate_limit: str = "20 per minute"
    ) -> Callable[[F], F]:
        """
        Decorator for admin-only endpoints with enhanced security controls.
        
        This decorator provides additional security for administrative endpoints
        including stricter rate limiting, enhanced logging, and admin-specific
        permission validation.
        
        Args:
            admin_permissions: Specific admin permissions required
            rate_limit: Rate limit for admin endpoints
            
        Returns:
            Decorated function with admin authorization
        """
        default_admin_perms = admin_permissions or ['admin.access', 'admin.manage']
        
        def decorator(func: F) -> F:
            @functools.wraps(func)
            @self.rate_limited_authorization(
                permissions=default_admin_perms,
                rate_limit=rate_limit
            )
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Additional admin-specific logging
                self.audit_logger.log_admin_access(
                    user_id=g.current_user_id,
                    endpoint=request.endpoint,
                    permissions=default_admin_perms,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                
                return func(*args, **kwargs)
            
            return cast(F, wrapper)
        return decorator
    
    def require_api_key(
        self,
        api_key_header: str = 'X-API-Key',
        required_scopes: Optional[List[str]] = None
    ) -> Callable[[F], F]:
        """
        Decorator for API key-based authentication with scope validation.
        
        This decorator validates API keys for service-to-service communication
        and external integrations, providing an alternative to JWT authentication
        for specific use cases.
        
        Args:
            api_key_header: Header name containing the API key
            required_scopes: Required API key scopes for access
            
        Returns:
            Decorated function with API key authentication
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                api_key = request.headers.get(api_key_header)
                if not api_key:
                    self.audit_logger.log_authentication_event(
                        event_type='api_key_missing',
                        endpoint=request.endpoint,
                        ip_address=request.remote_addr
                    )
                    return jsonify({'error': 'API key required'}), 401
                
                # Validate API key (implement validation logic based on your needs)
                # This would typically involve checking against a database or cache
                key_validation = self._validate_api_key(api_key, required_scopes)
                
                if not key_validation.get('valid', False):
                    self.audit_logger.log_authentication_event(
                        event_type='api_key_invalid',
                        api_key_hash=self._hash_api_key(api_key),
                        endpoint=request.endpoint,
                        ip_address=request.remote_addr
                    )
                    return jsonify({'error': 'Invalid API key'}), 401
                
                # Store API key context
                g.api_key_id = key_validation['key_id']
                g.api_key_scopes = key_validation.get('scopes', [])
                g.auth_method = 'api_key'
                
                self.audit_logger.log_authentication_event(
                    event_type='api_key_success',
                    api_key_id=g.api_key_id,
                    scopes=g.api_key_scopes,
                    endpoint=request.endpoint,
                    ip_address=request.remote_addr
                )
                
                return func(*args, **kwargs)
            
            return cast(F, wrapper)
        return decorator
    
    def conditional_auth(
        self,
        condition_func: Callable[[], bool],
        fallback_permissions: Optional[List[str]] = None
    ) -> Callable[[F], F]:
        """
        Decorator for conditional authentication based on custom logic.
        
        This decorator allows for flexible authentication requirements based
        on runtime conditions, useful for endpoints that may be public under
        certain circumstances or require different authentication levels.
        
        Args:
            condition_func: Function that returns True if auth is required
            fallback_permissions: Permissions required when auth is needed
            
        Returns:
            Decorated function with conditional authentication
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                requires_auth = condition_func()
                
                if requires_auth:
                    # Apply authentication and authorization
                    if fallback_permissions:
                        return self.require_permissions(fallback_permissions)(func)(*args, **kwargs)
                    else:
                        return self.require_authentication()(func)(*args, **kwargs)
                else:
                    # No authentication required
                    g.current_user_id = 'anonymous'
                    g.auth_method = 'none'
                    return func(*args, **kwargs)
            
            return cast(F, wrapper)
        return decorator
    
    def _extract_resource_type(self, endpoint: Optional[str]) -> str:
        """
        Extract resource type from Flask endpoint for authorization context.
        
        Args:
            endpoint: Flask endpoint name
            
        Returns:
            Resource type string for authorization
        """
        if not endpoint:
            return 'unknown'
        
        # Extract resource type from endpoint patterns
        # Example: 'api.documents.get_document' -> 'documents'
        parts = endpoint.split('.')
        if len(parts) >= 2:
            return parts[-2]  # Second to last part typically contains resource type
        
        return parts[0] if parts else 'unknown'
    
    def _calculate_retry_after(self, rate_limit: str) -> int:
        """
        Calculate retry-after header value based on rate limit specification.
        
        Args:
            rate_limit: Rate limit specification string
            
        Returns:
            Retry-after time in seconds
        """
        # Parse rate limit string and calculate retry time
        # This is a simplified implementation
        if 'minute' in rate_limit:
            return 60
        elif 'hour' in rate_limit:
            return 3600
        elif 'second' in rate_limit:
            return 1
        else:
            return 60  # Default fallback
    
    def _validate_api_key(self, api_key: str, required_scopes: Optional[List[str]]) -> Dict[str, Any]:
        """
        Validate API key and check required scopes.
        
        Args:
            api_key: API key to validate
            required_scopes: Required scopes for access
            
        Returns:
            Validation result dictionary
        """
        # This is a placeholder implementation
        # In a real implementation, you would check against your API key storage
        return {
            'valid': True,
            'key_id': 'example_key_id',
            'scopes': required_scopes or []
        }
    
    def _hash_api_key(self, api_key: str) -> str:
        """
        Create a secure hash of API key for logging purposes.
        
        Args:
            api_key: API key to hash
            
        Returns:
            Secure hash of the API key
        """
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]


# Create global instance for decorator usage
auth_decorators = AuthenticationDecorators()

# Export commonly used decorators for convenient imports
require_authentication = auth_decorators.require_authentication
require_permissions = auth_decorators.require_permissions
rate_limited_authorization = auth_decorators.rate_limited_authorization
require_admin = auth_decorators.require_admin
require_api_key = auth_decorators.require_api_key
conditional_auth = auth_decorators.conditional_auth


def init_decorators(app, limiter: Optional[Limiter] = None) -> AuthenticationDecorators:
    """
    Initialize authentication decorators with Flask application and rate limiter.
    
    This function should be called during Flask application factory setup
    to properly configure the decorators with the application context and
    rate limiting capabilities.
    
    Args:
        app: Flask application instance
        limiter: Flask-Limiter instance for rate limiting integration
        
    Returns:
        Configured AuthenticationDecorators instance
    
    Example:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["1000 per hour"]
        )
        
        decorators = init_decorators(app, limiter)
    """
    global auth_decorators
    auth_decorators = AuthenticationDecorators(limiter=limiter)
    
    # Store in app context for access throughout the application
    app.extensions = getattr(app, 'extensions', {})
    app.extensions['auth_decorators'] = auth_decorators
    
    return auth_decorators


def get_decorators() -> AuthenticationDecorators:
    """
    Get the current authentication decorators instance.
    
    Returns:
        Current AuthenticationDecorators instance
    """
    return auth_decorators


__all__ = [
    'AuthenticationDecorators',
    'require_authentication',
    'require_permissions', 
    'rate_limited_authorization',
    'require_admin',
    'require_api_key',
    'conditional_auth',
    'init_decorators',
    'get_decorators'
]