"""
Authentication Module Initialization

This module provides comprehensive Flask Blueprint registration, centralized imports for 
authentication components, and integration with Flask application factory per Section 6.4.1.
Establishes the auth package as the primary authentication provider for the Flask application
with proper namespace organization and enterprise-grade security features.

The authentication module serves as the central authentication provider implementing:
- Flask Blueprint for authentication routes per Section 6.4.1 authentication framework
- Package-level imports for authentication components per Section 5.2.3
- Blueprint registration pattern for Flask application factory integration per Section 4.2.1
- Authentication module namespace organization per Section 6.1.1 Flask Blueprint architecture
- Flask-Login integration for session management per Section 6.4.1
- Flask-Talisman security headers enforcement per Section 6.4.3
- Comprehensive security monitoring and metrics collection

Key Components:
- CoreJWTAuthenticator: Enterprise JWT authentication with Auth0 integration
- Authorization system: Role-based access control with Redis caching
- Decorators: Route protection and permission validation
- Session management: Flask-Login with Redis distributed storage
- Security headers: Flask-Talisman HTTP security enforcement
- Monitoring: Prometheus metrics and structured logging

Integration Points:
- Flask application factory pattern for modular configuration
- Blueprint registration for clean route organization
- Centralized authentication state management
- Enterprise security policy enforcement
- Comprehensive audit logging and monitoring

Dependencies:
- Flask 2.3+: Web framework and Blueprint support
- Flask-Login 0.7.0+: Session management and user context
- Flask-Talisman 1.1.0+: HTTP security header enforcement
- PyJWT 2.8+: JWT token processing and validation
- Auth0 Python SDK 4.7+: Enterprise authentication integration
- redis-py 5.0+: Distributed caching and session storage
- structlog 23.1+: Comprehensive security audit logging
- prometheus-client 0.17+: Security metrics and monitoring

Architecture:
This module implements Flask Blueprint architecture for authentication routes with
comprehensive integration to Flask application factory pattern, enabling modular
deployment and enterprise-grade security policy enforcement.

Author: Flask Migration Team
Version: 1.0.0
License: Enterprise
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import logging
import os
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timezone

# Flask core dependencies
from flask import Flask, Blueprint, g, request, current_app, jsonify
from flask_login import LoginManager, current_user
from werkzeug.exceptions import HTTPException

# Import authentication components
from .authentication import (
    CoreJWTAuthenticator,
    AuthenticatedUser,
    get_core_authenticator,
    require_authentication,
    get_authenticated_user,
    authenticate_token,
    create_auth_health_check,
    auth_operation_metrics
)

from .authorization import (
    AuthorizationManager,
    require_permissions,
    verify_resource_access,
    check_user_permissions,
    get_authorization_manager,
    create_permission_cache_metrics
)

from .decorators import (
    login_required_with_permissions,
    rate_limited_authorization,
    resource_owner_required,
    admin_required,
    api_key_required,
    csrf_protect,
    audit_security_event
)

from .session import (
    FlaskLoginSessionManager,
    initialize_session_management,
    create_user_loader,
    configure_session_callbacks,
    get_session_manager,
    cleanup_expired_sessions
)

from .security import (
    configure_security_headers,
    initialize_flask_talisman,
    get_security_configuration,
    create_csp_nonce,
    validate_security_context
)

# Monitoring and logging
import structlog
from prometheus_client import Counter, Histogram, Gauge, Info

# Configure structured logging for authentication module
logger = structlog.get_logger(__name__)

# Authentication module metrics
auth_module_metrics = {
    'blueprint_registrations': Counter(
        'auth_blueprint_registrations_total',
        'Total authentication blueprint registrations',
        ['app_name', 'blueprint_name']
    ),
    'initialization_duration': Histogram(
        'auth_module_initialization_duration_seconds',
        'Time spent initializing authentication module',
        ['component', 'initialization_phase']
    ),
    'active_components': Gauge(
        'auth_active_components',
        'Number of active authentication components',
        ['component_type']
    ),
    'module_info': Info(
        'auth_module_info',
        'Authentication module version and configuration information'
    )
}

# Authentication Blueprint
auth_blueprint = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    template_folder='templates',
    static_folder='static'
)

# Module-level configuration
_auth_config: Optional[Dict[str, Any]] = None
_login_manager: Optional[LoginManager] = None
_session_manager: Optional['FlaskLoginSessionManager'] = None
_authorization_manager: Optional['AuthorizationManager'] = None
_core_authenticator: Optional[CoreJWTAuthenticator] = None


def create_auth_blueprint() -> Blueprint:
    """
    Create and configure the authentication Flask Blueprint with comprehensive 
    route organization and security integration.
    
    This function creates the main authentication blueprint containing all
    authentication-related routes including login, logout, token refresh,
    user profile management, and health checks per Section 6.4.1.
    
    Returns:
        Blueprint: Configured authentication blueprint for registration
        
    Example:
        auth_bp = create_auth_blueprint()
        app.register_blueprint(auth_bp)
    """
    logger.info("Creating authentication blueprint")
    
    @auth_blueprint.route('/health', methods=['GET'])
    def health_check():
        """
        Authentication system health check endpoint.
        
        Returns comprehensive health status of all authentication components
        including JWT authentication, Auth0 connectivity, Redis caching,
        and session management systems.
        """
        try:
            health_status = create_auth_health_check()
            
            # Add module-specific health information
            health_status['module'] = {
                'name': 'authentication',
                'version': '1.0.0',
                'blueprint_registered': True,
                'components_active': len([
                    c for c in [_core_authenticator, _session_manager, _authorization_manager]
                    if c is not None
                ])
            }
            
            status_code = 200 if health_status['status'] == 'healthy' else 503
            return jsonify(health_status), status_code
            
        except Exception as e:
            logger.error(
                "Authentication health check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return jsonify({
                'status': 'unhealthy',
                'error': 'Health check system error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 503
    
    @auth_blueprint.route('/login', methods=['POST'])
    @audit_security_event('authentication_attempt')
    async def login():
        """
        JWT authentication endpoint with Auth0 integration.
        
        Accepts JWT tokens from Auth0 and creates authenticated user sessions
        with comprehensive security validation and audit logging.
        """
        try:
            # Extract token from request
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Missing or invalid authorization header',
                    'error_code': 'AUTH_TOKEN_MISSING'
                }), 401
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Authenticate with core authenticator
            authenticator = get_core_authenticator()
            authenticated_user = await authenticator.authenticate_request(token=token)
            
            if not authenticated_user:
                return jsonify({
                    'error': 'Authentication failed',
                    'error_code': 'AUTH_TOKEN_INVALID'
                }), 401
            
            # Create Flask-Login session
            session_manager = get_session_manager()
            session_data = await session_manager.create_user_session(authenticated_user)
            
            logger.info(
                "User authentication successful",
                user_id=authenticated_user.user_id,
                session_id=session_data.get('session_id'),
                login_method='jwt_auth0'
            )
            
            return jsonify({
                'status': 'authenticated',
                'user': {
                    'user_id': authenticated_user.user_id,
                    'email': authenticated_user.profile.get('email'),
                    'name': authenticated_user.profile.get('name'),
                    'permissions': authenticated_user.permissions[:50]  # Limit for response size
                },
                'session': {
                    'session_id': session_data.get('session_id'),
                    'expires_at': session_data.get('expires_at')
                }
            }), 200
            
        except Exception as e:
            logger.error(
                "Login endpoint error",
                error=str(e),
                error_type=type(e).__name__,
                endpoint='auth.login'
            )
            
            return jsonify({
                'error': 'Authentication system error',
                'error_code': 'AUTH_SYSTEM_ERROR'
            }), 500
    
    @auth_blueprint.route('/logout', methods=['POST'])
    @require_authentication()
    @audit_security_event('logout_attempt')
    async def logout():
        """
        Secure logout endpoint with comprehensive session cleanup.
        
        Revokes JWT tokens, clears Flask-Login sessions, and invalidates
        all cached authentication data for the current user.
        """
        try:
            current_user = get_authenticated_user()
            if not current_user:
                return jsonify({
                    'error': 'No active session to logout',
                    'error_code': 'NO_ACTIVE_SESSION'
                }), 400
            
            user_id = current_user.user_id
            
            # Revoke JWT token
            authenticator = get_core_authenticator()
            if current_user.token:
                await authenticator.revoke_token(current_user.token, reason='user_logout')
            
            # Clear Flask-Login session
            session_manager = get_session_manager()
            await session_manager.clear_user_session(user_id)
            
            logger.info(
                "User logout successful",
                user_id=user_id,
                logout_method='explicit_logout'
            )
            
            return jsonify({
                'status': 'logged_out',
                'message': 'Session terminated successfully'
            }), 200
            
        except Exception as e:
            logger.error(
                "Logout endpoint error",
                error=str(e),
                error_type=type(e).__name__,
                endpoint='auth.logout'
            )
            
            return jsonify({
                'error': 'Logout system error',
                'error_code': 'LOGOUT_SYSTEM_ERROR'
            }), 500
    
    @auth_blueprint.route('/profile', methods=['GET'])
    @require_authentication()
    def get_user_profile():
        """
        User profile endpoint with authenticated user context.
        
        Returns comprehensive user profile information including permissions,
        authentication metadata, and session details.
        """
        try:
            current_user = get_authenticated_user()
            if not current_user:
                return jsonify({
                    'error': 'Authentication required',
                    'error_code': 'AUTH_REQUIRED'
                }), 401
            
            profile_data = {
                'user_id': current_user.user_id,
                'profile': current_user.profile,
                'permissions': current_user.permissions,
                'authenticated_at': current_user.authenticated_at.isoformat(),
                'session_info': {
                    'active': True,
                    'auth_method': 'jwt_auth0',
                    'permissions_count': len(current_user.permissions)
                }
            }
            
            return jsonify(profile_data), 200
            
        except Exception as e:
            logger.error(
                "Profile endpoint error",
                error=str(e),
                error_type=type(e).__name__,
                endpoint='auth.profile'
            )
            
            return jsonify({
                'error': 'Profile retrieval error',
                'error_code': 'PROFILE_ERROR'
            }), 500
    
    @auth_blueprint.route('/refresh', methods=['POST'])
    @audit_security_event('token_refresh_attempt')
    async def refresh_token():
        """
        JWT token refresh endpoint for session extension.
        
        Accepts refresh tokens and returns new access tokens while maintaining
        user session continuity and security validation.
        """
        try:
            data = request.get_json()
            if not data or 'refresh_token' not in data:
                return jsonify({
                    'error': 'Refresh token required',
                    'error_code': 'REFRESH_TOKEN_MISSING'
                }), 400
            
            refresh_token = data['refresh_token']
            current_access_token = data.get('access_token')
            
            # Refresh token using core authenticator
            authenticator = get_core_authenticator()
            new_access_token, new_refresh_token = await authenticator.refresh_token(
                refresh_token,
                current_access_token
            )
            
            logger.info(
                "Token refresh successful",
                operation='token_refresh',
                refresh_method='jwt_refresh'
            )
            
            return jsonify({
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'token_type': 'Bearer',
                'expires_in': 3600  # 1 hour
            }), 200
            
        except Exception as e:
            logger.error(
                "Token refresh error",
                error=str(e),
                error_type=type(e).__name__,
                endpoint='auth.refresh'
            )
            
            return jsonify({
                'error': 'Token refresh failed',
                'error_code': 'TOKEN_REFRESH_ERROR'
            }), 400
    
    @auth_blueprint.route('/permissions', methods=['GET'])
    @require_authentication()
    def get_user_permissions():
        """
        User permissions endpoint for authorization context.
        
        Returns detailed permission information for the authenticated user
        including role assignments and resource-specific permissions.
        """
        try:
            current_user = get_authenticated_user()
            if not current_user:
                return jsonify({
                    'error': 'Authentication required',
                    'error_code': 'AUTH_REQUIRED'
                }), 401
            
            # Get detailed permissions from authorization manager
            authz_manager = get_authorization_manager()
            detailed_permissions = authz_manager.get_user_permission_details(
                current_user.user_id
            )
            
            permissions_data = {
                'user_id': current_user.user_id,
                'permissions': current_user.permissions,
                'permissions_count': len(current_user.permissions),
                'detailed_permissions': detailed_permissions,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            return jsonify(permissions_data), 200
            
        except Exception as e:
            logger.error(
                "Permissions endpoint error",
                error=str(e),
                error_type=type(e).__name__,
                endpoint='auth.permissions'
            )
            
            return jsonify({
                'error': 'Permissions retrieval error',
                'error_code': 'PERMISSIONS_ERROR'
            }), 500
    
    logger.info("Authentication blueprint created successfully")
    return auth_blueprint


def initialize_authentication_module(
    app: Flask,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Initialize comprehensive authentication module with Flask application factory pattern.
    
    This function provides complete authentication system initialization including
    Flask-Login setup, security headers configuration, session management,
    and component registration per Section 6.1.1 Flask Blueprint architecture.
    
    Args:
        app: Flask application instance
        config: Optional authentication configuration override
        
    Returns:
        Dictionary containing initialization status and component references
        
    Example:
        auth_init = initialize_authentication_module(app, {
            'AUTH0_DOMAIN': 'company.auth0.com',
            'REDIS_URL': 'redis://localhost:6379/1'
        })
        if auth_init['status'] == 'success':
            print("Authentication module initialized successfully")
    """
    global _auth_config, _login_manager, _session_manager, _authorization_manager, _core_authenticator
    
    start_time = datetime.now(timezone.utc)
    initialization_results = {
        'status': 'initializing',
        'components': {},
        'errors': [],
        'started_at': start_time.isoformat()
    }
    
    try:
        logger.info(
            "Initializing authentication module",
            app_name=app.name,
            config_provided=config is not None
        )
        
        # Store configuration
        _auth_config = config or {}
        
        # Record blueprint registration
        auth_module_metrics['blueprint_registrations'].labels(
            app_name=app.name,
            blueprint_name='auth'
        ).inc()
        
        # Initialize Flask-Login
        logger.debug("Initializing Flask-Login session management")
        init_start = datetime.now(timezone.utc)
        
        _login_manager = LoginManager()
        _login_manager.init_app(app)
        _login_manager.login_view = 'auth.login'
        _login_manager.login_message = 'Please log in to access this page.'
        _login_manager.login_message_category = 'info'
        _login_manager.session_protection = 'strong'
        
        auth_module_metrics['initialization_duration'].labels(
            component='flask_login',
            initialization_phase='setup'
        ).observe((datetime.now(timezone.utc) - init_start).total_seconds())
        
        initialization_results['components']['flask_login'] = {
            'status': 'initialized',
            'login_view': _login_manager.login_view
        }
        
        # Initialize session management
        logger.debug("Initializing session management system")
        init_start = datetime.now(timezone.utc)
        
        _session_manager = initialize_session_management(app, _auth_config)
        
        # Configure user loader
        user_loader = create_user_loader(_session_manager)
        _login_manager.user_loader(user_loader)
        
        # Configure session callbacks
        configure_session_callbacks(app, _login_manager, _session_manager)
        
        auth_module_metrics['initialization_duration'].labels(
            component='session_manager',
            initialization_phase='setup'
        ).observe((datetime.now(timezone.utc) - init_start).total_seconds())
        
        initialization_results['components']['session_manager'] = {
            'status': 'initialized',
            'backend': 'redis',
            'encryption': 'aes_256_gcm'
        }
        
        # Initialize security headers
        logger.debug("Initializing Flask-Talisman security headers")
        init_start = datetime.now(timezone.utc)
        
        security_config = configure_security_headers(app, _auth_config)
        initialize_flask_talisman(app, security_config)
        
        auth_module_metrics['initialization_duration'].labels(
            component='security_headers',
            initialization_phase='setup'
        ).observe((datetime.now(timezone.utc) - init_start).total_seconds())
        
        initialization_results['components']['security_headers'] = {
            'status': 'initialized',
            'talisman_enabled': True,
            'csp_enabled': security_config.get('content_security_policy') is not None
        }
        
        # Initialize core authenticator
        logger.debug("Initializing core JWT authenticator")
        init_start = datetime.now(timezone.utc)
        
        _core_authenticator = get_core_authenticator()
        
        auth_module_metrics['initialization_duration'].labels(
            component='core_authenticator',
            initialization_phase='setup'
        ).observe((datetime.now(timezone.utc) - init_start).total_seconds())
        
        initialization_results['components']['core_authenticator'] = {
            'status': 'initialized',
            'auth0_domain': _core_authenticator.auth0_domain,
            'jwt_algorithm': _core_authenticator.jwt_algorithm
        }
        
        # Initialize authorization manager
        logger.debug("Initializing authorization management system")
        init_start = datetime.now(timezone.utc)
        
        _authorization_manager = get_authorization_manager()
        
        auth_module_metrics['initialization_duration'].labels(
            component='authorization_manager',
            initialization_phase='setup'
        ).observe((datetime.now(timezone.utc) - init_start).total_seconds())
        
        initialization_results['components']['authorization_manager'] = {
            'status': 'initialized',
            'cache_enabled': True,
            'permission_backend': 'auth0_jwt'
        }
        
        # Register error handlers
        logger.debug("Registering authentication error handlers")
        register_auth_error_handlers(app)
        
        # Update metrics
        auth_module_metrics['active_components'].labels(
            component_type='authentication'
        ).set(len([c for c in initialization_results['components'].values() 
                   if c['status'] == 'initialized']))
        
        # Set module information
        auth_module_metrics['module_info'].info({
            'version': '1.0.0',
            'flask_version': app.config.get('FLASK_VERSION', 'unknown'),
            'auth0_integration': 'enabled',
            'redis_backend': 'enabled',
            'security_headers': 'flask_talisman'
        })
        
        total_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        initialization_results.update({
            'status': 'success',
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'total_duration_seconds': total_duration,
            'components_initialized': len(initialization_results['components'])
        })
        
        logger.info(
            "Authentication module initialized successfully",
            app_name=app.name,
            components_count=len(initialization_results['components']),
            duration_seconds=total_duration
        )
        
        return initialization_results
        
    except Exception as e:
        error_msg = f"Authentication module initialization failed: {str(e)}"
        initialization_results['errors'].append({
            'error': error_msg,
            'error_type': type(e).__name__,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        initialization_results.update({
            'status': 'failed',
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'total_duration_seconds': (datetime.now(timezone.utc) - start_time).total_seconds()
        })
        
        logger.error(
            "Authentication module initialization failed",
            app_name=app.name,
            error=str(e),
            error_type=type(e).__name__
        )
        
        raise RuntimeError(error_msg) from e


def register_auth_blueprint(app: Flask) -> None:
    """
    Register authentication blueprint with Flask application.
    
    This function creates and registers the authentication blueprint with the
    Flask application, providing centralized authentication route organization
    per Section 5.2.2 API router component.
    
    Args:
        app: Flask application instance
        
    Example:
        register_auth_blueprint(app)
    """
    try:
        auth_bp = create_auth_blueprint()
        app.register_blueprint(auth_bp)
        
        logger.info(
            "Authentication blueprint registered successfully",
            app_name=app.name,
            blueprint_name='auth',
            url_prefix='/auth'
        )
        
    except Exception as e:
        logger.error(
            "Failed to register authentication blueprint",
            app_name=app.name,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


def register_auth_error_handlers(app: Flask) -> None:
    """
    Register comprehensive authentication error handlers for Flask application.
    
    Args:
        app: Flask application instance
    """
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors with structured response."""
        return jsonify({
            'error': 'Authentication required',
            'error_code': 'AUTH_REQUIRED',
            'message': 'Please provide valid authentication credentials',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 401
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors with structured response."""
        return jsonify({
            'error': 'Access denied',
            'error_code': 'ACCESS_DENIED',
            'message': 'Insufficient permissions for this operation',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 403
    
    @app.errorhandler(429)
    def handle_rate_limit(error):
        """Handle 429 Rate Limit errors with structured response."""
        return jsonify({
            'error': 'Rate limit exceeded',
            'error_code': 'RATE_LIMIT_EXCEEDED',
            'message': 'Too many requests, please try again later',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 429


def get_auth_module_status() -> Dict[str, Any]:
    """
    Get comprehensive status of authentication module components.
    
    Returns:
        Dictionary containing status of all authentication components
        
    Example:
        status = get_auth_module_status()
        print(f"Authentication module status: {status['overall_status']}")
    """
    try:
        component_status = {
            'overall_status': 'healthy',
            'components': {},
            'metrics': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check core authenticator
        if _core_authenticator:
            auth_health = _core_authenticator.get_health_status()
            component_status['components']['core_authenticator'] = auth_health
        else:
            component_status['components']['core_authenticator'] = {
                'status': 'not_initialized'
            }
        
        # Check session manager
        if _session_manager:
            session_health = _session_manager.get_health_status()
            component_status['components']['session_manager'] = session_health
        else:
            component_status['components']['session_manager'] = {
                'status': 'not_initialized'
            }
        
        # Check authorization manager
        if _authorization_manager:
            authz_health = _authorization_manager.get_health_status()
            component_status['components']['authorization_manager'] = authz_health
        else:
            component_status['components']['authorization_manager'] = {
                'status': 'not_initialized'
            }
        
        # Check Flask-Login
        component_status['components']['flask_login'] = {
            'status': 'initialized' if _login_manager else 'not_initialized',
            'login_view': getattr(_login_manager, 'login_view', None)
        }
        
        # Determine overall status
        component_statuses = [
            comp.get('status', 'unknown') 
            for comp in component_status['components'].values()
        ]
        
        if 'unhealthy' in component_statuses or 'not_initialized' in component_statuses:
            component_status['overall_status'] = 'unhealthy'
        elif 'degraded' in component_statuses:
            component_status['overall_status'] = 'degraded'
        
        return component_status
        
    except Exception as e:
        return {
            'overall_status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Centralized imports for authentication components per Section 5.2.3
__all__ = [
    # Core authentication
    'CoreJWTAuthenticator',
    'AuthenticatedUser', 
    'get_core_authenticator',
    'require_authentication',
    'get_authenticated_user',
    'authenticate_token',
    'create_auth_health_check',
    
    # Authorization
    'AuthorizationManager',
    'require_permissions',
    'verify_resource_access',
    'check_user_permissions',
    'get_authorization_manager',
    
    # Decorators
    'login_required_with_permissions',
    'rate_limited_authorization',
    'resource_owner_required',
    'admin_required',
    'api_key_required',
    'csrf_protect',
    'audit_security_event',
    
    # Session management
    'FlaskLoginSessionManager',
    'initialize_session_management',
    'get_session_manager',
    'cleanup_expired_sessions',
    
    # Security headers
    'configure_security_headers',
    'initialize_flask_talisman',
    'get_security_configuration',
    'create_csp_nonce',
    'validate_security_context',
    
    # Blueprint and initialization
    'auth_blueprint',
    'create_auth_blueprint',
    'initialize_authentication_module',
    'register_auth_blueprint',
    'get_auth_module_status',
    
    # Metrics
    'auth_operation_metrics',
    'auth_module_metrics'
]

# Module version and metadata
__version__ = '1.0.0'
__author__ = 'Flask Migration Team'
__license__ = 'Enterprise'
__compliance__ = ['SOC 2', 'ISO 27001', 'OWASP Top 10']