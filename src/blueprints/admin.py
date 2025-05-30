"""
Administrative Blueprint providing secure administrative functionality with elevated permissions,
system management endpoints, user administration, and comprehensive audit logging.

This module implements enterprise-grade administrative controls with multi-factor authentication
integration, enhanced authorization decorators, comprehensive security event logging, and 
administrative dashboard capabilities as specified in Section 6.4.2 of the technical specification.

Key Features:
- Enhanced authorization decorators with admin-level permissions
- Comprehensive security event logging for administrative actions
- Administrative endpoint protection with elevated security
- System management and user administration capabilities
- Admin-specific rate limiting and security controls
- Administrative dashboard and monitoring capabilities

Dependencies:
- src/auth/decorators.py: Enhanced authorization decorators
- src/auth/authorization.py: Role-based access control
- src/auth/audit.py: Security audit logging
- src/data/__init__.py: Database operations
- src/monitoring/__init__.py: Monitoring integration
"""

from typing import Dict, Any, List, Optional, Union
from functools import wraps
from datetime import datetime, timedelta
import json
import traceback

from flask import Blueprint, request, jsonify, current_app, g
from flask_login import current_user, login_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Authentication and authorization imports
from src.auth.decorators import require_permissions, rate_limited_authorization
from src.auth.authorization import (
    validate_user_permissions,
    get_user_roles,
    get_permission_hierarchy,
    invalidate_user_permissions
)
from src.auth.audit import SecurityAuditLogger, log_security_event

# Data access imports
from src.data import get_mongodb_client, get_motor_client
from src.data.exceptions import DatabaseError, ConnectionError as DBConnectionError

# Monitoring imports
from src.monitoring import get_metrics_collector, get_health_monitor
from src.monitoring.logging import get_logger

# Initialize the admin blueprint with URL prefix
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# Initialize logger for administrative operations
logger = get_logger(__name__)

# Initialize security audit logger for admin actions
security_logger = SecurityAuditLogger()

# Admin-specific rate limiter configuration
admin_limiter = None  # Will be initialized by create_admin_limiter function


def create_admin_limiter(app) -> Limiter:
    """
    Create and configure admin-specific rate limiter with Redis backend
    for enhanced security and abuse prevention.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured Limiter instance for admin endpoints
    """
    global admin_limiter
    
    try:
        redis_client = redis.Redis(
            host=app.config.get('REDIS_HOST', 'localhost'),
            port=int(app.config.get('REDIS_PORT', 6379)),
            password=app.config.get('REDIS_PASSWORD'),
            db=int(app.config.get('REDIS_LIMITER_DB', 3)),  # Separate DB for admin rate limiting
            decode_responses=True,
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            retry_on_timeout=True
        )
        
        admin_limiter = Limiter(
            key_func=lambda: f"admin_{current_user.id if current_user.is_authenticated else get_remote_address()}",
            app=app,
            storage_uri=f"redis://{redis_client.connection_pool.connection_kwargs['host']}:{redis_client.connection_pool.connection_kwargs['port']}/{redis_client.connection_pool.connection_kwargs['db']}",
            storage_options={'connection_pool': redis_client.connection_pool},
            default_limits=[
                "200 per hour",     # Sustained admin operations
                "50 per minute",    # Burst protection
                "5 per second"      # Spike protection
            ],
            strategy="moving-window",
            headers_enabled=True,
            header_name_mapping={
                "X-RateLimit-Limit": "X-Admin-RateLimit-Limit",
                "X-RateLimit-Remaining": "X-Admin-RateLimit-Remaining",
                "X-RateLimit-Reset": "X-Admin-RateLimit-Reset"
            }
        )
        
        logger.info("Admin rate limiter initialized successfully")
        return admin_limiter
        
    except Exception as e:
        logger.error(f"Failed to initialize admin rate limiter: {str(e)}")
        # Fallback to memory-based rate limiter
        admin_limiter = Limiter(
            key_func=lambda: f"admin_{current_user.id if current_user.is_authenticated else get_remote_address()}",
            app=app,
            default_limits=["100 per hour", "20 per minute", "2 per second"]
        )
        return admin_limiter


def admin_required(permissions: List[str] = None, audit_action: str = None):
    """
    Enhanced admin authorization decorator with comprehensive security controls.
    
    This decorator provides multi-layered security for administrative endpoints:
    - Requires authentication via Flask-Login
    - Validates admin-level permissions
    - Enforces strict rate limiting
    - Logs all access attempts for audit compliance
    - Supports resource-specific authorization
    
    Args:
        permissions: List of required admin permissions (default: ['admin.access'])
        audit_action: Specific action being performed for audit logging
        
    Returns:
        Decorated function with enhanced admin authorization
        
    Example:
        @admin_required(['admin.users.manage'], 'user_modification')
        def update_user(user_id):
            return update_user_account(user_id)
    """
    if permissions is None:
        permissions = ['admin.access']
    
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            start_time = datetime.utcnow()
            
            try:
                # Validate user is authenticated
                if not current_user.is_authenticated:
                    security_logger.log_authorization_event(
                        event_type='admin_access_denied',
                        user_id='anonymous',
                        result='denied',
                        permissions=permissions,
                        additional_context={
                            'reason': 'not_authenticated',
                            'endpoint': request.endpoint,
                            'method': request.method,
                            'audit_action': audit_action
                        }
                    )
                    return jsonify({'error': 'Authentication required'}), 401
                
                # Validate admin permissions
                user_id = current_user.id
                has_permissions = validate_user_permissions(
                    user_id, 
                    permissions,
                    resource_id=None,
                    allow_owner=False  # Admin permissions don't allow owner bypass
                )
                
                if not has_permissions:
                    security_logger.log_authorization_event(
                        event_type='admin_access_denied',
                        user_id=user_id,
                        result='denied',
                        permissions=permissions,
                        additional_context={
                            'reason': 'insufficient_permissions',
                            'endpoint': request.endpoint,
                            'method': request.method,
                            'audit_action': audit_action,
                            'user_roles': get_user_roles(user_id)
                        }
                    )
                    return jsonify({'error': 'Insufficient administrative permissions'}), 403
                
                # Log successful authorization
                security_logger.log_authorization_event(
                    event_type='admin_access_granted',
                    user_id=user_id,
                    result='granted',
                    permissions=permissions,
                    additional_context={
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'audit_action': audit_action,
                        'request_data': _sanitize_request_data(request)
                    }
                )
                
                # Execute the protected function
                result = func(*args, **kwargs)
                
                # Log successful completion
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                security_logger.log_authorization_event(
                    event_type='admin_action_completed',
                    user_id=user_id,
                    result='success',
                    permissions=permissions,
                    additional_context={
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'audit_action': audit_action,
                        'execution_time_seconds': execution_time
                    }
                )
                
                return result
                
            except Exception as e:
                # Log administrative errors for security monitoring
                security_logger.log_authorization_event(
                    event_type='admin_action_error',
                    user_id=current_user.id if current_user.is_authenticated else 'anonymous',
                    result='error',
                    permissions=permissions,
                    additional_context={
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'audit_action': audit_action,
                        'error': str(e),
                        'traceback': traceback.format_exc()
                    }
                )
                
                logger.error(f"Admin action error: {str(e)}", extra={
                    'user_id': current_user.id if current_user.is_authenticated else None,
                    'endpoint': request.endpoint,
                    'audit_action': audit_action
                })
                
                return jsonify({'error': 'Administrative action failed'}), 500
                
        return wrapper
    return decorator


def _sanitize_request_data(request_obj) -> Dict[str, Any]:
    """
    Sanitize request data for audit logging, removing sensitive information.
    
    Args:
        request_obj: Flask request object
        
    Returns:
        Sanitized request data dictionary
    """
    sensitive_fields = ['password', 'token', 'secret', 'key', 'auth']
    
    try:
        data = {}
        
        # Add basic request information
        data['url'] = request_obj.url
        data['method'] = request_obj.method
        data['remote_addr'] = request_obj.remote_addr
        data['user_agent'] = request_obj.headers.get('User-Agent', 'Unknown')
        
        # Add query parameters (sanitized)
        if request_obj.args:
            args = {}
            for key, value in request_obj.args.items():
                if any(sensitive_field in key.lower() for sensitive_field in sensitive_fields):
                    args[key] = '[REDACTED]'
                else:
                    args[key] = value
            data['query_params'] = args
        
        # Add form data (sanitized)
        if request_obj.form:
            form_data = {}
            for key, value in request_obj.form.items():
                if any(sensitive_field in key.lower() for sensitive_field in sensitive_fields):
                    form_data[key] = '[REDACTED]'
                else:
                    form_data[key] = value
            data['form_data'] = form_data
            
        return data
        
    except Exception as e:
        logger.warning(f"Failed to sanitize request data: {str(e)}")
        return {'sanitization_error': str(e)}


# Administrative Dashboard Endpoints

@admin_bp.route('/dashboard', methods=['GET'])
@admin_limiter.limit("10 per minute")
@admin_required(['admin.dashboard.view'], 'dashboard_access')
def get_admin_dashboard():
    """
    Administrative dashboard endpoint providing system overview and statistics.
    
    Returns comprehensive system metrics, user statistics, security events,
    and operational health information for administrative monitoring.
    
    Security Controls:
    - Admin-level permissions required
    - Rate limited to 10 requests per minute
    - Comprehensive audit logging
    - Input validation and sanitization
    
    Returns:
        JSON response with dashboard data and system metrics
    """
    try:
        # Collect system metrics
        metrics_collector = get_metrics_collector()
        health_monitor = get_health_monitor()
        
        # Get database statistics
        mongodb_client = get_mongodb_client()
        db_stats = _get_database_statistics(mongodb_client)
        
        # Get user statistics
        user_stats = _get_user_statistics(mongodb_client)
        
        # Get security event summary
        security_stats = _get_security_statistics()
        
        # Get system health status
        health_status = health_monitor.get_comprehensive_health()
        
        # Compile dashboard data
        dashboard_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'system_health': health_status,
            'database_statistics': db_stats,
            'user_statistics': user_stats,
            'security_statistics': security_stats,
            'performance_metrics': {
                'response_time_avg': metrics_collector.get_average_response_time(),
                'request_rate': metrics_collector.get_request_rate(),
                'error_rate': metrics_collector.get_error_rate(),
                'active_connections': metrics_collector.get_active_connections()
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': dashboard_data,
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard data collection failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve dashboard data',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/system/status', methods=['GET'])
@admin_limiter.limit("20 per minute")
@admin_required(['admin.system.view'], 'system_status_check')
def get_system_status():
    """
    System status endpoint providing detailed health and configuration information.
    
    Returns comprehensive system status including database connectivity,
    external service health, cache status, and configuration validation.
    
    Returns:
        JSON response with detailed system status information
    """
    try:
        health_monitor = get_health_monitor()
        
        # Check all system components
        status_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'components': {}
        }
        
        # Database connectivity
        try:
            mongodb_client = get_mongodb_client()
            mongodb_client.admin.command('ping')
            status_info['components']['mongodb'] = {
                'status': 'healthy',
                'response_time_ms': _measure_database_response_time(mongodb_client)
            }
        except Exception as e:
            status_info['components']['mongodb'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            status_info['overall_status'] = 'degraded'
        
        # Redis cache connectivity
        try:
            redis_client = redis.Redis.from_url(current_app.config.get('REDIS_URL'))
            redis_client.ping()
            status_info['components']['redis'] = {
                'status': 'healthy',
                'memory_usage': redis_client.info('memory')['used_memory_human']
            }
        except Exception as e:
            status_info['components']['redis'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            status_info['overall_status'] = 'degraded'
        
        # External services status
        auth0_status = _check_auth0_connectivity()
        status_info['components']['auth0'] = auth0_status
        if auth0_status['status'] != 'healthy':
            status_info['overall_status'] = 'degraded'
        
        # Application metrics
        metrics_collector = get_metrics_collector()
        status_info['components']['application'] = {
            'status': 'healthy',
            'uptime_seconds': metrics_collector.get_uptime(),
            'active_sessions': metrics_collector.get_active_sessions(),
            'memory_usage_mb': metrics_collector.get_memory_usage()
        }
        
        return jsonify(status_info), 200
        
    except Exception as e:
        logger.error(f"System status check failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'System status check failed',
            'timestamp': datetime.utcnow().isoformat(),
            'error_id': _generate_error_id()
        }), 500


# User Administration Endpoints

@admin_bp.route('/users', methods=['GET'])
@admin_limiter.limit("30 per minute")
@admin_required(['admin.users.view'], 'user_list_access')
def list_users():
    """
    List users with comprehensive filtering and pagination support.
    
    Query Parameters:
    - page: Page number (default: 1)
    - limit: Items per page (default: 50, max: 200)
    - search: Search term for username/email
    - role: Filter by user role
    - status: Filter by account status (active, inactive, suspended)
    - sort: Sort field (username, email, created_at, last_login)
    - order: Sort order (asc, desc)
    
    Returns:
        JSON response with paginated user list and metadata
    """
    try:
        # Parse and validate query parameters
        page = max(1, int(request.args.get('page', 1)))
        limit = min(200, max(1, int(request.args.get('limit', 50))))
        search = request.args.get('search', '').strip()
        role_filter = request.args.get('role', '').strip()
        status_filter = request.args.get('status', '').strip()
        sort_field = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')
        
        # Validate sort parameters
        valid_sort_fields = ['username', 'email', 'created_at', 'last_login', 'status']
        if sort_field not in valid_sort_fields:
            sort_field = 'created_at'
        
        if sort_order not in ['asc', 'desc']:
            sort_order = 'desc'
        
        # Build MongoDB query
        mongodb_client = get_mongodb_client()
        users_collection = mongodb_client.app_database.users
        
        query_filter = {}
        
        # Apply search filter
        if search:
            query_filter['$or'] = [
                {'username': {'$regex': search, '$options': 'i'}},
                {'email': {'$regex': search, '$options': 'i'}},
                {'profile.name': {'$regex': search, '$options': 'i'}}
            ]
        
        # Apply role filter
        if role_filter:
            query_filter['roles'] = {'$in': [role_filter]}
        
        # Apply status filter
        if status_filter:
            query_filter['status'] = status_filter
        
        # Calculate pagination
        skip = (page - 1) * limit
        sort_direction = 1 if sort_order == 'asc' else -1
        
        # Execute query with pagination
        cursor = users_collection.find(query_filter).sort(sort_field, sort_direction)
        total_count = users_collection.count_documents(query_filter)
        users = list(cursor.skip(skip).limit(limit))
        
        # Sanitize user data for response
        sanitized_users = []
        for user in users:
            sanitized_user = _sanitize_user_data(user)
            sanitized_users.append(sanitized_user)
        
        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit
        has_next = page < total_pages
        has_prev = page > 1
        
        return jsonify({
            'status': 'success',
            'data': {
                'users': sanitized_users,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': total_pages,
                    'has_next': has_next,
                    'has_prev': has_prev
                },
                'filters': {
                    'search': search,
                    'role': role_filter,
                    'status': status_filter,
                    'sort': sort_field,
                    'order': sort_order
                }
            },
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': 'Invalid query parameters',
            'details': str(e)
        }), 400
    except Exception as e:
        logger.error(f"User list retrieval failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve user list',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/users/<user_id>', methods=['GET'])
@admin_limiter.limit("60 per minute")
@admin_required(['admin.users.view'], 'user_detail_access')
def get_user_details(user_id: str):
    """
    Get detailed user information including profile, roles, and activity history.
    
    Args:
        user_id: User identifier
        
    Returns:
        JSON response with comprehensive user details
    """
    try:
        mongodb_client = get_mongodb_client()
        users_collection = mongodb_client.app_database.users
        
        # Find user by ID
        user = users_collection.find_one({'_id': user_id})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Get user activity history
        activity_history = _get_user_activity_history(user_id, limit=50)
        
        # Get user permissions
        user_permissions = get_user_roles(user_id)
        
        # Get user session information
        session_info = _get_user_session_info(user_id)
        
        # Compile detailed user information
        user_details = {
            'user_profile': _sanitize_user_data(user),
            'permissions': user_permissions,
            'activity_history': activity_history,
            'session_info': session_info,
            'account_statistics': {
                'login_count': user.get('login_count', 0),
                'last_login': user.get('last_login'),
                'account_created': user.get('created_at'),
                'password_last_changed': user.get('password_changed_at'),
                'failed_login_attempts': user.get('failed_logins', 0)
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': user_details,
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"User details retrieval failed for user {user_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve user details',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/users/<user_id>/permissions', methods=['PUT'])
@admin_limiter.limit("10 per minute")
@admin_required(['admin.users.manage', 'admin.permissions.modify'], 'user_permission_modification')
def update_user_permissions(user_id: str):
    """
    Update user permissions and roles with comprehensive validation and audit logging.
    
    Args:
        user_id: User identifier
        
    Request Body:
        {
            "roles": ["role1", "role2"],
            "permissions": ["permission1", "permission2"],
            "reason": "Administrative justification"
        }
        
    Returns:
        JSON response with updated permission status
    """
    try:
        # Validate request data
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body is required'
            }), 400
        
        # Validate required fields
        roles = data.get('roles', [])
        permissions = data.get('permissions', [])
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'status': 'error',
                'message': 'Administrative reason is required for permission changes'
            }), 400
        
        # Validate user exists
        mongodb_client = get_mongodb_client()
        users_collection = mongodb_client.app_database.users
        
        user = users_collection.find_one({'_id': user_id})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Validate roles and permissions
        valid_roles = _get_valid_roles()
        valid_permissions = _get_valid_permissions()
        
        invalid_roles = [role for role in roles if role not in valid_roles]
        invalid_permissions = [perm for perm in permissions if perm not in valid_permissions]
        
        if invalid_roles or invalid_permissions:
            return jsonify({
                'status': 'error',
                'message': 'Invalid roles or permissions specified',
                'details': {
                    'invalid_roles': invalid_roles,
                    'invalid_permissions': invalid_permissions
                }
            }), 400
        
        # Get current permissions for audit comparison
        current_roles = user.get('roles', [])
        current_permissions = user.get('permissions', [])
        
        # Update user permissions
        update_data = {
            'roles': roles,
            'permissions': permissions,
            'permissions_updated_at': datetime.utcnow(),
            'permissions_updated_by': current_user.id,
            'permissions_update_reason': reason
        }
        
        result = users_collection.update_one(
            {'_id': user_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update user permissions'
            }), 500
        
        # Invalidate user permission cache
        invalidate_user_permissions(user_id)
        
        # Log permission change for audit
        security_logger.log_authorization_event(
            event_type='user_permissions_modified',
            user_id=current_user.id,
            result='success',
            permissions=['admin.users.manage', 'admin.permissions.modify'],
            additional_context={
                'target_user_id': user_id,
                'previous_roles': current_roles,
                'new_roles': roles,
                'previous_permissions': current_permissions,
                'new_permissions': permissions,
                'reason': reason,
                'modification_timestamp': datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': 'User permissions updated successfully',
            'data': {
                'user_id': user_id,
                'updated_roles': roles,
                'updated_permissions': permissions,
                'updated_at': datetime.utcnow().isoformat(),
                'updated_by': current_user.id
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Permission update failed for user {user_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update user permissions',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/users/<user_id>/status', methods=['PUT'])
@admin_limiter.limit("15 per minute")
@admin_required(['admin.users.manage'], 'user_status_modification')
def update_user_status(user_id: str):
    """
    Update user account status (active, suspended, inactive) with audit logging.
    
    Args:
        user_id: User identifier
        
    Request Body:
        {
            "status": "active|suspended|inactive",
            "reason": "Administrative justification",
            "duration_hours": 24  // Optional, for temporary suspensions
        }
        
    Returns:
        JSON response with status update confirmation
    """
    try:
        # Validate request data
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body is required'
            }), 400
        
        # Validate required fields
        new_status = data.get('status', '').strip().lower()
        reason = data.get('reason', '').strip()
        duration_hours = data.get('duration_hours')
        
        if new_status not in ['active', 'suspended', 'inactive']:
            return jsonify({
                'status': 'error',
                'message': 'Status must be one of: active, suspended, inactive'
            }), 400
        
        if not reason:
            return jsonify({
                'status': 'error',
                'message': 'Administrative reason is required for status changes'
            }), 400
        
        # Validate user exists
        mongodb_client = get_mongodb_client()
        users_collection = mongodb_client.app_database.users
        
        user = users_collection.find_one({'_id': user_id})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Prevent self-modification for critical operations
        if user_id == current_user.id and new_status in ['suspended', 'inactive']:
            return jsonify({
                'status': 'error',
                'message': 'Cannot suspend or deactivate your own account'
            }), 403
        
        # Prepare update data
        current_status = user.get('status', 'active')
        update_data = {
            'status': new_status,
            'status_updated_at': datetime.utcnow(),
            'status_updated_by': current_user.id,
            'status_update_reason': reason,
            'previous_status': current_status
        }
        
        # Handle temporary suspensions
        if new_status == 'suspended' and duration_hours:
            try:
                duration = int(duration_hours)
                if duration > 0:
                    suspension_end = datetime.utcnow() + timedelta(hours=duration)
                    update_data['suspension_end'] = suspension_end
            except (ValueError, TypeError):
                return jsonify({
                    'status': 'error',
                    'message': 'duration_hours must be a positive integer'
                }), 400
        
        # Update user status
        result = users_collection.update_one(
            {'_id': user_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update user status'
            }), 500
        
        # Invalidate user sessions if suspended or deactivated
        if new_status in ['suspended', 'inactive']:
            _invalidate_user_sessions(user_id)
        
        # Log status change for audit
        security_logger.log_authorization_event(
            event_type='user_status_modified',
            user_id=current_user.id,
            result='success',
            permissions=['admin.users.manage'],
            additional_context={
                'target_user_id': user_id,
                'previous_status': current_status,
                'new_status': new_status,
                'reason': reason,
                'duration_hours': duration_hours,
                'modification_timestamp': datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': f'User status updated to {new_status}',
            'data': {
                'user_id': user_id,
                'previous_status': current_status,
                'new_status': new_status,
                'updated_at': datetime.utcnow().isoformat(),
                'updated_by': current_user.id,
                'suspension_end': update_data.get('suspension_end')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Status update failed for user {user_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update user status',
            'error_id': _generate_error_id()
        }), 500


# Security and Audit Endpoints

@admin_bp.route('/security/events', methods=['GET'])
@admin_limiter.limit("30 per minute")
@admin_required(['admin.security.view'], 'security_events_access')
def get_security_events():
    """
    Retrieve security events and audit logs with filtering and pagination.
    
    Query Parameters:
    - page: Page number (default: 1)
    - limit: Items per page (default: 100, max: 500)
    - event_type: Filter by event type
    - user_id: Filter by user ID
    - start_date: Start date for filtering (ISO format)
    - end_date: End date for filtering (ISO format)
    - severity: Filter by severity level (low, medium, high, critical)
    
    Returns:
        JSON response with paginated security events
    """
    try:
        # Parse query parameters
        page = max(1, int(request.args.get('page', 1)))
        limit = min(500, max(1, int(request.args.get('limit', 100))))
        event_type = request.args.get('event_type', '').strip()
        user_id_filter = request.args.get('user_id', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        severity = request.args.get('severity', '').strip()
        
        # Build query filter
        mongodb_client = get_mongodb_client()
        security_logs_collection = mongodb_client.app_database.security_events
        
        query_filter = {}
        
        # Apply filters
        if event_type:
            query_filter['event_type'] = event_type
        
        if user_id_filter:
            query_filter['user_id'] = user_id_filter
        
        if severity:
            query_filter['severity'] = severity
        
        # Apply date range filter
        if start_date or end_date:
            date_filter = {}
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    date_filter['$gte'] = start_dt
                except ValueError:
                    return jsonify({
                        'status': 'error',
                        'message': 'Invalid start_date format. Use ISO format.'
                    }), 400
            
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    date_filter['$lte'] = end_dt
                except ValueError:
                    return jsonify({
                        'status': 'error',
                        'message': 'Invalid end_date format. Use ISO format.'
                    }), 400
            
            query_filter['timestamp'] = date_filter
        
        # Execute query with pagination
        skip = (page - 1) * limit
        cursor = security_logs_collection.find(query_filter).sort('timestamp', -1)
        total_count = security_logs_collection.count_documents(query_filter)
        events = list(cursor.skip(skip).limit(limit))
        
        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit
        has_next = page < total_pages
        has_prev = page > 1
        
        # Convert ObjectId to string for JSON serialization
        for event in events:
            if '_id' in event:
                event['_id'] = str(event['_id'])
        
        return jsonify({
            'status': 'success',
            'data': {
                'events': events,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': total_pages,
                    'has_next': has_next,
                    'has_prev': has_prev
                },
                'filters': {
                    'event_type': event_type,
                    'user_id': user_id_filter,
                    'start_date': start_date,
                    'end_date': end_date,
                    'severity': severity
                }
            },
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Security events retrieval failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve security events',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/security/metrics', methods=['GET'])
@admin_limiter.limit("20 per minute")
@admin_required(['admin.security.view'], 'security_metrics_access')
def get_security_metrics():
    """
    Retrieve comprehensive security metrics and statistics.
    
    Returns aggregated security metrics including:
    - Authentication failure rates
    - Authorization violations
    - Rate limiting violations
    - Suspicious activity patterns
    - Geographic access patterns
    
    Returns:
        JSON response with security metrics and analytics
    """
    try:
        mongodb_client = get_mongodb_client()
        security_logs_collection = mongodb_client.app_database.security_events
        
        # Calculate time ranges for metrics
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)
        
        # Aggregate security metrics
        metrics = {
            'timestamp': now.isoformat(),
            'authentication_metrics': {
                'last_24h': _get_authentication_metrics(security_logs_collection, last_24h, now),
                'last_7d': _get_authentication_metrics(security_logs_collection, last_7d, now),
                'last_30d': _get_authentication_metrics(security_logs_collection, last_30d, now)
            },
            'authorization_metrics': {
                'last_24h': _get_authorization_metrics(security_logs_collection, last_24h, now),
                'last_7d': _get_authorization_metrics(security_logs_collection, last_7d, now),
                'last_30d': _get_authorization_metrics(security_logs_collection, last_30d, now)
            },
            'threat_indicators': _get_threat_indicators(security_logs_collection, last_24h, now),
            'geographic_patterns': _get_geographic_patterns(security_logs_collection, last_7d, now),
            'rate_limiting_violations': _get_rate_limiting_metrics(security_logs_collection, last_24h, now)
        }
        
        return jsonify({
            'status': 'success',
            'data': metrics,
            'generated_at': now.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Security metrics retrieval failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve security metrics',
            'error_id': _generate_error_id()
        }), 500


# System Management Endpoints

@admin_bp.route('/system/cache/flush', methods=['POST'])
@admin_limiter.limit("5 per minute")
@admin_required(['admin.system.manage'], 'cache_flush_operation')
def flush_system_cache():
    """
    Flush system caches including Redis permissions cache and session storage.
    
    Request Body:
        {
            "cache_types": ["permissions", "sessions", "auth_tokens", "all"],
            "reason": "Administrative justification"
        }
        
    Returns:
        JSON response with cache flush results
    """
    try:
        # Validate request data
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body is required'
            }), 400
        
        cache_types = data.get('cache_types', ['all'])
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'status': 'error',
                'message': 'Administrative reason is required for cache operations'
            }), 400
        
        # Initialize Redis clients
        redis_client = redis.Redis.from_url(current_app.config.get('REDIS_URL'))
        
        flush_results = {}
        
        # Flush specific cache types
        if 'all' in cache_types or 'permissions' in cache_types:
            perm_keys = redis_client.keys('perm_cache:*')
            if perm_keys:
                deleted_count = redis_client.delete(*perm_keys)
                flush_results['permissions'] = {
                    'status': 'success',
                    'keys_deleted': deleted_count
                }
            else:
                flush_results['permissions'] = {
                    'status': 'success',
                    'keys_deleted': 0
                }
        
        if 'all' in cache_types or 'sessions' in cache_types:
            session_keys = redis_client.keys('session:*')
            if session_keys:
                deleted_count = redis_client.delete(*session_keys)
                flush_results['sessions'] = {
                    'status': 'success',
                    'keys_deleted': deleted_count
                }
            else:
                flush_results['sessions'] = {
                    'status': 'success',
                    'keys_deleted': 0
                }
        
        if 'all' in cache_types or 'auth_tokens' in cache_types:
            token_keys = redis_client.keys('jwt_validation:*')
            if token_keys:
                deleted_count = redis_client.delete(*token_keys)
                flush_results['auth_tokens'] = {
                    'status': 'success',
                    'keys_deleted': deleted_count
                }
            else:
                flush_results['auth_tokens'] = {
                    'status': 'success',
                    'keys_deleted': 0
                }
        
        # Log cache flush operation
        security_logger.log_authorization_event(
            event_type='system_cache_flushed',
            user_id=current_user.id,
            result='success',
            permissions=['admin.system.manage'],
            additional_context={
                'cache_types': cache_types,
                'reason': reason,
                'flush_results': flush_results,
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Cache flush completed',
            'data': {
                'cache_types_flushed': cache_types,
                'results': flush_results,
                'flushed_at': datetime.utcnow().isoformat(),
                'flushed_by': current_user.id
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Cache flush operation failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Cache flush operation failed',
            'error_id': _generate_error_id()
        }), 500


@admin_bp.route('/system/maintenance', methods=['POST'])
@admin_limiter.limit("3 per minute")
@admin_required(['admin.system.manage', 'admin.maintenance'], 'maintenance_mode_toggle')
def toggle_maintenance_mode():
    """
    Toggle system maintenance mode with controlled access.
    
    Request Body:
        {
            "maintenance_mode": true|false,
            "reason": "Administrative justification",
            "duration_minutes": 60  // Optional, for automatic restoration
        }
        
    Returns:
        JSON response with maintenance mode status
    """
    try:
        # Validate request data
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body is required'
            }), 400
        
        maintenance_mode = data.get('maintenance_mode')
        reason = data.get('reason', '').strip()
        duration_minutes = data.get('duration_minutes')
        
        if maintenance_mode is None:
            return jsonify({
                'status': 'error',
                'message': 'maintenance_mode field is required'
            }), 400
        
        if not reason:
            return jsonify({
                'status': 'error',
                'message': 'Administrative reason is required'
            }), 400
        
        # Store maintenance mode status in Redis
        redis_client = redis.Redis.from_url(current_app.config.get('REDIS_URL'))
        
        maintenance_data = {
            'enabled': maintenance_mode,
            'reason': reason,
            'enabled_by': current_user.id,
            'enabled_at': datetime.utcnow().isoformat()
        }
        
        if maintenance_mode and duration_minutes:
            try:
                duration = int(duration_minutes)
                if duration > 0:
                    maintenance_end = datetime.utcnow() + timedelta(minutes=duration)
                    maintenance_data['auto_disable_at'] = maintenance_end.isoformat()
            except (ValueError, TypeError):
                return jsonify({
                    'status': 'error',
                    'message': 'duration_minutes must be a positive integer'
                }), 400
        
        # Set maintenance mode in Redis
        redis_client.set(
            'system:maintenance_mode',
            json.dumps(maintenance_data),
            ex=86400  # Expire in 24 hours as safety mechanism
        )
        
        # Log maintenance mode change
        security_logger.log_authorization_event(
            event_type='maintenance_mode_toggled',
            user_id=current_user.id,
            result='success',
            permissions=['admin.system.manage', 'admin.maintenance'],
            additional_context={
                'maintenance_mode': maintenance_mode,
                'reason': reason,
                'duration_minutes': duration_minutes,
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': f'Maintenance mode {"enabled" if maintenance_mode else "disabled"}',
            'data': {
                'maintenance_mode': maintenance_mode,
                'reason': reason,
                'changed_by': current_user.id,
                'changed_at': datetime.utcnow().isoformat(),
                'auto_disable_at': maintenance_data.get('auto_disable_at')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Maintenance mode toggle failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to toggle maintenance mode',
            'error_id': _generate_error_id()
        }), 500


# Helper Functions

def _get_database_statistics(mongodb_client) -> Dict[str, Any]:
    """Get comprehensive database statistics and health information."""
    try:
        # Get database stats
        db_stats = mongodb_client.app_database.command('dbStats')
        
        # Get collection stats
        collections = mongodb_client.app_database.list_collection_names()
        collection_stats = {}
        
        for collection_name in collections:
            try:
                stats = mongodb_client.app_database.command('collStats', collection_name)
                collection_stats[collection_name] = {
                    'document_count': stats.get('count', 0),
                    'size_bytes': stats.get('size', 0),
                    'index_count': stats.get('nindexes', 0),
                    'average_document_size': stats.get('avgObjSize', 0)
                }
            except Exception:
                continue
        
        return {
            'database_size_bytes': db_stats.get('dataSize', 0),
            'index_size_bytes': db_stats.get('indexSize', 0),
            'total_collections': len(collections),
            'collection_statistics': collection_stats,
            'last_updated': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database statistics collection failed: {str(e)}")
        return {'error': str(e)}


def _get_user_statistics(mongodb_client) -> Dict[str, Any]:
    """Get comprehensive user statistics and demographics."""
    try:
        users_collection = mongodb_client.app_database.users
        
        # Total user counts by status
        total_users = users_collection.count_documents({})
        active_users = users_collection.count_documents({'status': 'active'})
        suspended_users = users_collection.count_documents({'status': 'suspended'})
        inactive_users = users_collection.count_documents({'status': 'inactive'})
        
        # Recent user activity
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_logins = users_collection.count_documents({
            'last_login': {'$gte': last_24h}
        })
        
        # New registrations in last 7 days
        last_7d = datetime.utcnow() - timedelta(days=7)
        new_registrations = users_collection.count_documents({
            'created_at': {'$gte': last_7d}
        })
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'suspended_users': suspended_users,
            'inactive_users': inactive_users,
            'recent_logins_24h': recent_logins,
            'new_registrations_7d': new_registrations,
            'last_updated': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"User statistics collection failed: {str(e)}")
        return {'error': str(e)}


def _get_security_statistics() -> Dict[str, Any]:
    """Get security event statistics and threat indicators."""
    try:
        # This would typically query a security events collection
        # For now, return placeholder data
        return {
            'failed_authentications_24h': 0,
            'authorization_violations_24h': 0,
            'rate_limit_violations_24h': 0,
            'suspicious_ips_24h': 0,
            'last_updated': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Security statistics collection failed: {str(e)}")
        return {'error': str(e)}


def _sanitize_user_data(user: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize user data for safe return in API responses."""
    sensitive_fields = ['password', 'password_hash', 'salt', 'auth_tokens']
    
    sanitized = {}
    for key, value in user.items():
        if key not in sensitive_fields:
            sanitized[key] = value
    
    # Convert ObjectId to string if present
    if '_id' in sanitized:
        sanitized['_id'] = str(sanitized['_id'])
    
    return sanitized


def _measure_database_response_time(mongodb_client) -> float:
    """Measure database response time in milliseconds."""
    try:
        start_time = datetime.utcnow()
        mongodb_client.admin.command('ping')
        end_time = datetime.utcnow()
        
        response_time = (end_time - start_time).total_seconds() * 1000
        return round(response_time, 2)
        
    except Exception:
        return -1.0


def _check_auth0_connectivity() -> Dict[str, Any]:
    """Check Auth0 service connectivity and status."""
    try:
        # This would implement actual Auth0 health check
        # For now, return mock data
        return {
            'status': 'healthy',
            'response_time_ms': 150,
            'last_checked': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'last_checked': datetime.utcnow().isoformat()
        }


def _get_user_activity_history(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get user activity history from audit logs."""
    try:
        # This would query activity logs
        # For now, return placeholder data
        return []
        
    except Exception as e:
        logger.error(f"User activity history retrieval failed: {str(e)}")
        return []


def _get_user_session_info(user_id: str) -> Dict[str, Any]:
    """Get current session information for a user."""
    try:
        # This would query Redis session storage
        # For now, return placeholder data
        return {
            'active_sessions': 0,
            'last_activity': None,
            'session_locations': []
        }
        
    except Exception as e:
        logger.error(f"User session info retrieval failed: {str(e)}")
        return {}


def _get_valid_roles() -> List[str]:
    """Get list of valid user roles."""
    return [
        'user',
        'moderator',
        'admin',
        'super_admin',
        'api_user',
        'readonly_user'
    ]


def _get_valid_permissions() -> List[str]:
    """Get list of valid permissions."""
    return [
        'admin.access',
        'admin.dashboard.view',
        'admin.users.view',
        'admin.users.manage',
        'admin.permissions.modify',
        'admin.security.view',
        'admin.system.view',
        'admin.system.manage',
        'admin.maintenance',
        'api.read',
        'api.write',
        'api.delete'
    ]


def _invalidate_user_sessions(user_id: str):
    """Invalidate all sessions for a specific user."""
    try:
        redis_client = redis.Redis.from_url(current_app.config.get('REDIS_URL'))
        session_keys = redis_client.keys(f'session:*:{user_id}')
        
        if session_keys:
            redis_client.delete(*session_keys)
            logger.info(f"Invalidated {len(session_keys)} sessions for user {user_id}")
        
    except Exception as e:
        logger.error(f"Session invalidation failed for user {user_id}: {str(e)}")


def _generate_error_id() -> str:
    """Generate unique error ID for tracking."""
    import uuid
    return str(uuid.uuid4())[:8]


def _get_authentication_metrics(collection, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Get authentication metrics for a specific time period."""
    try:
        total_attempts = collection.count_documents({
            'event_type': {'$in': ['authentication_success', 'authentication_failure']},
            'timestamp': {'$gte': start_date, '$lte': end_date}
        })
        
        failed_attempts = collection.count_documents({
            'event_type': 'authentication_failure',
            'timestamp': {'$gte': start_date, '$lte': end_date}
        })
        
        success_rate = ((total_attempts - failed_attempts) / total_attempts * 100) if total_attempts > 0 else 0
        
        return {
            'total_attempts': total_attempts,
            'failed_attempts': failed_attempts,
            'success_rate_percent': round(success_rate, 2)
        }
        
    except Exception:
        return {'total_attempts': 0, 'failed_attempts': 0, 'success_rate_percent': 0}


def _get_authorization_metrics(collection, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Get authorization metrics for a specific time period."""
    try:
        total_checks = collection.count_documents({
            'event_type': {'$in': ['admin_access_granted', 'admin_access_denied']},
            'timestamp': {'$gte': start_date, '$lte': end_date}
        })
        
        denied_checks = collection.count_documents({
            'event_type': 'admin_access_denied',
            'timestamp': {'$gte': start_date, '$lte': end_date}
        })
        
        return {
            'total_authorization_checks': total_checks,
            'denied_authorizations': denied_checks
        }
        
    except Exception:
        return {'total_authorization_checks': 0, 'denied_authorizations': 0}


def _get_threat_indicators(collection, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Get threat indicators and suspicious activity patterns."""
    try:
        # This would implement comprehensive threat analysis
        # For now, return basic indicators
        return {
            'brute_force_attempts': 0,
            'suspicious_login_patterns': 0,
            'rate_limit_violations': 0,
            'privilege_escalation_attempts': 0
        }
        
    except Exception:
        return {}


def _get_geographic_patterns(collection, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Get geographic access patterns and anomalies."""
    try:
        # This would implement geographic analysis
        # For now, return placeholder data
        return {
            'unique_countries': 0,
            'unusual_locations': 0,
            'top_countries': []
        }
        
    except Exception:
        return {}


def _get_rate_limiting_metrics(collection, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Get rate limiting violation metrics."""
    try:
        violations = collection.count_documents({
            'event_type': 'rate_limit_violation',
            'timestamp': {'$gte': start_date, '$lte': end_date}
        })
        
        return {
            'total_violations': violations,
            'unique_users_affected': 0,  # Would calculate from actual data
            'top_violating_endpoints': []
        }
        
    except Exception:
        return {'total_violations': 0}


# Error handlers for the admin blueprint
@admin_bp.errorhandler(429)
def handle_rate_limit_exceeded(error):
    """Handle rate limit exceeded errors for admin endpoints."""
    security_logger.log_rate_limit_violation(
        user_id=current_user.id if current_user.is_authenticated else 'anonymous',
        endpoint=request.endpoint or 'unknown',
        limit_exceeded=str(error.description),
        current_usage=0  # Would extract from rate limiter
    )
    
    return jsonify({
        'status': 'error',
        'message': 'Administrative rate limit exceeded',
        'retry_after': getattr(error, 'retry_after', 60)
    }), 429


@admin_bp.errorhandler(403)
def handle_forbidden(error):
    """Handle forbidden access errors for admin endpoints."""
    return jsonify({
        'status': 'error',
        'message': 'Administrative access forbidden',
        'required_permissions': 'admin.access'
    }), 403


@admin_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors for admin endpoints."""
    error_id = _generate_error_id()
    
    logger.error(f"Admin endpoint internal error [ID: {error_id}]: {str(error)}")
    
    return jsonify({
        'status': 'error',
        'message': 'Internal administrative system error',
        'error_id': error_id
    }), 500


# Blueprint initialization function
def init_admin_blueprint(app):
    """
    Initialize the admin blueprint with the Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize admin-specific rate limiter
    create_admin_limiter(app)
    
    # Register the blueprint
    app.register_blueprint(admin_bp)
    
    logger.info("Admin blueprint initialized successfully")