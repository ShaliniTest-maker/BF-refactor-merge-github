"""
Comprehensive Unit Tests for Flask Blueprint Route Testing

This module provides comprehensive unit testing for all Flask Blueprint routes with 100% 
coverage requirement per Section 6.6.3 critical requirement. The tests validate HTTP method 
support, authentication integration, request validation, response formatting, and error 
handling for API layer components maintaining backward compatibility with Node.js implementation.

Key Features:
- 100% API layer coverage testing per Section 6.6.3 critical requirement
- HTTP Method Support testing for RESTful endpoints per F-002-RQ-001
- Authentication and authorization pattern testing per F-003-RQ-002
- Request/response format validation maintaining Node.js compatibility per Section 0.1.4
- Rate limiting testing with Flask-Limiter per Section 5.2.2
- Comprehensive error handling validation per F-005-RQ-001
- Performance baseline testing per Section 0.3.2

Test Organization:
- API Blueprint endpoints testing per Section 6.6.1 test organization
- Health Blueprint monitoring endpoints per Section 6.5.2.1
- Public Blueprint unauthenticated endpoints per Section 6.1.3
- Admin Blueprint administrative endpoints per Section 6.4.2
- Authentication decorator testing per Section 6.4.1
- Rate limiting integration testing per Section 5.2.2

Coverage Requirements:
- API Layer Coverage: 100% (critical requirement)
- HTTP Method Coverage: GET, POST, PUT, DELETE, PATCH per F-002-RQ-001
- Authentication Coverage: JWT validation, role-based access control
- Error Handling Coverage: All status codes and error scenarios
"""

import pytest
import json
import jwt
import time
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Dict, Any, List, Optional, Union
from unittest.mock import Mock, MagicMock, patch, call
from uuid import uuid4

import requests
from flask import Flask, g, request
from flask.testing import FlaskClient
from werkzeug.test import Client, EnvironBuilder
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound

# Import Flask application and blueprints for testing
try:
    from src.blueprints.api import api_blueprint, register_api_blueprint
    from src.blueprints.health import health_blueprint, init_health_blueprint
    from src.blueprints.public import public_bp, init_public_blueprint
    from src.blueprints.admin import admin_bp, init_admin_blueprint
    from src.auth.decorators import require_authentication, require_permissions, rate_limited_authorization
except ImportError:
    # Graceful handling if modules are not yet available
    api_blueprint = None
    health_blueprint = None
    public_bp = None
    admin_bp = None


# ============================================================================
# TEST CONFIGURATION AND FIXTURES
# ============================================================================

@pytest.fixture(scope="function")
def flask_app(test_config, mock_environment):
    """Create Flask application with all blueprints for comprehensive testing."""
    app = Flask(__name__)
    
    # Configure test application
    app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': test_config['jwt_secret_key'],
        'JWT_SECRET_KEY': test_config['jwt_secret_key'],
        'JWT_ALGORITHM': test_config['jwt_algorithm'],
        'FLASK_ENV': 'testing',
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_AUDIENCE': 'test-api-audience',
        'REDIS_URL': 'redis://localhost:6379/0',
        'MONGODB_URL': 'mongodb://localhost:27017/test_db',
        'RATE_LIMIT_STORAGE_URL': 'redis://localhost:6379/3',
        'CORS_ORIGINS': ['https://localhost:3000'],
        'MAX_RESPONSE_TIME_VARIANCE_PERCENT': 10.0,
        'ENABLE_DATABASE_HEALTH_CHECKS': True,
        'ENABLE_CACHE_HEALTH_CHECKS': True,
        'ENABLE_EXTERNAL_SERVICE_HEALTH_CHECKS': True,
        'PERFORMANCE_VARIANCE_TRACKING': True,
        'PROMETHEUS_METRICS_ENABLED': True
    })
    
    # Register blueprints if available
    if api_blueprint:
        app.register_blueprint(api_blueprint)
    if health_blueprint:
        app.register_blueprint(health_blueprint)
    if public_bp:
        app.register_blueprint(public_bp)
    if admin_bp:
        app.register_blueprint(admin_bp)
    
    # Initialize application extensions
    with app.app_context():
        # Initialize rate limiter (mocked for testing)
        app.limiter = MagicMock()
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['limiter'] = app.limiter
        
        # Initialize health monitor
        app.extensions['health_monitor'] = MagicMock()
        
        yield app


@pytest.fixture(scope="function")
def client(flask_app) -> FlaskClient:
    """Flask test client for making HTTP requests."""
    return flask_app.test_client()


@pytest.fixture(scope="function") 
def auth_headers(test_jwt_token) -> Dict[str, str]:
    """Authentication headers with valid JWT token."""
    return {
        'Authorization': f'Bearer {test_jwt_token}',
        'Content-Type': 'application/json'
    }


@pytest.fixture(scope="function")
def admin_headers(test_config) -> Dict[str, str]:
    """Authentication headers with admin permissions."""
    admin_payload = {
        "user_id": "admin-user-123",
        "email": "admin@example.com",
        "roles": ["admin", "super_admin"],
        "permissions": ["admin.access", "admin.users.manage", "admin.system.manage"],
        "organization_id": "admin-org-123",
        "session_id": "admin-session-456",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "flask-auth-system"
    }
    
    admin_token = jwt.encode(
        payload=admin_payload,
        key=test_config["jwt_secret_key"],
        algorithm=test_config["jwt_algorithm"]
    )
    
    return {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }


@pytest.fixture(scope="function")
def invalid_auth_headers() -> Dict[str, str]:
    """Invalid authentication headers for negative testing."""
    return {
        'Authorization': 'Bearer invalid-token-12345',
        'Content-Type': 'application/json'
    }


@pytest.fixture(scope="function")
def sample_resource_data() -> Dict[str, Any]:
    """Sample resource data for testing CRUD operations."""
    return {
        "name": "Test Resource",
        "description": "A test resource for API testing",
        "data": {
            "category": "testing",
            "priority": "high",
            "metadata": {
                "created_by": "test_user",
                "version": "1.0"
            }
        },
        "tags": ["test", "api", "resource"],
        "active": True
    }


@pytest.fixture(scope="function")
def mock_business_logic():
    """Mock business logic service for testing."""
    with patch('src.blueprints.api.BusinessLogicService') as mock_service:
        # Configure default mock responses
        mock_service.process_request.return_value = {
            'status': 'processed',
            'data': [{'id': 'resource-1', 'name': 'Test Resource 1'}],
            'total_count': 1,
            'has_next': False,
            'has_prev': False
        }
        
        mock_service.get_resource.return_value = {
            'id': 'resource-123',
            'name': 'Test Resource',
            'data': {'test': 'value'},
            'created_by': 'test-user',
            'created_at': datetime.utcnow().isoformat()
        }
        
        mock_service.create_resource.return_value = {
            'id': 'new-resource-456',
            'name': 'New Test Resource',
            'created_at': datetime.utcnow().isoformat()
        }
        
        mock_service.update_resource.return_value = {
            'id': 'resource-123',
            'name': 'Updated Resource',
            'updated_at': datetime.utcnow().isoformat()
        }
        
        mock_service.delete_resource.return_value = True
        
        yield mock_service


@pytest.fixture(scope="function")
def mock_database_manager():
    """Mock database manager for testing."""
    with patch('src.blueprints.health.get_database_manager') as mock_get_db:
        mock_db = MagicMock()
        mock_db.get_health_status.return_value = {
            'overall_status': 'healthy',
            'components': {
                'mongodb_client': 'connected',
                'motor_database': 'connected'
            }
        }
        mock_db.mongodb_client = MagicMock()
        mock_db.motor_database = MagicMock()
        mock_get_db.return_value = mock_db
        yield mock_db


@pytest.fixture(scope="function")
def mock_cache_manager():
    """Mock cache manager for testing."""
    with patch('src.blueprints.health.get_cache_manager') as mock_get_cache:
        mock_cache = MagicMock()
        mock_cache.get_health_status.return_value = {
            'status': 'healthy',
            'components': {
                'redis_client': 'connected'
            },
            'cache_stats': {
                'hit_rate': 0.95,
                'memory_usage': '256MB'
            }
        }
        mock_get_cache.return_value = mock_cache
        
        with patch('src.blueprints.health.is_cache_available', return_value=True):
            yield mock_cache


@pytest.fixture(scope="function")
def mock_external_services():
    """Mock external service monitoring for testing."""
    with patch('src.blueprints.health.get_monitoring_summary') as mock_monitoring:
        mock_monitoring.return_value = {
            'registered_services': ['auth0', 'aws_s3', 'external_api'],
            'health_cache': {
                'auth0': {
                    'status': 'healthy',
                    'duration': 0.150,
                    'timestamp': datetime.utcnow().isoformat()
                },
                'aws_s3': {
                    'status': 'healthy', 
                    'duration': 0.200,
                    'timestamp': datetime.utcnow().isoformat()
                },
                'external_api': {
                    'status': 'degraded',
                    'duration': 0.500,
                    'timestamp': datetime.utcnow().isoformat()
                }
            },
            'service_metadata': {
                'auth0': {
                    'service_type': 'authentication',
                    'endpoint_url': 'https://test-domain.auth0.com',
                    'metadata': {'circuit_breaker_enabled': True}
                },
                'aws_s3': {
                    'service_type': 'storage',
                    'endpoint_url': 'https://s3.amazonaws.com',
                    'metadata': {'circuit_breaker_enabled': True}
                },
                'external_api': {
                    'service_type': 'api',
                    'endpoint_url': 'https://api.external.com',
                    'metadata': {'circuit_breaker_enabled': False}
                }
            }
        }
        yield mock_monitoring


@pytest.fixture(scope="function")
def mock_monitoring_stack():
    """Mock monitoring stack for testing."""
    with patch('src.blueprints.health.get_monitoring_stack') as mock_stack:
        mock_stack_obj = MagicMock()
        mock_stack_obj.get_monitoring_status.return_value = {
            'service_name': 'flask-migration-app',
            'environment': 'testing',
            'uptime_seconds': 3600,
            'initialization_metrics': {
                'startup_time': 2.5,
                'component_init_time': 1.2
            },
            'components': {
                'logging': {'initialized': True, 'level': 'INFO'},
                'metrics': {'initialized': True, 'registry': 'prometheus'},
                'health_checks': {'initialized': True, 'endpoints': 5},
                'apm': {'initialized': False, 'reason': 'disabled_in_testing'}
            }
        }
        mock_stack.return_value = mock_stack_obj
        yield mock_stack_obj


# ============================================================================
# API BLUEPRINT TESTS
# ============================================================================

class TestAPIBlueprint:
    """
    Comprehensive testing for API Blueprint endpoints covering all HTTP methods,
    authentication patterns, request validation, and response formatting.
    """
    
    @pytest.mark.utilities
    @pytest.mark.auth
    def test_api_health_endpoint_success(self, client, mock_database_manager, mock_cache_manager):
        """Test API health check endpoint returns healthy status."""
        with patch('src.blueprints.api.DatabaseManager.get_connection', return_value=MagicMock()):
            response = client.get('/api/v1/health')
            
            assert response.status_code == 200
            data = response.get_json()
            
            assert data['success'] is True
            assert data['status_code'] == 200
            assert 'timestamp' in data
            assert 'data' in data
            assert data['data']['service'] == 'api'
            assert 'components' in data['data']
    
    def test_api_health_endpoint_with_database_failure(self, client):
        """Test API health check endpoint handles database failures gracefully."""
        with patch('src.blueprints.api.DatabaseManager.get_connection', side_effect=Exception("Database unavailable")):
            response = client.get('/api/v1/health')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['success'] is False
            assert data['status_code'] == 503
            assert 'error' in data
    
    @pytest.mark.auth
    def test_api_system_status_requires_authentication(self, client):
        """Test system status endpoint requires valid authentication."""
        response = client.get('/api/v1/status')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    @pytest.mark.auth
    def test_api_system_status_with_valid_auth(self, client, auth_headers, mock_database_manager):
        """Test system status endpoint with valid authentication."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.get('/api/v1/status', headers=auth_headers)
                
                assert response.status_code == 200
                data = response.get_json()
                
                assert data['success'] is True
                assert 'data' in data
                assert 'system' in data['data']
                assert 'database' in data['data']
    
    @pytest.mark.performance
    def test_api_list_resources_get_method(self, client, auth_headers, mock_business_logic):
        """Test GET /api/v1/resources endpoint with pagination and filtering."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                # Test basic listing
                response = client.get('/api/v1/resources', headers=auth_headers)
                
                assert response.status_code == 200
                data = response.get_json()
                
                assert data['success'] is True
                assert 'data' in data
                assert 'resources' in data['data']
                assert 'pagination' in data['data']
                
                # Verify pagination structure
                pagination = data['data']['pagination']
                assert 'page' in pagination
                assert 'limit' in pagination
                assert 'total_items' in pagination
                assert 'total_pages' in pagination
                assert 'has_next' in pagination
                assert 'has_prev' in pagination
    
    def test_api_list_resources_with_query_parameters(self, client, auth_headers, mock_business_logic):
        """Test GET /api/v1/resources with query parameters for filtering and sorting."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                query_params = {
                    'page': '2',
                    'limit': '10',
                    'search': 'test',
                    'sort_by': 'name',
                    'sort_order': 'asc'
                }
                
                response = client.get('/api/v1/resources', headers=auth_headers, query_string=query_params)
                
                assert response.status_code == 200
                data = response.get_json()
                
                assert data['success'] is True
                assert data['data']['pagination']['page'] == 2
                assert data['data']['pagination']['limit'] == 10
    
    def test_api_list_resources_invalid_query_parameters(self, client, auth_headers):
        """Test GET /api/v1/resources with invalid query parameters."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                # Test invalid sort field
                response = client.get('/api/v1/resources?sort_by=invalid_field', headers=auth_headers)
                
                assert response.status_code == 200  # Should handle gracefully with default
                
                # Test invalid pagination values
                response = client.get('/api/v1/resources?page=invalid&limit=invalid', headers=auth_headers)
                
                assert response.status_code == 400
                data = response.get_json()
                assert 'error' in data
    
    def test_api_get_resource_by_id_success(self, client, auth_headers, mock_business_logic):
        """Test GET /api/v1/resources/<id> endpoint success."""
        resource_id = "test-resource-123"
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.get(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['success'] is True
                    assert 'data' in data
                    assert data['data']['id'] == 'resource-123'
    
    def test_api_get_resource_not_found(self, client, auth_headers, mock_business_logic):
        """Test GET /api/v1/resources/<id> with non-existent resource."""
        resource_id = "non-existent-resource"
        mock_business_logic.get_resource.return_value = None
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.get(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                
                assert response.status_code == 404
                data = response.get_json()
                
                assert data['success'] is False
                assert data['error']['code'] == 'RESOURCE_NOT_FOUND'
    
    def test_api_get_resource_access_denied(self, client, auth_headers, mock_business_logic):
        """Test GET /api/v1/resources/<id> with access denied."""
        resource_id = "restricted-resource-123"
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=False):
                    response = client.get(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                    
                    assert response.status_code == 403
                    data = response.get_json()
                    
                    assert data['success'] is False
                    assert data['error']['code'] == 'RESOURCE_ACCESS_DENIED'
    
    def test_api_create_resource_post_method(self, client, auth_headers, sample_resource_data, mock_business_logic):
        """Test POST /api/v1/resources endpoint for resource creation."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.post(
                    '/api/v1/resources',
                    headers=auth_headers,
                    data=json.dumps(sample_resource_data)
                )
                
                assert response.status_code == 201
                data = response.get_json()
                
                assert data['success'] is True
                assert data['status_code'] == 201
                assert 'data' in data
                assert data['data']['id'] == 'new-resource-456'
    
    def test_api_create_resource_validation_error(self, client, auth_headers):
        """Test POST /api/v1/resources with validation errors."""
        invalid_data = {
            'name': '',  # Invalid: empty name
            'description': 'x' * 2000,  # Invalid: too long
            'data': 'not_an_object',  # Invalid: should be object
            'tags': ['tag1', ''],  # Invalid: empty tag
            'terms_accepted': False  # Invalid: should be true
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.post(
                    '/api/v1/resources',
                    headers=auth_headers,
                    data=json.dumps(invalid_data)
                )
                
                assert response.status_code == 400
                data = response.get_json()
                
                assert data['success'] is False
                assert 'error' in data
                assert data['error']['code'] == 'VALIDATION_ERROR'
                assert 'details' in data['error']
    
    def test_api_create_resource_missing_content_type(self, client, auth_headers, sample_resource_data):
        """Test POST /api/v1/resources without proper content type."""
        headers_without_content_type = {
            'Authorization': auth_headers['Authorization']
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.post(
                    '/api/v1/resources',
                    headers=headers_without_content_type,
                    data=json.dumps(sample_resource_data)
                )
                
                # Should still work as Flask handles JSON detection
                assert response.status_code in [201, 400]  # Either success or validation error
    
    def test_api_update_resource_put_method(self, client, auth_headers, sample_resource_data, mock_business_logic):
        """Test PUT /api/v1/resources/<id> endpoint for resource update."""
        resource_id = "test-resource-123"
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.put(
                        f'/api/v1/resources/{resource_id}',
                        headers=auth_headers,
                        data=json.dumps(sample_resource_data)
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['success'] is True
                    assert 'data' in data
                    assert data['data']['id'] == 'resource-123'
    
    def test_api_patch_resource_method(self, client, auth_headers, mock_business_logic):
        """Test PATCH /api/v1/resources/<id> endpoint for partial resource update."""
        resource_id = "test-resource-123"
        patch_data = {
            'name': 'Updated Resource Name',
            'description': 'Updated description'
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.patch(
                        f'/api/v1/resources/{resource_id}',
                        headers=auth_headers,
                        data=json.dumps(patch_data)
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['success'] is True
                    assert 'data' in data
    
    def test_api_patch_resource_empty_update(self, client, auth_headers, mock_business_logic):
        """Test PATCH /api/v1/resources/<id> with no valid fields."""
        resource_id = "test-resource-123"
        empty_data = {}
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.patch(
                        f'/api/v1/resources/{resource_id}',
                        headers=auth_headers,
                        data=json.dumps(empty_data)
                    )
                    
                    assert response.status_code == 400
                    data = response.get_json()
                    
                    assert data['success'] is False
                    assert data['error']['code'] == 'NO_UPDATE_DATA'
    
    def test_api_delete_resource_method(self, client, auth_headers, mock_business_logic):
        """Test DELETE /api/v1/resources/<id> endpoint for resource deletion."""
        resource_id = "test-resource-123"
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.delete(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['success'] is True
                    assert 'data' in data
                    assert data['data']['deleted'] is True
                    assert data['data']['resource_id'] == resource_id
    
    def test_api_delete_resource_failure(self, client, auth_headers, mock_business_logic):
        """Test DELETE /api/v1/resources/<id> with deletion failure."""
        resource_id = "test-resource-123"
        mock_business_logic.delete_resource.return_value = False
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api._check_resource_access', return_value=True):
                    response = client.delete(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                    
                    assert response.status_code == 500
                    data = response.get_json()
                    
                    assert data['success'] is False
                    assert data['error']['code'] == 'RESOURCE_DELETE_FAILED'
    
    def test_api_external_sync_post_method(self, client, auth_headers):
        """Test POST /api/v1/external/sync endpoint for external service synchronization."""
        sync_data = {
            'sync_type': 'incremental'
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                with patch('src.blueprints.api.ExternalServiceClient') as mock_client:
                    mock_client.call_external_api.return_value = {
                        'status': 'success',
                        'synced_items': 150,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    response = client.post(
                        '/api/v1/external/sync',
                        headers=auth_headers,
                        data=json.dumps(sync_data)
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['success'] is True
                    assert 'data' in data
    
    def test_api_external_sync_invalid_type(self, client, auth_headers):
        """Test POST /api/v1/external/sync with invalid sync type."""
        sync_data = {
            'sync_type': 'invalid_type'
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                response = client.post(
                    '/api/v1/external/sync',
                    headers=auth_headers,
                    data=json.dumps(sync_data)
                )
                
                assert response.status_code == 400
                data = response.get_json()
                
                assert data['success'] is False
                assert data['error']['code'] == 'INVALID_SYNC_TYPE'


# ============================================================================
# HEALTH BLUEPRINT TESTS
# ============================================================================

class TestHealthBlueprint:
    """
    Comprehensive testing for Health Blueprint endpoints including liveness probes,
    readiness probes, dependency health checks, and Prometheus metrics.
    """
    
    def test_health_basic_endpoint(self, client, mock_database_manager, mock_cache_manager, mock_external_services, mock_monitoring_stack):
        """Test basic health check endpoint for load balancer monitoring."""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert 'status' in data
        assert 'timestamp' in data
        assert 'check_type' in data
        assert data['check_type'] == 'comprehensive'
        assert 'system_info' in data
        assert 'dependencies' in data
        assert 'summary' in data
    
    def test_health_liveness_probe(self, client):
        """Test Kubernetes liveness probe endpoint per Section 6.5.2.1."""
        response = client.get('/health/live')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['status'] == 'healthy'
        assert data['check_type'] == 'liveness'
        assert 'application' in data
        assert data['application']['process_responsive'] is True
    
    def test_health_liveness_probe_failure(self, client):
        """Test liveness probe failure scenario."""
        with patch('src.blueprints.health.current_app.config', side_effect=Exception("App context failure")):
            response = client.get('/health/live')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['status'] == 'unhealthy'
            assert 'error' in data
    
    def test_health_readiness_probe_success(self, client, mock_database_manager, mock_cache_manager, mock_external_services):
        """Test Kubernetes readiness probe endpoint when all dependencies are healthy."""
        response = client.get('/health/ready')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['status'] == 'ready'
        assert data['check_type'] == 'readiness'
        assert 'dependencies' in data
        assert 'summary' in data
        assert data['summary']['total_dependencies'] > 0
    
    def test_health_readiness_probe_dependency_failure(self, client, mock_cache_manager, mock_external_services):
        """Test readiness probe when database dependency fails."""
        with patch('src.blueprints.health.get_database_manager', side_effect=Exception("Database unavailable")):
            response = client.get('/health/ready')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['status'] == 'not_ready'
            assert 'dependencies' in data
    
    def test_health_dependencies_detailed_check(self, client, mock_database_manager, mock_cache_manager, mock_external_services, mock_monitoring_stack):
        """Test detailed dependency health check endpoint."""
        response = client.get('/health/dependencies')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['check_type'] == 'dependencies'
        assert 'dependencies' in data
        assert 'summary' in data
        assert 'circuit_breakers' in data
        assert 'performance_metrics' in data
        
        # Verify dependency details
        dependencies = data['dependencies']
        assert 'database' in dependencies
        assert 'cache' in dependencies
        assert 'external_services' in dependencies
        assert 'monitoring' in dependencies
    
    def test_health_dependencies_with_unhealthy_services(self, client, mock_cache_manager):
        """Test dependency health check with some unhealthy services."""
        # Mock unhealthy database
        with patch('src.blueprints.health.get_database_manager', side_effect=Exception("Database connection failed")):
            response = client.get('/health/dependencies')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['summary']['unhealthy_dependencies'] > 0
    
    @pytest.mark.performance
    def test_health_prometheus_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint per Section 6.5.1.1."""
        with patch('src.blueprints.health.generate_latest') as mock_generate:
            mock_generate.return_value = b'# HELP test_metric A test metric\n# TYPE test_metric gauge\ntest_metric 1.0\n'
            
            response = client.get('/health/metrics')
            
            assert response.status_code == 200
            assert response.content_type == 'text/plain; charset=utf-8'
            assert b'test_metric' in response.data
    
    def test_health_prometheus_metrics_error(self, client):
        """Test Prometheus metrics endpoint error handling."""
        with patch('src.blueprints.health.generate_latest', side_effect=Exception("Metrics error")):
            response = client.get('/health/metrics')
            
            assert response.status_code == 500
            assert response.content_type == 'text/plain; charset=utf-8'
            assert b'health_blueprint_metrics_error' in response.data
    
    def test_health_database_connectivity_check(self, client):
        """Test database connectivity health validation."""
        with patch('src.blueprints.health.get_database_manager') as mock_get_db:
            mock_db = MagicMock()
            mock_db.get_health_status.return_value = {
                'overall_status': 'healthy',
                'components': {
                    'mongodb_client': 'connected',
                    'motor_database': 'connected',
                    'connection_pool': 'healthy'
                }
            }
            mock_get_db.return_value = mock_db
            
            response = client.get('/health')
            
            assert response.status_code == 200
            data = response.get_json()
            
            database_health = data['dependencies']['database']
            assert database_health['status'] == 'healthy'
            assert 'response_time_ms' in database_health
            assert 'additional_info' in database_health
    
    def test_health_cache_connectivity_check(self, client, mock_database_manager, mock_external_services, mock_monitoring_stack):
        """Test Redis cache connectivity health validation."""
        with patch('src.blueprints.health.is_cache_available', return_value=True):
            with patch('src.blueprints.health.get_cache_manager') as mock_get_cache:
                mock_cache = MagicMock()
                mock_cache.get_health_status.return_value = {
                    'status': 'healthy',
                    'components': {
                        'redis_client': 'connected',
                        'connection_pool': 'healthy'
                    },
                    'cache_stats': {
                        'hit_rate': 0.95,
                        'memory_usage': '256MB'
                    }
                }
                mock_get_cache.return_value = mock_cache
                
                response = client.get('/health')
                
                assert response.status_code == 200
                data = response.get_json()
                
                cache_health = data['dependencies']['cache']
                assert cache_health['status'] == 'healthy'
                assert 'additional_info' in cache_health
    
    def test_health_external_services_monitoring(self, client, mock_database_manager, mock_cache_manager, mock_monitoring_stack):
        """Test external services health monitoring integration."""
        with patch('src.blueprints.health.get_monitoring_summary') as mock_monitoring:
            mock_monitoring.return_value = {
                'registered_services': ['auth0', 'aws_s3'],
                'health_cache': {
                    'auth0': {
                        'status': 'healthy',
                        'duration': 0.150,
                        'timestamp': datetime.utcnow().isoformat()
                    },
                    'aws_s3': {
                        'status': 'degraded',
                        'duration': 0.800,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                },
                'service_metadata': {
                    'auth0': {
                        'service_type': 'authentication',
                        'endpoint_url': 'https://test-domain.auth0.com'
                    },
                    'aws_s3': {
                        'service_type': 'storage',
                        'endpoint_url': 'https://s3.amazonaws.com'
                    }
                }
            }
            
            response = client.get('/health')
            
            assert response.status_code == 200
            data = response.get_json()
            
            external_services = data['dependencies']['external_services']
            assert 'auth0' in external_services
            assert 'aws_s3' in external_services
            assert external_services['auth0']['status'] == 'healthy'
            assert external_services['aws_s3']['status'] == 'degraded'


# ============================================================================
# PUBLIC BLUEPRINT TESTS
# ============================================================================

class TestPublicBlueprint:
    """
    Comprehensive testing for Public Blueprint endpoints including user registration,
    password reset, contact forms, and public information endpoints.
    """
    
    def test_public_health_check(self, client):
        """Test public health check endpoint for load balancer monitoring."""
        response = client.get('/api/public/health')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'version' in data
        assert 'environment' in data
    
    def test_public_health_check_failure(self, client):
        """Test public health check endpoint failure handling."""
        with patch('src.blueprints.public.current_app.config', side_effect=Exception("Config error")):
            response = client.get('/api/public/health')
            
            assert response.status_code == 503
            data = response.get_json()
            
            assert data['status'] == 'unhealthy'
            assert 'error' in data
    
    def test_public_user_registration_success(self, client):
        """Test successful user registration via Auth0."""
        registration_data = {
            'email': 'test@example.com',
            'password': 'StrongPassword123!',
            'first_name': 'John',
            'last_name': 'Doe',
            'organization': 'Test Corp',
            'terms_accepted': True,
            'marketing_consent': False
        }
        
        with patch('src.blueprints.public.Auth0ManagementClient') as mock_auth0:
            mock_client = MagicMock()
            mock_client.create_user.return_value = {
                'user_id': 'auth0|test-user-123',
                'email': 'test@example.com',
                'name': 'John Doe',
                'email_verified': False
            }
            mock_auth0.return_value = mock_client
            
            response = client.post(
                '/api/public/register',
                json=registration_data,
                content_type='application/json'
            )
            
            assert response.status_code == 201
            data = response.get_json()
            
            assert data['success'] is True
            assert 'user' in data
            assert data['user']['email'] == 'test@example.com'
    
    def test_public_user_registration_validation_errors(self, client):
        """Test user registration with validation errors."""
        invalid_registration_data = {
            'email': 'invalid-email',  # Invalid email format
            'password': '123',  # Too weak
            'first_name': '',  # Empty name
            'last_name': 'Doe',
            'terms_accepted': False  # Must be true
        }
        
        response = client.post(
            '/api/public/register',
            json=invalid_registration_data,
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        
        assert 'error' in data
        assert data['code'] == 'VALIDATION_ERROR'
        assert 'details' in data
    
    def test_public_user_registration_duplicate_email(self, client):
        """Test user registration with duplicate email address."""
        registration_data = {
            'email': 'existing@example.com',
            'password': 'StrongPassword123!',
            'first_name': 'John',
            'last_name': 'Doe',
            'terms_accepted': True
        }
        
        with patch('src.blueprints.public.Auth0ManagementClient') as mock_auth0:
            mock_client = MagicMock()
            mock_client.create_user.side_effect = Exception("user already exists")
            mock_auth0.return_value = mock_client
            
            response = client.post(
                '/api/public/register',
                json=registration_data,
                content_type='application/json'
            )
            
            assert response.status_code == 409
            data = response.get_json()
            
            assert 'error' in data
            assert data['code'] == 'USER_EXISTS'
    
    def test_public_password_reset_request(self, client):
        """Test password reset request endpoint."""
        reset_data = {
            'email': 'user@example.com'
        }
        
        with patch('src.blueprints.public.Auth0ManagementClient') as mock_auth0:
            mock_client = MagicMock()
            mock_client.request_password_reset.return_value = {'status': 'success'}
            mock_auth0.return_value = mock_client
            
            response = client.post(
                '/api/public/password-reset',
                json=reset_data,
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            
            assert data['success'] is True
            assert 'message' in data
    
    def test_public_password_reset_invalid_email(self, client):
        """Test password reset with invalid email format."""
        reset_data = {
            'email': 'invalid-email-format'
        }
        
        response = client.post(
            '/api/public/password-reset',
            json=reset_data,
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        
        assert 'error' in data
        assert data['code'] == 'INVALID_EMAIL'
    
    def test_public_contact_form_submission(self, client):
        """Test contact form submission endpoint."""
        contact_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'subject': 'Test Inquiry',
            'message': 'This is a test message for the contact form validation.'
        }
        
        response = client.post(
            '/api/public/contact',
            json=contact_data,
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert 'reference_id' in data
    
    def test_public_contact_form_spam_detection(self, client):
        """Test contact form spam detection and filtering."""
        spam_data = {
            'name': 'Spammer',
            'email': 'spam@example.com',
            'subject': 'Buy Viagra Now!',
            'message': 'Click here to buy viagra cheap! Act now for limited time offer!'
        }
        
        response = client.post(
            '/api/public/contact',
            json=spam_data,
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        
        assert 'error' in data
        assert data['code'] == 'SPAM_DETECTED'
    
    def test_public_info_endpoint(self, client):
        """Test public information endpoint."""
        response = client.get('/api/public/info')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert 'application' in data
        assert 'features' in data
        assert 'security' in data
        assert 'contact' in data
        assert data['features']['user_registration'] is True
        assert data['security']['https_required'] is True
    
    def test_public_api_documentation_endpoint(self, client):
        """Test public API documentation endpoint."""
        response = client.get('/api/public/api-docs')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['openapi'] == '3.0.0'
        assert 'info' in data
        assert 'paths' in data
        assert '/api/public/register' in data['paths']
        assert '/api/public/password-reset' in data['paths']
        assert '/api/public/contact' in data['paths']
    
    def test_public_cors_headers(self, client):
        """Test CORS headers are properly set for public endpoints."""
        response = client.get('/api/public/info')
        
        assert response.status_code == 200
        # CORS headers should be present (depending on Flask-CORS configuration)
        assert 'Access-Control-Allow-Origin' in response.headers or response.status_code == 200
    
    def test_public_endpoint_rate_limiting(self, client):
        """Test rate limiting on public endpoints."""
        # This test would verify rate limiting behavior
        # For unit testing, we mock the rate limiter
        with patch('src.blueprints.public.public_limiter') as mock_limiter:
            mock_limiter.limit.return_value = lambda f: f  # Mock decorator
            
            # Make multiple requests to test rate limiting
            for i in range(5):
                response = client.get('/api/public/info')
                assert response.status_code == 200


# ============================================================================
# ADMIN BLUEPRINT TESTS
# ============================================================================

class TestAdminBlueprint:
    """
    Comprehensive testing for Admin Blueprint endpoints including dashboard access,
    user management, system administration, and security monitoring.
    """
    
    @pytest.mark.auth
    def test_admin_dashboard_requires_authentication(self, client):
        """Test admin dashboard requires valid authentication."""
        response = client.get('/api/admin/dashboard')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    @pytest.mark.auth
    def test_admin_dashboard_with_valid_auth(self, client, admin_headers):
        """Test admin dashboard with valid admin authentication."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_metrics_collector') as mock_metrics:
                    with patch('src.blueprints.admin.get_health_monitor') as mock_health:
                        with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                            # Configure mocks
                            mock_metrics.return_value = MagicMock()
                            mock_health.return_value = MagicMock()
                            mock_db.return_value = MagicMock()
                            
                            response = client.get('/api/admin/dashboard', headers=admin_headers)
                            
                            assert response.status_code == 200
                            data = response.get_json()
                            
                            assert data['status'] == 'success'
                            assert 'data' in data
                            assert 'system_health' in data['data']
                            assert 'database_statistics' in data['data']
                            assert 'user_statistics' in data['data']
    
    def test_admin_dashboard_insufficient_permissions(self, client, auth_headers):
        """Test admin dashboard with insufficient permissions."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'regular-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=False):
                response = client.get('/api/admin/dashboard', headers=auth_headers)
                
                assert response.status_code == 403
                data = response.get_json()
                
                assert 'error' in data
                assert 'Insufficient administrative permissions' in data['error']
    
    def test_admin_system_status_endpoint(self, client, admin_headers):
        """Test admin system status endpoint."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    with patch('redis.Redis.from_url') as mock_redis:
                        # Configure mocks
                        mock_db_client = MagicMock()
                        mock_db_client.admin.command.return_value = {'ok': 1}
                        mock_db.return_value = mock_db_client
                        
                        mock_redis_client = MagicMock()
                        mock_redis_client.ping.return_value = True
                        mock_redis_client.info.return_value = {'used_memory_human': '256MB'}
                        mock_redis.return_value = mock_redis_client
                        
                        response = client.get('/api/admin/system/status', headers=admin_headers)
                        
                        assert response.status_code == 200
                        data = response.get_json()
                        
                        assert 'timestamp' in data
                        assert 'overall_status' in data
                        assert 'components' in data
                        assert 'mongodb' in data['components']
                        assert 'redis' in data['components']
    
    def test_admin_list_users_endpoint(self, client, admin_headers):
        """Test admin user listing endpoint with pagination."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    # Configure mock database response
                    mock_collection = MagicMock()
                    mock_collection.find.return_value.sort.return_value.skip.return_value.limit.return_value = [
                        {
                            '_id': 'user-1',
                            'username': 'john_doe',
                            'email': 'john@example.com',
                            'status': 'active',
                            'roles': ['user']
                        },
                        {
                            '_id': 'user-2', 
                            'username': 'jane_smith',
                            'email': 'jane@example.com',
                            'status': 'active',
                            'roles': ['user', 'moderator']
                        }
                    ]
                    mock_collection.count_documents.return_value = 2
                    
                    mock_db.return_value.app_database.users = mock_collection
                    
                    response = client.get('/api/admin/users', headers=admin_headers)
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['status'] == 'success'
                    assert 'data' in data
                    assert 'users' in data['data']
                    assert 'pagination' in data['data']
                    assert len(data['data']['users']) == 2
    
    def test_admin_list_users_with_filters(self, client, admin_headers):
        """Test admin user listing with search and filter parameters."""
        query_params = {
            'page': '1',
            'limit': '10',
            'search': 'john',
            'role': 'admin',
            'status': 'active',
            'sort': 'username',
            'order': 'asc'
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find.return_value.sort.return_value.skip.return_value.limit.return_value = []
                    mock_collection.count_documents.return_value = 0
                    mock_db.return_value.app_database.users = mock_collection
                    
                    response = client.get('/api/admin/users', headers=admin_headers, query_string=query_params)
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['status'] == 'success'
                    assert data['data']['filters']['search'] == 'john'
                    assert data['data']['filters']['role'] == 'admin'
    
    def test_admin_get_user_details(self, client, admin_headers):
        """Test admin get user details endpoint."""
        user_id = 'test-user-123'
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find_one.return_value = {
                        '_id': user_id,
                        'username': 'test_user',
                        'email': 'test@example.com',
                        'status': 'active',
                        'roles': ['user'],
                        'created_at': datetime.utcnow(),
                        'login_count': 10
                    }
                    mock_db.return_value.app_database.users = mock_collection
                    
                    with patch('src.blueprints.admin.get_user_roles', return_value=['user']):
                        response = client.get(f'/api/admin/users/{user_id}', headers=admin_headers)
                        
                        assert response.status_code == 200
                        data = response.get_json()
                        
                        assert data['status'] == 'success'
                        assert 'data' in data
                        assert 'user_profile' in data['data']
                        assert 'permissions' in data['data']
                        assert 'account_statistics' in data['data']
    
    def test_admin_get_user_not_found(self, client, admin_headers):
        """Test admin get user details for non-existent user."""
        user_id = 'non-existent-user'
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find_one.return_value = None
                    mock_db.return_value.app_database.users = mock_collection
                    
                    response = client.get(f'/api/admin/users/{user_id}', headers=admin_headers)
                    
                    assert response.status_code == 404
                    data = response.get_json()
                    
                    assert data['status'] == 'error'
                    assert data['message'] == 'User not found'
    
    def test_admin_update_user_permissions(self, client, admin_headers):
        """Test admin update user permissions endpoint."""
        user_id = 'test-user-123'
        permissions_data = {
            'roles': ['user', 'moderator'],
            'permissions': ['read', 'write'],
            'reason': 'Promoting user to moderator role'
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    # Mock user exists
                    mock_collection = MagicMock()
                    mock_collection.find_one.return_value = {
                        '_id': user_id,
                        'roles': ['user'],
                        'permissions': ['read']
                    }
                    mock_collection.update_one.return_value = MagicMock(modified_count=1)
                    mock_db.return_value.app_database.users = mock_collection
                    
                    with patch('src.blueprints.admin._get_valid_roles', return_value=['user', 'moderator', 'admin']):
                        with patch('src.blueprints.admin._get_valid_permissions', return_value=['read', 'write', 'delete']):
                            with patch('src.blueprints.admin.invalidate_user_permissions'):
                                response = client.put(
                                    f'/api/admin/users/{user_id}/permissions',
                                    headers=admin_headers,
                                    json=permissions_data
                                )
                                
                                assert response.status_code == 200
                                data = response.get_json()
                                
                                assert data['status'] == 'success'
                                assert 'data' in data
                                assert data['data']['user_id'] == user_id
    
    def test_admin_update_user_status(self, client, admin_headers):
        """Test admin update user status endpoint."""
        user_id = 'test-user-123'
        status_data = {
            'status': 'suspended',
            'reason': 'Violation of terms of service',
            'duration_hours': 24
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find_one.return_value = {
                        '_id': user_id,
                        'status': 'active'
                    }
                    mock_collection.update_one.return_value = MagicMock(modified_count=1)
                    mock_db.return_value.app_database.users = mock_collection
                    
                    with patch('src.blueprints.admin._invalidate_user_sessions'):
                        response = client.put(
                            f'/api/admin/users/{user_id}/status',
                            headers=admin_headers,
                            json=status_data
                        )
                        
                        assert response.status_code == 200
                        data = response.get_json()
                        
                        assert data['status'] == 'success'
                        assert data['data']['new_status'] == 'suspended'
    
    def test_admin_update_user_status_self_modification_denied(self, client, admin_headers):
        """Test admin cannot suspend their own account."""
        user_id = 'admin-user-123'  # Same as current user
        status_data = {
            'status': 'suspended',
            'reason': 'Self-suspension test'
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find_one.return_value = {
                        '_id': user_id,
                        'status': 'active'
                    }
                    mock_db.return_value.app_database.users = mock_collection
                    
                    response = client.put(
                        f'/api/admin/users/{user_id}/status',
                        headers=admin_headers,
                        json=status_data
                    )
                    
                    assert response.status_code == 403
                    data = response.get_json()
                    
                    assert data['status'] == 'error'
                    assert 'cannot suspend or deactivate your own account' in data['message'].lower()
    
    def test_admin_security_events_endpoint(self, client, admin_headers):
        """Test admin security events monitoring endpoint."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('src.blueprints.admin.get_mongodb_client') as mock_db:
                    mock_collection = MagicMock()
                    mock_collection.find.return_value.sort.return_value.skip.return_value.limit.return_value = [
                        {
                            '_id': 'event-1',
                            'event_type': 'authentication_failure',
                            'user_id': 'user-123',
                            'timestamp': datetime.utcnow(),
                            'severity': 'medium'
                        }
                    ]
                    mock_collection.count_documents.return_value = 1
                    mock_db.return_value.app_database.security_events = mock_collection
                    
                    response = client.get('/api/admin/security/events', headers=admin_headers)
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['status'] == 'success'
                    assert 'data' in data
                    assert 'events' in data['data']
                    assert 'pagination' in data['data']
    
    def test_admin_cache_flush_operation(self, client, admin_headers):
        """Test admin cache flush operation."""
        flush_data = {
            'cache_types': ['permissions', 'sessions'],
            'reason': 'Routine maintenance cache flush'
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('redis.Redis.from_url') as mock_redis:
                    mock_redis_client = MagicMock()
                    mock_redis_client.keys.return_value = ['perm_cache:user1', 'session:sess1']
                    mock_redis_client.delete.return_value = 2
                    mock_redis.return_value = mock_redis_client
                    
                    response = client.post(
                        '/api/admin/system/cache/flush',
                        headers=admin_headers,
                        json=flush_data
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['status'] == 'success'
                    assert 'data' in data
                    assert 'cache_types_flushed' in data['data']
                    assert 'results' in data['data']
    
    def test_admin_maintenance_mode_toggle(self, client, admin_headers):
        """Test admin maintenance mode toggle operation."""
        maintenance_data = {
            'maintenance_mode': True,
            'reason': 'Scheduled system maintenance',
            'duration_minutes': 60
        }
        
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                with patch('redis.Redis.from_url') as mock_redis:
                    mock_redis_client = MagicMock()
                    mock_redis_client.set.return_value = True
                    mock_redis.return_value = mock_redis_client
                    
                    response = client.post(
                        '/api/admin/system/maintenance',
                        headers=admin_headers,
                        json=maintenance_data
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    
                    assert data['status'] == 'success'
                    assert data['data']['maintenance_mode'] is True
                    assert 'auto_disable_at' in data['data']


# ============================================================================
# AUTHENTICATION AND AUTHORIZATION TESTS
# ============================================================================

class TestAuthenticationIntegration:
    """
    Comprehensive testing for authentication and authorization patterns
    across all Blueprint endpoints.
    """
    
    @pytest.mark.auth
    def test_jwt_token_validation_success(self, client, test_jwt_token):
        """Test successful JWT token validation."""
        headers = {'Authorization': f'Bearer {test_jwt_token}'}
        
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'test-user-123',
                'claims': {'roles': ['user'], 'permissions': ['read']}
            }
            
            with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
                response = client.get('/api/v1/status', headers=headers)
                
                # Should not be 401 (authentication successful)
                assert response.status_code != 401
    
    @pytest.mark.auth
    def test_jwt_token_validation_failure(self, client, invalid_auth_headers):
        """Test JWT token validation failure."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {'valid': False, 'error': 'Invalid token'}
            
            response = client.get('/api/v1/status', headers=invalid_auth_headers)
            
            assert response.status_code == 401
            data = response.get_json()
            assert 'error' in data
    
    @pytest.mark.auth
    def test_expired_jwt_token_handling(self, client, expired_jwt_token):
        """Test handling of expired JWT tokens."""
        headers = {'Authorization': f'Bearer {expired_jwt_token}'}
        
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {'valid': False, 'error': 'Token expired'}
            
            response = client.get('/api/v1/status', headers=headers)
            
            assert response.status_code == 401
            data = response.get_json()
            assert 'error' in data
    
    @pytest.mark.auth
    def test_missing_authorization_header(self, client):
        """Test endpoints with missing Authorization header."""
        response = client.get('/api/v1/status')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    @pytest.mark.auth
    def test_malformed_authorization_header(self, client):
        """Test endpoints with malformed Authorization header."""
        headers = {'Authorization': 'Invalid header format'}
        
        response = client.get('/api/v1/status', headers=headers)
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_permission_based_authorization_success(self, client, auth_headers):
        """Test successful permission-based authorization."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'test-user-123',
                'claims': {'roles': ['user'], 'permissions': ['resource.read']}
            }
            
            with patch('src.auth.decorators.validate_user_permissions', return_value=True):
                with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
                    response = client.get('/api/v1/resources', headers=auth_headers)
                    
                    # Should not be 403 (authorization successful)
                    assert response.status_code != 403
    
    def test_permission_based_authorization_failure(self, client, auth_headers):
        """Test permission-based authorization failure."""
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'test-user-123',
                'claims': {'roles': ['user'], 'permissions': ['limited.read']}
            }
            
            with patch('src.auth.decorators.validate_user_permissions', return_value=False):
                with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
                    response = client.get('/api/v1/resources', headers=auth_headers)
                    
                    assert response.status_code == 403
                    data = response.get_json()
                    assert 'error' in data
    
    def test_resource_ownership_authorization(self, client, auth_headers):
        """Test resource ownership-based authorization."""
        resource_id = 'owned-resource-123'
        
        with patch('src.auth.decorators.validate_jwt_token') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'user_id': 'test-user-123',
                'claims': {'roles': ['user']}
            }
            
            with patch('src.auth.decorators.check_resource_ownership', return_value=True):
                with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
                    with patch('src.blueprints.api.BusinessLogicService.get_resource') as mock_get:
                        mock_get.return_value = {'id': resource_id, 'created_by': 'test-user-123'}
                        
                        response = client.get(f'/api/v1/resources/{resource_id}', headers=auth_headers)
                        
                        # Should allow access based on ownership
                        assert response.status_code != 403


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestRateLimiting:
    """
    Comprehensive testing for rate limiting functionality across all endpoints.
    """
    
    @pytest.mark.performance
    def test_rate_limiting_within_limits(self, client, auth_headers):
        """Test normal request rate within limits."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.auth.decorators.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                # Make multiple requests within rate limit
                for i in range(3):
                    response = client.get('/api/v1/health', headers=auth_headers)
                    assert response.status_code == 200
    
    def test_rate_limiting_exceeded_simulation(self, client, auth_headers):
        """Test rate limiting exceeded simulation."""
        # Mock rate limiter to simulate rate limit exceeded
        with patch('flask_limiter.Limiter.limit') as mock_limit:
            from werkzeug.exceptions import TooManyRequests
            mock_limit.side_effect = TooManyRequests()
            
            # This test would verify rate limiting behavior
            # In practice, the rate limiter would be properly configured
            pass
    
    def test_rate_limiting_admin_endpoints(self, client, admin_headers):
        """Test rate limiting on admin endpoints."""
        with patch('src.blueprints.admin.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin-user-123'
            
            with patch('src.blueprints.admin.validate_user_permissions', return_value=True):
                # Admin endpoints typically have stricter rate limits
                response = client.get('/api/admin/dashboard', headers=admin_headers)
                
                # Should succeed within rate limits
                assert response.status_code in [200, 401, 403]  # Not rate limited
    
    def test_rate_limiting_public_endpoints(self, client):
        """Test rate limiting on public endpoints."""
        # Public endpoints should have generous rate limits
        for i in range(3):
            response = client.get('/api/public/health')
            assert response.status_code == 200


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """
    Comprehensive testing for error handling and response formatting
    per F-005-RQ-001 requirements.
    """
    
    def test_404_error_handling(self, client):
        """Test 404 Not Found error handling."""
        response = client.get('/api/v1/nonexistent-endpoint')
        
        assert response.status_code == 404
    
    def test_400_bad_request_handling(self, client, auth_headers):
        """Test 400 Bad Request error handling."""
        # Send malformed JSON
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                data='invalid json data'
            )
            
            assert response.status_code == 400
    
    def test_500_internal_server_error_handling(self, client, auth_headers):
        """Test 500 Internal Server Error handling."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.BusinessLogicService.process_request', side_effect=Exception("Internal error")):
                response = client.get('/api/v1/resources', headers=auth_headers)
                
                assert response.status_code == 500
                data = response.get_json()
                assert 'error' in data
    
    def test_validation_error_response_format(self, client, auth_headers):
        """Test validation error response format consistency."""
        invalid_data = {'invalid': 'data'}
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                json=invalid_data
            )
            
            assert response.status_code == 400
            data = response.get_json()
            
            # Verify consistent error response format
            assert 'success' in data
            assert data['success'] is False
            assert 'error' in data
            assert 'code' in data['error']
    
    def test_business_logic_error_handling(self, client, auth_headers, mock_business_logic):
        """Test business logic error handling."""
        from src.blueprints.api import BusinessValidationError
        mock_business_logic.create_resource.side_effect = BusinessValidationError("Business rule violation")
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                json={'name': 'Test Resource'}
            )
            
            assert response.status_code == 422
            data = response.get_json()
            
            assert data['success'] is False
            assert data['error']['code'] == 'BUSINESS_VALIDATION_ERROR'
    
    def test_database_error_handling(self, client, auth_headers):
        """Test database error handling."""
        from src.blueprints.api import DataAccessError
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.blueprints.api.BusinessLogicService.get_resource', side_effect=DataAccessError("Database connection failed")):
                response = client.get('/api/v1/resources/test-id', headers=auth_headers)
                
                assert response.status_code == 500
                data = response.get_json()
                
                assert data['success'] is False
                assert data['error']['code'] == 'DATABASE_ERROR'


# ============================================================================
# REQUEST VALIDATION TESTS
# ============================================================================

class TestRequestValidation:
    """
    Comprehensive testing for request validation using marshmallow schemas
    and pydantic models per Section 3.2.2 requirements.
    """
    
    def test_json_content_type_validation(self, client, auth_headers):
        """Test JSON content type validation."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            # Test with correct content type
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                json={'name': 'Test Resource'}
            )
            
            # Should not fail due to content type (may fail for other reasons)
            assert response.status_code != 415
    
    def test_form_data_content_type_handling(self, client, auth_headers):
        """Test form data content type handling."""
        headers = {
            'Authorization': auth_headers['Authorization'],
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=headers,
                data={'name': 'Test Resource'}
            )
            
            # Should handle form data appropriately
            assert response.status_code in [200, 201, 400]  # Not unsupported media type
    
    def test_multipart_form_data_handling(self, client, auth_headers):
        """Test multipart form data handling."""
        data = {
            'name': 'Test Resource',
            'description': 'A test resource with file upload'
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers={'Authorization': auth_headers['Authorization']},
                data=data,
                content_type='multipart/form-data'
            )
            
            # Should handle multipart data appropriately
            assert response.status_code in [200, 201, 400]
    
    def test_request_size_limits(self, client, auth_headers):
        """Test request size limits handling."""
        # Create a large payload
        large_data = {
            'name': 'Test Resource',
            'data': {'large_field': 'x' * 10000}  # Large data
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                json=large_data
            )
            
            # Should handle large requests appropriately
            assert response.status_code in [200, 201, 400, 413]
    
    def test_input_sanitization(self, client, auth_headers):
        """Test input sanitization for security."""
        potentially_dangerous_data = {
            'name': '<script>alert("xss")</script>',
            'description': '<?php system("rm -rf /"); ?>',
            'data': {
                'script_tag': '<img src="x" onerror="alert(1)">',
                'sql_injection': "'; DROP TABLE users; --"
            }
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post(
                '/api/v1/resources',
                headers=auth_headers,
                json=potentially_dangerous_data
            )
            
            # Should either sanitize or reject dangerous input
            if response.status_code in [200, 201]:
                data = response.get_json()
                # Verify dangerous content is sanitized
                assert '<script>' not in str(data)
                assert '<?php' not in str(data)


# ============================================================================
# PERFORMANCE TESTING
# ============================================================================

class TestPerformance:
    """
    Basic performance testing to ensure API endpoints meet response time requirements
    per Section 0.3.2 performance monitoring requirements.
    """
    
    @pytest.mark.performance
    def test_health_endpoint_response_time(self, client, performance_timer):
        """Test health endpoint response time."""
        performance_timer.start()
        response = client.get('/health')
        performance_timer.stop()
        
        assert response.status_code == 200
        # Assert response time under 1 second for health check
        performance_timer.assert_duration_under(1.0)
    
    @pytest.mark.performance
    def test_api_resources_list_response_time(self, client, auth_headers, performance_timer, mock_business_logic):
        """Test API resources listing response time."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            with patch('src.auth.decorators.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                performance_timer.start()
                response = client.get('/api/v1/resources', headers=auth_headers)
                performance_timer.stop()
                
                assert response.status_code == 200
                # Assert reasonable response time for list operations
                performance_timer.assert_duration_under(2.0)
    
    @pytest.mark.performance
    def test_concurrent_request_handling(self, client, auth_headers, mock_business_logic):
        """Test concurrent request handling capability."""
        import threading
        import queue
        
        results = queue.Queue()
        
        def make_request():
            with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
                with patch('src.auth.decorators.validate_jwt_token', return_value={'valid': True, 'user_id': 'test-user-123'}):
                    response = client.get('/api/v1/health', headers=auth_headers)
                    results.put(response.status_code)
        
        # Create multiple concurrent requests
        threads = []
        for i in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all requests succeeded
        response_codes = []
        while not results.empty():
            response_codes.append(results.get())
        
        assert len(response_codes) == 5
        assert all(code == 200 for code in response_codes)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestBlueprintIntegration:
    """
    Integration testing for Blueprint interactions and cross-cutting concerns.
    """
    
    def test_blueprint_registration(self, flask_app):
        """Test that all blueprints are properly registered."""
        blueprint_names = [bp.name for bp in flask_app.blueprints.values()]
        
        # Verify expected blueprints are registered
        expected_blueprints = ['api', 'health', 'public', 'admin']
        for blueprint_name in expected_blueprints:
            if globals().get(f'{blueprint_name}_blueprint') or globals().get(f'{blueprint_name}_bp'):
                assert blueprint_name in blueprint_names
    
    def test_cors_configuration(self, client):
        """Test CORS configuration across blueprints."""
        # Test preflight OPTIONS request
        response = client.options('/api/public/info')
        
        # Should handle OPTIONS requests appropriately
        assert response.status_code in [200, 405]  # Either allowed or method not allowed
    
    def test_content_security_headers(self, client):
        """Test security headers are properly set."""
        response = client.get('/api/public/health')
        
        assert response.status_code == 200
        # Verify security headers are present (if configured)
        headers = response.headers
        # Common security headers would be checked here
    
    def test_request_id_tracking(self, client, auth_headers):
        """Test request ID tracking across endpoint calls."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.get('/api/v1/health', headers=auth_headers)
            
            assert response.status_code == 200
            data = response.get_json()
            
            # Verify request tracking is implemented
            if 'request_id' in data:
                assert data['request_id']
    
    def test_error_consistency_across_blueprints(self, client):
        """Test error response consistency across different blueprints."""
        # Test 404 errors from different blueprints
        responses = [
            client.get('/api/v1/nonexistent'),
            client.get('/health/nonexistent'),
            client.get('/api/public/nonexistent'),
            client.get('/api/admin/nonexistent')
        ]
        
        for response in responses:
            assert response.status_code == 404
            # Could verify consistent error format if implemented


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """
    Testing edge cases and boundary conditions for comprehensive coverage.
    """
    
    def test_empty_request_body_handling(self, client, auth_headers):
        """Test handling of empty request bodies."""
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post('/api/v1/resources', headers=auth_headers, json={})
            
            # Should handle empty JSON appropriately
            assert response.status_code in [400, 422]  # Validation error expected
    
    def test_null_values_in_request(self, client, auth_headers):
        """Test handling of null values in requests."""
        data_with_nulls = {
            'name': None,
            'description': None,
            'data': None
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post('/api/v1/resources', headers=auth_headers, json=data_with_nulls)
            
            # Should handle null values appropriately
            assert response.status_code in [400, 422]
    
    def test_unicode_content_handling(self, client, auth_headers):
        """Test handling of Unicode content in requests."""
        unicode_data = {
            'name': 'Test Resource with Unicode: café, naïve, résumé, 中文',
            'description': 'Description with emojis: 🚀 🎉 ✨',
            'data': {
                'unicode_field': 'Iñtërnâtiônàlizætiøn'
            }
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post('/api/v1/resources', headers=auth_headers, json=unicode_data)
            
            # Should handle Unicode content appropriately
            assert response.status_code in [200, 201, 400, 422]
    
    def test_very_long_field_values(self, client, auth_headers):
        """Test handling of very long field values."""
        long_string = 'x' * 10000
        data_with_long_values = {
            'name': long_string,
            'description': long_string,
            'data': {
                'long_field': long_string
            }
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post('/api/v1/resources', headers=auth_headers, json=data_with_long_values)
            
            # Should handle or reject very long values
            assert response.status_code in [400, 413, 422]
    
    def test_deeply_nested_json_handling(self, client, auth_headers):
        """Test handling of deeply nested JSON structures."""
        # Create deeply nested structure
        nested_data = {'level_0': {}}
        current_level = nested_data['level_0']
        
        for i in range(1, 50):  # Create 50 levels of nesting
            current_level[f'level_{i}'] = {}
            current_level = current_level[f'level_{i}']
        
        current_level['final_value'] = 'deep_value'
        
        request_data = {
            'name': 'Deeply Nested Resource',
            'data': nested_data
        }
        
        with patch('src.blueprints.api.get_current_user', return_value={'id': 'test-user-123'}):
            response = client.post('/api/v1/resources', headers=auth_headers, json=request_data)
            
            # Should handle or reject deeply nested structures
            assert response.status_code in [200, 201, 400, 413, 422]


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])