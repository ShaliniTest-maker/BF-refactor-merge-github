"""
External Service Integration Mock Fixtures

This module provides comprehensive mock fixtures for external service integrations including
AWS service simulation, HTTP client mocking, circuit breaker testing, and third-party API
integration patterns. Implements enterprise-grade mock patterns for testing external
dependencies without actual service calls.

Key Features:
- boto3 1.28+ AWS service mock fixtures for S3 operations testing per Section 0.1.2
- requests 2.31+ and httpx 0.24+ HTTP client mock fixtures per Section 3.2.3
- Circuit breaker mock fixtures for external service resilience testing per Section 6.3.3
- Third-party API mock fixtures maintaining API contracts per Section 0.1.4
- Retry logic mock fixtures with exponential backoff testing per Section 4.2.3
- AWS KMS mock fixtures for encryption key management testing per Section 6.4.3
- External service monitoring mock fixtures for performance testing per Section 6.3.5

Architecture Integration:
- Section 0.1.2: External Integration Components - AWS and HTTP client mocking
- Section 6.3.3: External Systems - Resilience patterns and monitoring mock fixtures
- Section 6.3.5: Performance and Scalability - Performance monitoring fixtures
- Section 4.2.3: Error Handling and Recovery - Retry logic and circuit breaker mocks
- Section 6.4.3: Security Architecture - AWS KMS encryption mock fixtures

Performance Requirements:
- Performance baseline mock fixtures ensuring ≤10% variance testing per Section 0.3.2
- External service latency simulation for realistic testing scenarios
- Connection pool mock fixtures for HTTP client performance validation
- Circuit breaker state transition mock fixtures for resilience testing

Testing Strategy:
- Comprehensive external service integration testing per Section 6.6.1
- Performance validation mock fixtures per Section 6.6.1
- Mock external dependencies for isolated unit testing
- Integration test fixtures for end-to-end external service workflows

Author: Flask Migration Team
Version: 1.0.0
Dependencies: pytest, boto3, moto, requests-mock, httpx, pytest-mock, pytest-asyncio
"""

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, AsyncGenerator, Generator
from unittest.mock import Mock, MagicMock, AsyncMock, patch, PropertyMock
from urllib.parse import urljoin, urlparse

import pytest
import pytest_asyncio
from moto import mock_s3, mock_kms, mock_cloudwatch
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import requests
import httpx
from requests.exceptions import RequestException, ConnectionError, Timeout, HTTPError
import httpx
import structlog

# Import integration components for mocking
from src.integrations.base_client import (
    BaseExternalServiceClient,
    BaseClientConfiguration,
    create_auth0_config,
    create_aws_s3_config,
    create_external_api_config
)
from src.integrations.http_client import (
    HTTPClientManager,
    SynchronousHTTPClient,
    AsynchronousHTTPClient,
    OptimizedHTTPAdapter
)
from src.integrations.circuit_breaker import (
    EnhancedCircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerPolicy,
    CircuitBreakerState
)
from src.integrations.external_apis import (
    GenericAPIClient,
    WebhookHandler,
    FileProcessingClient,
    EnterpriseServiceWrapper
)
from src.integrations.monitoring import (
    ExternalServiceMonitor,
    ServiceHealthState,
    ExternalServiceType,
    ServiceMetrics
)
from src.config.settings import TestingConfig

# Initialize structured logger for mock fixtures
logger = structlog.get_logger(__name__)

# =============================================================================
# AWS Service Mock Fixtures - boto3 1.28+ per Section 0.1.2
# =============================================================================

@pytest.fixture(scope="session")
def aws_credentials():
    """Mock AWS credentials for testing to prevent real AWS calls."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    return {
        "aws_access_key_id": "testing",
        "aws_secret_access_key": "testing",
        "region_name": "us-east-1"
    }


@pytest.fixture
def mock_s3_client(aws_credentials):
    """
    Mock AWS S3 client with comprehensive bucket and object operations.
    
    Provides realistic S3 behavior for file upload, download, deletion,
    and metadata operations supporting all S3 client methods used in
    the application per Section 0.1.2 AWS SDK migration.
    """
    with mock_s3():
        # Create mock S3 client
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        # Create test buckets for different use cases
        test_buckets = [
            'test-uploads-bucket',
            'test-documents-bucket', 
            'test-images-bucket',
            'test-backups-bucket'
        ]
        
        for bucket_name in test_buckets:
            s3_client.create_bucket(Bucket=bucket_name)
        
        # Add sample objects for testing
        sample_objects = [
            {
                'bucket': 'test-uploads-bucket',
                'key': 'sample/test-file.txt',
                'body': b'Sample file content for testing',
                'metadata': {'content-type': 'text/plain', 'uploaded-by': 'test-user'}
            },
            {
                'bucket': 'test-images-bucket',
                'key': 'images/sample-image.jpg',
                'body': b'\xff\xd8\xff\xe0\x00\x10JFIF',  # JPEG header
                'metadata': {'content-type': 'image/jpeg', 'size': '1024x768'}
            },
            {
                'bucket': 'test-documents-bucket',
                'key': 'docs/sample-document.pdf',
                'body': b'%PDF-1.4 Sample PDF content',
                'metadata': {'content-type': 'application/pdf', 'version': '1.0'}
            }
        ]
        
        for obj in sample_objects:
            s3_client.put_object(
                Bucket=obj['bucket'],
                Key=obj['key'],
                Body=obj['body'],
                Metadata=obj['metadata']
            )
        
        # Add performance tracking methods
        s3_client._performance_metrics = {
            'upload_times': [],
            'download_times': [],
            'operation_counts': {'put_object': 0, 'get_object': 0, 'delete_object': 0}
        }
        
        original_put_object = s3_client.put_object
        original_get_object = s3_client.get_object
        original_delete_object = s3_client.delete_object
        
        def tracked_put_object(*args, **kwargs):
            start_time = time.time()
            result = original_put_object(*args, **kwargs)
            s3_client._performance_metrics['upload_times'].append(time.time() - start_time)
            s3_client._performance_metrics['operation_counts']['put_object'] += 1
            return result
        
        def tracked_get_object(*args, **kwargs):
            start_time = time.time()
            result = original_get_object(*args, **kwargs)
            s3_client._performance_metrics['download_times'].append(time.time() - start_time)
            s3_client._performance_metrics['operation_counts']['get_object'] += 1
            return result
        
        def tracked_delete_object(*args, **kwargs):
            start_time = time.time()
            result = original_delete_object(*args, **kwargs)
            s3_client._performance_metrics['operation_counts']['delete_object'] += 1
            return result
        
        s3_client.put_object = tracked_put_object
        s3_client.get_object = tracked_get_object
        s3_client.delete_object = tracked_delete_object
        
        logger.info(
            "Mock S3 client initialized",
            buckets=test_buckets,
            sample_objects=len(sample_objects),
            performance_tracking=True
        )
        
        yield s3_client


@pytest.fixture 
def mock_kms_client(aws_credentials):
    """
    Mock AWS KMS client for encryption key management testing per Section 6.4.3.
    
    Provides realistic KMS behavior for key creation, encryption, decryption,
    and key rotation operations supporting enterprise security requirements.
    """
    with mock_kms():
        # Create mock KMS client
        kms_client = boto3.client('kms', region_name='us-east-1')
        
        # Create test encryption keys
        test_keys = []
        key_descriptions = [
            'Application data encryption key',
            'Database encryption key', 
            'File storage encryption key',
            'Session token encryption key'
        ]
        
        for description in key_descriptions:
            key_response = kms_client.create_key(
                Description=description,
                Usage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS'
            )
            test_keys.append(key_response['KeyMetadata']['KeyId'])
        
        # Create aliases for keys
        for i, key_id in enumerate(test_keys):
            alias_name = f'alias/test-key-{i+1}'
            kms_client.create_alias(
                AliasName=alias_name,
                TargetKeyId=key_id
            )
        
        # Add performance and usage tracking
        kms_client._performance_metrics = {
            'encrypt_times': [],
            'decrypt_times': [],
            'operation_counts': {'encrypt': 0, 'decrypt': 0, 'generate_data_key': 0}
        }
        
        original_encrypt = kms_client.encrypt
        original_decrypt = kms_client.decrypt
        original_generate_data_key = kms_client.generate_data_key
        
        def tracked_encrypt(*args, **kwargs):
            start_time = time.time()
            result = original_encrypt(*args, **kwargs)
            kms_client._performance_metrics['encrypt_times'].append(time.time() - start_time)
            kms_client._performance_metrics['operation_counts']['encrypt'] += 1
            return result
        
        def tracked_decrypt(*args, **kwargs):
            start_time = time.time()
            result = original_decrypt(*args, **kwargs)
            kms_client._performance_metrics['decrypt_times'].append(time.time() - start_time)
            kms_client._performance_metrics['operation_counts']['decrypt'] += 1
            return result
        
        def tracked_generate_data_key(*args, **kwargs):
            start_time = time.time()
            result = original_generate_data_key(*args, **kwargs)
            kms_client._performance_metrics['operation_counts']['generate_data_key'] += 1
            return result
        
        kms_client.encrypt = tracked_encrypt
        kms_client.decrypt = tracked_decrypt
        kms_client.generate_data_key = tracked_generate_data_key
        
        logger.info(
            "Mock KMS client initialized",
            test_keys=len(test_keys),
            performance_tracking=True
        )
        
        yield kms_client


@pytest.fixture
def mock_cloudwatch_client(aws_credentials):
    """
    Mock AWS CloudWatch client for metrics and monitoring testing per Section 6.3.5.
    
    Provides realistic CloudWatch behavior for custom metrics submission,
    log group management, and dashboard integration supporting monitoring
    requirements.
    """
    with mock_cloudwatch():
        # Create mock CloudWatch client
        cloudwatch_client = boto3.client('cloudwatch', region_name='us-east-1')
        
        # Create test log groups
        logs_client = boto3.client('logs', region_name='us-east-1')
        test_log_groups = [
            '/aws/lambda/flask-app-function',
            '/flask-app/application-logs',
            '/flask-app/performance-logs',
            '/flask-app/security-logs'
        ]
        
        for log_group in test_log_groups:
            try:
                logs_client.create_log_group(logGroupName=log_group)
            except logs_client.exceptions.ResourceAlreadyExistsException:
                pass
        
        # Add performance tracking for CloudWatch operations
        cloudwatch_client._performance_metrics = {
            'put_metric_times': [],
            'operation_counts': {'put_metric_data': 0, 'get_metric_statistics': 0}
        }
        
        original_put_metric_data = cloudwatch_client.put_metric_data
        original_get_metric_statistics = cloudwatch_client.get_metric_statistics
        
        def tracked_put_metric_data(*args, **kwargs):
            start_time = time.time()
            result = original_put_metric_data(*args, **kwargs)
            cloudwatch_client._performance_metrics['put_metric_times'].append(time.time() - start_time)
            cloudwatch_client._performance_metrics['operation_counts']['put_metric_data'] += 1
            return result
        
        def tracked_get_metric_statistics(*args, **kwargs):
            start_time = time.time()
            result = original_get_metric_statistics(*args, **kwargs)
            cloudwatch_client._performance_metrics['operation_counts']['get_metric_statistics'] += 1
            return result
        
        cloudwatch_client.put_metric_data = tracked_put_metric_data
        cloudwatch_client.get_metric_statistics = tracked_get_metric_statistics
        
        logger.info(
            "Mock CloudWatch client initialized", 
            log_groups=test_log_groups,
            performance_tracking=True
        )
        
        yield cloudwatch_client


# =============================================================================
# HTTP Client Mock Fixtures - requests 2.31+ and httpx 0.24+ per Section 3.2.3
# =============================================================================

@pytest.fixture
def mock_requests_session():
    """
    Mock requests session with comprehensive HTTP client behavior simulation.
    
    Provides realistic HTTP request/response patterns for external API testing
    with support for retry logic, connection pooling, and performance monitoring
    per Section 3.2.3 HTTP client integration.
    """
    session_mock = Mock(spec=requests.Session)
    
    # Configure default response behavior
    def create_response(status_code=200, json_data=None, text=None, headers=None):
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.ok = status_code < 400
        response.json.return_value = json_data or {}
        response.text = text or json.dumps(json_data or {})
        response.headers = headers or {'Content-Type': 'application/json'}
        response.elapsed = timedelta(milliseconds=150)  # Simulate realistic response time
        return response
    
    # Configure different response scenarios
    session_mock.get.return_value = create_response(200, {'status': 'success', 'data': []})
    session_mock.post.return_value = create_response(201, {'status': 'created', 'id': 'test-123'})
    session_mock.put.return_value = create_response(200, {'status': 'updated'})
    session_mock.delete.return_value = create_response(204)
    session_mock.patch.return_value = create_response(200, {'status': 'patched'})
    
    # Add performance tracking
    session_mock._performance_metrics = {
        'request_times': [],
        'request_counts': {'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0, 'PATCH': 0},
        'status_codes': {},
        'connection_pool_hits': 0
    }
    
    def track_request(method, url, **kwargs):
        start_time = time.time()
        
        # Simulate different response scenarios based on URL patterns
        if 'error' in url:
            response = create_response(500, {'error': 'Internal server error'})
        elif 'timeout' in url:
            raise Timeout("Request timeout")
        elif 'connection-error' in url:
            raise ConnectionError("Connection failed")
        elif 'not-found' in url:
            response = create_response(404, {'error': 'Not found'})
        elif 'auth' in url and kwargs.get('headers', {}).get('Authorization') is None:
            response = create_response(401, {'error': 'Unauthorized'})
        else:
            response = create_response(200, {'status': 'success', 'url': url, 'method': method})
        
        # Track performance metrics
        session_mock._performance_metrics['request_times'].append(time.time() - start_time)
        session_mock._performance_metrics['request_counts'][method.upper()] += 1
        session_mock._performance_metrics['status_codes'][response.status_code] = \
            session_mock._performance_metrics['status_codes'].get(response.status_code, 0) + 1
        session_mock._performance_metrics['connection_pool_hits'] += 1
        
        return response
    
    session_mock.request.side_effect = track_request
    
    # Configure session properties
    session_mock.adapters = {'http://': OptimizedHTTPAdapter(), 'https://': OptimizedHTTPAdapter()}
    session_mock.headers = {'User-Agent': 'Flask-App/1.0.0'}
    session_mock.timeout = 30.0
    
    logger.info("Mock requests session initialized with performance tracking")
    
    return session_mock


@pytest.fixture
def mock_httpx_client():
    """
    Mock httpx async client with comprehensive HTTP client behavior simulation.
    
    Provides realistic async HTTP request/response patterns for external API testing
    with support for connection pooling, timeout management, and performance monitoring
    per Section 3.2.3 async HTTP client integration.
    """
    client_mock = AsyncMock(spec=httpx.AsyncClient)
    
    # Configure default async response behavior
    async def create_async_response(status_code=200, json_data=None, text=None, headers=None):
        response = Mock(spec=httpx.Response)
        response.status_code = status_code
        response.is_success = status_code < 400
        response.is_error = status_code >= 400
        response.json.return_value = json_data or {}
        response.text = text or json.dumps(json_data or {})
        response.headers = headers or {'Content-Type': 'application/json'}
        response.elapsed = timedelta(milliseconds=120)  # Simulate realistic async response time
        return response
    
    # Configure different async response scenarios
    client_mock.get.return_value = await create_async_response(200, {'status': 'success', 'data': []})
    client_mock.post.return_value = await create_async_response(201, {'status': 'created', 'id': 'async-123'})
    client_mock.put.return_value = await create_async_response(200, {'status': 'updated'})
    client_mock.delete.return_value = await create_async_response(204)
    client_mock.patch.return_value = await create_async_response(200, {'status': 'patched'})
    
    # Add performance tracking for async operations
    client_mock._performance_metrics = {
        'async_request_times': [],
        'async_request_counts': {'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0, 'PATCH': 0},
        'async_status_codes': {},
        'connection_pool_usage': 0
    }
    
    async def track_async_request(method, url, **kwargs):
        start_time = time.time()
        
        # Simulate different async response scenarios
        if 'async-error' in url:
            response = await create_async_response(500, {'error': 'Async server error'})
        elif 'async-timeout' in url:
            raise httpx.TimeoutException("Async request timeout")
        elif 'async-connection' in url:
            raise httpx.ConnectError("Async connection failed")
        elif 'async-not-found' in url:
            response = await create_async_response(404, {'error': 'Async not found'})
        else:
            response = await create_async_response(200, {'status': 'async_success', 'url': url, 'method': method})
        
        # Track async performance metrics
        client_mock._performance_metrics['async_request_times'].append(time.time() - start_time)
        client_mock._performance_metrics['async_request_counts'][method.upper()] += 1
        client_mock._performance_metrics['async_status_codes'][response.status_code] = \
            client_mock._performance_metrics['async_status_codes'].get(response.status_code, 0) + 1
        client_mock._performance_metrics['connection_pool_usage'] += 1
        
        return response
    
    client_mock.request.side_effect = track_async_request
    
    # Configure async client properties
    client_mock.timeout = httpx.Timeout(30.0, connect=10.0)
    client_mock.limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
    client_mock.headers = {'User-Agent': 'Flask-App-Async/1.0.0'}
    
    logger.info("Mock httpx async client initialized with performance tracking")
    
    return client_mock


@pytest.fixture
def mock_http_client_manager(mock_requests_session, mock_httpx_client):
    """
    Mock HTTP client manager integrating both sync and async clients.
    
    Provides comprehensive HTTP client management with performance monitoring,
    connection pooling, and error handling per Section 3.2.3 HTTP client
    integration requirements.
    """
    manager_mock = Mock(spec=HTTPClientManager)
    
    # Configure client manager with mocked clients
    manager_mock.sync_client = mock_requests_session
    manager_mock.async_client = mock_httpx_client
    
    # Add manager-level performance tracking
    manager_mock._performance_metrics = {
        'total_requests': 0,
        'sync_requests': 0,
        'async_requests': 0,
        'avg_response_time': 0.0,
        'error_rate': 0.0,
        'connection_pool_efficiency': 0.95
    }
    
    def track_sync_request(*args, **kwargs):
        manager_mock._performance_metrics['total_requests'] += 1
        manager_mock._performance_metrics['sync_requests'] += 1
        return mock_requests_session.request(*args, **kwargs)
    
    async def track_async_request(*args, **kwargs):
        manager_mock._performance_metrics['total_requests'] += 1
        manager_mock._performance_metrics['async_requests'] += 1
        return await mock_httpx_client.request(*args, **kwargs)
    
    manager_mock.make_request = track_sync_request
    manager_mock.make_async_request = track_async_request
    
    # Configure health check methods
    manager_mock.check_health.return_value = {
        'sync_client_healthy': True,
        'async_client_healthy': True,
        'connection_pools_available': True,
        'total_connections': 150,
        'active_connections': 45
    }
    
    logger.info("Mock HTTP client manager initialized with dual client support")
    
    return manager_mock


# =============================================================================
# Circuit Breaker Mock Fixtures per Section 6.3.3
# =============================================================================

@pytest.fixture
def mock_circuit_breaker_config():
    """
    Mock circuit breaker configuration for different service types.
    
    Provides realistic circuit breaker configuration patterns for Auth0,
    AWS S3, external APIs, and database connections per Section 6.3.3
    resilience patterns.
    """
    return {
        'auth0': CircuitBreakerConfig(
            service_name='auth0',
            service_type=ExternalServiceType.AUTH_PROVIDER,
            fail_max=5,
            recovery_timeout=60,
            expected_exception=(RequestException, ConnectionError, Timeout),
            enable_metrics=True,
            enable_health_monitoring=True,
            fallback_enabled=True,
            fallback_response={'error': 'Authentication service temporarily unavailable'}
        ),
        'aws_s3': CircuitBreakerConfig(
            service_name='aws_s3',
            service_type=ExternalServiceType.CLOUD_STORAGE,
            fail_max=3,
            recovery_timeout=120,
            expected_exception=(ClientError, NoCredentialsError, ConnectionError),
            enable_metrics=True,
            enable_health_monitoring=True,
            fallback_enabled=True,
            fallback_response={'error': 'File storage service temporarily unavailable'}
        ),
        'external_api': CircuitBreakerConfig(
            service_name='external_api',
            service_type=ExternalServiceType.HTTP_API,
            fail_max=10,
            recovery_timeout=30,
            expected_exception=(RequestException, HTTPError, Timeout),
            enable_metrics=True,
            enable_health_monitoring=True,
            fallback_enabled=True,
            fallback_response={'error': 'External API temporarily unavailable'}
        ),
        'redis_cache': CircuitBreakerConfig(
            service_name='redis_cache',
            service_type=ExternalServiceType.CACHE,
            fail_max=15,
            recovery_timeout=15,
            expected_exception=(ConnectionError, TimeoutError),
            enable_metrics=True,
            enable_health_monitoring=True,
            fallback_enabled=True,
            fallback_response=None  # Cache failures should fallback to source
        )
    }


@pytest.fixture
def mock_circuit_breaker(mock_circuit_breaker_config):
    """
    Mock enhanced circuit breaker with comprehensive state management.
    
    Provides realistic circuit breaker behavior including state transitions,
    failure counting, half-open testing, and metrics collection per Section 6.3.3
    external service protection patterns.
    """
    circuit_breaker_mock = Mock(spec=EnhancedCircuitBreaker)
    
    # Initialize circuit breaker state
    circuit_breaker_mock._state = CircuitBreakerState.CLOSED
    circuit_breaker_mock._failure_count = 0
    circuit_breaker_mock._last_failure_time = None
    circuit_breaker_mock._half_open_calls = 0
    circuit_breaker_mock._config = mock_circuit_breaker_config['external_api']
    
    # Add comprehensive metrics tracking
    circuit_breaker_mock._metrics = {
        'total_calls': 0,
        'successful_calls': 0,
        'failed_calls': 0,
        'state_transitions': [],
        'fallback_activations': 0,
        'circuit_open_duration': 0.0,
        'recovery_attempts': 0
    }
    
    def simulate_call(func, *args, **kwargs):
        """Simulate circuit breaker protected function call."""
        circuit_breaker_mock._metrics['total_calls'] += 1
        
        # Check circuit state
        if circuit_breaker_mock._state == CircuitBreakerState.OPEN:
            # Check if recovery timeout has passed
            if (circuit_breaker_mock._last_failure_time and 
                time.time() - circuit_breaker_mock._last_failure_time > circuit_breaker_mock._config.recovery_timeout):
                circuit_breaker_mock._state = CircuitBreakerState.HALF_OPEN
                circuit_breaker_mock._metrics['state_transitions'].append({
                    'from': 'OPEN',
                    'to': 'HALF_OPEN',
                    'timestamp': time.time()
                })
            else:
                # Circuit is open, activate fallback
                circuit_breaker_mock._metrics['fallback_activations'] += 1
                if circuit_breaker_mock._config.fallback_response:
                    return circuit_breaker_mock._config.fallback_response
                raise CircuitBreakerOpenError("Circuit breaker is open")
        
        try:
            # Simulate function execution
            if 'error' in str(args) or 'error' in str(kwargs):
                raise RequestException("Simulated external service error")
            
            result = func(*args, **kwargs) if callable(func) else {'status': 'success'}
            
            # Successful call
            circuit_breaker_mock._metrics['successful_calls'] += 1
            circuit_breaker_mock._failure_count = 0
            
            # Transition from half-open to closed if needed
            if circuit_breaker_mock._state == CircuitBreakerState.HALF_OPEN:
                circuit_breaker_mock._half_open_calls += 1
                if circuit_breaker_mock._half_open_calls >= circuit_breaker_mock._config.half_open_max_calls:
                    circuit_breaker_mock._state = CircuitBreakerState.CLOSED
                    circuit_breaker_mock._half_open_calls = 0
                    circuit_breaker_mock._metrics['state_transitions'].append({
                        'from': 'HALF_OPEN',
                        'to': 'CLOSED',
                        'timestamp': time.time()
                    })
            
            return result
            
        except Exception as e:
            # Failed call
            circuit_breaker_mock._metrics['failed_calls'] += 1
            circuit_breaker_mock._failure_count += 1
            circuit_breaker_mock._last_failure_time = time.time()
            
            # Check if we should open the circuit
            if circuit_breaker_mock._failure_count >= circuit_breaker_mock._config.fail_max:
                if circuit_breaker_mock._state != CircuitBreakerState.OPEN:
                    circuit_breaker_mock._state = CircuitBreakerState.OPEN
                    circuit_breaker_mock._metrics['state_transitions'].append({
                        'from': 'CLOSED' if circuit_breaker_mock._state != CircuitBreakerState.HALF_OPEN else 'HALF_OPEN',
                        'to': 'OPEN',
                        'timestamp': time.time()
                    })
            
            # Reset half-open calls on failure
            if circuit_breaker_mock._state == CircuitBreakerState.HALF_OPEN:
                circuit_breaker_mock._half_open_calls = 0
            
            raise e
    
    circuit_breaker_mock.call = simulate_call
    circuit_breaker_mock.state = property(lambda self: circuit_breaker_mock._state)
    circuit_breaker_mock.failure_count = property(lambda self: circuit_breaker_mock._failure_count)
    circuit_breaker_mock.metrics = property(lambda self: circuit_breaker_mock._metrics)
    
    # Add utility methods
    def reset_breaker():
        circuit_breaker_mock._state = CircuitBreakerState.CLOSED
        circuit_breaker_mock._failure_count = 0
        circuit_breaker_mock._last_failure_time = None
        circuit_breaker_mock._half_open_calls = 0
    
    def force_open():
        circuit_breaker_mock._state = CircuitBreakerState.OPEN
        circuit_breaker_mock._last_failure_time = time.time()
    
    circuit_breaker_mock.reset = reset_breaker
    circuit_breaker_mock.force_open = force_open
    
    logger.info("Mock circuit breaker initialized with comprehensive state management")
    
    return circuit_breaker_mock


# =============================================================================
# Retry Logic Mock Fixtures per Section 4.2.3
# =============================================================================

@pytest.fixture
def mock_retry_manager():
    """
    Mock retry manager with exponential backoff testing support.
    
    Provides realistic retry logic simulation with exponential backoff,
    jitter implementation, and comprehensive retry statistics per Section 4.2.3
    error handling and recovery patterns.
    """
    retry_manager_mock = Mock()
    
    # Initialize retry configuration
    retry_manager_mock._config = {
        'max_retries': 3,
        'initial_delay': 1.0,
        'max_delay': 30.0,
        'exponential_base': 2.0,
        'jitter_factor': 0.1,
        'retry_on_exceptions': (RequestException, ConnectionError, Timeout, HTTPError)
    }
    
    # Add retry statistics tracking
    retry_manager_mock._statistics = {
        'total_attempts': 0,
        'successful_retries': 0,
        'failed_retries': 0,
        'retry_patterns': [],
        'backoff_times': [],
        'exception_counts': {}
    }
    
    def simulate_retry_with_exponential_backoff(func, *args, **kwargs):
        """Simulate retry logic with exponential backoff and jitter."""
        max_retries = retry_manager_mock._config['max_retries']
        initial_delay = retry_manager_mock._config['initial_delay']
        max_delay = retry_manager_mock._config['max_delay']
        exponential_base = retry_manager_mock._config['exponential_base']
        jitter_factor = retry_manager_mock._config['jitter_factor']
        
        last_exception = None
        
        for attempt in range(max_retries + 1):
            retry_manager_mock._statistics['total_attempts'] += 1
            
            try:
                # Simulate function execution
                if 'permanent_error' in str(args) or 'permanent_error' in str(kwargs):
                    raise ValueError("Permanent error - should not retry")
                elif 'retry_success_on_attempt_2' in str(args) and attempt < 2:
                    raise RequestException("Temporary error")
                elif 'retry_success_on_attempt_3' in str(args) and attempt < 3:
                    raise ConnectionError("Connection temporarily failed")
                elif 'always_fail' in str(args):
                    raise RequestException("Always failing request")
                
                # Successful execution
                if attempt > 0:
                    retry_manager_mock._statistics['successful_retries'] += 1
                
                return func(*args, **kwargs) if callable(func) else {'status': 'success', 'attempts': attempt + 1}
                
            except Exception as e:
                last_exception = e
                exception_type = type(e).__name__
                retry_manager_mock._statistics['exception_counts'][exception_type] = \
                    retry_manager_mock._statistics['exception_counts'].get(exception_type, 0) + 1
                
                # Check if exception is retryable
                if not isinstance(e, retry_manager_mock._config['retry_on_exceptions']):
                    break
                
                # If this is not the last attempt, calculate backoff time
                if attempt < max_retries:
                    # Calculate exponential backoff with jitter
                    delay = min(initial_delay * (exponential_base ** attempt), max_delay)
                    jitter = delay * jitter_factor * (0.5 - time.time() % 1)  # Pseudo-random jitter
                    final_delay = max(0, delay + jitter)
                    
                    retry_manager_mock._statistics['backoff_times'].append(final_delay)
                    retry_manager_mock._statistics['retry_patterns'].append({
                        'attempt': attempt + 1,
                        'exception': exception_type,
                        'delay': final_delay,
                        'timestamp': time.time()
                    })
                    
                    # Simulate delay (in tests we don't actually wait)
                    time.sleep(0.001)  # Minimal delay for testing
        
        # All retries exhausted
        retry_manager_mock._statistics['failed_retries'] += 1
        raise RetryExhaustedError(f"Max retries exceeded. Last exception: {last_exception}")
    
    retry_manager_mock.retry_with_backoff = simulate_retry_with_exponential_backoff
    
    # Add utility methods
    def get_retry_statistics():
        stats = retry_manager_mock._statistics.copy()
        if stats['total_attempts'] > 0:
            stats['success_rate'] = (stats['total_attempts'] - stats['failed_retries']) / stats['total_attempts']
            stats['avg_backoff_time'] = sum(stats['backoff_times']) / len(stats['backoff_times']) if stats['backoff_times'] else 0
        return stats
    
    def reset_statistics():
        retry_manager_mock._statistics = {
            'total_attempts': 0,
            'successful_retries': 0,
            'failed_retries': 0,
            'retry_patterns': [],
            'backoff_times': [],
            'exception_counts': {}
        }
    
    retry_manager_mock.get_statistics = get_retry_statistics
    retry_manager_mock.reset_statistics = reset_statistics
    
    logger.info("Mock retry manager initialized with exponential backoff simulation")
    
    return retry_manager_mock


# =============================================================================
# Third-Party API Mock Fixtures per Section 0.1.4
# =============================================================================

@pytest.fixture
def mock_auth0_api_client():
    """
    Mock Auth0 API client maintaining API contracts per Section 0.1.4.
    
    Provides realistic Auth0 behavior for token validation, user management,
    and OAuth flows while maintaining identical API contracts from the
    Node.js implementation.
    """
    auth0_client_mock = Mock()
    
    # Configure Auth0 API endpoints
    auth0_client_mock.base_url = "https://test-tenant.auth0.com"
    auth0_client_mock.api_version = "v2"
    
    # Mock token validation
    def validate_token(token):
        if token == "valid_jwt_token":
            return {
                "sub": "auth0|test-user-123",
                "email": "test@example.com",
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
                "iss": "https://test-tenant.auth0.com/",
                "aud": "test-client-id",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "scope": "openid profile email"
            }
        elif token == "expired_jwt_token":
            raise HTTPError("Token has expired")
        elif token == "invalid_signature_token":
            raise HTTPError("Invalid token signature")
        else:
            raise HTTPError("Invalid token")
    
    auth0_client_mock.validate_token = validate_token
    
    # Mock user management endpoints
    def get_user(user_id):
        if user_id == "auth0|test-user-123":
            return {
                "user_id": user_id,
                "email": "test@example.com",
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
                "created_at": "2023-01-01T00:00:00.000Z",
                "updated_at": "2023-12-01T00:00:00.000Z",
                "app_metadata": {},
                "user_metadata": {"preferences": {"theme": "dark"}}
            }
        else:
            raise HTTPError("User not found", response=Mock(status_code=404))
    
    def update_user(user_id, user_data):
        if user_id == "auth0|test-user-123":
            return {
                "user_id": user_id,
                **user_data,
                "updated_at": datetime.utcnow().isoformat() + "Z"
            }
        else:
            raise HTTPError("User not found", response=Mock(status_code=404))
    
    auth0_client_mock.get_user = get_user
    auth0_client_mock.update_user = update_user
    
    # Mock OAuth flows
    def get_access_token(client_credentials):
        if client_credentials.get('client_secret') == 'valid_secret':
            return {
                "access_token": "mock_access_token_" + str(uuid.uuid4()),
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read:users update:users"
            }
        else:
            raise HTTPError("Invalid client credentials")
    
    auth0_client_mock.get_access_token = get_access_token
    
    # Add performance and usage tracking
    auth0_client_mock._performance_metrics = {
        'token_validations': 0,
        'user_requests': 0,
        'oauth_requests': 0,
        'avg_response_time': 0.0,
        'error_count': 0
    }
    
    # Wrap methods with performance tracking
    original_validate_token = auth0_client_mock.validate_token
    original_get_user = auth0_client_mock.get_user
    original_get_access_token = auth0_client_mock.get_access_token
    
    def tracked_validate_token(token):
        start_time = time.time()
        try:
            result = original_validate_token(token)
            auth0_client_mock._performance_metrics['token_validations'] += 1
            return result
        except Exception as e:
            auth0_client_mock._performance_metrics['error_count'] += 1
            raise e
        finally:
            auth0_client_mock._performance_metrics['avg_response_time'] = time.time() - start_time
    
    def tracked_get_user(user_id):
        start_time = time.time()
        try:
            result = original_get_user(user_id)
            auth0_client_mock._performance_metrics['user_requests'] += 1
            return result
        except Exception as e:
            auth0_client_mock._performance_metrics['error_count'] += 1
            raise e
        finally:
            auth0_client_mock._performance_metrics['avg_response_time'] = time.time() - start_time
    
    def tracked_get_access_token(client_credentials):
        start_time = time.time()
        try:
            result = original_get_access_token(client_credentials)
            auth0_client_mock._performance_metrics['oauth_requests'] += 1
            return result
        except Exception as e:
            auth0_client_mock._performance_metrics['error_count'] += 1
            raise e
        finally:
            auth0_client_mock._performance_metrics['avg_response_time'] = time.time() - start_time
    
    auth0_client_mock.validate_token = tracked_validate_token
    auth0_client_mock.get_user = tracked_get_user
    auth0_client_mock.get_access_token = tracked_get_access_token
    
    logger.info("Mock Auth0 API client initialized with performance tracking")
    
    return auth0_client_mock


@pytest.fixture
def mock_external_api_client():
    """
    Mock generic external API client for third-party service integration testing.
    
    Provides configurable external API behavior for testing various third-party
    integrations while maintaining API contracts per Section 0.1.4 API surface
    compatibility requirements.
    """
    api_client_mock = Mock()
    
    # Configure API client properties
    api_client_mock.base_url = "https://api.external-service.com"
    api_client_mock.api_version = "v1"
    api_client_mock.timeout = 30.0
    
    # Mock API operations
    def api_get(endpoint, params=None, headers=None):
        """Mock GET request to external API."""
        if 'health' in endpoint:
            return {'status': 'healthy', 'version': '1.0.0', 'timestamp': time.time()}
        elif 'users' in endpoint:
            return {
                'users': [
                    {'id': 1, 'name': 'John Doe', 'email': 'john@example.com'},
                    {'id': 2, 'name': 'Jane Smith', 'email': 'jane@example.com'}
                ],
                'total': 2,
                'page': 1
            }
        elif 'data' in endpoint:
            return {'data': list(range(10)), 'metadata': {'generated_at': time.time()}}
        else:
            return {'status': 'success', 'endpoint': endpoint, 'params': params}
    
    def api_post(endpoint, data=None, json=None, headers=None):
        """Mock POST request to external API."""
        if 'webhook' in endpoint:
            return {'webhook_id': str(uuid.uuid4()), 'status': 'registered'}
        elif 'users' in endpoint:
            user_data = json or data or {}
            return {
                'id': 123,
                'created_at': datetime.utcnow().isoformat(),
                **user_data
            }
        else:
            return {'status': 'created', 'id': str(uuid.uuid4()), 'data': json or data}
    
    def api_put(endpoint, data=None, json=None, headers=None):
        """Mock PUT request to external API."""
        return {
            'status': 'updated',
            'endpoint': endpoint,
            'updated_at': datetime.utcnow().isoformat(),
            'data': json or data
        }
    
    def api_delete(endpoint, headers=None):
        """Mock DELETE request to external API."""
        return {'status': 'deleted', 'endpoint': endpoint}
    
    api_client_mock.get = api_get
    api_client_mock.post = api_post
    api_client_mock.put = api_put
    api_client_mock.delete = api_delete
    
    # Add webhook validation simulation
    def validate_webhook_signature(payload, signature, secret):
        """Mock webhook signature validation."""
        expected_signature = hmac.new(
            secret.encode(),
            payload.encode() if isinstance(payload, str) else payload,
            hashlib.sha256
        ).hexdigest()
        return f"sha256={expected_signature}" == signature
    
    api_client_mock.validate_webhook_signature = validate_webhook_signature
    
    # Add file processing simulation
    def process_file(file_data, processing_options=None):
        """Mock file processing operation."""
        return {
            'file_id': str(uuid.uuid4()),
            'size': len(file_data) if file_data else 0,
            'processed_at': datetime.utcnow().isoformat(),
            'options': processing_options or {},
            'status': 'processed'
        }
    
    api_client_mock.process_file = process_file
    
    # Add performance tracking
    api_client_mock._performance_metrics = {
        'api_calls': {'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0},
        'response_times': [],
        'error_count': 0,
        'webhook_validations': 0,
        'file_processes': 0
    }
    
    # Wrap methods with performance tracking
    for method_name in ['get', 'post', 'put', 'delete']:
        original_method = getattr(api_client_mock, method_name)
        
        def create_tracked_method(method, original):
            def tracked_method(*args, **kwargs):
                start_time = time.time()
                try:
                    result = original(*args, **kwargs)
                    api_client_mock._performance_metrics['api_calls'][method.upper()] += 1
                    api_client_mock._performance_metrics['response_times'].append(time.time() - start_time)
                    return result
                except Exception as e:
                    api_client_mock._performance_metrics['error_count'] += 1
                    raise e
            return tracked_method
        
        setattr(api_client_mock, method_name, create_tracked_method(method_name, original_method))
    
    logger.info("Mock external API client initialized with comprehensive features")
    
    return api_client_mock


# =============================================================================
# Performance Monitoring Mock Fixtures per Section 6.3.5
# =============================================================================

@pytest.fixture
def mock_external_service_monitor():
    """
    Mock external service monitor for performance testing per Section 6.3.5.
    
    Provides comprehensive external service monitoring simulation with health
    checks, performance metrics collection, and service state management
    supporting the ≤10% variance requirement.
    """
    monitor_mock = Mock(spec=ExternalServiceMonitor)
    
    # Initialize monitoring state
    monitor_mock._services = {}
    monitor_mock._health_states = {}
    monitor_mock._performance_baselines = {}
    
    # Add comprehensive metrics tracking
    monitor_mock._metrics = {
        'total_health_checks': 0,
        'healthy_services': 0,
        'degraded_services': 0,
        'unhealthy_services': 0,
        'avg_response_times': {},
        'error_rates': {},
        'uptime_percentages': {},
        'performance_variance': {}
    }
    
    def register_service(service_name, service_type, health_endpoint=None, baseline_metrics=None):
        """Register a service for monitoring."""
        monitor_mock._services[service_name] = {
            'service_type': service_type,
            'health_endpoint': health_endpoint,
            'registered_at': time.time(),
            'baseline_metrics': baseline_metrics or {}
        }
        monitor_mock._health_states[service_name] = ServiceHealthState.HEALTHY
        monitor_mock._performance_baselines[service_name] = baseline_metrics or {
            'avg_response_time': 100.0,  # 100ms baseline
            'error_rate': 0.01,  # 1% error rate baseline
            'throughput': 1000.0  # 1000 req/s baseline
        }
        
        logger.info(f"Service {service_name} registered for monitoring")
    
    def check_service_health(service_name):
        """Perform health check for a specific service."""
        monitor_mock._metrics['total_health_checks'] += 1
        
        if service_name not in monitor_mock._services:
            return {
                'service_name': service_name,
                'status': 'unknown',
                'error': 'Service not registered'
            }
        
        # Simulate health check logic
        service_info = monitor_mock._services[service_name]
        baseline = monitor_mock._performance_baselines[service_name]
        
        # Simulate realistic health check results
        current_response_time = baseline['avg_response_time'] * (0.8 + 0.4 * time.time() % 1)  # ±20% variance
        current_error_rate = baseline['error_rate'] * (0.5 + 1.0 * time.time() % 1)  # 0.5x - 1.5x variance
        
        # Calculate performance variance from baseline
        response_time_variance = abs(current_response_time - baseline['avg_response_time']) / baseline['avg_response_time']
        error_rate_variance = abs(current_error_rate - baseline['error_rate']) / baseline['error_rate'] if baseline['error_rate'] > 0 else 0
        
        # Determine health state based on performance variance
        if response_time_variance > 0.1 or error_rate_variance > 0.5:  # >10% response time variance or >50% error rate variance
            health_state = ServiceHealthState.DEGRADED
            monitor_mock._metrics['degraded_services'] += 1
        elif response_time_variance > 0.2 or error_rate_variance > 1.0:  # >20% response time variance or >100% error rate variance
            health_state = ServiceHealthState.UNHEALTHY
            monitor_mock._metrics['unhealthy_services'] += 1
        else:
            health_state = ServiceHealthState.HEALTHY
            monitor_mock._metrics['healthy_services'] += 1
        
        monitor_mock._health_states[service_name] = health_state
        
        # Update performance metrics
        monitor_mock._metrics['avg_response_times'][service_name] = current_response_time
        monitor_mock._metrics['error_rates'][service_name] = current_error_rate
        monitor_mock._metrics['performance_variance'][service_name] = {
            'response_time_variance': response_time_variance,
            'error_rate_variance': error_rate_variance,
            'within_tolerance': response_time_variance <= 0.1  # ≤10% variance requirement
        }
        
        return {
            'service_name': service_name,
            'status': health_state.value,
            'response_time_ms': current_response_time,
            'error_rate': current_error_rate,
            'performance_variance': {
                'response_time': f"{response_time_variance:.2%}",
                'error_rate': f"{error_rate_variance:.2%}",
                'within_tolerance': response_time_variance <= 0.1
            },
            'baseline_metrics': baseline,
            'timestamp': time.time()
        }
    
    def check_all_services_health():
        """Perform health check for all registered services."""
        results = {}
        overall_status = 'healthy'
        
        for service_name in monitor_mock._services:
            service_health = check_service_health(service_name)
            results[service_name] = service_health
            
            if service_health['status'] == 'unhealthy':
                overall_status = 'unhealthy'
            elif service_health['status'] == 'degraded' and overall_status == 'healthy':
                overall_status = 'degraded'
        
        return {
            'overall_status': overall_status,
            'services': results,
            'summary': {
                'total_services': len(monitor_mock._services),
                'healthy': sum(1 for r in results.values() if r['status'] == 'healthy'),
                'degraded': sum(1 for r in results.values() if r['status'] == 'degraded'),
                'unhealthy': sum(1 for r in results.values() if r['status'] == 'unhealthy')
            }
        }
    
    def get_performance_report():
        """Generate comprehensive performance report."""
        total_variance = []
        services_within_tolerance = 0
        
        for service_name, variance_data in monitor_mock._metrics['performance_variance'].items():
            total_variance.append(variance_data['response_time_variance'])
            if variance_data['within_tolerance']:
                services_within_tolerance += 1
        
        avg_variance = sum(total_variance) / len(total_variance) if total_variance else 0
        
        return {
            'overall_performance': {
                'avg_variance_from_baseline': f"{avg_variance:.2%}",
                'within_10_percent_tolerance': avg_variance <= 0.1,
                'services_within_tolerance': services_within_tolerance,
                'total_services': len(monitor_mock._services)
            },
            'service_details': monitor_mock._metrics['performance_variance'],
            'monitoring_summary': {
                'total_health_checks': monitor_mock._metrics['total_health_checks'],
                'healthy_services': monitor_mock._metrics['healthy_services'],
                'degraded_services': monitor_mock._metrics['degraded_services'],
                'unhealthy_services': monitor_mock._metrics['unhealthy_services']
            }
        }
    
    monitor_mock.register_service = register_service
    monitor_mock.check_service_health = check_service_health
    monitor_mock.check_all_services_health = check_all_services_health
    monitor_mock.get_performance_report = get_performance_report
    
    # Pre-register common services for testing
    monitor_mock.register_service('auth0', ExternalServiceType.AUTH_PROVIDER, '/health')
    monitor_mock.register_service('aws_s3', ExternalServiceType.CLOUD_STORAGE, None)
    monitor_mock.register_service('external_api', ExternalServiceType.HTTP_API, '/health')
    monitor_mock.register_service('redis_cache', ExternalServiceType.CACHE, '/ping')
    
    logger.info("Mock external service monitor initialized with performance tracking")
    
    return monitor_mock


# =============================================================================
# Integration Test Utilities
# =============================================================================

@pytest.fixture
def external_service_test_context(
    mock_s3_client,
    mock_kms_client,
    mock_cloudwatch_client,
    mock_requests_session,
    mock_httpx_client,
    mock_http_client_manager,
    mock_circuit_breaker,
    mock_retry_manager,
    mock_auth0_api_client,
    mock_external_api_client,
    mock_external_service_monitor
):
    """
    Comprehensive external service test context providing all mock fixtures.
    
    Provides a complete testing environment for external service integrations
    with performance monitoring, circuit breaker protection, and comprehensive
    API client simulation per Section 6.6.1 testing strategy.
    """
    return {
        'aws_services': {
            's3_client': mock_s3_client,
            'kms_client': mock_kms_client,
            'cloudwatch_client': mock_cloudwatch_client
        },
        'http_clients': {
            'requests_session': mock_requests_session,
            'httpx_client': mock_httpx_client,
            'client_manager': mock_http_client_manager
        },
        'resilience_patterns': {
            'circuit_breaker': mock_circuit_breaker,
            'retry_manager': mock_retry_manager
        },
        'api_clients': {
            'auth0_client': mock_auth0_api_client,
            'external_api_client': mock_external_api_client
        },
        'monitoring': {
            'service_monitor': mock_external_service_monitor
        }
    }


@pytest.fixture
def performance_baseline_context():
    """
    Performance baseline context for testing ≤10% variance requirement.
    
    Provides baseline metrics and performance validation utilities for ensuring
    the Python implementation maintains performance parity with the Node.js
    baseline per Section 0.3.2 performance monitoring requirements.
    """
    return {
        'baseline_metrics': {
            'auth0_response_time': 150.0,  # 150ms
            'aws_s3_upload_time': 2000.0,  # 2s
            'external_api_response_time': 300.0,  # 300ms
            'circuit_breaker_overhead': 5.0,  # 5ms
            'retry_logic_overhead': 10.0  # 10ms
        },
        'tolerance_thresholds': {
            'acceptable_variance': 0.10,  # 10%
            'warning_variance': 0.08,  # 8%
            'critical_variance': 0.15  # 15%
        },
        'performance_validation': {
            'track_response_times': True,
            'validate_variance': True,
            'log_performance_metrics': True,
            'alert_on_threshold_breach': True
        }
    }


# =============================================================================
# Cleanup and Utility Functions
# =============================================================================

@pytest.fixture(autouse=True)
def cleanup_external_service_mocks():
    """Automatically cleanup external service mocks after each test."""
    yield
    
    # Reset any global state or registries
    logger.info("Cleaning up external service mocks after test")


def create_mock_api_response(status_code=200, data=None, headers=None, response_time=0.1):
    """
    Utility function to create standardized mock API responses.
    
    Args:
        status_code: HTTP status code
        data: Response data
        headers: Response headers
        response_time: Simulated response time
        
    Returns:
        Mock response object with standardized structure
    """
    response = Mock()
    response.status_code = status_code
    response.ok = status_code < 400
    response.json.return_value = data or {}
    response.text = json.dumps(data or {})
    response.headers = headers or {'Content-Type': 'application/json'}
    response.elapsed = timedelta(seconds=response_time)
    return response


def simulate_external_service_latency(min_latency=0.05, max_latency=0.5):
    """
    Utility function to simulate realistic external service latency.
    
    Args:
        min_latency: Minimum latency in seconds
        max_latency: Maximum latency in seconds
        
    Returns:
        Simulated latency value
    """
    import random
    return random.uniform(min_latency, max_latency)


# Export all fixtures for use in tests
__all__ = [
    # AWS Service Mocks
    'aws_credentials',
    'mock_s3_client',
    'mock_kms_client', 
    'mock_cloudwatch_client',
    
    # HTTP Client Mocks
    'mock_requests_session',
    'mock_httpx_client',
    'mock_http_client_manager',
    
    # Circuit Breaker Mocks
    'mock_circuit_breaker_config',
    'mock_circuit_breaker',
    
    # Retry Logic Mocks
    'mock_retry_manager',
    
    # Third-Party API Mocks
    'mock_auth0_api_client',
    'mock_external_api_client',
    
    # Performance Monitoring Mocks
    'mock_external_service_monitor',
    
    # Integration Test Context
    'external_service_test_context',
    'performance_baseline_context',
    
    # Utilities
    'cleanup_external_service_mocks',
    'create_mock_api_response',
    'simulate_external_service_latency'
]