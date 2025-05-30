"""
External Service Integration Mock Fixtures

Comprehensive mock fixtures providing AWS service simulation, HTTP client mocking, circuit breaker
testing, and third-party API integration patterns for external dependency testing. This module
implements enterprise-grade testing patterns aligned with Section 0.1.2, 6.3.3, and 6.6.1
specifications for external service integration library replacement.

Key Features:
- boto3 1.28+ AWS service mock fixtures for S3 operations testing per Section 0.1.2
- requests 2.31+ and httpx 0.24+ HTTP client mock fixtures per Section 3.2.3
- Circuit breaker mock fixtures for external service resilience testing per Section 6.3.3
- Third-party API mock fixtures maintaining API contracts per Section 0.1.4
- Retry logic mock fixtures with exponential backoff testing per Section 4.2.3
- Performance monitoring mock fixtures for external service testing per Section 6.3.5
- AWS KMS mock fixtures for encryption key management testing per Section 6.4.3

Testing Integration:
- pytest fixture integration for comprehensive test isolation and repeatability
- Testcontainers compatibility for production-equivalent behavior per Section 6.6.1
- Factory pattern integration for dynamic test object generation per Section 6.6.1
- Performance variance testing supporting ≤10% variance requirement per Section 0.3.2

Dependencies:
- pytest 7.4+ with comprehensive external service simulation capabilities
- pytest-mock for HTTP client and AWS service mocking per Section 6.6.1
- boto3 1.28+ for AWS service integration testing per Section 0.1.2
- requests 2.31+ and httpx 0.24+ for HTTP client testing per Section 0.1.2
- pybreaker for circuit breaker pattern testing per Section 6.3.3

Author: Blitzy Platform Migration Team
Version: 1.0.0
Dependencies: pytest 7.4+, pytest-mock, boto3 1.28+, requests 2.31+, httpx 0.24+
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from unittest.mock import Mock, MagicMock, patch, AsyncMock, PropertyMock
from io import BytesIO, StringIO

import pytest
import pytest_asyncio
from moto import mock_s3, mock_kms, mock_sts, mock_cloudwatch, mock_iam
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
import requests
import httpx
from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError
from httpx import RequestError, TimeoutException, ConnectError

# Import application dependencies for comprehensive integration testing
try:
    from src.integrations.base_client import (
        BaseExternalServiceClient,
        BaseClientConfiguration,
        ServiceType,
        HealthStatus,
        CircuitBreakerState
    )
    from src.integrations.http_client import (
        SynchronousHTTPClient,
        AsynchronousHTTPClient,
        HTTPClientManager
    )
    from src.integrations.circuit_breaker import (
        ExternalServiceCircuitBreaker,
        CircuitBreakerManager,
        CircuitBreakerConfig
    )
    from src.integrations.external_apis import (
        GenericAPIClient,
        APIClientConfig,
        WebhookConfig,
        FileProcessingConfig
    )
    from src.config.settings import BaseConfig
except ImportError:
    # Graceful handling if modules don't exist yet - provide fallback classes
    class ServiceType:
        AUTH = "auth"
        AWS = "aws"
        DATABASE = "database"
        CACHE = "cache"
        EXTERNAL_API = "external_api"
    
    class HealthStatus:
        HEALTHY = "healthy"
        DEGRADED = "degraded"
        UNHEALTHY = "unhealthy"
    
    class CircuitBreakerState:
        CLOSED = "closed"
        OPEN = "open"
        HALF_OPEN = "half_open"
    
    class BaseConfig:
        TESTING = True

# Initialize structured logger for test execution tracking
logger = logging.getLogger(__name__)


# ================================================================================================
# AWS SERVICE MOCK FIXTURES - Section 0.1.2 External Integration Components
# ================================================================================================

@pytest.fixture(scope="function")
def mock_aws_credentials(monkeypatch):
    """
    Mock AWS credentials fixture preventing accidental live service calls during testing.
    
    Provides safe credential mocking for all AWS service interactions ensuring test isolation
    and preventing unintended charges or security exposure during development testing.
    
    Returns:
        Dict[str, str]: Mocked AWS credential configuration
    """
    mock_credentials = {
        'AWS_ACCESS_KEY_ID': 'testing',
        'AWS_SECRET_ACCESS_KEY': 'testing',
        'AWS_SECURITY_TOKEN': 'testing',
        'AWS_SESSION_TOKEN': 'testing',
        'AWS_DEFAULT_REGION': 'us-east-1'
    }
    
    # Set environment variables for boto3 credential discovery
    for key, value in mock_credentials.items():
        monkeypatch.setenv(key, value)
    
    return mock_credentials


@pytest.fixture(scope="function")
def mock_s3_service(mock_aws_credentials):
    """
    Comprehensive S3 service mock fixture providing realistic S3 operations testing.
    
    Implements moto-based S3 mocking with complete bucket lifecycle management, object
    operations, and error condition simulation for comprehensive AWS integration testing
    per Section 0.1.2 AWS SDK for JavaScript replacement with boto3 1.28+.
    
    Yields:
        boto3.client: Mocked S3 client with comprehensive operation support
    """
    with mock_s3():
        # Create boto3 S3 client with mocked backend
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        # Create test buckets for various test scenarios
        test_buckets = [
            'test-file-uploads',
            'test-document-storage',
            'test-image-processing',
            'test-backup-storage',
            'test-error-scenarios'
        ]
        
        for bucket_name in test_buckets:
            s3_client.create_bucket(Bucket=bucket_name)
        
        # Populate test buckets with sample objects for testing
        sample_objects = [
            ('test-file-uploads', 'documents/sample.pdf', b'Sample PDF content'),
            ('test-file-uploads', 'images/test.jpg', b'Sample image content'),
            ('test-document-storage', 'contracts/agreement.docx', b'Contract content'),
            ('test-image-processing', 'thumbnails/preview.png', b'Thumbnail content'),
            ('test-backup-storage', 'backups/database.sql', b'Database backup content')
        ]
        
        for bucket, key, content in sample_objects:
            s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=content,
                ContentType='application/octet-stream',
                Metadata={
                    'test-object': 'true',
                    'created-at': datetime.utcnow().isoformat(),
                    'test-scenario': 'mock-fixture'
                }
            )
        
        logger.info(
            "s3_mock_service_initialized",
            buckets_created=len(test_buckets),
            objects_created=len(sample_objects),
            component="external_service_mocks"
        )
        
        yield s3_client


@pytest.fixture(scope="function")
def mock_s3_operations(mock_s3_service):
    """
    High-level S3 operations mock fixture providing common S3 operation patterns.
    
    Encapsulates frequent S3 operations including file upload/download, batch operations,
    and error condition simulation for comprehensive external service integration testing.
    
    Returns:
        Dict[str, Callable]: Dictionary of mocked S3 operation functions
    """
    def upload_file(bucket: str, key: str, content: Union[str, bytes], 
                   metadata: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Mock S3 file upload operation with comprehensive response simulation."""
        try:
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            upload_metadata = metadata or {}
            upload_metadata.update({
                'upload-timestamp': datetime.utcnow().isoformat(),
                'mock-operation': 'upload_file',
                'content-size': str(len(content))
            })
            
            response = mock_s3_service.put_object(
                Bucket=bucket,
                Key=key,
                Body=content,
                Metadata=upload_metadata
            )
            
            return {
                'success': True,
                'etag': response['ETag'].strip('"'),
                'version_id': response.get('VersionId'),
                'size': len(content),
                'metadata': upload_metadata,
                'upload_timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def download_file(bucket: str, key: str) -> Dict[str, Any]:
        """Mock S3 file download operation with error handling simulation."""
        try:
            response = mock_s3_service.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()
            
            return {
                'success': True,
                'content': content,
                'content_type': response.get('ContentType', 'application/octet-stream'),
                'metadata': response.get('Metadata', {}),
                'last_modified': response.get('LastModified', datetime.utcnow()).isoformat(),
                'etag': response['ETag'].strip('"'),
                'size': response.get('ContentLength', len(content))
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            return {
                'success': False,
                'error': f"S3 ClientError: {error_code}",
                'error_code': error_code,
                'error_type': 'ClientError',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def delete_file(bucket: str, key: str) -> Dict[str, Any]:
        """Mock S3 file deletion operation with comprehensive response tracking."""
        try:
            response = mock_s3_service.delete_object(Bucket=bucket, Key=key)
            
            return {
                'success': True,
                'deleted': True,
                'delete_marker': response.get('DeleteMarker', False),
                'version_id': response.get('VersionId'),
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def list_objects(bucket: str, prefix: str = '') -> Dict[str, Any]:
        """Mock S3 object listing with pagination and filtering support."""
        try:
            kwargs = {'Bucket': bucket}
            if prefix:
                kwargs['Prefix'] = prefix
            
            response = mock_s3_service.list_objects_v2(**kwargs)
            
            objects = []
            for obj in response.get('Contents', []):
                objects.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'etag': obj['ETag'].strip('"'),
                    'storage_class': obj.get('StorageClass', 'STANDARD')
                })
            
            return {
                'success': True,
                'objects': objects,
                'count': len(objects),
                'truncated': response.get('IsTruncated', False),
                'prefix': prefix,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def batch_upload(uploads: List[Tuple[str, str, bytes]]) -> Dict[str, Any]:
        """Mock S3 batch upload operation for performance testing scenarios."""
        results = []
        start_time = time.time()
        
        for bucket, key, content in uploads:
            result = upload_file(bucket, key, content)
            result['batch_item'] = True
            results.append(result)
        
        duration = time.time() - start_time
        success_count = sum(1 for r in results if r['success'])
        
        return {
            'success': success_count == len(uploads),
            'results': results,
            'total_uploads': len(uploads),
            'successful_uploads': success_count,
            'failed_uploads': len(uploads) - success_count,
            'duration_seconds': duration,
            'uploads_per_second': len(uploads) / duration if duration > 0 else 0,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def simulate_s3_error(error_type: str = 'NoSuchBucket') -> Callable:
        """Generate S3 error simulation function for error handling testing."""
        def error_operation(*args, **kwargs):
            error_responses = {
                'NoSuchBucket': ClientError(
                    error_response={
                        'Error': {
                            'Code': 'NoSuchBucket',
                            'Message': 'The specified bucket does not exist'
                        }
                    },
                    operation_name='GetObject'
                ),
                'AccessDenied': ClientError(
                    error_response={
                        'Error': {
                            'Code': 'AccessDenied',
                            'Message': 'Access Denied'
                        }
                    },
                    operation_name='GetObject'
                ),
                'NoSuchKey': ClientError(
                    error_response={
                        'Error': {
                            'Code': 'NoSuchKey',
                            'Message': 'The specified key does not exist'
                        }
                    },
                    operation_name='GetObject'
                ),
                'ServiceUnavailable': ClientError(
                    error_response={
                        'Error': {
                            'Code': 'ServiceUnavailable',
                            'Message': 'Service Unavailable'
                        }
                    },
                    operation_name='GetObject'
                )
            }
            
            raise error_responses.get(error_type, Exception(f"Simulated error: {error_type}"))
        
        return error_operation
    
    return {
        'upload_file': upload_file,
        'download_file': download_file,
        'delete_file': delete_file,
        'list_objects': list_objects,
        'batch_upload': batch_upload,
        'simulate_error': simulate_s3_error,
        'client': mock_s3_service
    }


@pytest.fixture(scope="function")
def mock_kms_service(mock_aws_credentials):
    """
    AWS KMS service mock fixture for encryption key management testing per Section 6.4.3.
    
    Provides comprehensive KMS operations mocking including key creation, encryption/decryption,
    and key rotation simulation for security testing scenarios.
    
    Yields:
        boto3.client: Mocked KMS client with comprehensive cryptographic operation support
    """
    with mock_kms():
        kms_client = boto3.client('kms', region_name='us-east-1')
        
        # Create test encryption keys for various scenarios
        test_keys = []
        key_configs = [
            {'KeyUsage': 'ENCRYPT_DECRYPT', 'Description': 'Test encryption key'},
            {'KeyUsage': 'ENCRYPT_DECRYPT', 'Description': 'Test file encryption key'},
            {'KeyUsage': 'SIGN_VERIFY', 'Description': 'Test signing key'}
        ]
        
        for config in key_configs:
            response = kms_client.create_key(**config)
            test_keys.append(response['KeyMetadata']['KeyId'])
        
        # Create key aliases for easier testing
        for i, key_id in enumerate(test_keys):
            alias_name = f'alias/test-key-{i+1}'
            kms_client.create_alias(
                AliasName=alias_name,
                TargetKeyId=key_id
            )
        
        logger.info(
            "kms_mock_service_initialized",
            keys_created=len(test_keys),
            aliases_created=len(test_keys),
            component="external_service_mocks"
        )
        
        yield kms_client


# ================================================================================================
# HTTP CLIENT MOCK FIXTURES - Section 3.2.3 HTTP Client Integration
# ================================================================================================

@pytest.fixture(scope="function")
def mock_requests_client():
    """
    Comprehensive requests 2.31+ HTTP client mock fixture for synchronous API testing.
    
    Provides realistic HTTP response simulation with status codes, headers, timing patterns,
    and error condition handling for external service integration testing per Section 0.1.2.
    
    Returns:
        Mock: Configured requests mock with comprehensive response patterns
    """
    mock_session = Mock(spec=requests.Session)
    
    def create_response(status_code: int = 200, json_data: Optional[Dict] = None,
                       text_data: Optional[str] = None, headers: Optional[Dict] = None,
                       elapsed_seconds: float = 0.1) -> Mock:
        """Create realistic HTTP response mock with timing and header simulation."""
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.ok = 200 <= status_code < 300
        response.headers = headers or {
            'Content-Type': 'application/json',
            'Server': 'nginx/1.18.0',
            'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'X-Request-ID': str(uuid.uuid4())
        }
        
        if json_data is not None:
            response.json.return_value = json_data
            response.text = json.dumps(json_data)
            response.content = response.text.encode('utf-8')
        elif text_data is not None:
            response.text = text_data
            response.content = text_data.encode('utf-8')
            response.json.side_effect = ValueError("No JSON object could be decoded")
        else:
            response.text = ''
            response.content = b''
            response.json.side_effect = ValueError("No JSON object could be decoded")
        
        # Simulate request timing
        response.elapsed = timedelta(seconds=elapsed_seconds)
        
        return response
    
    def configure_endpoint(method: str, url: str, responses: List[Dict[str, Any]]):
        """Configure multiple responses for endpoint testing scenarios."""
        response_cycle = iter(responses)
        
        def side_effect(*args, **kwargs):
            try:
                response_config = next(response_cycle)
                if 'exception' in response_config:
                    raise response_config['exception']
                return create_response(**response_config)
            except StopIteration:
                # Repeat last response if cycle exhausted
                return create_response(**responses[-1])
        
        method_mock = getattr(mock_session, method.lower())
        method_mock.side_effect = side_effect
    
    # Configure common successful responses
    mock_session.get.return_value = create_response(
        status_code=200,
        json_data={'message': 'GET request successful', 'timestamp': datetime.utcnow().isoformat()}
    )
    
    mock_session.post.return_value = create_response(
        status_code=201,
        json_data={'message': 'POST request successful', 'id': str(uuid.uuid4()), 'created_at': datetime.utcnow().isoformat()}
    )
    
    mock_session.put.return_value = create_response(
        status_code=200,
        json_data={'message': 'PUT request successful', 'updated_at': datetime.utcnow().isoformat()}
    )
    
    mock_session.delete.return_value = create_response(
        status_code=204,
        headers={'Content-Type': 'application/json'}
    )
    
    mock_session.patch.return_value = create_response(
        status_code=200,
        json_data={'message': 'PATCH request successful', 'updated_at': datetime.utcnow().isoformat()}
    )
    
    # Add helper methods for dynamic configuration
    mock_session.create_response = create_response
    mock_session.configure_endpoint = configure_endpoint
    
    # Add connection pool simulation
    mock_session.adapters = {
        'http://': Mock(spec=requests.adapters.HTTPAdapter),
        'https://': Mock(spec=requests.adapters.HTTPAdapter)
    }
    
    # Configure realistic request preparation
    mock_request = Mock(spec=requests.PreparedRequest)
    mock_request.url = 'https://api.example.com/test'
    mock_request.method = 'GET'
    mock_request.headers = {}
    mock_request.body = None
    mock_session.prepare_request.return_value = mock_request
    
    logger.info(
        "requests_mock_client_initialized",
        methods_configured=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        component="external_service_mocks"
    )
    
    return mock_session


@pytest.fixture(scope="function")
def mock_httpx_client():
    """
    Comprehensive httpx 0.24+ async HTTP client mock fixture for asynchronous API testing.
    
    Provides realistic async HTTP response simulation with connection pooling, timeout handling,
    and HTTP/2 support simulation for high-performance external service integration testing.
    
    Returns:
        AsyncMock: Configured httpx async client mock with comprehensive async patterns
    """
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    async def create_async_response(status_code: int = 200, json_data: Optional[Dict] = None,
                                   text_data: Optional[str] = None, headers: Optional[Dict] = None,
                                   elapsed_seconds: float = 0.05) -> Mock:
        """Create realistic async HTTP response mock with performance simulation."""
        response = Mock(spec=httpx.Response)
        response.status_code = status_code
        response.is_success = 200 <= status_code < 300
        response.is_error = status_code >= 400
        response.headers = headers or {
            'content-type': 'application/json',
            'server': 'uvicorn',
            'date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'x-request-id': str(uuid.uuid4()),
            'x-response-time': f"{elapsed_seconds:.3f}s"
        }
        
        if json_data is not None:
            response.json.return_value = json_data
            response.text = json.dumps(json_data)
            response.content = response.text.encode('utf-8')
        elif text_data is not None:
            response.text = text_data
            response.content = text_data.encode('utf-8')
            response.json.side_effect = ValueError("Response is not valid JSON")
        else:
            response.text = ''
            response.content = b''
            response.json.side_effect = ValueError("Response is not valid JSON")
        
        # Simulate request timing for performance testing
        response.elapsed = timedelta(seconds=elapsed_seconds)
        
        # Add HTTP/2 and connection info simulation
        response.http_version = 'HTTP/2.0'
        response.url = 'https://api.example.com/test'
        response.request = Mock(spec=httpx.Request)
        response.request.method = 'GET'
        response.request.url = response.url
        
        # Simulate async operations delay
        await asyncio.sleep(elapsed_seconds / 10)  # Reduced delay for testing
        
        return response
    
    # Configure common async responses
    mock_client.get.return_value = await create_async_response(
        status_code=200,
        json_data={'message': 'Async GET successful', 'timestamp': datetime.utcnow().isoformat()}
    )
    
    mock_client.post.return_value = await create_async_response(
        status_code=201,
        json_data={'message': 'Async POST successful', 'id': str(uuid.uuid4())}
    )
    
    mock_client.put.return_value = await create_async_response(
        status_code=200,
        json_data={'message': 'Async PUT successful', 'updated_at': datetime.utcnow().isoformat()}
    )
    
    mock_client.delete.return_value = await create_async_response(
        status_code=204,
        headers={'content-type': 'application/json'}
    )
    
    mock_client.patch.return_value = await create_async_response(
        status_code=200,
        json_data={'message': 'Async PATCH successful', 'updated_at': datetime.utcnow().isoformat()}
    )
    
    # Configure connection pool and limits simulation
    mock_client.limits = Mock()
    mock_client.limits.max_connections = 100
    mock_client.limits.max_keepalive_connections = 50
    mock_client.limits.keepalive_expiry = 30.0
    
    # Add helper methods for dynamic configuration
    mock_client.create_response = create_async_response
    
    # Configure context manager behavior for async with statements
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = AsyncMock()
    
    logger.info(
        "httpx_mock_client_initialized",
        methods_configured=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        http_version='HTTP/2.0',
        component="external_service_mocks"
    )
    
    return mock_client


@pytest.fixture(scope="function")
def mock_http_error_scenarios():
    """
    HTTP error scenario simulation fixture for comprehensive error handling testing.
    
    Provides realistic error condition simulation including timeout, connection errors,
    rate limiting, and server errors for resilience pattern testing.
    
    Returns:
        Dict[str, Callable]: Dictionary of error simulation functions
    """
    def simulate_timeout(delay: float = 30.0):
        """Simulate HTTP timeout scenarios for timeout handling testing."""
        def timeout_error(*args, **kwargs):
            time.sleep(delay / 1000)  # Reduced delay for testing
            raise RequestException(f"Request timed out after {delay}s")
        return timeout_error
    
    def simulate_connection_error():
        """Simulate connection failure scenarios for connectivity testing."""
        def connection_error(*args, **kwargs):
            raise RequestsConnectionError("Failed to establish connection to remote host")
        return connection_error
    
    def simulate_rate_limit(retry_after: int = 60):
        """Simulate rate limiting scenarios for rate limit handling testing."""
        def rate_limit_error(*args, **kwargs):
            response = Mock(spec=requests.Response)
            response.status_code = 429
            response.headers = {
                'Retry-After': str(retry_after),
                'X-RateLimit-Limit': '1000',
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int(time.time()) + retry_after)
            }
            response.json.return_value = {
                'error': 'Rate limit exceeded',
                'message': f'Rate limit exceeded. Try again in {retry_after} seconds.',
                'retry_after': retry_after
            }
            response.text = json.dumps(response.json.return_value)
            return response
        return rate_limit_error
    
    def simulate_server_error(status_code: int = 500):
        """Simulate server error scenarios for error handling testing."""
        def server_error(*args, **kwargs):
            response = Mock(spec=requests.Response)
            response.status_code = status_code
            response.ok = False
            response.headers = {
                'Content-Type': 'application/json',
                'X-Error-ID': str(uuid.uuid4())
            }
            response.json.return_value = {
                'error': 'Internal Server Error',
                'message': f'Server error occurred (HTTP {status_code})',
                'status_code': status_code,
                'timestamp': datetime.utcnow().isoformat()
            }
            response.text = json.dumps(response.json.return_value)
            return response
        return server_error
    
    def simulate_auth_error():
        """Simulate authentication error scenarios for auth handling testing."""
        def auth_error(*args, **kwargs):
            response = Mock(spec=requests.Response)
            response.status_code = 401
            response.ok = False
            response.headers = {
                'Content-Type': 'application/json',
                'WWW-Authenticate': 'Bearer realm="api"'
            }
            response.json.return_value = {
                'error': 'Unauthorized',
                'message': 'Invalid or expired authentication token',
                'status_code': 401
            }
            response.text = json.dumps(response.json.return_value)
            return response
        return auth_error
    
    def simulate_intermittent_failures(failure_rate: float = 0.3):
        """Simulate intermittent failures for reliability testing."""
        call_count = 0
        
        def intermittent_failure(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            if call_count % int(1 / failure_rate) == 0:
                raise RequestException("Intermittent service failure")
            
            response = Mock(spec=requests.Response)
            response.status_code = 200
            response.ok = True
            response.json.return_value = {
                'message': 'Request successful',
                'call_count': call_count,
                'timestamp': datetime.utcnow().isoformat()
            }
            response.text = json.dumps(response.json.return_value)
            return response
        
        return intermittent_failure
    
    return {
        'timeout': simulate_timeout,
        'connection_error': simulate_connection_error,
        'rate_limit': simulate_rate_limit,
        'server_error': simulate_server_error,
        'auth_error': simulate_auth_error,
        'intermittent_failures': simulate_intermittent_failures
    }


# ================================================================================================
# CIRCUIT BREAKER MOCK FIXTURES - Section 6.3.3 Resilience Patterns
# ================================================================================================

@pytest.fixture(scope="function")
def mock_circuit_breaker():
    """
    Circuit breaker pattern mock fixture for resilience testing per Section 6.3.3.
    
    Provides comprehensive circuit breaker behavior simulation including state transitions,
    failure threshold management, and recovery automation testing for external service protection.
    
    Returns:
        Mock: Configured circuit breaker mock with state management
    """
    circuit_breaker = Mock()
    
    # Initialize circuit breaker state
    circuit_breaker.state = CircuitBreakerState.CLOSED
    circuit_breaker.failure_count = 0
    circuit_breaker.failure_threshold = 5
    circuit_breaker.reset_timeout = 60
    circuit_breaker.last_failure_time = None
    circuit_breaker.call_count = 0
    circuit_breaker.success_count = 0
    
    def call_with_circuit_breaker(func: Callable, *args, **kwargs):
        """Circuit breaker call wrapper with comprehensive state management."""
        circuit_breaker.call_count += 1
        current_time = time.time()
        
        # Check if circuit breaker should transition from OPEN to HALF_OPEN
        if (circuit_breaker.state == CircuitBreakerState.OPEN and 
            circuit_breaker.last_failure_time and
            current_time - circuit_breaker.last_failure_time >= circuit_breaker.reset_timeout):
            circuit_breaker.state = CircuitBreakerState.HALF_OPEN
            logger.info(
                "circuit_breaker_state_transition",
                from_state="OPEN",
                to_state="HALF_OPEN",
                reset_timeout=circuit_breaker.reset_timeout,
                component="external_service_mocks"
            )
        
        # Handle circuit breaker states
        if circuit_breaker.state == CircuitBreakerState.OPEN:
            from src.integrations.circuit_breaker import CircuitBreakerOpenError
            raise CircuitBreakerOpenError(
                f"Circuit breaker is OPEN. Failure count: {circuit_breaker.failure_count}"
            )
        
        try:
            # Execute the function
            result = func(*args, **kwargs)
            
            # Success handling
            circuit_breaker.success_count += 1
            
            if circuit_breaker.state == CircuitBreakerState.HALF_OPEN:
                # Transition to CLOSED on successful call in HALF_OPEN state
                circuit_breaker.state = CircuitBreakerState.CLOSED
                circuit_breaker.failure_count = 0
                logger.info(
                    "circuit_breaker_recovery_successful",
                    state="CLOSED",
                    success_count=circuit_breaker.success_count,
                    component="external_service_mocks"
                )
            
            return result
            
        except Exception as e:
            # Failure handling
            circuit_breaker.failure_count += 1
            circuit_breaker.last_failure_time = current_time
            
            if circuit_breaker.failure_count >= circuit_breaker.failure_threshold:
                circuit_breaker.state = CircuitBreakerState.OPEN
                logger.warning(
                    "circuit_breaker_opened",
                    failure_count=circuit_breaker.failure_count,
                    failure_threshold=circuit_breaker.failure_threshold,
                    component="external_service_mocks"
                )
            
            raise e
    
    def reset_circuit_breaker():
        """Reset circuit breaker to initial state for testing scenarios."""
        circuit_breaker.state = CircuitBreakerState.CLOSED
        circuit_breaker.failure_count = 0
        circuit_breaker.last_failure_time = None
        circuit_breaker.call_count = 0
        circuit_breaker.success_count = 0
        logger.info(
            "circuit_breaker_reset",
            state="CLOSED",
            component="external_service_mocks"
        )
    
    def get_circuit_breaker_stats():
        """Get comprehensive circuit breaker statistics for testing validation."""
        return {
            'state': circuit_breaker.state,
            'failure_count': circuit_breaker.failure_count,
            'success_count': circuit_breaker.success_count,
            'call_count': circuit_breaker.call_count,
            'failure_threshold': circuit_breaker.failure_threshold,
            'reset_timeout': circuit_breaker.reset_timeout,
            'last_failure_time': circuit_breaker.last_failure_time,
            'failure_rate': circuit_breaker.failure_count / circuit_breaker.call_count if circuit_breaker.call_count > 0 else 0,
            'success_rate': circuit_breaker.success_count / circuit_breaker.call_count if circuit_breaker.call_count > 0 else 0
        }
    
    def configure_circuit_breaker(failure_threshold: int = 5, reset_timeout: int = 60):
        """Configure circuit breaker parameters for specific testing scenarios."""
        circuit_breaker.failure_threshold = failure_threshold
        circuit_breaker.reset_timeout = reset_timeout
        logger.info(
            "circuit_breaker_configured",
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            component="external_service_mocks"
        )
    
    # Attach methods to circuit breaker mock
    circuit_breaker.call = call_with_circuit_breaker
    circuit_breaker.reset = reset_circuit_breaker
    circuit_breaker.stats = get_circuit_breaker_stats
    circuit_breaker.configure = configure_circuit_breaker
    
    logger.info(
        "circuit_breaker_mock_initialized",
        initial_state=circuit_breaker.state,
        failure_threshold=circuit_breaker.failure_threshold,
        reset_timeout=circuit_breaker.reset_timeout,
        component="external_service_mocks"
    )
    
    return circuit_breaker


@pytest.fixture(scope="function")
def mock_circuit_breaker_manager(mock_circuit_breaker):
    """
    Circuit breaker manager mock fixture for multi-service circuit breaker testing.
    
    Provides centralized circuit breaker management with service-specific configurations
    and global state monitoring for comprehensive resilience pattern testing.
    
    Returns:
        Mock: Circuit breaker manager with multi-service support
    """
    manager = Mock()
    manager.circuit_breakers = {}
    
    def get_circuit_breaker(service_name: str, service_type: str = ServiceType.EXTERNAL_API):
        """Get or create circuit breaker for specific service."""
        if service_name not in manager.circuit_breakers:
            # Create new circuit breaker with service-specific configuration
            cb = Mock()
            cb.state = CircuitBreakerState.CLOSED
            cb.failure_count = 0
            cb.success_count = 0
            cb.call_count = 0
            cb.service_name = service_name
            cb.service_type = service_type
            
            # Service-specific thresholds per Section 6.3.5
            thresholds = {
                ServiceType.AUTH: {'failure_threshold': 5, 'reset_timeout': 60},
                ServiceType.AWS: {'failure_threshold': 3, 'reset_timeout': 60},
                ServiceType.DATABASE: {'failure_threshold': 10, 'reset_timeout': 120},
                ServiceType.CACHE: {'failure_threshold': 10, 'reset_timeout': 30},
                ServiceType.EXTERNAL_API: {'failure_threshold': 5, 'reset_timeout': 60}
            }
            
            config = thresholds.get(service_type, thresholds[ServiceType.EXTERNAL_API])
            cb.failure_threshold = config['failure_threshold']
            cb.reset_timeout = config['reset_timeout']
            
            manager.circuit_breakers[service_name] = cb
            
            logger.info(
                "circuit_breaker_created",
                service_name=service_name,
                service_type=service_type,
                failure_threshold=cb.failure_threshold,
                reset_timeout=cb.reset_timeout,
                component="external_service_mocks"
            )
        
        return manager.circuit_breakers[service_name]
    
    def get_all_circuit_breakers():
        """Get status of all circuit breakers for monitoring."""
        return {
            name: {
                'state': cb.state,
                'failure_count': cb.failure_count,
                'success_count': cb.success_count,
                'call_count': cb.call_count,
                'service_type': cb.service_type,
                'failure_threshold': cb.failure_threshold,
                'reset_timeout': cb.reset_timeout
            }
            for name, cb in manager.circuit_breakers.items()
        }
    
    def reset_all_circuit_breakers():
        """Reset all circuit breakers for testing scenarios."""
        for cb in manager.circuit_breakers.values():
            cb.state = CircuitBreakerState.CLOSED
            cb.failure_count = 0
            cb.success_count = 0
            cb.call_count = 0
        
        logger.info(
            "all_circuit_breakers_reset",
            count=len(manager.circuit_breakers),
            component="external_service_mocks"
        )
    
    manager.get_circuit_breaker = get_circuit_breaker
    manager.get_all = get_all_circuit_breakers
    manager.reset_all = reset_all_circuit_breakers
    
    return manager


# ================================================================================================
# RETRY LOGIC MOCK FIXTURES - Section 4.2.3 Error Handling
# ================================================================================================

@pytest.fixture(scope="function")
def mock_retry_manager():
    """
    Retry logic mock fixture with exponential backoff testing per Section 4.2.3.
    
    Provides comprehensive retry pattern simulation including exponential backoff,
    jitter implementation, and retry exhaustion testing for fault tolerance validation.
    
    Returns:
        Mock: Retry manager with comprehensive retry pattern support
    """
    retry_manager = Mock()
    retry_manager.retry_attempts = {}
    retry_manager.retry_stats = {}
    
    def execute_with_retry(func: Callable, max_attempts: int = 3, 
                          base_delay: float = 1.0, max_delay: float = 30.0,
                          jitter: bool = True, exponential_base: float = 2.0,
                          service_name: str = 'default') -> Any:
        """Execute function with comprehensive retry logic and statistics tracking."""
        
        if service_name not in retry_manager.retry_stats:
            retry_manager.retry_stats[service_name] = {
                'total_calls': 0,
                'total_retries': 0,
                'successful_calls': 0,
                'failed_calls': 0,
                'retry_exhausted': 0,
                'average_attempts': 0.0,
                'total_delay': 0.0
            }
        
        stats = retry_manager.retry_stats[service_name]
        stats['total_calls'] += 1
        
        attempt = 0
        total_delay = 0.0
        last_exception = None
        
        while attempt < max_attempts:
            attempt += 1
            
            try:
                if attempt > 1:
                    # Calculate exponential backoff delay
                    delay = min(base_delay * (exponential_base ** (attempt - 2)), max_delay)
                    
                    # Add jitter if enabled
                    if jitter:
                        import random
                        jitter_factor = random.uniform(0.1, 1.0)
                        delay *= jitter_factor
                    
                    # Simulate delay (reduced for testing)
                    time.sleep(delay / 100)  # Reduced delay for testing
                    total_delay += delay
                    
                    stats['total_retries'] += 1
                    
                    logger.info(
                        "retry_attempt",
                        service_name=service_name,
                        attempt=attempt,
                        max_attempts=max_attempts,
                        delay=delay,
                        total_delay=total_delay,
                        component="external_service_mocks"
                    )
                
                # Execute the function
                result = func()
                
                # Success - update statistics
                stats['successful_calls'] += 1
                stats['total_delay'] += total_delay
                stats['average_attempts'] = (stats['average_attempts'] * (stats['total_calls'] - 1) + attempt) / stats['total_calls']
                
                logger.info(
                    "retry_success",
                    service_name=service_name,
                    attempts_used=attempt,
                    total_delay=total_delay,
                    component="external_service_mocks"
                )
                
                return result
                
            except Exception as e:
                last_exception = e
                
                logger.warning(
                    "retry_attempt_failed",
                    service_name=service_name,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    error=str(e),
                    error_type=type(e).__name__,
                    component="external_service_mocks"
                )
                
                if attempt >= max_attempts:
                    break
        
        # Retry exhausted - update statistics
        stats['failed_calls'] += 1
        stats['retry_exhausted'] += 1
        stats['total_delay'] += total_delay
        stats['average_attempts'] = (stats['average_attempts'] * (stats['total_calls'] - 1) + attempt) / stats['total_calls']
        
        logger.error(
            "retry_exhausted",
            service_name=service_name,
            max_attempts=max_attempts,
            total_delay=total_delay,
            final_error=str(last_exception),
            component="external_service_mocks"
        )
        
        from src.integrations.exceptions import RetryExhaustedError
        raise RetryExhaustedError(
            f"Retry exhausted after {max_attempts} attempts for service {service_name}. Last error: {last_exception}"
        )
    
    def get_retry_stats(service_name: str = None) -> Dict[str, Any]:
        """Get comprehensive retry statistics for performance analysis."""
        if service_name:
            return retry_manager.retry_stats.get(service_name, {})
        return retry_manager.retry_stats
    
    def reset_retry_stats(service_name: str = None):
        """Reset retry statistics for testing scenarios."""
        if service_name:
            if service_name in retry_manager.retry_stats:
                retry_manager.retry_stats[service_name] = {
                    'total_calls': 0,
                    'total_retries': 0,
                    'successful_calls': 0,
                    'failed_calls': 0,
                    'retry_exhausted': 0,
                    'average_attempts': 0.0,
                    'total_delay': 0.0
                }
        else:
            retry_manager.retry_stats = {}
        
        logger.info(
            "retry_stats_reset",
            service_name=service_name or "all",
            component="external_service_mocks"
        )
    
    def configure_retry_policy(service_name: str, max_attempts: int = 3,
                              base_delay: float = 1.0, max_delay: float = 30.0,
                              exponential_base: float = 2.0, jitter: bool = True):
        """Configure service-specific retry policy for testing scenarios."""
        if service_name not in retry_manager.retry_attempts:
            retry_manager.retry_attempts[service_name] = {}
        
        retry_manager.retry_attempts[service_name] = {
            'max_attempts': max_attempts,
            'base_delay': base_delay,
            'max_delay': max_delay,
            'exponential_base': exponential_base,
            'jitter': jitter
        }
        
        logger.info(
            "retry_policy_configured",
            service_name=service_name,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            component="external_service_mocks"
        )
    
    retry_manager.execute = execute_with_retry
    retry_manager.get_stats = get_retry_stats
    retry_manager.reset_stats = reset_retry_stats
    retry_manager.configure_policy = configure_retry_policy
    
    logger.info(
        "retry_manager_mock_initialized",
        component="external_service_mocks"
    )
    
    return retry_manager


# ================================================================================================
# THIRD-PARTY API MOCK FIXTURES - Section 0.1.4 API Surface Changes
# ================================================================================================

@pytest.fixture(scope="function")
def mock_auth0_service():
    """
    Auth0 authentication service mock fixture maintaining API contracts per Section 0.1.4.
    
    Provides comprehensive Auth0 service simulation including JWT token validation,
    user management, and OAuth2 flow testing for authentication integration testing.
    
    Returns:
        Mock: Auth0 service mock with comprehensive authentication patterns
    """
    auth0_mock = Mock()
    
    # Mock JWT tokens for testing
    valid_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtZG9tYWluLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHx0ZXN0LXVzZXItaWQiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJodHRwczovL3Rlc3QtZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYXQiOjE2MzQ2NDcyMDAsImV4cCI6OTk5OTk5OTk5OSwiYXpwIjoidGVzdC1jbGllbnQtaWQiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwicGVybWlzc2lvbnMiOlsicmVhZDp1c2VycyIsIndyaXRlOnVzZXJzIiwicmVhZDpkYXRhIiwid3JpdGU6ZGF0YSJdfQ"
    
    expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtZG9tYWluLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHx0ZXN0LXVzZXItaWQiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJodHRwczovL3Rlc3QtZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYXQiOjE2MzQ2NDcyMDAsImV4cCI6MTYzNDY0NzIwMSwiYXpwIjoidGVzdC1jbGllbnQtaWQiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwicGVybWlzc2lvbnMiOlsicmVhZDp1c2VycyJdfQ"
    
    def validate_token(token: str) -> Dict[str, Any]:
        """Mock JWT token validation with comprehensive response patterns."""
        if not token or token == "invalid":
            return {
                'valid': False,
                'error': 'Invalid token',
                'error_code': 'invalid_token',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        if token == expired_jwt_token:
            return {
                'valid': False,
                'error': 'Token expired',
                'error_code': 'token_expired',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        if token == valid_jwt_token:
            return {
                'valid': True,
                'decoded': {
                    'iss': 'https://test-domain.auth0.com/',
                    'sub': 'auth0|test-user-id',
                    'aud': ['https://api.example.com', 'https://test-domain.auth0.com/userinfo'],
                    'iat': 1634647200,
                    'exp': 9999999999,
                    'azp': 'test-client-id',
                    'scope': 'openid profile email',
                    'permissions': ['read:users', 'write:users', 'read:data', 'write:data']
                },
                'user_id': 'auth0|test-user-id',
                'client_id': 'test-client-id',
                'permissions': ['read:users', 'write:users', 'read:data', 'write:data'],
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Default valid token response for other tokens
        return {
            'valid': True,
            'decoded': {
                'iss': 'https://test-domain.auth0.com/',
                'sub': 'auth0|generic-user-id',
                'aud': ['https://api.example.com'],
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'azp': 'test-client-id',
                'scope': 'openid profile email',
                'permissions': ['read:data']
            },
            'user_id': 'auth0|generic-user-id',
            'client_id': 'test-client-id',
            'permissions': ['read:data'],
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_user_info(user_id: str) -> Dict[str, Any]:
        """Mock Auth0 user information retrieval."""
        if user_id == 'auth0|test-user-id':
            return {
                'user_id': user_id,
                'email': 'test.user@example.com',
                'email_verified': True,
                'name': 'Test User',
                'nickname': 'testuser',
                'picture': 'https://gravatar.com/avatar/test',
                'created_at': '2023-01-01T00:00:00.000Z',
                'updated_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat(),
                'logins_count': 42,
                'app_metadata': {
                    'roles': ['user'],
                    'permissions': ['read:users', 'write:users', 'read:data', 'write:data']
                },
                'user_metadata': {
                    'preferences': {
                        'theme': 'light',
                        'language': 'en'
                    }
                }
            }
        elif user_id == 'auth0|admin-user-id':
            return {
                'user_id': user_id,
                'email': 'admin.user@example.com',
                'email_verified': True,
                'name': 'Admin User',
                'nickname': 'adminuser',
                'picture': 'https://gravatar.com/avatar/admin',
                'created_at': '2023-01-01T00:00:00.000Z',
                'updated_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat(),
                'logins_count': 128,
                'app_metadata': {
                    'roles': ['admin', 'user'],
                    'permissions': ['read:users', 'write:users', 'read:data', 'write:data', 'admin:system']
                },
                'user_metadata': {
                    'preferences': {
                        'theme': 'dark',
                        'language': 'en'
                    }
                }
            }
        else:
            return {
                'error': 'User not found',
                'error_code': 'user_not_found',
                'user_id': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def exchange_code_for_token(authorization_code: str, redirect_uri: str) -> Dict[str, Any]:
        """Mock OAuth2 authorization code exchange for token."""
        if not authorization_code or authorization_code == 'invalid':
            return {
                'error': 'invalid_grant',
                'error_description': 'Invalid authorization code',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return {
            'access_token': valid_jwt_token,
            'refresh_token': 'test-refresh-token-' + str(uuid.uuid4()),
            'id_token': valid_jwt_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'openid profile email',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def refresh_token(refresh_token: str) -> Dict[str, Any]:
        """Mock token refresh operation."""
        if not refresh_token or refresh_token == 'invalid':
            return {
                'error': 'invalid_grant',
                'error_description': 'Invalid refresh token',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return {
            'access_token': valid_jwt_token,
            'refresh_token': 'new-refresh-token-' + str(uuid.uuid4()),
            'id_token': valid_jwt_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'openid profile email',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_jwks() -> Dict[str, Any]:
        """Mock JWKS (JSON Web Key Set) endpoint for token verification."""
        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'test-key-id',
                    'x5t': 'test-x5t',
                    'n': 'test-modulus',
                    'e': 'AQAB',
                    'x5c': ['test-certificate'],
                    'issuer': 'https://test-domain.auth0.com/'
                }
            ]
        }
    
    # Attach methods to Auth0 mock
    auth0_mock.validate_token = validate_token
    auth0_mock.get_user_info = get_user_info
    auth0_mock.exchange_code_for_token = exchange_code_for_token
    auth0_mock.refresh_token = refresh_token
    auth0_mock.get_jwks = get_jwks
    
    # Add token constants for easy testing
    auth0_mock.VALID_TOKEN = valid_jwt_token
    auth0_mock.EXPIRED_TOKEN = expired_jwt_token
    auth0_mock.INVALID_TOKEN = "invalid"
    
    logger.info(
        "auth0_service_mock_initialized",
        features=['token_validation', 'user_info', 'oauth2_flow', 'token_refresh', 'jwks'],
        component="external_service_mocks"
    )
    
    return auth0_mock


@pytest.fixture(scope="function")
def mock_third_party_apis():
    """
    Third-party API integration mock fixture for comprehensive API testing.
    
    Provides realistic third-party service simulation including webhook handling,
    file processing APIs, and payment gateway integration for external dependency testing.
    
    Returns:
        Dict[str, Mock]: Dictionary of third-party API service mocks
    """
    
    # Payment Gateway Mock
    payment_gateway = Mock()
    
    def process_payment(amount: float, currency: str = 'USD', 
                       payment_method: str = 'card') -> Dict[str, Any]:
        """Mock payment processing with realistic response patterns."""
        if amount <= 0:
            return {
                'success': False,
                'error': 'Invalid amount',
                'error_code': 'invalid_amount',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        if amount > 10000:  # Simulate large amount failure
            return {
                'success': False,
                'error': 'Amount exceeds limit',
                'error_code': 'amount_limit_exceeded',
                'limit': 10000,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        transaction_id = str(uuid.uuid4())
        return {
            'success': True,
            'transaction_id': transaction_id,
            'amount': amount,
            'currency': currency,
            'payment_method': payment_method,
            'status': 'completed',
            'fee': amount * 0.029 + 0.30,  # Simulate processing fee
            'net_amount': amount - (amount * 0.029 + 0.30),
            'reference': f'PAY_{int(time.time())}_{transaction_id[:8]}',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    payment_gateway.process_payment = process_payment
    
    # Notification Service Mock
    notification_service = Mock()
    
    def send_notification(notification_type: str, recipient: str, 
                         message: str, metadata: Dict = None) -> Dict[str, Any]:
        """Mock notification service with delivery simulation."""
        notification_id = str(uuid.uuid4())
        
        # Simulate delivery failure for certain patterns
        if 'fail' in recipient.lower() or 'invalid' in recipient.lower():
            return {
                'success': False,
                'notification_id': notification_id,
                'error': 'Delivery failed',
                'error_code': 'delivery_failed',
                'recipient': recipient,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return {
            'success': True,
            'notification_id': notification_id,
            'type': notification_type,
            'recipient': recipient,
            'status': 'delivered',
            'delivery_time': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
            'timestamp': datetime.utcnow().isoformat()
        }
    
    notification_service.send_notification = send_notification
    
    # File Processing Service Mock
    file_processing_service = Mock()
    
    def process_file(file_content: bytes, file_type: str, 
                    processing_options: Dict = None) -> Dict[str, Any]:
        """Mock file processing service with realistic processing simulation."""
        processing_id = str(uuid.uuid4())
        
        # Simulate processing time based on file size
        processing_time = len(file_content) / 10000  # Simulated processing speed
        
        if len(file_content) > 100 * 1024 * 1024:  # 100MB limit
            return {
                'success': False,
                'processing_id': processing_id,
                'error': 'File too large',
                'error_code': 'file_too_large',
                'max_size': 100 * 1024 * 1024,
                'file_size': len(file_content),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Simulate unsupported file type
        supported_types = ['pdf', 'jpg', 'png', 'docx', 'txt']
        if file_type.lower() not in supported_types:
            return {
                'success': False,
                'processing_id': processing_id,
                'error': 'Unsupported file type',
                'error_code': 'unsupported_file_type',
                'supported_types': supported_types,
                'provided_type': file_type,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return {
            'success': True,
            'processing_id': processing_id,
            'file_type': file_type,
            'file_size': len(file_content),
            'processing_time': processing_time,
            'status': 'completed',
            'result_url': f'https://files.example.com/processed/{processing_id}',
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'metadata': {
                'processed_at': datetime.utcnow().isoformat(),
                'processing_options': processing_options or {}
            },
            'timestamp': datetime.utcnow().isoformat()
        }
    
    file_processing_service.process_file = process_file
    
    # Analytics Service Mock
    analytics_service = Mock()
    
    def track_event(event_name: str, properties: Dict = None, 
                   user_id: str = None) -> Dict[str, Any]:
        """Mock analytics event tracking service."""
        event_id = str(uuid.uuid4())
        
        return {
            'success': True,
            'event_id': event_id,
            'event_name': event_name,
            'properties': properties or {},
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': str(uuid.uuid4()),
            'ip_address': '127.0.0.1',
            'user_agent': 'TestAgent/1.0'
        }
    
    analytics_service.track_event = track_event
    
    logger.info(
        "third_party_apis_mock_initialized",
        services=['payment_gateway', 'notification_service', 'file_processing_service', 'analytics_service'],
        component="external_service_mocks"
    )
    
    return {
        'payment_gateway': payment_gateway,
        'notification_service': notification_service,
        'file_processing_service': file_processing_service,
        'analytics_service': analytics_service
    }


# ================================================================================================
# MONITORING AND PERFORMANCE MOCK FIXTURES - Section 6.3.5
# ================================================================================================

@pytest.fixture(scope="function")
def mock_performance_monitor():
    """
    Performance monitoring mock fixture for external service performance testing per Section 6.3.5.
    
    Provides comprehensive performance metrics collection and baseline comparison simulation
    for validating ≤10% variance requirement from Node.js implementation.
    
    Returns:
        Mock: Performance monitor with comprehensive metrics collection
    """
    monitor = Mock()
    monitor.metrics = {}
    monitor.baselines = {}
    
    def record_request_metrics(service_name: str, endpoint: str, method: str,
                             response_time: float, status_code: int,
                             request_size: int = 0, response_size: int = 0) -> Dict[str, Any]:
        """Record request metrics for performance analysis."""
        
        metric_key = f"{service_name}:{endpoint}:{method}"
        
        if metric_key not in monitor.metrics:
            monitor.metrics[metric_key] = {
                'service_name': service_name,
                'endpoint': endpoint,
                'method': method,
                'request_count': 0,
                'total_response_time': 0.0,
                'min_response_time': float('inf'),
                'max_response_time': 0.0,
                'error_count': 0,
                'success_count': 0,
                'total_request_size': 0,
                'total_response_size': 0,
                'status_codes': {},
                'response_times': []
            }
        
        metrics = monitor.metrics[metric_key]
        metrics['request_count'] += 1
        metrics['total_response_time'] += response_time
        metrics['min_response_time'] = min(metrics['min_response_time'], response_time)
        metrics['max_response_time'] = max(metrics['max_response_time'], response_time)
        metrics['total_request_size'] += request_size
        metrics['total_response_size'] += response_size
        metrics['response_times'].append(response_time)
        
        # Keep only recent response times for percentile calculation
        if len(metrics['response_times']) > 1000:
            metrics['response_times'] = metrics['response_times'][-1000:]
        
        if 200 <= status_code < 400:
            metrics['success_count'] += 1
        else:
            metrics['error_count'] += 1
        
        status_key = str(status_code)
        metrics['status_codes'][status_key] = metrics['status_codes'].get(status_key, 0) + 1
        
        # Calculate percentiles
        sorted_times = sorted(metrics['response_times'])
        count = len(sorted_times)
        if count > 0:
            p50_idx = int(count * 0.5)
            p95_idx = int(count * 0.95)
            p99_idx = int(count * 0.99)
            
            metrics['p50_response_time'] = sorted_times[p50_idx]
            metrics['p95_response_time'] = sorted_times[p95_idx] if p95_idx < count else sorted_times[-1]
            metrics['p99_response_time'] = sorted_times[p99_idx] if p99_idx < count else sorted_times[-1]
            metrics['avg_response_time'] = metrics['total_response_time'] / metrics['request_count']
        
        return {
            'recorded': True,
            'metric_key': metric_key,
            'response_time': response_time,
            'status_code': status_code,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def set_baseline(service_name: str, endpoint: str, method: str,
                    baseline_metrics: Dict[str, float]):
        """Set performance baseline for Node.js comparison."""
        baseline_key = f"{service_name}:{endpoint}:{method}"
        monitor.baselines[baseline_key] = {
            **baseline_metrics,
            'set_at': datetime.utcnow().isoformat()
        }
        
        logger.info(
            "performance_baseline_set",
            service_name=service_name,
            endpoint=endpoint,
            method=method,
            baseline_metrics=baseline_metrics,
            component="external_service_mocks"
        )
    
    def compare_with_baseline(service_name: str, endpoint: str, method: str) -> Dict[str, Any]:
        """Compare current metrics with Node.js baseline per Section 0.3.2."""
        metric_key = f"{service_name}:{endpoint}:{method}"
        baseline_key = metric_key
        
        if baseline_key not in monitor.baselines:
            return {
                'comparison_available': False,
                'error': 'No baseline set for this endpoint',
                'metric_key': metric_key
            }
        
        if metric_key not in monitor.metrics:
            return {
                'comparison_available': False,
                'error': 'No current metrics available',
                'metric_key': metric_key
            }
        
        current = monitor.metrics[metric_key]
        baseline = monitor.baselines[baseline_key]
        
        # Calculate variance percentages
        def calculate_variance(current_val: float, baseline_val: float) -> float:
            if baseline_val == 0:
                return 0.0
            return ((current_val - baseline_val) / baseline_val) * 100
        
        avg_response_time_variance = calculate_variance(
            current.get('avg_response_time', 0),
            baseline.get('avg_response_time', 0)
        )
        
        p95_response_time_variance = calculate_variance(
            current.get('p95_response_time', 0),
            baseline.get('p95_response_time', 0)
        )
        
        error_rate_current = (current['error_count'] / current['request_count']) * 100 if current['request_count'] > 0 else 0
        error_rate_baseline = baseline.get('error_rate', 0)
        error_rate_variance = calculate_variance(error_rate_current, error_rate_baseline)
        
        # Check ≤10% variance requirement
        variance_compliant = (
            abs(avg_response_time_variance) <= 10 and
            abs(p95_response_time_variance) <= 10 and
            abs(error_rate_variance) <= 10
        )
        
        comparison = {
            'comparison_available': True,
            'variance_compliant': variance_compliant,
            'variance_threshold': 10.0,
            'current_metrics': {
                'avg_response_time': current.get('avg_response_time', 0),
                'p95_response_time': current.get('p95_response_time', 0),
                'error_rate': error_rate_current,
                'request_count': current['request_count']
            },
            'baseline_metrics': {
                'avg_response_time': baseline.get('avg_response_time', 0),
                'p95_response_time': baseline.get('p95_response_time', 0),
                'error_rate': error_rate_baseline
            },
            'variance_analysis': {
                'avg_response_time_variance': avg_response_time_variance,
                'p95_response_time_variance': p95_response_time_variance,
                'error_rate_variance': error_rate_variance
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if not variance_compliant:
            logger.warning(
                "performance_variance_exceeded",
                service_name=service_name,
                endpoint=endpoint,
                avg_variance=avg_response_time_variance,
                p95_variance=p95_response_time_variance,
                error_rate_variance=error_rate_variance,
                component="external_service_mocks"
            )
        
        return comparison
    
    def get_all_metrics() -> Dict[str, Any]:
        """Get comprehensive metrics for all monitored services."""
        return {
            'metrics': monitor.metrics,
            'baselines': monitor.baselines,
            'total_services': len(set(key.split(':')[0] for key in monitor.metrics.keys())),
            'total_endpoints': len(monitor.metrics),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def reset_metrics(service_name: str = None):
        """Reset metrics for testing scenarios."""
        if service_name:
            # Reset metrics for specific service
            keys_to_remove = [key for key in monitor.metrics.keys() if key.startswith(f"{service_name}:")]
            for key in keys_to_remove:
                del monitor.metrics[key]
        else:
            monitor.metrics = {}
        
        logger.info(
            "performance_metrics_reset",
            service_name=service_name or "all",
            component="external_service_mocks"
        )
    
    # Set some default baselines for common scenarios
    default_baselines = [
        ('auth_service', '/validate', 'POST', {'avg_response_time': 150.0, 'p95_response_time': 300.0, 'error_rate': 1.0}),
        ('aws_s3', '/upload', 'POST', {'avg_response_time': 500.0, 'p95_response_time': 1000.0, 'error_rate': 2.0}),
        ('external_api', '/users', 'GET', {'avg_response_time': 200.0, 'p95_response_time': 400.0, 'error_rate': 0.5}),
    ]
    
    for service, endpoint, method, metrics in default_baselines:
        set_baseline(service, endpoint, method, metrics)
    
    monitor.record_request = record_request_metrics
    monitor.set_baseline = set_baseline
    monitor.compare_with_baseline = compare_with_baseline
    monitor.get_all_metrics = get_all_metrics
    monitor.reset_metrics = reset_metrics
    
    logger.info(
        "performance_monitor_mock_initialized",
        default_baselines_count=len(default_baselines),
        variance_threshold=10.0,
        component="external_service_mocks"
    )
    
    return monitor


# ================================================================================================
# COMPOSITE FIXTURE - Integration of All External Service Mocks
# ================================================================================================

@pytest.fixture(scope="function")
def external_service_mocks(mock_s3_operations, mock_httpx_client, mock_requests_client,
                          mock_circuit_breaker_manager, mock_retry_manager,
                          mock_auth0_service, mock_third_party_apis,
                          mock_performance_monitor):
    """
    Comprehensive external service mocks fixture integrating all mock services.
    
    Provides a unified interface to all external service mocks for comprehensive
    integration testing scenarios with realistic service behavior simulation.
    
    Returns:
        Dict[str, Any]: Complete external service mock environment
    """
    
    comprehensive_mocks = {
        # AWS Services
        'aws': {
            's3': mock_s3_operations,
        },
        
        # HTTP Clients
        'http': {
            'sync_client': mock_requests_client,
            'async_client': mock_httpx_client,
        },
        
        # Resilience Patterns
        'resilience': {
            'circuit_breaker': mock_circuit_breaker_manager,
            'retry_manager': mock_retry_manager,
        },
        
        # Authentication Services
        'auth': {
            'auth0': mock_auth0_service,
        },
        
        # Third-party APIs
        'third_party': mock_third_party_apis,
        
        # Monitoring and Performance
        'monitoring': {
            'performance': mock_performance_monitor,
        }
    }
    
    # Add helper methods for comprehensive testing scenarios
    def simulate_complete_workflow(workflow_type: str = 'file_upload') -> Dict[str, Any]:
        """Simulate complete workflow with all external services."""
        if workflow_type == 'file_upload':
            # Simulate complete file upload workflow
            auth_result = mock_auth0_service.validate_token(mock_auth0_service.VALID_TOKEN)
            
            if auth_result['valid']:
                # Record performance metrics
                start_time = time.time()
                
                # Simulate S3 upload
                upload_result = mock_s3_operations['upload_file'](
                    'test-file-uploads',
                    'workflow-test/sample.pdf',
                    b'Sample workflow file content'
                )
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                # Record metrics
                mock_performance_monitor.record_request(
                    'aws_s3', '/upload', 'POST', response_time, 200
                )
                
                return {
                    'workflow': 'file_upload',
                    'success': True,
                    'auth_result': auth_result,
                    'upload_result': upload_result,
                    'performance': {
                        'response_time': response_time,
                        'recorded': True
                    },
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'workflow': 'file_upload',
                    'success': False,
                    'error': 'Authentication failed',
                    'auth_result': auth_result,
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        return {
            'workflow': workflow_type,
            'success': False,
            'error': f'Unknown workflow type: {workflow_type}',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_health_status() -> Dict[str, Any]:
        """Get comprehensive health status of all mock services."""
        return {
            'status': 'healthy',
            'services': {
                'aws_s3': {'status': 'healthy', 'operations': len(mock_s3_operations)},
                'http_clients': {'status': 'healthy', 'sync_configured': True, 'async_configured': True},
                'auth0': {'status': 'healthy', 'token_validation': True},
                'circuit_breakers': {'status': 'healthy', 'active_breakers': len(mock_circuit_breaker_manager.circuit_breakers)},
                'retry_manager': {'status': 'healthy', 'services_tracked': len(mock_retry_manager.retry_stats)},
                'third_party_apis': {'status': 'healthy', 'services': len(mock_third_party_apis)},
                'performance_monitor': {'status': 'healthy', 'metrics_tracked': len(mock_performance_monitor.metrics)}
            },
            'timestamp': datetime.utcnow().isoformat()
        }
    
    comprehensive_mocks['simulate_workflow'] = simulate_complete_workflow
    comprehensive_mocks['get_health'] = get_health_status
    
    logger.info(
        "comprehensive_external_service_mocks_initialized",
        mock_categories=['aws', 'http', 'resilience', 'auth', 'third_party', 'monitoring'],
        features=['workflow_simulation', 'health_monitoring', 'performance_tracking'],
        component="external_service_mocks"
    )
    
    return comprehensive_mocks


# ================================================================================================
# MODULE-LEVEL EXPORTS AND DOCUMENTATION
# ================================================================================================

__all__ = [
    # AWS Service Mocks
    'mock_aws_credentials',
    'mock_s3_service',
    'mock_s3_operations',
    'mock_kms_service',
    
    # HTTP Client Mocks
    'mock_requests_client',
    'mock_httpx_client',
    'mock_http_error_scenarios',
    
    # Resilience Pattern Mocks
    'mock_circuit_breaker',
    'mock_circuit_breaker_manager',
    'mock_retry_manager',
    
    # Third-party Service Mocks
    'mock_auth0_service',
    'mock_third_party_apis',
    
    # Monitoring and Performance Mocks
    'mock_performance_monitor',
    
    # Comprehensive Integration Mock
    'external_service_mocks'
]

# Module initialization logging
logger.info(
    "external_service_mocks_module_loaded",
    fixtures_available=len(__all__),
    coverage_areas=[
        "aws_services",
        "http_clients", 
        "resilience_patterns",
        "third_party_apis",
        "performance_monitoring"
    ],
    compliance_requirements=[
        "section_0_1_2_external_integration",
        "section_6_3_3_resilience_patterns", 
        "section_6_3_5_performance_monitoring",
        "section_0_3_2_variance_requirement"
    ],
    component="external_service_mocks"
)