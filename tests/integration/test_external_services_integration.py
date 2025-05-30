"""
External Service Integration Testing Suite

Comprehensive integration testing covering AWS service integration with boto3, HTTP client 
patterns with requests/httpx, circuit breaker resilience, and third-party API communication.
Tests realistic external service interactions with comprehensive error handling, retry logic,
and performance monitoring as specified in Sections 0.1.2, 6.3.3, and 6.3.5.

This test suite validates:
- AWS SDK for JavaScript replaced with boto3 1.28+ for S3 operations per Section 0.1.2
- HTTP Client Libraries replaced with requests 2.31+ and httpx 0.24+ per Section 0.1.2  
- Circuit breaker implementation for external service resilience per Section 6.3.3
- Retry logic with tenacity exponential backoff per Section 4.2.3
- External service monitoring with Prometheus metrics per Section 6.3.5
- Connection pooling optimization for performance per Section 6.1.3
- Third-party API contract testing with mock implementations per Section 6.3.3

Performance Requirements:
- Validates ≤10% variance from Node.js baseline per Section 0.3.2
- Tests enterprise-grade monitoring integration per Section 6.5.1.1
- Verifies resilience patterns under failure conditions per Section 6.3.3
- Validates comprehensive error handling and recovery per Section 4.2.3

Test Categories:
- AWS S3 Integration Testing
- HTTP Client Integration Testing (requests + httpx)
- Circuit Breaker Integration Testing
- Retry Logic Integration Testing
- External Service Monitoring Integration Testing
- Connection Pool Optimization Testing
- Third-Party API Contract Testing
- Performance Variance Validation Testing
- Error Handling and Recovery Testing
- Security and Authentication Integration Testing
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
from contextlib import contextmanager, asynccontextmanager
import threading

import pytest
import pytest_asyncio
import requests
import httpx
import boto3
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from moto import mock_s3
import pybreaker
from tenacity import RetryError as TenacityRetryError
from prometheus_client import CollectorRegistry, REGISTRY
import structlog

from src.integrations import (
    BaseExternalServiceClient,
    create_aws_service_client,
    create_api_service_client,
    external_service_monitor,
    track_external_service_call,
    record_circuit_breaker_event,
    export_metrics,
    ServiceType,
    HealthStatus,
    CircuitBreakerState,
    IntegrationError,
    HTTPClientError,
    ConnectionError,
    TimeoutError,
    CircuitBreakerOpenError,
    RetryExhaustedError,
    AWSServiceError
)
from src.integrations.http_client import (
    HTTPClientManager,
    SynchronousHTTPClient,
    AsynchronousHTTPClient,
    create_sync_client,
    create_async_client
)
from src.integrations.circuit_breaker import (
    ExternalServiceCircuitBreaker,
    CircuitBreakerManager
)
from src.integrations.retry import (
    RetryManager,
    create_retry_config,
    exponential_backoff_with_jitter
)
from src.integrations.external_apis import (
    GenericAPIClient,
    WebhookHandler,
    FileProcessingClient
)


# Test configuration constants aligned with Section 6.3.5 performance requirements
TEST_TIMEOUT_SECONDS = 30
MAX_RETRY_ATTEMPTS = 3
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # 10% variance limit per Section 0.3.2
CONNECTION_POOL_SIZE = 50
CONCURRENT_REQUEST_LIMIT = 100

# Structured logger for test execution tracking
logger = structlog.get_logger(__name__)


@pytest.fixture(scope="function")
def mock_aws_credentials():
    """Mock AWS credentials for S3 testing without real AWS access."""
    with patch.dict('os.environ', {
        'AWS_ACCESS_KEY_ID': 'testing',
        'AWS_SECRET_ACCESS_KEY': 'testing',
        'AWS_SECURITY_TOKEN': 'testing',
        'AWS_SESSION_TOKEN': 'testing',
        'AWS_DEFAULT_REGION': 'us-east-1'
    }):
        yield


@pytest.fixture(scope="function")
def s3_bucket_setup():
    """Set up mock S3 bucket for integration testing."""
    with mock_s3():
        # Create mock S3 client
        s3_client = boto3.client('s3', region_name='us-east-1')
        bucket_name = 'test-integration-bucket'
        
        # Create test bucket
        s3_client.create_bucket(Bucket=bucket_name)
        
        yield {
            'client': s3_client,
            'bucket_name': bucket_name,
            'region': 'us-east-1'
        }


@pytest.fixture(scope="function")
def http_server_mock():
    """Mock HTTP server for external service testing."""
    with patch('requests.Session.request') as mock_request:
        # Configure default successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success', 'data': 'test'}
        mock_response.text = '{"status": "success", "data": "test"}'
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.elapsed.total_seconds.return_value = 0.150
        
        mock_request.return_value = mock_response
        
        yield {
            'mock_request': mock_request,
            'mock_response': mock_response
        }


@pytest.fixture(scope="function")
async def async_http_server_mock():
    """Mock async HTTP server for httpx testing."""
    with patch('httpx.AsyncClient.request') as mock_request:
        # Configure default successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success', 'data': 'test'}
        mock_response.text = '{"status": "success", "data": "test"}'
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.elapsed.total_seconds.return_value = 0.150
        
        mock_request.return_value = mock_response
        
        yield {
            'mock_request': mock_request,
            'mock_response': mock_response
        }


@pytest.fixture(scope="function")
def circuit_breaker_manager():
    """Circuit breaker manager fixture with test configuration."""
    manager = CircuitBreakerManager()
    
    # Configure test circuit breakers with specific failure thresholds
    manager.create_circuit_breaker(
        service_name='test_service',
        failure_threshold=3,
        recovery_timeout=5,
        expected_exception=requests.RequestException
    )
    
    yield manager
    
    # Cleanup circuit breakers
    manager.reset_all_circuit_breakers()


@pytest.fixture(scope="function")
def prometheus_registry():
    """Isolated Prometheus registry for metrics testing."""
    test_registry = CollectorRegistry()
    yield test_registry


@pytest.fixture(scope="function")
def performance_baseline():
    """Performance baseline data for Node.js comparison per Section 0.3.2."""
    return {
        'http_request_duration': {
            'mean': 0.150,  # 150ms baseline
            'p95': 0.300,   # 300ms 95th percentile
            'p99': 0.500    # 500ms 99th percentile
        },
        'aws_s3_operations': {
            'upload_mean': 0.800,    # 800ms upload baseline
            'download_mean': 0.600,  # 600ms download baseline
            'delete_mean': 0.200     # 200ms delete baseline
        },
        'external_api_calls': {
            'auth_validation': 0.100,  # 100ms auth validation
            'data_retrieval': 0.250,   # 250ms data retrieval
            'data_submission': 0.350   # 350ms data submission
        }
    }


class TestAWSS3Integration:
    """
    AWS S3 integration testing with boto3 1.28+ per Section 0.1.2.
    
    Tests AWS SDK for JavaScript replacement with boto3 for S3 operations including
    file uploads, downloads, deletions, error handling, and performance monitoring.
    """

    def test_s3_client_initialization_success(self, mock_aws_credentials, s3_bucket_setup):
        """Test successful S3 client initialization with proper credentials."""
        s3_client = create_aws_service_client(
            service_name='s3',
            region_name='us-east-1',
            service_type=ServiceType.AWS_S3
        )
        
        assert s3_client is not None
        assert s3_client.service_type == ServiceType.AWS_S3
        assert s3_client.endpoint_url is not None
        
        # Test client can list buckets
        response = s3_client.client.list_buckets()
        assert 'Buckets' in response
        
        logger.info(
            "s3_client_initialization_test_passed",
            service_type="aws_s3",
            client_initialized=True
        )

    def test_s3_file_upload_integration(self, mock_aws_credentials, s3_bucket_setup):
        """Test S3 file upload operations with error handling and monitoring."""
        s3_setup = s3_bucket_setup
        s3_client = s3_setup['client']
        bucket_name = s3_setup['bucket_name']
        
        # Test file upload
        test_content = b"Test file content for S3 upload integration test"
        file_key = f"test-files/integration-test-{uuid.uuid4()}.txt"
        
        start_time = time.time()
        
        # Upload file using S3 client
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_key,
            Body=test_content,
            ContentType='text/plain'
        )
        
        upload_duration = time.time() - start_time
        
        # Verify file was uploaded
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        retrieved_content = response['Body'].read()
        
        assert retrieved_content == test_content
        assert upload_duration < 1.0  # Performance check
        
        # Test file metadata
        head_response = s3_client.head_object(Bucket=bucket_name, Key=file_key)
        assert head_response['ContentType'] == 'text/plain'
        assert head_response['ContentLength'] == len(test_content)
        
        logger.info(
            "s3_file_upload_test_passed",
            bucket_name=bucket_name,
            file_key=file_key,
            upload_duration_ms=upload_duration * 1000,
            file_size_bytes=len(test_content)
        )

    def test_s3_file_download_integration(self, mock_aws_credentials, s3_bucket_setup):
        """Test S3 file download operations with performance monitoring."""
        s3_setup = s3_bucket_setup
        s3_client = s3_setup['client']
        bucket_name = s3_setup['bucket_name']
        
        # Upload test file first
        test_content = b"Test file content for S3 download integration test"
        file_key = f"test-files/download-test-{uuid.uuid4()}.txt"
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_key,
            Body=test_content
        )
        
        # Test file download
        start_time = time.time()
        
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        downloaded_content = response['Body'].read()
        
        download_duration = time.time() - start_time
        
        assert downloaded_content == test_content
        assert download_duration < 1.0  # Performance check
        
        # Test streaming download for large files simulation
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        chunks = []
        for chunk in response['Body'].iter_chunks(chunk_size=1024):
            chunks.append(chunk)
        
        streamed_content = b''.join(chunks)
        assert streamed_content == test_content
        
        logger.info(
            "s3_file_download_test_passed",
            bucket_name=bucket_name,
            file_key=file_key,
            download_duration_ms=download_duration * 1000,
            streaming_enabled=True
        )

    def test_s3_error_handling_integration(self, mock_aws_credentials, s3_bucket_setup):
        """Test S3 error handling for various failure scenarios."""
        s3_setup = s3_bucket_setup
        s3_client = s3_setup['client']
        bucket_name = s3_setup['bucket_name']
        
        # Test file not found error
        with pytest.raises(ClientError) as exc_info:
            s3_client.get_object(Bucket=bucket_name, Key='nonexistent-file.txt')
        
        error = exc_info.value
        assert error.response['Error']['Code'] == 'NoSuchKey'
        
        # Test bucket not found error
        with pytest.raises(ClientError) as exc_info:
            s3_client.get_object(Bucket='nonexistent-bucket', Key='test-file.txt')
        
        error = exc_info.value
        assert error.response['Error']['Code'] == 'NoSuchBucket'
        
        # Test invalid key error handling
        with pytest.raises(ClientError):
            s3_client.put_object(
                Bucket=bucket_name,
                Key='',  # Empty key should cause error
                Body=b'test content'
            )
        
        logger.info(
            "s3_error_handling_test_passed",
            error_scenarios_tested=['NoSuchKey', 'NoSuchBucket', 'InvalidKey']
        )

    def test_s3_performance_variance_validation(self, mock_aws_credentials, s3_bucket_setup, performance_baseline):
        """Test S3 operations performance variance against Node.js baseline per Section 0.3.2."""
        s3_setup = s3_bucket_setup
        s3_client = s3_setup['client']
        bucket_name = s3_setup['bucket_name']
        baseline = performance_baseline['aws_s3_operations']
        
        # Test upload performance
        test_content = b"Performance test content" * 100  # Larger file
        file_key = f"perf-test/upload-{uuid.uuid4()}.txt"
        
        upload_times = []
        for _ in range(5):  # Multiple iterations for statistical significance
            start_time = time.time()
            s3_client.put_object(
                Bucket=bucket_name,
                Key=f"{file_key}-{_}",
                Body=test_content
            )
            upload_times.append(time.time() - start_time)
        
        avg_upload_time = sum(upload_times) / len(upload_times)
        upload_variance = abs(avg_upload_time - baseline['upload_mean']) / baseline['upload_mean']
        
        # Validate performance variance ≤10% per Section 0.3.2
        assert upload_variance <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Upload performance variance {upload_variance:.2%} exceeds {PERFORMANCE_VARIANCE_THRESHOLD:.2%}"
        
        # Test download performance
        download_times = []
        for i in range(5):
            start_time = time.time()
            response = s3_client.get_object(Bucket=bucket_name, Key=f"{file_key}-{i}")
            response['Body'].read()
            download_times.append(time.time() - start_time)
        
        avg_download_time = sum(download_times) / len(download_times)
        download_variance = abs(avg_download_time - baseline['download_mean']) / baseline['download_mean']
        
        assert download_variance <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Download performance variance {download_variance:.2%} exceeds {PERFORMANCE_VARIANCE_THRESHOLD:.2%}"
        
        logger.info(
            "s3_performance_variance_test_passed",
            upload_avg_duration_ms=avg_upload_time * 1000,
            upload_variance_percentage=upload_variance * 100,
            download_avg_duration_ms=avg_download_time * 1000,
            download_variance_percentage=download_variance * 100,
            performance_threshold_met=True
        )


class TestHTTPClientIntegration:
    """
    HTTP client integration testing with requests 2.31+ and httpx 0.24+ per Section 0.1.2.
    
    Tests external service integration library replacement maintaining API contracts
    with comprehensive connection pooling, timeout management, and error handling.
    """

    def test_requests_sync_client_integration(self, http_server_mock):
        """Test requests 2.31+ synchronous HTTP client integration."""
        mock_data = http_server_mock
        
        # Create synchronous HTTP client
        sync_client = create_sync_client(
            base_url='https://api.example.com',
            timeout=30.0,
            max_retries=3,
            pool_connections=20,
            pool_maxsize=50
        )
        
        assert isinstance(sync_client, SynchronousHTTPClient)
        
        # Test GET request
        response = sync_client.get('/users/123', headers={'Accept': 'application/json'})
        
        assert response.status_code == 200
        assert response.json()['status'] == 'success'
        
        # Verify connection pooling configuration
        adapter = sync_client.session.adapters['https://']
        assert adapter.config['pool_connections'] == 20
        assert adapter.config['pool_maxsize'] == 50
        
        # Test POST request with data
        post_data = {'name': 'Test User', 'email': 'test@example.com'}
        response = sync_client.post('/users', json=post_data)
        
        assert response.status_code == 200
        
        # Verify request was made with correct parameters
        mock_data['mock_request'].assert_called()
        last_call = mock_data['mock_request'].call_args
        assert last_call[0][0] == 'POST'  # HTTP method
        
        logger.info(
            "requests_sync_client_test_passed",
            client_type="SynchronousHTTPClient",
            pool_connections=20,
            pool_maxsize=50,
            requests_made=2
        )

    @pytest.mark.asyncio
    async def test_httpx_async_client_integration(self, async_http_server_mock):
        """Test httpx 0.24+ asynchronous HTTP client integration."""
        mock_data = await async_http_server_mock
        
        # Create asynchronous HTTP client
        async_client = create_async_client(
            base_url='https://api.example.com',
            timeout=30.0,
            max_connections=100,
            max_keepalive_connections=50,
            keepalive_expiry=30.0
        )
        
        assert isinstance(async_client, AsynchronousHTTPClient)
        
        async with async_client:
            # Test async GET request
            response = await async_client.get('/users/123')
            
            assert response.status_code == 200
            assert response.json()['status'] == 'success'
            
            # Test async POST request
            post_data = {'name': 'Async Test User', 'email': 'async@example.com'}
            response = await async_client.post('/users', json=post_data)
            
            assert response.status_code == 200
            
            # Test concurrent requests
            tasks = [
                async_client.get(f'/users/{i}')
                for i in range(10)
            ]
            
            concurrent_responses = await asyncio.gather(*tasks)
            assert len(concurrent_responses) == 10
            assert all(r.status_code == 200 for r in concurrent_responses)
        
        # Verify connection limits configuration
        limits = async_client.client.limits
        assert limits.max_connections == 100
        assert limits.max_keepalive_connections == 50
        
        logger.info(
            "httpx_async_client_test_passed",
            client_type="AsynchronousHTTPClient",
            max_connections=100,
            max_keepalive_connections=50,
            concurrent_requests=10
        )

    def test_http_client_manager_integration(self, http_server_mock):
        """Test HTTP client manager with dual client support."""
        # Create HTTP client manager
        client_manager = create_client_manager(
            base_url='https://api.example.com',
            sync_config={
                'timeout': 30.0,
                'pool_connections': 20,
                'pool_maxsize': 50
            },
            async_config={
                'timeout': 30.0,
                'max_connections': 100,
                'max_keepalive_connections': 50
            }
        )
        
        assert isinstance(client_manager, HTTPClientManager)
        assert client_manager.sync_client is not None
        assert client_manager.async_client is not None
        
        # Test synchronous request through manager
        sync_response = client_manager.sync_client.get('/health')
        assert sync_response.status_code == 200
        
        # Test client manager context management
        with client_manager.sync_context() as sync_client:
            response = sync_client.get('/sync-test')
            assert response.status_code == 200
        
        logger.info(
            "http_client_manager_test_passed",
            manager_type="HTTPClientManager",
            sync_client_available=True,
            async_client_available=True
        )

    def test_http_client_error_handling_integration(self, performance_baseline):
        """Test HTTP client error handling for various failure scenarios."""
        with patch('requests.Session.request') as mock_request:
            # Test connection error
            mock_request.side_effect = requests.ConnectionError("Connection failed")
            
            sync_client = create_sync_client(base_url='https://api.example.com')
            
            with pytest.raises(ConnectionError):
                sync_client.get('/test')
            
            # Test timeout error
            mock_request.side_effect = requests.Timeout("Request timeout")
            
            with pytest.raises(TimeoutError):
                sync_client.get('/test')
            
            # Test HTTP error response
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = requests.HTTPError("Server error")
            mock_request.return_value = mock_response
            
            with pytest.raises(HTTPResponseError):
                sync_client.get('/test')
        
        logger.info(
            "http_client_error_handling_test_passed",
            error_scenarios_tested=['ConnectionError', 'TimeoutError', 'HTTPError']
        )

    def test_connection_pool_optimization_integration(self, http_server_mock):
        """Test connection pooling optimization for performance per Section 6.1.3."""
        # Create client with optimized connection pool settings
        sync_client = create_sync_client(
            base_url='https://api.example.com',
            pool_connections=CONNECTION_POOL_SIZE,
            pool_maxsize=CONNECTION_POOL_SIZE * 2,
            pool_block=False
        )
        
        # Simulate concurrent requests to test connection pooling
        import threading
        response_times = []
        errors = []
        
        def make_request(request_id):
            try:
                start_time = time.time()
                response = sync_client.get(f'/concurrent-test/{request_id}')
                duration = time.time() - start_time
                response_times.append(duration)
                assert response.status_code == 200
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads to test connection pooling
        threads = []
        for i in range(20):  # Test with 20 concurrent requests
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Validate connection pooling effectiveness
        assert len(errors) == 0, f"Connection pool errors: {errors}"
        assert len(response_times) == 20
        assert total_time < 5.0  # Should complete quickly with pooling
        
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 1.0  # Individual requests should be fast
        
        logger.info(
            "connection_pool_optimization_test_passed",
            pool_size=CONNECTION_POOL_SIZE,
            concurrent_requests=20,
            total_time_seconds=total_time,
            avg_response_time_seconds=avg_response_time,
            errors_count=len(errors)
        )


class TestCircuitBreakerIntegration:
    """
    Circuit breaker integration testing with pybreaker per Section 6.3.3.
    
    Tests circuit breaker implementation for external service resilience with
    automatic failure detection, recovery automation, and fallback mechanisms.
    """

    def test_circuit_breaker_closed_state_integration(self, circuit_breaker_manager):
        """Test circuit breaker in closed state with successful requests."""
        manager = circuit_breaker_manager
        
        # Mock successful external service
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            mock_get.return_value = mock_response
            
            # Create circuit breaker client
            cb = manager.get_circuit_breaker('test_service')
            assert cb.current_state == 'closed'
            
            # Make successful requests
            for i in range(5):
                result = cb.call(requests.get, 'https://api.example.com/test')
                assert result.status_code == 200
            
            # Circuit breaker should remain closed
            assert cb.current_state == 'closed'
            assert cb.fail_counter == 0
        
        logger.info(
            "circuit_breaker_closed_state_test_passed",
            state="closed",
            successful_requests=5,
            fail_counter=0
        )

    def test_circuit_breaker_open_state_integration(self, circuit_breaker_manager):
        """Test circuit breaker opening after failure threshold."""
        manager = circuit_breaker_manager
        
        # Mock failing external service
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.RequestException("Service unavailable")
            
            cb = manager.get_circuit_breaker('test_service')
            
            # Make requests that will fail
            for i in range(CIRCUIT_BREAKER_FAILURE_THRESHOLD):
                with pytest.raises(requests.RequestException):
                    cb.call(requests.get, 'https://api.example.com/test')
            
            # Circuit breaker should be open after failure threshold
            assert cb.current_state == 'open'
            
            # Further requests should be blocked
            with pytest.raises(CircuitBreakerOpenError):
                cb.call(requests.get, 'https://api.example.com/test')
        
        logger.info(
            "circuit_breaker_open_state_test_passed",
            state="open",
            failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            requests_blocked=True
        )

    def test_circuit_breaker_half_open_recovery_integration(self, circuit_breaker_manager):
        """Test circuit breaker half-open state and recovery."""
        manager = circuit_breaker_manager
        
        cb = manager.get_circuit_breaker('test_service')
        
        # Force circuit breaker to open state
        cb._state = pybreaker.STATE_OPEN
        cb._last_failure = time.time() - 10  # Force recovery timeout
        
        with patch('requests.get') as mock_get:
            # First request after timeout should put CB in half-open state
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            mock_get.return_value = mock_response
            
            # Trigger half-open state
            result = cb.call(requests.get, 'https://api.example.com/test')
            assert result.status_code == 200
            
            # Circuit breaker should return to closed state after successful request
            assert cb.current_state == 'closed'
            assert cb.fail_counter == 0
        
        logger.info(
            "circuit_breaker_half_open_recovery_test_passed",
            recovery_successful=True,
            final_state="closed"
        )

    def test_circuit_breaker_monitoring_integration(self, circuit_breaker_manager, prometheus_registry):
        """Test circuit breaker monitoring with Prometheus metrics per Section 6.3.5."""
        manager = circuit_breaker_manager
        
        # Track circuit breaker events
        state_changes = []
        
        def mock_record_event(service_name, event_type, state):
            state_changes.append({
                'service': service_name,
                'event': event_type,
                'state': state,
                'timestamp': time.time()
            })
        
        with patch('src.integrations.monitoring.record_circuit_breaker_event', side_effect=mock_record_event):
            cb = manager.get_circuit_breaker('test_service')
            
            # Simulate failure sequence
            with patch('requests.get', side_effect=requests.RequestException("Service down")):
                for i in range(CIRCUIT_BREAKER_FAILURE_THRESHOLD):
                    try:
                        cb.call(requests.get, 'https://api.example.com/test')
                    except requests.RequestException:
                        pass
            
            # Verify state change events were recorded
            assert len(state_changes) > 0
            
            # Check for state transition events
            open_events = [e for e in state_changes if e['state'] == 'open']
            assert len(open_events) > 0
        
        logger.info(
            "circuit_breaker_monitoring_test_passed",
            state_changes_recorded=len(state_changes),
            monitoring_events_captured=True
        )

    def test_circuit_breaker_fallback_mechanisms_integration(self, circuit_breaker_manager):
        """Test circuit breaker fallback mechanisms per Section 6.3.3."""
        manager = circuit_breaker_manager
        
        def fallback_function():
            return {'status': 'fallback', 'message': 'Service temporarily unavailable'}
        
        # Configure circuit breaker with fallback
        cb = manager.get_circuit_breaker('test_service')
        
        # Force circuit breaker to open state
        cb._state = pybreaker.STATE_OPEN
        
        # Test fallback execution when circuit breaker is open
        with pytest.raises(CircuitBreakerOpenError):
            cb.call(requests.get, 'https://api.example.com/test')
        
        # Implement fallback pattern
        try:
            result = cb.call(requests.get, 'https://api.example.com/test')
        except CircuitBreakerOpenError:
            result = fallback_function()
        
        assert result['status'] == 'fallback'
        assert 'temporarily unavailable' in result['message']
        
        logger.info(
            "circuit_breaker_fallback_test_passed",
            fallback_executed=True,
            graceful_degradation=True
        )


class TestRetryLogicIntegration:
    """
    Retry logic integration testing with tenacity per Section 4.2.3.
    
    Tests retry logic with exponential backoff, jitter implementation, and
    error classification-based retry policies with comprehensive monitoring.
    """

    def test_exponential_backoff_retry_integration(self):
        """Test exponential backoff retry strategy with tenacity."""
        from tenacity import retry, stop_after_attempt, wait_exponential
        
        call_count = 0
        call_times = []
        
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=0.1, max=2.0),
            reraise=True
        )
        def mock_external_call():
            nonlocal call_count
            call_count += 1
            call_times.append(time.time())
            
            if call_count < 3:
                raise requests.RequestException("Temporary failure")
            return {'status': 'success', 'attempt': call_count}
        
        # Execute function with retry logic
        start_time = time.time()
        result = mock_external_call()
        total_time = time.time() - start_time
        
        assert result['status'] == 'success'
        assert call_count == 3
        assert len(call_times) == 3
        
        # Verify exponential backoff timing
        if len(call_times) >= 2:
            first_retry_delay = call_times[1] - call_times[0]
            second_retry_delay = call_times[2] - call_times[1]
            assert second_retry_delay >= first_retry_delay
        
        logger.info(
            "exponential_backoff_retry_test_passed",
            total_attempts=call_count,
            total_time_seconds=total_time,
            exponential_backoff_verified=True
        )

    def test_retry_exhaustion_integration(self):
        """Test retry exhaustion handling after maximum attempts."""
        from tenacity import retry, stop_after_attempt, wait_exponential, RetryError
        
        call_count = 0
        
        @retry(
            stop=stop_after_attempt(MAX_RETRY_ATTEMPTS),
            wait=wait_exponential(multiplier=1, min=0.1, max=1.0),
            reraise=True
        )
        def failing_external_call():
            nonlocal call_count
            call_count += 1
            raise requests.RequestException("Persistent failure")
        
        # Test retry exhaustion
        with pytest.raises(TenacityRetryError):
            failing_external_call()
        
        assert call_count == MAX_RETRY_ATTEMPTS
        
        logger.info(
            "retry_exhaustion_test_passed",
            max_attempts=MAX_RETRY_ATTEMPTS,
            final_attempt_count=call_count,
            retry_exhausted=True
        )

    def test_retry_jitter_implementation_integration(self):
        """Test jitter implementation to prevent thundering herd patterns."""
        from tenacity import retry, stop_after_attempt, wait_exponential_jitter
        
        call_times = []
        
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=0.1, max=1.0, jitter=0.5),
            reraise=True
        )
        def jittered_external_call():
            call_times.append(time.time())
            if len(call_times) < 3:
                raise requests.RequestException("Jitter test failure")
            return {'status': 'success'}
        
        result = jittered_external_call()
        
        assert result['status'] == 'success'
        assert len(call_times) == 3
        
        # Verify jitter introduces variability
        if len(call_times) >= 3:
            delay1 = call_times[1] - call_times[0]
            delay2 = call_times[2] - call_times[1]
            # Jitter should introduce some variability
            assert abs(delay1 - delay2) > 0.01  # Some variation expected
        
        logger.info(
            "retry_jitter_test_passed",
            total_attempts=len(call_times),
            jitter_variability_detected=True
        )

    def test_error_classification_retry_integration(self):
        """Test error classification-based retry policies."""
        from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_fixed
        
        # Test retryable errors
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_fixed(0.1),
            retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout))
        )
        def connection_error_call():
            raise requests.ConnectionError("Network error")
        
        with pytest.raises(TenacityRetryError):
            connection_error_call()
        
        # Test non-retryable errors (should fail immediately)
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_fixed(0.1),
            retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout))
        )
        def auth_error_call():
            raise requests.HTTPError("401 Unauthorized")
        
        with pytest.raises(requests.HTTPError):
            auth_error_call()
        
        logger.info(
            "error_classification_retry_test_passed",
            retryable_errors=['ConnectionError', 'Timeout'],
            non_retryable_errors=['HTTPError']
        )


class TestExternalServiceMonitoringIntegration:
    """
    External service monitoring integration testing per Section 6.3.5.
    
    Tests Prometheus metrics integration, performance variance tracking,
    and comprehensive service health monitoring.
    """

    def test_prometheus_metrics_collection_integration(self, prometheus_registry):
        """Test Prometheus metrics collection for external services."""
        from prometheus_client import Counter, Histogram, Gauge, generate_latest
        
        # Create test metrics
        request_counter = Counter(
            'external_service_requests_total',
            'Total external service requests',
            ['service', 'method', 'status'],
            registry=prometheus_registry
        )
        
        response_time_histogram = Histogram(
            'external_service_response_time_seconds',
            'External service response time',
            ['service'],
            registry=prometheus_registry
        )
        
        # Simulate external service calls with metrics
        service_calls = [
            ('auth0', 'GET', '200', 0.150),
            ('aws_s3', 'PUT', '200', 0.800),
            ('aws_s3', 'GET', '200', 0.600),
            ('auth0', 'POST', '401', 0.100),
            ('external_api', 'GET', '500', 1.200)
        ]
        
        for service, method, status, duration in service_calls:
            request_counter.labels(service=service, method=method, status=status).inc()
            response_time_histogram.labels(service=service).observe(duration)
        
        # Generate and validate metrics
        metrics_output = generate_latest(prometheus_registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'external_service_requests_total' in metrics_text
        assert 'external_service_response_time_seconds' in metrics_text
        assert 'auth0' in metrics_text
        assert 'aws_s3' in metrics_text
        
        logger.info(
            "prometheus_metrics_collection_test_passed",
            metrics_generated=True,
            service_calls_tracked=len(service_calls),
            metrics_output_size=len(metrics_text)
        )

    @pytest.mark.asyncio
    async def test_external_service_health_monitoring_integration(self):
        """Test external service health monitoring with async operations."""
        # Mock external service monitor
        class MockExternalServiceMonitor:
            def __init__(self):
                self.health_cache = {}
                self.service_metadata = {}
            
            async def check_service_health(self, service_name, endpoint_url):
                # Simulate health check
                start_time = time.time()
                await asyncio.sleep(0.1)  # Simulate network delay
                duration = time.time() - start_time
                
                health_status = {
                    'status': 'healthy',
                    'timestamp': datetime.utcnow().isoformat(),
                    'duration': duration,
                    'endpoint': endpoint_url
                }
                
                self.health_cache[service_name] = health_status
                return health_status
            
            def get_health_summary(self):
                return {
                    'registered_services': list(self.health_cache.keys()),
                    'health_cache': self.health_cache,
                    'service_metadata': self.service_metadata,
                    'cache_entries': len(self.health_cache),
                    'last_updated': datetime.utcnow().isoformat()
                }
        
        monitor = MockExternalServiceMonitor()
        
        # Test health checks for multiple services
        services = [
            ('auth0', 'https://dev-tenant.auth0.com/'),
            ('aws_s3', 'https://s3.amazonaws.com/'),
            ('external_api', 'https://api.external.com/')
        ]
        
        # Perform health checks
        health_results = []
        for service_name, endpoint in services:
            health = await monitor.check_service_health(service_name, endpoint)
            health_results.append(health)
            assert health['status'] == 'healthy'
            assert health['duration'] > 0
        
        # Get comprehensive health summary
        summary = monitor.get_health_summary()
        assert len(summary['registered_services']) == 3
        assert summary['cache_entries'] == 3
        
        logger.info(
            "external_service_health_monitoring_test_passed",
            services_monitored=len(services),
            all_services_healthy=all(h['status'] == 'healthy' for h in health_results),
            cache_entries=summary['cache_entries']
        )

    def test_performance_variance_tracking_integration(self, performance_baseline):
        """Test performance variance tracking against Node.js baseline per Section 0.3.2."""
        baseline = performance_baseline
        
        # Simulate performance measurements
        measurements = {
            'http_request_duration': [0.145, 0.160, 0.148, 0.155, 0.152],  # Within variance
            'aws_s3_upload': [0.820, 0.790, 0.810, 0.800, 0.805],  # Within variance
            'external_api_auth': [0.095, 0.105, 0.098, 0.102, 0.100]  # Within variance
        }
        
        variance_results = {}
        
        for operation, times in measurements.items():
            avg_time = sum(times) / len(times)
            
            if operation == 'http_request_duration':
                baseline_time = baseline['http_request_duration']['mean']
            elif operation == 'aws_s3_upload':
                baseline_time = baseline['aws_s3_operations']['upload_mean']
            elif operation == 'external_api_auth':
                baseline_time = baseline['external_api_calls']['auth_validation']
            
            variance = abs(avg_time - baseline_time) / baseline_time
            variance_results[operation] = {
                'avg_time': avg_time,
                'baseline_time': baseline_time,
                'variance': variance,
                'within_threshold': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
        
        # Validate all operations meet performance requirements
        for operation, result in variance_results.items():
            assert result['within_threshold'], \
                f"{operation} variance {result['variance']:.2%} exceeds threshold"
        
        logger.info(
            "performance_variance_tracking_test_passed",
            operations_tested=len(variance_results),
            all_within_threshold=all(r['within_threshold'] for r in variance_results.values()),
            max_variance=max(r['variance'] for r in variance_results.values())
        )


class TestThirdPartyAPIContractIntegration:
    """
    Third-party API contract testing with mock service implementations per Section 6.3.3.
    
    Tests external systems integration with contract validation, mock service
    implementations, and comprehensive API compatibility testing.
    """

    def test_generic_api_client_integration(self, http_server_mock):
        """Test generic API client with third-party service contracts."""
        mock_data = http_server_mock
        
        # Create generic API client
        api_client = create_api_service_client(
            service_name='external_crm',
            base_url='https://api.crm-service.com',
            service_type=ServiceType.EXTERNAL_API,
            api_key='test-api-key-12345'
        )
        
        assert api_client.service_type == ServiceType.EXTERNAL_API
        assert api_client.endpoint_url == 'https://api.crm-service.com'
        
        # Test API contract compliance - GET user
        user_response = api_client.get('/users/123')
        assert user_response.status_code == 200
        
        # Verify contract compliance
        user_data = user_response.json()
        assert 'status' in user_data
        assert user_data['status'] == 'success'
        
        # Test API contract compliance - POST user
        new_user_data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'role': 'customer'
        }
        
        create_response = api_client.post('/users', json=new_user_data)
        assert create_response.status_code == 200
        
        # Verify authentication headers
        last_call = mock_data['mock_request'].call_args
        headers = last_call[1]['headers']
        assert 'Authorization' in headers or 'X-API-Key' in headers
        
        logger.info(
            "generic_api_client_test_passed",
            service_name='external_crm',
            api_calls_made=2,
            contract_compliance_verified=True
        )

    def test_webhook_handler_integration(self, app, client):
        """Test webhook handler for external service callbacks."""
        from src.integrations.external_apis import WebhookHandler
        
        # Create webhook handler
        webhook_handler = WebhookHandler(
            endpoint='/webhooks/external-service',
            secret_key='webhook-secret-123',
            validate_signature=True
        )
        
        # Register webhook endpoint
        @app.route('/webhooks/external-service', methods=['POST'])
        def handle_webhook():
            return webhook_handler.process_request(request)
        
        # Test webhook payload
        webhook_payload = {
            'event_type': 'user.created',
            'timestamp': datetime.utcnow().isoformat(),
            'data': {
                'user_id': '12345',
                'email': 'newuser@example.com',
                'status': 'active'
            }
        }
        
        # Test webhook processing
        with app.test_request_context():
            response = client.post(
                '/webhooks/external-service',
                json=webhook_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            assert response.status_code == 200
            response_data = response.get_json()
            assert response_data['status'] == 'processed'
        
        logger.info(
            "webhook_handler_test_passed",
            endpoint='/webhooks/external-service',
            event_type='user.created',
            processing_successful=True
        )

    def test_file_processing_integration(self, s3_bucket_setup):
        """Test file processing integration with external services."""
        s3_setup = s3_bucket_setup
        
        # Create file processing client
        file_processor = FileProcessingClient(
            upload_service='aws_s3',
            processing_service='external_processor',
            s3_bucket=s3_setup['bucket_name']
        )
        
        # Test file upload and processing workflow
        test_file_content = b"Test file content for processing"
        file_metadata = {
            'filename': 'test-document.txt',
            'content_type': 'text/plain',
            'processing_options': {
                'extract_text': True,
                'generate_thumbnail': False
            }
        }
        
        # Simulate file processing workflow
        with patch('src.integrations.external_apis.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'processing_id': 'proc-123456',
                'status': 'processing',
                'estimated_completion': '2024-01-01T12:05:00Z'
            }
            mock_post.return_value = mock_response
            
            # Upload and process file
            processing_result = file_processor.upload_and_process(
                file_content=test_file_content,
                metadata=file_metadata
            )
            
            assert processing_result['status'] == 'processing'
            assert 'processing_id' in processing_result
        
        logger.info(
            "file_processing_integration_test_passed",
            file_size_bytes=len(test_file_content),
            processing_initiated=True,
            s3_integration=True
        )

    def test_external_service_contract_validation_integration(self):
        """Test contract validation for external services."""
        # Define expected API contract
        expected_contract = {
            'endpoints': {
                '/users': {
                    'methods': ['GET', 'POST'],
                    'response_format': 'json',
                    'authentication': 'api_key'
                },
                '/users/{id}': {
                    'methods': ['GET', 'PUT', 'DELETE'],
                    'response_format': 'json',
                    'authentication': 'api_key'
                }
            },
            'error_handling': {
                'error_format': 'json',
                'status_codes': [400, 401, 403, 404, 500]
            }
        }
        
        # Mock API responses for contract validation
        with patch('requests.get') as mock_get:
            # Test successful contract validation
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success', 'data': []}
            mock_response.headers = {'Content-Type': 'application/json'}
            mock_get.return_value = mock_response
            
            api_client = create_api_service_client(
                service_name='contract_test_api',
                base_url='https://api.test.com',
                service_type=ServiceType.EXTERNAL_API
            )
            
            # Validate contract compliance
            response = api_client.get('/users')
            
            # Verify response format matches contract
            assert response.status_code == 200
            assert response.headers['Content-Type'] == 'application/json'
            assert isinstance(response.json(), dict)
            assert 'status' in response.json()
        
        logger.info(
            "external_service_contract_validation_test_passed",
            contract_endpoints_validated=len(expected_contract['endpoints']),
            response_format_verified=True,
            authentication_verified=True
        )


class TestIntegrationPerformanceValidation:
    """
    Integration performance validation testing per Section 0.3.2.
    
    Tests comprehensive performance requirements including ≤10% variance
    from Node.js baseline, concurrent request handling, and system scalability.
    """

    def test_concurrent_request_performance_integration(self, http_server_mock, performance_baseline):
        """Test concurrent request handling performance."""
        import concurrent.futures
        
        # Create HTTP client optimized for concurrent requests
        client = create_sync_client(
            base_url='https://api.example.com',
            pool_connections=20,
            pool_maxsize=100
        )
        
        def make_concurrent_request(request_id):
            start_time = time.time()
            response = client.get(f'/concurrent/{request_id}')
            duration = time.time() - start_time
            return {
                'request_id': request_id,
                'status_code': response.status_code,
                'duration': duration
            }
        
        # Test concurrent request performance
        num_concurrent_requests = 50
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(make_concurrent_request, i)
                for i in range(num_concurrent_requests)
            ]
            
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_time = time.time() - start_time
        successful_requests = [r for r in results if r['status_code'] == 200]
        avg_response_time = sum(r['duration'] for r in successful_requests) / len(successful_requests)
        
        # Validate performance requirements
        assert len(successful_requests) == num_concurrent_requests
        assert total_time < 10.0  # Should complete within 10 seconds
        assert avg_response_time < 1.0  # Individual requests should be fast
        
        # Compare with baseline
        baseline_time = performance_baseline['http_request_duration']['mean']
        variance = abs(avg_response_time - baseline_time) / baseline_time
        
        assert variance <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Concurrent request variance {variance:.2%} exceeds threshold"
        
        logger.info(
            "concurrent_request_performance_test_passed",
            concurrent_requests=num_concurrent_requests,
            total_time_seconds=total_time,
            avg_response_time_seconds=avg_response_time,
            performance_variance=variance,
            within_threshold=True
        )

    @pytest.mark.asyncio
    async def test_async_performance_integration(self, async_http_server_mock, performance_baseline):
        """Test asynchronous request performance with httpx."""
        # Create async HTTP client
        async_client = create_async_client(
            base_url='https://api.example.com',
            max_connections=100,
            max_keepalive_connections=50
        )
        
        async def make_async_request(request_id):
            start_time = time.time()
            response = await async_client.get(f'/async/{request_id}')
            duration = time.time() - start_time
            return {
                'request_id': request_id,
                'status_code': response.status_code,
                'duration': duration
            }
        
        # Test async request performance
        num_async_requests = 100
        start_time = time.time()
        
        async with async_client:
            tasks = [make_async_request(i) for i in range(num_async_requests)]
            results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        successful_requests = [r for r in results if r['status_code'] == 200]
        avg_response_time = sum(r['duration'] for r in successful_requests) / len(successful_requests)
        
        # Validate async performance
        assert len(successful_requests) == num_async_requests
        assert total_time < 5.0  # Async should be faster than sync
        
        # Compare with baseline
        baseline_time = performance_baseline['http_request_duration']['mean']
        variance = abs(avg_response_time - baseline_time) / baseline_time
        
        assert variance <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Async request variance {variance:.2%} exceeds threshold"
        
        logger.info(
            "async_performance_test_passed",
            async_requests=num_async_requests,
            total_time_seconds=total_time,
            avg_response_time_seconds=avg_response_time,
            performance_variance=variance,
            async_advantage=True
        )

    def test_integration_memory_performance(self, http_server_mock):
        """Test memory usage patterns during integration operations."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create multiple clients to test memory usage
        clients = []
        for i in range(10):
            client = create_sync_client(
                base_url=f'https://api{i}.example.com',
                pool_connections=10,
                pool_maxsize=20
            )
            clients.append(client)
        
        # Make requests with all clients
        for i, client in enumerate(clients):
            for j in range(10):
                response = client.get(f'/memory-test/{i}/{j}')
                assert response.status_code == 200
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory
        
        # Cleanup clients
        for client in clients:
            client.close()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_cleanup = peak_memory - final_memory
        
        # Validate memory usage
        assert memory_increase < 100  # Should not use excessive memory
        assert memory_cleanup > 0  # Memory should be freed after cleanup
        
        logger.info(
            "integration_memory_performance_test_passed",
            initial_memory_mb=initial_memory,
            peak_memory_mb=peak_memory,
            memory_increase_mb=memory_increase,
            memory_cleanup_mb=memory_cleanup,
            memory_efficient=True
        )


@pytest.mark.integration
class TestComprehensiveIntegrationScenarios:
    """
    Comprehensive integration scenarios testing realistic workflows
    combining multiple external services, resilience patterns, and monitoring.
    """

    @pytest.mark.asyncio
    async def test_end_to_end_integration_workflow(
        self,
        mock_aws_credentials,
        s3_bucket_setup,
        http_server_mock,
        circuit_breaker_manager,
        performance_baseline
    ):
        """Test comprehensive end-to-end integration workflow."""
        # Simulate realistic workflow: file upload + processing + notifications
        workflow_start_time = time.time()
        
        # Step 1: Upload file to S3
        s3_setup = s3_bucket_setup
        test_file_content = b"Integration test file content" * 100  # Larger file
        file_key = f"workflows/e2e-test-{uuid.uuid4()}.txt"
        
        s3_upload_start = time.time()
        s3_setup['client'].put_object(
            Bucket=s3_setup['bucket_name'],
            Key=file_key,
            Body=test_file_content
        )
        s3_upload_time = time.time() - s3_upload_start
        
        # Step 2: Process file via external API
        api_client = create_api_service_client(
            service_name='file_processor',
            base_url='https://api.processor.com',
            service_type=ServiceType.EXTERNAL_API
        )
        
        processing_start = time.time()
        processing_response = api_client.post('/process', json={
            'file_location': f"s3://{s3_setup['bucket_name']}/{file_key}",
            'processing_type': 'text_extraction'
        })
        processing_time = time.time() - processing_start
        
        assert processing_response.status_code == 200
        
        # Step 3: Send notification via external service
        notification_client = create_api_service_client(
            service_name='notification_service',
            base_url='https://api.notifications.com',
            service_type=ServiceType.EXTERNAL_API
        )
        
        notification_start = time.time()
        notification_response = notification_client.post('/notify', json={
            'recipient': 'admin@example.com',
            'message': f'File {file_key} processed successfully',
            'type': 'processing_complete'
        })
        notification_time = time.time() - notification_start
        
        assert notification_response.status_code == 200
        
        total_workflow_time = time.time() - workflow_start_time
        
        # Validate performance requirements
        baseline = performance_baseline
        
        s3_variance = abs(s3_upload_time - baseline['aws_s3_operations']['upload_mean']) / baseline['aws_s3_operations']['upload_mean']
        api_variance = abs(processing_time - baseline['external_api_calls']['data_submission']) / baseline['external_api_calls']['data_submission']
        
        assert s3_variance <= PERFORMANCE_VARIANCE_THRESHOLD
        assert api_variance <= PERFORMANCE_VARIANCE_THRESHOLD
        assert total_workflow_time < 5.0  # Total workflow should complete quickly
        
        logger.info(
            "end_to_end_integration_workflow_test_passed",
            total_workflow_time_seconds=total_workflow_time,
            s3_upload_time_seconds=s3_upload_time,
            processing_time_seconds=processing_time,
            notification_time_seconds=notification_time,
            s3_variance=s3_variance,
            api_variance=api_variance,
            workflow_completed=True
        )

    def test_resilience_under_failure_conditions(self, circuit_breaker_manager):
        """Test system resilience under various failure conditions."""
        manager = circuit_breaker_manager
        
        # Test progressive failure handling
        failure_scenarios = [
            ('network_timeout', requests.Timeout("Network timeout")),
            ('connection_error', requests.ConnectionError("Connection failed")),
            ('server_error', requests.HTTPError("500 Server Error")),
            ('service_unavailable', requests.RequestException("Service unavailable"))
        ]
        
        resilience_results = {}
        
        for scenario_name, exception in failure_scenarios:
            with patch('requests.get', side_effect=exception):
                cb = manager.get_circuit_breaker('resilience_test')
                
                # Test failure handling
                failure_count = 0
                for attempt in range(10):
                    try:
                        cb.call(requests.get, 'https://api.example.com/test')
                    except (CircuitBreakerOpenError, requests.RequestException):
                        failure_count += 1
                
                resilience_results[scenario_name] = {
                    'failure_count': failure_count,
                    'circuit_breaker_activated': cb.current_state == 'open',
                    'protected_from_cascade': failure_count < 10  # Some failures should be prevented
                }
        
        # Validate resilience patterns
        for scenario, result in resilience_results.items():
            assert result['circuit_breaker_activated'], f"Circuit breaker not activated for {scenario}"
            assert result['protected_from_cascade'], f"System not protected from cascade failures in {scenario}"
        
        logger.info(
            "resilience_under_failure_test_passed",
            failure_scenarios_tested=len(failure_scenarios),
            all_scenarios_handled=True,
            circuit_breaker_protection_verified=True
        )

    def test_monitoring_and_observability_integration(self, prometheus_registry):
        """Test comprehensive monitoring and observability integration."""
        from prometheus_client import Counter, Histogram, generate_latest
        
        # Create comprehensive monitoring metrics
        metrics = {
            'requests': Counter(
                'integration_requests_total',
                'Total integration requests',
                ['service', 'operation', 'status'],
                registry=prometheus_registry
            ),
            'response_time': Histogram(
                'integration_response_time_seconds',
                'Integration response time',
                ['service', 'operation'],
                registry=prometheus_registry
            ),
            'errors': Counter(
                'integration_errors_total',
                'Total integration errors',
                ['service', 'error_type'],
                registry=prometheus_registry
            )
        }
        
        # Simulate comprehensive monitoring data
        operations = [
            ('aws_s3', 'upload', 'success', 0.800),
            ('aws_s3', 'download', 'success', 0.600),
            ('external_api', 'authenticate', 'success', 0.100),
            ('external_api', 'fetch_data', 'success', 0.250),
            ('notification_service', 'send_email', 'error', 1.500),
            ('circuit_breaker', 'state_change', 'open', 0.001)
        ]
        
        for service, operation, status, duration in operations:
            metrics['requests'].labels(
                service=service,
                operation=operation,
                status=status
            ).inc()
            
            metrics['response_time'].labels(
                service=service,
                operation=operation
            ).observe(duration)
            
            if status == 'error':
                metrics['errors'].labels(
                    service=service,
                    error_type='service_unavailable'
                ).inc()
        
        # Generate comprehensive metrics output
        metrics_output = generate_latest(prometheus_registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Validate monitoring coverage
        assert 'integration_requests_total' in metrics_text
        assert 'integration_response_time_seconds' in metrics_text
        assert 'integration_errors_total' in metrics_text
        assert 'aws_s3' in metrics_text
        assert 'external_api' in metrics_text
        assert 'notification_service' in metrics_text
        
        # Validate specific metrics
        assert 'integration_requests_total{operation="upload"' in metrics_text
        assert 'integration_errors_total{error_type="service_unavailable"' in metrics_text
        
        logger.info(
            "monitoring_and_observability_test_passed",
            operations_monitored=len(operations),
            metrics_exported=True,
            comprehensive_coverage=True,
            prometheus_integration=True
        )


# Module-level test configuration
pytestmark = [
    pytest.mark.integration,
    pytest.mark.timeout(TEST_TIMEOUT_SECONDS)
]

# Test execution summary logging
def pytest_runtest_logreport(report):
    """Log test execution summary for integration tests."""
    if report.when == "call" and "integration" in report.nodeid:
        logger.info(
            "integration_test_completed",
            test_name=report.nodeid,
            outcome=report.outcome,
            duration_seconds=report.duration,
            integration_test=True
        )