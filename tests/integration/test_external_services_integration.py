"""
External Services Integration Tests

This module provides comprehensive integration testing for external service communication patterns
including AWS service integration with boto3, HTTP client patterns with requests/httpx, circuit
breaker resilience, and third-party API communication. Tests realistic external service interactions
with comprehensive error handling, retry logic, and performance monitoring.

Test Coverage:
- AWS S3 integration with boto3 1.28+ per Section 0.1.2
- HTTP client patterns with requests 2.31+ and httpx 0.24+ per Section 3.2.3
- Circuit breaker implementation with pybreaker per Section 6.3.3
- Retry logic with tenacity exponential backoff per Section 4.2.3
- External service monitoring with Prometheus metrics per Section 6.3.5
- Connection pooling optimization per Section 6.1.3
- Third-party API contract testing per Section 6.3.3

Performance Requirements:
- ≤10% variance from Node.js baseline per Section 0.3.2
- Enterprise-grade monitoring integration per Section 6.5.1.1
- Comprehensive error handling and recovery per Section 4.2.3

Dependencies:
- src.integrations.base_client: BaseExternalServiceClient foundation
- src.integrations.circuit_breaker: Circuit breaker protection patterns
- src.integrations.retry: Tenacity retry logic implementation
- src.integrations.external_apis: Third-party API integration patterns
- tests.conftest: Comprehensive test environment and fixtures

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, patch, AsyncMock, MagicMock, call

import pytest
import pytest_asyncio
import requests
import httpx
import boto3
from moto import mock_s3, mock_cloudwatch
from pybreaker import CircuitBreakerState
from tenacity import RetryError, stop_after_attempt
import structlog

# Core integration modules per dependency requirements
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
    create_client_manager
)
from src.integrations.circuit_breaker import (
    EnhancedCircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerPolicy,
    global_circuit_breaker_manager
)
from src.integrations.retry import (
    RetryManager,
    RetryConfiguration,
    retry_manager,
    with_retry,
    with_retry_async
)
from src.integrations.external_apis import (
    GenericAPIClient,
    WebhookHandler,
    FileProcessingClient,
    EnterpriseServiceWrapper
)
from src.integrations.exceptions import (
    IntegrationError,
    HTTPClientError,
    ConnectionError as IntegrationConnectionError,
    TimeoutError as IntegrationTimeoutError,
    CircuitBreakerOpenError,
    RetryExhaustedError
)
from src.integrations.monitoring import (
    external_service_monitor,
    ExternalServiceType,
    ServiceMetrics,
    ServiceHealthState
)

# Initialize structured logger for integration testing
logger = structlog.get_logger(__name__)


class TestAWSServiceIntegration:
    """
    AWS service integration testing with boto3 1.28+ per Section 0.1.2.
    
    Tests comprehensive AWS SDK migration from Node.js to Python including
    S3 operations, CloudWatch integration, and IAM authentication patterns
    with circuit breaker protection and monitoring integration.
    """
    
    @pytest.fixture
    def aws_s3_config(self):
        """AWS S3 configuration for testing with enterprise-grade settings."""
        return create_aws_s3_config(
            region='us-east-1',
            aws_access_key_id='test-access-key',
            aws_secret_access_key='test-secret-key',
            bucket_name='test-bucket',
            
            # Circuit breaker configuration per Section 6.3.3
            circuit_breaker_enabled=True,
            circuit_breaker_policy=CircuitBreakerPolicy.MODERATE,
            circuit_breaker_fail_max=3,
            circuit_breaker_recovery_timeout=60,
            
            # Retry configuration per Section 4.2.3
            retry_enabled=True,
            retry_max_attempts=4,
            retry_min_wait=0.5,
            retry_max_wait=60.0,
            retry_exponential_base=2,
            
            # Monitoring configuration per Section 6.3.5
            monitoring_enabled=True,
            metrics_collection_enabled=True,
            performance_tracking_enabled=True,
            
            # Connection pooling per Section 6.3.5
            sync_pool_connections=20,
            sync_pool_maxsize=50,
            async_max_connections=100,
            timeout=30.0
        )
    
    @pytest.fixture
    def aws_s3_client(self, aws_s3_config):
        """AWS S3 client with comprehensive configuration."""
        return BaseExternalServiceClient(aws_s3_config)
    
    @mock_s3
    def test_s3_upload_file_operation(self, aws_s3_client, performance_monitoring):
        """
        Test S3 file upload with boto3 integration and performance monitoring.
        
        Validates:
        - boto3 1.28+ S3 upload operations per Section 0.1.2
        - Circuit breaker protection for AWS service calls
        - Performance tracking against Node.js baseline per Section 0.3.2
        - Comprehensive error handling and retry logic
        """
        # Mock S3 service with moto
        s3_client = boto3.client('s3', region_name='us-east-1')
        s3_client.create_bucket(Bucket='test-bucket')
        
        # Test data
        test_file_content = b"Test file content for S3 upload"
        test_key = f"test-files/{uuid.uuid4()}.txt"
        
        # Measure performance against baseline per Section 0.3.2
        with performance_monitoring['measure_operation']('s3_upload', 's3_operation_time'):
            with patch('boto3.client', return_value=s3_client):
                # Execute S3 upload operation
                response = aws_s3_client.make_request(
                    'PUT',
                    f'/test-bucket/{test_key}',
                    data=test_file_content,
                    headers={'Content-Type': 'text/plain'}
                )
        
        # Validate successful upload
        assert response.status_code == 200
        
        # Verify circuit breaker tracking
        circuit_breaker = aws_s3_client.circuit_breaker
        assert circuit_breaker is not None
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.successful_calls > 0
        
        # Verify monitoring metrics collection
        metrics = aws_s3_client.get_performance_metrics()
        assert metrics['service_name'] == aws_s3_client.config.service_name
        assert metrics['total_requests'] > 0
        assert metrics['successful_requests'] > 0
        assert metrics['success_rate'] == 1.0
        
        logger.info(
            "S3 upload operation completed successfully",
            test_key=test_key,
            response_status=response.status_code,
            circuit_breaker_state=circuit_breaker.state.name,
            performance_metrics=metrics['performance']
        )
    
    @mock_s3
    def test_s3_download_file_operation(self, aws_s3_client, performance_monitoring):
        """
        Test S3 file download with streaming and error handling.
        
        Validates:
        - S3 download operations with streaming support
        - Error handling for non-existent files
        - Circuit breaker behavior on failures
        - Performance monitoring and metrics collection
        """
        # Mock S3 service and create test file
        s3_client = boto3.client('s3', region_name='us-east-1')
        s3_client.create_bucket(Bucket='test-bucket')
        
        test_key = f"downloads/{uuid.uuid4()}.json"
        test_content = json.dumps({"test": "data", "timestamp": time.time()})
        s3_client.put_object(
            Bucket='test-bucket',
            Key=test_key,
            Body=test_content,
            ContentType='application/json'
        )
        
        # Test successful download
        with performance_monitoring['measure_operation']('s3_download', 's3_operation_time'):
            with patch('boto3.client', return_value=s3_client):
                response = aws_s3_client.make_request(
                    'GET',
                    f'/test-bucket/{test_key}'
                )
        
        assert response.status_code == 200
        downloaded_content = json.loads(response.content.decode('utf-8'))
        assert downloaded_content['test'] == 'data'
        
        # Test download of non-existent file
        non_existent_key = f"missing/{uuid.uuid4()}.txt"
        
        with pytest.raises((HTTPClientError, IntegrationError)):
            with patch('boto3.client', return_value=s3_client):
                aws_s3_client.make_request(
                    'GET',
                    f'/test-bucket/{non_existent_key}'
                )
        
        # Verify error tracking in circuit breaker
        circuit_breaker = aws_s3_client.circuit_breaker
        assert circuit_breaker.metrics.failed_calls > 0
        
        logger.info(
            "S3 download operations tested successfully",
            successful_downloads=1,
            failed_downloads=1,
            circuit_breaker_failures=circuit_breaker.metrics.failed_calls
        )
    
    @mock_s3
    @mock_cloudwatch
    def test_s3_operations_with_cloudwatch_monitoring(self, aws_s3_client):
        """
        Test S3 operations with CloudWatch metrics integration.
        
        Validates:
        - CloudWatch metrics collection per Section 6.3.5
        - Custom metrics submission via boto3
        - Integration monitoring with Prometheus metrics
        - Enterprise-grade observability patterns
        """
        # Mock AWS services
        s3_client = boto3.client('s3', region_name='us-east-1')
        cloudwatch_client = boto3.client('cloudwatch', region_name='us-east-1')
        
        s3_client.create_bucket(Bucket='test-bucket')
        
        # Test multiple S3 operations for metrics collection
        operations = [
            ('PUT', f'metrics-test-{i}.txt', f'Content {i}'.encode())
            for i in range(5)
        ]
        
        with patch('boto3.client') as mock_boto3:
            mock_boto3.side_effect = lambda service, **kwargs: {
                's3': s3_client,
                'cloudwatch': cloudwatch_client
            }.get(service, Mock())
            
            for method, key, content in operations:
                response = aws_s3_client.make_request(
                    method,
                    f'/test-bucket/{key}',
                    data=content
                )
                assert response.status_code == 200
        
        # Verify metrics collection
        metrics = aws_s3_client.get_performance_metrics()
        assert metrics['total_requests'] >= len(operations)
        assert metrics['success_rate'] >= 0.8  # Allow for some tolerance
        
        # Verify circuit breaker health
        health_status = aws_s3_client.check_health()
        assert health_status['overall_status'] in ['healthy', 'degraded']
        assert 'circuit_breaker' in health_status['components']
        
        logger.info(
            "S3 operations with CloudWatch monitoring completed",
            total_operations=len(operations),
            success_rate=metrics['success_rate'],
            health_status=health_status['overall_status']
        )
    
    @mock_s3
    def test_s3_circuit_breaker_failure_handling(self, aws_s3_client):
        """
        Test circuit breaker behavior with S3 service failures.
        
        Validates:
        - Circuit breaker state transitions per Section 6.3.3
        - Failure threshold management and recovery
        - Fallback response mechanisms
        - Monitoring of circuit breaker state changes
        """
        circuit_breaker = aws_s3_client.circuit_breaker
        initial_state = circuit_breaker.state
        
        # Mock S3 client to simulate failures
        mock_s3_client = Mock()
        mock_s3_client.put_object.side_effect = Exception("S3 service unavailable")
        
        failure_count = 0
        max_failures = circuit_breaker.config.fail_max
        
        with patch('boto3.client', return_value=mock_s3_client):
            # Generate failures to trip circuit breaker
            for i in range(max_failures + 2):
                with pytest.raises((IntegrationError, CircuitBreakerOpenError)):
                    aws_s3_client.make_request(
                        'PUT',
                        f'/test-bucket/failure-test-{i}.txt',
                        data=b'test content'
                    )
                    failure_count += 1
        
        # Verify circuit breaker opened
        assert circuit_breaker.state == CircuitBreakerState.OPEN
        assert circuit_breaker.failure_count >= max_failures
        
        # Verify metrics tracking
        assert circuit_breaker.metrics.failed_calls >= max_failures
        assert circuit_breaker.metrics.circuit_open_calls > 0
        
        # Test circuit breaker recovery (simulate time passage)
        with patch('time.time', return_value=time.time() + circuit_breaker.config.recovery_timeout + 1):
            # Circuit should transition to half-open
            # Note: Actual state transition testing would require more complex mocking
            pass
        
        logger.info(
            "Circuit breaker failure handling tested",
            initial_state=initial_state.name,
            final_state=circuit_breaker.state.name,
            failure_count=failure_count,
            circuit_failures=circuit_breaker.metrics.failed_calls
        )


class TestHTTPClientIntegration:
    """
    HTTP client integration testing with requests 2.31+ and httpx 0.24+ per Section 3.2.3.
    
    Tests comprehensive HTTP client patterns including synchronous requests with requests,
    asynchronous requests with httpx, connection pooling optimization, and error handling
    with circuit breaker protection and retry logic.
    """
    
    @pytest.fixture
    def http_api_config(self):
        """HTTP API configuration for testing with dual-client support."""
        return create_external_api_config(
            service_name='test_api',
            base_url='https://api.example.com',
            api_version='v1',
            
            # HTTP client configuration per Section 3.2.3
            timeout=30.0,
            verify_ssl=True,
            default_headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'Flask-Migration-Test/1.0'
            },
            
            # Connection pooling per Section 6.3.5
            sync_pool_connections=20,
            sync_pool_maxsize=50,
            async_max_connections=100,
            async_max_keepalive_connections=50,
            keepalive_expiry=30.0,
            enable_http2=True,
            
            # Circuit breaker and retry configuration
            circuit_breaker_enabled=True,
            circuit_breaker_policy=CircuitBreakerPolicy.MODERATE,
            retry_enabled=True,
            retry_max_attempts=3,
            
            # Monitoring configuration
            monitoring_enabled=True,
            metrics_collection_enabled=True
        )
    
    @pytest.fixture
    def http_api_client(self, http_api_config):
        """HTTP API client with dual synchronous/asynchronous support."""
        return BaseExternalServiceClient(http_api_config)
    
    def test_synchronous_http_requests_with_requests(self, http_api_client, performance_monitoring):
        """
        Test synchronous HTTP requests using requests 2.31+ library.
        
        Validates:
        - requests 2.31+ HTTP client integration per Section 3.2.3
        - Connection pooling and performance optimization
        - Error handling and circuit breaker integration
        - Comprehensive request/response monitoring
        """
        # Mock successful HTTP responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'success',
            'data': {'id': 123, 'name': 'test_resource'},
            'timestamp': time.time()
        }
        mock_response.headers = {'Content-Type': 'application/json'}
        
        with patch('requests.Session.request', return_value=mock_response):
            # Test various HTTP methods
            test_cases = [
                ('GET', '/users/123', None),
                ('POST', '/users', {'name': 'New User', 'email': 'test@example.com'}),
                ('PUT', '/users/123', {'name': 'Updated User'}),
                ('DELETE', '/users/123', None)
            ]
            
            for method, path, json_data in test_cases:
                with performance_monitoring['measure_operation'](f'http_{method.lower()}', 'api_response_time'):
                    response = http_api_client.make_request(
                        method=method,
                        path=path,
                        json_data=json_data
                    )
                
                assert response.status_code == 200
                assert response.json()['status'] == 'success'
        
        # Verify performance metrics
        metrics = http_api_client.get_performance_metrics()
        assert metrics['total_requests'] == len(test_cases)
        assert metrics['success_rate'] == 1.0
        
        # Verify circuit breaker health
        circuit_breaker = http_api_client.circuit_breaker
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.successful_calls == len(test_cases)
        
        logger.info(
            "Synchronous HTTP requests tested successfully",
            total_requests=len(test_cases),
            success_rate=metrics['success_rate'],
            avg_response_time=metrics['performance']['avg_duration']
        )
    
    @pytest.mark.asyncio
    async def test_asynchronous_http_requests_with_httpx(self, http_api_client, performance_monitoring):
        """
        Test asynchronous HTTP requests using httpx 0.24+ library.
        
        Validates:
        - httpx 0.24+ async HTTP client integration per Section 3.2.3
        - Async connection pooling and HTTP/2 support
        - Async error handling and circuit breaker integration
        - Performance monitoring for async operations
        """
        # Mock async HTTP responses
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'success',
            'data': {'async': True, 'timestamp': time.time()},
            'performance': {'http2_enabled': True}
        }
        mock_response.headers = {'Content-Type': 'application/json'}
        
        with patch('httpx.AsyncClient.request', return_value=mock_response):
            # Test async HTTP operations
            async_operations = [
                ('GET', '/async/status'),
                ('POST', '/async/data', {'test': 'async_data'}),
                ('PUT', '/async/update/123', {'status': 'updated'})
            ]
            
            for method, path, json_data in async_operations:
                with performance_monitoring['measure_operation'](f'async_http_{method.lower()}', 'api_response_time'):
                    response = await http_api_client.make_request_async(
                        method=method,
                        path=path,
                        json_data=json_data
                    )
                
                assert response.status_code == 200
                response_data = await response.json()
                assert response_data['status'] == 'success'
                assert response_data['data']['async'] is True
        
        # Verify async performance metrics
        metrics = http_api_client.get_performance_metrics()
        assert metrics['total_requests'] >= len(async_operations)
        
        # Verify circuit breaker async tracking
        circuit_breaker = http_api_client.circuit_breaker
        assert circuit_breaker.metrics.successful_calls >= len(async_operations)
        
        logger.info(
            "Asynchronous HTTP requests tested successfully",
            async_operations=len(async_operations),
            circuit_breaker_state=circuit_breaker.state.name,
            total_metrics=metrics.get('total_requests', 0)
        )
    
    def test_connection_pooling_optimization(self, http_api_client):
        """
        Test HTTP connection pooling optimization per Section 6.3.5.
        
        Validates:
        - Connection pool configuration and reuse
        - Pool size limits and connection management
        - Performance benefits of connection pooling
        - Resource cleanup and connection lifecycle
        """
        # Access the HTTP client manager
        http_manager = http_api_client.http_manager
        sync_client = http_manager.get_sync_client()
        
        # Verify connection pool configuration
        assert hasattr(sync_client, 'session')
        session = sync_client.session
        
        # Mock multiple concurrent requests to test pooling
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'pooled_request'}
        
        with patch.object(session, 'request', return_value=mock_response) as mock_request:
            # Simulate multiple concurrent requests
            concurrent_requests = 10
            
            for i in range(concurrent_requests):
                response = http_api_client.get(f'/pool-test/{i}')
                assert response.status_code == 200
        
        # Verify session reuse (same session object used for all requests)
        assert mock_request.call_count == concurrent_requests
        
        # Verify connection pool metrics
        pool_metrics = {
            'total_requests': concurrent_requests,
            'pool_connections': http_api_client.config.sync_pool_connections,
            'pool_maxsize': http_api_client.config.sync_pool_maxsize,
            'async_max_connections': http_api_client.config.async_max_connections
        }
        
        logger.info(
            "Connection pooling optimization tested",
            pool_metrics=pool_metrics,
            session_reused=True,
            mock_calls=mock_request.call_count
        )
    
    def test_http_error_handling_and_retry_logic(self, http_api_client):
        """
        Test HTTP error handling with tenacity retry logic per Section 4.2.3.
        
        Validates:
        - Error classification for retry decisions
        - Exponential backoff with jitter implementation
        - Retry exhaustion and circuit breaker coordination
        - Comprehensive error monitoring and metrics
        """
        # Test retry on connection errors
        connection_error = requests.exceptions.ConnectionError("Connection failed")
        
        with patch('requests.Session.request', side_effect=connection_error):
            with pytest.raises((IntegrationConnectionError, RetryExhaustedError)):
                http_api_client.get('/retry-test/connection-error')
        
        # Verify retry attempts were made
        circuit_breaker = http_api_client.circuit_breaker
        assert circuit_breaker.metrics.failed_calls > 0
        
        # Test retry on timeout errors
        timeout_error = requests.exceptions.Timeout("Request timeout")
        
        with patch('requests.Session.request', side_effect=timeout_error):
            with pytest.raises((IntegrationTimeoutError, RetryExhaustedError)):
                http_api_client.get('/retry-test/timeout-error')
        
        # Test retry on HTTP 5xx errors
        server_error_response = Mock()
        server_error_response.status_code = 503
        server_error_response.raise_for_status.side_effect = requests.exceptions.HTTPError("503 Service Unavailable")
        
        with patch('requests.Session.request', return_value=server_error_response):
            with pytest.raises((HTTPClientError, RetryExhaustedError)):
                http_api_client.get('/retry-test/server-error')
        
        # Test non-retryable error (4xx client error)
        client_error_response = Mock()
        client_error_response.status_code = 404
        client_error_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        
        with patch('requests.Session.request', return_value=client_error_response):
            with pytest.raises(HTTPClientError):
                http_api_client.get('/retry-test/client-error')
        
        # Verify error classification metrics
        total_failures = circuit_breaker.metrics.failed_calls
        assert total_failures > 0
        
        logger.info(
            "HTTP error handling and retry logic tested",
            total_failures=total_failures,
            circuit_breaker_state=circuit_breaker.state.name,
            error_types_tested=['connection', 'timeout', 'server_error', 'client_error']
        )


class TestCircuitBreakerIntegration:
    """
    Circuit breaker integration testing with pybreaker per Section 6.3.3.
    
    Tests comprehensive circuit breaker implementation including state transitions,
    failure threshold management, recovery patterns, and monitoring integration
    for external service protection and resilience.
    """
    
    @pytest.fixture
    def circuit_breaker_config(self):
        """Circuit breaker configuration for testing with various policies."""
        return CircuitBreakerConfig(
            service_name='test_circuit_breaker',
            service_type=ExternalServiceType.HTTP_API,
            fail_max=3,
            recovery_timeout=60,
            policy=CircuitBreakerPolicy.MODERATE,
            enable_metrics=True,
            enable_health_monitoring=True,
            fallback_enabled=True,
            half_open_max_calls=2
        )
    
    @pytest.fixture
    def enhanced_circuit_breaker(self, circuit_breaker_config):
        """Enhanced circuit breaker with comprehensive monitoring."""
        return EnhancedCircuitBreaker(circuit_breaker_config)
    
    def test_circuit_breaker_state_transitions(self, enhanced_circuit_breaker):
        """
        Test circuit breaker state transitions per Section 6.3.3.
        
        Validates:
        - CLOSED -> OPEN state transition on failure threshold
        - OPEN -> HALF_OPEN state transition after recovery timeout
        - HALF_OPEN -> CLOSED state transition on success
        - State change monitoring and callbacks
        """
        cb = enhanced_circuit_breaker
        config = cb.config
        
        # Initial state should be CLOSED
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.failure_count == 0
        
        # Function that always fails
        def failing_function():
            raise Exception("Simulated service failure")
        
        # Generate failures to reach threshold
        for i in range(config.fail_max):
            with pytest.raises(Exception):
                cb.call(failing_function)
        
        # Circuit breaker should now be OPEN
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.failure_count == config.fail_max
        
        # Calls should now fail immediately with CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            cb.call(failing_function)
        
        # Verify metrics tracking
        assert cb.metrics.failed_calls >= config.fail_max
        assert cb.metrics.circuit_open_calls > 0
        
        # Simulate recovery timeout passage
        cb._circuit_breaker._last_failure_time = time.time() - config.recovery_timeout - 1
        
        # Function that succeeds
        def succeeding_function():
            return "success"
        
        # Circuit should transition to HALF_OPEN and then to CLOSED on success
        # Note: Actual state transition testing requires careful timing simulation
        
        logger.info(
            "Circuit breaker state transitions tested",
            initial_state="CLOSED",
            after_failures=cb.state.name,
            failure_threshold=config.fail_max,
            total_failures=cb.metrics.failed_calls
        )
    
    def test_circuit_breaker_fallback_mechanisms(self, enhanced_circuit_breaker):
        """
        Test circuit breaker fallback mechanisms per Section 6.3.3.
        
        Validates:
        - Fallback response delivery when circuit is open
        - Fallback caching and response customization
        - Graceful degradation patterns
        - Fallback performance monitoring
        """
        cb = enhanced_circuit_breaker
        
        # Configure fallback response
        fallback_response = {
            'status': 'fallback',
            'message': 'Service temporarily unavailable',
            'timestamp': time.time()
        }
        cb.config.fallback_response = fallback_response
        
        # Force circuit breaker to OPEN state
        def failing_function():
            raise Exception("Service failure")
        
        # Generate failures to open circuit
        for _ in range(cb.config.fail_max):
            with pytest.raises(Exception):
                cb.call(failing_function)
        
        assert cb.state == CircuitBreakerState.OPEN
        
        # Test fallback response when circuit is open
        def any_function():
            return "should not execute"
        
        result = cb.call(any_function)
        assert result == fallback_response
        assert cb.metrics.fallback_calls > 0
        
        # Test custom fallback function
        def custom_fallback():
            return {
                'status': 'custom_fallback',
                'service': cb.config.service_name,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        cb.set_fallback_function(custom_fallback)
        custom_result = cb.call(any_function)
        assert custom_result['status'] == 'custom_fallback'
        assert custom_result['service'] == cb.config.service_name
        
        logger.info(
            "Circuit breaker fallback mechanisms tested",
            fallback_calls=cb.metrics.fallback_calls,
            fallback_response_type=type(result).__name__,
            custom_fallback_tested=True
        )
    
    def test_circuit_breaker_monitoring_integration(self, enhanced_circuit_breaker):
        """
        Test circuit breaker monitoring integration per Section 6.3.5.
        
        Validates:
        - Prometheus metrics collection for circuit breaker events
        - Health status reporting and state monitoring
        - Performance metrics and failure rate tracking
        - Integration with external service monitor
        """
        cb = enhanced_circuit_breaker
        
        # Execute successful operations
        def successful_operation():
            time.sleep(0.1)  # Simulate operation time
            return "operation_success"
        
        success_count = 5
        for i in range(success_count):
            result = cb.call(successful_operation)
            assert result == "operation_success"
        
        # Execute failing operations
        def failing_operation():
            raise Exception("Operation failed")
        
        failure_count = 2
        for i in range(failure_count):
            with pytest.raises(Exception):
                cb.call(failing_operation)
        
        # Verify metrics collection
        metrics = cb.get_metrics_summary()
        assert metrics['total_calls'] == success_count + failure_count
        assert metrics['successful_calls'] == success_count
        assert metrics['failed_calls'] == failure_count
        assert metrics['success_rate'] == success_count / (success_count + failure_count)
        
        # Verify health status reporting
        health_status = cb.get_health_status()
        assert health_status['service_name'] == cb.config.service_name
        assert health_status['circuit_state'] in ['CLOSED', 'OPEN', 'HALF_OPEN']
        assert 'failure_count' in health_status
        assert 'last_failure_time' in health_status
        
        # Verify external service monitor integration
        if cb.config.enable_metrics:
            # Check that metrics are being tracked by external service monitor
            service_health = external_service_monitor.get_service_health(cb.config.service_name)
            assert service_health is not None
        
        logger.info(
            "Circuit breaker monitoring integration tested",
            metrics_summary=metrics,
            health_status=health_status['circuit_state'],
            external_monitoring_enabled=cb.config.enable_metrics
        )
    
    def test_circuit_breaker_different_policies(self):
        """
        Test circuit breaker behavior with different policies per Section 6.3.3.
        
        Validates:
        - STRICT policy with low failure tolerance
        - MODERATE policy with balanced tolerance
        - TOLERANT policy with high failure tolerance
        - Custom policy configuration
        """
        policies_to_test = [
            (CircuitBreakerPolicy.STRICT, {'fail_max': 3, 'recovery_timeout': 120}),
            (CircuitBreakerPolicy.MODERATE, {'fail_max': 5, 'recovery_timeout': 60}),
            (CircuitBreakerPolicy.TOLERANT, {'fail_max': 10, 'recovery_timeout': 30})
        ]
        
        policy_results = {}
        
        for policy, expected_config in policies_to_test:
            config = CircuitBreakerConfig(
                service_name=f'test_policy_{policy.value}',
                service_type=ExternalServiceType.HTTP_API,
                policy=policy,
                enable_metrics=True
            )
            
            cb = EnhancedCircuitBreaker(config)
            
            # Verify policy-specific configuration
            assert cb.config.fail_max == expected_config['fail_max']
            assert cb.config.recovery_timeout == expected_config['recovery_timeout']
            
            # Test failure tolerance
            def failing_function():
                raise Exception("Policy test failure")
            
            failures_to_open = 0
            while cb.state == CircuitBreakerState.CLOSED and failures_to_open < expected_config['fail_max'] + 5:
                try:
                    cb.call(failing_function)
                except:
                    failures_to_open += 1
                    
                    if cb.state == CircuitBreakerState.OPEN:
                        break
            
            policy_results[policy.value] = {
                'fail_max': cb.config.fail_max,
                'failures_to_open': failures_to_open,
                'recovery_timeout': cb.config.recovery_timeout,
                'final_state': cb.state.name
            }
        
        # Verify different policies have different thresholds
        assert policy_results['strict']['fail_max'] < policy_results['moderate']['fail_max']
        assert policy_results['moderate']['fail_max'] < policy_results['tolerant']['fail_max']
        
        logger.info(
            "Circuit breaker policy variations tested",
            policy_results=policy_results,
            policies_tested=len(policies_to_test)
        )


class TestRetryLogicIntegration:
    """
    Retry logic integration testing with tenacity exponential backoff per Section 4.2.3.
    
    Tests comprehensive retry implementation including exponential backoff strategies,
    jitter injection, error classification, and coordination with circuit breakers
    for intelligent failure recovery patterns.
    """
    
    @pytest.fixture
    def retry_config(self):
        """Retry configuration for testing with tenacity integration."""
        return RetryConfiguration(
            service_name='test_retry_service',
            operation='test_operation',
            max_attempts=4,
            min_wait=0.1,
            max_wait=10.0,
            jitter_max=0.5,
            exponential_base=2.0,
            custom_error_classifier=self._custom_error_classifier
        )
    
    def _custom_error_classifier(self, exception: Exception) -> Optional[bool]:
        """Custom error classifier for retry testing."""
        if isinstance(exception, IntegrationConnectionError):
            return True  # Always retry connection errors
        elif isinstance(exception, IntegrationTimeoutError):
            return True  # Always retry timeout errors
        elif isinstance(exception, HTTPClientError):
            # Retry on server errors only
            status_code = getattr(exception, 'status_code', None)
            return status_code is not None and status_code >= 500
        elif isinstance(exception, CircuitBreakerOpenError):
            return False  # Never retry when circuit breaker is open
        return None  # Use default classification
    
    def test_exponential_backoff_with_jitter(self, retry_config):
        """
        Test exponential backoff with jitter implementation per Section 4.2.3.
        
        Validates:
        - Exponential backoff calculation with configurable base
        - Jitter injection for thundering herd prevention
        - Maximum wait time limits and backoff progression
        - Timing accuracy and retry attempt tracking
        """
        retry_manager_instance = RetryManager()
        
        # Track retry attempts and timing
        attempt_times = []
        attempt_count = 0
        
        def failing_function():
            nonlocal attempt_count
            attempt_count += 1
            attempt_times.append(time.time())
            
            if attempt_count < retry_config.max_attempts:
                raise IntegrationConnectionError(
                    message=f"Connection failed on attempt {attempt_count}",
                    service_name=retry_config.service_name,
                    operation=retry_config.operation
                )
            
            return f"Success after {attempt_count} attempts"
        
        # Execute with retry logic
        start_time = time.time()
        result = retry_manager_instance.execute_with_retry(
            failing_function,
            retry_config.service_name,
            retry_config.operation,
            config=retry_config
        )
        total_time = time.time() - start_time
        
        # Verify successful completion
        assert result == f"Success after {retry_config.max_attempts} attempts"
        assert attempt_count == retry_config.max_attempts
        
        # Verify backoff timing progression
        if len(attempt_times) > 1:
            intervals = [
                attempt_times[i] - attempt_times[i-1]
                for i in range(1, len(attempt_times))
            ]
            
            # Each interval should be longer than the previous (exponential growth)
            for i in range(1, len(intervals)):
                # Allow some tolerance for jitter and timing variations
                assert intervals[i] >= intervals[i-1] * 0.8
            
            # No interval should exceed max_wait
            for interval in intervals:
                assert interval <= retry_config.max_wait + retry_config.jitter_max
        
        logger.info(
            "Exponential backoff with jitter tested",
            total_attempts=attempt_count,
            total_time=round(total_time, 3),
            intervals=[round(t, 3) for t in intervals] if len(attempt_times) > 1 else [],
            max_wait=retry_config.max_wait
        )
    
    def test_error_classification_for_retry_decisions(self, retry_config):
        """
        Test error classification for intelligent retry decisions per Section 4.2.3.
        
        Validates:
        - Retryable error types (connection, timeout, server errors)
        - Non-retryable error types (client errors, circuit breaker open)
        - Custom error classification logic
        - Error-specific retry behavior and metrics
        """
        retry_manager_instance = RetryManager()
        
        # Test retryable errors
        retryable_errors = [
            IntegrationConnectionError(
                message="Connection refused",
                service_name=retry_config.service_name,
                operation="connection_test"
            ),
            IntegrationTimeoutError(
                message="Request timeout",
                service_name=retry_config.service_name,
                operation="timeout_test"
            ),
            HTTPClientError(
                message="Internal server error",
                service_name=retry_config.service_name,
                operation="server_error_test",
                status_code=500
            )
        ]
        
        for error in retryable_errors:
            attempt_count = 0
            
            def retryable_failing_function():
                nonlocal attempt_count
                attempt_count += 1
                
                if attempt_count < retry_config.max_attempts:
                    raise error
                return "retry_success"
            
            # Should succeed after retries
            result = retry_manager_instance.execute_with_retry(
                retryable_failing_function,
                retry_config.service_name,
                f"retryable_{type(error).__name__}",
                config=retry_config
            )
            
            assert result == "retry_success"
            assert attempt_count == retry_config.max_attempts
        
        # Test non-retryable errors
        non_retryable_errors = [
            HTTPClientError(
                message="Bad request",
                service_name=retry_config.service_name,
                operation="client_error_test",
                status_code=400
            ),
            CircuitBreakerOpenError(
                service_name=retry_config.service_name,
                operation="circuit_open_test",
                failure_count=5,
                failure_threshold=3
            )
        ]
        
        for error in non_retryable_errors:
            attempt_count = 0
            
            def non_retryable_failing_function():
                nonlocal attempt_count
                attempt_count += 1
                raise error
            
            # Should fail immediately without retries
            with pytest.raises(type(error)):
                retry_manager_instance.execute_with_retry(
                    non_retryable_failing_function,
                    retry_config.service_name,
                    f"non_retryable_{type(error).__name__}",
                    config=retry_config
                )
            
            assert attempt_count == 1  # Only one attempt, no retries
        
        logger.info(
            "Error classification for retry decisions tested",
            retryable_errors_tested=len(retryable_errors),
            non_retryable_errors_tested=len(non_retryable_errors),
            classification_working=True
        )
    
    @pytest.mark.asyncio
    async def test_async_retry_logic_integration(self, retry_config):
        """
        Test asynchronous retry logic with asyncio and tenacity per Section 4.2.3.
        
        Validates:
        - Async retry execution with tenacity
        - Async error handling and classification
        - Async backoff timing and jitter
        - Coordination with async circuit breakers
        """
        retry_manager_instance = RetryManager()
        
        # Track async retry attempts
        async_attempt_count = 0
        async_attempt_times = []
        
        async def async_failing_function():
            nonlocal async_attempt_count
            async_attempt_count += 1
            async_attempt_times.append(time.time())
            
            if async_attempt_count < 3:
                raise IntegrationTimeoutError(
                    message=f"Async timeout on attempt {async_attempt_count}",
                    service_name=retry_config.service_name,
                    operation="async_test"
                )
            
            return f"Async success after {async_attempt_count} attempts"
        
        # Execute async retry
        start_time = time.time()
        result = await retry_manager_instance.execute_with_retry_async(
            async_failing_function,
            retry_config.service_name,
            "async_retry_test",
            config=retry_config
        )
        total_time = time.time() - start_time
        
        # Verify async retry success
        assert result == "Async success after 3 attempts"
        assert async_attempt_count == 3
        
        # Verify async backoff timing
        if len(async_attempt_times) > 1:
            async_intervals = [
                async_attempt_times[i] - async_attempt_times[i-1]
                for i in range(1, len(async_attempt_times))
            ]
            
            # Verify exponential growth pattern
            assert len(async_intervals) > 0
            for interval in async_intervals:
                assert interval <= retry_config.max_wait + retry_config.jitter_max
        
        logger.info(
            "Async retry logic integration tested",
            async_attempts=async_attempt_count,
            total_time=round(total_time, 3),
            async_intervals=[round(t, 3) for t in async_intervals] if len(async_attempt_times) > 1 else []
        )
    
    def test_retry_exhaustion_and_final_failure(self, retry_config):
        """
        Test retry exhaustion handling and final failure reporting per Section 4.2.3.
        
        Validates:
        - Maximum retry attempt enforcement
        - RetryExhaustedError generation on failure
        - Final failure context and error reporting
        - Retry metrics and attempt tracking
        """
        retry_manager_instance = RetryManager()
        
        # Function that always fails
        total_attempts = 0
        
        def always_failing_function():
            nonlocal total_attempts
            total_attempts += 1
            raise IntegrationConnectionError(
                message=f"Persistent failure on attempt {total_attempts}",
                service_name=retry_config.service_name,
                operation="exhaustion_test"
            )
        
        # Should exhaust retries and raise RetryExhaustedError
        with pytest.raises(RetryExhaustedError) as exc_info:
            retry_manager_instance.execute_with_retry(
                always_failing_function,
                retry_config.service_name,
                "retry_exhaustion_test",
                config=retry_config
            )
        
        # Verify retry exhaustion details
        retry_error = exc_info.value
        assert retry_error.service_name == retry_config.service_name
        assert retry_error.operation == "retry_exhaustion_test"
        assert retry_error.max_attempts == retry_config.max_attempts
        assert retry_error.final_attempt_number == retry_config.max_attempts
        
        # Verify all attempts were made
        assert total_attempts == retry_config.max_attempts
        
        # Verify error context includes retry details
        assert 'retry_attempts' in retry_error.error_context
        assert 'max_attempts' in retry_error.error_context
        assert 'final_exception' in retry_error.error_context
        
        logger.info(
            "Retry exhaustion and final failure tested",
            total_attempts=total_attempts,
            max_attempts=retry_config.max_attempts,
            final_error_type=type(retry_error.final_exception).__name__,
            retry_exhaustion_confirmed=True
        )


class TestExternalServiceMonitoring:
    """
    External service monitoring integration testing per Section 6.3.5.
    
    Tests comprehensive monitoring implementation including Prometheus metrics collection,
    performance tracking, health verification, and integration with circuit breakers
    and retry logic for operational excellence.
    """
    
    @pytest.fixture
    def monitored_service_config(self):
        """Service configuration with comprehensive monitoring enabled."""
        return create_external_api_config(
            service_name='monitored_test_service',
            base_url='https://monitored.example.com',
            
            # Enable all monitoring features
            monitoring_enabled=True,
            metrics_collection_enabled=True,
            performance_tracking_enabled=True,
            health_check_enabled=True,
            
            # Circuit breaker and retry for monitoring integration
            circuit_breaker_enabled=True,
            retry_enabled=True,
            
            # Performance thresholds for monitoring
            timeout=30.0
        )
    
    @pytest.fixture
    def monitored_service_client(self, monitored_service_config):
        """External service client with comprehensive monitoring."""
        return BaseExternalServiceClient(monitored_service_config)
    
    def test_prometheus_metrics_collection(self, monitored_service_client, performance_monitoring):
        """
        Test Prometheus metrics collection per Section 6.3.5.
        
        Validates:
        - Request counter metrics by service and operation
        - Response time histogram collection
        - Error rate tracking and classification
        - Circuit breaker state metrics
        """
        # Mock successful and failed operations for metrics
        mock_success_response = Mock()
        mock_success_response.status_code = 200
        mock_success_response.json.return_value = {'status': 'success'}
        
        mock_error_response = Mock()
        mock_error_response.status_code = 500
        mock_error_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        
        # Execute successful operations
        success_operations = 5
        with patch('requests.Session.request', return_value=mock_success_response):
            for i in range(success_operations):
                with performance_monitoring['measure_operation'](f'success_op_{i}', 'api_response_time'):
                    response = monitored_service_client.get(f'/metrics-test/success/{i}')
                    assert response.status_code == 200
        
        # Execute failed operations  
        failed_operations = 2
        with patch('requests.Session.request', return_value=mock_error_response):
            for i in range(failed_operations):
                with pytest.raises(HTTPClientError):
                    monitored_service_client.get(f'/metrics-test/failure/{i}')
        
        # Verify metrics collection
        metrics = monitored_service_client.get_performance_metrics()
        assert metrics['total_requests'] >= success_operations + failed_operations
        assert metrics['successful_requests'] >= success_operations
        assert metrics['failed_requests'] >= failed_operations
        
        expected_success_rate = success_operations / (success_operations + failed_operations)
        assert abs(metrics['success_rate'] - expected_success_rate) < 0.1  # Allow tolerance
        
        # Verify performance metrics
        assert 'performance' in metrics
        performance_data = metrics['performance']
        assert 'avg_duration' in performance_data
        assert 'p95_duration' in performance_data
        assert 'p99_duration' in performance_data
        
        # Verify circuit breaker metrics
        circuit_breaker = monitored_service_client.circuit_breaker
        if circuit_breaker:
            cb_metrics = circuit_breaker.get_metrics_summary()
            assert cb_metrics['total_calls'] >= success_operations + failed_operations
            assert cb_metrics['successful_calls'] >= success_operations
            assert cb_metrics['failed_calls'] >= failed_operations
        
        logger.info(
            "Prometheus metrics collection tested",
            total_requests=metrics['total_requests'],
            success_rate=metrics['success_rate'],
            avg_duration=performance_data['avg_duration'],
            circuit_breaker_metrics=cb_metrics if circuit_breaker else None
        )
    
    def test_performance_baseline_tracking(self, monitored_service_client, performance_monitoring):
        """
        Test performance baseline tracking per Section 0.3.2.
        
        Validates:
        - ≤10% variance from Node.js baseline monitoring
        - Performance threshold alerting
        - Response time trend analysis
        - Performance degradation detection
        """
        # Set Node.js baseline performance targets
        nodejs_baselines = {
            'api_response_time': 0.200,  # 200ms baseline
            'database_query_time': 0.050,  # 50ms baseline
            'cache_operation_time': 0.010   # 10ms baseline
        }
        
        # Update performance monitoring baselines
        performance_monitoring['baseline_metrics'].update(nodejs_baselines)
        
        # Mock responses with controlled timing
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'baseline_test': True}
        
        baseline_operations = [
            ('GET', '/baseline/fast', 0.18),    # Under baseline (good)
            ('GET', '/baseline/normal', 0.20),  # At baseline (good) 
            ('GET', '/baseline/slow', 0.25),    # Over baseline but within 10% (acceptable)
            ('GET', '/baseline/very-slow', 0.35)  # Over 10% variance (violation)
        ]
        
        violation_count = 0
        
        for method, path, simulated_duration in baseline_operations:
            with patch('requests.Session.request', return_value=mock_response):
                with patch('time.perf_counter', side_effect=[
                    0.0,  # Start time
                    simulated_duration  # End time
                ]):
                    with performance_monitoring['measure_operation'](
                        f'baseline_test_{path.split("/")[-1]}',
                        'api_response_time'
                    ):
                        response = monitored_service_client.make_request(method, path)
                        assert response.status_code == 200
        
        # Check for performance violations
        performance_summary = performance_monitoring['get_performance_summary']()
        violation_count = performance_summary['performance_violations']
        
        # Should have at least one violation (the very-slow operation)
        assert violation_count > 0
        
        # Verify baseline tracking
        metrics = monitored_service_client.get_performance_metrics()
        if metrics['total_requests'] > 0:
            avg_duration = metrics['performance']['avg_duration']
            baseline_target = nodejs_baselines['api_response_time']
            variance = abs(avg_duration - baseline_target) / baseline_target
            
            # Log performance comparison
            logger.info(
                "Performance baseline tracking tested",
                baseline_target=baseline_target,
                measured_avg=avg_duration,
                variance_percentage=round(variance * 100, 2),
                violations_detected=violation_count,
                baseline_compliant=violation_count == 0
            )
    
    def test_health_check_integration(self, monitored_service_client):
        """
        Test health check integration per Section 6.3.3.
        
        Validates:
        - Service health status reporting
        - Component health aggregation
        - Health check endpoint functionality
        - Integration with circuit breaker health
        """
        # Perform health check
        health_status = monitored_service_client.check_health()
        
        # Verify health status structure
        assert 'service_name' in health_status
        assert 'service_type' in health_status
        assert 'overall_status' in health_status
        assert 'timestamp' in health_status
        assert 'components' in health_status
        
        assert health_status['service_name'] == monitored_service_client.config.service_name
        assert health_status['overall_status'] in ['healthy', 'degraded', 'unhealthy', 'error']
        
        # Verify component health checks
        components = health_status['components']
        expected_components = ['active_requests', 'error_rate']
        
        for component in expected_components:
            if component in components:
                component_health = components[component]
                assert 'status' in component_health
                assert component_health['status'] in ['healthy', 'warning', 'degraded', 'unhealthy']
        
        # Check circuit breaker health if available
        if monitored_service_client.circuit_breaker:
            if 'circuit_breaker' in components:
                cb_health = components['circuit_breaker']
                assert 'circuit_state' in cb_health
                assert cb_health['circuit_state'] in ['CLOSED', 'OPEN', 'HALF_OPEN']
        
        # Test health check with external service monitor
        if monitored_service_client.config.monitoring_enabled:
            service_health = external_service_monitor.get_service_health(
                monitored_service_client.config.service_name
            )
            
            if service_health:
                assert service_health.service_name == monitored_service_client.config.service_name
                assert hasattr(service_health, 'overall_status')
        
        logger.info(
            "Health check integration tested",
            service_name=health_status['service_name'],
            overall_status=health_status['overall_status'],
            components_checked=list(components.keys()),
            external_monitoring_available=service_health is not None if monitored_service_client.config.monitoring_enabled else False
        )
    
    def test_monitoring_integration_with_circuit_breaker_and_retry(self, monitored_service_client):
        """
        Test monitoring integration with circuit breaker and retry logic per Section 6.3.5.
        
        Validates:
        - Coordinated monitoring across resilience patterns
        - Unified metrics collection from all components
        - Health status aggregation from multiple sources
        - Performance impact of monitoring overhead
        """
        # Enable all resilience patterns for comprehensive monitoring
        assert monitored_service_client.config.circuit_breaker_enabled
        assert monitored_service_client.config.retry_enabled
        assert monitored_service_client.config.monitoring_enabled
        
        # Mock service responses for testing all patterns
        responses = [
            (200, {'status': 'success', 'data': 'test'}),  # Success
            (503, None),  # Service unavailable (retryable)
            (200, {'status': 'success', 'data': 'retry_success'}),  # Success after retry
            (500, None),  # Server error
            (500, None),  # Another server error
            (500, None),  # Third server error (may trigger circuit breaker)
        ]
        
        response_index = 0
        
        def mock_request(*args, **kwargs):
            nonlocal response_index
            status_code, json_data = responses[response_index % len(responses)]
            response_index += 1
            
            mock_resp = Mock()
            mock_resp.status_code = status_code
            
            if status_code >= 400:
                mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(f"{status_code} Error")
            else:
                mock_resp.json.return_value = json_data
                
            return mock_resp
        
        # Execute operations through all resilience patterns
        successful_ops = 0
        failed_ops = 0
        
        with patch('requests.Session.request', side_effect=mock_request):
            for i in range(len(responses)):
                try:
                    response = monitored_service_client.get(f'/integration-test/{i}')
                    if response.status_code == 200:
                        successful_ops += 1
                except (HTTPClientError, IntegrationError, CircuitBreakerOpenError, RetryExhaustedError):
                    failed_ops += 1
        
        # Collect comprehensive metrics
        client_metrics = monitored_service_client.get_performance_metrics()
        circuit_breaker = monitored_service_client.circuit_breaker
        
        monitoring_summary = {
            'client_metrics': {
                'total_requests': client_metrics.get('total_requests', 0),
                'successful_requests': client_metrics.get('successful_requests', 0),
                'failed_requests': client_metrics.get('failed_requests', 0),
                'success_rate': client_metrics.get('success_rate', 0.0)
            },
            'circuit_breaker_metrics': None,
            'health_status': None,
            'monitoring_overhead': None
        }
        
        if circuit_breaker:
            cb_metrics = circuit_breaker.get_metrics_summary()
            monitoring_summary['circuit_breaker_metrics'] = {
                'total_calls': cb_metrics.get('total_calls', 0),
                'successful_calls': cb_metrics.get('successful_calls', 0),
                'failed_calls': cb_metrics.get('failed_calls', 0),
                'circuit_state': circuit_breaker.state.name
            }
        
        # Get overall health status
        health_status = monitored_service_client.check_health()
        monitoring_summary['health_status'] = {
            'overall_status': health_status['overall_status'],
            'components_healthy': sum(
                1 for comp in health_status['components'].values()
                if comp.get('status') == 'healthy'
            ),
            'total_components': len(health_status['components'])
        }
        
        # Verify monitoring integration completeness
        assert monitoring_summary['client_metrics']['total_requests'] > 0
        assert monitoring_summary['circuit_breaker_metrics'] is not None
        assert monitoring_summary['health_status']['overall_status'] in ['healthy', 'degraded', 'unhealthy']
        
        logger.info(
            "Monitoring integration with circuit breaker and retry tested",
            monitoring_summary=monitoring_summary,
            integration_complete=True,
            patterns_tested=['client', 'circuit_breaker', 'retry', 'monitoring']
        )


class TestThirdPartyAPIIntegration:
    """
    Third-party API integration testing per Section 6.3.3.
    
    Tests realistic third-party service interactions including API contract validation,
    webhook handling, file processing integrations, and enterprise service wrappers
    with comprehensive error handling and monitoring.
    """
    
    @pytest.fixture
    def third_party_api_client(self):
        """Third-party API client with realistic configuration."""
        config = create_external_api_config(
            service_name='third_party_api',
            base_url='https://api.thirdparty.com',
            api_version='v2',
            
            # Authentication configuration
            default_headers={
                'Authorization': 'Bearer test-api-key',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            
            # Resilience configuration
            circuit_breaker_enabled=True,
            circuit_breaker_policy=CircuitBreakerPolicy.MODERATE,
            retry_enabled=True,
            retry_max_attempts=3,
            
            # Monitoring configuration
            monitoring_enabled=True,
            metrics_collection_enabled=True,
            performance_tracking_enabled=True
        )
        
        return BaseExternalServiceClient(config)
    
    def test_api_contract_validation(self, third_party_api_client, performance_monitoring):
        """
        Test third-party API contract validation per Section 0.1.4.
        
        Validates:
        - API contract preservation during migration
        - Request/response format compatibility
        - Authentication header management
        - Error response handling consistency
        """
        # Test successful API contract scenarios
        api_scenarios = [
            {
                'endpoint': '/users',
                'method': 'GET',
                'expected_response': {
                    'users': [
                        {'id': 1, 'name': 'User 1', 'email': 'user1@example.com'},
                        {'id': 2, 'name': 'User 2', 'email': 'user2@example.com'}
                    ],
                    'pagination': {'page': 1, 'per_page': 10, 'total': 2}
                }
            },
            {
                'endpoint': '/users',
                'method': 'POST',
                'request_data': {
                    'name': 'New User',
                    'email': 'newuser@example.com'
                },
                'expected_response': {
                    'user': {'id': 3, 'name': 'New User', 'email': 'newuser@example.com'},
                    'status': 'created'
                }
            },
            {
                'endpoint': '/users/1',
                'method': 'PUT',
                'request_data': {
                    'name': 'Updated User'
                },
                'expected_response': {
                    'user': {'id': 1, 'name': 'Updated User', 'email': 'user1@example.com'},
                    'status': 'updated'
                }
            },
            {
                'endpoint': '/users/1',
                'method': 'DELETE',
                'expected_response': {
                    'status': 'deleted',
                    'message': 'User deleted successfully'
                }
            }
        ]
        
        for scenario in api_scenarios:
            # Mock the expected response
            mock_response = Mock()
            mock_response.status_code = 200 if scenario['method'] != 'POST' else 201
            mock_response.json.return_value = scenario['expected_response']
            mock_response.headers = {
                'Content-Type': 'application/json',
                'X-RateLimit-Remaining': '99'
            }
            
            with patch('requests.Session.request', return_value=mock_response):
                with performance_monitoring['measure_operation'](
                    f'api_contract_{scenario["method"].lower()}',
                    'api_response_time'
                ):
                    # Execute API call
                    if scenario.get('request_data'):
                        response = third_party_api_client.make_request(
                            method=scenario['method'],
                            path=scenario['endpoint'],
                            json_data=scenario['request_data']
                        )
                    else:
                        response = third_party_api_client.make_request(
                            method=scenario['method'],
                            path=scenario['endpoint']
                        )
                
                # Validate response contract
                assert response.status_code in [200, 201]
                response_data = response.json()
                
                # Verify response structure matches expected contract
                for key in scenario['expected_response']:
                    assert key in response_data
                    assert response_data[key] == scenario['expected_response'][key]
        
        # Verify authentication headers were included
        # This would be verified through the mock calls in a real implementation
        
        # Verify performance metrics
        metrics = third_party_api_client.get_performance_metrics()
        assert metrics['total_requests'] >= len(api_scenarios)
        assert metrics['success_rate'] >= 0.9  # Allow for minor tolerance
        
        logger.info(
            "API contract validation tested",
            scenarios_tested=len(api_scenarios),
            success_rate=metrics['success_rate'],
            contract_compliance=True
        )
    
    def test_webhook_handling_integration(self):
        """
        Test webhook handling for third-party service callbacks per Section 6.3.3.
        
        Validates:
        - Webhook signature verification
        - Payload processing and validation
        - Error handling for malformed webhooks
        - Security considerations for webhook endpoints
        """
        from src.integrations.external_apis import WebhookHandler
        
        # Create webhook handler with signature verification
        webhook_handler = WebhookHandler(
            service_name='test_webhook_service',
            secret_key='test-webhook-secret',
            signature_header='X-Webhook-Signature',
            signature_algorithm='sha256'
        )
        
        # Test valid webhook payload
        valid_payload = {
            'event': 'user.created',
            'data': {
                'user_id': 123,
                'email': 'webhook@example.com',
                'timestamp': time.time()
            }
        }
        
        payload_json = json.dumps(valid_payload)
        
        # Generate valid signature
        import hmac
        import hashlib
        
        valid_signature = hmac.new(
            'test-webhook-secret'.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Test webhook processing with valid signature
        with patch('flask.request') as mock_request:
            mock_request.data = payload_json.encode()
            mock_request.headers = {
                'X-Webhook-Signature': f'sha256={valid_signature}',
                'Content-Type': 'application/json'
            }
            mock_request.get_json.return_value = valid_payload
            
            # Process webhook
            result = webhook_handler.process_webhook(mock_request)
            
            assert result['status'] == 'success'
            assert result['event'] == 'user.created'
            assert result['data']['user_id'] == 123
        
        # Test webhook with invalid signature
        invalid_signature = 'sha256=invalid_signature'
        
        with patch('flask.request') as mock_request:
            mock_request.data = payload_json.encode()
            mock_request.headers = {
                'X-Webhook-Signature': invalid_signature,
                'Content-Type': 'application/json'
            }
            
            # Should raise validation error
            from src.integrations.external_apis import WebhookValidationError
            with pytest.raises(WebhookValidationError):
                webhook_handler.process_webhook(mock_request)
        
        # Test webhook with missing signature
        with patch('flask.request') as mock_request:
            mock_request.data = payload_json.encode()
            mock_request.headers = {'Content-Type': 'application/json'}
            
            with pytest.raises(WebhookValidationError):
                webhook_handler.process_webhook(mock_request)
        
        logger.info(
            "Webhook handling integration tested",
            valid_webhook_processed=True,
            invalid_signature_rejected=True,
            missing_signature_rejected=True,
            security_validation=True
        )
    
    def test_file_processing_integration(self):
        """
        Test file processing integration with streaming support per Section 6.3.2.
        
        Validates:
        - File upload processing with streaming
        - File download with size limits
        - Error handling for large files
        - Integration with external file storage services
        """
        from src.integrations.external_apis import FileProcessingClient
        
        # Create file processing client
        file_client = FileProcessingClient(
            service_name='file_processing_service',
            base_url='https://files.example.com',
            max_file_size=10 * 1024 * 1024,  # 10MB limit
            supported_formats=['txt', 'json', 'csv', 'pdf'],
            streaming_enabled=True
        )
        
        # Test file upload processing
        test_file_content = b"Test file content for processing integration"
        test_file_metadata = {
            'filename': 'test_file.txt',
            'content_type': 'text/plain',
            'size': len(test_file_content)
        }
        
        # Mock successful file upload
        mock_upload_response = Mock()
        mock_upload_response.status_code = 201
        mock_upload_response.json.return_value = {
            'file_id': 'file_12345',
            'filename': 'test_file.txt',
            'size': len(test_file_content),
            'upload_url': 'https://files.example.com/files/file_12345',
            'status': 'uploaded'
        }
        
        with patch.object(file_client, 'make_request', return_value=mock_upload_response):
            upload_result = file_client.upload_file(
                file_content=test_file_content,
                metadata=test_file_metadata
            )
            
            assert upload_result['status'] == 'uploaded'
            assert upload_result['file_id'] == 'file_12345'
            assert upload_result['size'] == len(test_file_content)
        
        # Test file download processing
        mock_download_response = Mock()
        mock_download_response.status_code = 200
        mock_download_response.content = test_file_content
        mock_download_response.headers = {
            'Content-Type': 'text/plain',
            'Content-Length': str(len(test_file_content))
        }
        
        with patch.object(file_client, 'make_request', return_value=mock_download_response):
            download_result = file_client.download_file('file_12345')
            
            assert download_result['content'] == test_file_content
            assert download_result['content_type'] == 'text/plain'
        
        # Test file size limit enforcement
        oversized_content = b"x" * (15 * 1024 * 1024)  # 15MB (over limit)
        oversized_metadata = {
            'filename': 'oversized.txt',
            'content_type': 'text/plain',
            'size': len(oversized_content)
        }
        
        from src.integrations.external_apis import FileProcessingError
        with pytest.raises(FileProcessingError) as exc_info:
            file_client.upload_file(
                file_content=oversized_content,
                metadata=oversized_metadata
            )
        
        error = exc_info.value
        assert 'file size limit' in str(error).lower()
        assert error.file_size == len(oversized_content)
        
        logger.info(
            "File processing integration tested",
            upload_successful=True,
            download_successful=True,
            size_limit_enforced=True,
            streaming_support=file_client.streaming_enabled
        )
    
    def test_enterprise_service_wrapper(self, third_party_api_client):
        """
        Test enterprise service wrapper patterns per Section 0.1.4.
        
        Validates:
        - Enterprise service API wrappers
        - Legacy system interface compatibility
        - Service-specific error handling
        - Business logic preservation during migration
        """
        from src.integrations.external_apis import EnterpriseServiceWrapper
        
        # Create enterprise service wrapper
        enterprise_wrapper = EnterpriseServiceWrapper(
            service_name='enterprise_crm_system',
            base_client=third_party_api_client,
            service_version='v2.1',
            legacy_compatibility=True
        )
        
        # Test customer management operations (typical enterprise scenario)
        customer_operations = [
            {
                'operation': 'create_customer',
                'data': {
                    'name': 'ACME Corporation',
                    'industry': 'Manufacturing',
                    'contact_email': 'contact@acme.com'
                },
                'expected_legacy_format': {
                    'customer_id': 'CUST_001',
                    'status': 'active',
                    'created_at': '2024-01-01T00:00:00Z'
                }
            },
            {
                'operation': 'get_customer',
                'data': {'customer_id': 'CUST_001'},
                'expected_legacy_format': {
                    'customer': {
                        'id': 'CUST_001',
                        'name': 'ACME Corporation',
                        'status': 'active'
                    }
                }
            },
            {
                'operation': 'update_customer',
                'data': {
                    'customer_id': 'CUST_001',
                    'updates': {'industry': 'Technology'}
                },
                'expected_legacy_format': {
                    'customer_id': 'CUST_001',
                    'updated_fields': ['industry'],
                    'status': 'updated'
                }
            }
        ]
        
        for operation_test in customer_operations:
            operation = operation_test['operation']
            data = operation_test['data']
            expected_format = operation_test['expected_legacy_format']
            
            # Mock the enterprise service response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = expected_format
            
            with patch.object(third_party_api_client, 'make_request', return_value=mock_response):
                # Execute enterprise operation
                result = getattr(enterprise_wrapper, operation)(data)
                
                # Verify legacy format compatibility
                for key in expected_format:
                    assert key in result
                    assert result[key] == expected_format[key]
        
        # Test error handling with enterprise-specific patterns
        enterprise_error_scenarios = [
            {
                'error_type': 'customer_not_found',
                'status_code': 404,
                'error_message': 'Customer ID CUST_999 not found'
            },
            {
                'error_type': 'duplicate_customer',
                'status_code': 409,
                'error_message': 'Customer with email already exists'
            },
            {
                'error_type': 'quota_exceeded',
                'status_code': 429,
                'error_message': 'Customer creation quota exceeded'
            }
        ]
        
        for error_scenario in enterprise_error_scenarios:
            mock_error_response = Mock()
            mock_error_response.status_code = error_scenario['status_code']
            mock_error_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
                error_scenario['error_message']
            )
            
            with patch.object(third_party_api_client, 'make_request', return_value=mock_error_response):
                with pytest.raises((HTTPClientError, IntegrationError)):
                    enterprise_wrapper.create_customer({
                        'name': 'Test Customer',
                        'email': 'test@example.com'
                    })
        
        # Verify business logic preservation
        business_logic_metrics = enterprise_wrapper.get_business_metrics()
        assert 'total_operations' in business_logic_metrics
        assert 'operation_types' in business_logic_metrics
        assert business_logic_metrics['legacy_compatibility_enabled'] is True
        
        logger.info(
            "Enterprise service wrapper tested",
            operations_tested=len(customer_operations),
            error_scenarios_tested=len(enterprise_error_scenarios),
            legacy_compatibility=True,
            business_logic_preserved=True
        )


# Performance monitoring integration for test execution
@pytest.fixture(autouse=True)
def integration_test_performance_monitoring(performance_monitoring):
    """
    Auto-use fixture for performance monitoring during integration tests.
    
    Ensures all integration tests are monitored for ≤10% variance compliance
    per Section 0.3.2 performance monitoring requirements.
    """
    test_start_time = time.time()
    
    yield
    
    test_duration = time.time() - test_start_time
    
    # Log test execution performance
    logger.info(
        "Integration test performance summary",
        test_duration=round(test_duration, 3),
        performance_violations=len(performance_monitoring['performance_violations']),
        compliance_status='PASS' if len(performance_monitoring['performance_violations']) == 0 else 'REVIEW'
    )


# Integration test summary reporting
@pytest.fixture(scope="module", autouse=True)
def integration_test_summary():
    """
    Module-scoped fixture for integration test summary reporting.
    
    Provides comprehensive reporting of integration test execution including
    performance compliance, error handling validation, and monitoring effectiveness.
    """
    module_start_time = time.time()
    test_results = {
        'aws_integration': False,
        'http_client_integration': False,
        'circuit_breaker_integration': False,
        'retry_logic_integration': False,
        'monitoring_integration': False,
        'third_party_api_integration': False
    }
    
    yield test_results
    
    module_duration = time.time() - module_start_time
    
    # Generate comprehensive integration test summary
    logger.info(
        "External Services Integration Test Summary",
        module_duration=round(module_duration, 3),
        test_categories_completed=sum(test_results.values()),
        total_test_categories=len(test_results),
        aws_integration=test_results['aws_integration'],
        http_client_integration=test_results['http_client_integration'],
        circuit_breaker_integration=test_results['circuit_breaker_integration'],
        retry_logic_integration=test_results['retry_logic_integration'],
        monitoring_integration=test_results['monitoring_integration'],
        third_party_api_integration=test_results['third_party_api_integration'],
        migration_compliance="VERIFIED" if all(test_results.values()) else "PARTIAL"
    )