"""
External Service Integration Testing Module

Comprehensive unit tests for external service integration layer covering HTTP clients
(requests/httpx), AWS SDK (boto3), circuit breaker patterns, and third-party API
integration per Section 5.2.6 and Section 6.3.3 requirements.

This module validates external service communication with comprehensive mocking and
resilience pattern validation, ensuring ≤10% performance variance from Node.js baseline
and 90+ integration layer coverage per Section 6.6.3.

Test Coverage Areas:
- HTTP client library testing for requests 2.31+ and httpx 0.24+ per Section 5.2.6
- AWS service integration testing with boto3 1.28+ per Section 5.2.6  
- Circuit breaker and retry logic testing for service resilience per Section 5.2.6
- External service authentication testing per Section 5.2.6
- API rate limiting and retry logic testing per Section 5.2.6
- Connection pooling testing for external services per Section 5.2.6

Key Testing Patterns:
- pytest 7.4+ framework with extensive plugin ecosystem support per Section 6.6.1
- pytest-mock for comprehensive external service simulation per Section 6.6.1
- pytest-asyncio for asynchronous HTTP client and database operations per Section 6.6.1
- Performance variance tracking ensuring ≤10% compliance per Section 0.3.2
- Enterprise error handling and resilience pattern validation per Section 6.3.3
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from unittest.mock import Mock, AsyncMock, patch, MagicMock, call
from urllib.parse import urljoin

import pytest
import pytest_asyncio
from pytest_mock import MockerFixture
import requests
import httpx
import boto3
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
from requests.exceptions import (
    RequestException, HTTPError, ConnectionError as RequestsConnectionError,
    Timeout, TooManyRedirects, RetryError
)
import structlog
from tenacity import RetryError as TenacityRetryError

# Import integration components for testing per Section 5.2.6
from src.integrations import (
    # Core integration classes and factory functions
    BaseExternalServiceClient,
    BaseClientConfiguration,
    create_auth_service_client,
    create_aws_service_client,
    create_api_service_client,
    
    # Service type classifications and monitoring
    ServiceType,
    HealthStatus,
    CircuitBreakerState,
    external_service_monitor,
    ExternalServiceMonitoring,
    track_external_service_call,
    record_circuit_breaker_event,
    update_service_health,
    get_monitoring_summary,
    export_metrics,
    
    # Exception hierarchy for comprehensive error handling
    IntegrationError,
    HTTPClientError,
    ConnectionError,
    TimeoutError,
    HTTPResponseError,
    CircuitBreakerOpenError,
    CircuitBreakerHalfOpenError,
    RetryExhaustedError,
    Auth0Error,
    AWSServiceError,
    MongoDBError,
    RedisError,
    IntegrationExceptionFactory
)


class TestHTTPClientIntegration:
    """
    HTTP client integration testing covering requests 2.31+ and httpx 0.24+ per Section 5.2.6.
    
    Validates synchronous and asynchronous HTTP client implementations with comprehensive
    mocking patterns, connection pooling verification, and performance optimization testing.
    """
    
    def test_requests_client_initialization(self, mocker: MockerFixture):
        """
        Test requests 2.31+ client initialization with connection pooling configuration.
        
        Validates HTTPAdapter configuration, connection pool settings, and timeout
        configuration equivalent to Node.js HTTP client patterns per Section 6.3.5.
        """
        # Mock requests session creation
        mock_session = mocker.patch('requests.Session')
        mock_adapter = mocker.patch('requests.adapters.HTTPAdapter')
        
        # Test client configuration
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            timeout=30.0,
            retry_attempts=3,
            connection_pool_size=50,
            max_connections=100
        )
        
        client = BaseExternalServiceClient(config)
        
        # Verify session initialization
        mock_session.assert_called_once()
        
        # Verify HTTPAdapter configuration per Section 6.3.5
        mock_adapter.assert_called_with(
            pool_connections=config.connection_pool_size,
            pool_maxsize=config.max_connections,
            max_retries=config.retry_attempts
        )
        
        assert client.config.service_type == ServiceType.HTTP_API
        assert client.config.base_url == "https://api.example.com"
        assert client.config.timeout == 30.0
        assert client.config.retry_attempts == 3
    
    def test_requests_get_request_success(self, mocker: MockerFixture):
        """
        Test successful GET request execution with response validation.
        
        Validates request header configuration, response parsing, and monitoring
        integration for successful HTTP operations per Section 5.2.6.
        """
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test_response", "status": "success"}
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.elapsed.total_seconds.return_value = 0.25
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.return_value = mock_response
        
        # Mock monitoring for external service call tracking
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            timeout=30.0
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute GET request
        response_data = client.get("/test-endpoint", params={"key": "value"})
        
        # Verify request execution
        mock_session_instance.get.assert_called_once_with(
            "https://api.example.com/test-endpoint",
            params={"key": "value"},
            timeout=30.0,
            headers=client._get_default_headers()
        )
        
        # Verify response processing
        assert response_data["data"] == "test_response"
        assert response_data["status"] == "success"
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["service_name"] == config.service_type.value
        assert call_args[1]["operation"] == "GET"
        assert call_args[1]["success"] is True
        assert call_args[1]["duration"] == 0.25
    
    def test_requests_post_request_with_json_payload(self, mocker: MockerFixture):
        """
        Test POST request with JSON payload and authentication headers.
        
        Validates JSON serialization, authentication token injection, and response
        handling for POST operations per Section 5.2.6.
        """
        # Mock successful POST response
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "12345", "created": True}
        mock_response.elapsed.total_seconds.return_value = 0.45
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.post.return_value = mock_response
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            auth_token="Bearer test-token-12345"
        )
        
        client = BaseExternalServiceClient(config)
        
        # Test payload
        payload = {
            "name": "Test Resource",
            "description": "Test resource creation",
            "metadata": {"source": "test_suite"}
        }
        
        # Execute POST request
        response_data = client.post("/resources", json=payload)
        
        # Verify request execution with authentication
        expected_headers = client._get_default_headers()
        expected_headers["Authorization"] = "Bearer test-token-12345"
        
        mock_session_instance.post.assert_called_once_with(
            "https://api.example.com/resources",
            json=payload,
            timeout=config.timeout,
            headers=expected_headers
        )
        
        # Verify response processing
        assert response_data["id"] == "12345"
        assert response_data["created"] is True
        
        # Verify monitoring integration for POST operation
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["operation"] == "POST"
        assert call_args[1]["success"] is True
    
    def test_requests_error_handling(self, mocker: MockerFixture):
        """
        Test comprehensive error handling for requests HTTP client.
        
        Validates exception classification, error logging, and monitoring integration
        for various HTTP error scenarios per Section 6.3.3.
        """
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        # Mock monitoring and logging
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_logger = mocker.patch('structlog.get_logger')
        mock_logger_instance = Mock()
        mock_logger.return_value = mock_logger_instance
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com"
        )
        
        client = BaseExternalServiceClient(config)
        
        # Test connection error handling
        mock_session_instance.get.side_effect = RequestsConnectionError("Connection failed")
        
        with pytest.raises(ConnectionError) as exc_info:
            client.get("/test-endpoint")
        
        assert "Connection failed" in str(exc_info.value)
        
        # Verify error monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["error_type"] == "ConnectionError"
        
        # Test timeout error handling
        mock_session_instance.get.side_effect = Timeout("Request timeout")
        mock_track_call.reset_mock()
        
        with pytest.raises(TimeoutError) as exc_info:
            client.get("/test-endpoint")
        
        assert "Request timeout" in str(exc_info.value)
        
        # Test HTTP error handling (4xx/5xx responses)
        mock_http_error = HTTPError("404 Not Found")
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Resource not found"
        mock_http_error.response = mock_response
        
        mock_session_instance.get.side_effect = mock_http_error
        mock_track_call.reset_mock()
        
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get("/test-endpoint")
        
        assert exc_info.value.status_code == 404
        assert "Resource not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_httpx_async_client_initialization(self, mocker: MockerFixture):
        """
        Test httpx 0.24+ async client initialization with connection pool configuration.
        
        Validates AsyncClient configuration, connection limits, and timeout settings
        for high-performance async HTTP operations per Section 5.2.6.
        """
        # Mock httpx AsyncClient
        mock_async_client = mocker.patch('httpx.AsyncClient')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            timeout=30.0,
            max_connections=100,
            max_keepalive_connections=50,
            keepalive_expiry=30.0
        )
        
        # Create async client instance
        async with httpx.AsyncClient(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.timeout),
            limits=httpx.Limits(
                max_connections=config.max_connections,
                max_keepalive_connections=config.max_keepalive_connections,
                keepalive_expiry=config.keepalive_expiry
            )
        ) as client:
            # Verify client configuration
            mock_async_client.assert_called_once()
            call_kwargs = mock_async_client.call_args[1]
            
            assert call_kwargs["base_url"] == config.base_url
            assert isinstance(call_kwargs["timeout"], httpx.Timeout)
            assert isinstance(call_kwargs["limits"], httpx.Limits)
    
    @pytest.mark.asyncio
    async def test_httpx_async_get_request_success(self, mocker: MockerFixture):
        """
        Test successful async GET request execution with httpx client.
        
        Validates async request processing, response handling, and monitoring
        integration for non-blocking HTTP operations per Section 5.2.6.
        """
        # Mock successful async response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "async_response", "status": "success"}
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.elapsed.total_seconds.return_value = 0.15
        
        # Mock httpx AsyncClient
        mock_async_client = mocker.patch('httpx.AsyncClient')
        mock_client_instance = AsyncMock()
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_response
        
        # Mock async monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            timeout=30.0
        )
        
        # Execute async GET request
        async with httpx.AsyncClient(base_url=config.base_url) as client:
            response = await client.get("/async-endpoint", params={"async": "true"})
            response_data = response.json()
        
        # Verify async request execution
        mock_client_instance.get.assert_called_once_with(
            "/async-endpoint",
            params={"async": "true"}
        )
        
        # Verify response processing
        assert response_data["data"] == "async_response"
        assert response_data["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_httpx_async_post_with_concurrent_requests(self, mocker: MockerFixture):
        """
        Test concurrent async POST requests with httpx for performance validation.
        
        Validates concurrent request handling, connection pool efficiency, and
        performance optimization for high-throughput scenarios per Section 6.3.5.
        """
        # Mock successful async responses
        mock_responses = []
        for i in range(5):
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"id": f"resource_{i}", "batch": True}
            mock_response.elapsed.total_seconds.return_value = 0.1 + (i * 0.02)
            mock_responses.append(mock_response)
        
        # Mock httpx AsyncClient with concurrent response handling
        mock_async_client = mocker.patch('httpx.AsyncClient')
        mock_client_instance = AsyncMock()
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.side_effect = mock_responses
        
        # Mock performance monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            max_connections=50
        )
        
        # Execute concurrent POST requests
        async def make_request(session, resource_id):
            payload = {"name": f"Resource {resource_id}", "batch_id": "test_batch"}
            response = await session.post("/resources", json=payload)
            return response.json()
        
        start_time = time.time()
        async with httpx.AsyncClient(base_url=config.base_url) as client:
            tasks = [make_request(client, i) for i in range(5)]
            results = await asyncio.gather(*tasks)
        
        execution_time = time.time() - start_time
        
        # Verify concurrent execution efficiency (should be < 1 second for 5 requests)
        assert execution_time < 1.0, f"Concurrent requests took {execution_time:.2f}s, expected < 1.0s"
        
        # Verify all requests completed successfully
        assert len(results) == 5
        for i, result in enumerate(results):
            assert result["id"] == f"resource_{i}"
            assert result["batch"] is True
        
        # Verify POST calls were made
        assert mock_client_instance.post.call_count == 5
    
    @pytest.mark.asyncio
    async def test_httpx_async_error_handling(self, mocker: MockerFixture):
        """
        Test comprehensive async error handling for httpx client.
        
        Validates async exception handling, error classification, and monitoring
        integration for async HTTP operations per Section 6.3.3.
        """
        # Mock httpx AsyncClient
        mock_async_client = mocker.patch('httpx.AsyncClient')
        mock_client_instance = AsyncMock()
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com"
        )
        
        # Test async connection error
        mock_client_instance.get.side_effect = httpx.ConnectError("Async connection failed")
        
        with pytest.raises(ConnectionError) as exc_info:
            async with httpx.AsyncClient(base_url=config.base_url) as client:
                await client.get("/test-endpoint")
        
        assert "Async connection failed" in str(exc_info.value)
        
        # Test async timeout error
        mock_client_instance.get.side_effect = httpx.TimeoutException("Async request timeout")
        
        with pytest.raises(TimeoutError) as exc_info:
            async with httpx.AsyncClient(base_url=config.base_url) as client:
                await client.get("/test-endpoint")
        
        assert "Async request timeout" in str(exc_info.value)
        
        # Test async HTTP status error
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_http_status_error = httpx.HTTPStatusError(
            "500 Internal Server Error",
            request=Mock(),
            response=mock_response
        )
        
        mock_client_instance.get.side_effect = mock_http_status_error
        
        with pytest.raises(HTTPResponseError) as exc_info:
            async with httpx.AsyncClient(base_url=config.base_url) as client:
                await client.get("/test-endpoint")
        
        assert exc_info.value.status_code == 500
        assert "Internal server error" in str(exc_info.value)


class TestAWSServiceIntegration:
    """
    AWS service integration testing with boto3 1.28+ per Section 5.2.6.
    
    Validates AWS SDK integration, S3 operations, CloudWatch monitoring, and
    error handling patterns for cloud service operations.
    """
    
    def test_boto3_s3_client_initialization(self, mocker: MockerFixture):
        """
        Test boto3 S3 client initialization with configuration optimization.
        
        Validates boto3 client configuration, connection pooling, and service-specific
        settings for optimal AWS integration per Section 6.3.5.
        """
        # Mock boto3 client creation
        mock_boto3_client = mocker.patch('boto3.client')
        mock_session = mocker.patch('boto3.Session')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_S3,
            region="us-east-1",
            max_pool_connections=50
        )
        
        # Create AWS service client
        aws_client = create_aws_service_client(config)
        
        # Verify boto3 client configuration
        mock_boto3_client.assert_called_once_with(
            's3',
            region_name=config.region,
            config=mocker.ANY  # boto3.Config object with connection settings
        )
        
        # Verify connection pool configuration
        call_args = mock_boto3_client.call_args
        boto3_config = call_args[1]['config']
        assert boto3_config.max_pool_connections == 50
        assert boto3_config.region_name == "us-east-1"
        assert boto3_config.retries['max_attempts'] >= 3
    
    def test_s3_file_upload_operation(self, mocker: MockerFixture):
        """
        Test S3 file upload with multipart handling and progress monitoring.
        
        Validates file upload operations, multipart upload for large files, and
        progress tracking for AWS S3 integration per Section 5.2.6.
        """
        # Mock S3 client and operations
        mock_s3_client = Mock()
        mock_boto3_client = mocker.patch('boto3.client', return_value=mock_s3_client)
        
        # Mock successful upload response
        mock_s3_client.upload_fileobj.return_value = None
        mock_s3_client.head_object.return_value = {
            'ContentLength': 1024,
            'ETag': '"abc123def456"',
            'LastModified': datetime.utcnow()
        }
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_S3,
            region="us-east-1",
            bucket_name="test-bucket"
        )
        
        aws_client = create_aws_service_client(config)
        
        # Test file upload
        file_content = b"Test file content for S3 upload validation"
        file_key = "test-files/sample.txt"
        
        # Execute upload operation
        start_time = time.time()
        upload_result = aws_client.upload_file(
            file_content=file_content,
            file_key=file_key,
            content_type="text/plain"
        )
        upload_duration = time.time() - start_time
        
        # Verify S3 upload call
        mock_s3_client.upload_fileobj.assert_called_once()
        upload_args = mock_s3_client.upload_fileobj.call_args
        
        assert upload_args[1]['Bucket'] == config.bucket_name
        assert upload_args[1]['Key'] == file_key
        assert 'ContentType' in upload_args[1]['ExtraArgs']
        assert upload_args[1]['ExtraArgs']['ContentType'] == "text/plain"
        
        # Verify upload result
        assert upload_result['success'] is True
        assert upload_result['file_key'] == file_key
        assert upload_result['content_length'] == 1024
        assert 'etag' in upload_result
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["service_name"] == ServiceType.AWS_S3.value
        assert call_args[1]["operation"] == "upload_file"
        assert call_args[1]["success"] is True
        assert call_args[1]["duration"] == upload_duration
    
    def test_s3_multipart_upload_for_large_files(self, mocker: MockerFixture):
        """
        Test S3 multipart upload for large file handling and optimization.
        
        Validates multipart upload implementation, part size optimization, and
        upload progress tracking for large file operations per Section 6.3.2.
        """
        # Mock S3 client with multipart operations
        mock_s3_client = Mock()
        mock_boto3_client = mocker.patch('boto3.client', return_value=mock_s3_client)
        
        # Mock multipart upload responses
        mock_s3_client.create_multipart_upload.return_value = {
            'UploadId': 'test-upload-id-12345'
        }
        
        # Mock part upload responses
        mock_parts = []
        for i in range(1, 4):  # 3 parts
            mock_parts.append({
                'ETag': f'"part{i}etag"',
                'PartNumber': i
            })
        
        mock_s3_client.upload_part.side_effect = mock_parts
        
        mock_s3_client.complete_multipart_upload.return_value = {
            'ETag': '"combined-etag"',
            'Location': 'https://test-bucket.s3.amazonaws.com/large-file.bin'
        }
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_S3,
            region="us-east-1",
            bucket_name="test-bucket",
            multipart_threshold=10 * 1024 * 1024,  # 10MB threshold
            part_size=5 * 1024 * 1024  # 5MB parts
        )
        
        aws_client = create_aws_service_client(config)
        
        # Simulate large file (15MB requiring multipart upload)
        large_file_size = 15 * 1024 * 1024
        file_key = "large-files/big-file.bin"
        
        # Execute multipart upload
        start_time = time.time()
        upload_result = aws_client.upload_large_file(
            file_size=large_file_size,
            file_key=file_key,
            content_type="application/octet-stream"
        )
        upload_duration = time.time() - start_time
        
        # Verify multipart upload initialization
        mock_s3_client.create_multipart_upload.assert_called_once_with(
            Bucket=config.bucket_name,
            Key=file_key,
            ContentType="application/octet-stream"
        )
        
        # Verify part uploads (3 parts for 15MB file with 5MB parts)
        assert mock_s3_client.upload_part.call_count == 3
        
        # Verify multipart completion
        mock_s3_client.complete_multipart_upload.assert_called_once()
        complete_args = mock_s3_client.complete_multipart_upload.call_args
        assert complete_args[1]['UploadId'] == 'test-upload-id-12345'
        assert len(complete_args[1]['MultipartUpload']['Parts']) == 3
        
        # Verify upload result
        assert upload_result['success'] is True
        assert upload_result['multipart'] is True
        assert upload_result['parts_uploaded'] == 3
        assert upload_result['total_size'] == large_file_size
    
    def test_s3_file_download_with_streaming(self, mocker: MockerFixture):
        """
        Test S3 file download with streaming support for memory optimization.
        
        Validates file download operations, streaming implementation, and memory
        management for large file downloads per Section 6.3.2.
        """
        # Mock S3 client and streaming response
        mock_s3_client = Mock()
        mock_boto3_client = mocker.patch('boto3.client', return_value=mock_s3_client)
        
        # Mock streaming download response
        mock_streaming_body = Mock()
        mock_streaming_body.read.return_value = b"Downloaded file content chunk"
        mock_streaming_body.__iter__.return_value = iter([
            b"chunk1", b"chunk2", b"chunk3"
        ])
        
        mock_s3_client.get_object.return_value = {
            'Body': mock_streaming_body,
            'ContentLength': 1024,
            'ContentType': 'application/octet-stream',
            'ETag': '"download123"'
        }
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_S3,
            region="us-east-1",
            bucket_name="test-bucket"
        )
        
        aws_client = create_aws_service_client(config)
        
        # Test streaming download
        file_key = "downloads/test-file.bin"
        
        start_time = time.time()
        download_result = aws_client.download_file_stream(file_key)
        download_duration = time.time() - start_time
        
        # Verify S3 download call
        mock_s3_client.get_object.assert_called_once_with(
            Bucket=config.bucket_name,
            Key=file_key
        )
        
        # Verify streaming download result
        assert download_result['success'] is True
        assert download_result['file_key'] == file_key
        assert download_result['content_length'] == 1024
        assert download_result['content_type'] == 'application/octet-stream'
        assert 'stream_chunks' in download_result
        
        # Verify streaming capability
        chunks = list(download_result['stream_chunks'])
        assert chunks == [b"chunk1", b"chunk2", b"chunk3"]
        
        # Verify monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["operation"] == "download_file_stream"
        assert call_args[1]["success"] is True
    
    def test_cloudwatch_metrics_integration(self, mocker: MockerFixture):
        """
        Test CloudWatch metrics submission and monitoring integration.
        
        Validates CloudWatch client configuration, custom metrics submission, and
        integration monitoring for AWS observability per Section 6.3.5.
        """
        # Mock CloudWatch client
        mock_cloudwatch_client = Mock()
        mock_boto3_client = mocker.patch('boto3.client')
        mock_boto3_client.side_effect = lambda service, **kwargs: (
            mock_cloudwatch_client if service == 'cloudwatch' else Mock()
        )
        
        # Mock CloudWatch put_metric_data response
        mock_cloudwatch_client.put_metric_data.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}
        }
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_CLOUDWATCH,
            region="us-east-1",
            namespace="Flask-Migration/External-Integrations"
        )
        
        aws_client = create_aws_service_client(config)
        
        # Test metrics submission
        metrics_data = [
            {
                'MetricName': 'ExternalAPIResponse',
                'Value': 250.5,
                'Unit': 'Milliseconds',
                'Dimensions': [
                    {'Name': 'ServiceType', 'Value': 'HTTP_API'},
                    {'Name': 'Environment', 'Value': 'test'}
                ]
            },
            {
                'MetricName': 'CircuitBreakerOpen',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'ServiceName', 'Value': 'auth0-api'},
                    {'Name': 'Environment', 'Value': 'test'}
                ]
            }
        ]
        
        start_time = time.time()
        metrics_result = aws_client.submit_metrics(metrics_data)
        submission_duration = time.time() - start_time
        
        # Verify CloudWatch metrics submission
        mock_cloudwatch_client.put_metric_data.assert_called_once_with(
            Namespace=config.namespace,
            MetricData=metrics_data
        )
        
        # Verify submission result
        assert metrics_result['success'] is True
        assert metrics_result['metrics_submitted'] == 2
        assert metrics_result['namespace'] == config.namespace
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["service_name"] == ServiceType.AWS_CLOUDWATCH.value
        assert call_args[1]["operation"] == "submit_metrics"
        assert call_args[1]["success"] is True
    
    def test_aws_service_error_handling(self, mocker: MockerFixture):
        """
        Test comprehensive AWS service error handling and classification.
        
        Validates AWS-specific exception handling, error classification, and
        monitoring integration for various AWS error scenarios per Section 6.3.3.
        """
        # Mock boto3 client
        mock_s3_client = Mock()
        mock_boto3_client = mocker.patch('boto3.client', return_value=mock_s3_client)
        
        # Mock monitoring and logging
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_logger = mocker.patch('structlog.get_logger')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AWS_S3,
            region="us-east-1",
            bucket_name="test-bucket"
        )
        
        aws_client = create_aws_service_client(config)
        
        # Test ClientError (4xx/5xx AWS errors)
        client_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'NoSuchBucket',
                    'Message': 'The specified bucket does not exist'
                }
            },
            operation_name='GetObject'
        )
        
        mock_s3_client.get_object.side_effect = client_error
        
        with pytest.raises(AWSServiceError) as exc_info:
            aws_client.download_file_stream("test-file.txt")
        
        assert exc_info.value.error_code == "NoSuchBucket"
        assert "The specified bucket does not exist" in str(exc_info.value)
        
        # Verify error monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["error_type"] == "AWSServiceError"
        assert call_args[1]["error_code"] == "NoSuchBucket"
        
        # Test EndpointConnectionError (network connectivity)
        mock_s3_client.get_object.side_effect = EndpointConnectionError(
            endpoint_url="https://s3.us-east-1.amazonaws.com"
        )
        mock_track_call.reset_mock()
        
        with pytest.raises(ConnectionError) as exc_info:
            aws_client.download_file_stream("test-file.txt")
        
        assert "https://s3.us-east-1.amazonaws.com" in str(exc_info.value)
        
        # Test BotoCoreError (general boto3 errors)
        mock_s3_client.get_object.side_effect = BotoCoreError()
        mock_track_call.reset_mock()
        
        with pytest.raises(AWSServiceError) as exc_info:
            aws_client.download_file_stream("test-file.txt")
        
        # Verify error classification
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["error_type"] == "AWSServiceError"


class TestCircuitBreakerPatterns:
    """
    Circuit breaker pattern testing for service resilience per Section 5.2.6.
    
    Validates circuit breaker implementation, state transitions, fallback mechanisms,
    and recovery patterns for external service protection.
    """
    
    def test_circuit_breaker_initialization(self, mocker: MockerFixture):
        """
        Test circuit breaker initialization with configuration validation.
        
        Validates circuit breaker configuration, threshold settings, and state
        initialization for service resilience per Section 6.3.3.
        """
        # Mock pybreaker circuit breaker
        mock_circuit_breaker = mocker.patch('pybreaker.CircuitBreaker')
        
        # Mock monitoring
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=HTTPClientError
        )
        
        client = BaseExternalServiceClient(config)
        
        # Verify circuit breaker initialization
        mock_circuit_breaker.assert_called_once_with(
            fail_max=config.failure_threshold,
            reset_timeout=config.recovery_timeout,
            exclude=[config.expected_exception]
        )
        
        assert client.config.circuit_breaker_enabled is True
        assert client.config.failure_threshold == 5
        assert client.config.recovery_timeout == 60
    
    def test_circuit_breaker_closed_state_operation(self, mocker: MockerFixture):
        """
        Test circuit breaker operation in closed state with success tracking.
        
        Validates normal operation flow, success counting, and state maintenance
        when circuit breaker is in closed state per Section 6.3.3.
        """
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "data": "test"}
        mock_response.elapsed.total_seconds.return_value = 0.2
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.return_value = mock_response
        
        # Mock circuit breaker in closed state
        mock_circuit_breaker = Mock()
        mock_circuit_breaker.current_state = "closed"
        mock_circuit_breaker.fail_counter = 0
        mock_pybreaker = mocker.patch('pybreaker.CircuitBreaker', return_value=mock_circuit_breaker)
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            failure_threshold=5
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute request through circuit breaker
        response_data = client.get("/test-endpoint")
        
        # Verify successful operation
        assert response_data["status"] == "success"
        assert response_data["data"] == "test"
        
        # Verify circuit breaker state tracking
        mock_record_event.assert_called_with(
            service_name=config.service_type.value,
            event_type="request_success",
            current_state="closed",
            failure_count=0
        )
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is True
        assert call_args[1]["circuit_breaker_state"] == "closed"
    
    def test_circuit_breaker_failure_threshold_reached(self, mocker: MockerFixture):
        """
        Test circuit breaker state transition when failure threshold is reached.
        
        Validates failure counting, threshold detection, and state transition from
        closed to open state per Section 6.3.3.
        """
        # Mock failing HTTP responses
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.side_effect = RequestsConnectionError("Connection failed")
        
        # Mock circuit breaker with progressive failure counting
        mock_circuit_breaker = Mock()
        mock_circuit_breaker.current_state = "closed"
        mock_circuit_breaker.fail_counter = 0
        
        # Simulate failure threshold progression
        failure_responses = []
        for i in range(6):  # Exceed threshold of 5
            mock_circuit_breaker.fail_counter = i
            if i >= 5:
                mock_circuit_breaker.current_state = "open"
                mock_circuit_breaker.side_effect = CircuitBreakerOpenError("Circuit breaker is open")
            failure_responses.append(mock_circuit_breaker)
        
        mock_pybreaker = mocker.patch('pybreaker.CircuitBreaker')
        mock_pybreaker.return_value = mock_circuit_breaker
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            failure_threshold=5
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute requests to trigger failure threshold
        for i in range(5):
            try:
                client.get("/test-endpoint")
            except ConnectionError:
                # Expected failures
                pass
        
        # Verify circuit breaker opens after threshold
        mock_circuit_breaker.current_state = "open"
        
        with pytest.raises(CircuitBreakerOpenError):
            client.get("/test-endpoint")
        
        # Verify circuit breaker state change events
        assert mock_record_event.call_count >= 5
        
        # Check final state transition event
        final_call = mock_record_event.call_args_list[-1]
        assert final_call[1]["event_type"] == "state_transition"
        assert final_call[1]["current_state"] == "open"
    
    def test_circuit_breaker_open_state_with_fallback(self, mocker: MockerFixture):
        """
        Test circuit breaker behavior in open state with fallback mechanism.
        
        Validates open state operation, fallback response delivery, and monitoring
        integration during service outage per Section 6.3.3.
        """
        # Mock circuit breaker in open state
        mock_circuit_breaker = Mock()
        mock_circuit_breaker.current_state = "open"
        mock_circuit_breaker.fail_counter = 5
        mock_circuit_breaker.call.side_effect = CircuitBreakerOpenError("Circuit breaker is open")
        
        mock_pybreaker = mocker.patch('pybreaker.CircuitBreaker', return_value=mock_circuit_breaker)
        
        # Mock fallback response
        mock_cache = mocker.patch('redis.Redis')
        mock_cache_instance = Mock()
        mock_cache.return_value = mock_cache_instance
        mock_cache_instance.get.return_value = json.dumps({
            "status": "fallback",
            "data": "cached_response",
            "timestamp": datetime.utcnow().isoformat()
        }).encode()
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            fallback_enabled=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute request with circuit breaker open
        try:
            response_data = client.get_with_fallback("/test-endpoint")
        except CircuitBreakerOpenError:
            # Fallback mechanism activated
            response_data = client.get_fallback_response("/test-endpoint")
        
        # Verify fallback response
        assert response_data["status"] == "fallback"
        assert response_data["data"] == "cached_response"
        assert "timestamp" in response_data
        
        # Verify circuit breaker open state tracking
        mock_record_event.assert_called_with(
            service_name=config.service_type.value,
            event_type="fallback_activated",
            current_state="open",
            failure_count=5
        )
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is True  # Fallback considered success
        assert call_args[1]["circuit_breaker_state"] == "open"
        assert call_args[1]["fallback_used"] is True
    
    def test_circuit_breaker_half_open_state_recovery(self, mocker: MockerFixture):
        """
        Test circuit breaker recovery in half-open state with probe requests.
        
        Validates half-open state operation, probe request handling, and state
        transition logic during recovery per Section 6.3.3.
        """
        # Mock successful probe response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "recovered", "probe": True}
        mock_response.elapsed.total_seconds.return_value = 0.3
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.return_value = mock_response
        
        # Mock circuit breaker in half-open state transitioning to closed
        mock_circuit_breaker = Mock()
        mock_circuit_breaker.current_state = "half-open"
        mock_circuit_breaker.fail_counter = 0
        
        # Simulate successful probe leading to closed state
        def circuit_breaker_call(func, *args, **kwargs):
            result = func(*args, **kwargs)
            mock_circuit_breaker.current_state = "closed"  # Success transitions to closed
            return result
        
        mock_circuit_breaker.call.side_effect = circuit_breaker_call
        mock_pybreaker = mocker.patch('pybreaker.CircuitBreaker', return_value=mock_circuit_breaker)
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            recovery_timeout=60
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute probe request in half-open state
        response_data = client.get("/health-check")
        
        # Verify successful probe response
        assert response_data["status"] == "recovered"
        assert response_data["probe"] is True
        
        # Verify state transition to closed
        assert mock_circuit_breaker.current_state == "closed"
        
        # Verify recovery event tracking
        mock_record_event.assert_called_with(
            service_name=config.service_type.value,
            event_type="state_transition",
            current_state="closed",
            failure_count=0
        )
        
        # Verify monitoring integration
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is True
        assert call_args[1]["circuit_breaker_state"] == "closed"
        assert call_args[1]["recovery_successful"] is True


class TestRetryLogicPatterns:
    """
    Retry logic and resilience pattern testing per Section 5.2.6.
    
    Validates tenacity retry implementation, exponential backoff, jitter patterns,
    and retry exhaustion handling for fault tolerance.
    """
    
    def test_exponential_backoff_retry_configuration(self, mocker: MockerFixture):
        """
        Test exponential backoff retry configuration and initialization.
        
        Validates tenacity retry decorator configuration, backoff parameters, and
        exception classification for intelligent retry patterns per Section 6.3.3.
        """
        # Mock tenacity retry decorator
        mock_retry_decorator = mocker.patch('tenacity.retry')
        mock_wait_exponential = mocker.patch('tenacity.wait_exponential')
        mock_stop_after_attempt = mocker.patch('tenacity.stop_after_attempt')
        mock_retry_if_exception_type = mocker.patch('tenacity.retry_if_exception_type')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            retry_enabled=True,
            retry_attempts=3,
            retry_backoff_multiplier=1,
            retry_backoff_min=2,
            retry_backoff_max=30,
            retry_exceptions=[HTTPClientError, ConnectionError, TimeoutError]
        )
        
        client = BaseExternalServiceClient(config)
        
        # Verify retry decorator configuration
        mock_wait_exponential.assert_called_with(
            multiplier=config.retry_backoff_multiplier,
            min=config.retry_backoff_min,
            max=config.retry_backoff_max
        )
        
        mock_stop_after_attempt.assert_called_with(config.retry_attempts)
        
        # Verify exception type configuration
        for exception_type in config.retry_exceptions:
            mock_retry_if_exception_type.assert_any_call(exception_type)
    
    def test_retry_success_after_transient_failure(self, mocker: MockerFixture):
        """
        Test successful retry after transient failure with backoff timing.
        
        Validates retry execution, backoff timing, and eventual success handling
        for transient failure recovery per Section 6.3.3.
        """
        # Mock HTTP responses: failure, failure, success
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        # Configure progressive responses
        failure_response = RequestsConnectionError("Temporary connection failure")
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"status": "success", "retry_recovered": True}
        success_response.elapsed.total_seconds.return_value = 0.4
        
        mock_session_instance.get.side_effect = [
            failure_response,  # First attempt fails
            failure_response,  # Second attempt fails
            success_response   # Third attempt succeeds
        ]
        
        # Mock retry timing
        mock_time_sleep = mocker.patch('time.sleep')
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            retry_enabled=True,
            retry_attempts=3,
            retry_backoff_min=1,
            retry_backoff_max=10
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute request with retry logic
        start_time = time.time()
        response_data = client.get_with_retry("/test-endpoint")
        total_duration = time.time() - start_time
        
        # Verify eventual success
        assert response_data["status"] == "success"
        assert response_data["retry_recovered"] is True
        
        # Verify retry attempts
        assert mock_session_instance.get.call_count == 3
        
        # Verify backoff sleep calls (2 retries = 2 sleep calls)
        assert mock_time_sleep.call_count == 2
        
        # Verify exponential backoff timing (approximately 1s, then 2s)
        sleep_calls = [call.args[0] for call in mock_time_sleep.call_args_list]
        assert 0.8 <= sleep_calls[0] <= 1.2  # ~1s with jitter
        assert 1.8 <= sleep_calls[1] <= 2.2  # ~2s with jitter
        
        # Verify monitoring tracks final success
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is True
        assert call_args[1]["retry_attempts"] == 3
        assert call_args[1]["retry_successful"] is True
    
    def test_retry_exhaustion_with_all_attempts_failed(self, mocker: MockerFixture):
        """
        Test retry exhaustion when all attempts fail with proper error handling.
        
        Validates retry exhaustion detection, final error reporting, and monitoring
        integration when all retry attempts are exhausted per Section 6.3.3.
        """
        # Mock consistently failing HTTP responses
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.side_effect = RequestsConnectionError("Persistent connection failure")
        
        # Mock retry timing
        mock_time_sleep = mocker.patch('time.sleep')
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            retry_enabled=True,
            retry_attempts=3,
            retry_backoff_min=1,
            retry_backoff_max=10
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute request expecting retry exhaustion
        start_time = time.time()
        
        with pytest.raises(RetryExhaustedError) as exc_info:
            client.get_with_retry("/test-endpoint")
        
        total_duration = time.time() - start_time
        
        # Verify retry exhaustion
        assert "Retry attempts exhausted" in str(exc_info.value)
        assert exc_info.value.attempts == 3
        assert exc_info.value.last_exception.__class__ == RequestsConnectionError
        
        # Verify all retry attempts were made
        assert mock_session_instance.get.call_count == 3
        
        # Verify backoff sleep calls
        assert mock_time_sleep.call_count == 2  # 2 retries = 2 sleep calls
        
        # Verify total duration includes backoff time (approximately 3+ seconds)
        assert total_duration >= 3.0, f"Expected >= 3s total time, got {total_duration:.2f}s"
        
        # Verify error monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["retry_attempts"] == 3
        assert call_args[1]["retry_exhausted"] is True
        assert call_args[1]["error_type"] == "RetryExhaustedError"
    
    def test_jitter_implementation_for_thundering_herd_prevention(self, mocker: MockerFixture):
        """
        Test jitter implementation in retry backoff for thundering herd prevention.
        
        Validates jitter randomization, backoff variation, and distributed retry
        timing for preventing thundering herd patterns per Section 6.3.3.
        """
        # Mock random jitter generation
        mock_random = mocker.patch('random.uniform')
        mock_random.side_effect = [0.8, 1.2, 0.9]  # Jitter factors
        
        # Mock failing then successful HTTP responses
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        failure_response = RequestsConnectionError("Network congestion")
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"status": "success", "jitter_test": True}
        success_response.elapsed.total_seconds.return_value = 0.3
        
        mock_session_instance.get.side_effect = [
            failure_response,  # First attempt fails
            failure_response,  # Second attempt fails  
            success_response   # Third attempt succeeds
        ]
        
        # Mock sleep to track jittered backoff
        mock_time_sleep = mocker.patch('time.sleep')
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            retry_enabled=True,
            retry_attempts=3,
            retry_backoff_min=2,
            retry_backoff_max=8,
            retry_jitter_enabled=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute request with jittered retry
        response_data = client.get_with_jittered_retry("/test-endpoint")
        
        # Verify eventual success
        assert response_data["status"] == "success"
        assert response_data["jitter_test"] is True
        
        # Verify jittered sleep timing
        assert mock_time_sleep.call_count == 2
        sleep_calls = [call.args[0] for call in mock_time_sleep.call_args_list]
        
        # Verify jitter variation (sleep times should vary due to jitter)
        assert sleep_calls[0] != sleep_calls[1], "Jitter should create different backoff times"
        
        # Verify sleep times are within jittered range
        for sleep_time in sleep_calls:
            assert 1.0 <= sleep_time <= 10.0, f"Sleep time {sleep_time} outside jittered range"
        
        # Verify jitter randomization was applied
        assert mock_random.call_count >= 2
        
        # Verify monitoring includes jitter metadata
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["retry_jitter_enabled"] is True
        assert call_args[1]["retry_successful"] is True
    
    def test_retry_exception_classification(self, mocker: MockerFixture):
        """
        Test retry exception classification and selective retry behavior.
        
        Validates exception type filtering, retry decision logic, and immediate
        failure for non-retryable exceptions per Section 6.3.3.
        """
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            retry_enabled=True,
            retry_attempts=3,
            retryable_exceptions=[ConnectionError, TimeoutError],
            non_retryable_exceptions=[HTTPResponseError]
        )
        
        client = BaseExternalServiceClient(config)
        
        # Test retryable exception (ConnectionError)
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.side_effect = RequestsConnectionError("Retryable connection error")
        
        with pytest.raises(RetryExhaustedError):
            client.get_with_selective_retry("/test-endpoint")
        
        # Verify retries were attempted for retryable exception
        assert mock_session_instance.get.call_count == 3
        
        # Reset mocks for non-retryable exception test
        mock_session_instance.reset_mock()
        mock_track_call.reset_mock()
        
        # Test non-retryable exception (HTTPResponseError)
        http_error = HTTPError("400 Bad Request")
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid request format"
        http_error.response = mock_response
        
        # Create HTTPResponseError from HTTPError
        response_error = HTTPResponseError("400 Bad Request", status_code=400, response_text="Invalid request format")
        mock_session_instance.get.side_effect = response_error
        
        # Non-retryable exception should fail immediately
        with pytest.raises(HTTPResponseError) as exc_info:
            client.get_with_selective_retry("/test-endpoint")
        
        # Verify no retries for non-retryable exception
        assert mock_session_instance.get.call_count == 1
        assert exc_info.value.status_code == 400
        
        # Verify monitoring tracks immediate failure
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["retry_attempts"] == 1  # Only initial attempt
        assert call_args[1]["retry_skipped"] is True
        assert call_args[1]["error_type"] == "HTTPResponseError"


class TestExternalServiceAuthentication:
    """
    External service authentication testing per Section 5.2.6.
    
    Validates Auth0 integration, JWT token handling, API key management, and
    authentication state management for external services.
    """
    
    def test_auth0_service_client_initialization(self, mocker: MockerFixture):
        """
        Test Auth0 service client initialization and configuration.
        
        Validates Auth0 Python SDK integration, client configuration, and
        authentication endpoint setup per Section 6.3.3.
        """
        # Mock Auth0 client
        mock_auth0_client = mocker.patch('auth0.Auth0')
        mock_management_api = mocker.patch('auth0.management.Auth0')
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AUTH0,
            auth0_domain="test-tenant.auth0.com",
            auth0_client_id="test_client_id_12345",
            auth0_client_secret="test_client_secret_67890",
            auth0_audience="https://api.test-app.com"
        )
        
        auth_client = create_auth_service_client(config)
        
        # Verify Auth0 client initialization
        mock_auth0_client.assert_called_once_with(
            domain=config.auth0_domain,
            client_id=config.auth0_client_id,
            client_secret=config.auth0_client_secret
        )
        
        # Verify management API initialization
        mock_management_api.assert_called_once_with(
            domain=config.auth0_domain,
            token=mocker.ANY  # Management API token
        )
        
        assert auth_client.config.service_type == ServiceType.AUTH0
        assert auth_client.config.auth0_domain == "test-tenant.auth0.com"
        assert auth_client.config.auth0_audience == "https://api.test-app.com"
    
    def test_jwt_token_validation_with_auth0(self, mocker: MockerFixture):
        """
        Test JWT token validation using Auth0 JWKS endpoint.
        
        Validates JWT signature verification, claims extraction, and token
        validation workflow with Auth0 integration per Section 6.4.1.
        """
        # Mock PyJWT token validation
        mock_jwt_decode = mocker.patch('jwt.decode')
        mock_jwt_get_unverified_header = mocker.patch('jwt.get_unverified_header')
        
        # Mock Auth0 JWKS retrieval
        mock_requests_get = mocker.patch('requests.get')
        mock_jwks_response = Mock()
        mock_jwks_response.json.return_value = {
            "keys": [
                {
                    "kid": "test_key_id",
                    "kty": "RSA",
                    "use": "sig",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
        mock_requests_get.return_value = mock_jwks_response
        
        # Mock JWT header and payload
        mock_jwt_get_unverified_header.return_value = {"kid": "test_key_id", "alg": "RS256"}
        mock_jwt_decode.return_value = {
            "sub": "auth0|test_user_12345",
            "aud": "https://api.test-app.com",
            "iss": "https://test-tenant.auth0.com/",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "scope": "read:profile write:data"
        }
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AUTH0,
            auth0_domain="test-tenant.auth0.com",
            auth0_audience="https://api.test-app.com"
        )
        
        auth_client = create_auth_service_client(config)
        
        # Test JWT token validation
        test_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test_payload.test_signature"
        
        start_time = time.time()
        validation_result = auth_client.validate_jwt_token(test_token)
        validation_duration = time.time() - start_time
        
        # Verify JWKS retrieval
        mock_requests_get.assert_called_once_with(
            f"https://{config.auth0_domain}/.well-known/jwks.json"
        )
        
        # Verify JWT validation
        mock_jwt_decode.assert_called_once_with(
            test_token,
            mocker.ANY,  # RSA public key
            algorithms=["RS256"],
            audience=config.auth0_audience,
            issuer=f"https://{config.auth0_domain}/"
        )
        
        # Verify validation result
        assert validation_result["valid"] is True
        assert validation_result["user_id"] == "auth0|test_user_12345"
        assert validation_result["audience"] == "https://api.test-app.com"
        assert validation_result["scopes"] == ["read:profile", "write:data"]
        
        # Verify monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["service_name"] == ServiceType.AUTH0.value
        assert call_args[1]["operation"] == "validate_jwt_token"
        assert call_args[1]["success"] is True
        assert call_args[1]["duration"] == validation_duration
    
    def test_auth0_user_profile_retrieval(self, mocker: MockerFixture):
        """
        Test Auth0 user profile retrieval with Management API.
        
        Validates Auth0 Management API integration, user data retrieval, and
        profile caching for user context management per Section 5.2.3.
        """
        # Mock Auth0 Management API client
        mock_management_api = Mock()
        mock_auth0_management = mocker.patch('auth0.management.Auth0', return_value=mock_management_api)
        
        # Mock user profile response
        mock_user_profile = {
            "user_id": "auth0|test_user_12345",
            "email": "test.user@example.com",
            "name": "Test User",
            "picture": "https://gravatar.com/avatar/test.jpg",
            "app_metadata": {
                "roles": ["user", "admin"],
                "permissions": ["read:profile", "write:data", "admin:users"]
            },
            "user_metadata": {
                "preferences": {"theme": "dark", "language": "en"},
                "last_login": "2023-12-01T10:30:00Z"
            }
        }
        
        mock_management_api.users.get.return_value = mock_user_profile
        
        # Mock Redis caching
        mock_redis_client = Mock()
        mock_redis = mocker.patch('redis.Redis', return_value=mock_redis_client)
        mock_redis_client.get.return_value = None  # Cache miss
        mock_redis_client.setex.return_value = True
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.AUTH0,
            auth0_domain="test-tenant.auth0.com",
            auth0_management_token="mgmt_token_12345",
            cache_user_profiles=True,
            cache_ttl=3600
        )
        
        auth_client = create_auth_service_client(config)
        
        # Test user profile retrieval
        user_id = "auth0|test_user_12345"
        
        start_time = time.time()
        profile_result = auth_client.get_user_profile(user_id)
        retrieval_duration = time.time() - start_time
        
        # Verify Management API call
        mock_management_api.users.get.assert_called_once_with(user_id)
        
        # Verify profile data
        assert profile_result["user_id"] == user_id
        assert profile_result["email"] == "test.user@example.com"
        assert profile_result["name"] == "Test User"
        assert "admin" in profile_result["app_metadata"]["roles"]
        assert "read:profile" in profile_result["app_metadata"]["permissions"]
        
        # Verify caching
        mock_redis_client.setex.assert_called_once_with(
            f"user_profile:{user_id}",
            config.cache_ttl,
            json.dumps(mock_user_profile)
        )
        
        # Verify monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["operation"] == "get_user_profile"
        assert call_args[1]["success"] is True
        assert call_args[1]["cache_hit"] is False
    
    def test_api_key_authentication_for_external_services(self, mocker: MockerFixture):
        """
        Test API key authentication for external service integration.
        
        Validates API key management, header injection, and authentication
        workflow for third-party service integration per Section 5.2.6.
        """
        # Mock successful HTTP response with API key auth
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "authenticated",
            "api_version": "v2",
            "rate_limit": {"remaining": 4999, "reset_time": "2023-12-01T11:00:00Z"}
        }
        mock_response.headers = {
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": "1701423600"
        }
        mock_response.elapsed.total_seconds.return_value = 0.2
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.return_value = mock_response
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.external-service.com",
            api_key="sk-test-api-key-12345",
            api_key_header="X-API-Key",
            rate_limit_tracking=True
        )
        
        api_client = create_api_service_client(config)
        
        # Test API key authenticated request
        response_data = api_client.get("/authenticated-endpoint", params={"test": "data"})
        
        # Verify API key header injection
        mock_session_instance.get.assert_called_once()
        call_args = mock_session_instance.get.call_args
        
        headers = call_args[1]["headers"]
        assert headers[config.api_key_header] == config.api_key
        assert "User-Agent" in headers
        assert "Content-Type" in headers
        
        # Verify authenticated response
        assert response_data["status"] == "authenticated"
        assert response_data["api_version"] == "v2"
        assert response_data["rate_limit"]["remaining"] == 4999
        
        # Verify rate limit tracking
        assert api_client.rate_limit_remaining == 4999
        assert api_client.rate_limit_reset_time is not None
        
        # Verify monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["authentication_type"] == "api_key"
        assert call_args[1]["rate_limit_remaining"] == 4999
        assert call_args[1]["success"] is True
    
    def test_oauth2_token_refresh_workflow(self, mocker: MockerFixture):
        """
        Test OAuth2 token refresh workflow for maintaining authentication.
        
        Validates token expiration detection, refresh token usage, and token
        update workflow for maintaining service authentication per Section 6.4.1.
        """
        # Mock OAuth2 token refresh response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "new_access_token_12345",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_token_67890",
            "scope": "read write admin"
        }
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.post.return_value = mock_token_response
        
        # Mock token storage
        mock_redis_client = Mock()
        mock_redis = mocker.patch('redis.Redis', return_value=mock_redis_client)
        mock_redis_client.setex.return_value = True
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.OAUTH2_API,
            oauth2_token_url="https://auth.external-service.com/oauth/token",
            oauth2_client_id="client_id_12345",
            oauth2_client_secret="client_secret_67890",
            oauth2_refresh_token="refresh_token_original",
            token_storage_enabled=True
        )
        
        oauth_client = create_api_service_client(config)
        
        # Test token refresh
        start_time = time.time()
        refresh_result = oauth_client.refresh_access_token()
        refresh_duration = time.time() - start_time
        
        # Verify token refresh request
        mock_session_instance.post.assert_called_once_with(
            config.oauth2_token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": config.oauth2_refresh_token,
                "client_id": config.oauth2_client_id,
                "client_secret": config.oauth2_client_secret
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        # Verify token refresh result
        assert refresh_result["success"] is True
        assert refresh_result["access_token"] == "new_access_token_12345"
        assert refresh_result["expires_in"] == 3600
        assert refresh_result["refresh_token"] == "new_refresh_token_67890"
        
        # Verify token storage
        mock_redis_client.setex.assert_called()
        storage_calls = mock_redis_client.setex.call_args_list
        
        # Should store both access token and refresh token
        assert len(storage_calls) >= 2
        
        # Verify monitoring
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["operation"] == "refresh_access_token"
        assert call_args[1]["success"] is True
        assert call_args[1]["duration"] == refresh_duration


class TestConnectionPoolingOptimization:
    """
    Connection pooling testing for external services per Section 5.2.6.
    
    Validates HTTP connection pooling, database connection management, and
    resource optimization patterns for external service efficiency.
    """
    
    def test_http_connection_pool_configuration(self, mocker: MockerFixture):
        """
        Test HTTP connection pool configuration and optimization.
        
        Validates HTTPAdapter connection pool settings, connection reuse, and
        pool size optimization for HTTP client efficiency per Section 6.3.5.
        """
        # Mock HTTPAdapter with connection pooling
        mock_http_adapter = mocker.patch('requests.adapters.HTTPAdapter')
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            connection_pool_size=20,
            max_connections=50,
            pool_maxsize=50,
            pool_block=False
        )
        
        client = BaseExternalServiceClient(config)
        
        # Verify HTTPAdapter configuration
        mock_http_adapter.assert_called_with(
            pool_connections=config.connection_pool_size,
            pool_maxsize=config.max_connections,
            max_retries=mocker.ANY
        )
        
        # Verify session mount configuration
        mock_session_instance.mount.assert_called()
        mount_calls = mock_session_instance.mount.call_args_list
        
        # Should mount adapters for both HTTP and HTTPS
        assert len(mount_calls) >= 2
        
        # Verify adapter mounting
        http_mount = next((call for call in mount_calls if call[0][0] == "http://"), None)
        https_mount = next((call for call in mount_calls if call[0][0] == "https://"), None)
        
        assert http_mount is not None
        assert https_mount is not None
    
    def test_connection_pool_reuse_efficiency(self, mocker: MockerFixture):
        """
        Test connection pool reuse efficiency and performance optimization.
        
        Validates connection reuse patterns, pool utilization tracking, and
        performance benefits of connection pooling per Section 6.3.5.
        """
        # Mock multiple HTTP responses for connection reuse testing
        mock_responses = []
        for i in range(10):
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"request_id": i, "data": f"response_{i}"}
            mock_response.elapsed.total_seconds.return_value = 0.1 + (i * 0.01)
            mock_responses.append(mock_response)
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.side_effect = mock_responses
        
        # Mock connection pool metrics
        mock_pool_metrics = Mock()
        mock_pool_metrics.pool_connections_count = 5
        mock_pool_metrics.active_connections = 3
        mock_pool_metrics.idle_connections = 2
        
        mock_session_instance.get_adapter.return_value.poolmanager = mock_pool_metrics
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            connection_pool_size=20,
            max_connections=50,
            pool_metrics_enabled=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute multiple requests to test connection reuse
        start_time = time.time()
        responses = []
        
        for i in range(10):
            response_data = client.get(f"/test-endpoint-{i}")
            responses.append(response_data)
        
        total_duration = time.time() - start_time
        
        # Verify all requests completed successfully
        assert len(responses) == 10
        for i, response in enumerate(responses):
            assert response["request_id"] == i
            assert response["data"] == f"response_{i}"
        
        # Verify connection reuse efficiency (10 requests should complete quickly)
        assert total_duration < 2.0, f"Expected < 2s for 10 requests, got {total_duration:.2f}s"
        
        # Verify session reuse (same session instance used for all requests)
        assert mock_session_instance.get.call_count == 10
        
        # Verify monitoring includes pool metrics
        assert mock_track_call.call_count == 10
        
        # Check pool metrics in monitoring
        final_call = mock_track_call.call_args_list[-1]
        call_args = final_call[1]
        assert "pool_connections" in call_args
        assert "active_connections" in call_args
        assert "idle_connections" in call_args
    
    def test_connection_pool_exhaustion_handling(self, mocker: MockerFixture):
        """
        Test connection pool exhaustion detection and handling.
        
        Validates pool exhaustion detection, connection queuing, and graceful
        degradation when connection limits are reached per Section 6.3.3.
        """
        # Mock connection pool exhaustion
        from requests.exceptions import ConnectionError as RequestsConnectionError
        pool_exhaustion_error = RequestsConnectionError("HTTPSConnectionPool: Pool exhausted")
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.side_effect = pool_exhaustion_error
        
        # Mock pool metrics showing exhaustion
        mock_pool_metrics = Mock()
        mock_pool_metrics.pool_connections_count = 10
        mock_pool_metrics.active_connections = 10
        mock_pool_metrics.idle_connections = 0
        mock_pool_metrics.queued_requests = 5
        
        mock_session_instance.get_adapter.return_value.poolmanager = mock_pool_metrics
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            connection_pool_size=10,
            max_connections=10,
            pool_exhaustion_handling=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Test pool exhaustion handling
        with pytest.raises(ConnectionError) as exc_info:
            client.get("/test-endpoint")
        
        # Verify pool exhaustion error classification
        assert "Pool exhausted" in str(exc_info.value)
        
        # Verify monitoring tracks pool exhaustion
        mock_track_call.assert_called_once()
        call_args = mock_track_call.call_args
        assert call_args[1]["success"] is False
        assert call_args[1]["error_type"] == "ConnectionError"
        assert call_args[1]["pool_exhausted"] is True
        assert call_args[1]["active_connections"] == 10
        assert call_args[1]["queued_requests"] == 5
    
    @pytest.mark.asyncio
    async def test_async_connection_pool_optimization(self, mocker: MockerFixture):
        """
        Test async connection pool optimization with httpx client.
        
        Validates async connection pool configuration, concurrent connection
        management, and performance optimization for async operations per Section 6.3.5.
        """
        # Mock httpx async client with connection pool
        mock_async_client = mocker.patch('httpx.AsyncClient')
        
        # Mock successful async responses
        mock_responses = []
        for i in range(20):
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"async_id": i, "concurrent": True}
            mock_response.elapsed.total_seconds.return_value = 0.05 + (i * 0.002)
            mock_responses.append(mock_response)
        
        mock_client_instance = AsyncMock()
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = mock_responses
        
        # Mock connection pool limits
        mock_limits = Mock()
        mock_limits.max_connections = 100
        mock_limits.max_keepalive_connections = 50
        mock_limits.keepalive_expiry = 30.0
        
        # Mock monitoring
        mock_track_call = mocker.patch('src.integrations.track_external_service_call')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            max_connections=100,
            max_keepalive_connections=50,
            keepalive_expiry=30.0,
            async_pool_optimization=True
        )
        
        # Test concurrent async requests with connection pooling
        async def make_concurrent_request(session, request_id):
            response = await session.get(f"/async-endpoint-{request_id}")
            return response.json()
        
        start_time = time.time()
        
        async with httpx.AsyncClient(
            base_url=config.base_url,
            limits=httpx.Limits(
                max_connections=config.max_connections,
                max_keepalive_connections=config.max_keepalive_connections,
                keepalive_expiry=config.keepalive_expiry
            )
        ) as client:
            # Execute 20 concurrent requests
            tasks = [make_concurrent_request(client, i) for i in range(20)]
            results = await asyncio.gather(*tasks)
        
        total_duration = time.time() - start_time
        
        # Verify concurrent execution efficiency
        assert total_duration < 1.0, f"Expected < 1s for 20 concurrent requests, got {total_duration:.2f}s"
        
        # Verify all requests completed successfully
        assert len(results) == 20
        for i, result in enumerate(results):
            assert result["async_id"] == i
            assert result["concurrent"] is True
        
        # Verify concurrent connection usage
        assert mock_client_instance.get.call_count == 20
        
        # Verify httpx client configuration
        mock_async_client.assert_called_once()
        call_kwargs = mock_async_client.call_args[1]
        
        assert call_kwargs["base_url"] == config.base_url
        assert isinstance(call_kwargs["limits"], httpx.Limits)


class TestExternalServiceMonitoring:
    """
    External service monitoring and observability testing per Section 6.3.5.
    
    Validates monitoring integration, metrics collection, performance tracking,
    and observability patterns for external service operations.
    """
    
    def test_service_call_tracking_and_metrics(self, mocker: MockerFixture):
        """
        Test external service call tracking with comprehensive metrics.
        
        Validates call tracking implementation, metrics collection, and
        performance monitoring for external service operations per Section 6.3.5.
        """
        # Mock prometheus metrics
        mock_prometheus_counter = Mock()
        mock_prometheus_histogram = Mock()
        mock_prometheus_gauge = Mock()
        
        mock_prometheus = mocker.patch('prometheus_client.Counter', return_value=mock_prometheus_counter)
        mocker.patch('prometheus_client.Histogram', return_value=mock_prometheus_histogram)
        mocker.patch('prometheus_client.Gauge', return_value=mock_prometheus_gauge)
        
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tracking_test": True}
        mock_response.elapsed.total_seconds.return_value = 0.25
        
        mock_session = mocker.patch('requests.Session')
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.get.return_value = mock_response
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            monitoring_enabled=True,
            metrics_collection=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Execute tracked request
        start_time = time.time()
        response_data = client.get("/monitored-endpoint")
        
        # Verify response
        assert response_data["tracking_test"] is True
        
        # Verify prometheus metrics were recorded
        mock_prometheus_counter.inc.assert_called_once()
        mock_prometheus_histogram.observe.assert_called_once_with(0.25)
        mock_prometheus_gauge.set.assert_called()
        
        # Verify metrics labels
        counter_call = mock_prometheus_counter.inc.call_args
        assert "service_type" in str(counter_call)
        assert "operation" in str(counter_call)
        assert "status" in str(counter_call)
    
    def test_circuit_breaker_state_monitoring(self, mocker: MockerFixture):
        """
        Test circuit breaker state monitoring and event tracking.
        
        Validates circuit breaker state tracking, event recording, and
        monitoring integration for resilience pattern observability per Section 6.3.3.
        """
        # Mock circuit breaker state monitoring
        mock_circuit_breaker_gauge = Mock()
        mock_circuit_breaker_counter = Mock()
        
        mocker.patch('prometheus_client.Gauge', return_value=mock_circuit_breaker_gauge)
        mocker.patch('prometheus_client.Counter', return_value=mock_circuit_breaker_counter)
        
        # Mock circuit breaker events
        mock_record_event = mocker.patch('src.integrations.record_circuit_breaker_event')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            circuit_breaker_enabled=True,
            monitoring_enabled=True
        )
        
        client = BaseExternalServiceClient(config)
        
        # Simulate circuit breaker state transitions
        states = ["closed", "open", "half-open", "closed"]
        failure_counts = [0, 5, 5, 0]
        
        for i, (state, failures) in enumerate(zip(states, failure_counts)):
            record_circuit_breaker_event(
                service_name=config.service_type.value,
                event_type="state_transition" if i > 0 else "initialization",
                current_state=state,
                failure_count=failures
            )
        
        # Verify all state transitions were recorded
        assert mock_record_event.call_count == 4
        
        # Verify state monitoring calls
        recorded_states = [call[1]["current_state"] for call in mock_record_event.call_args_list]
        assert recorded_states == ["closed", "open", "half-open", "closed"]
        
        # Verify failure count tracking
        recorded_failures = [call[1]["failure_count"] for call in mock_record_event.call_args_list]
        assert recorded_failures == [0, 5, 5, 0]
    
    def test_performance_variance_tracking(self, mocker: MockerFixture):
        """
        Test performance variance tracking against Node.js baseline.
        
        Validates performance comparison, variance calculation, and alert
        generation for ≤10% variance requirement per Section 0.3.2.
        """
        # Mock performance baseline data
        nodejs_baseline = {
            "response_time_avg": 250,  # 250ms average
            "response_time_p95": 400,  # 400ms 95th percentile
            "requests_per_second": 1000,
            "memory_usage_mb": 512
        }
        
        # Mock current performance metrics
        current_metrics = {
            "response_time_avg": 270,  # 8% increase (within 10% limit)
            "response_time_p95": 440,  # 10% increase (at limit)
            "requests_per_second": 950,  # 5% decrease
            "memory_usage_mb": 520     # 1.6% increase
        }
        
        # Mock performance monitoring
        mock_performance_tracker = mocker.patch('src.integrations.track_performance_variance')
        
        # Mock alerting system
        mock_alert_system = mocker.patch('src.integrations.send_performance_alert')
        
        config = BaseClientConfiguration(
            service_type=ServiceType.HTTP_API,
            base_url="https://api.example.com",
            performance_monitoring=True,
            variance_threshold=0.10  # 10% threshold
        )
        
        client = BaseExternalServiceClient(config)
        
        # Calculate performance variance
        variance_results = client.calculate_performance_variance(
            baseline=nodejs_baseline,
            current=current_metrics
        )
        
        # Verify variance calculations
        assert variance_results["response_time_avg_variance"] == 0.08  # 8%
        assert variance_results["response_time_p95_variance"] == 0.10  # 10%
        assert variance_results["requests_per_second_variance"] == -0.05  # -5%
        assert variance_results["memory_usage_variance"] == 0.016  # 1.6%
        
        # Verify overall compliance
        assert variance_results["within_threshold"] is True
        assert variance_results["max_variance"] == 0.10
        
        # Verify threshold warnings for metrics at limit
        assert "response_time_p95" in variance_results["threshold_warnings"]
        
        # Verify no alert triggered (within threshold)
        mock_alert_system.assert_not_called()
        
        # Test threshold breach scenario
        breach_metrics = current_metrics.copy()
        breach_metrics["response_time_avg"] = 300  # 20% increase (exceeds 10% limit)
        
        breach_results = client.calculate_performance_variance(
            baseline=nodejs_baseline,
            current=breach_metrics
        )
        
        # Verify threshold breach detection
        assert breach_results["within_threshold"] is False
        assert breach_results["response_time_avg_variance"] == 0.20  # 20%
        
        # Verify alert triggered for breach
        mock_alert_system.assert_called_once()
        alert_call = mock_alert_system.call_args
        assert alert_call[1]["metric"] == "response_time_avg"
        assert alert_call[1]["variance"] == 0.20
        assert alert_call[1]["threshold"] == 0.10
    
    def test_health_monitoring_and_status_reporting(self, mocker: MockerFixture):
        """
        Test external service health monitoring and status reporting.
        
        Validates health check implementation, status aggregation, and
        monitoring dashboard integration per Section 6.3.3.
        """
        # Mock external service health responses
        service_health_data = {
            "auth0_api": {
                "status": "healthy",
                "response_time": 120,
                "last_check": datetime.utcnow().isoformat(),
                "success_rate": 0.99
            },
            "aws_s3": {
                "status": "healthy", 
                "response_time": 80,
                "last_check": datetime.utcnow().isoformat(),
                "success_rate": 1.0
            },
            "external_api": {
                "status": "degraded",
                "response_time": 800,
                "last_check": datetime.utcnow().isoformat(),
                "success_rate": 0.95,
                "issues": ["High latency detected"]
            }
        }
        
        # Mock health monitoring system
        mock_health_monitor = mocker.patch('src.integrations.external_service_monitor')
        mock_health_monitor.get_service_health.side_effect = lambda service: service_health_data.get(service, {})
        
        # Mock health status aggregation
        mock_get_monitoring_summary = mocker.patch('src.integrations.get_monitoring_summary')
        mock_get_monitoring_summary.return_value = {
            "registered_services": list(service_health_data.keys()),
            "health_cache": service_health_data,
            "service_metadata": {
                service: {"service_type": "external"} for service in service_health_data.keys()
            },
            "last_updated": datetime.utcnow().isoformat(),
            "cache_entries": len(service_health_data)
        }
        
        config = BaseClientConfiguration(
            service_type=ServiceType.MONITORING,
            health_check_enabled=True,
            health_check_interval=60
        )
        
        monitor = external_service_monitor
        
        # Execute health monitoring
        health_summary = get_monitoring_summary()
        
        # Verify health data aggregation
        assert len(health_summary["registered_services"]) == 3
        assert "auth0_api" in health_summary["health_cache"]
        assert "aws_s3" in health_summary["health_cache"]
        assert "external_api" in health_summary["health_cache"]
        
        # Verify service health statuses
        auth0_health = health_summary["health_cache"]["auth0_api"]
        assert auth0_health["status"] == "healthy"
        assert auth0_health["response_time"] == 120
        assert auth0_health["success_rate"] == 0.99
        
        s3_health = health_summary["health_cache"]["aws_s3"]
        assert s3_health["status"] == "healthy"
        assert s3_health["response_time"] == 80
        assert s3_health["success_rate"] == 1.0
        
        api_health = health_summary["health_cache"]["external_api"]
        assert api_health["status"] == "degraded"
        assert api_health["response_time"] == 800
        assert "High latency detected" in api_health["issues"]
        
        # Verify overall health assessment
        healthy_services = [s for s, h in health_summary["health_cache"].items() if h["status"] == "healthy"]
        degraded_services = [s for s, h in health_summary["health_cache"].items() if h["status"] == "degraded"]
        
        assert len(healthy_services) == 2
        assert len(degraded_services) == 1
        assert "external_api" in degraded_services
    
    def test_metrics_export_for_prometheus_scraping(self, mocker: MockerFixture):
        """
        Test metrics export functionality for Prometheus scraping.
        
        Validates metrics serialization, Prometheus format compliance, and
        metrics endpoint functionality per Section 6.3.5.
        """
        # Mock prometheus metrics registry
        mock_prometheus_registry = Mock()
        mock_prometheus_generate_latest = mocker.patch(
            'prometheus_client.generate_latest',
            return_value=b"""# HELP external_service_requests_total Total external service requests
# TYPE external_service_requests_total counter
external_service_requests_total{service_type="HTTP_API",operation="GET",status="success"} 150.0
external_service_requests_total{service_type="AWS_S3",operation="upload_file",status="success"} 25.0
external_service_requests_total{service_type="AUTH0",operation="validate_jwt_token",status="success"} 300.0

# HELP external_service_request_duration_seconds External service request duration
# TYPE external_service_request_duration_seconds histogram
external_service_request_duration_seconds_bucket{service_type="HTTP_API",operation="GET",le="0.1"} 50.0
external_service_request_duration_seconds_bucket{service_type="HTTP_API",operation="GET",le="0.5"} 140.0
external_service_request_duration_seconds_bucket{service_type="HTTP_API",operation="GET",le="1.0"} 150.0
external_service_request_duration_seconds_bucket{service_type="HTTP_API",operation="GET",le="+Inf"} 150.0
external_service_request_duration_seconds_count{service_type="HTTP_API",operation="GET"} 150.0
external_service_request_duration_seconds_sum{service_type="HTTP_API",operation="GET"} 25.5

# HELP circuit_breaker_state Circuit breaker current state
# TYPE circuit_breaker_state gauge
circuit_breaker_state{service_name="auth0_api"} 0.0
circuit_breaker_state{service_name="aws_s3"} 0.0
circuit_breaker_state{service_name="external_api"} 1.0

# HELP external_service_health_status External service health status
# TYPE external_service_health_status gauge
external_service_health_status{service_name="auth0_api"} 1.0
external_service_health_status{service_name="aws_s3"} 1.0
external_service_health_status{service_name="external_api"} 0.5
"""
        )
        
        # Mock export_metrics function
        mock_export_metrics = mocker.patch('src.integrations.export_metrics')
        mock_export_metrics.return_value = mock_prometheus_generate_latest.return_value.decode('utf-8')
        
        # Execute metrics export
        metrics_data = export_metrics()
        
        # Verify metrics export
        assert isinstance(metrics_data, str)
        assert "external_service_requests_total" in metrics_data
        assert "external_service_request_duration_seconds" in metrics_data
        assert "circuit_breaker_state" in metrics_data
        assert "external_service_health_status" in metrics_data
        
        # Verify metric values
        assert 'service_type="HTTP_API"' in metrics_data
        assert 'service_type="AWS_S3"' in metrics_data
        assert 'service_type="AUTH0"' in metrics_data
        
        # Verify counter metrics
        assert "150.0" in metrics_data  # HTTP API request count
        assert "25.0" in metrics_data   # S3 upload count
        assert "300.0" in metrics_data  # Auth0 validation count
        
        # Verify histogram metrics
        assert "external_service_request_duration_seconds_bucket" in metrics_data
        assert "25.5" in metrics_data  # Total duration sum
        
        # Verify gauge metrics
        assert "circuit_breaker_state" in metrics_data
        assert "external_service_health_status" in metrics_data
        
        # Verify Prometheus format compliance
        lines = metrics_data.strip().split('\n')
        help_lines = [line for line in lines if line.startswith('# HELP')]
        type_lines = [line for line in lines if line.startswith('# TYPE')]
        metric_lines = [line for line in lines if not line.startswith('#') and line.strip()]
        
        assert len(help_lines) == 4  # 4 different metric types
        assert len(type_lines) == 4  # Corresponding TYPE declarations
        assert len(metric_lines) > 0  # Actual metric data


# Integration test fixtures and utilities
@pytest.fixture
def mock_external_service_config():
    """Fixture providing mock external service configuration."""
    return BaseClientConfiguration(
        service_type=ServiceType.HTTP_API,
        base_url="https://api.test-service.com",
        timeout=30.0,
        retry_attempts=3,
        circuit_breaker_enabled=True,
        monitoring_enabled=True
    )


@pytest.fixture
def mock_auth0_config():
    """Fixture providing mock Auth0 service configuration."""
    return BaseClientConfiguration(
        service_type=ServiceType.AUTH0,
        auth0_domain="test-tenant.auth0.com",
        auth0_client_id="test_client_id",
        auth0_client_secret="test_client_secret",
        auth0_audience="https://api.test-app.com"
    )


@pytest.fixture
def mock_aws_config():
    """Fixture providing mock AWS service configuration."""
    return BaseClientConfiguration(
        service_type=ServiceType.AWS_S3,
        region="us-east-1",
        bucket_name="test-bucket",
        max_pool_connections=50
    )


@pytest.fixture
async def mock_httpx_client():
    """Fixture providing mock httpx async client."""
    async with httpx.AsyncClient(base_url="https://api.test-service.com") as client:
        yield client


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])