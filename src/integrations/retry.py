"""
Retry logic implementation using tenacity library for intelligent exponential backoff strategies.

This module provides comprehensive retry management for external service integration with
configurable maximum attempts, jitter injection, error classification-based retry policies,
and circuit breaker coordination. Implements enterprise-grade retry patterns with
monitoring and metrics collection for operational excellence.

Aligned with:
- Section 6.3.3: External Systems - Advanced Retry Patterns with tenacity integration
- Section 6.3.5: Performance and Scalability - Resilience and monitoring requirements
- Section 4.2.3: Error Handling and Recovery - Tenacity exponential backoff strategies
- Section 6.5.1: Monitoring Infrastructure - Prometheus metrics collection
"""

import functools
import logging
import random
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Type, Union

import structlog
from prometheus_client import Counter, Histogram, Gauge
from tenacity import (
    Retrying,
    RetryError as TenacityRetryError,
    retry,
    retry_if_exception_type,
    retry_unless_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_exponential_jitter,
    before_sleep_log,
    after_log,
    AsyncRetrying
)

from .exceptions import (
    IntegrationError,
    RetryError,
    RetryExhaustedError,
    RetryBackoffError,
    HTTPClientError,
    TimeoutError,
    ConnectionError,
    CircuitBreakerOpenError,
    Auth0Error,
    AWSServiceError,
    MongoDBError,
    RedisError,
    IntegrationExceptionFactory
)

# Initialize structured logger for retry operations
logger = structlog.get_logger(__name__)

# Prometheus metrics for retry monitoring per Section 6.5.1
retry_attempts_total = Counter(
    'retry_attempts_total',
    'Total number of retry attempts by service and operation',
    ['service_name', 'operation', 'attempt_number']
)

retry_success_total = Counter(
    'retry_success_total',
    'Total number of successful retries by service and operation',
    ['service_name', 'operation', 'final_attempt']
)

retry_exhausted_total = Counter(
    'retry_exhausted_total',
    'Total number of exhausted retry attempts by service and operation',
    ['service_name', 'operation', 'max_attempts']
)

retry_backoff_duration = Histogram(
    'retry_backoff_duration_seconds',
    'Duration of retry backoff periods by service and operation',
    ['service_name', 'operation'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

retry_total_duration = Histogram(
    'retry_total_duration_seconds',
    'Total duration of retry cycles by service and operation',
    ['service_name', 'operation'],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
)

active_retries_gauge = Gauge(
    'active_retries_current',
    'Current number of active retry operations by service',
    ['service_name', 'operation']
)

retry_error_classification = Counter(
    'retry_error_classification_total',
    'Count of errors by classification for retry decisions',
    ['service_name', 'operation', 'error_type', 'retry_decision']
)


class RetryConfiguration:
    """
    Configuration class for retry strategies with service-specific patterns.
    
    Provides intelligent retry configuration for different external service types
    with customizable backoff strategies, jitter implementation, and error
    classification patterns aligned with Section 6.3.3 requirements.
    """
    
    # Default configurations per service type
    DEFAULT_CONFIGS = {
        'auth0': {
            'max_attempts': 3,
            'min_wait': 1.0,
            'max_wait': 30.0,
            'jitter_max': 2.0,
            'exponential_base': 2,
            'retryable_exceptions': (HTTPClientError, TimeoutError, ConnectionError),
            'non_retryable_exceptions': (Auth0Error,),
            'circuit_breaker_threshold': 5
        },
        'aws_s3': {
            'max_attempts': 4,
            'min_wait': 0.5,
            'max_wait': 60.0,
            'jitter_max': 3.0,
            'exponential_base': 2,
            'retryable_exceptions': (HTTPClientError, TimeoutError, ConnectionError),
            'non_retryable_exceptions': (AWSServiceError,),
            'circuit_breaker_threshold': 3
        },
        'mongodb': {
            'max_attempts': 5,
            'min_wait': 0.1,
            'max_wait': 10.0,
            'jitter_max': 1.0,
            'exponential_base': 1.5,
            'retryable_exceptions': (ConnectionError, TimeoutError),
            'non_retryable_exceptions': (MongoDBError,),
            'circuit_breaker_threshold': 10
        },
        'redis': {
            'max_attempts': 3,
            'min_wait': 0.1,
            'max_wait': 5.0,
            'jitter_max': 0.5,
            'exponential_base': 2,
            'retryable_exceptions': (ConnectionError, TimeoutError),
            'non_retryable_exceptions': (RedisError,),
            'circuit_breaker_threshold': 5
        },
        'external_api': {
            'max_attempts': 3,
            'min_wait': 2.0,
            'max_wait': 60.0,
            'jitter_max': 5.0,
            'exponential_base': 2,
            'retryable_exceptions': (HTTPClientError, TimeoutError, ConnectionError),
            'non_retryable_exceptions': (),
            'circuit_breaker_threshold': 5
        },
        'default': {
            'max_attempts': 3,
            'min_wait': 1.0,
            'max_wait': 30.0,
            'jitter_max': 2.0,
            'exponential_base': 2,
            'retryable_exceptions': (HTTPClientError, TimeoutError, ConnectionError),
            'non_retryable_exceptions': (),
            'circuit_breaker_threshold': 5
        }
    }
    
    def __init__(
        self,
        service_name: str,
        operation: str,
        max_attempts: Optional[int] = None,
        min_wait: Optional[float] = None,
        max_wait: Optional[float] = None,
        jitter_max: Optional[float] = None,
        exponential_base: Optional[float] = None,
        retryable_exceptions: Optional[tuple] = None,
        non_retryable_exceptions: Optional[tuple] = None,
        circuit_breaker_threshold: Optional[int] = None,
        custom_error_classifier: Optional[Callable] = None
    ):
        """
        Initialize retry configuration for specific service and operation.
        
        Args:
            service_name: Name of the external service
            operation: Specific operation being performed
            max_attempts: Maximum number of retry attempts
            min_wait: Minimum wait time between retries (seconds)
            max_wait: Maximum wait time between retries (seconds)
            jitter_max: Maximum jitter to add to wait time (seconds)
            exponential_base: Base for exponential backoff calculation
            retryable_exceptions: Tuple of exception types that should trigger retries
            non_retryable_exceptions: Tuple of exception types that should not be retried
            circuit_breaker_threshold: Number of failures before circuit breaker activation
            custom_error_classifier: Custom function for error classification
        """
        self.service_name = service_name
        self.operation = operation
        
        # Get base configuration for service type
        service_config = self.DEFAULT_CONFIGS.get(service_name, self.DEFAULT_CONFIGS['default'])
        
        # Apply configuration with override priority
        self.max_attempts = max_attempts or service_config['max_attempts']
        self.min_wait = min_wait or service_config['min_wait']
        self.max_wait = max_wait or service_config['max_wait']
        self.jitter_max = jitter_max or service_config['jitter_max']
        self.exponential_base = exponential_base or service_config['exponential_base']
        self.retryable_exceptions = retryable_exceptions or service_config['retryable_exceptions']
        self.non_retryable_exceptions = non_retryable_exceptions or service_config['non_retryable_exceptions']
        self.circuit_breaker_threshold = circuit_breaker_threshold or service_config['circuit_breaker_threshold']
        self.custom_error_classifier = custom_error_classifier
        
        # Initialize retry state tracking
        self._failure_count = 0
        self._last_failure_time = None
        self._circuit_open_until = None
        
        logger.info(
            "Retry configuration initialized",
            service_name=service_name,
            operation=operation,
            max_attempts=self.max_attempts,
            min_wait=self.min_wait,
            max_wait=self.max_wait,
            jitter_max=self.jitter_max
        )
    
    def is_retryable_error(self, exception: Exception) -> bool:
        """
        Classify error for retry decision using error classification patterns.
        
        Implements intelligent error classification per Section 6.3.3 advanced
        retry patterns with support for custom error classifiers and circuit
        breaker integration.
        
        Args:
            exception: Exception to classify
            
        Returns:
            True if the error should trigger a retry, False otherwise
        """
        error_type = type(exception).__name__
        
        # Check for circuit breaker state
        if self._is_circuit_open():
            retry_error_classification.labels(
                service_name=self.service_name,
                operation=self.operation,
                error_type=error_type,
                retry_decision='circuit_open'
            ).inc()
            return False
        
        # Check non-retryable exceptions first
        if isinstance(exception, self.non_retryable_exceptions):
            retry_error_classification.labels(
                service_name=self.service_name,
                operation=self.operation,
                error_type=error_type,
                retry_decision='non_retryable'
            ).inc()
            return False
        
        # Check for circuit breaker specific errors
        if isinstance(exception, CircuitBreakerOpenError):
            retry_error_classification.labels(
                service_name=self.service_name,
                operation=self.operation,
                error_type=error_type,
                retry_decision='circuit_breaker_open'
            ).inc()
            return False
        
        # Apply custom error classifier if provided
        if self.custom_error_classifier:
            custom_result = self.custom_error_classifier(exception)
            if custom_result is not None:
                retry_error_classification.labels(
                    service_name=self.service_name,
                    operation=self.operation,
                    error_type=error_type,
                    retry_decision='custom_classifier'
                ).inc()
                return custom_result
        
        # Check retryable exceptions
        if isinstance(exception, self.retryable_exceptions):
            retry_error_classification.labels(
                service_name=self.service_name,
                operation=self.operation,
                error_type=error_type,
                retry_decision='retryable'
            ).inc()
            return True
        
        # Check for specific HTTP status codes that are retryable
        if isinstance(exception, HTTPClientError):
            status_code = getattr(exception, 'status_code', None)
            if status_code:
                if status_code in [429, 502, 503, 504, 408]:  # Retryable HTTP status codes
                    retry_error_classification.labels(
                        service_name=self.service_name,
                        operation=self.operation,
                        error_type=f"{error_type}_{status_code}",
                        retry_decision='retryable_http_status'
                    ).inc()
                    return True
                elif 400 <= status_code < 500:  # Client errors (not retryable)
                    retry_error_classification.labels(
                        service_name=self.service_name,
                        operation=self.operation,
                        error_type=f"{error_type}_{status_code}",
                        retry_decision='client_error'
                    ).inc()
                    return False
        
        # Default to non-retryable for unknown errors
        retry_error_classification.labels(
            service_name=self.service_name,
            operation=self.operation,
            error_type=error_type,
            retry_decision='unknown_non_retryable'
        ).inc()
        return False
    
    def record_failure(self):
        """Record a failure for circuit breaker tracking."""
        self._failure_count += 1
        self._last_failure_time = datetime.utcnow()
        
        # Check if circuit breaker should open
        if self._failure_count >= self.circuit_breaker_threshold:
            self._circuit_open_until = datetime.utcnow() + timedelta(seconds=60)  # 60 second circuit open period
            logger.warning(
                "Circuit breaker opened due to failure threshold",
                service_name=self.service_name,
                operation=self.operation,
                failure_count=self._failure_count,
                threshold=self.circuit_breaker_threshold
            )
    
    def record_success(self):
        """Record a success for circuit breaker tracking."""
        self._failure_count = 0
        self._last_failure_time = None
        self._circuit_open_until = None
    
    def _is_circuit_open(self) -> bool:
        """Check if circuit breaker is currently open."""
        if self._circuit_open_until is None:
            return False
        
        if datetime.utcnow() >= self._circuit_open_until:
            # Circuit breaker timeout expired, reset state
            self._circuit_open_until = None
            self._failure_count = 0
            logger.info(
                "Circuit breaker timeout expired, resetting",
                service_name=self.service_name,
                operation=self.operation
            )
            return False
        
        return True
    
    def get_tenacity_config(self):
        """
        Generate tenacity configuration for this retry strategy.
        
        Returns:
            Dictionary containing tenacity configuration parameters
        """
        return {
            'stop': stop_after_attempt(self.max_attempts),
            'wait': wait_exponential_jitter(
                initial=self.min_wait,
                max=self.max_wait,
                exp_base=self.exponential_base,
                jitter=self.jitter_max
            ),
            'retry': retry_if_exception_type(self.retryable_exceptions),
            'before_sleep': self._before_sleep_callback,
            'after': self._after_callback,
            'reraise': True
        }
    
    def _before_sleep_callback(self, retry_state):
        """Callback executed before each retry sleep period."""
        attempt_number = retry_state.attempt_number
        next_action = retry_state.next_action
        outcome = retry_state.outcome
        
        if outcome and outcome.failed:
            exception = outcome.exception()
            
            # Record retry metrics
            retry_attempts_total.labels(
                service_name=self.service_name,
                operation=self.operation,
                attempt_number=str(attempt_number)
            ).inc()
            
            # Calculate and record backoff duration
            if hasattr(next_action, 'sleep'):
                backoff_duration = next_action.sleep
                retry_backoff_duration.labels(
                    service_name=self.service_name,
                    operation=self.operation
                ).observe(backoff_duration)
            
            logger.warning(
                "Retry attempt failed, backing off",
                service_name=self.service_name,
                operation=self.operation,
                attempt_number=attempt_number,
                exception_type=type(exception).__name__,
                exception_message=str(exception),
                backoff_duration=getattr(next_action, 'sleep', 0),
                correlation_id=getattr(exception, 'correlation_id', None)
            )
    
    def _after_callback(self, retry_state):
        """Callback executed after retry completion."""
        attempt_number = retry_state.attempt_number
        outcome = retry_state.outcome
        
        if outcome.failed:
            # Retry exhausted
            retry_exhausted_total.labels(
                service_name=self.service_name,
                operation=self.operation,
                max_attempts=str(self.max_attempts)
            ).inc()
            
            logger.error(
                "Retry attempts exhausted",
                service_name=self.service_name,
                operation=self.operation,
                total_attempts=attempt_number,
                max_attempts=self.max_attempts,
                final_exception=str(outcome.exception())
            )
        else:
            # Success after retries
            retry_success_total.labels(
                service_name=self.service_name,
                operation=self.operation,
                final_attempt=str(attempt_number)
            ).inc()
            
            logger.info(
                "Retry cycle completed successfully",
                service_name=self.service_name,
                operation=self.operation,
                total_attempts=attempt_number,
                success=True
            )


class RetryManager:
    """
    Central retry management system for external service integration.
    
    Provides comprehensive retry management with configuration caching,
    metrics collection, and enterprise-grade monitoring integration
    per Section 6.3.5 requirements.
    """
    
    def __init__(self):
        """Initialize retry manager with configuration cache."""
        self._configurations: Dict[str, RetryConfiguration] = {}
        self._active_retries: Dict[str, int] = {}
        
        logger.info("Retry manager initialized")
    
    def get_configuration(
        self,
        service_name: str,
        operation: str,
        **kwargs
    ) -> RetryConfiguration:
        """
        Get or create retry configuration for service and operation.
        
        Args:
            service_name: Name of the external service
            operation: Specific operation being performed
            **kwargs: Additional configuration parameters
            
        Returns:
            RetryConfiguration instance for the service/operation
        """
        config_key = f"{service_name}:{operation}"
        
        if config_key not in self._configurations:
            self._configurations[config_key] = RetryConfiguration(
                service_name=service_name,
                operation=operation,
                **kwargs
            )
        
        return self._configurations[config_key]
    
    def execute_with_retry(
        self,
        func: Callable,
        service_name: str,
        operation: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute function with comprehensive retry logic and monitoring.
        
        Implements tenacity-based retry with exponential backoff, jitter,
        error classification, and circuit breaker integration per
        Section 6.3.3 advanced retry patterns.
        
        Args:
            func: Function to execute with retry logic
            service_name: Name of the external service
            operation: Specific operation being performed
            *args: Arguments to pass to function
            **kwargs: Keyword arguments to pass to function
            
        Returns:
            Result of successful function execution
            
        Raises:
            RetryExhaustedError: When maximum retry attempts are exhausted
            CircuitBreakerOpenError: When circuit breaker is open
        """
        config = self.get_configuration(service_name, operation)
        retry_key = f"{service_name}:{operation}"
        
        # Track active retries
        self._active_retries[retry_key] = self._active_retries.get(retry_key, 0) + 1
        active_retries_gauge.labels(
            service_name=service_name,
            operation=operation
        ).set(self._active_retries[retry_key])
        
        start_time = time.time()
        
        try:
            # Check circuit breaker state before starting
            if config._is_circuit_open():
                raise CircuitBreakerOpenError(
                    service_name=service_name,
                    operation=operation,
                    time_until_reset=int((config._circuit_open_until - datetime.utcnow()).total_seconds())
                )
            
            # Create tenacity Retrying instance with configuration
            retrying = Retrying(**config.get_tenacity_config())
            
            # Execute function with retry logic
            result = retrying(func, *args, **kwargs)
            
            # Record success
            config.record_success()
            
            total_duration = time.time() - start_time
            retry_total_duration.labels(
                service_name=service_name,
                operation=operation
            ).observe(total_duration)
            
            logger.info(
                "Function executed successfully with retry manager",
                service_name=service_name,
                operation=operation,
                total_duration=total_duration,
                success=True
            )
            
            return result
            
        except TenacityRetryError as e:
            # Record failure for circuit breaker
            config.record_failure()
            
            total_duration = time.time() - start_time
            retry_total_duration.labels(
                service_name=service_name,
                operation=operation
            ).observe(total_duration)
            
            # Extract original exception
            original_exception = e.last_attempt.exception()
            
            # Create comprehensive retry exhausted error
            retry_exhausted_error = RetryExhaustedError(
                service_name=service_name,
                operation=operation,
                max_retries=config.max_attempts,
                last_exception=original_exception,
                total_duration=total_duration
            )
            
            logger.error(
                "Retry attempts exhausted for function execution",
                service_name=service_name,
                operation=operation,
                max_attempts=config.max_attempts,
                total_duration=total_duration,
                last_exception=str(original_exception),
                exc_info=e
            )
            
            raise retry_exhausted_error from original_exception
            
        except Exception as e:
            # Record failure for circuit breaker
            config.record_failure()
            
            total_duration = time.time() - start_time
            retry_total_duration.labels(
                service_name=service_name,
                operation=operation
            ).observe(total_duration)
            
            logger.error(
                "Unexpected error during retry execution",
                service_name=service_name,
                operation=operation,
                total_duration=total_duration,
                exception=str(e),
                exc_info=e
            )
            
            raise
            
        finally:
            # Update active retries tracking
            self._active_retries[retry_key] = max(0, self._active_retries.get(retry_key, 1) - 1)
            active_retries_gauge.labels(
                service_name=service_name,
                operation=operation
            ).set(self._active_retries[retry_key])
    
    async def execute_with_retry_async(
        self,
        func: Callable,
        service_name: str,
        operation: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute async function with comprehensive retry logic and monitoring.
        
        Implements async tenacity-based retry with exponential backoff, jitter,
        error classification, and circuit breaker integration for async operations.
        
        Args:
            func: Async function to execute with retry logic
            service_name: Name of the external service
            operation: Specific operation being performed
            *args: Arguments to pass to function
            **kwargs: Keyword arguments to pass to function
            
        Returns:
            Result of successful async function execution
            
        Raises:
            RetryExhaustedError: When maximum retry attempts are exhausted
            CircuitBreakerOpenError: When circuit breaker is open
        """
        config = self.get_configuration(service_name, operation)
        retry_key = f"{service_name}:{operation}"
        
        # Track active retries
        self._active_retries[retry_key] = self._active_retries.get(retry_key, 0) + 1
        active_retries_gauge.labels(
            service_name=service_name,
            operation=operation
        ).set(self._active_retries[retry_key])
        
        start_time = time.time()
        
        try:
            # Check circuit breaker state before starting
            if config._is_circuit_open():
                raise CircuitBreakerOpenError(
                    service_name=service_name,
                    operation=operation,
                    time_until_reset=int((config._circuit_open_until - datetime.utcnow()).total_seconds())
                )
            
            # Create async tenacity Retrying instance
            retrying = AsyncRetrying(**config.get_tenacity_config())
            
            # Execute async function with retry logic
            result = await retrying(func, *args, **kwargs)
            
            # Record success
            config.record_success()
            
            total_duration = time.time() - start_time
            retry_total_duration.labels(
                service_name=service_name,
                operation=operation
            ).observe(total_duration)
            
            logger.info(
                "Async function executed successfully with retry manager",
                service_name=service_name,
                operation=operation,
                total_duration=total_duration,
                success=True
            )
            
            return result
            
        except TenacityRetryError as e:
            # Record failure for circuit breaker
            config.record_failure()
            
            total_duration = time.time() - start_time
            retry_total_duration.labels(
                service_name=service_name,
                operation=operation
            ).observe(total_duration)
            
            # Extract original exception
            original_exception = e.last_attempt.exception()
            
            # Create comprehensive retry exhausted error
            retry_exhausted_error = RetryExhaustedError(
                service_name=service_name,
                operation=operation,
                max_retries=config.max_attempts,
                last_exception=original_exception,
                total_duration=total_duration
            )
            
            logger.error(
                "Async retry attempts exhausted for function execution",
                service_name=service_name,
                operation=operation,
                max_attempts=config.max_attempts,
                total_duration=total_duration,
                last_exception=str(original_exception),
                exc_info=e
            )
            
            raise retry_exhausted_error from original_exception
            
        finally:
            # Update active retries tracking
            self._active_retries[retry_key] = max(0, self._active_retries.get(retry_key, 1) - 1)
            active_retries_gauge.labels(
                service_name=service_name,
                operation=operation
            ).set(self._active_retries[retry_key])
    
    def get_retry_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive retry statistics for monitoring and observability.
        
        Returns:
            Dictionary containing retry statistics and configuration details
        """
        stats = {
            'active_retries': dict(self._active_retries),
            'configurations': {
                key: {
                    'service_name': config.service_name,
                    'operation': config.operation,
                    'max_attempts': config.max_attempts,
                    'min_wait': config.min_wait,
                    'max_wait': config.max_wait,
                    'failure_count': config._failure_count,
                    'circuit_open': config._is_circuit_open(),
                    'circuit_open_until': config._circuit_open_until.isoformat() if config._circuit_open_until else None
                }
                for key, config in self._configurations.items()
            },
            'total_configurations': len(self._configurations),
            'total_active_retries': sum(self._active_retries.values())
        }
        
        return stats


# Global retry manager instance
retry_manager = RetryManager()


def with_retry(
    service_name: str,
    operation: str,
    max_attempts: Optional[int] = None,
    min_wait: Optional[float] = None,
    max_wait: Optional[float] = None,
    jitter_max: Optional[float] = None,
    custom_error_classifier: Optional[Callable] = None
):
    """
    Decorator for adding comprehensive retry logic to functions.
    
    Implements intelligent exponential backoff with jitter, error classification,
    and circuit breaker integration per Section 6.3.3 advanced retry patterns.
    
    Args:
        service_name: Name of the external service
        operation: Specific operation being performed
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries (seconds)
        max_wait: Maximum wait time between retries (seconds)
        jitter_max: Maximum jitter to add to wait time (seconds)
        custom_error_classifier: Custom function for error classification
        
    Returns:
        Decorated function with retry capabilities
        
    Example:
        @with_retry('auth0', 'validate_token', max_attempts=3)
        def validate_jwt_token(token):
            # Function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract retry configuration parameters
            config_params = {}
            if max_attempts is not None:
                config_params['max_attempts'] = max_attempts
            if min_wait is not None:
                config_params['min_wait'] = min_wait
            if max_wait is not None:
                config_params['max_wait'] = max_wait
            if jitter_max is not None:
                config_params['jitter_max'] = jitter_max
            if custom_error_classifier is not None:
                config_params['custom_error_classifier'] = custom_error_classifier
            
            # Update configuration if parameters provided
            if config_params:
                config_key = f"{service_name}:{operation}"
                retry_manager._configurations[config_key] = RetryConfiguration(
                    service_name=service_name,
                    operation=operation,
                    **config_params
                )
            
            return retry_manager.execute_with_retry(
                func, service_name, operation, *args, **kwargs
            )
        
        return wrapper
    return decorator


def with_retry_async(
    service_name: str,
    operation: str,
    max_attempts: Optional[int] = None,
    min_wait: Optional[float] = None,
    max_wait: Optional[float] = None,
    jitter_max: Optional[float] = None,
    custom_error_classifier: Optional[Callable] = None
):
    """
    Decorator for adding comprehensive retry logic to async functions.
    
    Implements intelligent exponential backoff with jitter, error classification,
    and circuit breaker integration for async operations per Section 6.3.3.
    
    Args:
        service_name: Name of the external service
        operation: Specific operation being performed
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries (seconds)
        max_wait: Maximum wait time between retries (seconds)
        jitter_max: Maximum jitter to add to wait time (seconds)
        custom_error_classifier: Custom function for error classification
        
    Returns:
        Decorated async function with retry capabilities
        
    Example:
        @with_retry_async('aws_s3', 'upload_file', max_attempts=4)
        async def upload_file_to_s3(file_data):
            # Async function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract retry configuration parameters
            config_params = {}
            if max_attempts is not None:
                config_params['max_attempts'] = max_attempts
            if min_wait is not None:
                config_params['min_wait'] = min_wait
            if max_wait is not None:
                config_params['max_wait'] = max_wait
            if jitter_max is not None:
                config_params['jitter_max'] = jitter_max
            if custom_error_classifier is not None:
                config_params['custom_error_classifier'] = custom_error_classifier
            
            # Update configuration if parameters provided
            if config_params:
                config_key = f"{service_name}:{operation}"
                retry_manager._configurations[config_key] = RetryConfiguration(
                    service_name=service_name,
                    operation=operation,
                    **config_params
                )
            
            return await retry_manager.execute_with_retry_async(
                func, service_name, operation, *args, **kwargs
            )
        
        return wrapper
    return decorator


# Service-specific convenience decorators
def with_auth0_retry(operation: str, **kwargs):
    """Convenience decorator for Auth0 service retry patterns."""
    return with_retry('auth0', operation, **kwargs)


def with_aws_retry(operation: str, **kwargs):
    """Convenience decorator for AWS service retry patterns."""
    return with_retry('aws_s3', operation, **kwargs)


def with_database_retry(operation: str, **kwargs):
    """Convenience decorator for MongoDB retry patterns."""
    return with_retry('mongodb', operation, **kwargs)


def with_cache_retry(operation: str, **kwargs):
    """Convenience decorator for Redis cache retry patterns."""
    return with_retry('redis', operation, **kwargs)


def with_api_retry(operation: str, **kwargs):
    """Convenience decorator for external API retry patterns."""
    return with_retry('external_api', operation, **kwargs)


# Async versions of convenience decorators
def with_auth0_retry_async(operation: str, **kwargs):
    """Async convenience decorator for Auth0 service retry patterns."""
    return with_retry_async('auth0', operation, **kwargs)


def with_aws_retry_async(operation: str, **kwargs):
    """Async convenience decorator for AWS service retry patterns."""
    return with_retry_async('aws_s3', operation, **kwargs)


def with_database_retry_async(operation: str, **kwargs):
    """Async convenience decorator for MongoDB retry patterns."""
    return with_retry_async('mongodb', operation, **kwargs)


def with_cache_retry_async(operation: str, **kwargs):
    """Async convenience decorator for Redis cache retry patterns."""
    return with_retry_async('redis', operation, **kwargs)


def with_api_retry_async(operation: str, **kwargs):
    """Async convenience decorator for external API retry patterns."""
    return with_retry_async('external_api', operation, **kwargs)


def create_custom_error_classifier(
    retryable_status_codes: Optional[List[int]] = None,
    non_retryable_status_codes: Optional[List[int]] = None,
    retryable_error_messages: Optional[List[str]] = None,
    non_retryable_error_messages: Optional[List[str]] = None
) -> Callable:
    """
    Create custom error classifier for advanced retry logic.
    
    Enables creation of service-specific error classification logic for
    sophisticated retry decision making per Section 6.3.3 requirements.
    
    Args:
        retryable_status_codes: HTTP status codes that should trigger retries
        non_retryable_status_codes: HTTP status codes that should not trigger retries
        retryable_error_messages: Error message patterns that should trigger retries
        non_retryable_error_messages: Error message patterns that should not trigger retries
        
    Returns:
        Custom error classifier function
        
    Example:
        classifier = create_custom_error_classifier(
            retryable_status_codes=[503, 504],
            non_retryable_status_codes=[401, 403],
            retryable_error_messages=['timeout', 'connection reset'],
            non_retryable_error_messages=['invalid credentials', 'access denied']
        )
    """
    def classifier(exception: Exception) -> Optional[bool]:
        """
        Custom error classifier implementation.
        
        Args:
            exception: Exception to classify
            
        Returns:
            True if retryable, False if not retryable, None for default handling
        """
        # Check HTTP status codes for HTTPClientError instances
        if isinstance(exception, HTTPClientError) and hasattr(exception, 'status_code'):
            status_code = exception.status_code
            
            if non_retryable_status_codes and status_code in non_retryable_status_codes:
                return False
            
            if retryable_status_codes and status_code in retryable_status_codes:
                return True
        
        # Check error message patterns
        error_message = str(exception).lower()
        
        if non_retryable_error_messages:
            for pattern in non_retryable_error_messages:
                if pattern.lower() in error_message:
                    return False
        
        if retryable_error_messages:
            for pattern in retryable_error_messages:
                if pattern.lower() in error_message:
                    return True
        
        # Return None for default handling
        return None
    
    return classifier


def get_retry_metrics() -> Dict[str, Any]:
    """
    Get comprehensive retry metrics for monitoring and observability.
    
    Returns:
        Dictionary containing current retry metrics and statistics
    """
    return retry_manager.get_retry_statistics()


def reset_circuit_breaker(service_name: str, operation: str) -> bool:
    """
    Manually reset circuit breaker for specific service and operation.
    
    Args:
        service_name: Name of the external service
        operation: Specific operation
        
    Returns:
        True if circuit breaker was reset, False if configuration not found
    """
    config_key = f"{service_name}:{operation}"
    config = retry_manager._configurations.get(config_key)
    
    if config:
        config.record_success()  # This resets the circuit breaker
        
        logger.info(
            "Circuit breaker manually reset",
            service_name=service_name,
            operation=operation
        )
        
        return True
    
    return False


# Advanced retry pattern examples and utilities
class RetryPatterns:
    """
    Collection of advanced retry patterns for common integration scenarios.
    
    Provides pre-configured retry patterns for typical external service
    integration patterns following Section 6.3.3 best practices.
    """
    
    @staticmethod
    def aggressive_retry_pattern(service_name: str, operation: str):
        """Aggressive retry pattern for critical services."""
        return RetryConfiguration(
            service_name=service_name,
            operation=operation,
            max_attempts=5,
            min_wait=0.1,
            max_wait=10.0,
            jitter_max=1.0,
            exponential_base=1.5
        )
    
    @staticmethod
    def conservative_retry_pattern(service_name: str, operation: str):
        """Conservative retry pattern for rate-limited services."""
        return RetryConfiguration(
            service_name=service_name,
            operation=operation,
            max_attempts=2,
            min_wait=5.0,
            max_wait=60.0,
            jitter_max=10.0,
            exponential_base=3
        )
    
    @staticmethod
    def bulk_operation_retry_pattern(service_name: str, operation: str):
        """Retry pattern optimized for bulk operations."""
        return RetryConfiguration(
            service_name=service_name,
            operation=operation,
            max_attempts=3,
            min_wait=2.0,
            max_wait=30.0,
            jitter_max=5.0,
            exponential_base=2
        )