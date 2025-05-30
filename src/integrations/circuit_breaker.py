"""
Circuit Breaker Implementation for External Service Protection

This module implements comprehensive circuit breaker patterns using the pybreaker library for
external service resilience, automatic failure detection, and fallback mechanisms. It provides
configurable failure thresholds, half-open state management, and state transition monitoring
with Prometheus metrics integration per Section 6.3.3 and 6.3.5 specifications.

Key Features:
- Service-specific failure threshold configuration per Section 6.3.5
- Automatic failure detection and recovery automation per Section 6.3.3
- Fallback mechanisms preventing cascade failures per Section 6.3.3
- State transition monitoring with Prometheus metrics per Section 6.3.5
- Graceful degradation patterns for service outages per Section 6.3.3
- Enterprise-grade monitoring integration per Section 6.5.1.1

Performance Requirements:
- Circuit breaker overhead <1ms per request per Section 6.5.1.1
- ≤10% variance from Node.js baseline per Section 0.3.2
- Real-time state transition monitoring per Section 6.3.5
- Enterprise APM integration compatibility per Section 6.5.4
"""

import time
import logging
import functools
import asyncio
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Type, Union
from enum import Enum
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from threading import RLock

# Circuit breaker implementation using pybreaker
import pybreaker

# Structured logging for enterprise integration
import structlog

# Custom exception hierarchy for integration error handling
from src.integrations.exceptions import (
    CircuitBreakerError,
    CircuitBreakerOpenError,
    CircuitBreakerHalfOpenError,
    IntegrationError,
    HTTPClientError,
    TimeoutError,
    ConnectionError,
    RetryExhaustedError,
    Auth0Error,
    AWSServiceError,
    MongoDBError,
    RedisError,
    IntegrationExceptionFactory
)

# External service monitoring integration
from src.integrations.monitoring import (
    external_service_monitor,
    ServiceType,
    CircuitBreakerState,
    HealthStatus,
    record_circuit_breaker_event,
    update_service_health
)

logger = structlog.get_logger(__name__)


class CircuitBreakerConfig:
    """
    Circuit breaker configuration management per Section 6.3.5 specifications.
    
    Provides service-specific failure thresholds, half-open timeout configuration,
    and recovery parameters based on service criticality and operational requirements.
    """
    
    # Service-specific failure thresholds per Section 6.3.5
    SERVICE_FAILURE_THRESHOLDS = {
        ServiceType.AUTH: {
            'fail_max': 5,
            'reset_timeout': 60,
            'name': 'auth_service_circuit_breaker'
        },
        ServiceType.AWS: {
            'fail_max': 3,
            'reset_timeout': 60,
            'name': 'aws_service_circuit_breaker'
        },
        ServiceType.DATABASE: {
            'fail_max': 10,
            'reset_timeout': 120,
            'name': 'database_circuit_breaker'
        },
        ServiceType.CACHE: {
            'fail_max': 10,
            'reset_timeout': 30,
            'name': 'cache_circuit_breaker'
        },
        ServiceType.API: {
            'fail_max': 5,
            'reset_timeout': 60,
            'name': 'external_api_circuit_breaker'
        },
        ServiceType.WEBHOOK: {
            'fail_max': 3,
            'reset_timeout': 90,
            'name': 'webhook_circuit_breaker'
        },
        ServiceType.FILE_STORAGE: {
            'fail_max': 3,
            'reset_timeout': 60,
            'name': 'file_storage_circuit_breaker'
        }
    }
    
    # Default configuration for unknown service types
    DEFAULT_CONFIG = {
        'fail_max': 5,
        'reset_timeout': 60,
        'name': 'default_circuit_breaker'
    }
    
    # Exception types that should trigger circuit breaker failures
    FAILURE_EXCEPTIONS = (
        ConnectionError,
        TimeoutError,
        HTTPClientError,
        IntegrationError,
        RetryExhaustedError,
        Auth0Error,
        AWSServiceError,
        MongoDBError,
        RedisError
    )
    
    # Exception types that should NOT trigger circuit breaker failures
    NON_FAILURE_EXCEPTIONS = (
        ValueError,
        TypeError,
        KeyError,
        AttributeError
    )
    
    @classmethod
    def get_config(cls, service_type: ServiceType) -> Dict[str, Any]:
        """
        Get circuit breaker configuration for service type.
        
        Args:
            service_type: Type of external service
            
        Returns:
            Configuration dictionary with failure thresholds and timeouts
        """
        return cls.SERVICE_FAILURE_THRESHOLDS.get(service_type, cls.DEFAULT_CONFIG)
    
    @classmethod
    def should_count_as_failure(cls, exception: Exception) -> bool:
        """
        Determine if exception should count as circuit breaker failure.
        
        Args:
            exception: Exception instance to evaluate
            
        Returns:
            True if exception should trigger circuit breaker failure
        """
        # Explicitly non-failure exceptions
        if isinstance(exception, cls.NON_FAILURE_EXCEPTIONS):
            return False
        
        # Explicitly failure exceptions
        if isinstance(exception, cls.FAILURE_EXCEPTIONS):
            return True
        
        # Default to counting as failure for unknown exceptions
        return True


class ExternalServiceCircuitBreaker:
    """
    Comprehensive circuit breaker implementation for external service protection.
    
    Implements pybreaker-based circuit breaker patterns with automatic failure detection,
    fallback mechanisms, and state transition monitoring. Provides service-specific
    configuration, Prometheus metrics integration, and graceful degradation capabilities.
    
    Features:
    - Service-specific failure threshold management per Section 6.3.5
    - Automatic failure detection and recovery automation per Section 6.3.3
    - State transition monitoring with Prometheus metrics per Section 6.3.5
    - Fallback mechanisms preventing cascade failures per Section 6.3.3
    - Graceful degradation patterns for service outages per Section 6.3.3
    """
    
    def __init__(
        self,
        service_name: str,
        service_type: ServiceType,
        fallback_function: Optional[Callable] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize circuit breaker for external service protection.
        
        Args:
            service_name: Unique service identifier
            service_type: Service type classification for configuration
            fallback_function: Optional fallback function for graceful degradation
            custom_config: Optional custom configuration overrides
        """
        self.service_name = service_name
        self.service_type = service_type
        self.fallback_function = fallback_function
        
        # Get service-specific configuration
        self.config = CircuitBreakerConfig.get_config(service_type)
        if custom_config:
            self.config.update(custom_config)
        
        # Initialize pybreaker circuit breaker with monitoring integration
        self.circuit_breaker = self._create_circuit_breaker()
        
        # State tracking for monitoring
        self._previous_state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._recovery_start_time: Optional[datetime] = None
        self._lock = RLock()
        
        # Register service for monitoring
        self._register_service_monitoring()
        
        logger.info(
            "circuit_breaker_initialized",
            service_name=service_name,
            service_type=service_type.value,
            config=self.config,
            component="integrations.circuit_breaker"
        )
    
    def _create_circuit_breaker(self) -> pybreaker.CircuitBreaker:
        """
        Create and configure pybreaker circuit breaker instance.
        
        Returns:
            Configured pybreaker CircuitBreaker instance
        """
        return pybreaker.CircuitBreaker(
            fail_max=self.config['fail_max'],
            reset_timeout=self.config['reset_timeout'],
            exclude=CircuitBreakerConfig.NON_FAILURE_EXCEPTIONS,
            listeners=[
                self._on_circuit_breaker_call,
                self._on_circuit_breaker_success,
                self._on_circuit_breaker_failure,
                self._on_circuit_breaker_fallback,
                self._on_circuit_breaker_open,
                self._on_circuit_breaker_close,
                self._on_circuit_breaker_half_open
            ],
            name=f"{self.service_name}_{self.config['name']}"
        )
    
    def _register_service_monitoring(self) -> None:
        """Register service with external service monitoring system."""
        try:
            external_service_monitor.register_service(
                service_name=self.service_name,
                service_type=self.service_type,
                endpoint_url=f"circuit_breaker://{self.service_name}",
                health_check_path="/health",
                metadata={
                    'circuit_breaker_config': self.config,
                    'failure_threshold': self.config['fail_max'],
                    'reset_timeout': self.config['reset_timeout']
                }
            )
        except Exception as e:
            logger.warning(
                "service_monitoring_registration_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.circuit_breaker"
            )
    
    # Circuit breaker event listeners for monitoring integration
    
    def _on_circuit_breaker_call(self, cb: pybreaker.CircuitBreaker) -> None:
        """Handle circuit breaker call event."""
        logger.debug(
            "circuit_breaker_call",
            service_name=self.service_name,
            state=cb.current_state,
            failure_count=cb.fail_counter,
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_success(self, cb: pybreaker.CircuitBreaker) -> None:
        """Handle circuit breaker success event."""
        with self._lock:
            self._failure_count = cb.fail_counter
            self._last_failure_time = None
            
            # Update monitoring metrics
            self._update_circuit_breaker_state(cb.current_state)
            
            # Update service health status
            update_service_health(
                service_name=self.service_name,
                service_type=self.service_type,
                status=HealthStatus.HEALTHY,
                duration=0.0,
                metadata={'circuit_breaker_state': cb.current_state}
            )
        
        logger.info(
            "circuit_breaker_success",
            service_name=self.service_name,
            state=cb.current_state,
            failure_count=cb.fail_counter,
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_failure(self, cb: pybreaker.CircuitBreaker, exception: Exception) -> None:
        """Handle circuit breaker failure event."""
        with self._lock:
            self._failure_count = cb.fail_counter
            self._last_failure_time = datetime.utcnow()
            
            # Record failure metrics
            external_service_monitor.record_circuit_breaker_failure(
                service_name=self.service_name,
                service_type=self.service_type,
                failure_reason=type(exception).__name__
            )
            
            # Update service health status
            health_status = HealthStatus.DEGRADED if cb.current_state == 'closed' else HealthStatus.UNHEALTHY
            update_service_health(
                service_name=self.service_name,
                service_type=self.service_type,
                status=health_status,
                duration=0.0,
                metadata={
                    'circuit_breaker_state': cb.current_state,
                    'failure_reason': str(exception),
                    'failure_count': cb.fail_counter
                }
            )
        
        logger.error(
            "circuit_breaker_failure",
            service_name=self.service_name,
            state=cb.current_state,
            failure_count=cb.fail_counter,
            exception=str(exception),
            exception_type=type(exception).__name__,
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_fallback(self, cb: pybreaker.CircuitBreaker, exception: Exception) -> None:
        """Handle circuit breaker fallback event."""
        logger.warning(
            "circuit_breaker_fallback_triggered",
            service_name=self.service_name,
            state=cb.current_state,
            exception=str(exception),
            has_fallback=self.fallback_function is not None,
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_open(self, cb: pybreaker.CircuitBreaker, prev_state: str, exception: Exception) -> None:
        """Handle circuit breaker open state transition."""
        with self._lock:
            previous_state = self._map_pybreaker_state_to_enum(prev_state)
            current_state = CircuitBreakerState.OPEN
            
            # Record state transition
            external_service_monitor.record_circuit_breaker_state(
                service_name=self.service_name,
                service_type=self.service_type,
                state=current_state,
                previous_state=previous_state
            )
            
            self._previous_state = current_state
            
            # Update service health to unhealthy
            update_service_health(
                service_name=self.service_name,
                service_type=self.service_type,
                status=HealthStatus.UNHEALTHY,
                duration=0.0,
                metadata={
                    'circuit_breaker_state': current_state.value,
                    'failure_count': cb.fail_counter,
                    'reset_timeout': self.config['reset_timeout']
                }
            )
        
        logger.warning(
            "circuit_breaker_opened",
            service_name=self.service_name,
            previous_state=prev_state,
            current_state="open",
            failure_count=cb.fail_counter,
            reset_timeout=self.config['reset_timeout'],
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_close(self, cb: pybreaker.CircuitBreaker, prev_state: str) -> None:
        """Handle circuit breaker close state transition."""
        with self._lock:
            previous_state = self._map_pybreaker_state_to_enum(prev_state)
            current_state = CircuitBreakerState.CLOSED
            
            # Record state transition
            external_service_monitor.record_circuit_breaker_state(
                service_name=self.service_name,
                service_type=self.service_type,
                state=current_state,
                previous_state=previous_state
            )
            
            self._previous_state = current_state
            self._recovery_start_time = None
            
            # Update service health to healthy
            update_service_health(
                service_name=self.service_name,
                service_type=self.service_type,
                status=HealthStatus.HEALTHY,
                duration=0.0,
                metadata={
                    'circuit_breaker_state': current_state.value,
                    'recovery_completed': True
                }
            )
        
        logger.info(
            "circuit_breaker_closed",
            service_name=self.service_name,
            previous_state=prev_state,
            current_state="closed",
            component="integrations.circuit_breaker"
        )
    
    def _on_circuit_breaker_half_open(self, cb: pybreaker.CircuitBreaker, prev_state: str) -> None:
        """Handle circuit breaker half-open state transition."""
        with self._lock:
            previous_state = self._map_pybreaker_state_to_enum(prev_state)
            current_state = CircuitBreakerState.HALF_OPEN
            
            # Record state transition
            external_service_monitor.record_circuit_breaker_state(
                service_name=self.service_name,
                service_type=self.service_type,
                state=current_state,
                previous_state=previous_state
            )
            
            self._previous_state = current_state
            self._recovery_start_time = datetime.utcnow()
            
            # Update service health to degraded during testing
            update_service_health(
                service_name=self.service_name,
                service_type=self.service_type,
                status=HealthStatus.DEGRADED,
                duration=0.0,
                metadata={
                    'circuit_breaker_state': current_state.value,
                    'recovery_testing': True
                }
            )
        
        logger.info(
            "circuit_breaker_half_open",
            service_name=self.service_name,
            previous_state=prev_state,
            current_state="half_open",
            component="integrations.circuit_breaker"
        )
    
    def _map_pybreaker_state_to_enum(self, state: str) -> CircuitBreakerState:
        """Map pybreaker state string to CircuitBreakerState enum."""
        state_mapping = {
            'closed': CircuitBreakerState.CLOSED,
            'open': CircuitBreakerState.OPEN,
            'half-open': CircuitBreakerState.HALF_OPEN
        }
        return state_mapping.get(state, CircuitBreakerState.CLOSED)
    
    def _update_circuit_breaker_state(self, current_state: str) -> None:
        """Update circuit breaker state in monitoring system."""
        state_enum = self._map_pybreaker_state_to_enum(current_state)
        external_service_monitor.record_circuit_breaker_state(
            service_name=self.service_name,
            service_type=self.service_type,
            state=state_enum,
            previous_state=self._previous_state
        )
        self._previous_state = state_enum
    
    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for protecting functions with circuit breaker.
        
        Args:
            func: Function to protect with circuit breaker
            
        Returns:
            Wrapped function with circuit breaker protection
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.call_with_circuit_breaker(func, *args, **kwargs)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await self.call_with_circuit_breaker_async(func, *args, **kwargs)
        
        # Return appropriate wrapper based on function type
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    
    def call_with_circuit_breaker(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or fallback result
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            CircuitBreakerHalfOpenError: When test call fails in half-open state
        """
        try:
            with external_service_monitor.track_request(
                service_name=self.service_name,
                service_type=self.service_type,
                method=kwargs.get('method', 'CALL'),
                endpoint=func.__name__
            ):
                result = self.circuit_breaker(func)(*args, **kwargs)
                return result
        
        except pybreaker.CircuitBreakerError as e:
            # Handle circuit breaker errors with appropriate exception types
            if self.circuit_breaker.current_state == 'open':
                time_until_reset = max(0, int(
                    self.config['reset_timeout'] - 
                    (time.time() - self.circuit_breaker._state_storage['last_failure_time'])
                ))
                
                circuit_error = CircuitBreakerOpenError(
                    service_name=self.service_name,
                    operation=func.__name__,
                    time_until_reset=time_until_reset,
                    failure_count=self._failure_count,
                    failure_threshold=self.config['fail_max'],
                    reset_timeout=self.config['reset_timeout']
                )
            elif self.circuit_breaker.current_state == 'half-open':
                circuit_error = CircuitBreakerHalfOpenError(
                    service_name=self.service_name,
                    operation=func.__name__,
                    failure_count=self._failure_count,
                    failure_threshold=self.config['fail_max']
                )
            else:
                circuit_error = CircuitBreakerError(
                    message=str(e),
                    service_name=self.service_name,
                    operation=func.__name__,
                    circuit_state=self.circuit_breaker.current_state,
                    failure_count=self._failure_count
                )
            
            # Attempt fallback if available
            if self.fallback_function:
                try:
                    logger.info(
                        "circuit_breaker_fallback_executed",
                        service_name=self.service_name,
                        operation=func.__name__,
                        component="integrations.circuit_breaker"
                    )
                    return self.fallback_function(*args, **kwargs)
                except Exception as fallback_error:
                    logger.error(
                        "circuit_breaker_fallback_failed",
                        service_name=self.service_name,
                        operation=func.__name__,
                        fallback_error=str(fallback_error),
                        component="integrations.circuit_breaker"
                    )
                    raise circuit_error from fallback_error
            
            raise circuit_error
        
        except Exception as e:
            # Handle other exceptions
            if CircuitBreakerConfig.should_count_as_failure(e):
                logger.error(
                    "circuit_breaker_function_failure",
                    service_name=self.service_name,
                    operation=func.__name__,
                    error=str(e),
                    error_type=type(e).__name__,
                    component="integrations.circuit_breaker"
                )
            raise
    
    async def call_with_circuit_breaker_async(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute async function with circuit breaker protection.
        
        Args:
            func: Async function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or fallback result
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            CircuitBreakerHalfOpenError: When test call fails in half-open state
        """
        # Check circuit breaker state before execution
        if self.circuit_breaker.current_state == 'open':
            time_until_reset = max(0, int(
                self.config['reset_timeout'] - 
                (time.time() - self.circuit_breaker._state_storage.get('last_failure_time', 0))
            ))
            
            circuit_error = CircuitBreakerOpenError(
                service_name=self.service_name,
                operation=func.__name__,
                time_until_reset=time_until_reset,
                failure_count=self._failure_count,
                failure_threshold=self.config['fail_max'],
                reset_timeout=self.config['reset_timeout']
            )
            
            # Attempt fallback if available
            if self.fallback_function:
                try:
                    logger.info(
                        "circuit_breaker_async_fallback_executed",
                        service_name=self.service_name,
                        operation=func.__name__,
                        component="integrations.circuit_breaker"
                    )
                    if asyncio.iscoroutinefunction(self.fallback_function):
                        return await self.fallback_function(*args, **kwargs)
                    else:
                        return self.fallback_function(*args, **kwargs)
                except Exception as fallback_error:
                    logger.error(
                        "circuit_breaker_async_fallback_failed",
                        service_name=self.service_name,
                        operation=func.__name__,
                        fallback_error=str(fallback_error),
                        component="integrations.circuit_breaker"
                    )
                    raise circuit_error from fallback_error
            
            raise circuit_error
        
        # Execute async function with monitoring
        try:
            with external_service_monitor.track_request(
                service_name=self.service_name,
                service_type=self.service_type,
                method=kwargs.get('method', 'ASYNC_CALL'),
                endpoint=func.__name__
            ):
                result = await func(*args, **kwargs)
                
                # Record success for circuit breaker
                self._on_circuit_breaker_success(self.circuit_breaker)
                
                return result
        
        except Exception as e:
            # Record failure for circuit breaker
            if CircuitBreakerConfig.should_count_as_failure(e):
                with self._lock:
                    self._failure_count += 1
                    self._last_failure_time = datetime.utcnow()
                    
                    # Check if failure threshold exceeded
                    if self._failure_count >= self.config['fail_max']:
                        self._on_circuit_breaker_open(
                            self.circuit_breaker,
                            self.circuit_breaker.current_state,
                            e
                        )
                        # Update pybreaker state
                        self.circuit_breaker._state_storage['current_state'] = 'open'
                        self.circuit_breaker._state_storage['last_failure_time'] = time.time()
                
                self._on_circuit_breaker_failure(self.circuit_breaker, e)
            
            raise
    
    def get_state(self) -> Dict[str, Any]:
        """
        Get current circuit breaker state information.
        
        Returns:
            Dictionary containing circuit breaker state details
        """
        with self._lock:
            return {
                'service_name': self.service_name,
                'service_type': self.service_type.value,
                'current_state': self.circuit_breaker.current_state,
                'failure_count': self._failure_count,
                'failure_threshold': self.config['fail_max'],
                'reset_timeout': self.config['reset_timeout'],
                'last_failure_time': self._last_failure_time.isoformat() if self._last_failure_time else None,
                'recovery_start_time': self._recovery_start_time.isoformat() if self._recovery_start_time else None,
                'has_fallback': self.fallback_function is not None,
                'time_until_reset': self._get_time_until_reset()
            }
    
    def _get_time_until_reset(self) -> Optional[int]:
        """Get time until circuit breaker reset in seconds."""
        if (self.circuit_breaker.current_state == 'open' and 
            hasattr(self.circuit_breaker, '_state_storage') and
            'last_failure_time' in self.circuit_breaker._state_storage):
            
            time_since_failure = time.time() - self.circuit_breaker._state_storage['last_failure_time']
            return max(0, int(self.config['reset_timeout'] - time_since_failure))
        
        return None
    
    def force_open(self) -> None:
        """Force circuit breaker to open state for testing or emergency."""
        with self._lock:
            self.circuit_breaker._state_storage['current_state'] = 'open'
            self.circuit_breaker._state_storage['last_failure_time'] = time.time()
            self._failure_count = self.config['fail_max']
            
            self._on_circuit_breaker_open(
                self.circuit_breaker,
                self._previous_state.value,
                Exception("Force opened")
            )
        
        logger.warning(
            "circuit_breaker_force_opened",
            service_name=self.service_name,
            component="integrations.circuit_breaker"
        )
    
    def force_close(self) -> None:
        """Force circuit breaker to closed state for testing or emergency."""
        with self._lock:
            previous_state = self.circuit_breaker.current_state
            self.circuit_breaker._state_storage['current_state'] = 'closed'
            self.circuit_breaker.fail_counter = 0
            self._failure_count = 0
            self._last_failure_time = None
            
            self._on_circuit_breaker_close(self.circuit_breaker, previous_state)
        
        logger.warning(
            "circuit_breaker_force_closed",
            service_name=self.service_name,
            component="integrations.circuit_breaker"
        )
    
    def reset_metrics(self) -> None:
        """Reset circuit breaker metrics for clean state."""
        with self._lock:
            self.circuit_breaker.fail_counter = 0
            self._failure_count = 0
            self._last_failure_time = None
            self._recovery_start_time = None
        
        logger.info(
            "circuit_breaker_metrics_reset",
            service_name=self.service_name,
            component="integrations.circuit_breaker"
        )


class CircuitBreakerManager:
    """
    Centralized circuit breaker management for multiple external services.
    
    Provides factory methods, bulk operations, and comprehensive monitoring
    for all circuit breakers in the application. Implements enterprise-grade
    service coordination and health management patterns.
    """
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self._circuit_breakers: Dict[str, ExternalServiceCircuitBreaker] = {}
        self._lock = RLock()
        self._thread_pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="cb_manager")
        
        logger.info(
            "circuit_breaker_manager_initialized",
            component="integrations.circuit_breaker"
        )
    
    def create_circuit_breaker(
        self,
        service_name: str,
        service_type: ServiceType,
        fallback_function: Optional[Callable] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> ExternalServiceCircuitBreaker:
        """
        Create and register a new circuit breaker.
        
        Args:
            service_name: Unique service identifier
            service_type: Service type classification
            fallback_function: Optional fallback function
            custom_config: Optional custom configuration
            
        Returns:
            Configured ExternalServiceCircuitBreaker instance
        """
        with self._lock:
            if service_name in self._circuit_breakers:
                logger.warning(
                    "circuit_breaker_already_exists",
                    service_name=service_name,
                    component="integrations.circuit_breaker"
                )
                return self._circuit_breakers[service_name]
            
            circuit_breaker = ExternalServiceCircuitBreaker(
                service_name=service_name,
                service_type=service_type,
                fallback_function=fallback_function,
                custom_config=custom_config
            )
            
            self._circuit_breakers[service_name] = circuit_breaker
            
            logger.info(
                "circuit_breaker_created",
                service_name=service_name,
                service_type=service_type.value,
                total_circuit_breakers=len(self._circuit_breakers),
                component="integrations.circuit_breaker"
            )
            
            return circuit_breaker
    
    def get_circuit_breaker(self, service_name: str) -> Optional[ExternalServiceCircuitBreaker]:
        """
        Get existing circuit breaker by service name.
        
        Args:
            service_name: Service identifier
            
        Returns:
            ExternalServiceCircuitBreaker instance or None
        """
        with self._lock:
            return self._circuit_breakers.get(service_name)
    
    def get_all_circuit_breakers(self) -> Dict[str, ExternalServiceCircuitBreaker]:
        """
        Get all registered circuit breakers.
        
        Returns:
            Dictionary mapping service names to circuit breakers
        """
        with self._lock:
            return dict(self._circuit_breakers)
    
    def get_circuit_breaker_states(self) -> Dict[str, Dict[str, Any]]:
        """
        Get state information for all circuit breakers.
        
        Returns:
            Dictionary mapping service names to state information
        """
        with self._lock:
            return {
                name: cb.get_state()
                for name, cb in self._circuit_breakers.items()
            }
    
    def get_health_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive health summary of all circuit breakers.
        
        Returns:
            Health summary with circuit breaker statistics
        """
        with self._lock:
            states = self.get_circuit_breaker_states()
            
            summary = {
                'total_circuit_breakers': len(self._circuit_breakers),
                'healthy_services': 0,
                'degraded_services': 0,
                'failed_services': 0,
                'circuit_breakers': states,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            for state in states.values():
                if state['current_state'] == 'closed':
                    summary['healthy_services'] += 1
                elif state['current_state'] == 'half-open':
                    summary['degraded_services'] += 1
                else:
                    summary['failed_services'] += 1
            
            return summary
    
    def force_open_all(self) -> None:
        """Force all circuit breakers to open state for emergency shutdown."""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.force_open()
        
        logger.warning(
            "all_circuit_breakers_force_opened",
            total_circuit_breakers=len(self._circuit_breakers),
            component="integrations.circuit_breaker"
        )
    
    def force_close_all(self) -> None:
        """Force all circuit breakers to closed state for emergency recovery."""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.force_close()
        
        logger.warning(
            "all_circuit_breakers_force_closed",
            total_circuit_breakers=len(self._circuit_breakers),
            component="integrations.circuit_breaker"
        )
    
    def reset_all_metrics(self) -> None:
        """Reset metrics for all circuit breakers."""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.reset_metrics()
        
        logger.info(
            "all_circuit_breaker_metrics_reset",
            total_circuit_breakers=len(self._circuit_breakers),
            component="integrations.circuit_breaker"
        )
    
    def remove_circuit_breaker(self, service_name: str) -> bool:
        """
        Remove circuit breaker for service.
        
        Args:
            service_name: Service identifier
            
        Returns:
            True if circuit breaker was removed, False if not found
        """
        with self._lock:
            if service_name in self._circuit_breakers:
                del self._circuit_breakers[service_name]
                logger.info(
                    "circuit_breaker_removed",
                    service_name=service_name,
                    component="integrations.circuit_breaker"
                )
                return True
            return False
    
    def shutdown(self) -> None:
        """Shutdown circuit breaker manager and cleanup resources."""
        with self._lock:
            self._thread_pool.shutdown(wait=True)
            self._circuit_breakers.clear()
        
        logger.info(
            "circuit_breaker_manager_shutdown",
            component="integrations.circuit_breaker"
        )


# Global circuit breaker manager instance
circuit_breaker_manager = CircuitBreakerManager()


def create_circuit_breaker(
    service_name: str,
    service_type: ServiceType,
    fallback_function: Optional[Callable] = None,
    custom_config: Optional[Dict[str, Any]] = None
) -> ExternalServiceCircuitBreaker:
    """
    Factory function for creating circuit breakers.
    
    Args:
        service_name: Unique service identifier
        service_type: Service type classification
        fallback_function: Optional fallback function
        custom_config: Optional custom configuration
        
    Returns:
        Configured ExternalServiceCircuitBreaker instance
    """
    return circuit_breaker_manager.create_circuit_breaker(
        service_name=service_name,
        service_type=service_type,
        fallback_function=fallback_function,
        custom_config=custom_config
    )


def circuit_breaker(
    service_name: str,
    service_type: ServiceType,
    fallback_function: Optional[Callable] = None,
    custom_config: Optional[Dict[str, Any]] = None
) -> Callable:
    """
    Decorator for protecting functions with circuit breaker.
    
    Args:
        service_name: Unique service identifier
        service_type: Service type classification
        fallback_function: Optional fallback function
        custom_config: Optional custom configuration
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        cb = create_circuit_breaker(
            service_name=service_name,
            service_type=service_type,
            fallback_function=fallback_function,
            custom_config=custom_config
        )
        return cb(func)
    
    return decorator


def get_circuit_breaker_health() -> Dict[str, Any]:
    """
    Get comprehensive circuit breaker health information.
    
    Returns:
        Health summary for all circuit breakers
    """
    return circuit_breaker_manager.get_health_summary()


def get_circuit_breaker_states() -> Dict[str, Dict[str, Any]]:
    """
    Get state information for all circuit breakers.
    
    Returns:
        Dictionary mapping service names to state information
    """
    return circuit_breaker_manager.get_circuit_breaker_states()


# Graceful fallback functions for common service types

def auth_service_fallback(*args, **kwargs) -> Dict[str, Any]:
    """
    Fallback function for authentication service failures.
    
    Returns cached authentication result or deny access.
    """
    logger.warning(
        "auth_service_fallback_triggered",
        component="integrations.circuit_breaker"
    )
    
    # Return cached result if available, otherwise deny access
    return {
        'authenticated': False,
        'user': None,
        'error': 'Authentication service unavailable',
        'fallback': True
    }


def cache_service_fallback(*args, **kwargs) -> Optional[Any]:
    """
    Fallback function for cache service failures.
    
    Returns None to indicate cache miss.
    """
    logger.warning(
        "cache_service_fallback_triggered",
        component="integrations.circuit_breaker"
    )
    
    # Return None to indicate cache miss
    return None


def file_storage_fallback(*args, **kwargs) -> Dict[str, Any]:
    """
    Fallback function for file storage service failures.
    
    Returns error response indicating storage unavailable.
    """
    logger.warning(
        "file_storage_fallback_triggered",
        component="integrations.circuit_breaker"
    )
    
    return {
        'success': False,
        'error': 'File storage service unavailable',
        'fallback': True
    }


# Module-level logger configuration
logger.info(
    "circuit_breaker_module_loaded",
    component="integrations.circuit_breaker",
    features=[
        "pybreaker_integration",
        "service_specific_configuration",
        "prometheus_metrics_integration",
        "fallback_mechanisms",
        "graceful_degradation",
        "state_transition_monitoring",
        "enterprise_monitoring"
    ]
)