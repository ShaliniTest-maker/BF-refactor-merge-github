"""
Circuit breaker implementation using pybreaker library for external service protection.

This module provides comprehensive circuit breaker functionality for external service integrations
with automatic failure detection, fallback mechanisms, and state transition monitoring. It implements
configurable failure thresholds, half-open state management, and Prometheus metrics integration
for enterprise-grade resilience patterns.

Aligned with:
- Section 6.3.3: External Systems integration resilience patterns
- Section 6.3.5: Performance and Scalability monitoring requirements
- Section 6.5: Monitoring and Observability comprehensive tracking
- Section 0.3.2: Performance monitoring requirements for ≤10% variance
"""

import time
import functools
import logging
from typing import Any, Dict, List, Optional, Callable, Union, TypeVar, Generic
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from contextlib import asynccontextmanager, contextmanager

# Core circuit breaker implementation per Section 6.3.3
import pybreaker
from pybreaker import CircuitBreaker, CircuitBreakerState

# Structured logging per Section 6.5.1.2
import structlog

# External service integration libraries per Section 3.2.3
import requests
import httpx
from requests.exceptions import RequestException, ConnectionError, Timeout
import httpx

# Monitoring and metrics integration per Section 6.3.5
from .monitoring import (
    external_service_monitor, 
    ExternalServiceType, 
    ServiceHealthState,
    ServiceMetrics
)

# Exception handling integration per Section 4.2.3
from .exceptions import (
    CircuitBreakerError,
    CircuitBreakerOpenError, 
    CircuitBreakerHalfOpenError,
    IntegrationError,
    HTTPClientError,
    TimeoutError as IntegrationTimeoutError,
    ConnectionError as IntegrationConnectionError,
    RetryExhaustedError
)

# Type hint support
T = TypeVar('T')
CallableT = TypeVar('CallableT', bound=Callable)

logger = structlog.get_logger(__name__)

class CircuitBreakerPolicy(Enum):
    """Circuit breaker policy types for different service characteristics."""
    STRICT = "strict"          # Low failure tolerance for critical services
    MODERATE = "moderate"      # Balanced failure tolerance for standard services
    TOLERANT = "tolerant"      # High failure tolerance for non-critical services
    CUSTOM = "custom"          # Custom configuration for specific requirements

@dataclass
class CircuitBreakerConfig:
    """
    Circuit breaker configuration for external service protection.
    
    Provides comprehensive configuration options for failure thresholds,
    timeouts, and monitoring integration per Section 6.3.5.
    """
    service_name: str
    service_type: ExternalServiceType
    
    # Failure threshold configuration per Section 6.3.5
    fail_max: int = 5                      # Maximum failures before opening circuit
    recovery_timeout: int = 60             # Seconds to wait before half-open transition
    expected_exception: tuple = (Exception,)  # Exceptions that trigger circuit breaker
    
    # Performance monitoring configuration per Section 6.3.5
    enable_metrics: bool = True            # Enable Prometheus metrics collection
    enable_health_monitoring: bool = True  # Enable health state monitoring
    
    # Fallback configuration per Section 6.3.3
    fallback_enabled: bool = True          # Enable fallback mechanism
    fallback_response: Any = None          # Default fallback response
    
    # Advanced configuration options
    half_open_max_calls: int = 5           # Maximum calls allowed in half-open state
    reset_timeout_jitter: float = 0.1      # Jitter factor for reset timeout
    state_change_callback: Optional[Callable] = None  # Callback for state changes
    
    # Service-specific configuration
    timeout_seconds: float = 30.0          # Request timeout for external service
    retry_count: int = 3                   # Number of retries before circuit activation
    
    # Policy-based configuration
    policy: CircuitBreakerPolicy = CircuitBreakerPolicy.MODERATE
    
    def __post_init__(self):
        """Apply policy-based configuration defaults."""
        if self.policy == CircuitBreakerPolicy.STRICT:
            self.fail_max = 3
            self.recovery_timeout = 120
            self.half_open_max_calls = 3
            self.retry_count = 1
        elif self.policy == CircuitBreakerPolicy.MODERATE:
            self.fail_max = 5
            self.recovery_timeout = 60
            self.half_open_max_calls = 5
            self.retry_count = 3
        elif self.policy == CircuitBreakerPolicy.TOLERANT:
            self.fail_max = 10
            self.recovery_timeout = 30
            self.half_open_max_calls = 10
            self.retry_count = 5

@dataclass
class CircuitBreakerMetrics:
    """Circuit breaker execution metrics for monitoring and analysis."""
    service_name: str
    service_type: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    circuit_open_calls: int = 0
    half_open_calls: int = 0
    fallback_calls: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    average_response_time: float = 0.0
    state_transitions: List[Dict[str, Any]] = field(default_factory=list)

class EnhancedCircuitBreaker:
    """
    Enhanced circuit breaker implementation with comprehensive monitoring and fallback support.
    
    Provides enterprise-grade circuit breaker functionality with automatic failure detection,
    fallback mechanisms, and integrated monitoring per Section 6.3.3 and 6.3.5 requirements.
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        """
        Initialize enhanced circuit breaker with configuration.
        
        Args:
            config: Circuit breaker configuration containing all operational parameters
        """
        self.config = config
        self.metrics = CircuitBreakerMetrics(
            service_name=config.service_name,
            service_type=config.service_type.value
        )
        
        # Initialize pybreaker circuit breaker per Section 6.3.3
        self._circuit_breaker = CircuitBreaker(
            fail_max=config.fail_max,
            reset_timeout=config.recovery_timeout,
            exclude=(),  # No exceptions to exclude by default
            listeners=[self._on_state_change] if config.state_change_callback or config.enable_metrics else []
        )
        
        # Register service with monitoring system per Section 6.3.5
        if config.enable_metrics:
            self._register_with_monitoring()
        
        # Initialize fallback mechanism per Section 6.3.3
        self._fallback_cache: Dict[str, Any] = {}
        
        logger.info("Circuit breaker initialized",
                   service_name=config.service_name,
                   service_type=config.service_type.value,
                   fail_max=config.fail_max,
                   recovery_timeout=config.recovery_timeout,
                   policy=config.policy.value)
    
    def _register_with_monitoring(self) -> None:
        """Register circuit breaker with external service monitoring system."""
        try:
            service_metrics = ServiceMetrics(
                service_name=self.config.service_name,
                service_type=self.config.service_type,
                health_endpoint=None,  # Circuit breaker doesn't provide health endpoint
                timeout_seconds=self.config.timeout_seconds,
                critical_threshold_ms=self.config.timeout_seconds * 1000 * 0.8,
                warning_threshold_ms=self.config.timeout_seconds * 1000 * 0.5
            )
            external_service_monitor.register_service(service_metrics)
            
            logger.debug("Circuit breaker registered with monitoring system",
                        service_name=self.config.service_name)
        except Exception as e:
            logger.warning("Failed to register circuit breaker with monitoring",
                          service_name=self.config.service_name,
                          error=str(e))
    
    def _on_state_change(self, prev_state: CircuitBreakerState, new_state: CircuitBreakerState) -> None:
        """
        Handle circuit breaker state changes for monitoring and callbacks.
        
        Args:
            prev_state: Previous circuit breaker state
            new_state: New circuit breaker state
        """
        # Record state transition for metrics
        transition = {
            'timestamp': datetime.utcnow().isoformat(),
            'from_state': prev_state.name,
            'to_state': new_state.name,
            'failure_count': self._circuit_breaker.fail_counter
        }
        self.metrics.state_transitions.append(transition)
        
        # Update monitoring system per Section 6.3.5
        if self.config.enable_metrics:
            try:
                external_service_monitor.track_circuit_breaker_state(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    circuit_breaker=self._circuit_breaker
                )
            except Exception as e:
                logger.warning("Failed to update circuit breaker monitoring",
                              service_name=self.config.service_name,
                              error=str(e))
        
        # Execute custom state change callback if provided
        if self.config.state_change_callback:
            try:
                self.config.state_change_callback(prev_state, new_state, self.config.service_name)
            except Exception as e:
                logger.error("Circuit breaker state change callback failed",
                           service_name=self.config.service_name,
                           error=str(e))
        
        logger.info("Circuit breaker state changed",
                   service_name=self.config.service_name,
                   service_type=self.config.service_type.value,
                   from_state=prev_state.name,
                   to_state=new_state.name,
                   failure_count=self._circuit_breaker.fail_counter)
    
    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self._circuit_breaker.current_state
    
    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._circuit_breaker.fail_counter
    
    @property
    def is_open(self) -> bool:
        """Check if circuit breaker is in OPEN state."""
        return self.state == CircuitBreakerState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit breaker is in HALF_OPEN state."""
        return self.state == CircuitBreakerState.HALF_OPEN
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit breaker is in CLOSED state."""
        return self.state == CircuitBreakerState.CLOSED
    
    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute with circuit breaker protection
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result or fallback response
            
        Raises:
            CircuitBreakerOpenError: When circuit is open and no fallback available
            CircuitBreakerHalfOpenError: When half-open test call fails
            IntegrationError: For other integration-related failures
        """
        start_time = time.time()
        operation_id = f"{self.config.service_name}_{int(start_time)}"
        
        try:
            # Update metrics for total calls
            self.metrics.total_calls += 1
            
            # Check circuit breaker state before execution
            if self.is_open:
                self.metrics.circuit_open_calls += 1
                if self.config.fallback_enabled:
                    return self._execute_fallback(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        failure_count=self.failure_count,
                        failure_threshold=self.config.fail_max
                    )
            
            # Execute function with circuit breaker protection
            result = self._circuit_breaker(func)(*args, **kwargs)
            
            # Update success metrics
            execution_time = time.time() - start_time
            self.metrics.successful_calls += 1
            self.metrics.last_success_time = datetime.utcnow()
            self._update_response_time(execution_time)
            
            # Track retry success if monitoring enabled
            if self.config.enable_metrics:
                external_service_monitor.track_retry_attempt(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    attempt_number=1,  # Successful on first attempt
                    success=True
                )
            
            logger.debug("Circuit breaker call succeeded",
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        execution_time=execution_time,
                        operation_id=operation_id)
            
            return result
            
        except pybreaker.CircuitBreakerError as e:
            # Handle pybreaker-specific circuit breaker errors
            self.metrics.failed_calls += 1
            self.metrics.last_failure_time = datetime.utcnow()
            
            if "half-open" in str(e).lower():
                self.metrics.half_open_calls += 1
                if self.config.fallback_enabled:
                    return self._execute_fallback(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerHalfOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__
                    )
            else:
                self.metrics.circuit_open_calls += 1
                if self.config.fallback_enabled:
                    return self._execute_fallback(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        failure_count=self.failure_count,
                        failure_threshold=self.config.fail_max
                    )
        
        except Exception as e:
            # Handle application-level exceptions
            execution_time = time.time() - start_time
            self.metrics.failed_calls += 1
            self.metrics.last_failure_time = datetime.utcnow()
            self._update_response_time(execution_time)
            
            # Track retry failure if monitoring enabled
            if self.config.enable_metrics:
                external_service_monitor.track_retry_attempt(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    attempt_number=1,  # Failed on first attempt
                    success=False
                )
            
            logger.error("Circuit breaker call failed",
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        execution_time=execution_time,
                        operation_id=operation_id,
                        error=str(e),
                        error_type=type(e).__name__)
            
            # Execute fallback if enabled, otherwise re-raise
            if self.config.fallback_enabled:
                return self._execute_fallback(operation_id, *args, **kwargs)
            else:
                raise
    
    async def call_async(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute async function with circuit breaker protection.
        
        Args:
            func: Async function to execute with circuit breaker protection
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result or fallback response
            
        Raises:
            CircuitBreakerOpenError: When circuit is open and no fallback available
            CircuitBreakerHalfOpenError: When half-open test call fails
            IntegrationError: For other integration-related failures
        """
        start_time = time.time()
        operation_id = f"{self.config.service_name}_async_{int(start_time)}"
        
        try:
            # Update metrics for total calls
            self.metrics.total_calls += 1
            
            # Check circuit breaker state before execution
            if self.is_open:
                self.metrics.circuit_open_calls += 1
                if self.config.fallback_enabled:
                    return await self._execute_fallback_async(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        failure_count=self.failure_count,
                        failure_threshold=self.config.fail_max
                    )
            
            # Execute async function with circuit breaker protection
            # Note: pybreaker doesn't natively support async, so we handle state manually
            try:
                result = await func(*args, **kwargs)
                
                # Manually update circuit breaker success
                self._circuit_breaker._call_succeeded()
                
                # Update success metrics
                execution_time = time.time() - start_time
                self.metrics.successful_calls += 1
                self.metrics.last_success_time = datetime.utcnow()
                self._update_response_time(execution_time)
                
                # Track retry success if monitoring enabled
                if self.config.enable_metrics:
                    external_service_monitor.track_retry_attempt(
                        service_name=self.config.service_name,
                        service_type=self.config.service_type,
                        attempt_number=1,  # Successful on first attempt
                        success=True
                    )
                
                logger.debug("Async circuit breaker call succeeded",
                            service_name=self.config.service_name,
                            operation=func.__name__,
                            execution_time=execution_time,
                            operation_id=operation_id)
                
                return result
                
            except Exception as e:
                # Manually update circuit breaker failure
                self._circuit_breaker._call_failed()
                raise e
            
        except pybreaker.CircuitBreakerError as e:
            # Handle pybreaker-specific circuit breaker errors
            self.metrics.failed_calls += 1
            self.metrics.last_failure_time = datetime.utcnow()
            
            if "half-open" in str(e).lower():
                self.metrics.half_open_calls += 1
                if self.config.fallback_enabled:
                    return await self._execute_fallback_async(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerHalfOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__
                    )
            else:
                self.metrics.circuit_open_calls += 1
                if self.config.fallback_enabled:
                    return await self._execute_fallback_async(operation_id, *args, **kwargs)
                else:
                    raise CircuitBreakerOpenError(
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        failure_count=self.failure_count,
                        failure_threshold=self.config.fail_max
                    )
        
        except Exception as e:
            # Handle application-level exceptions
            execution_time = time.time() - start_time
            self.metrics.failed_calls += 1
            self.metrics.last_failure_time = datetime.utcnow()
            self._update_response_time(execution_time)
            
            # Track retry failure if monitoring enabled
            if self.config.enable_metrics:
                external_service_monitor.track_retry_attempt(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    attempt_number=1,  # Failed on first attempt
                    success=False
                )
            
            logger.error("Async circuit breaker call failed",
                        service_name=self.config.service_name,
                        operation=func.__name__,
                        execution_time=execution_time,
                        operation_id=operation_id,
                        error=str(e),
                        error_type=type(e).__name__)
            
            # Execute fallback if enabled, otherwise re-raise
            if self.config.fallback_enabled:
                return await self._execute_fallback_async(operation_id, *args, **kwargs)
            else:
                raise
    
    def _execute_fallback(self, operation_id: str, *args, **kwargs) -> Any:
        """
        Execute fallback mechanism for failed operations.
        
        Args:
            operation_id: Unique identifier for the operation
            *args: Original function positional arguments
            **kwargs: Original function keyword arguments
            
        Returns:
            Fallback response or cached response if available
        """
        self.metrics.fallback_calls += 1
        
        # Check for cached fallback response
        cache_key = f"{self.config.service_name}:fallback:{hash(str(args) + str(kwargs))}"
        if cache_key in self._fallback_cache:
            cached_response = self._fallback_cache[cache_key]
            logger.info("Circuit breaker fallback: using cached response",
                       service_name=self.config.service_name,
                       operation_id=operation_id,
                       cache_key=cache_key)
            return cached_response
        
        # Return configured fallback response
        if self.config.fallback_response is not None:
            logger.info("Circuit breaker fallback: using configured response",
                       service_name=self.config.service_name,
                       operation_id=operation_id,
                       fallback_type="configured")
            return self.config.fallback_response
        
        # Generate default fallback response based on service type
        default_fallback = self._generate_default_fallback()
        logger.info("Circuit breaker fallback: using default response",
                   service_name=self.config.service_name,
                   operation_id=operation_id,
                   fallback_type="default")
        return default_fallback
    
    async def _execute_fallback_async(self, operation_id: str, *args, **kwargs) -> Any:
        """
        Execute async fallback mechanism for failed operations.
        
        Args:
            operation_id: Unique identifier for the operation
            *args: Original function positional arguments
            **kwargs: Original function keyword arguments
            
        Returns:
            Fallback response or cached response if available
        """
        # Async fallback implementation is the same as sync for now
        # Future enhancement: could include async cache lookups or async fallback services
        return self._execute_fallback(operation_id, *args, **kwargs)
    
    def _generate_default_fallback(self) -> Any:
        """
        Generate appropriate default fallback response based on service type.
        
        Returns:
            Service-appropriate default fallback response
        """
        if self.config.service_type == ExternalServiceType.AUTH_PROVIDER:
            return {
                'status': 'error',
                'message': 'Authentication service temporarily unavailable',
                'fallback': True,
                'retry_after': self.config.recovery_timeout
            }
        elif self.config.service_type == ExternalServiceType.CLOUD_STORAGE:
            return {
                'status': 'error',
                'message': 'Storage service temporarily unavailable',
                'fallback': True,
                'retry_after': self.config.recovery_timeout
            }
        elif self.config.service_type == ExternalServiceType.HTTP_API:
            return {
                'status': 'error',
                'message': 'External API temporarily unavailable',
                'fallback': True,
                'retry_after': self.config.recovery_timeout
            }
        else:
            return {
                'status': 'error',
                'message': 'Service temporarily unavailable',
                'fallback': True,
                'service': self.config.service_name,
                'retry_after': self.config.recovery_timeout
            }
    
    def _update_response_time(self, execution_time: float) -> None:
        """Update average response time with exponential moving average."""
        alpha = 0.3  # Smoothing factor for exponential moving average
        if self.metrics.average_response_time == 0.0:
            self.metrics.average_response_time = execution_time
        else:
            self.metrics.average_response_time = (
                alpha * execution_time + 
                (1 - alpha) * self.metrics.average_response_time
            )
    
    def set_fallback_cache(self, cache_key: str, response: Any, ttl_seconds: int = 300) -> None:
        """
        Set cached fallback response for graceful degradation.
        
        Args:
            cache_key: Cache key for the fallback response
            response: Response to cache for fallback
            ttl_seconds: Time-to-live for the cached response
        """
        cache_entry = {
            'response': response,
            'expires_at': time.time() + ttl_seconds
        }
        self._fallback_cache[cache_key] = cache_entry
        
        logger.debug("Fallback cache entry set",
                    service_name=self.config.service_name,
                    cache_key=cache_key,
                    ttl_seconds=ttl_seconds)
    
    def clear_fallback_cache(self) -> None:
        """Clear all cached fallback responses."""
        self._fallback_cache.clear()
        logger.info("Fallback cache cleared",
                   service_name=self.config.service_name)
    
    def reset_circuit(self) -> None:
        """Manually reset circuit breaker to CLOSED state."""
        old_state = self.state
        self._circuit_breaker._reset()
        
        logger.info("Circuit breaker manually reset",
                   service_name=self.config.service_name,
                   old_state=old_state.name,
                   new_state=self.state.name)
    
    def get_metrics(self) -> CircuitBreakerMetrics:
        """Get current circuit breaker metrics."""
        return self.metrics
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status for monitoring.
        
        Returns:
            Dictionary containing circuit breaker health and status information
        """
        return {
            'service_name': self.config.service_name,
            'service_type': self.config.service_type.value,
            'circuit_state': self.state.name,
            'failure_count': self.failure_count,
            'failure_threshold': self.config.fail_max,
            'recovery_timeout': self.config.recovery_timeout,
            'total_calls': self.metrics.total_calls,
            'successful_calls': self.metrics.successful_calls,
            'failed_calls': self.metrics.failed_calls,
            'success_rate': (
                self.metrics.successful_calls / self.metrics.total_calls 
                if self.metrics.total_calls > 0 else 0.0
            ),
            'average_response_time': self.metrics.average_response_time,
            'last_failure_time': (
                self.metrics.last_failure_time.isoformat() 
                if self.metrics.last_failure_time else None
            ),
            'last_success_time': (
                self.metrics.last_success_time.isoformat() 
                if self.metrics.last_success_time else None
            ),
            'fallback_enabled': self.config.fallback_enabled,
            'fallback_calls': self.metrics.fallback_calls,
            'policy': self.config.policy.value
        }

class CircuitBreakerManager:
    """
    Central manager for multiple circuit breakers with unified configuration and monitoring.
    
    Provides centralized management of circuit breakers for different external services
    with consistent configuration, monitoring, and fallback strategies per Section 6.3.3.
    """
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self._circuit_breakers: Dict[str, EnhancedCircuitBreaker] = {}
        self._global_config: Dict[str, Any] = {}
        
        logger.info("Circuit breaker manager initialized")
    
    def register_circuit_breaker(
        self, 
        service_name: str, 
        config: CircuitBreakerConfig
    ) -> EnhancedCircuitBreaker:
        """
        Register new circuit breaker for external service.
        
        Args:
            service_name: Unique identifier for the service
            config: Circuit breaker configuration
            
        Returns:
            Configured enhanced circuit breaker instance
        """
        if service_name in self._circuit_breakers:
            logger.warning("Circuit breaker already registered, replacing",
                          service_name=service_name)
        
        circuit_breaker = EnhancedCircuitBreaker(config)
        self._circuit_breakers[service_name] = circuit_breaker
        
        logger.info("Circuit breaker registered",
                   service_name=service_name,
                   service_type=config.service_type.value,
                   policy=config.policy.value)
        
        return circuit_breaker
    
    def get_circuit_breaker(self, service_name: str) -> Optional[EnhancedCircuitBreaker]:
        """
        Get circuit breaker for specified service.
        
        Args:
            service_name: Service identifier
            
        Returns:
            Circuit breaker instance or None if not found
        """
        return self._circuit_breakers.get(service_name)
    
    def get_all_circuit_breakers(self) -> Dict[str, EnhancedCircuitBreaker]:
        """Get all registered circuit breakers."""
        return self._circuit_breakers.copy()
    
    def get_global_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status for all circuit breakers.
        
        Returns:
            Dictionary containing global circuit breaker health status
        """
        circuit_statuses = {}
        total_calls = 0
        total_failures = 0
        open_circuits = 0
        
        for name, cb in self._circuit_breakers.items():
            status = cb.get_health_status()
            circuit_statuses[name] = status
            
            total_calls += status['total_calls']
            total_failures += status['failed_calls']
            if status['circuit_state'] == 'OPEN':
                open_circuits += 1
        
        overall_health = "healthy"
        if open_circuits > 0:
            if open_circuits == len(self._circuit_breakers):
                overall_health = "critical"
            else:
                overall_health = "degraded"
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_health': overall_health,
            'total_circuit_breakers': len(self._circuit_breakers),
            'open_circuits': open_circuits,
            'total_calls': total_calls,
            'total_failures': total_failures,
            'global_success_rate': (
                (total_calls - total_failures) / total_calls 
                if total_calls > 0 else 0.0
            ),
            'circuit_breakers': circuit_statuses
        }
    
    def reset_all_circuits(self) -> None:
        """Reset all circuit breakers to CLOSED state."""
        for name, cb in self._circuit_breakers.items():
            cb.reset_circuit()
        
        logger.info("All circuit breakers reset",
                   count=len(self._circuit_breakers))

# Decorator for automatic circuit breaker application
def circuit_breaker(
    service_name: str,
    service_type: ExternalServiceType,
    config: Optional[CircuitBreakerConfig] = None,
    manager: Optional[CircuitBreakerManager] = None
) -> Callable[[CallableT], CallableT]:
    """
    Decorator to apply circuit breaker protection to functions.
    
    Args:
        service_name: Name of the external service
        service_type: Type of external service
        config: Optional circuit breaker configuration
        manager: Optional circuit breaker manager instance
        
    Returns:
        Decorated function with circuit breaker protection
    """
    def decorator(func: CallableT) -> CallableT:
        # Use global manager if not provided
        cb_manager = manager or global_circuit_breaker_manager
        
        # Create default config if not provided
        if config is None:
            default_config = CircuitBreakerConfig(
                service_name=service_name,
                service_type=service_type
            )
        else:
            default_config = config
        
        # Register circuit breaker
        circuit_breaker_instance = cb_manager.register_circuit_breaker(
            service_name=service_name,
            config=default_config
        )
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return circuit_breaker_instance.call(func, *args, **kwargs)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await circuit_breaker_instance.call_async(func, *args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if hasattr(func, '__code__') and func.__code__.co_flags & 0x80:  # Check if async
            return async_wrapper
        else:
            return wrapper
    
    return decorator

# Predefined circuit breaker configurations per Section 6.3.5
PREDEFINED_CONFIGS = {
    'auth0': CircuitBreakerConfig(
        service_name='auth0',
        service_type=ExternalServiceType.AUTH_PROVIDER,
        fail_max=5,                    # Auth0 failure threshold per Section 6.3.5
        recovery_timeout=60,           # Recovery timeout per Section 6.3.5
        policy=CircuitBreakerPolicy.STRICT,
        timeout_seconds=5.0,
        retry_count=2
    ),
    'aws_s3': CircuitBreakerConfig(
        service_name='aws_s3',
        service_type=ExternalServiceType.CLOUD_STORAGE,
        fail_max=5,                    # S3 failure threshold per Section 6.3.5
        recovery_timeout=60,           # Recovery timeout per Section 6.3.5
        policy=CircuitBreakerPolicy.MODERATE,
        timeout_seconds=10.0,
        retry_count=3
    ),
    'mongodb': CircuitBreakerConfig(
        service_name='mongodb',
        service_type=ExternalServiceType.DATABASE,
        fail_max=3,                    # Database critical failure threshold
        recovery_timeout=30,           # Faster recovery for database
        policy=CircuitBreakerPolicy.STRICT,
        timeout_seconds=5.0,
        retry_count=2
    ),
    'redis': CircuitBreakerConfig(
        service_name='redis',
        service_type=ExternalServiceType.CACHE,
        fail_max=10,                   # Higher tolerance for cache
        recovery_timeout=30,           # Faster recovery for cache
        policy=CircuitBreakerPolicy.TOLERANT,
        timeout_seconds=2.0,
        retry_count=3
    ),
    'external_api': CircuitBreakerConfig(
        service_name='external_api',
        service_type=ExternalServiceType.HTTP_API,
        fail_max=5,                    # Standard API failure threshold
        recovery_timeout=60,           # Standard recovery timeout
        policy=CircuitBreakerPolicy.MODERATE,
        timeout_seconds=30.0,
        retry_count=3
    )
}

# Global circuit breaker manager instance
global_circuit_breaker_manager = CircuitBreakerManager()

# Convenience functions for common integrations
def create_auth0_circuit_breaker() -> EnhancedCircuitBreaker:
    """Create circuit breaker for Auth0 integration per Section 6.3.3."""
    return global_circuit_breaker_manager.register_circuit_breaker(
        'auth0', PREDEFINED_CONFIGS['auth0']
    )

def create_aws_s3_circuit_breaker() -> EnhancedCircuitBreaker:
    """Create circuit breaker for AWS S3 integration per Section 6.3.3."""
    return global_circuit_breaker_manager.register_circuit_breaker(
        'aws_s3', PREDEFINED_CONFIGS['aws_s3']
    )

def create_mongodb_circuit_breaker() -> EnhancedCircuitBreaker:
    """Create circuit breaker for MongoDB integration per Section 6.3.3."""
    return global_circuit_breaker_manager.register_circuit_breaker(
        'mongodb', PREDEFINED_CONFIGS['mongodb']
    )

def create_redis_circuit_breaker() -> EnhancedCircuitBreaker:
    """Create circuit breaker for Redis integration per Section 6.3.3."""
    return global_circuit_breaker_manager.register_circuit_breaker(
        'redis', PREDEFINED_CONFIGS['redis']
    )

def create_external_api_circuit_breaker() -> EnhancedCircuitBreaker:
    """Create circuit breaker for external API integration per Section 6.3.3."""
    return global_circuit_breaker_manager.register_circuit_breaker(
        'external_api', PREDEFINED_CONFIGS['external_api']
    )

# Context managers for circuit breaker operations
@contextmanager
def circuit_breaker_context(
    service_name: str, 
    service_type: ExternalServiceType,
    config: Optional[CircuitBreakerConfig] = None
):
    """
    Context manager for circuit breaker operations.
    
    Args:
        service_name: Name of the external service
        service_type: Type of external service
        config: Optional circuit breaker configuration
        
    Yields:
        Circuit breaker instance for protected operations
    """
    # Create or get circuit breaker
    cb_manager = global_circuit_breaker_manager
    existing_cb = cb_manager.get_circuit_breaker(service_name)
    
    if existing_cb:
        circuit_breaker_instance = existing_cb
    else:
        if config is None:
            config = CircuitBreakerConfig(
                service_name=service_name,
                service_type=service_type
            )
        circuit_breaker_instance = cb_manager.register_circuit_breaker(
            service_name=service_name,
            config=config
        )
    
    try:
        yield circuit_breaker_instance
    except Exception as e:
        logger.error("Circuit breaker context error",
                    service_name=service_name,
                    error=str(e))
        raise

@asynccontextmanager
async def async_circuit_breaker_context(
    service_name: str, 
    service_type: ExternalServiceType,
    config: Optional[CircuitBreakerConfig] = None
):
    """
    Async context manager for circuit breaker operations.
    
    Args:
        service_name: Name of the external service
        service_type: Type of external service
        config: Optional circuit breaker configuration
        
    Yields:
        Circuit breaker instance for protected async operations
    """
    # Create or get circuit breaker
    cb_manager = global_circuit_breaker_manager
    existing_cb = cb_manager.get_circuit_breaker(service_name)
    
    if existing_cb:
        circuit_breaker_instance = existing_cb
    else:
        if config is None:
            config = CircuitBreakerConfig(
                service_name=service_name,
                service_type=service_type
            )
        circuit_breaker_instance = cb_manager.register_circuit_breaker(
            service_name=service_name,
            config=config
        )
    
    try:
        yield circuit_breaker_instance
    except Exception as e:
        logger.error("Async circuit breaker context error",
                    service_name=service_name,
                    error=str(e))
        raise

# Export key components for external use
__all__ = [
    'CircuitBreakerConfig',
    'CircuitBreakerPolicy',
    'CircuitBreakerMetrics',
    'EnhancedCircuitBreaker',
    'CircuitBreakerManager',
    'circuit_breaker',
    'circuit_breaker_context',
    'async_circuit_breaker_context',
    'global_circuit_breaker_manager',
    'PREDEFINED_CONFIGS',
    'create_auth0_circuit_breaker',
    'create_aws_s3_circuit_breaker',
    'create_mongodb_circuit_breaker',
    'create_redis_circuit_breaker',
    'create_external_api_circuit_breaker'
]