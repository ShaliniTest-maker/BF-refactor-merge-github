"""
Health Check Endpoints Implementation

This module provides comprehensive health monitoring endpoints for Kubernetes-native
liveness and readiness probes, load balancer integration, dependency health validation,
and circuit breaker state monitoring. Implements enterprise-grade health state management
for container orchestration and automated failure detection.

Key Features:
- Kubernetes liveness probe endpoint (/health/live) for container restart management
- Kubernetes readiness probe endpoint (/health/ready) for traffic routing control
- AWS Application Load Balancer compatible health endpoints
- Comprehensive dependency health validation (MongoDB, Redis, Auth0)
- Circuit breaker state monitoring and integration
- JSON response format with detailed diagnostic information
- Health state flow management with degradation detection
- Enterprise monitoring integration with Prometheus metrics
- Structured logging for health check events and state transitions

Technical Requirements:
- Flask-compatible health endpoints per Section 6.5.2.1
- Kubernetes probe configuration per Section 6.5.2.1
- Dependency health validation per Section 4.5.2
- Circuit breaker monitoring per Section 4.5.2
- Load balancer integration per Section 6.5.2.1
"""

import asyncio
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from enum import Enum
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from flask import Blueprint, jsonify, current_app, g
import redis
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError
from motor.motor_asyncio import AsyncIOMotorClient
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import structlog
from prometheus_client import Counter, Gauge, Histogram, Enum as PrometheusEnum
import pybreaker
from auth0.exceptions import Auth0Error
import jwt
from jwt.exceptions import InvalidTokenError

# Import configuration dependencies
from src.config.database import get_database_config, DatabaseConnectionError
from src.config.auth import get_auth_config, AuthenticationError
from src.monitoring.logging import get_logger, log_integration_event, log_security_event


# Health state enumeration for state management
class HealthState(Enum):
    """Health state enumeration for comprehensive state tracking."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    PARTIAL_FAILURE = "partial_failure"
    CIRCUIT_OPEN = "circuit_open"
    HALF_OPEN = "half_open"
    UNHEALTHY = "unhealthy"


# Health check result data structure
@dataclass
class HealthCheckResult:
    """Structured health check result with detailed diagnostic information."""
    service_name: str
    status: HealthState
    response_time_ms: Optional[float]
    message: str
    details: Dict[str, Any]
    timestamp: str
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result['status'] = self.status.value
        return result


# Prometheus metrics for health monitoring
health_metrics = {
    'check_duration': Histogram(
        'health_check_duration_seconds',
        'Health check execution duration',
        ['service', 'check_type']
    ),
    'check_total': Counter(
        'health_checks_total',
        'Total health check attempts',
        ['service', 'status', 'check_type']
    ),
    'service_status': PrometheusEnum(
        'health_service_status',
        'Current health status of services',
        ['service'],
        states=[state.value for state in HealthState]
    ),
    'circuit_breaker_state': Gauge(
        'health_circuit_breaker_state',
        'Circuit breaker state for health dependencies',
        ['service']
    ),
    'dependency_availability': Gauge(
        'health_dependency_availability',
        'Dependency service availability percentage',
        ['service']
    ),
    'total_health_score': Gauge(
        'health_total_score',
        'Overall system health score (0-100)'
    )
}


class HealthCheckTimeout(Exception):
    """Custom exception for health check timeouts."""
    pass


class DependencyHealthValidator:
    """
    Comprehensive dependency health validation with circuit breaker integration.
    
    Validates critical system dependencies including MongoDB, Redis, Auth0,
    and external services with intelligent circuit breaker patterns and
    performance monitoring for enterprise-grade reliability.
    """
    
    def __init__(self):
        """Initialize dependency health validator with enterprise configuration."""
        self.logger = get_logger(f"{__name__}.DependencyHealthValidator")
        
        # Health check configuration
        self.check_timeout = 10.0  # seconds
        self.circuit_breaker_timeout = 60.0  # seconds
        self.max_concurrent_checks = 5
        
        # Circuit breakers for external dependencies
        self._init_circuit_breakers()
        
        # Health state tracking
        self._health_state = HealthState.HEALTHY
        self._last_health_check = None
        self._health_state_lock = threading.RLock()
        self._dependency_states: Dict[str, HealthCheckResult] = {}
        
        # Thread pool for concurrent health checks
        self._executor = ThreadPoolExecutor(max_workers=self.max_concurrent_checks)
        
        self.logger.info("Dependency health validator initialized")
    
    def _init_circuit_breakers(self) -> None:
        """Initialize circuit breakers for external service dependencies."""
        circuit_breaker_config = {
            'fail_max': 5,
            'reset_timeout': self.circuit_breaker_timeout,
            'exclude': [HealthCheckTimeout],  # Don't trip on timeouts
        }
        
        # MongoDB circuit breaker
        self.mongodb_breaker = pybreaker.CircuitBreaker(
            name='mongodb_health',
            **circuit_breaker_config
        )
        
        # Redis circuit breaker
        self.redis_breaker = pybreaker.CircuitBreaker(
            name='redis_health',
            **circuit_breaker_config
        )
        
        # Auth0 circuit breaker
        self.auth0_breaker = pybreaker.CircuitBreaker(
            name='auth0_health',
            **circuit_breaker_config
        )
        
        # AWS services circuit breaker
        self.aws_breaker = pybreaker.CircuitBreaker(
            name='aws_health',
            **circuit_breaker_config
        )
        
        # Circuit breaker state change listeners
        for breaker_name, breaker in [
            ('mongodb', self.mongodb_breaker),
            ('redis', self.redis_breaker),
            ('auth0', self.auth0_breaker),
            ('aws', self.aws_breaker)
        ]:
            breaker.add_listener(self._circuit_breaker_state_change_listener(breaker_name))
        
        self.logger.info("Circuit breakers initialized for all dependencies")
    
    def _circuit_breaker_state_change_listener(self, service_name: str):
        """Create circuit breaker state change listener for service."""
        def listener(breaker, old_state, new_state):
            """Handle circuit breaker state changes with logging and metrics."""
            state_mapping = {
                pybreaker.STATE_CLOSED: 0,
                pybreaker.STATE_OPEN: 1,
                pybreaker.STATE_HALF_OPEN: 2
            }
            
            health_metrics['circuit_breaker_state'].labels(
                service=service_name
            ).set(state_mapping.get(new_state, -1))
            
            log_integration_event(
                service_name=service_name,
                operation='circuit_breaker_state_change',
                status=f"{old_state}_to_{new_state}",
                details={
                    'old_state': str(old_state),
                    'new_state': str(new_state),
                    'failure_count': breaker.fail_counter,
                    'reset_timeout': breaker.reset_timeout
                },
                logger=self.logger
            )
            
            self.logger.warning(
                f"Circuit breaker state change for {service_name}",
                service=service_name,
                old_state=str(old_state),
                new_state=str(new_state),
                failure_count=breaker.fail_counter
            )
        
        return listener
    
    def _execute_with_timeout(self, check_func, service_name: str, timeout: float = None) -> HealthCheckResult:
        """Execute health check with timeout and error handling."""
        timeout = timeout or self.check_timeout
        start_time = time.time()
        
        try:
            # Execute health check with timeout
            future = self._executor.submit(check_func)
            result = future.result(timeout=timeout)
            
            # Calculate response time
            response_time_ms = (time.time() - start_time) * 1000
            
            # Update metrics
            health_metrics['check_duration'].labels(
                service=service_name,
                check_type='dependency'
            ).observe(response_time_ms / 1000)
            
            health_metrics['check_total'].labels(
                service=service_name,
                status=result.status.value,
                check_type='dependency'
            ).inc()
            
            # Update service status metric
            health_metrics['service_status'].labels(
                service=service_name
            ).state(result.status.value)
            
            return result
            
        except FuturesTimeoutError:
            response_time_ms = timeout * 1000
            error_msg = f"Health check timeout after {timeout}s"
            
            health_metrics['check_total'].labels(
                service=service_name,
                status='timeout',
                check_type='dependency'
            ).inc()
            
            self.logger.warning(
                f"Health check timeout for {service_name}",
                service=service_name,
                timeout=timeout
            )
            
            raise HealthCheckTimeout(error_msg)
            
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            error_msg = f"Health check failed: {str(e)}"
            
            health_metrics['check_total'].labels(
                service=service_name,
                status='error',
                check_type='dependency'
            ).inc()
            
            self.logger.error(
                f"Health check error for {service_name}",
                service=service_name,
                error=str(e),
                exc_info=True
            )
            
            raise e
    
    @pybreaker.CircuitBreaker(name='mongodb_health_check')
    def _check_mongodb_health(self) -> HealthCheckResult:
        """Check MongoDB database connectivity and health."""
        try:
            db_config = get_database_config()
            
            # Test synchronous connection
            mongo_client = db_config.get_mongodb_client()
            start_time = time.time()
            
            # Execute ping command
            result = mongo_client.admin.command('ping')
            response_time_ms = (time.time() - start_time) * 1000
            
            # Check server status for additional diagnostics
            server_status = mongo_client.admin.command('serverStatus')
            
            # Validate response
            if result.get('ok') != 1:
                raise ConnectionFailure("MongoDB ping command failed")
            
            # Get connection pool stats
            connection_info = {
                'host': mongo_client.address[0] if mongo_client.address else 'unknown',
                'port': mongo_client.address[1] if mongo_client.address else 'unknown',
                'max_pool_size': mongo_client.max_pool_size,
                'server_version': server_status.get('version', 'unknown'),
                'uptime_seconds': server_status.get('uptime', 0),
                'connections': server_status.get('connections', {}),
                'network': server_status.get('network', {}),
            }
            
            return HealthCheckResult(
                service_name='mongodb',
                status=HealthState.HEALTHY,
                response_time_ms=response_time_ms,
                message='MongoDB connection successful',
                details=connection_info,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except (ConnectionFailure, ServerSelectionTimeoutError, PyMongoError) as e:
            return HealthCheckResult(
                service_name='mongodb',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='MongoDB connection failed',
                details={'connection_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
        except Exception as e:
            return HealthCheckResult(
                service_name='mongodb',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='MongoDB health check error',
                details={'unexpected_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
    
    @pybreaker.CircuitBreaker(name='redis_health_check')
    def _check_redis_health(self) -> HealthCheckResult:
        """Check Redis cache connectivity and health."""
        try:
            db_config = get_database_config()
            
            # Test Redis connection
            redis_client = db_config.get_redis_client()
            start_time = time.time()
            
            # Execute ping command
            ping_result = redis_client.ping()
            response_time_ms = (time.time() - start_time) * 1000
            
            # Get Redis info for diagnostics
            redis_info = redis_client.info()
            
            # Validate ping response
            if not ping_result:
                raise redis.ConnectionError("Redis ping failed")
            
            # Extract key Redis metrics
            redis_details = {
                'redis_version': redis_info.get('redis_version', 'unknown'),
                'redis_mode': redis_info.get('redis_mode', 'unknown'),
                'connected_clients': redis_info.get('connected_clients', 0),
                'used_memory_human': redis_info.get('used_memory_human', 'unknown'),
                'keyspace_hits': redis_info.get('keyspace_hits', 0),
                'keyspace_misses': redis_info.get('keyspace_misses', 0),
                'total_commands_processed': redis_info.get('total_commands_processed', 0),
                'uptime_in_seconds': redis_info.get('uptime_in_seconds', 0),
            }
            
            # Calculate hit ratio
            hits = redis_details['keyspace_hits']
            misses = redis_details['keyspace_misses']
            total_requests = hits + misses
            hit_ratio = (hits / total_requests * 100) if total_requests > 0 else 0
            redis_details['hit_ratio_percent'] = round(hit_ratio, 2)
            
            return HealthCheckResult(
                service_name='redis',
                status=HealthState.HEALTHY,
                response_time_ms=response_time_ms,
                message='Redis connection successful',
                details=redis_details,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except (redis.ConnectionError, redis.TimeoutError, redis.RedisError) as e:
            return HealthCheckResult(
                service_name='redis',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='Redis connection failed',
                details={'connection_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
        except Exception as e:
            return HealthCheckResult(
                service_name='redis',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='Redis health check error',
                details={'unexpected_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
    
    @pybreaker.CircuitBreaker(name='auth0_health_check')
    def _check_auth0_health(self) -> HealthCheckResult:
        """Check Auth0 authentication service connectivity and health."""
        try:
            auth_config = get_auth_config()
            domain = auth_config.config.get('AUTH0_DOMAIN')
            
            if not domain:
                return HealthCheckResult(
                    service_name='auth0',
                    status=HealthState.UNHEALTHY,
                    response_time_ms=None,
                    message='Auth0 domain not configured',
                    details={'configuration_error': 'AUTH0_DOMAIN not set'},
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    error='Auth0 domain not configured'
                )
            
            # Test Auth0 JWKS endpoint
            jwks_url = f"https://{domain}/.well-known/jwks.json"
            start_time = time.time()
            
            # Configure session with retry strategy
            session = requests.Session()
            session.timeout = self.check_timeout
            
            response = session.get(jwks_url, timeout=self.check_timeout)
            response.raise_for_status()
            
            response_time_ms = (time.time() - start_time) * 1000
            jwks_data = response.json()
            
            # Validate JWKS structure
            if 'keys' not in jwks_data or not jwks_data['keys']:
                raise ValueError("Invalid JWKS response structure")
            
            auth0_details = {
                'domain': domain,
                'jwks_endpoint': jwks_url,
                'keys_count': len(jwks_data['keys']),
                'response_status': response.status_code,
                'response_headers': dict(response.headers),
            }
            
            return HealthCheckResult(
                service_name='auth0',
                status=HealthState.HEALTHY,
                response_time_ms=response_time_ms,
                message='Auth0 service accessible',
                details=auth0_details,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except (RequestException, Timeout, ConnectionError) as e:
            return HealthCheckResult(
                service_name='auth0',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='Auth0 service connection failed',
                details={'connection_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
        except (ValueError, Auth0Error, InvalidTokenError) as e:
            return HealthCheckResult(
                service_name='auth0',
                status=HealthState.DEGRADED,
                response_time_ms=None,
                message='Auth0 service degraded',
                details={'service_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
        except Exception as e:
            return HealthCheckResult(
                service_name='auth0',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='Auth0 health check error',
                details={'unexpected_error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
    
    def _check_circuit_breaker_states(self) -> HealthCheckResult:
        """Check circuit breaker states for all dependencies."""
        try:
            circuit_breakers = {
                'mongodb': self.mongodb_breaker,
                'redis': self.redis_breaker,
                'auth0': self.auth0_breaker,
                'aws': self.aws_breaker,
            }
            
            circuit_states = {}
            overall_state = HealthState.HEALTHY
            
            for service_name, breaker in circuit_breakers.items():
                state_name = str(breaker.current_state)
                failure_count = breaker.fail_counter
                
                circuit_states[service_name] = {
                    'state': state_name,
                    'failure_count': failure_count,
                    'reset_timeout': breaker.reset_timeout,
                    'last_failure': getattr(breaker, 'last_failure_time', None)
                }
                
                # Determine overall state based on individual circuit states
                if breaker.current_state == pybreaker.STATE_OPEN:
                    overall_state = HealthState.CIRCUIT_OPEN
                elif breaker.current_state == pybreaker.STATE_HALF_OPEN:
                    if overall_state == HealthState.HEALTHY:
                        overall_state = HealthState.HALF_OPEN
                elif failure_count > 0:
                    if overall_state == HealthState.HEALTHY:
                        overall_state = HealthState.DEGRADED
            
            return HealthCheckResult(
                service_name='circuit_breakers',
                status=overall_state,
                response_time_ms=0.0,  # Circuit breaker checks are instantaneous
                message=f'Circuit breakers status: {overall_state.value}',
                details=circuit_states,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            return HealthCheckResult(
                service_name='circuit_breakers',
                status=HealthState.UNHEALTHY,
                response_time_ms=None,
                message='Circuit breaker status check failed',
                details={'error': str(e)},
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
    
    def validate_all_dependencies(self) -> Dict[str, HealthCheckResult]:
        """
        Validate all system dependencies concurrently.
        
        Returns:
            Dictionary of health check results for all dependencies
        """
        start_time = time.time()
        
        # Define health check functions
        health_checks = {
            'mongodb': lambda: self._execute_with_timeout(
                self._check_mongodb_health, 'mongodb'
            ),
            'redis': lambda: self._execute_with_timeout(
                self._check_redis_health, 'redis'
            ),
            'auth0': lambda: self._execute_with_timeout(
                self._check_auth0_health, 'auth0'
            ),
            'circuit_breakers': lambda: self._execute_with_timeout(
                self._check_circuit_breaker_states, 'circuit_breakers'
            ),
        }
        
        # Execute health checks concurrently
        futures = {}
        results = {}
        
        for service_name, check_func in health_checks.items():
            future = self._executor.submit(check_func)
            futures[service_name] = future
        
        # Collect results with timeout handling
        for service_name, future in futures.items():
            try:
                result = future.result(timeout=self.check_timeout + 1)
                results[service_name] = result
                
            except FuturesTimeoutError:
                results[service_name] = HealthCheckResult(
                    service_name=service_name,
                    status=HealthState.UNHEALTHY,
                    response_time_ms=None,
                    message=f'{service_name} health check timeout',
                    details={'timeout': self.check_timeout},
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    error='Health check timeout'
                )
            except Exception as e:
                results[service_name] = HealthCheckResult(
                    service_name=service_name,
                    status=HealthState.UNHEALTHY,
                    response_time_ms=None,
                    message=f'{service_name} health check failed',
                    details={'error': str(e)},
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    error=str(e)
                )
        
        # Update dependency states
        with self._health_state_lock:
            self._dependency_states = results
            self._last_health_check = datetime.now(timezone.utc)
        
        # Calculate and update overall health metrics
        self._update_health_metrics(results)
        
        total_time = time.time() - start_time
        self.logger.info(
            "Dependency health validation completed",
            total_checks=len(results),
            total_time_ms=total_time * 1000,
            healthy_count=sum(1 for r in results.values() if r.status == HealthState.HEALTHY),
            degraded_count=sum(1 for r in results.values() if r.status == HealthState.DEGRADED),
            unhealthy_count=sum(1 for r in results.values() if r.status == HealthState.UNHEALTHY)
        )
        
        return results
    
    def _update_health_metrics(self, results: Dict[str, HealthCheckResult]) -> None:
        """Update Prometheus metrics based on health check results."""
        try:
            # Update dependency availability metrics
            for service_name, result in results.items():
                if service_name == 'circuit_breakers':
                    continue  # Skip circuit breaker service for availability metrics
                
                availability = 100.0 if result.status == HealthState.HEALTHY else 0.0
                health_metrics['dependency_availability'].labels(
                    service=service_name
                ).set(availability)
            
            # Calculate overall health score
            total_services = len([r for r in results.values() if r.service_name != 'circuit_breakers'])
            healthy_services = len([
                r for r in results.values() 
                if r.service_name != 'circuit_breakers' and r.status == HealthState.HEALTHY
            ])
            
            health_score = (healthy_services / total_services * 100) if total_services > 0 else 0
            health_metrics['total_health_score'].set(health_score)
            
        except Exception as e:
            self.logger.error(
                "Failed to update health metrics",
                error=str(e),
                exc_info=True
            )
    
    def get_current_health_state(self) -> HealthState:
        """Get current overall health state."""
        with self._health_state_lock:
            return self._health_state
    
    def get_last_health_check_time(self) -> Optional[datetime]:
        """Get timestamp of last health check."""
        with self._health_state_lock:
            return self._last_health_check


class HealthCheckEndpoints:
    """
    Kubernetes-native health check endpoints with enterprise monitoring integration.
    
    Provides comprehensive health monitoring endpoints for container orchestration,
    load balancer integration, and enterprise observability platforms.
    """
    
    def __init__(self):
        """Initialize health check endpoints with enterprise configuration."""
        self.logger = get_logger(f"{__name__}.HealthCheckEndpoints")
        self.dependency_validator = DependencyHealthValidator()
        
        # Health check caching to prevent overwhelming dependencies
        self._cache_duration = 30  # seconds
        self._cached_result: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_lock = threading.RLock()
        
        self.logger.info("Health check endpoints initialized")
    
    def _get_cached_health_result(self) -> Optional[Dict[str, Any]]:
        """Get cached health result if still valid."""
        with self._cache_lock:
            if (self._cached_result and self._cache_timestamp and 
                (datetime.now(timezone.utc) - self._cache_timestamp).total_seconds() < self._cache_duration):
                return self._cached_result
            return None
    
    def _cache_health_result(self, result: Dict[str, Any]) -> None:
        """Cache health result with timestamp."""
        with self._cache_lock:
            self._cached_result = result
            self._cache_timestamp = datetime.now(timezone.utc)
    
    def liveness_probe(self) -> Tuple[Dict[str, Any], int]:
        """
        Kubernetes liveness probe endpoint.
        
        Returns HTTP 200 when Flask application is operational and capable of
        handling requests. Returns HTTP 503 when application is in fatal state
        requiring container restart.
        
        Returns:
            Tuple of (response_dict, http_status_code)
        """
        start_time = time.time()
        
        try:
            # Basic application health checks
            app_health = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'checks': {
                    'flask_app': {
                        'status': 'healthy',
                        'message': 'Flask application is running'
                    },
                    'memory': self._check_memory_health(),
                    'threads': self._check_thread_health(),
                }
            }
            
            # Check for any fatal conditions
            fatal_conditions = []
            
            # Memory check
            memory_check = app_health['checks']['memory']
            if memory_check['status'] == 'critical':
                fatal_conditions.append(f"Memory: {memory_check['message']}")
            
            # Thread check
            thread_check = app_health['checks']['threads']
            if thread_check['status'] == 'critical':
                fatal_conditions.append(f"Threads: {thread_check['message']}")
            
            response_time_ms = (time.time() - start_time) * 1000
            
            if fatal_conditions:
                app_health['status'] = 'unhealthy'
                app_health['fatal_conditions'] = fatal_conditions
                
                # Record liveness probe failure
                health_metrics['check_total'].labels(
                    service='application',
                    status='unhealthy',
                    check_type='liveness'
                ).inc()
                
                self.logger.error(
                    "Liveness probe failed - application in fatal state",
                    fatal_conditions=fatal_conditions,
                    response_time_ms=response_time_ms
                )
                
                return app_health, 503
            
            # Record successful liveness probe
            health_metrics['check_duration'].labels(
                service='application',
                check_type='liveness'
            ).observe(response_time_ms / 1000)
            
            health_metrics['check_total'].labels(
                service='application',
                status='healthy',
                check_type='liveness'
            ).inc()
            
            app_health['response_time_ms'] = response_time_ms
            
            self.logger.debug(
                "Liveness probe successful",
                response_time_ms=response_time_ms,
                status='healthy'
            )
            
            return app_health, 200
            
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            
            error_response = {
                'status': 'unhealthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'message': 'Liveness probe failed with unexpected error',
                'response_time_ms': response_time_ms
            }
            
            health_metrics['check_total'].labels(
                service='application',
                status='error',
                check_type='liveness'
            ).inc()
            
            self.logger.error(
                "Liveness probe error",
                error=str(e),
                response_time_ms=response_time_ms,
                exc_info=True
            )
            
            return error_response, 503
    
    def readiness_probe(self) -> Tuple[Dict[str, Any], int]:
        """
        Kubernetes readiness probe endpoint.
        
        Returns HTTP 200 when all critical dependencies (MongoDB, Redis, Auth0)
        are accessible and functional. Returns HTTP 503 when dependencies are
        unavailable or degraded.
        
        Returns:
            Tuple of (response_dict, http_status_code)
        """
        start_time = time.time()
        
        try:
            # Check for cached result first
            cached_result = self._get_cached_health_result()
            if cached_result:
                cached_result['from_cache'] = True
                return cached_result['response'], cached_result['status_code']
            
            # Validate all dependencies
            dependency_results = self.dependency_validator.validate_all_dependencies()
            
            # Determine overall readiness status
            readiness_status = self._determine_readiness_status(dependency_results)
            
            response_time_ms = (time.time() - start_time) * 1000
            
            # Build response
            response = {
                'status': readiness_status['status'],
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'response_time_ms': response_time_ms,
                'dependencies': {
                    name: result.to_dict() 
                    for name, result in dependency_results.items()
                },
                'summary': readiness_status['summary'],
                'from_cache': False
            }
            
            # Determine HTTP status code
            if readiness_status['ready']:
                status_code = 200
                log_level = 'debug'
            else:
                status_code = 503
                log_level = 'warning'
            
            # Cache the result
            cache_entry = {
                'response': response,
                'status_code': status_code
            }
            self._cache_health_result(cache_entry)
            
            # Record metrics
            health_metrics['check_duration'].labels(
                service='application',
                check_type='readiness'
            ).observe(response_time_ms / 1000)
            
            health_metrics['check_total'].labels(
                service='application',
                status=readiness_status['status'],
                check_type='readiness'
            ).inc()
            
            # Log readiness probe result
            getattr(self.logger, log_level)(
                f"Readiness probe {readiness_status['status']}",
                response_time_ms=response_time_ms,
                status=readiness_status['status'],
                ready=readiness_status['ready'],
                healthy_dependencies=readiness_status['summary']['healthy'],
                total_dependencies=readiness_status['summary']['total']
            )
            
            return response, status_code
            
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            
            error_response = {
                'status': 'unhealthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'message': 'Readiness probe failed with unexpected error',
                'response_time_ms': response_time_ms,
                'from_cache': False
            }
            
            health_metrics['check_total'].labels(
                service='application',
                status='error',
                check_type='readiness'
            ).inc()
            
            self.logger.error(
                "Readiness probe error",
                error=str(e),
                response_time_ms=response_time_ms,
                exc_info=True
            )
            
            return error_response, 503
    
    def _determine_readiness_status(self, dependency_results: Dict[str, HealthCheckResult]) -> Dict[str, Any]:
        """Determine overall readiness status from dependency results."""
        # Critical dependencies that must be healthy for readiness
        critical_dependencies = ['mongodb', 'redis', 'auth0']
        
        # Count dependency states
        healthy_count = 0
        degraded_count = 0
        unhealthy_count = 0
        circuit_open_count = 0
        total_critical = len(critical_dependencies)
        
        critical_issues = []
        
        for dep_name in critical_dependencies:
            if dep_name in dependency_results:
                result = dependency_results[dep_name]
                
                if result.status == HealthState.HEALTHY:
                    healthy_count += 1
                elif result.status == HealthState.DEGRADED:
                    degraded_count += 1
                    critical_issues.append(f"{dep_name}: degraded - {result.message}")
                elif result.status in [HealthState.UNHEALTHY, HealthState.PARTIAL_FAILURE]:
                    unhealthy_count += 1
                    critical_issues.append(f"{dep_name}: unhealthy - {result.message}")
                elif result.status in [HealthState.CIRCUIT_OPEN, HealthState.HALF_OPEN]:
                    circuit_open_count += 1
                    critical_issues.append(f"{dep_name}: circuit breaker active - {result.message}")
        
        # Check circuit breaker states
        circuit_result = dependency_results.get('circuit_breakers')
        if circuit_result and circuit_result.status in [HealthState.CIRCUIT_OPEN, HealthState.HALF_OPEN]:
            critical_issues.append(f"Circuit breakers: {circuit_result.message}")
        
        # Determine overall status and readiness
        if unhealthy_count > 0 or circuit_open_count > 0:
            status = 'unhealthy'
            ready = False
        elif degraded_count > 0:
            status = 'degraded'
            ready = False  # Degraded services make app not ready for new traffic
        elif healthy_count == total_critical:
            status = 'healthy'
            ready = True
        else:
            status = 'partial'
            ready = False
        
        return {
            'status': status,
            'ready': ready,
            'summary': {
                'total': total_critical,
                'healthy': healthy_count,
                'degraded': degraded_count,
                'unhealthy': unhealthy_count,
                'circuit_open': circuit_open_count,
                'critical_issues': critical_issues
            }
        }
    
    def _check_memory_health(self) -> Dict[str, Any]:
        """Check application memory health."""
        try:
            import psutil
            import gc
            
            # Get process memory info
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            # Get garbage collection info
            gc_stats = {
                'generation_0': gc.get_count()[0],
                'generation_1': gc.get_count()[1],
                'generation_2': gc.get_count()[2],
                'total_collections': sum(gc.get_stats()[i]['collections'] for i in range(3)),
            }
            
            # Determine status based on memory usage
            if memory_percent > 90:
                status = 'critical'
                message = f'High memory usage: {memory_percent:.1f}%'
            elif memory_percent > 75:
                status = 'warning'
                message = f'Elevated memory usage: {memory_percent:.1f}%'
            else:
                status = 'healthy'
                message = f'Normal memory usage: {memory_percent:.1f}%'
            
            return {
                'status': status,
                'message': message,
                'details': {
                    'rss_bytes': memory_info.rss,
                    'vms_bytes': memory_info.vms,
                    'percent': memory_percent,
                    'gc_stats': gc_stats
                }
            }
            
        except ImportError:
            return {
                'status': 'unknown',
                'message': 'psutil not available for memory monitoring',
                'details': {}
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Memory check failed: {str(e)}',
                'details': {'error': str(e)}
            }
    
    def _check_thread_health(self) -> Dict[str, Any]:
        """Check application thread health."""
        try:
            import threading
            
            active_threads = threading.active_count()
            current_thread = threading.current_thread()
            
            # Get thread details
            thread_details = {
                'active_count': active_threads,
                'current_thread': current_thread.name,
                'daemon_threads': 0,
                'alive_threads': 0
            }
            
            # Count thread types
            for thread in threading.enumerate():
                if thread.daemon:
                    thread_details['daemon_threads'] += 1
                if thread.is_alive():
                    thread_details['alive_threads'] += 1
            
            # Determine status based on thread count
            if active_threads > 100:
                status = 'critical'
                message = f'High thread count: {active_threads}'
            elif active_threads > 50:
                status = 'warning'
                message = f'Elevated thread count: {active_threads}'
            else:
                status = 'healthy'
                message = f'Normal thread count: {active_threads}'
            
            return {
                'status': status,
                'message': message,
                'details': thread_details
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Thread check failed: {str(e)}',
                'details': {'error': str(e)}
            }


# Flask Blueprint for health check endpoints
health_blueprint = Blueprint('health', __name__, url_prefix='/health')

# Global health check endpoints instance
health_endpoints = HealthCheckEndpoints()


@health_blueprint.route('/live', methods=['GET'])
def liveness_probe():
    """
    Kubernetes liveness probe endpoint.
    
    Returns:
        JSON response with application health status and HTTP status code
    """
    response_data, status_code = health_endpoints.liveness_probe()
    return jsonify(response_data), status_code


@health_blueprint.route('/ready', methods=['GET'])
def readiness_probe():
    """
    Kubernetes readiness probe endpoint.
    
    Returns:
        JSON response with dependency health status and HTTP status code
    """
    response_data, status_code = health_endpoints.readiness_probe()
    return jsonify(response_data), status_code


@health_blueprint.route('', methods=['GET'])
@health_blueprint.route('/', methods=['GET'])
def general_health():
    """
    General health endpoint compatible with load balancers.
    
    Returns:
        JSON response with comprehensive health information
    """
    # Use readiness probe logic for general health
    response_data, status_code = health_endpoints.readiness_probe()
    
    # Add additional general health information
    response_data['endpoint'] = 'general_health'
    response_data['compatible_with'] = [
        'AWS Application Load Balancer',
        'Kubernetes Probes',
        'Enterprise Monitoring'
    ]
    
    return jsonify(response_data), status_code


@health_blueprint.route('/dependencies', methods=['GET'])
def dependency_health():
    """
    Detailed dependency health information endpoint.
    
    Returns:
        JSON response with comprehensive dependency status
    """
    start_time = time.time()
    
    try:
        # Get detailed dependency health
        dependency_results = health_endpoints.dependency_validator.validate_all_dependencies()
        
        # Calculate response time
        response_time_ms = (time.time() - start_time) * 1000
        
        # Build detailed response
        response = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'response_time_ms': response_time_ms,
            'dependencies': {
                name: result.to_dict() 
                for name, result in dependency_results.items()
            },
            'summary': {
                'total_dependencies': len(dependency_results),
                'healthy': sum(1 for r in dependency_results.values() if r.status == HealthState.HEALTHY),
                'degraded': sum(1 for r in dependency_results.values() if r.status == HealthState.DEGRADED),
                'unhealthy': sum(1 for r in dependency_results.values() if r.status == HealthState.UNHEALTHY),
            }
        }
        
        # Determine status code based on results
        if all(r.status == HealthState.HEALTHY for r in dependency_results.values()):
            status_code = 200
        else:
            status_code = 503
        
        return jsonify(response), status_code
        
    except Exception as e:
        error_response = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'message': 'Dependency health check failed',
            'response_time_ms': (time.time() - start_time) * 1000
        }
        
        return jsonify(error_response), 500


def init_health_monitoring(app):
    """
    Initialize health monitoring for Flask application.
    
    Args:
        app: Flask application instance
    """
    # Register health check blueprint
    app.register_blueprint(health_blueprint)
    
    # Initialize health check logger
    logger = get_logger(__name__)
    logger.info(
        "Health monitoring initialized",
        endpoints=[
            '/health/live',
            '/health/ready', 
            '/health',
            '/health/dependencies'
        ],
        kubernetes_compatible=True,
        load_balancer_compatible=True
    )


# Export main components
__all__ = [
    'HealthState',
    'HealthCheckResult',
    'DependencyHealthValidator',
    'HealthCheckEndpoints',
    'health_blueprint',
    'init_health_monitoring',
    'health_metrics'
]