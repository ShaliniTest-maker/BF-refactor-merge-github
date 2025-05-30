"""
Health Check Endpoints Implementation

This module provides comprehensive health monitoring capabilities for the Flask application
including Kubernetes-native liveness and readiness probes, load balancer integration,
dependency health validation, and circuit breaker state monitoring.

Features:
- Kubernetes liveness probe endpoint (/health/live)
- Kubernetes readiness probe endpoint (/health/ready) 
- Load balancer compatible health endpoints for AWS ALB
- Dependency health validation for MongoDB, Redis, and Auth0
- Circuit breaker state monitoring integration
- JSON response format with diagnostic information
- Health state flow management with degradation detection

Compliance:
- Section 6.5.2.1: Kubernetes probe endpoints for container orchestration
- Section 4.5.2: Health check and circuit breaker flow patterns
- Section 6.1.3: Health check endpoints for monitoring application status
"""

import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import json

from flask import Flask, Blueprint, jsonify, current_app, request
import structlog
import pymongo
import redis
import requests
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
from concurrent.futures import ThreadPoolExecutor
import psutil
import os


# Configure structured logger for health monitoring
logger = structlog.get_logger(__name__)


class HealthStatus(Enum):
    """Health status enumeration for consistent status reporting."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class DependencyType(Enum):
    """Dependency types for health validation."""
    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_SERVICE = "external_service"
    AUTHENTICATION = "authentication"
    CIRCUIT_BREAKER = "circuit_breaker"


@dataclass
class HealthCheckResult:
    """Health check result data structure."""
    service: str
    status: HealthStatus
    response_time_ms: float
    message: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None
    dependency_type: Optional[DependencyType] = None


@dataclass
class SystemHealth:
    """System-wide health status aggregation."""
    overall_status: HealthStatus
    services: List[HealthCheckResult]
    timestamp: str
    uptime_seconds: float
    version: str
    environment: str
    instance_id: str
    memory_usage_percent: float
    cpu_usage_percent: float
    active_connections: int


class CircuitBreakerState:
    """Circuit breaker state tracking for external services."""
    
    def __init__(self):
        self.states = {
            'auth0': {'state': 'closed', 'failure_count': 0, 'last_failure': None},
            'aws_s3': {'state': 'closed', 'failure_count': 0, 'last_failure': None},
            'mongodb': {'state': 'closed', 'failure_count': 0, 'last_failure': None},
            'redis': {'state': 'closed', 'failure_count': 0, 'last_failure': None}
        }
        self.failure_threshold = 5
        self.recovery_timeout = 60  # seconds
        self.half_open_timeout = 30  # seconds
        self._lock = threading.Lock()
    
    def record_success(self, service: str) -> None:
        """Record successful service interaction."""
        with self._lock:
            if service in self.states:
                self.states[service]['failure_count'] = 0
                if self.states[service]['state'] in ['open', 'half_open']:
                    self.states[service]['state'] = 'closed'
                    logger.info("Circuit breaker closed", service=service)
    
    def record_failure(self, service: str) -> None:
        """Record failed service interaction."""
        with self._lock:
            if service not in self.states:
                return
            
            self.states[service]['failure_count'] += 1
            self.states[service]['last_failure'] = datetime.now(timezone.utc)
            
            if (self.states[service]['failure_count'] >= self.failure_threshold 
                and self.states[service]['state'] == 'closed'):
                self.states[service]['state'] = 'open'
                logger.warning("Circuit breaker opened", 
                             service=service, 
                             failure_count=self.states[service]['failure_count'])
    
    def get_state(self, service: str) -> str:
        """Get current circuit breaker state for service."""
        with self._lock:
            if service not in self.states:
                return 'unknown'
            
            state_info = self.states[service]
            current_time = datetime.now(timezone.utc)
            
            # Check if open circuit should transition to half-open
            if (state_info['state'] == 'open' 
                and state_info['last_failure'] 
                and (current_time - state_info['last_failure']).total_seconds() > self.recovery_timeout):
                self.states[service]['state'] = 'half_open'
                logger.info("Circuit breaker transitioned to half-open", service=service)
            
            return state_info['state']
    
    def can_execute(self, service: str) -> bool:
        """Check if service calls are allowed."""
        state = self.get_state(service)
        return state in ['closed', 'half_open']
    
    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get all circuit breaker states for health reporting."""
        with self._lock:
            return {service: dict(info) for service, info in self.states.items()}


# Global circuit breaker instance
circuit_breaker = CircuitBreakerState()


class HealthChecker:
    """Main health checker class with dependency validation capabilities."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.start_time = time.time()
        self.instance_id = os.environ.get('HOSTNAME', f'flask-{os.getpid()}')
        self.executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='health-check')
        
        # Connection pools and clients (will be initialized from app config)
        self.mongo_client: Optional[pymongo.MongoClient] = None
        self.motor_client: Optional[AsyncIOMotorClient] = None
        self.redis_client: Optional[redis.Redis] = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize health checker with Flask application."""
        self.app = app
        
        # Initialize database connections from app configuration
        self._initialize_connections()
        
        # Register health check blueprint
        self._register_blueprint()
        
        # Set up periodic health checks
        self._setup_periodic_checks()
    
    def _initialize_connections(self) -> None:
        """Initialize database and cache connections for health checks."""
        try:
            # MongoDB connection configuration
            mongo_uri = self.app.config.get('MONGODB_URI', 'mongodb://localhost:27017/')
            mongo_db = self.app.config.get('MONGODB_DB_NAME', 'flask_app')
            
            # Initialize PyMongo client for synchronous operations
            self.mongo_client = pymongo.MongoClient(
                mongo_uri,
                maxPoolSize=10,  # Smaller pool for health checks
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                connectTimeoutMS=5000,
                socketTimeoutMS=5000,
                waitQueueTimeoutMS=5000
            )
            
            # Initialize Motor client for async operations
            self.motor_client = AsyncIOMotorClient(
                mongo_uri,
                maxPoolSize=10,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=5000
            )
            
            # Redis connection configuration
            redis_url = self.app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(
                redis_url,
                max_connections=5,  # Smaller pool for health checks
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            logger.info("Health checker connections initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize health checker connections", error=str(e))
    
    def _register_blueprint(self) -> None:
        """Register health check endpoints blueprint."""
        health_bp = Blueprint('health', __name__)
        
        @health_bp.route('/health/live', methods=['GET'])
        def liveness_probe():
            """
            Kubernetes liveness probe endpoint.
            
            Returns HTTP 200 when the Flask application process is running
            and capable of handling requests, HTTP 503 when the application
            is in a fatal state requiring container restart.
            """
            try:
                result = self.check_liveness()
                
                if result['status'] == HealthStatus.HEALTHY.value:
                    return jsonify(result), 200
                else:
                    return jsonify(result), 503
                    
            except Exception as e:
                logger.error("Liveness probe failed", error=str(e))
                return jsonify({
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'Liveness check failed: {str(e)}',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 503
        
        @health_bp.route('/health/ready', methods=['GET'])
        def readiness_probe():
            """
            Kubernetes readiness probe endpoint.
            
            Returns HTTP 200 when all critical dependencies (MongoDB, Redis, Auth0)
            are accessible and functional, HTTP 503 when dependencies are
            unavailable or degraded.
            """
            try:
                result = self.check_readiness()
                
                if result['overall_status'] == HealthStatus.HEALTHY.value:
                    return jsonify(result), 200
                else:
                    return jsonify(result), 503
                    
            except Exception as e:
                logger.error("Readiness probe failed", error=str(e))
                return jsonify({
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'Readiness check failed: {str(e)}',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 503
        
        @health_bp.route('/health', methods=['GET'])
        def health_status():
            """
            Load balancer compatible health endpoint.
            
            Provides comprehensive health status including all dependencies
            and system metrics for load balancer integration.
            """
            try:
                # Use readiness check for load balancer health
                result = self.check_readiness()
                
                # Add additional diagnostic information for load balancers
                result.update({
                    'load_balancer_compatible': True,
                    'instance_id': self.instance_id,
                    'uptime_seconds': time.time() - self.start_time,
                    'request_id': request.headers.get('X-Request-ID', 'unknown')
                })
                
                if result['overall_status'] == HealthStatus.HEALTHY.value:
                    return jsonify(result), 200
                else:
                    return jsonify(result), 503
                    
            except Exception as e:
                logger.error("Health status check failed", error=str(e))
                return jsonify({
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'Health check failed: {str(e)}',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'load_balancer_compatible': True,
                    'instance_id': self.instance_id
                }), 503
        
        @health_bp.route('/health/dependencies', methods=['GET'])
        def dependency_status():
            """
            Detailed dependency health status endpoint.
            
            Provides detailed status for each dependency including
            circuit breaker states and performance metrics.
            """
            try:
                dependencies = self.check_all_dependencies()
                circuit_states = circuit_breaker.get_all_states()
                
                result = {
                    'dependencies': [asdict(dep) for dep in dependencies],
                    'circuit_breaker_states': circuit_states,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'instance_id': self.instance_id
                }
                
                # Determine overall status
                unhealthy_count = sum(1 for dep in dependencies 
                                    if dep.status == HealthStatus.UNHEALTHY)
                degraded_count = sum(1 for dep in dependencies 
                                   if dep.status == HealthStatus.DEGRADED)
                
                if unhealthy_count > 0:
                    result['overall_status'] = HealthStatus.UNHEALTHY.value
                    status_code = 503
                elif degraded_count > 0:
                    result['overall_status'] = HealthStatus.DEGRADED.value
                    status_code = 200  # Still serving requests
                else:
                    result['overall_status'] = HealthStatus.HEALTHY.value
                    status_code = 200
                
                return jsonify(result), status_code
                
            except Exception as e:
                logger.error("Dependency status check failed", error=str(e))
                return jsonify({
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'Dependency check failed: {str(e)}',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 503
        
        # Register blueprint with app
        self.app.register_blueprint(health_bp)
        logger.info("Health check endpoints registered successfully")
    
    def _setup_periodic_checks(self) -> None:
        """Set up periodic background health checks for circuit breaker management."""
        def periodic_health_check():
            """Background health check to maintain circuit breaker states."""
            try:
                dependencies = self.check_all_dependencies()
                
                # Update circuit breaker states based on health checks
                for dep in dependencies:
                    service_name = dep.service.lower().replace(' ', '_')
                    if dep.status == HealthStatus.HEALTHY:
                        circuit_breaker.record_success(service_name)
                    elif dep.status == HealthStatus.UNHEALTHY:
                        circuit_breaker.record_failure(service_name)
                
                logger.debug("Periodic health check completed", 
                           healthy_services=len([d for d in dependencies 
                                               if d.status == HealthStatus.HEALTHY]))
            except Exception as e:
                logger.error("Periodic health check failed", error=str(e))
        
        # Run periodic health checks every 30 seconds
        def run_periodic_checks():
            import threading
            timer = threading.Timer(30.0, run_periodic_checks)
            timer.daemon = True
            timer.start()
            periodic_health_check()
        
        # Start the periodic check timer
        run_periodic_checks()
    
    def check_liveness(self) -> Dict[str, Any]:
        """
        Check application liveness.
        
        Verifies that the Flask application process is running and
        capable of handling requests.
        """
        start_time = time.time()
        
        try:
            # Basic application health checks
            memory_info = psutil.virtual_memory()
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            
            # Check critical application components
            is_healthy = (
                memory_info.percent < 95.0 and  # Memory usage below 95%
                cpu_percent < 95.0 and  # CPU usage below 95%
                self.app is not None  # Flask app is available
            )
            
            response_time = (time.time() - start_time) * 1000
            
            result = {
                'status': HealthStatus.HEALTHY.value if is_healthy else HealthStatus.UNHEALTHY.value,
                'message': 'Application is running' if is_healthy else 'Application is degraded',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'response_time_ms': response_time,
                'instance_id': self.instance_id,
                'uptime_seconds': time.time() - self.start_time,
                'memory_usage_percent': memory_info.percent,
                'cpu_usage_percent': cpu_percent,
                'process_id': os.getpid()
            }
            
            logger.debug("Liveness check completed", 
                        status=result['status'], 
                        response_time_ms=response_time)
            
            return result
            
        except Exception as e:
            logger.error("Liveness check failed", error=str(e))
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'message': f'Liveness check error: {str(e)}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'response_time_ms': (time.time() - start_time) * 1000,
                'instance_id': self.instance_id
            }
    
    def check_readiness(self) -> Dict[str, Any]:
        """
        Check application readiness.
        
        Verifies that all critical dependencies are accessible and
        the application is ready to serve requests.
        """
        start_time = time.time()
        
        try:
            # Perform comprehensive dependency checks
            dependencies = self.check_all_dependencies()
            
            # Get system metrics
            memory_info = psutil.virtual_memory()
            process = psutil.Process()
            cpu_percent = process.cpu_percent()
            
            # Determine overall health status
            unhealthy_dependencies = [d for d in dependencies 
                                    if d.status == HealthStatus.UNHEALTHY]
            degraded_dependencies = [d for d in dependencies 
                                   if d.status == HealthStatus.DEGRADED]
            
            if len(unhealthy_dependencies) > 0:
                overall_status = HealthStatus.UNHEALTHY
                message = f"Critical dependencies unhealthy: {[d.service for d in unhealthy_dependencies]}"
            elif len(degraded_dependencies) > 0:
                overall_status = HealthStatus.DEGRADED
                message = f"Some dependencies degraded: {[d.service for d in degraded_dependencies]}"
            else:
                overall_status = HealthStatus.HEALTHY
                message = "All dependencies healthy"
            
            response_time = (time.time() - start_time) * 1000
            
            system_health = SystemHealth(
                overall_status=overall_status,
                services=[dep for dep in dependencies],
                timestamp=datetime.now(timezone.utc).isoformat(),
                uptime_seconds=time.time() - self.start_time,
                version=self.app.config.get('VERSION', '1.0.0'),
                environment=self.app.config.get('ENVIRONMENT', 'unknown'),
                instance_id=self.instance_id,
                memory_usage_percent=memory_info.percent,
                cpu_usage_percent=cpu_percent,
                active_connections=len([d for d in dependencies 
                                      if d.status == HealthStatus.HEALTHY])
            )
            
            result = asdict(system_health)
            result['response_time_ms'] = response_time
            result['message'] = message
            
            logger.info("Readiness check completed", 
                       status=overall_status.value, 
                       healthy_count=len([d for d in dependencies 
                                        if d.status == HealthStatus.HEALTHY]),
                       total_count=len(dependencies),
                       response_time_ms=response_time)
            
            return result
            
        except Exception as e:
            logger.error("Readiness check failed", error=str(e))
            return {
                'overall_status': HealthStatus.UNHEALTHY.value,
                'message': f'Readiness check error: {str(e)}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'response_time_ms': (time.time() - start_time) * 1000,
                'instance_id': self.instance_id,
                'services': []
            }
    
    def check_all_dependencies(self) -> List[HealthCheckResult]:
        """Check all critical dependencies concurrently."""
        futures = []
        
        # Submit all health checks to thread pool
        futures.append(self.executor.submit(self.check_mongodb_health))
        futures.append(self.executor.submit(self.check_redis_health))
        futures.append(self.executor.submit(self.check_auth0_health))
        futures.append(self.executor.submit(self.check_aws_health))
        
        # Collect results with timeout
        results = []
        for future in futures:
            try:
                result = future.result(timeout=10)  # 10 second timeout
                results.append(result)
            except Exception as e:
                logger.error("Dependency check failed", error=str(e))
                results.append(HealthCheckResult(
                    service="Unknown",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0.0,
                    message=f"Check failed: {str(e)}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.EXTERNAL_SERVICE
                ))
        
        return results
    
    def check_mongodb_health(self) -> HealthCheckResult:
        """Check MongoDB database health."""
        start_time = time.time()
        service_name = "mongodb"
        
        try:
            if not circuit_breaker.can_execute(service_name):
                return HealthCheckResult(
                    service="MongoDB",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0.0,
                    message="Circuit breaker open",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.DATABASE,
                    details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
                )
            
            if self.mongo_client is None:
                raise Exception("MongoDB client not initialized")
            
            # Perform basic connectivity test
            server_info = self.mongo_client.server_info()
            
            # Test database operation
            db_name = self.app.config.get('MONGODB_DB_NAME', 'flask_app')
            db = self.mongo_client[db_name]
            
            # Simple ping operation
            result = db.command('ping')
            
            response_time = (time.time() - start_time) * 1000
            
            if result.get('ok') == 1:
                circuit_breaker.record_success(service_name)
                return HealthCheckResult(
                    service="MongoDB",
                    status=HealthStatus.HEALTHY,
                    response_time_ms=response_time,
                    message="Database connection healthy",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.DATABASE,
                    details={
                        'server_version': server_info.get('version'),
                        'connection_pool_size': 10,  # From configuration
                        'circuit_breaker_state': circuit_breaker.get_state(service_name)
                    }
                )
            else:
                circuit_breaker.record_failure(service_name)
                return HealthCheckResult(
                    service="MongoDB",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    message="Database ping failed",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.DATABASE
                )
                
        except Exception as e:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            logger.error("MongoDB health check failed", error=str(e), response_time_ms=response_time)
            
            return HealthCheckResult(
                service="MongoDB",
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Database error: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.DATABASE,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
    
    def check_redis_health(self) -> HealthCheckResult:
        """Check Redis cache health."""
        start_time = time.time()
        service_name = "redis"
        
        try:
            if not circuit_breaker.can_execute(service_name):
                return HealthCheckResult(
                    service="Redis",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0.0,
                    message="Circuit breaker open",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.CACHE,
                    details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
                )
            
            if self.redis_client is None:
                raise Exception("Redis client not initialized")
            
            # Perform ping test
            ping_result = self.redis_client.ping()
            
            # Test basic operations
            test_key = f"health_check_{int(time.time())}"
            self.redis_client.set(test_key, "health_check", ex=60)  # 60 second expiry
            get_result = self.redis_client.get(test_key)
            self.redis_client.delete(test_key)
            
            response_time = (time.time() - start_time) * 1000
            
            if ping_result and get_result == b"health_check":
                circuit_breaker.record_success(service_name)
                
                # Get Redis info for health details
                redis_info = self.redis_client.info()
                
                return HealthCheckResult(
                    service="Redis",
                    status=HealthStatus.HEALTHY,
                    response_time_ms=response_time,
                    message="Cache connection healthy",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.CACHE,
                    details={
                        'redis_version': redis_info.get('redis_version'),
                        'connected_clients': redis_info.get('connected_clients'),
                        'used_memory_human': redis_info.get('used_memory_human'),
                        'circuit_breaker_state': circuit_breaker.get_state(service_name)
                    }
                )
            else:
                circuit_breaker.record_failure(service_name)
                return HealthCheckResult(
                    service="Redis",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    message="Cache operations failed",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.CACHE
                )
                
        except Exception as e:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            logger.error("Redis health check failed", error=str(e), response_time_ms=response_time)
            
            return HealthCheckResult(
                service="Redis",
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Cache error: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.CACHE,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
    
    def check_auth0_health(self) -> HealthCheckResult:
        """Check Auth0 authentication service health."""
        start_time = time.time()
        service_name = "auth0"
        
        try:
            if not circuit_breaker.can_execute(service_name):
                return HealthCheckResult(
                    service="Auth0",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0.0,
                    message="Circuit breaker open",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.AUTHENTICATION,
                    details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
                )
            
            # Get Auth0 configuration from app config
            auth0_domain = self.app.config.get('AUTH0_DOMAIN')
            if not auth0_domain:
                return HealthCheckResult(
                    service="Auth0",
                    status=HealthStatus.DEGRADED,
                    response_time_ms=0.0,
                    message="Auth0 domain not configured",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.AUTHENTICATION
                )
            
            # Make a health check request to Auth0's well-known endpoint
            well_known_url = f"https://{auth0_domain}/.well-known/openid_configuration"
            
            response = requests.get(
                well_known_url,
                timeout=5.0,
                headers={'User-Agent': 'Flask-Health-Check/1.0'}
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                circuit_breaker.record_success(service_name)
                config_data = response.json()
                
                return HealthCheckResult(
                    service="Auth0",
                    status=HealthStatus.HEALTHY,
                    response_time_ms=response_time,
                    message="Authentication service healthy",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.AUTHENTICATION,
                    details={
                        'issuer': config_data.get('issuer'),
                        'authorization_endpoint': bool(config_data.get('authorization_endpoint')),
                        'token_endpoint': bool(config_data.get('token_endpoint')),
                        'circuit_breaker_state': circuit_breaker.get_state(service_name)
                    }
                )
            else:
                circuit_breaker.record_failure(service_name)
                return HealthCheckResult(
                    service="Auth0",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time,
                    message=f"Auth0 responded with status {response.status_code}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.AUTHENTICATION
                )
                
        except requests.exceptions.Timeout:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                service="Auth0",
                status=HealthStatus.DEGRADED,
                response_time_ms=response_time,
                message="Auth0 request timeout",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.AUTHENTICATION,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
            
        except Exception as e:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            logger.error("Auth0 health check failed", error=str(e), response_time_ms=response_time)
            
            return HealthCheckResult(
                service="Auth0",
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"Auth0 error: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.AUTHENTICATION,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
    
    def check_aws_health(self) -> HealthCheckResult:
        """Check AWS services health (primarily S3)."""
        start_time = time.time()
        service_name = "aws_s3"
        
        try:
            if not circuit_breaker.can_execute(service_name):
                return HealthCheckResult(
                    service="AWS S3",
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0.0,
                    message="Circuit breaker open",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.EXTERNAL_SERVICE,
                    details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
                )
            
            # Try to import boto3 and check AWS configuration
            try:
                import boto3
                from botocore.config import Config
                from botocore.exceptions import ClientError, NoCredentialsError
            except ImportError:
                return HealthCheckResult(
                    service="AWS S3",
                    status=HealthStatus.DEGRADED,
                    response_time_ms=0.0,
                    message="AWS SDK not available",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    dependency_type=DependencyType.EXTERNAL_SERVICE
                )
            
            # Configure S3 client with health check settings
            config = Config(
                region_name=self.app.config.get('AWS_REGION', 'us-east-1'),
                retries={'max_attempts': 2, 'mode': 'standard'},
                connect_timeout=5,
                read_timeout=5
            )
            
            s3_client = boto3.client('s3', config=config)
            
            # Simple AWS health check - list buckets with minimal permissions
            s3_client.list_buckets()
            
            response_time = (time.time() - start_time) * 1000
            circuit_breaker.record_success(service_name)
            
            return HealthCheckResult(
                service="AWS S3",
                status=HealthStatus.HEALTHY,
                response_time_ms=response_time,
                message="AWS services accessible",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.EXTERNAL_SERVICE,
                details={
                    'region': config.region_name,
                    'circuit_breaker_state': circuit_breaker.get_state(service_name)
                }
            )
            
        except NoCredentialsError:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                service="AWS S3",
                status=HealthStatus.DEGRADED,
                response_time_ms=response_time,
                message="AWS credentials not configured",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.EXTERNAL_SERVICE,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
            
        except ClientError as e:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            # Some AWS errors indicate degraded service rather than complete failure
            if error_code in ['AccessDenied', 'Forbidden']:
                status = HealthStatus.DEGRADED
                message = f"AWS access limited: {error_code}"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"AWS error: {error_code}"
            
            return HealthCheckResult(
                service="AWS S3",
                status=status,
                response_time_ms=response_time,
                message=message,
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.EXTERNAL_SERVICE,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )
            
        except Exception as e:
            circuit_breaker.record_failure(service_name)
            response_time = (time.time() - start_time) * 1000
            logger.error("AWS health check failed", error=str(e), response_time_ms=response_time)
            
            return HealthCheckResult(
                service="AWS S3",
                status=HealthStatus.UNHEALTHY,
                response_time_ms=response_time,
                message=f"AWS error: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                dependency_type=DependencyType.EXTERNAL_SERVICE,
                details={'circuit_breaker_state': circuit_breaker.get_state(service_name)}
            )


# Global health checker instance
health_checker = HealthChecker()


def init_health_monitoring(app: Flask) -> HealthChecker:
    """
    Initialize health monitoring for the Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        HealthChecker: Configured health checker instance
    """
    health_checker.init_app(app)
    
    logger.info("Health monitoring initialized successfully",
                instance_id=health_checker.instance_id,
                endpoints=['/health/live', '/health/ready', '/health', '/health/dependencies'])
    
    return health_checker


def get_health_status() -> Dict[str, Any]:
    """
    Get current health status for programmatic access.
    
    Returns:
        Dict: Current system health status
    """
    if health_checker.app is None:
        return {
            'status': HealthStatus.UNHEALTHY.value,
            'message': 'Health checker not initialized',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    return health_checker.check_readiness()


def get_circuit_breaker_states() -> Dict[str, Dict[str, Any]]:
    """
    Get current circuit breaker states for all services.
    
    Returns:
        Dict: Circuit breaker states for all monitored services
    """
    return circuit_breaker.get_all_states()


# Export key components for external usage
__all__ = [
    'HealthChecker',
    'HealthStatus',
    'DependencyType',
    'HealthCheckResult',
    'SystemHealth',
    'CircuitBreakerState',
    'init_health_monitoring',
    'get_health_status',
    'get_circuit_breaker_states',
    'health_checker',
    'circuit_breaker'
]