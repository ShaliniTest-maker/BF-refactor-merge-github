"""
Database Configuration Module for Flask Application

This module implements comprehensive database connectivity configuration for MongoDB and Redis,
providing PyMongo 4.5+ synchronous and Motor 3.3+ asynchronous database drivers with optimized
connection pooling patterns to ensure ≤10% performance variance from Node.js baseline.

Key Components:
- MongoDB connectivity with PyMongo 4.5+ for synchronous operations
- Motor 3.3+ async MongoDB driver for high-performance async operations
- redis-py 5.0+ Redis client for caching and session management
- Optimized connection pooling configurations per Section 6.1.3
- Comprehensive monitoring integration with Prometheus metrics collection
- Environment-specific database configuration management
- Flask application factory pattern integration

Architecture Integration:
- Section 0.1.2: Database driver conversion from Node.js MongoDB drivers to PyMongo/Motor
- Section 6.1.3: Connection pool management with equivalent patterns to Node.js
- Section 6.2.4: Performance optimization with Prometheus metrics instrumentation
- Section 3.4: Database and storage technology stack requirements

Performance Requirements:
- Maintains ≤10% performance variance from Node.js baseline per Section 0.1.1
- Connection pool settings: maxPoolSize=50, waitQueueTimeoutMS=30000 per Section 6.1.3
- Redis connection pool settings: max_connections=50, retry_on_timeout=True per Section 6.1.3

Author: Flask Migration Team
Version: 1.0.0
Dependencies: PyMongo 4.5+, Motor 3.3+, redis-py 5.0+, prometheus-client 0.17+
"""

import os
import ssl
import logging
import urllib.parse
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import timedelta
from contextlib import contextmanager
from urllib.parse import quote_plus

# MongoDB drivers
import pymongo
from pymongo import MongoClient, ReadPreference, WriteConcern
from pymongo.monitoring import (
    CommandListener, PoolListener, ServerHeartbeatListener,
    CommandStartedEvent, CommandSucceededEvent, CommandFailedEvent,
    PoolCreatedEvent, PoolClearedEvent, ConnectionCreatedEvent,
    ConnectionClosedEvent, ConnectionCheckOutStartedEvent,
    ConnectionCheckOutFailedEvent, ConnectionCheckedOutEvent,
    ConnectionCheckedInEvent
)
from pymongo.errors import (
    ConnectionFailure, ServerSelectionTimeoutError, OperationFailure,
    NetworkTimeout, ConfigurationError, InvalidOperation
)

# Motor async driver
import motor.motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection

# Redis client
import redis
from redis import Redis, ConnectionPool, Sentinel
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
    TimeoutError as RedisTimeoutError,
    RedisError
)

# Monitoring and metrics
from prometheus_client import Counter, Histogram, Gauge, Info
import structlog

# Environment configuration
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure structured logging for database operations
logger = structlog.get_logger(__name__)


class DatabaseMonitoringListener(CommandListener):
    """
    PyMongo command listener for comprehensive database operation monitoring.
    
    Implements Prometheus metrics collection for MongoDB operations per Section 6.2.4
    performance optimization requirements, capturing query execution times, error rates,
    and operation counts for continuous performance validation.
    """
    
    def __init__(self):
        """Initialize Prometheus metrics collectors for database monitoring."""
        self.query_duration = Histogram(
            'mongodb_query_duration_seconds',
            'Database query execution time in seconds',
            ['database', 'collection', 'command', 'environment']
        )
        
        self.query_counter = Counter(
            'mongodb_operations_total',
            'Total database operations count',
            ['database', 'collection', 'command', 'status', 'environment']
        )
        
        self.query_errors = Counter(
            'mongodb_query_errors_total',
            'Total database query errors',
            ['database', 'collection', 'command', 'error_type', 'environment']
        )
        
        self.active_operations = Gauge(
            'mongodb_active_operations',
            'Currently active database operations',
            ['database', 'environment']
        )
        
        self.environment = os.getenv('FLASK_ENV', 'development')
        self._active_ops = {}
        
        logger.info("Database monitoring listener initialized", 
                   environment=self.environment,
                   metrics_enabled=True)
    
    def started(self, event: CommandStartedEvent):
        """Record start of database operation for duration tracking."""
        operation_id = event.request_id
        self._active_ops[operation_id] = {
            'start_time': event.command,
            'database': event.database_name,
            'collection': event.command.get('collection', event.command.get(event.command_name, '')),
            'command': event.command_name
        }
        
        # Update active operations gauge
        self.active_operations.labels(
            database=event.database_name,
            environment=self.environment
        ).inc()
        
        logger.debug("Database operation started",
                    operation_id=operation_id,
                    database=event.database_name,
                    command=event.command_name)
    
    def succeeded(self, event: CommandSucceededEvent):
        """Record successful database operation completion."""
        operation_id = event.request_id
        
        if operation_id in self._active_ops:
            op_data = self._active_ops.pop(operation_id)
            duration = event.duration_micros / 1_000_000  # Convert to seconds
            
            # Record operation duration
            self.query_duration.labels(
                database=event.database_name,
                collection=op_data['collection'],
                command=event.command_name,
                environment=self.environment
            ).observe(duration)
            
            # Increment success counter
            self.query_counter.labels(
                database=event.database_name,
                collection=op_data['collection'],
                command=event.command_name,
                status='success',
                environment=self.environment
            ).inc()
            
            # Update active operations gauge
            self.active_operations.labels(
                database=event.database_name,
                environment=self.environment
            ).dec()
            
            logger.debug("Database operation succeeded",
                        operation_id=operation_id,
                        database=event.database_name,
                        command=event.command_name,
                        duration_seconds=duration)
    
    def failed(self, event: CommandFailedEvent):
        """Record failed database operation for error tracking."""
        operation_id = event.request_id
        
        if operation_id in self._active_ops:
            op_data = self._active_ops.pop(operation_id)
            
            # Record error counter
            self.query_errors.labels(
                database=event.database_name,
                collection=op_data['collection'],
                command=event.command_name,
                error_type=type(event.failure).__name__,
                environment=self.environment
            ).inc()
            
            # Increment failure counter
            self.query_counter.labels(
                database=event.database_name,
                collection=op_data['collection'],
                command=event.command_name,
                status='failure',
                environment=self.environment
            ).inc()
            
            # Update active operations gauge
            self.active_operations.labels(
                database=event.database_name,
                environment=self.environment
            ).dec()
            
            logger.error("Database operation failed",
                        operation_id=operation_id,
                        database=event.database_name,
                        command=event.command_name,
                        error=str(event.failure))


class ConnectionPoolMonitoringListener(PoolListener):
    """
    PyMongo connection pool listener for pool utilization monitoring.
    
    Implements connection pool metrics collection per Section 6.1.3 resource optimization,
    tracking pool size, checked out connections, and connection lifecycle events.
    """
    
    def __init__(self):
        """Initialize connection pool monitoring metrics."""
        self.pool_size = Gauge(
            'mongodb_pool_size',
            'Current connection pool size',
            ['address', 'environment']
        )
        
        self.pool_checked_out = Gauge(
            'mongodb_pool_checked_out_connections',
            'Currently checked out connections',
            ['address', 'environment']
        )
        
        self.pool_checkouts = Counter(
            'mongodb_pool_checkouts_total',
            'Total connection checkouts from pool',
            ['address', 'environment']
        )
        
        self.pool_checkins = Counter(
            'mongodb_pool_checkins_total',
            'Total connection checkins to pool',
            ['address', 'environment']
        )
        
        self.pool_checkout_failures = Counter(
            'mongodb_pool_checkout_failures_total',
            'Total connection checkout failures',
            ['address', 'error_type', 'environment']
        )
        
        self.environment = os.getenv('FLASK_ENV', 'development')
        
        logger.info("Connection pool monitoring listener initialized",
                   environment=self.environment)
    
    def pool_created(self, event: PoolCreatedEvent):
        """Record pool creation and initial configuration."""
        address = str(event.address)
        max_pool_size = event.options.max_pool_size or 100
        
        self.pool_size.labels(
            address=address,
            environment=self.environment
        ).set(max_pool_size)
        
        logger.info("MongoDB connection pool created",
                   address=address,
                   max_pool_size=max_pool_size,
                   environment=self.environment)
    
    def pool_cleared(self, event: PoolClearedEvent):
        """Record pool clearing event."""
        address = str(event.address)
        
        # Reset checked out connections gauge
        self.pool_checked_out.labels(
            address=address,
            environment=self.environment
        ).set(0)
        
        logger.warning("MongoDB connection pool cleared",
                      address=address,
                      environment=self.environment)
    
    def connection_checked_out(self, event: ConnectionCheckedOutEvent):
        """Record connection checkout from pool."""
        address = str(event.address)
        
        self.pool_checkouts.labels(
            address=address,
            environment=self.environment
        ).inc()
        
        self.pool_checked_out.labels(
            address=address,
            environment=self.environment
        ).inc()
    
    def connection_checked_in(self, event: ConnectionCheckedInEvent):
        """Record connection checkin to pool."""
        address = str(event.address)
        
        self.pool_checkins.labels(
            address=address,
            environment=self.environment
        ).inc()
        
        self.pool_checked_out.labels(
            address=address,
            environment=self.environment
        ).dec()
    
    def connection_check_out_failed(self, event: ConnectionCheckOutFailedEvent):
        """Record connection checkout failure."""
        address = str(event.address)
        error_type = event.reason.__class__.__name__ if event.reason else 'Unknown'
        
        self.pool_checkout_failures.labels(
            address=address,
            error_type=error_type,
            environment=self.environment
        ).inc()
        
        logger.error("MongoDB connection checkout failed",
                    address=address,
                    error_type=error_type,
                    environment=self.environment)


class DatabaseConfig:
    """
    Comprehensive database configuration for MongoDB and Redis connectivity.
    
    Implements PyMongo 4.5+ synchronous and Motor 3.3+ asynchronous MongoDB drivers
    with redis-py 5.0+ for caching and session management. Provides optimized
    connection pooling and monitoring integration per technical specification
    requirements.
    """
    
    def __init__(self, environment: str = None):
        """
        Initialize database configuration for specified environment.
        
        Args:
            environment: Target environment (development, testing, staging, production)
        """
        self.environment = environment or os.getenv('FLASK_ENV', 'development')
        self.monitoring_enabled = os.getenv('DATABASE_MONITORING_ENABLED', 'true').lower() == 'true'
        
        # Initialize monitoring listeners
        self.command_listener = DatabaseMonitoringListener()
        self.pool_listener = ConnectionPoolMonitoringListener()
        
        # Initialize configuration based on environment
        self._load_environment_config()
        
        logger.info("Database configuration initialized",
                   environment=self.environment,
                   monitoring_enabled=self.monitoring_enabled)
    
    def _load_environment_config(self):
        """Load environment-specific database configuration settings."""
        
        # MongoDB Configuration
        self.mongodb_config = self._get_mongodb_config()
        
        # Redis Configuration  
        self.redis_config = self._get_redis_config()
        
        # Connection Pool Configuration
        self.connection_pool_config = self._get_connection_pool_config()
        
        # SSL/TLS Configuration
        self.ssl_config = self._get_ssl_config()
        
        # Monitoring Configuration
        self.monitoring_config = self._get_monitoring_config()
        
        logger.debug("Environment configuration loaded",
                    environment=self.environment,
                    mongodb_uri_configured=bool(self.mongodb_config.get('uri')),
                    redis_host_configured=bool(self.redis_config.get('host')))
    
    def _get_mongodb_config(self) -> Dict[str, Any]:
        """
        Get MongoDB connection configuration.
        
        Returns:
            MongoDB configuration dictionary with connection parameters
        """
        # Base MongoDB configuration
        config = {
            'uri': os.getenv('MONGODB_URI', 'mongodb://localhost:27017'),
            'database': os.getenv('MONGODB_DATABASE', 'flask_app'),
            'username': os.getenv('MONGODB_USERNAME'),
            'password': os.getenv('MONGODB_PASSWORD'),
            'auth_source': os.getenv('MONGODB_AUTH_SOURCE', 'admin'),
            'auth_mechanism': os.getenv('MONGODB_AUTH_MECHANISM', 'SCRAM-SHA-256'),
            'replica_set': os.getenv('MONGODB_REPLICA_SET'),
            'read_preference': os.getenv('MONGODB_READ_PREFERENCE', 'primary')
        }
        
        # Environment-specific overrides
        if self.environment == 'testing':
            config.update({
                'uri': os.getenv('MONGODB_TEST_URI', 'mongodb://localhost:27017'),
                'database': os.getenv('MONGODB_TEST_DATABASE', 'test_database')
            })
        elif self.environment == 'staging':
            config.update({
                'uri': os.getenv('MONGODB_STAGING_URI', 'mongodb://localhost:27017'),
                'database': os.getenv('MONGODB_STAGING_DATABASE', 'staging_database')
            })
        elif self.environment == 'production':
            config.update({
                'uri': os.getenv('MONGODB_PRODUCTION_URI', 'mongodb://localhost:27017'),
                'database': os.getenv('MONGODB_PRODUCTION_DATABASE', 'production_database')
            })
        
        # Build connection URI if credentials are provided separately
        if config['username'] and config['password'] and '://' in config['uri']:
            scheme, remainder = config['uri'].split('://', 1)
            username = quote_plus(config['username'])
            password = quote_plus(config['password'])
            config['uri'] = f"{scheme}://{username}:{password}@{remainder}"
        
        return config
    
    def _get_redis_config(self) -> Dict[str, Any]:
        """
        Get Redis connection configuration.
        
        Returns:
            Redis configuration dictionary with connection parameters
        """
        # Base Redis configuration
        config = {
            'host': os.getenv('REDIS_HOST', 'localhost'),
            'port': int(os.getenv('REDIS_PORT', '6379')),
            'db': int(os.getenv('REDIS_DB', '0')),
            'password': os.getenv('REDIS_PASSWORD'),
            'username': os.getenv('REDIS_USERNAME'),
            'ssl': os.getenv('REDIS_SSL', 'false').lower() == 'true',
            'ssl_cert_reqs': os.getenv('REDIS_SSL_CERT_REQS', 'required'),
            'ssl_ca_certs': os.getenv('REDIS_SSL_CA_CERTS'),
            'ssl_certfile': os.getenv('REDIS_SSL_CERTFILE'),
            'ssl_keyfile': os.getenv('REDIS_SSL_KEYFILE'),
            'decode_responses': True,
            'health_check_interval': int(os.getenv('REDIS_HEALTH_CHECK_INTERVAL', '30')),
            'socket_keepalive': True,
            'socket_keepalive_options': {
                'TCP_KEEPIDLE': 1,
                'TCP_KEEPINTVL': 3,
                'TCP_KEEPCNT': 5
            }
        }
        
        # Environment-specific overrides
        if self.environment == 'testing':
            config.update({
                'host': os.getenv('REDIS_TEST_HOST', 'localhost'),
                'port': int(os.getenv('REDIS_TEST_PORT', '6379')),
                'db': int(os.getenv('REDIS_TEST_DB', '15'))
            })
        elif self.environment == 'staging':
            config.update({
                'host': os.getenv('REDIS_STAGING_HOST', 'localhost'),
                'port': int(os.getenv('REDIS_STAGING_PORT', '6379')),
                'db': int(os.getenv('REDIS_STAGING_DB', '1'))
            })
        elif self.environment == 'production':
            config.update({
                'host': os.getenv('REDIS_PRODUCTION_HOST', 'localhost'),
                'port': int(os.getenv('REDIS_PRODUCTION_PORT', '6379')),
                'db': int(os.getenv('REDIS_PRODUCTION_DB', '0'))
            })
        
        # Redis Sentinel configuration for high availability
        sentinel_hosts = os.getenv('REDIS_SENTINEL_HOSTS')
        if sentinel_hosts:
            config['sentinel_hosts'] = [
                host.strip().split(':') for host in sentinel_hosts.split(',')
                if ':' in host.strip()
            ]
            config['sentinel_service_name'] = os.getenv('REDIS_SENTINEL_SERVICE_NAME', 'mymaster')
        
        return config
    
    def _get_connection_pool_config(self) -> Dict[str, Any]:
        """
        Get optimized connection pool configuration per Section 6.1.3.
        
        Returns:
            Connection pool configuration with performance-optimized settings
        """
        base_config = {
            # MongoDB PyMongo connection pool settings
            'mongodb_sync': {
                'maxPoolSize': int(os.getenv('MONGODB_MAX_POOL_SIZE', '50')),
                'minPoolSize': int(os.getenv('MONGODB_MIN_POOL_SIZE', '5')),
                'waitQueueTimeoutMS': int(os.getenv('MONGODB_WAIT_QUEUE_TIMEOUT_MS', '30000')),
                'serverSelectionTimeoutMS': int(os.getenv('MONGODB_SERVER_SELECTION_TIMEOUT_MS', '10000')),
                'socketTimeoutMS': int(os.getenv('MONGODB_SOCKET_TIMEOUT_MS', '30000')),
                'connectTimeoutMS': int(os.getenv('MONGODB_CONNECT_TIMEOUT_MS', '10000')),
                'heartbeatFrequencyMS': int(os.getenv('MONGODB_HEARTBEAT_FREQUENCY_MS', '10000')),
                'retryWrites': os.getenv('MONGODB_RETRY_WRITES', 'true').lower() == 'true',
                'retryReads': os.getenv('MONGODB_RETRY_READS', 'true').lower() == 'true'
            },
            
            # Motor async connection pool settings (enhanced for async performance)
            'mongodb_async': {
                'maxPoolSize': int(os.getenv('MOTOR_MAX_POOL_SIZE', '100')),
                'minPoolSize': int(os.getenv('MOTOR_MIN_POOL_SIZE', '10')),
                'waitQueueMultiple': int(os.getenv('MOTOR_WAIT_QUEUE_MULTIPLE', '2')),
                'waitQueueTimeoutMS': int(os.getenv('MOTOR_WAIT_QUEUE_TIMEOUT_MS', '30000')),
                'serverSelectionTimeoutMS': int(os.getenv('MOTOR_SERVER_SELECTION_TIMEOUT_MS', '10000')),
                'socketTimeoutMS': int(os.getenv('MOTOR_SOCKET_TIMEOUT_MS', '30000')),
                'connectTimeoutMS': int(os.getenv('MOTOR_CONNECT_TIMEOUT_MS', '10000')),
                'retryWrites': os.getenv('MOTOR_RETRY_WRITES', 'true').lower() == 'true',
                'retryReads': os.getenv('MOTOR_RETRY_READS', 'true').lower() == 'true'
            },
            
            # Redis connection pool settings per Section 6.1.3
            'redis': {
                'max_connections': int(os.getenv('REDIS_MAX_CONNECTIONS', '50')),
                'retry_on_timeout': os.getenv('REDIS_RETRY_ON_TIMEOUT', 'true').lower() == 'true',
                'socket_timeout': float(os.getenv('REDIS_SOCKET_TIMEOUT', '30.0')),
                'socket_connect_timeout': float(os.getenv('REDIS_SOCKET_CONNECT_TIMEOUT', '10.0')),
                'connection_pool_class_kwargs': {
                    'max_connections': int(os.getenv('REDIS_MAX_CONNECTIONS', '50')),
                    'retry_on_timeout': os.getenv('REDIS_RETRY_ON_TIMEOUT', 'true').lower() == 'true',
                    'health_check_interval': int(os.getenv('REDIS_HEALTH_CHECK_INTERVAL', '30'))
                }
            }
        }
        
        # Environment-specific pool optimizations
        if self.environment == 'development':
            # Smaller pools for development
            base_config['mongodb_sync']['maxPoolSize'] = 10
            base_config['mongodb_async']['maxPoolSize'] = 20
            base_config['redis']['max_connections'] = 10
        elif self.environment == 'testing':
            # Minimal pools for testing
            base_config['mongodb_sync']['maxPoolSize'] = 5
            base_config['mongodb_async']['maxPoolSize'] = 10
            base_config['redis']['max_connections'] = 5
        elif self.environment == 'production':
            # Maximum pools for production performance
            base_config['mongodb_sync']['maxPoolSize'] = int(os.getenv('MONGODB_MAX_POOL_SIZE', '100'))
            base_config['mongodb_async']['maxPoolSize'] = int(os.getenv('MOTOR_MAX_POOL_SIZE', '200'))
            base_config['redis']['max_connections'] = int(os.getenv('REDIS_MAX_CONNECTIONS', '100'))
        
        return base_config
    
    def _get_ssl_config(self) -> Dict[str, Any]:
        """
        Get SSL/TLS configuration for secure database connections.
        
        Returns:
            SSL configuration dictionary for MongoDB and Redis
        """
        return {
            'mongodb': {
                'ssl': os.getenv('MONGODB_SSL', 'false').lower() == 'true',
                'ssl_cert_reqs': ssl.CERT_REQUIRED if os.getenv('MONGODB_SSL_CERT_REQS', 'required') == 'required' else ssl.CERT_NONE,
                'ssl_ca_certs': os.getenv('MONGODB_SSL_CA_CERTS'),
                'ssl_certfile': os.getenv('MONGODB_SSL_CERTFILE'),
                'ssl_keyfile': os.getenv('MONGODB_SSL_KEYFILE'),
                'ssl_crlfile': os.getenv('MONGODB_SSL_CRLFILE'),
                'ssl_allow_invalid_certificates': os.getenv('MONGODB_SSL_ALLOW_INVALID_CERTIFICATES', 'false').lower() == 'true',
                'ssl_allow_invalid_hostnames': os.getenv('MONGODB_SSL_ALLOW_INVALID_HOSTNAMES', 'false').lower() == 'true'
            },
            'redis': {
                'ssl': os.getenv('REDIS_SSL', 'false').lower() == 'true',
                'ssl_cert_reqs': os.getenv('REDIS_SSL_CERT_REQS', 'required'),
                'ssl_ca_certs': os.getenv('REDIS_SSL_CA_CERTS'),
                'ssl_certfile': os.getenv('REDIS_SSL_CERTFILE'),
                'ssl_keyfile': os.getenv('REDIS_SSL_KEYFILE'),
                'ssl_check_hostname': os.getenv('REDIS_SSL_CHECK_HOSTNAME', 'true').lower() == 'true'
            }
        }
    
    def _get_monitoring_config(self) -> Dict[str, Any]:
        """
        Get database monitoring and metrics configuration.
        
        Returns:
            Monitoring configuration for Prometheus metrics and logging
        """
        return {
            'enabled': self.monitoring_enabled,
            'prometheus_enabled': os.getenv('PROMETHEUS_METRICS_ENABLED', 'true').lower() == 'true',
            'log_level': os.getenv('DATABASE_LOG_LEVEL', 'INFO'),
            'slow_query_threshold_ms': int(os.getenv('MONGODB_SLOW_QUERY_THRESHOLD_MS', '100')),
            'metrics_prefix': os.getenv('DATABASE_METRICS_PREFIX', 'flask_app'),
            'health_check_enabled': os.getenv('DATABASE_HEALTH_CHECK_ENABLED', 'true').lower() == 'true',
            'health_check_timeout': int(os.getenv('DATABASE_HEALTH_CHECK_TIMEOUT', '5'))
        }
    
    def get_mongodb_client(self) -> MongoClient:
        """
        Create and configure PyMongo synchronous client with optimized connection pooling.
        
        Returns:
            Configured PyMongo client instance
        """
        client_options = {
            **self.connection_pool_config['mongodb_sync'],
            'readPreference': self._get_read_preference(),
            'writeConcern': self._get_write_concern(),
            'readConcern': {'level': 'majority'}
        }
        
        # Add SSL configuration if enabled
        if self.ssl_config['mongodb']['ssl']:
            client_options.update({
                'ssl': True,
                'ssl_cert_reqs': self.ssl_config['mongodb']['ssl_cert_reqs'],
                'ssl_ca_certs': self.ssl_config['mongodb']['ssl_ca_certs'],
                'ssl_certfile': self.ssl_config['mongodb']['ssl_certfile'],
                'ssl_keyfile': self.ssl_config['mongodb']['ssl_keyfile'],
                'ssl_crlfile': self.ssl_config['mongodb']['ssl_crlfile'],
                'ssl_allow_invalid_certificates': self.ssl_config['mongodb']['ssl_allow_invalid_certificates'],
                'ssl_allow_invalid_hostnames': self.ssl_config['mongodb']['ssl_allow_invalid_hostnames']
            })
        
        # Add monitoring listeners if enabled
        event_listeners = []
        if self.monitoring_enabled:
            event_listeners.extend([self.command_listener, self.pool_listener])
        
        if event_listeners:
            client_options['event_listeners'] = event_listeners
        
        try:
            client = MongoClient(self.mongodb_config['uri'], **client_options)
            
            # Test connection
            client.admin.command('ping')
            
            logger.info("PyMongo client created successfully",
                       database=self.mongodb_config['database'],
                       environment=self.environment,
                       max_pool_size=client_options['maxPoolSize'])
            
            return client
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error("Failed to create PyMongo client",
                        error=str(e),
                        uri=self.mongodb_config['uri'],
                        environment=self.environment)
            raise
    
    def get_motor_client(self) -> AsyncIOMotorClient:
        """
        Create and configure Motor async client for high-performance async operations.
        
        Returns:
            Configured Motor async client instance
        """
        client_options = {
            **self.connection_pool_config['mongodb_async'],
            'readPreference': self._get_read_preference(),
            'writeConcern': self._get_write_concern(),
            'readConcern': {'level': 'majority'}
        }
        
        # Add SSL configuration if enabled
        if self.ssl_config['mongodb']['ssl']:
            client_options.update({
                'ssl': True,
                'ssl_cert_reqs': self.ssl_config['mongodb']['ssl_cert_reqs'],
                'ssl_ca_certs': self.ssl_config['mongodb']['ssl_ca_certs'],
                'ssl_certfile': self.ssl_config['mongodb']['ssl_certfile'],
                'ssl_keyfile': self.ssl_config['mongodb']['ssl_keyfile'],
                'ssl_crlfile': self.ssl_config['mongodb']['ssl_crlfile'],
                'ssl_allow_invalid_certificates': self.ssl_config['mongodb']['ssl_allow_invalid_certificates'],
                'ssl_allow_invalid_hostnames': self.ssl_config['mongodb']['ssl_allow_invalid_hostnames']
            })
        
        try:
            client = AsyncIOMotorClient(self.mongodb_config['uri'], **client_options)
            
            logger.info("Motor async client created successfully",
                       database=self.mongodb_config['database'],
                       environment=self.environment,
                       max_pool_size=client_options['maxPoolSize'])
            
            return client
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error("Failed to create Motor client",
                        error=str(e),
                        uri=self.mongodb_config['uri'],
                        environment=self.environment)
            raise
    
    def get_redis_client(self) -> Redis:
        """
        Create and configure redis-py client with optimized connection pooling.
        
        Returns:
            Configured Redis client instance
        """
        # Check for Redis Sentinel configuration
        if 'sentinel_hosts' in self.redis_config:
            return self._get_redis_sentinel_client()
        
        # Standard Redis client configuration
        pool_kwargs = {
            **self.connection_pool_config['redis']['connection_pool_class_kwargs'],
            'host': self.redis_config['host'],
            'port': self.redis_config['port'],
            'db': self.redis_config['db'],
            'password': self.redis_config['password'],
            'username': self.redis_config['username'],
            'decode_responses': self.redis_config['decode_responses'],
            'socket_timeout': self.connection_pool_config['redis']['socket_timeout'],
            'socket_connect_timeout': self.connection_pool_config['redis']['socket_connect_timeout'],
            'socket_keepalive': self.redis_config['socket_keepalive'],
            'socket_keepalive_options': self.redis_config['socket_keepalive_options']
        }
        
        # Add SSL configuration if enabled
        if self.redis_config['ssl']:
            pool_kwargs.update({
                'ssl': True,
                'ssl_cert_reqs': self.redis_config['ssl_cert_reqs'],
                'ssl_ca_certs': self.redis_config['ssl_ca_certs'],
                'ssl_certfile': self.redis_config['ssl_certfile'],
                'ssl_keyfile': self.redis_config['ssl_keyfile'],
                'ssl_check_hostname': self.redis_config['ssl_check_hostname']
            })
        
        try:
            # Create connection pool
            connection_pool = ConnectionPool(**pool_kwargs)
            
            # Create Redis client
            client = Redis(connection_pool=connection_pool)
            
            # Test connection
            client.ping()
            
            logger.info("Redis client created successfully",
                       host=self.redis_config['host'],
                       port=self.redis_config['port'],
                       db=self.redis_config['db'],
                       environment=self.environment,
                       max_connections=pool_kwargs['max_connections'])
            
            return client
            
        except (RedisConnectionError, RedisTimeoutError) as e:
            logger.error("Failed to create Redis client",
                        error=str(e),
                        host=self.redis_config['host'],
                        port=self.redis_config['port'],
                        environment=self.environment)
            raise
    
    def _get_redis_sentinel_client(self) -> Redis:
        """
        Create Redis client with Sentinel support for high availability.
        
        Returns:
            Redis client configured with Sentinel failover
        """
        sentinel_kwargs = {
            'socket_timeout': self.connection_pool_config['redis']['socket_timeout'],
            'socket_connect_timeout': self.connection_pool_config['redis']['socket_connect_timeout']
        }
        
        # Add SSL configuration for Sentinel if enabled
        if self.redis_config['ssl']:
            sentinel_kwargs.update({
                'ssl': True,
                'ssl_cert_reqs': self.redis_config['ssl_cert_reqs'],
                'ssl_ca_certs': self.redis_config['ssl_ca_certs'],
                'ssl_certfile': self.redis_config['ssl_certfile'],
                'ssl_keyfile': self.redis_config['ssl_keyfile']
            })
        
        try:
            # Create Sentinel instance
            sentinel = Sentinel(
                self.redis_config['sentinel_hosts'],
                sentinel_kwargs=sentinel_kwargs
            )
            
            # Get master client
            client = sentinel.master_for(
                self.redis_config['sentinel_service_name'],
                socket_timeout=self.connection_pool_config['redis']['socket_timeout'],
                socket_connect_timeout=self.connection_pool_config['redis']['socket_connect_timeout'],
                password=self.redis_config['password'],
                db=self.redis_config['db'],
                decode_responses=self.redis_config['decode_responses']
            )
            
            # Test connection
            client.ping()
            
            logger.info("Redis Sentinel client created successfully",
                       service_name=self.redis_config['sentinel_service_name'],
                       sentinel_hosts=self.redis_config['sentinel_hosts'],
                       environment=self.environment)
            
            return client
            
        except (RedisConnectionError, RedisTimeoutError) as e:
            logger.error("Failed to create Redis Sentinel client",
                        error=str(e),
                        sentinel_hosts=self.redis_config['sentinel_hosts'],
                        environment=self.environment)
            raise
    
    def _get_read_preference(self) -> ReadPreference:
        """
        Get MongoDB read preference based on configuration.
        
        Returns:
            ReadPreference enum value
        """
        preference_map = {
            'primary': ReadPreference.PRIMARY,
            'primaryPreferred': ReadPreference.PRIMARY_PREFERRED,
            'secondary': ReadPreference.SECONDARY,
            'secondaryPreferred': ReadPreference.SECONDARY_PREFERRED,
            'nearest': ReadPreference.NEAREST
        }
        
        preference = self.mongodb_config.get('read_preference', 'primary')
        return preference_map.get(preference, ReadPreference.PRIMARY)
    
    def _get_write_concern(self) -> WriteConcern:
        """
        Get MongoDB write concern based on environment.
        
        Returns:
            WriteConcern instance with appropriate settings
        """
        if self.environment == 'testing':
            # Faster writes for testing
            return WriteConcern(w=1, j=False)
        elif self.environment == 'production':
            # Durable writes for production
            return WriteConcern(w='majority', j=True, wtimeout=30000)
        else:
            # Balanced settings for development/staging
            return WriteConcern(w=1, j=True, wtimeout=10000)
    
    @contextmanager
    def get_database_session(self, client: MongoClient = None):
        """
        Context manager for database sessions with transaction support.
        
        Args:
            client: Optional PyMongo client (creates new if not provided)
            
        Yields:
            Database session with transaction context
        """
        if client is None:
            client = self.get_mongodb_client()
        
        session = None
        try:
            session = client.start_session()
            with session.start_transaction():
                yield session
                logger.debug("Database transaction committed successfully",
                           environment=self.environment)
        except Exception as e:
            if session:
                logger.error("Database transaction failed, rolling back",
                           error=str(e),
                           environment=self.environment)
            raise
        finally:
            if session:
                session.end_session()
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive database health checks.
        
        Returns:
            Health check results for MongoDB and Redis
        """
        health_status = {
            'mongodb': {'status': 'unknown', 'latency_ms': None, 'error': None},
            'redis': {'status': 'unknown', 'latency_ms': None, 'error': None},
            'overall': 'unknown'
        }
        
        # MongoDB health check
        try:
            import time
            start_time = time.time()
            
            client = self.get_mongodb_client()
            result = client.admin.command('ping')
            
            latency_ms = (time.time() - start_time) * 1000
            health_status['mongodb'] = {
                'status': 'healthy' if result.get('ok') == 1 else 'unhealthy',
                'latency_ms': round(latency_ms, 2),
                'error': None
            }
            
        except Exception as e:
            health_status['mongodb'] = {
                'status': 'unhealthy',
                'latency_ms': None,
                'error': str(e)
            }
        
        # Redis health check
        try:
            import time
            start_time = time.time()
            
            client = self.get_redis_client()
            result = client.ping()
            
            latency_ms = (time.time() - start_time) * 1000
            health_status['redis'] = {
                'status': 'healthy' if result else 'unhealthy',
                'latency_ms': round(latency_ms, 2),
                'error': None
            }
            
        except Exception as e:
            health_status['redis'] = {
                'status': 'unhealthy',
                'latency_ms': None,
                'error': str(e)
            }
        
        # Determine overall health
        mongodb_healthy = health_status['mongodb']['status'] == 'healthy'
        redis_healthy = health_status['redis']['status'] == 'healthy'
        
        if mongodb_healthy and redis_healthy:
            health_status['overall'] = 'healthy'
        elif mongodb_healthy or redis_healthy:
            health_status['overall'] = 'degraded'
        else:
            health_status['overall'] = 'unhealthy'
        
        logger.info("Database health check completed",
                   overall_status=health_status['overall'],
                   mongodb_status=health_status['mongodb']['status'],
                   redis_status=health_status['redis']['status'],
                   environment=self.environment)
        
        return health_status
    
    def get_database_info(self) -> Dict[str, Any]:
        """
        Get comprehensive database configuration information.
        
        Returns:
            Database configuration summary
        """
        return {
            'environment': self.environment,
            'mongodb': {
                'database': self.mongodb_config['database'],
                'read_preference': self.mongodb_config['read_preference'],
                'replica_set': self.mongodb_config['replica_set'],
                'ssl_enabled': self.ssl_config['mongodb']['ssl'],
                'pool_config': {
                    'max_pool_size': self.connection_pool_config['mongodb_sync']['maxPoolSize'],
                    'min_pool_size': self.connection_pool_config['mongodb_sync']['minPoolSize'],
                    'wait_queue_timeout_ms': self.connection_pool_config['mongodb_sync']['waitQueueTimeoutMS']
                }
            },
            'redis': {
                'host': self.redis_config['host'],
                'port': self.redis_config['port'],
                'db': self.redis_config['db'],
                'ssl_enabled': self.redis_config['ssl'],
                'sentinel_enabled': 'sentinel_hosts' in self.redis_config,
                'pool_config': {
                    'max_connections': self.connection_pool_config['redis']['max_connections'],
                    'socket_timeout': self.connection_pool_config['redis']['socket_timeout'],
                    'retry_on_timeout': self.connection_pool_config['redis']['retry_on_timeout']
                }
            },
            'monitoring': {
                'enabled': self.monitoring_enabled,
                'prometheus_enabled': self.monitoring_config['prometheus_enabled'],
                'slow_query_threshold_ms': self.monitoring_config['slow_query_threshold_ms']
            }
        }


# Factory functions for Flask application integration
def create_database_config(environment: str = None) -> DatabaseConfig:
    """
    Factory function to create database configuration instance.
    
    Args:
        environment: Target environment name
        
    Returns:
        DatabaseConfig instance for the specified environment
    """
    return DatabaseConfig(environment)


def get_mongodb_client(environment: str = None) -> MongoClient:
    """
    Factory function to get configured PyMongo client.
    
    Args:
        environment: Target environment name
        
    Returns:
        Configured PyMongo client instance
    """
    config = create_database_config(environment)
    return config.get_mongodb_client()


def get_motor_client(environment: str = None) -> AsyncIOMotorClient:
    """
    Factory function to get configured Motor async client.
    
    Args:
        environment: Target environment name
        
    Returns:
        Configured Motor async client instance
    """
    config = create_database_config(environment)
    return config.get_motor_client()


def get_redis_client(environment: str = None) -> Redis:
    """
    Factory function to get configured Redis client.
    
    Args:
        environment: Target environment name
        
    Returns:
        Configured Redis client instance
    """
    config = create_database_config(environment)
    return config.get_redis_client()


# Global configuration instance for module-level access
_global_config: Optional[DatabaseConfig] = None


def init_database_config(environment: str = None):
    """
    Initialize global database configuration.
    
    Args:
        environment: Target environment name
    """
    global _global_config
    _global_config = create_database_config(environment)


def get_database_config() -> DatabaseConfig:
    """
    Get global database configuration instance.
    
    Returns:
        Global DatabaseConfig instance
        
    Raises:
        RuntimeError: If configuration not initialized
    """
    if _global_config is None:
        raise RuntimeError("Database configuration not initialized. Call init_database_config() first.")
    return _global_config


# Export main classes and functions for Flask application factory pattern
__all__ = [
    'DatabaseConfig',
    'DatabaseMonitoringListener',
    'ConnectionPoolMonitoringListener',
    'create_database_config',
    'get_mongodb_client',
    'get_motor_client', 
    'get_redis_client',
    'init_database_config',
    'get_database_config'
]