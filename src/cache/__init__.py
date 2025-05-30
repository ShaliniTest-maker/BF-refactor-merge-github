"""
Cache Package Initialization

Centralized cache package providing Redis caching functionality, Flask-Caching integration,
and comprehensive cache management utilities for the Flask application. Establishes the
cache package as the primary caching provider with proper namespace organization and
connection management per Section 5.2.7 and Section 6.1.1.

This package implements enterprise-grade caching capabilities equivalent to Node.js
patterns while providing Python-native Flask integration with performance optimization
maintaining ≤10% variance from Node.js baseline per Section 0.1.1.

Key Features:
- Centralized Redis client access with connection pooling and circuit breaker patterns
- Flask-Caching 2.1+ integration for response caching and HTTP cache headers
- Intelligent cache invalidation strategies for data consistency
- Cache warming and performance optimization strategies
- Multi-tenant cache namespace management for enterprise deployments
- Comprehensive cache monitoring and observability integration
- Enterprise-grade error handling and resilience patterns

Architecture Integration:
- Flask application factory pattern support per Section 6.1.1
- Blueprint-compatible cache decorators and utilities
- Structured logging and Prometheus metrics integration
- Circuit breaker patterns for external service resilience
- Connection pool optimization for horizontal scaling
"""

import logging
from typing import Optional, Dict, Any, List, Callable
from flask import Flask, current_app
import structlog

# Core cache client components
from .client import (
    RedisClient,
    RedisPipeline,
    CircuitBreaker,
    create_redis_client,
    get_redis_client,
    init_redis_client,
    close_redis_client
)

# Flask response caching integration
from .response_cache import (
    ResponseCache,
    init_response_cache,
    get_response_cache,
    cache_for,
    cache_unless,
    cache_with_user_context,
    invalidate_endpoint_cache,
    invalidate_user_cache
)

# Cache strategies and management
from .strategies import (
    CacheStrategiesManager,
    CacheInvalidationTrigger,
    CacheWarmingPriority,
    TTLPolicy,
    CacheKeyPattern,
    TTLConfiguration,
    CacheEntry,
    cache_strategies,
    invalidate_by_pattern,
    invalidate_by_dependency,
    create_cache_key,
    schedule_warming_by_priority
)

# Cache exception handling
from .exceptions import (
    CacheError,
    CacheConnectionError,
    CacheTimeoutError,
    CacheCircuitBreakerError,
    CacheSerializationError,
    CachePoolExhaustedError,
    CacheMemoryError,
    CacheOperationError,
    CacheKeyError,
    CacheInvalidationError
)

# Cache monitoring and observability
from .monitoring import (
    CacheMonitor,
    cache_monitor,
    monitor_cache_operation,
    get_cache_metrics,
    generate_cache_health_report
)

# Configure structured logging for cache package
logger = structlog.get_logger(__name__)

# Package version information
__version__ = "1.0.0"
__author__ = "Flask Migration Team"

# Cache package state tracking
_cache_initialized = False
_redis_client: Optional[RedisClient] = None
_response_cache: Optional[ResponseCache] = None


class CacheManager:
    """
    Central cache manager providing unified interface to all cache functionalities.
    
    This class serves as the primary integration point for Flask applications,
    coordinating Redis client operations, response caching, cache strategies,
    and monitoring per Section 6.1.1 Flask application factory pattern.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize cache manager with optional Flask application.
        
        Args:
            app: Flask application instance (optional, can be set via init_app)
        """
        self.app = app
        self.redis_client: Optional[RedisClient] = None
        self.response_cache: Optional[ResponseCache] = None
        self.strategies_manager = cache_strategies
        self.monitor = cache_monitor
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize cache manager with Flask application factory pattern.
        
        Args:
            app: Flask application instance
        """
        global _cache_initialized, _redis_client, _response_cache
        
        try:
            # Get Redis configuration from Flask app config
            redis_config = {
                'host': app.config.get('REDIS_HOST', 'localhost'),
                'port': app.config.get('REDIS_PORT', 6379),
                'db': app.config.get('REDIS_DB', 0),
                'password': app.config.get('REDIS_PASSWORD'),
                'ssl': app.config.get('REDIS_SSL', False),
                'max_connections': app.config.get('REDIS_MAX_CONNECTIONS', 50),
                'socket_timeout': app.config.get('REDIS_SOCKET_TIMEOUT', 30.0),
                'socket_connect_timeout': app.config.get('REDIS_SOCKET_CONNECT_TIMEOUT', 10.0),
                'retry_on_timeout': app.config.get('REDIS_RETRY_ON_TIMEOUT', True),
                'health_check_interval': app.config.get('REDIS_HEALTH_CHECK_INTERVAL', 30),
                'decode_responses': app.config.get('REDIS_DECODE_RESPONSES', True),
                'encoding': app.config.get('REDIS_ENCODING', 'utf-8')
            }
            
            # Initialize Redis client with enterprise-grade configuration
            self.redis_client = init_redis_client(**redis_config)
            _redis_client = self.redis_client
            
            # Initialize Flask-Caching response cache integration
            self.response_cache = init_response_cache(app, self.redis_client)
            _response_cache = self.response_cache
            
            # Initialize cache monitoring
            self.monitor.init_app(app)
            
            # Configure cache strategies with application context
            self._configure_cache_strategies(app)
            
            # Register health check endpoint
            self._register_health_check_endpoint(app)
            
            # Store cache manager in app extensions
            if not hasattr(app, 'extensions'):
                app.extensions = {}
            app.extensions['cache_manager'] = self
            
            _cache_initialized = True
            
            logger.info(
                "cache_manager_initialized",
                redis_host=redis_config['host'],
                redis_port=redis_config['port'],
                redis_db=redis_config['db'],
                max_connections=redis_config['max_connections'],
                app_name=app.name
            )
            
        except Exception as e:
            logger.error(
                "cache_manager_initialization_failed",
                error_message=str(e),
                error_type=type(e).__name__,
                app_name=app.name if app else 'unknown'
            )
            raise CacheConnectionError(
                message=f"Failed to initialize cache manager: {str(e)}",
                error_code="CACHE_MANAGER_INIT_FAILED"
            )
    
    def _configure_cache_strategies(self, app: Flask) -> None:
        """
        Configure cache strategies based on application configuration.
        
        Args:
            app: Flask application instance
        """
        try:
            # Configure default TTL policies from application config
            default_ttl = app.config.get('CACHE_DEFAULT_TIMEOUT', 3600)
            cache_policies = app.config.get('CACHE_TTL_POLICIES', {})
            
            # Register namespace configurations
            for namespace, policy_config in cache_policies.items():
                ttl_config = TTLConfiguration(
                    policy=TTLPolicy(policy_config.get('policy', 'static')),
                    base_ttl_seconds=policy_config.get('base_ttl', default_ttl),
                    min_ttl_seconds=policy_config.get('min_ttl', 60),
                    max_ttl_seconds=policy_config.get('max_ttl', 86400),
                    sliding_window_seconds=policy_config.get('sliding_window', 3600),
                    adaptive_factor=policy_config.get('adaptive_factor', 1.0)
                )
                
                self.strategies_manager.namespace_manager.register_namespace(
                    namespace, ttl_config
                )
            
            logger.info(
                "cache_strategies_configured",
                default_ttl=default_ttl,
                configured_namespaces=list(cache_policies.keys())
            )
            
        except Exception as e:
            logger.warning(
                "cache_strategies_configuration_warning",
                error_message=str(e),
                using_defaults=True
            )
    
    def _register_health_check_endpoint(self, app: Flask) -> None:
        """
        Register cache health check endpoint for monitoring.
        
        Args:
            app: Flask application instance
        """
        @app.route('/health/cache')
        def cache_health_check():
            """Cache health check endpoint for load balancer and monitoring."""
            try:
                health_report = self.get_health_status()
                status_code = 200 if health_report['status'] == 'healthy' else 503
                
                return health_report, status_code, {'Content-Type': 'application/json'}
                
            except Exception as e:
                logger.error(
                    "cache_health_check_error",
                    error_message=str(e),
                    error_type=type(e).__name__
                )
                return {
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': '2024-01-01T00:00:00Z'
                }, 503, {'Content-Type': 'application/json'}
    
    def get_client(self) -> RedisClient:
        """
        Get Redis client instance.
        
        Returns:
            Redis client instance
            
        Raises:
            CacheError: If cache manager not initialized
        """
        if not self.redis_client:
            raise CacheError(
                message="Cache manager not initialized. Call init_app() first.",
                error_code="CACHE_MANAGER_NOT_INITIALIZED"
            )
        return self.redis_client
    
    def get_response_cache(self) -> ResponseCache:
        """
        Get response cache instance.
        
        Returns:
            Response cache instance
            
        Raises:
            CacheError: If cache manager not initialized
        """
        if not self.response_cache:
            raise CacheError(
                message="Response cache not initialized. Call init_app() first.",
                error_code="RESPONSE_CACHE_NOT_INITIALIZED"
            )
        return self.response_cache
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive cache health status.
        
        Returns:
            Dictionary containing cache health information
        """
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': '2024-01-01T00:00:00Z',
                'components': {}
            }
            
            # Redis client health
            if self.redis_client:
                redis_health = self.redis_client.health_check()
                health_status['components']['redis'] = redis_health
                
                if redis_health['status'] != 'healthy':
                    health_status['status'] = 'degraded'
            else:
                health_status['components']['redis'] = {'status': 'not_initialized'}
                health_status['status'] = 'unhealthy'
            
            # Response cache health
            if self.response_cache:
                cache_stats = self.response_cache.get_cache_stats()
                health_status['components']['response_cache'] = {
                    'status': 'healthy',
                    'hit_ratio': cache_stats.get('hit_ratio', 0.0),
                    'total_requests': cache_stats.get('total_requests', 0)
                }
            else:
                health_status['components']['response_cache'] = {'status': 'not_initialized'}
                if health_status['status'] == 'healthy':
                    health_status['status'] = 'degraded'
            
            # Cache strategies health
            strategies_stats = self.strategies_manager.get_cache_statistics()
            health_status['components']['strategies'] = {
                'status': 'healthy',
                'total_entries': strategies_stats.get('total_entries', 0),
                'total_size_bytes': strategies_stats.get('total_size_bytes', 0)
            }
            
            # Monitoring health
            monitoring_metrics = self.monitor.get_metrics_summary()
            health_status['components']['monitoring'] = {
                'status': 'healthy',
                'metrics_collected': len(monitoring_metrics)
            }
            
            return health_status
            
        except Exception as e:
            logger.error(
                "cache_health_status_error",
                error_message=str(e),
                error_type=type(e).__name__
            )
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': '2024-01-01T00:00:00Z'
            }
    
    def close(self) -> None:
        """Close cache manager and cleanup resources."""
        global _cache_initialized, _redis_client, _response_cache
        
        try:
            if self.redis_client:
                self.redis_client.close()
                self.redis_client = None
            
            if self.response_cache:
                # Response cache cleanup handled by Flask-Caching
                self.response_cache = None
            
            _cache_initialized = False
            _redis_client = None
            _response_cache = None
            
            logger.info("cache_manager_closed")
            
        except Exception as e:
            logger.warning(
                "cache_manager_close_error",
                error_message=str(e)
            )


# Global cache manager instance for Flask application integration
cache_manager = CacheManager()


def init_cache(app: Flask, redis_config: Optional[Dict[str, Any]] = None) -> CacheManager:
    """
    Initialize complete cache system for Flask application.
    
    Args:
        app: Flask application instance
        redis_config: Optional Redis configuration override
        
    Returns:
        Configured CacheManager instance
    """
    global cache_manager
    
    # Apply Redis configuration override if provided
    if redis_config:
        for key, value in redis_config.items():
            config_key = f"REDIS_{key.upper()}"
            app.config[config_key] = value
    
    # Initialize cache manager with application
    cache_manager.init_app(app)
    
    logger.info(
        "cache_system_initialized",
        app_name=app.name,
        config_override=bool(redis_config)
    )
    
    return cache_manager


def get_cache_manager() -> CacheManager:
    """
    Get global cache manager instance.
    
    Returns:
        Global CacheManager instance
        
    Raises:
        CacheError: If cache manager not initialized
    """
    global _cache_initialized
    
    if not _cache_initialized:
        raise CacheError(
            message="Cache system not initialized. Call init_cache() first.",
            error_code="CACHE_SYSTEM_NOT_INITIALIZED"
        )
    
    return cache_manager


def is_cache_available() -> bool:
    """
    Check if cache system is available and healthy.
    
    Returns:
        True if cache is available, False otherwise
    """
    try:
        if not _cache_initialized:
            return False
        
        health_status = cache_manager.get_health_status()
        return health_status['status'] in ['healthy', 'degraded']
        
    except Exception:
        return False


# Convenience functions for common cache operations
def cache_get(key: str, default: Any = None) -> Any:
    """
    Get value from cache with fallback.
    
    Args:
        key: Cache key
        default: Default value if key not found
        
    Returns:
        Cached value or default
    """
    try:
        client = get_redis_client()
        return client.get(key, default)
    except CacheError:
        return default


def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """
    Set value in cache with optional TTL.
    
    Args:
        key: Cache key
        value: Value to cache
        ttl: Time-to-live in seconds
        
    Returns:
        True if successful, False otherwise
    """
    try:
        client = get_redis_client()
        return client.set(key, value, ttl)
    except CacheError:
        return False


def cache_delete(*keys: str) -> int:
    """
    Delete keys from cache.
    
    Args:
        *keys: Cache keys to delete
        
    Returns:
        Number of keys deleted
    """
    try:
        client = get_redis_client()
        return client.delete(*keys)
    except CacheError:
        return 0


def cache_invalidate_pattern(pattern: str) -> List[str]:
    """
    Invalidate cache keys matching pattern.
    
    Args:
        pattern: Pattern to match (supports wildcards)
        
    Returns:
        List of invalidated keys
    """
    try:
        return invalidate_by_pattern(pattern)
    except CacheError:
        return []


# Package exports organized by category for clear public API
__all__ = [
    # Core cache manager
    'CacheManager',
    'cache_manager',
    'init_cache',
    'get_cache_manager',
    'is_cache_available',
    
    # Redis client components
    'RedisClient',
    'RedisPipeline',
    'CircuitBreaker',
    'create_redis_client',
    'get_redis_client',
    'init_redis_client',
    'close_redis_client',
    
    # Response caching
    'ResponseCache',
    'init_response_cache',
    'get_response_cache',
    'cache_for',
    'cache_unless',
    'cache_with_user_context',
    'invalidate_endpoint_cache',
    'invalidate_user_cache',
    
    # Cache strategies and management
    'CacheStrategiesManager',
    'CacheInvalidationTrigger',
    'CacheWarmingPriority',
    'TTLPolicy',
    'CacheKeyPattern',
    'TTLConfiguration',
    'CacheEntry',
    'cache_strategies',
    'invalidate_by_pattern',
    'invalidate_by_dependency',
    'create_cache_key',
    'schedule_warming_by_priority',
    
    # Exception handling
    'CacheError',
    'CacheConnectionError',
    'CacheTimeoutError',
    'CacheCircuitBreakerError',
    'CacheSerializationError',
    'CachePoolExhaustedError',
    'CacheMemoryError',
    'CacheOperationError',
    'CacheKeyError',
    'CacheInvalidationError',
    
    # Monitoring and observability
    'CacheMonitor',
    'cache_monitor',
    'monitor_cache_operation',
    'get_cache_metrics',
    'generate_cache_health_report',
    
    # Convenience functions
    'cache_get',
    'cache_set',
    'cache_delete',
    'cache_invalidate_pattern',
    
    # Package metadata
    '__version__'
]

# Log package initialization
logger.info(
    "cache_package_loaded",
    version=__version__,
    components_exported=len(__all__),
    redis_client_available=bool(_redis_client),
    response_cache_available=bool(_response_cache),
    cache_initialized=_cache_initialized
)