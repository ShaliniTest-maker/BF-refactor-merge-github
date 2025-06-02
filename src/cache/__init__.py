"""
Cache Package Initialization - Centralized Redis Caching Infrastructure

This module provides centralized access to Redis caching functionality, Flask-Caching integration,
and cache management utilities for the Node.js to Python Flask migration. Establishes the cache
package as the primary caching provider with proper namespace organization and connection management
supporting Flask application factory pattern per Section 6.1.1.

The cache package implements comprehensive caching layer requirements specified in Section 5.2.7
including response caching, session management, distributed caching, cache invalidation strategies,
and performance optimization maintaining ≤10% variance from Node.js baseline per Section 0.1.1.

Key Features:
- Centralized Redis client access with redis-py 5.0+ integration per Section 0.1.2
- Flask-Caching 2.1+ integration for response caching per Section 3.4.2
- Enterprise-grade connection pooling and circuit breaker patterns per Section 6.1.3
- Comprehensive cache invalidation and TTL management strategies per Section 5.2.7
- Cache warming and optimization for performance enhancement per Section 5.2.7
- Distributed cache coordination for multi-instance Flask deployments per Section 6.1.1
- Integration with enterprise monitoring and observability per Section 5.4.1
- Package-level namespace organization for maintainable code per Section 6.1.1

Architecture Integration:
- Flask application factory pattern compatibility per Section 6.1.1 Flask Blueprint architecture
- Flask extension integration per Section 4.2.1 Flask application initialization
- Seamless integration with src/config/database.py configuration management
- Enterprise monitoring integration with structured logging and metrics collection
- Circuit breaker coordination with external service resilience patterns
- Performance variance tracking against Node.js baseline cache performance

Package Organization:
- client.py: Core Redis client implementation with connection pooling and circuit breakers
- response_cache.py: Flask-Caching integration for HTTP response caching and optimization
- strategies.py: Cache invalidation, TTL management, and warming strategies
- exceptions.py: Comprehensive cache error handling and exception classes
- monitoring.py: Cache performance monitoring, metrics collection, and health checks

Usage Examples:
    Basic Redis client access:
    >>> from src.cache import get_redis_client, init_redis_client
    >>> redis_client = init_redis_client()
    >>> redis_client.set('key', 'value', ttl=300)
    >>> value = redis_client.get('key')

    Flask application integration:
    >>> from src.cache import init_cache_extensions
    >>> app = Flask(__name__)
    >>> cache_extensions = init_cache_extensions(app)

    Response caching with Flask decorator:
    >>> from src.cache import cached_response
    >>> @cached_response(ttl=300, policy='public')
    >>> def api_endpoint():
    >>>     return jsonify({'data': 'cached_response'})

Performance Requirements:
- Redis operation latency: ≤5ms for get/set operations
- Cache hit latency: ≤2ms for response cache hits
- Cache invalidation latency: ≤10ms for pattern-based invalidation
- Memory efficiency: ≤15% overhead for cache coordination structures
- Distributed coordination: ≤10ms for multi-instance cache synchronization

References:
- Section 5.2.7: Caching layer responsibilities and Redis operations with Flask integration
- Section 6.1.1: Flask application factory pattern integration requirements  
- Section 4.2.1: Flask application initialization and extension configuration
- Section 0.1.2: Data access components Redis client migration requirements
- Section 6.1.3: Resilience mechanisms and connection pool optimization
- Section 5.4.1: Monitoring and observability for cache performance tracking
"""

import logging
import warnings
from typing import Any, Dict, List, Optional, Union, Callable, Tuple

# Suppress Redis warnings during import for cleaner startup
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    
    # Core Redis client infrastructure
    from .client import (
        RedisConnectionManager,
        RedisClient,
        create_redis_client,
        init_redis_client,
        get_redis_client,
        close_redis_client
    )
    
    # Flask-Caching response cache integration
    from .response_cache import (
        FlaskResponseCache,
        CacheConfiguration,
        CachePolicy,
        CompressionType,
        CachedResponse,
        ResponseCacheMetrics,
        create_response_cache,
        get_response_cache,
        init_response_cache
    )
    
    # Cache strategies and management
    from .strategies import (
        CacheInvalidationPattern,
        TTLPolicy,
        CacheWarmingStrategy,
        CacheKeyPattern,
        TTLConfiguration,
        CacheStrategyMetrics,
        BaseCacheStrategy,
        CacheInvalidationStrategy,
        TTLManagementStrategy,
        CacheKeyPatternManager
    )

# Import monitoring and exceptions with fallback handling
try:
    from .monitoring import (
        CacheMonitoringManager,
        CacheHealthMonitor,
        monitor_cache_operation,
        track_cache_hit_miss
    )
    MONITORING_AVAILABLE = True
except ImportError as e:
    # Fallback monitoring implementations
    class CacheMonitoringManager:
        def __init__(self, *args, **kwargs):
            pass
        
        def record_cache_operation(self, *args, **kwargs):
            pass
    
    class CacheHealthMonitor:
        def __init__(self, *args, **kwargs):
            pass
        
        def check_cache_health(self):
            return True, {'status': 'monitoring_unavailable'}
    
    def monitor_cache_operation(operation, backend):
        def decorator(func):
            return func
        return decorator
    
    def track_cache_hit_miss(backend):
        def decorator(func):
            return func
        return decorator
    
    MONITORING_AVAILABLE = False

try:
    from .exceptions import (
        CacheError,
        RedisConnectionError,
        CacheOperationTimeoutError,
        CacheInvalidationError,
        CircuitBreakerOpenError,
        CacheKeyError,
        CacheSerializationError,
        CachePoolExhaustedError,
        handle_redis_exception
    )
    EXCEPTIONS_AVAILABLE = True
except ImportError as e:
    # Fallback exception classes
    class CacheError(Exception):
        def __init__(self, message, error_code=None, **kwargs):
            super().__init__(message)
            self.error_code = error_code
    
    class RedisConnectionError(CacheError):
        pass
    
    class CacheOperationTimeoutError(CacheError):
        pass
    
    class CacheInvalidationError(CacheError):
        pass
    
    class CircuitBreakerOpenError(CacheError):
        pass
    
    class CacheKeyError(CacheError):
        pass
    
    class CacheSerializationError(CacheError):
        pass
    
    class CachePoolExhaustedError(CacheError):
        pass
    
    def handle_redis_exception(error, operation):
        return CacheError(f"Cache operation failed: {operation}")
    
    EXCEPTIONS_AVAILABLE = False

# Configure package-level logging
logger = logging.getLogger(__name__)

# Package version and metadata
__version__ = "1.0.0"
__author__ = "Flask Migration Team"
__description__ = "Enterprise Redis caching infrastructure for Flask applications"

# Global cache extension instances for Flask application factory pattern
_cache_extensions: Optional[Dict[str, Any]] = None
_default_redis_client: Optional[RedisClient] = None
_default_response_cache: Optional[FlaskResponseCache] = None


def init_cache_extensions(
    app: Optional[Any] = None,
    redis_config: Optional[Dict[str, Any]] = None,
    response_cache_config: Optional[CacheConfiguration] = None,
    monitoring_enabled: bool = True
) -> Dict[str, Any]:
    """
    Initialize cache extensions for Flask application factory pattern integration.
    
    This function provides centralized cache initialization supporting Flask application
    factory pattern per Section 6.1.1 and Flask extension integration per Section 4.2.1.
    Creates and configures all cache components including Redis client, response cache,
    monitoring, and strategy managers for enterprise-grade cache management.
    
    Args:
        app: Flask application instance for initialization (optional for factory pattern)
        redis_config: Redis configuration override parameters
        response_cache_config: Response cache configuration instance
        monitoring_enabled: Enable cache monitoring and metrics collection
        
    Returns:
        Dictionary containing initialized cache extension instances
        
    Raises:
        CacheError: If cache initialization fails
        
    Example:
        Flask application factory pattern:
        >>> app = create_app()
        >>> cache_extensions = init_cache_extensions(app)
        >>> redis_client = cache_extensions['redis_client']
        >>> response_cache = cache_extensions['response_cache']
        
        Deferred initialization:
        >>> cache_extensions = init_cache_extensions()
        >>> # Later in factory function
        >>> cache_extensions['response_cache'].init_app(app)
    """
    global _cache_extensions, _default_redis_client, _default_response_cache
    
    try:
        # Initialize monitoring if available and enabled
        monitoring_manager = None
        if monitoring_enabled and MONITORING_AVAILABLE:
            try:
                monitoring_manager = CacheMonitoringManager()
                health_monitor = CacheHealthMonitor()
                monitoring_manager.health_monitor = health_monitor
                
                logger.info("Cache monitoring initialized successfully")
            except Exception as e:
                logger.warning(f"Cache monitoring initialization failed: {e}")
                monitoring_manager = None
        
        # Initialize Redis client with configuration
        redis_client_config = redis_config or {}
        redis_client = init_redis_client(
            monitoring=monitoring_manager,
            **redis_client_config
        )
        _default_redis_client = redis_client
        
        # Initialize response cache configuration
        if response_cache_config is None:
            response_cache_config = CacheConfiguration(
                policy=CachePolicy.DYNAMIC,
                ttl_seconds=300,  # 5 minutes default
                compression=CompressionType.AUTO,
                vary_headers=['Accept', 'Accept-Encoding', 'Authorization'],
                cache_private_responses=False,
                distributed_invalidation=True
            )
        
        # Initialize response cache
        response_cache = create_response_cache(
            app=app,
            config=response_cache_config,
            redis_client=redis_client
        )
        _default_response_cache = response_cache
        
        # Initialize cache strategies
        invalidation_strategy = CacheInvalidationStrategy(
            redis_client=redis_client,
            monitoring=monitoring_manager
        )
        
        ttl_strategy = TTLManagementStrategy(
            redis_client=redis_client,
            monitoring=monitoring_manager
        )
        
        key_pattern_manager = CacheKeyPatternManager(
            redis_client=redis_client,
            monitoring=monitoring_manager
        )
        
        # Register response cache with global instance if not already set
        if not _cache_extensions and response_cache:
            try:
                # Initialize global response cache for package-level access
                init_response_cache(
                    app=app if app else None,
                    config=response_cache_config,
                    redis_client=redis_client
                )
                logger.info("Global response cache initialized")
            except Exception as e:
                logger.warning(f"Global response cache initialization failed: {e}")
        
        # Create cache extensions dictionary
        cache_extensions = {
            'redis_client': redis_client,
            'response_cache': response_cache,
            'invalidation_strategy': invalidation_strategy,
            'ttl_strategy': ttl_strategy,
            'key_pattern_manager': key_pattern_manager,
            'monitoring_manager': monitoring_manager,
            'health_monitor': monitoring_manager.health_monitor if monitoring_manager else None,
            'config': {
                'redis_config': redis_client_config,
                'response_cache_config': response_cache_config,
                'monitoring_enabled': monitoring_enabled,
                'monitoring_available': MONITORING_AVAILABLE,
                'exceptions_available': EXCEPTIONS_AVAILABLE
            }
        }
        
        # Store global cache extensions reference
        _cache_extensions = cache_extensions
        
        # Configure Flask application if provided
        if app:
            app.config['CACHE_EXTENSIONS'] = cache_extensions
            
            # Add teardown handler for clean resource management
            @app.teardown_appcontext
            def close_cache_connections(error):
                """Clean up cache connections on application context teardown."""
                try:
                    if redis_client:
                        # Connection cleanup is handled by connection pool
                        pass
                except Exception as e:
                    logger.warning(f"Error during cache connection cleanup: {e}")
        
        logger.info(
            "Cache extensions initialized successfully",
            redis_client_initialized=redis_client is not None,
            response_cache_initialized=response_cache is not None,
            monitoring_enabled=monitoring_enabled and monitoring_manager is not None,
            strategies_initialized=True,
            flask_app_configured=app is not None
        )
        
        return cache_extensions
        
    except Exception as e:
        error_msg = f"Cache extensions initialization failed: {str(e)}"
        logger.error(error_msg)
        
        if EXCEPTIONS_AVAILABLE:
            raise CacheError(
                error_msg,
                error_code="CACHE_INITIALIZATION_FAILED",
                details={
                    'monitoring_enabled': monitoring_enabled,
                    'monitoring_available': MONITORING_AVAILABLE,
                    'exceptions_available': EXCEPTIONS_AVAILABLE,
                    'redis_config': redis_config,
                    'has_flask_app': app is not None
                }
            )
        else:
            raise Exception(error_msg)


def get_cache_extensions() -> Optional[Dict[str, Any]]:
    """
    Get initialized cache extensions for application access.
    
    Returns:
        Dictionary containing cache extension instances or None if not initialized
        
    Example:
        >>> cache_extensions = get_cache_extensions()
        >>> if cache_extensions:
        >>>     redis_client = cache_extensions['redis_client']
        >>>     response_cache = cache_extensions['response_cache']
    """
    return _cache_extensions


def get_default_redis_client() -> Optional[RedisClient]:
    """
    Get default Redis client instance for package-level access.
    
    Returns:
        Default RedisClient instance or None if not initialized
        
    Example:
        >>> redis_client = get_default_redis_client()
        >>> if redis_client:
        >>>     redis_client.set('key', 'value', ttl=300)
    """
    return _default_redis_client


def get_default_response_cache() -> Optional[FlaskResponseCache]:
    """
    Get default response cache instance for package-level access.
    
    Returns:
        Default FlaskResponseCache instance or None if not initialized
        
    Example:
        >>> response_cache = get_default_response_cache()
        >>> if response_cache:
        >>>     stats = response_cache.get_cache_stats()
    """
    return _default_response_cache


def cached_response(
    ttl: Optional[int] = None,
    policy: Union[str, CachePolicy] = CachePolicy.DYNAMIC,
    key_prefix: str = 'cached_response',
    tags: Optional[List[str]] = None,
    vary_headers: Optional[List[str]] = None,
    unless: Optional[Callable] = None
):
    """
    Convenient decorator for Flask response caching with sensible defaults.
    
    This decorator provides easy response caching for Flask routes with automatic
    cache key generation, TTL management, and policy-based configuration per
    Section 5.2.7 response caching requirements.
    
    Args:
        ttl: Cache timeout in seconds (uses configuration default if None)
        policy: Cache policy (string or CachePolicy enum)
        key_prefix: Prefix for cache key generation
        tags: Tags for cache invalidation
        vary_headers: Headers that affect cache variance
        unless: Function to determine if caching should be skipped
        
    Returns:
        Decorator function for Flask route caching
        
    Example:
        >>> @app.route('/api/data')
        >>> @cached_response(ttl=600, policy='public', tags=['api', 'data'])
        >>> def get_data():
        >>>     return jsonify({'data': 'cached_data'})
    """
    def decorator(func):
        # Get response cache instance
        response_cache = get_default_response_cache()
        
        if not response_cache:
            logger.warning(
                "Response cache not initialized, caching disabled for function",
                function=func.__name__
            )
            return func
        
        # Convert string policy to enum
        cache_policy = policy
        if isinstance(policy, str):
            try:
                cache_policy = CachePolicy(policy.lower())
            except ValueError:
                logger.warning(f"Invalid cache policy '{policy}', using default")
                cache_policy = CachePolicy.DYNAMIC
        
        # Use response cache decorator with configured parameters
        return response_cache.cached(
            timeout=ttl,
            key_prefix=key_prefix,
            unless=unless,
            policy=cache_policy,
            cache_tags=tags,
            vary_headers=vary_headers
        )(func)
    
    return decorator


def invalidate_cache(
    keys: Optional[Union[str, List[str]]] = None,
    patterns: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    strategy: Union[str, CacheInvalidationPattern] = CacheInvalidationPattern.IMMEDIATE
) -> Dict[str, Any]:
    """
    Convenient function for cache invalidation with multiple strategies.
    
    Provides easy cache invalidation with support for key-based, pattern-based,
    and tag-based invalidation strategies per Section 5.2.7 cache invalidation
    and TTL management requirements.
    
    Args:
        keys: Specific cache keys to invalidate
        patterns: Key patterns for bulk invalidation
        tags: Cache tags for tag-based invalidation
        strategy: Invalidation strategy (string or enum)
        
    Returns:
        Dictionary containing invalidation results
        
    Example:
        >>> # Invalidate specific keys
        >>> result = invalidate_cache(keys=['user:123:profile', 'session:abc'])
        
        >>> # Pattern-based invalidation
        >>> result = invalidate_cache(patterns=['user:*:cache', 'api:*'])
        
        >>> # Tag-based invalidation
        >>> result = invalidate_cache(tags=['user_data', 'api_cache'])
    """
    response_cache = get_default_response_cache()
    
    if not response_cache:
        raise CacheError(
            "Response cache not initialized, cannot perform invalidation",
            error_code="CACHE_NOT_INITIALIZED"
        )
    
    # Convert string strategy to enum
    invalidation_strategy = strategy
    if isinstance(strategy, str):
        try:
            invalidation_strategy = CacheInvalidationPattern(strategy.lower())
        except ValueError:
            logger.warning(f"Invalid invalidation strategy '{strategy}', using immediate")
            invalidation_strategy = CacheInvalidationPattern.IMMEDIATE
    
    return response_cache.invalidate_cache(
        keys=keys,
        patterns=patterns,
        tags=tags,
        invalidation_pattern=invalidation_strategy
    )


def get_cache_health() -> Dict[str, Any]:
    """
    Get comprehensive cache health status for monitoring integration.
    
    Returns:
        Dictionary containing cache health information across all components
        
    Example:
        >>> health = get_cache_health()
        >>> print(f"Redis healthy: {health['redis']['healthy']}")
        >>> print(f"Response cache hit rate: {health['response_cache']['hit_rate']}")
    """
    health_status = {
        'timestamp': None,
        'overall_healthy': False,
        'redis': {'healthy': False, 'details': {}},
        'response_cache': {'healthy': False, 'details': {}},
        'monitoring': {'available': MONITORING_AVAILABLE, 'details': {}},
        'extensions': {'initialized': _cache_extensions is not None}
    }
    
    try:
        # Check Redis health
        redis_client = get_default_redis_client()
        if redis_client:
            redis_healthy, redis_details = redis_client.health_check()
            health_status['redis']['healthy'] = redis_healthy
            health_status['redis']['details'] = redis_details
        
        # Check response cache health
        response_cache = get_default_response_cache()
        if response_cache:
            try:
                cache_stats = response_cache.get_cache_stats()
                health_status['response_cache']['healthy'] = True
                health_status['response_cache']['details'] = cache_stats
            except Exception as e:
                health_status['response_cache']['details'] = {'error': str(e)}
        
        # Check monitoring health
        if _cache_extensions and _cache_extensions.get('monitoring_manager'):
            try:
                monitoring_manager = _cache_extensions['monitoring_manager']
                health_monitor = _cache_extensions.get('health_monitor')
                
                if health_monitor:
                    monitoring_healthy, monitoring_details = health_monitor.check_cache_health()
                    health_status['monitoring']['available'] = True
                    health_status['monitoring']['healthy'] = monitoring_healthy
                    health_status['monitoring']['details'] = monitoring_details
            except Exception as e:
                health_status['monitoring']['details'] = {'error': str(e)}
        
        # Overall health assessment
        health_status['overall_healthy'] = (
            health_status['redis']['healthy'] and 
            health_status['response_cache']['healthy'] and
            health_status['extensions']['initialized']
        )
        
        health_status['timestamp'] = health_status['redis']['details'].get('timestamp')
        
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        health_status['error'] = str(e)
    
    return health_status


def get_cache_stats() -> Dict[str, Any]:
    """
    Get comprehensive cache statistics for monitoring and optimization.
    
    Returns:
        Dictionary containing performance metrics across all cache components
        
    Example:
        >>> stats = get_cache_stats()
        >>> print(f"Redis connections: {stats['redis']['connection_pool']['in_use_connections']}")
        >>> print(f"Cache hit rate: {stats['response_cache']['hit_rate']}")
    """
    stats = {
        'timestamp': None,
        'package_info': {
            'version': __version__,
            'monitoring_available': MONITORING_AVAILABLE,
            'exceptions_available': EXCEPTIONS_AVAILABLE,
            'extensions_initialized': _cache_extensions is not None
        },
        'redis': {},
        'response_cache': {},
        'strategies': {}
    }
    
    try:
        # Get Redis statistics
        redis_client = get_default_redis_client()
        if redis_client:
            stats['redis'] = redis_client.get_stats()
        
        # Get response cache statistics
        response_cache = get_default_response_cache()
        if response_cache:
            stats['response_cache'] = response_cache.get_cache_stats()
        
        # Get strategy statistics
        if _cache_extensions:
            for strategy_name in ['invalidation_strategy', 'ttl_strategy', 'key_pattern_manager']:
                strategy = _cache_extensions.get(strategy_name)
                if strategy and hasattr(strategy, 'get_metrics_summary'):
                    stats['strategies'][strategy_name] = strategy.get_metrics_summary()
        
        # Set overall timestamp
        stats['timestamp'] = (
            stats['redis'].get('timestamp') or 
            stats['response_cache'].get('timestamp')
        )
        
    except Exception as e:
        logger.error(f"Cache statistics collection failed: {e}")
        stats['error'] = str(e)
    
    return stats


def cleanup_cache_resources():
    """
    Clean up cache resources for application shutdown.
    
    Properly closes Redis connections, clears cache instances, and releases
    resources for graceful application shutdown per enterprise deployment
    requirements.
    
    Example:
        >>> # During application shutdown
        >>> cleanup_cache_resources()
    """
    global _cache_extensions, _default_redis_client, _default_response_cache
    
    try:
        # Close Redis client connections
        if _default_redis_client:
            _default_redis_client.close()
            _default_redis_client = None
        
        # Close global Redis client
        try:
            close_redis_client()
        except Exception as e:
            logger.warning(f"Error closing global Redis client: {e}")
        
        # Clear cache extensions
        if _cache_extensions:
            # Close monitoring if available
            monitoring_manager = _cache_extensions.get('monitoring_manager')
            if monitoring_manager and hasattr(monitoring_manager, 'close'):
                try:
                    monitoring_manager.close()
                except Exception as e:
                    logger.warning(f"Error closing monitoring manager: {e}")
            
            _cache_extensions = None
        
        # Clear response cache reference
        _default_response_cache = None
        
        logger.info("Cache resources cleaned up successfully")
        
    except Exception as e:
        logger.error(f"Cache resource cleanup failed: {e}")


# Export comprehensive public API for cache package
__all__ = [
    # Package metadata
    '__version__',
    '__author__',
    '__description__',
    
    # Core Redis client components
    'RedisConnectionManager',
    'RedisClient',
    'create_redis_client',
    'init_redis_client',
    'get_redis_client',
    'close_redis_client',
    
    # Flask response cache components
    'FlaskResponseCache',
    'CacheConfiguration',
    'CachePolicy',
    'CompressionType',
    'CachedResponse',
    'ResponseCacheMetrics',
    'create_response_cache',
    'get_response_cache',
    'init_response_cache',
    
    # Cache strategy components
    'CacheInvalidationPattern',
    'TTLPolicy',
    'CacheWarmingStrategy',
    'CacheKeyPattern',
    'TTLConfiguration',
    'CacheStrategyMetrics',
    'BaseCacheStrategy',
    'CacheInvalidationStrategy',
    'TTLManagementStrategy',
    'CacheKeyPatternManager',
    
    # Monitoring components (available if imported successfully)
    'CacheMonitoringManager',
    'CacheHealthMonitor',
    'monitor_cache_operation',
    'track_cache_hit_miss',
    
    # Exception components (available if imported successfully)
    'CacheError',
    'RedisConnectionError',
    'CacheOperationTimeoutError',
    'CacheInvalidationError',
    'CircuitBreakerOpenError',
    'CacheKeyError',
    'CacheSerializationError',
    'CachePoolExhaustedError',
    'handle_redis_exception',
    
    # Package-level integration functions
    'init_cache_extensions',
    'get_cache_extensions',
    'get_default_redis_client',
    'get_default_response_cache',
    'cached_response',
    'invalidate_cache',
    'get_cache_health',
    'get_cache_stats',
    'cleanup_cache_resources',
    
    # Package status flags
    'MONITORING_AVAILABLE',
    'EXCEPTIONS_AVAILABLE'
]