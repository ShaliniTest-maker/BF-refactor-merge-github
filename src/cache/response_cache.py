"""
Flask-Caching 2.1+ integration providing response caching, HTTP cache headers, and Flask 
request/response cache patterns. Implements comprehensive response caching equivalent to 
Node.js middleware patterns with TTL management, cache key generation, and cache invalidation 
strategies for performance optimization.

This module provides:
- Flask-Caching integration for response caching patterns
- HTTP cache headers management
- Intelligent cache key generation
- TTL management for cache lifecycle optimization
- Cache invalidation strategies for data consistency
- Performance optimization equivalent to Node.js caching patterns
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from flask import Flask, current_app, g, request, Response
from flask_caching import Cache
from prometheus_client import Counter, Histogram, Gauge
import structlog

from .client import RedisClient, get_redis_client
from .strategies import CacheInvalidationStrategy, TTLManager, CacheKeyGenerator
from .exceptions import CacheOperationError, CacheConnectionError, CacheKeyError

# Configure structured logging
logger = structlog.get_logger(__name__)

# Prometheus metrics for cache monitoring
cache_hits = Counter('response_cache_hits_total', 'Total cache hits', ['endpoint', 'method'])
cache_misses = Counter('response_cache_misses_total', 'Total cache misses', ['endpoint', 'method'])
cache_operations = Histogram('response_cache_operation_duration_seconds', 
                           'Response cache operation duration', ['operation', 'status'])
cache_size = Gauge('response_cache_size_bytes', 'Current cache size in bytes')
cache_hit_ratio = Gauge('response_cache_hit_ratio', 'Cache hit ratio', ['endpoint'])


class ResponseCache:
    """
    Flask-Caching 2.1+ integration providing comprehensive response caching capabilities.
    
    This class implements response caching patterns equivalent to Node.js middleware with:
    - Redis backend integration via Flask-Caching
    - Intelligent cache key generation
    - HTTP cache headers management
    - TTL-based cache lifecycle management
    - Cache invalidation strategies
    - Performance monitoring and metrics
    """
    
    def __init__(self, app: Optional[Flask] = None, redis_client: Optional[RedisClient] = None):
        """
        Initialize ResponseCache with Flask application and Redis client.
        
        Args:
            app: Flask application instance (optional, can be set via init_app)
            redis_client: Redis client instance (optional, will use default if not provided)
        """
        self.app = app
        self.cache: Optional[Cache] = None
        self.redis_client = redis_client
        self.ttl_manager = TTLManager()
        self.key_generator = CacheKeyGenerator()
        self.invalidation_strategy = CacheInvalidationStrategy()
        self._cache_stats = {'hits': 0, 'misses': 0, 'errors': 0}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize Flask-Caching extension with the Flask application.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Get Redis client if not provided
        if self.redis_client is None:
            self.redis_client = get_redis_client()
        
        # Configure Flask-Caching with Redis backend
        cache_config = {
            'CACHE_TYPE': 'RedisCache',
            'CACHE_REDIS_HOST': app.config.get('REDIS_HOST', 'localhost'),
            'CACHE_REDIS_PORT': app.config.get('REDIS_PORT', 6379),
            'CACHE_REDIS_DB': app.config.get('REDIS_CACHE_DB', 1),
            'CACHE_REDIS_PASSWORD': app.config.get('REDIS_PASSWORD'),
            'CACHE_DEFAULT_TIMEOUT': app.config.get('CACHE_DEFAULT_TIMEOUT', 300),
            'CACHE_KEY_PREFIX': app.config.get('CACHE_KEY_PREFIX', 'flask_response:'),
            'CACHE_OPTIONS': {
                'connection_pool_kwargs': {
                    'max_connections': 50,
                    'retry_on_timeout': True,
                    'socket_timeout': 30.0,
                    'socket_connect_timeout': 10.0
                }
            }
        }
        
        # Initialize Flask-Caching
        self.cache = Cache()
        self.cache.init_app(app, config=cache_config)
        
        # Store cache instance in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['response_cache'] = self
        
        # Initialize monitoring
        self._setup_monitoring(app)
        
        logger.info("Flask-Caching response cache initialized", 
                   redis_host=cache_config['CACHE_REDIS_HOST'],
                   redis_port=cache_config['CACHE_REDIS_PORT'],
                   default_timeout=cache_config['CACHE_DEFAULT_TIMEOUT'])
    
    def _setup_monitoring(self, app: Flask) -> None:
        """
        Setup monitoring and metrics collection for cache operations.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def track_cache_request():
            """Track cache-related metrics for incoming requests."""
            g.cache_start_time = time.time()
        
        @app.after_request
        def update_cache_metrics(response):
            """Update cache metrics after request processing."""
            try:
                if hasattr(g, 'cache_hit_status'):
                    endpoint = request.endpoint or 'unknown'
                    method = request.method
                    
                    if g.cache_hit_status == 'hit':
                        cache_hits.labels(endpoint=endpoint, method=method).inc()
                        self._cache_stats['hits'] += 1
                    elif g.cache_hit_status == 'miss':
                        cache_misses.labels(endpoint=endpoint, method=method).inc()
                        self._cache_stats['misses'] += 1
                    
                    # Update hit ratio
                    total_requests = self._cache_stats['hits'] + self._cache_stats['misses']
                    if total_requests > 0:
                        hit_ratio = self._cache_stats['hits'] / total_requests
                        cache_hit_ratio.labels(endpoint=endpoint).set(hit_ratio)
                
                # Update cache size metric
                self._update_cache_size()
                
            except Exception as e:
                logger.warning("Failed to update cache metrics", error=str(e))
            
            return response
    
    def _update_cache_size(self) -> None:
        """Update cache size metrics."""
        try:
            if self.redis_client:
                memory_info = self.redis_client.info('memory')
                used_memory = memory_info.get('used_memory', 0)
                cache_size.set(used_memory)
        except Exception as e:
            logger.warning("Failed to update cache size metric", error=str(e))
    
    def generate_cache_key(self, endpoint: str, method: str = 'GET', 
                          query_params: Optional[Dict] = None,
                          user_context: Optional[Dict] = None,
                          custom_keys: Optional[List[str]] = None) -> str:
        """
        Generate intelligent cache key for HTTP response caching.
        
        Args:
            endpoint: Flask endpoint name
            method: HTTP method
            query_params: Query parameters dictionary
            user_context: User context for personalized caching
            custom_keys: Additional custom keys for cache key generation
            
        Returns:
            Generated cache key string
            
        Raises:
            CacheKeyError: If cache key generation fails
        """
        try:
            key_components = [
                f"endpoint:{endpoint}",
                f"method:{method}",
                f"path:{request.path}"
            ]
            
            # Add query parameters (sorted for consistency)
            if query_params:
                sorted_params = sorted(query_params.items())
                param_str = "&".join([f"{k}={v}" for k, v in sorted_params])
                key_components.append(f"params:{param_str}")
            
            # Add user context for personalized caching
            if user_context:
                user_id = user_context.get('user_id', 'anonymous')
                roles = user_context.get('roles', [])
                key_components.extend([
                    f"user:{user_id}",
                    f"roles:{','.join(sorted(roles))}"
                ])
            
            # Add custom keys
            if custom_keys:
                key_components.extend([f"custom:{key}" for key in custom_keys])
            
            # Generate hash for consistent key length
            key_string = "|".join(key_components)
            key_hash = hashlib.sha256(key_string.encode('utf-8')).hexdigest()[:16]
            
            # Create final cache key with prefix
            cache_key = f"response:{endpoint}:{method}:{key_hash}"
            
            logger.debug("Generated cache key", 
                        endpoint=endpoint, method=method, 
                        cache_key=cache_key, components=len(key_components))
            
            return cache_key
            
        except Exception as e:
            logger.error("Cache key generation failed", 
                        endpoint=endpoint, method=method, error=str(e))
            raise CacheKeyError(f"Failed to generate cache key: {str(e)}")
    
    def cache_response(self, timeout: Optional[int] = None,
                      key_func: Optional[Callable] = None,
                      unless: Optional[Callable] = None,
                      forced_update: bool = False,
                      response_filter: Optional[Callable] = None) -> Callable:
        """
        Decorator for caching Flask response with comprehensive caching patterns.
        
        Args:
            timeout: Cache timeout in seconds (uses default if None)
            key_func: Custom function for generating cache keys
            unless: Function to determine if caching should be skipped
            forced_update: Force cache update regardless of existing cache
            response_filter: Function to filter/modify response before caching
            
        Returns:
            Decorated function with response caching capability
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Check if caching should be skipped
                if unless and unless():
                    logger.debug("Caching skipped due to unless condition", 
                               endpoint=request.endpoint)
                    g.cache_hit_status = 'skip'
                    return func(*args, **kwargs)
                
                # Generate cache key
                try:
                    if key_func:
                        cache_key = key_func()
                    else:
                        cache_key = self.generate_cache_key(
                            endpoint=request.endpoint or func.__name__,
                            method=request.method,
                            query_params=dict(request.args),
                            user_context=getattr(g, 'user_context', None)
                        )
                except Exception as e:
                    logger.error("Cache key generation failed, executing without cache", 
                               error=str(e))
                    return func(*args, **kwargs)
                
                # Check for cached response (unless forced update)
                if not forced_update:
                    try:
                        with cache_operations.labels(operation='get', status='success').time():
                            cached_response = self.cache.get(cache_key)
                        
                        if cached_response is not None:
                            logger.debug("Cache hit", cache_key=cache_key, 
                                       endpoint=request.endpoint)
                            g.cache_hit_status = 'hit'
                            
                            # Reconstruct response with cache headers
                            response = self._reconstruct_cached_response(cached_response)
                            return response
                            
                    except Exception as e:
                        logger.warning("Cache retrieval failed", 
                                     cache_key=cache_key, error=str(e))
                        self._cache_stats['errors'] += 1
                
                # Cache miss - execute function
                logger.debug("Cache miss", cache_key=cache_key, endpoint=request.endpoint)
                g.cache_hit_status = 'miss'
                
                try:
                    # Execute the actual function
                    response = func(*args, **kwargs)
                    
                    # Apply response filter if provided
                    if response_filter:
                        response = response_filter(response)
                    
                    # Cache the response
                    self._cache_response_data(cache_key, response, timeout)
                    
                    # Add cache headers to response
                    self._add_cache_headers(response, timeout)
                    
                    return response
                    
                except Exception as e:
                    logger.error("Function execution failed", 
                               cache_key=cache_key, error=str(e))
                    raise
            
            return wrapper
        return decorator
    
    def _cache_response_data(self, cache_key: str, response: Response, 
                           timeout: Optional[int] = None) -> None:
        """
        Cache response data with appropriate serialization.
        
        Args:
            cache_key: Cache key for storing response
            response: Flask Response object
            timeout: Cache timeout in seconds
        """
        try:
            # Determine cache timeout
            cache_timeout = timeout or self.ttl_manager.get_default_ttl()
            
            # Serialize response for caching
            cached_data = {
                'data': response.get_data(as_text=True),
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'mimetype': response.mimetype,
                'cached_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(seconds=cache_timeout)).isoformat()
            }
            
            # Store in cache
            with cache_operations.labels(operation='set', status='success').time():
                self.cache.set(cache_key, cached_data, timeout=cache_timeout)
            
            logger.debug("Response cached successfully", 
                        cache_key=cache_key, timeout=cache_timeout,
                        data_size=len(cached_data['data']))
                        
        except Exception as e:
            logger.error("Response caching failed", 
                        cache_key=cache_key, error=str(e))
            with cache_operations.labels(operation='set', status='error').time():
                pass
            raise CacheOperationError(f"Failed to cache response: {str(e)}")
    
    def _reconstruct_cached_response(self, cached_data: Dict) -> Response:
        """
        Reconstruct Flask Response object from cached data.
        
        Args:
            cached_data: Cached response data dictionary
            
        Returns:
            Reconstructed Flask Response object
        """
        try:
            response = Response(
                response=cached_data['data'],
                status=cached_data['status_code'],
                headers=cached_data.get('headers', {}),
                mimetype=cached_data.get('mimetype', 'text/html')
            )
            
            # Add cache-specific headers
            response.headers['X-Cache-Status'] = 'HIT'
            response.headers['X-Cache-Date'] = cached_data.get('cached_at', '')
            
            return response
            
        except Exception as e:
            logger.error("Failed to reconstruct cached response", error=str(e))
            raise CacheOperationError(f"Failed to reconstruct cached response: {str(e)}")
    
    def _add_cache_headers(self, response: Response, timeout: Optional[int] = None) -> None:
        """
        Add appropriate HTTP cache headers to response.
        
        Args:
            response: Flask Response object
            timeout: Cache timeout for cache-control headers
        """
        try:
            cache_timeout = timeout or self.ttl_manager.get_default_ttl()
            
            # Add cache headers
            response.headers['X-Cache-Status'] = 'MISS'
            response.headers['Cache-Control'] = f'public, max-age={cache_timeout}'
            response.headers['Expires'] = (
                datetime.utcnow() + timedelta(seconds=cache_timeout)
            ).strftime('%a, %d %b %Y %H:%M:%S GMT')
            response.headers['Last-Modified'] = datetime.utcnow().strftime(
                '%a, %d %b %Y %H:%M:%S GMT'
            )
            
            # Add ETag for cache validation
            if response.data:
                etag = hashlib.md5(response.data).hexdigest()
                response.headers['ETag'] = f'"{etag}"'
            
        except Exception as e:
            logger.warning("Failed to add cache headers", error=str(e))
    
    def invalidate_cache(self, pattern: Optional[str] = None,
                        endpoint: Optional[str] = None,
                        user_id: Optional[str] = None,
                        tags: Optional[List[str]] = None) -> bool:
        """
        Invalidate cached responses based on various criteria.
        
        Args:
            pattern: Cache key pattern for invalidation
            endpoint: Specific endpoint to invalidate
            user_id: User-specific cache invalidation
            tags: Cache tags for group invalidation
            
        Returns:
            True if invalidation successful, False otherwise
        """
        try:
            invalidated_count = 0
            
            if pattern:
                # Pattern-based invalidation
                invalidated_count += self._invalidate_by_pattern(pattern)
            
            if endpoint:
                # Endpoint-specific invalidation
                endpoint_pattern = f"response:{endpoint}:*"
                invalidated_count += self._invalidate_by_pattern(endpoint_pattern)
            
            if user_id:
                # User-specific invalidation
                user_pattern = f"*user:{user_id}*"
                invalidated_count += self._invalidate_by_pattern(user_pattern)
            
            if tags:
                # Tag-based invalidation
                for tag in tags:
                    tag_pattern = f"*tag:{tag}*"
                    invalidated_count += self._invalidate_by_pattern(tag_pattern)
            
            logger.info("Cache invalidation completed", 
                       pattern=pattern, endpoint=endpoint, user_id=user_id,
                       tags=tags, invalidated_count=invalidated_count)
            
            return invalidated_count > 0
            
        except Exception as e:
            logger.error("Cache invalidation failed", 
                        pattern=pattern, endpoint=endpoint, error=str(e))
            return False
    
    def _invalidate_by_pattern(self, pattern: str) -> int:
        """
        Invalidate cache keys matching a specific pattern.
        
        Args:
            pattern: Pattern for cache key matching
            
        Returns:
            Number of keys invalidated
        """
        try:
            if not self.redis_client:
                raise CacheConnectionError("Redis client not available")
            
            # Find matching keys
            matching_keys = self.redis_client.keys(pattern)
            
            if matching_keys:
                # Delete matching keys
                deleted_count = self.redis_client.delete(*matching_keys)
                logger.debug("Invalidated cache keys", 
                           pattern=pattern, count=deleted_count)
                return deleted_count
            
            return 0
            
        except Exception as e:
            logger.error("Pattern-based cache invalidation failed", 
                        pattern=pattern, error=str(e))
            return 0
    
    def warm_cache(self, endpoints: List[str], 
                  request_contexts: Optional[List[Dict]] = None) -> Dict[str, bool]:
        """
        Warm cache by pre-loading responses for specified endpoints.
        
        Args:
            endpoints: List of endpoint names to warm
            request_contexts: Optional request contexts for warming
            
        Returns:
            Dictionary mapping endpoints to warming success status
        """
        results = {}
        
        for endpoint in endpoints:
            try:
                # Implementation would depend on having access to the actual route functions
                # This is a placeholder for cache warming logic
                logger.info("Cache warming initiated", endpoint=endpoint)
                results[endpoint] = True
                
            except Exception as e:
                logger.error("Cache warming failed", endpoint=endpoint, error=str(e))
                results[endpoint] = False
        
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics and performance metrics.
        
        Returns:
            Dictionary containing cache statistics
        """
        try:
            stats = {
                'hits': self._cache_stats['hits'],
                'misses': self._cache_stats['misses'],
                'errors': self._cache_stats['errors'],
                'hit_ratio': 0.0,
                'total_requests': self._cache_stats['hits'] + self._cache_stats['misses'],
                'redis_info': {},
                'cache_config': {}
            }
            
            # Calculate hit ratio
            if stats['total_requests'] > 0:
                stats['hit_ratio'] = stats['hits'] / stats['total_requests']
            
            # Get Redis info if available
            if self.redis_client:
                try:
                    redis_info = self.redis_client.info()
                    stats['redis_info'] = {
                        'connected_clients': redis_info.get('connected_clients', 0),
                        'used_memory': redis_info.get('used_memory', 0),
                        'used_memory_human': redis_info.get('used_memory_human', '0B'),
                        'keyspace_hits': redis_info.get('keyspace_hits', 0),
                        'keyspace_misses': redis_info.get('keyspace_misses', 0)
                    }
                except Exception as e:
                    logger.warning("Failed to get Redis info", error=str(e))
            
            # Get cache configuration
            if self.cache and hasattr(self.cache, 'config'):
                stats['cache_config'] = {
                    'default_timeout': self.cache.config.get('CACHE_DEFAULT_TIMEOUT', 300),
                    'key_prefix': self.cache.config.get('CACHE_KEY_PREFIX', ''),
                    'cache_type': self.cache.config.get('CACHE_TYPE', 'unknown')
                }
            
            return stats
            
        except Exception as e:
            logger.error("Failed to get cache stats", error=str(e))
            return {'error': str(e)}
    
    def clear_all_cache(self) -> bool:
        """
        Clear all cached responses (use with caution).
        
        Returns:
            True if cache cleared successfully, False otherwise
        """
        try:
            if self.cache:
                self.cache.clear()
                logger.warning("All cache cleared")
                return True
            return False
            
        except Exception as e:
            logger.error("Failed to clear all cache", error=str(e))
            return False


# Global response cache instance
response_cache = ResponseCache()


def init_response_cache(app: Flask, redis_client: Optional[RedisClient] = None) -> ResponseCache:
    """
    Initialize response cache for Flask application.
    
    Args:
        app: Flask application instance
        redis_client: Optional Redis client instance
        
    Returns:
        Configured ResponseCache instance
    """
    global response_cache
    response_cache = ResponseCache(app, redis_client)
    return response_cache


def get_response_cache() -> ResponseCache:
    """
    Get the global response cache instance.
    
    Returns:
        Global ResponseCache instance
        
    Raises:
        RuntimeError: If response cache not initialized
    """
    if response_cache.cache is None:
        raise RuntimeError("Response cache not initialized. Call init_response_cache() first.")
    return response_cache


# Convenience decorators for common caching patterns

def cache_for(timeout: int = 300, key_func: Optional[Callable] = None):
    """
    Simple response caching decorator with specified timeout.
    
    Args:
        timeout: Cache timeout in seconds
        key_func: Optional custom key generation function
        
    Returns:
        Decorator function
    """
    return get_response_cache().cache_response(timeout=timeout, key_func=key_func)


def cache_unless(condition: Callable):
    """
    Cache response unless condition is true.
    
    Args:
        condition: Function returning boolean to skip caching
        
    Returns:
        Decorator function
    """
    return get_response_cache().cache_response(unless=condition)


def cache_with_user_context(timeout: int = 300):
    """
    Cache response with user context for personalized caching.
    
    Args:
        timeout: Cache timeout in seconds
        
    Returns:
        Decorator function
    """
    def user_key_func():
        user_context = getattr(g, 'user_context', None)
        return get_response_cache().generate_cache_key(
            endpoint=request.endpoint,
            method=request.method,
            query_params=dict(request.args),
            user_context=user_context
        )
    
    return get_response_cache().cache_response(timeout=timeout, key_func=user_key_func)


def invalidate_endpoint_cache(endpoint: str):
    """
    Convenience function to invalidate cache for specific endpoint.
    
    Args:
        endpoint: Endpoint name to invalidate
        
    Returns:
        True if invalidation successful
    """
    return get_response_cache().invalidate_cache(endpoint=endpoint)


def invalidate_user_cache(user_id: str):
    """
    Convenience function to invalidate user-specific cache.
    
    Args:
        user_id: User ID to invalidate cache for
        
    Returns:
        True if invalidation successful
    """
    return get_response_cache().invalidate_cache(user_id=user_id)