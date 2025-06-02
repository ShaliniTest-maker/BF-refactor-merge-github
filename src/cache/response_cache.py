"""
Flask-Caching 2.1+ Response Cache Implementation

Comprehensive response caching solution providing Flask-Caching integration, HTTP cache headers,
TTL management, and cache invalidation strategies for performance optimization. Implements
equivalent functionality to Node.js middleware patterns with enterprise-grade cache management,
distributed cache coordination, and performance monitoring.

This module implements response caching requirements specified in Section 5.2.7 caching layer
and Section 3.4.2 caching solutions, providing performance optimization maintaining ≤10%
variance from Node.js baseline per Section 0.1.1 primary objective.

Key Features:
- Flask-Caching 2.1+ integration with Redis backend for distributed response caching
- Intelligent cache key generation based on request parameters, headers, and user context
- HTTP cache headers (ETag, Last-Modified, Cache-Control) for client-side caching optimization
- Comprehensive TTL management with adaptive expiration strategies per Section 5.2.7
- Cache invalidation patterns including immediate, pattern-based, and tag-based invalidation
- Memory management and performance optimization equivalent to Node.js implementation
- Integration with enterprise monitoring and circuit breaker patterns per Section 6.1.3
- Request/response cache patterns with Flask decorator support

Architecture Integration:
- Seamless integration with src/cache/client.py RedisClient infrastructure
- Cache strategy integration via src/cache/strategies.py for TTL and invalidation management
- Enterprise error handling through src/cache/exceptions.py comprehensive exception classes
- Flask Blueprint integration for centralized response caching across application modules
- Performance monitoring via structured logging and metrics collection per Section 5.4.1

Performance Requirements:
- Response cache hit latency: ≤2ms for cached responses
- Cache miss processing overhead: ≤5ms additional latency for cache operations
- Memory efficiency: ≤15% overhead for cache metadata and coordination structures
- Distributed cache coordination: ≤10ms for multi-instance cache invalidation
- HTTP header processing: ≤1ms for cache header generation and validation

References:
- Section 5.2.7: Caching layer responsibilities and response caching for performance optimization
- Section 3.4.2: Flask-Caching 2.1+ integration and response caching patterns
- Section 6.1.3: Circuit breaker patterns and distributed cache coordination for resilience
- Section 5.4.1: Monitoring and observability for cache performance tracking and optimization
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
"""

import hashlib
import json
import time
import traceback
from datetime import datetime, timedelta, timezone
from functools import wraps, lru_cache
from typing import (
    Any, Dict, List, Optional, Union, Callable, Tuple, 
    Set, Pattern, TypeVar, Generic
)
from urllib.parse import urlencode
import gzip
import pickle
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from collections import defaultdict, deque

# Flask and Flask-Caching imports
from flask import Flask, request, response, jsonify, g, current_app
from flask_caching import Cache
from werkzeug.http import http_date, parse_date, quote_etag, unquote_etag
from werkzeug.wrappers import Response

# Redis and caching infrastructure
import structlog

# Internal cache infrastructure imports
from .client import RedisClient, get_redis_client
from .strategies import (
    CacheInvalidationStrategy, TTLManagementStrategy, CacheKeyPatternManager,
    CacheInvalidationPattern, TTLPolicy, CacheKeyPattern,
    CacheStrategyMetrics
)
from .exceptions import (
    CacheError, CacheOperationTimeoutError, CacheInvalidationError,
    CacheKeyError, CacheSerializationError
)

# Configure structured logging for enterprise integration
logger = structlog.get_logger(__name__)

# Type variables for generic cache operations
T = TypeVar('T')
F = TypeVar('F', bound=Callable)


class CachePolicy(Enum):
    """
    Cache policy types for different response caching strategies.
    
    Defines caching behavior for different types of responses including
    static content, dynamic content, API responses, and user-specific data.
    """
    NO_CACHE = "no-cache"                   # No caching for sensitive data
    PRIVATE = "private"                     # User-specific content caching
    PUBLIC = "public"                       # Public content caching
    STATIC = "static"                       # Static resource caching
    API_RESPONSE = "api_response"           # API response caching
    DYNAMIC = "dynamic"                     # Dynamic content with TTL
    CONDITIONAL = "conditional"             # ETag/Last-Modified based caching


class CompressionType(Enum):
    """Compression types for cached response data."""
    NONE = "none"
    GZIP = "gzip"
    DEFLATE = "deflate"
    AUTO = "auto"                          # Automatic compression based on content type


@dataclass
class CacheConfiguration:
    """
    Response cache configuration with policy-specific parameters.
    
    Provides comprehensive cache configuration supporting multiple cache policies,
    TTL strategies, and performance optimization settings per Section 5.2.7.
    """
    policy: CachePolicy = CachePolicy.DYNAMIC
    ttl_seconds: int = 300                  # Default 5 minutes TTL
    max_content_length: int = 1024 * 1024   # 1MB max cached response size
    compression: CompressionType = CompressionType.AUTO
    vary_headers: List[str] = field(default_factory=lambda: ['Accept', 'Accept-Encoding'])
    cache_private_responses: bool = False   # Cache responses with user context
    cache_query_params: bool = True         # Include query parameters in cache key
    cache_headers: List[str] = field(default_factory=list)  # Headers to include in cache key
    exclude_headers: List[str] = field(default_factory=lambda: ['Authorization', 'Cookie'])
    exclude_status_codes: Set[int] = field(default_factory=lambda: {401, 403, 404, 500, 502, 503})
    grace_period_seconds: int = 60          # Grace period for stale cache serving
    background_refresh: bool = True         # Background cache refresh for popular content
    distributed_invalidation: bool = True   # Enable distributed cache invalidation
    
    def __post_init__(self):
        """Validate cache configuration parameters."""
        if self.ttl_seconds <= 0:
            raise ValueError("TTL seconds must be positive")
        
        if self.max_content_length <= 0:
            raise ValueError("Max content length must be positive")
        
        if self.grace_period_seconds < 0:
            raise ValueError("Grace period seconds must be non-negative")


@dataclass
class CachedResponse:
    """
    Cached response data structure with metadata and validation support.
    
    Stores response content along with caching metadata including timestamps,
    ETags, headers, and validation information for HTTP cache compliance.
    """
    content: bytes                          # Response content (potentially compressed)
    status_code: int                        # HTTP status code
    headers: Dict[str, str]                 # Response headers
    content_type: str                       # Content-Type header
    etag: Optional[str] = None             # ETag for conditional requests
    last_modified: Optional[datetime] = None # Last-Modified timestamp
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None   # Cache expiration timestamp
    hit_count: int = 0                     # Number of cache hits
    compression: CompressionType = CompressionType.NONE
    original_size: int = 0                 # Original uncompressed size
    compressed_size: int = 0               # Compressed size
    cache_tags: Set[str] = field(default_factory=set)  # Tags for invalidation
    vary_data: Dict[str, str] = field(default_factory=dict)  # Vary header data
    
    def is_expired(self, grace_period: int = 0) -> bool:
        """Check if cached response is expired with optional grace period."""
        if self.expires_at is None:
            return False
        
        current_time = datetime.now(timezone.utc)
        grace_expiration = self.expires_at + timedelta(seconds=grace_period)
        
        return current_time > grace_expiration
    
    def is_stale(self) -> bool:
        """Check if cached response is stale (expired but within grace period)."""
        if self.expires_at is None:
            return False
        
        current_time = datetime.now(timezone.utc)
        return current_time > self.expires_at
    
    def get_age(self) -> int:
        """Get cache age in seconds."""
        current_time = datetime.now(timezone.utc)
        age_delta = current_time - self.created_at
        return int(age_delta.total_seconds())
    
    def matches_etag(self, etag: Optional[str]) -> bool:
        """Check if provided ETag matches cached response ETag."""
        if not etag or not self.etag:
            return False
        
        # Handle weak/strong ETag comparison
        cached_etag = unquote_etag(self.etag)[0] if self.etag else None
        request_etag = unquote_etag(etag)[0] if etag else None
        
        return cached_etag == request_etag
    
    def matches_last_modified(self, if_modified_since: Optional[str]) -> bool:
        """Check if response is modified since provided timestamp."""
        if not if_modified_since or not self.last_modified:
            return False
        
        try:
            client_timestamp = parse_date(if_modified_since)
            if client_timestamp:
                # Convert to UTC for comparison
                if client_timestamp.tzinfo is None:
                    client_timestamp = client_timestamp.replace(tzinfo=timezone.utc)
                
                return self.last_modified <= client_timestamp
        except (ValueError, TypeError):
            pass
        
        return False
    
    def increment_hit_count(self) -> None:
        """Increment cache hit counter for analytics."""
        self.hit_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cached response to dictionary for serialization."""
        return {
            'content': self.content.decode('utf-8') if isinstance(self.content, bytes) else self.content,
            'status_code': self.status_code,
            'headers': self.headers,
            'content_type': self.content_type,
            'etag': self.etag,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'hit_count': self.hit_count,
            'compression': self.compression.value,
            'original_size': self.original_size,
            'compressed_size': self.compressed_size,
            'cache_tags': list(self.cache_tags),
            'vary_data': self.vary_data
        }


class ResponseCacheMetrics:
    """
    Metrics collection for response cache performance monitoring.
    
    Tracks cache effectiveness, performance characteristics, and provides
    insights for optimization and Node.js baseline comparison per Section 5.4.1.
    """
    
    def __init__(self):
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_stores = 0
        self.cache_invalidations = 0
        self.hit_latencies = deque(maxlen=1000)
        self.miss_latencies = deque(maxlen=1000)
        self.store_latencies = deque(maxlen=1000)
        self.compression_savings = deque(maxlen=1000)
        self.cache_sizes = defaultdict(int)
        self.policy_usage = defaultdict(int)
        self.status_code_distribution = defaultdict(int)
        self.last_reset = time.time()
        self._lock = RLock()
    
    def record_hit(self, latency_ms: float, content_size: int, policy: CachePolicy):
        """Record cache hit metrics."""
        with self._lock:
            self.cache_hits += 1
            self.hit_latencies.append(latency_ms)
            self.cache_sizes['hit_content'] += content_size
            self.policy_usage[policy.value] += 1
    
    def record_miss(self, latency_ms: float, policy: CachePolicy):
        """Record cache miss metrics."""
        with self._lock:
            self.cache_misses += 1
            self.miss_latencies.append(latency_ms)
            self.policy_usage[policy.value] += 1
    
    def record_store(self, latency_ms: float, original_size: int, 
                    compressed_size: int, policy: CachePolicy):
        """Record cache store metrics."""
        with self._lock:
            self.cache_stores += 1
            self.store_latencies.append(latency_ms)
            
            if original_size > 0 and compressed_size < original_size:
                compression_ratio = (original_size - compressed_size) / original_size
                self.compression_savings.append(compression_ratio)
            
            self.cache_sizes['stored_content'] += compressed_size
            self.policy_usage[policy.value] += 1
    
    def record_invalidation(self, keys_count: int = 1):
        """Record cache invalidation metrics."""
        with self._lock:
            self.cache_invalidations += keys_count
    
    def record_status_code(self, status_code: int):
        """Record HTTP status code distribution."""
        with self._lock:
            self.status_code_distribution[status_code] += 1
    
    def get_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = self.cache_hits + self.cache_misses
        if total_requests == 0:
            return 0.0
        return self.cache_hits / total_requests
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        with self._lock:
            current_time = time.time()
            uptime_hours = (current_time - self.last_reset) / 3600
            
            summary = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'uptime_hours': uptime_hours,
                'cache_performance': {
                    'hit_rate': self.get_hit_rate(),
                    'total_hits': self.cache_hits,
                    'total_misses': self.cache_misses,
                    'total_stores': self.cache_stores,
                    'total_invalidations': self.cache_invalidations
                },
                'latency_metrics': {},
                'compression_metrics': {},
                'cache_usage': dict(self.policy_usage),
                'status_distribution': dict(self.status_code_distribution),
                'memory_usage': dict(self.cache_sizes)
            }
            
            # Calculate latency statistics
            if self.hit_latencies:
                hit_latencies = list(self.hit_latencies)
                summary['latency_metrics']['hit_avg_ms'] = sum(hit_latencies) / len(hit_latencies)
                summary['latency_metrics']['hit_max_ms'] = max(hit_latencies)
                summary['latency_metrics']['hit_min_ms'] = min(hit_latencies)
            
            if self.miss_latencies:
                miss_latencies = list(self.miss_latencies)
                summary['latency_metrics']['miss_avg_ms'] = sum(miss_latencies) / len(miss_latencies)
                summary['latency_metrics']['miss_max_ms'] = max(miss_latencies)
                summary['latency_metrics']['miss_min_ms'] = min(miss_latencies)
            
            if self.store_latencies:
                store_latencies = list(self.store_latencies)
                summary['latency_metrics']['store_avg_ms'] = sum(store_latencies) / len(store_latencies)
                summary['latency_metrics']['store_max_ms'] = max(store_latencies)
                summary['latency_metrics']['store_min_ms'] = min(store_latencies)
            
            # Calculate compression statistics
            if self.compression_savings:
                savings = list(self.compression_savings)
                summary['compression_metrics']['avg_compression_ratio'] = sum(savings) / len(savings)
                summary['compression_metrics']['max_compression_ratio'] = max(savings)
                summary['compression_metrics']['min_compression_ratio'] = min(savings)
                summary['compression_metrics']['compression_operations'] = len(savings)
            
            return summary


class FlaskResponseCache:
    """
    Comprehensive Flask response cache implementation with Flask-Caching 2.1+ integration.
    
    Provides enterprise-grade response caching with HTTP cache headers, TTL management,
    cache invalidation strategies, and performance optimization equivalent to Node.js
    middleware patterns per Section 5.2.7 and Section 3.4.2 requirements.
    """
    
    def __init__(
        self,
        app: Optional[Flask] = None,
        config: Optional[CacheConfiguration] = None,
        redis_client: Optional[RedisClient] = None
    ):
        """
        Initialize Flask response cache with configuration and dependencies.
        
        Args:
            app: Flask application instance for initialization
            config: Cache configuration with policy and performance settings
            redis_client: Redis client for cache backend operations
        """
        self.app = app
        self.config = config or CacheConfiguration()
        self.redis_client = redis_client
        
        # Flask-Caching instance for integration
        self.cache: Optional[Cache] = None
        
        # Cache strategy components
        self.invalidation_strategy: Optional[CacheInvalidationStrategy] = None
        self.ttl_strategy: Optional[TTLManagementStrategy] = None
        self.key_manager: Optional[CacheKeyPatternManager] = None
        
        # Performance metrics and monitoring
        self.metrics = ResponseCacheMetrics()
        
        # Cache key patterns for different response types
        self.cache_patterns = {}
        
        # Thread safety for cache operations
        self._lock = RLock()
        
        # Response compression settings
        self._compressible_types = {
            'text/html', 'text/css', 'text/javascript', 'text/plain',
            'application/json', 'application/javascript', 'application/xml',
            'image/svg+xml'
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize Flask application with response caching capabilities.
        
        Args:
            app: Flask application instance to configure
        """
        self.app = app
        
        # Initialize Redis client if not provided
        if self.redis_client is None:
            try:
                self.redis_client = get_redis_client()
            except CacheError:
                logger.warning("Redis client not available, response caching disabled")
                return
        
        # Configure Flask-Caching with Redis backend per Section 3.4.2
        cache_config = {
            'CACHE_TYPE': 'RedisCache',
            'CACHE_REDIS_HOST': self.redis_client.host,
            'CACHE_REDIS_PORT': self.redis_client.port,
            'CACHE_REDIS_DB': self.redis_client.db,
            'CACHE_REDIS_PASSWORD': self.redis_client.password,
            'CACHE_DEFAULT_TIMEOUT': self.config.ttl_seconds,
            'CACHE_KEY_PREFIX': 'response_cache:',
            'CACHE_OPTIONS': {
                'connection_pool_kwargs': {
                    'max_connections': self.redis_client.max_connections,
                    'retry_on_timeout': True,
                    'socket_timeout': self.redis_client.socket_timeout,
                    'socket_connect_timeout': self.redis_client.socket_connect_timeout
                }
            }
        }
        
        # Initialize Flask-Caching
        self.cache = Cache()
        self.cache.init_app(app, config=cache_config)
        
        # Initialize cache strategy components
        self.invalidation_strategy = CacheInvalidationStrategy(
            redis_client=self.redis_client
        )
        self.ttl_strategy = TTLManagementStrategy(
            redis_client=self.redis_client
        )
        self.key_manager = CacheKeyPatternManager(
            redis_client=self.redis_client
        )
        
        # Register cache key patterns for response caching
        self._register_response_cache_patterns()
        
        # Configure Flask application context
        app.config['RESPONSE_CACHE'] = self
        
        # Register before/after request handlers for cache operations
        self._register_request_handlers(app)
        
        logger.info(
            "Flask response cache initialized",
            redis_host=self.redis_client.host,
            redis_port=self.redis_client.port,
            default_ttl=self.config.ttl_seconds,
            cache_policy=self.config.policy.value,
            compression=self.config.compression.value
        )
    
    def _register_response_cache_patterns(self) -> None:
        """Register cache key patterns for different response types."""
        # API response pattern
        self.key_manager.register_pattern('api_response', CacheKeyPattern(
            namespace='response',
            pattern='api:{method}:{path}:{params_hash}:{user_hash}',
            ttl_policy=TTLPolicy.ADAPTIVE,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=1,
            tags={'api', 'response', 'user_specific'}
        ))
        
        # Public content pattern
        self.key_manager.register_pattern('public_content', CacheKeyPattern(
            namespace='response',
            pattern='public:{method}:{path}:{params_hash}',
            ttl_policy=TTLPolicy.FIXED,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=2,
            tags={'public', 'content'}
        ))
        
        # Static resource pattern
        self.key_manager.register_pattern('static_resource', CacheKeyPattern(
            namespace='response',
            pattern='static:{path}:{etag}',
            ttl_policy=TTLPolicy.FIXED,
            invalidation_pattern=CacheInvalidationPattern.LAZY,
            priority=3,
            tags={'static', 'resource'}
        ))
        
        # User-specific content pattern
        self.key_manager.register_pattern('user_content', CacheKeyPattern(
            namespace='response',
            pattern='user:{user_id}:{method}:{path}:{params_hash}',
            ttl_policy=TTLPolicy.SLIDING,
            invalidation_pattern=CacheInvalidationPattern.EVENT_DRIVEN,
            priority=1,
            tags={'user', 'private', 'content'}
        ))
    
    def _register_request_handlers(self, app: Flask) -> None:
        """Register Flask request handlers for cache operations."""
        @app.before_request
        def before_request_cache_check():
            """Check cache before processing request."""
            # Store request start time for latency tracking
            g.cache_start_time = time.perf_counter()
            
            # Skip caching for excluded methods
            if request.method not in ['GET', 'HEAD']:
                return None
            
            # Skip caching for excluded paths
            if self._should_skip_caching():
                return None
            
            # Check for cached response
            cached_response = self._get_cached_response()
            if cached_response:
                return self._create_flask_response(cached_response)
            
            return None
        
        @app.after_request
        def after_request_cache_store(response: Response) -> Response:
            """Store response in cache after processing."""
            # Skip if no cache start time (before_request was skipped)
            if not hasattr(g, 'cache_start_time'):
                return response
            
            # Calculate request processing time
            processing_time_ms = (time.perf_counter() - g.cache_start_time) * 1000
            
            # Store cacheable responses
            if self._is_response_cacheable(response):
                self._store_response_in_cache(response, processing_time_ms)
            
            # Add cache-related headers
            self._add_cache_headers(response)
            
            # Record metrics
            self.metrics.record_status_code(response.status_code)
            
            return response
    
    def cached(
        self,
        timeout: Optional[int] = None,
        key_prefix: str = 'cached_view',
        unless: Optional[Callable] = None,
        policy: Optional[CachePolicy] = None,
        cache_tags: Optional[List[str]] = None,
        vary_headers: Optional[List[str]] = None
    ) -> Callable[[F], F]:
        """
        Decorator for caching Flask view functions with comprehensive configuration.
        
        Args:
            timeout: Cache timeout in seconds (None for default)
            key_prefix: Prefix for cache key generation
            unless: Function to determine if caching should be skipped
            policy: Cache policy for response handling
            cache_tags: Tags for cache invalidation
            vary_headers: Headers that affect cache variance
            
        Returns:
            Decorated function with caching capabilities
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Check if caching should be skipped
                if unless and unless():
                    return func(*args, **kwargs)
                
                # Generate cache key
                cache_key = self._generate_function_cache_key(
                    func, key_prefix, args, kwargs, vary_headers
                )
                
                start_time = time.perf_counter()
                
                # Try to get cached response
                try:
                    cached_result = self.cache.get(cache_key)
                    if cached_result is not None:
                        # Cache hit
                        latency_ms = (time.perf_counter() - start_time) * 1000
                        self.metrics.record_hit(
                            latency_ms, 
                            len(str(cached_result)), 
                            policy or self.config.policy
                        )
                        
                        logger.debug(
                            "Function cache hit",
                            function=func.__name__,
                            cache_key=cache_key,
                            latency_ms=latency_ms
                        )
                        
                        return cached_result
                
                except Exception as e:
                    logger.warning(
                        "Function cache get failed",
                        function=func.__name__,
                        cache_key=cache_key,
                        error=str(e)
                    )
                
                # Cache miss - execute function
                try:
                    result = func(*args, **kwargs)
                    
                    # Calculate TTL
                    cache_timeout = timeout or self.config.ttl_seconds
                    if self.ttl_strategy:
                        ttl_policy = TTLPolicy.FIXED if policy == CachePolicy.STATIC else TTLPolicy.ADAPTIVE
                        cache_timeout = self.ttl_strategy.get_recommended_ttl(
                            cache_key, 
                            ttl_policy
                        )
                    
                    # Store in cache
                    try:
                        self.cache.set(cache_key, result, timeout=cache_timeout)
                        
                        # Store cache tags if provided
                        if cache_tags and self.invalidation_strategy:
                            for tag in cache_tags:
                                self.invalidation_strategy.register_key_tags(cache_key, tag)
                        
                        store_latency_ms = (time.perf_counter() - start_time) * 1000
                        self.metrics.record_store(
                            store_latency_ms,
                            len(str(result)),
                            len(str(result)),  # No compression for function results
                            policy or self.config.policy
                        )
                        
                        logger.debug(
                            "Function result cached",
                            function=func.__name__,
                            cache_key=cache_key,
                            ttl=cache_timeout,
                            store_latency_ms=store_latency_ms
                        )
                        
                    except Exception as e:
                        logger.warning(
                            "Function cache store failed",
                            function=func.__name__,
                            cache_key=cache_key,
                            error=str(e)
                        )
                    
                    # Record miss metrics
                    miss_latency_ms = (time.perf_counter() - start_time) * 1000
                    self.metrics.record_miss(miss_latency_ms, policy or self.config.policy)
                    
                    return result
                    
                except Exception as e:
                    logger.error(
                        "Function execution failed",
                        function=func.__name__,
                        error=str(e),
                        traceback=traceback.format_exc()
                    )
                    raise
            
            return wrapper
        return decorator
    
    def _should_skip_caching(self) -> bool:
        """Determine if current request should skip caching."""
        # Skip caching for excluded status codes or sensitive endpoints
        if hasattr(g, 'skip_cache') and g.skip_cache:
            return True
        
        # Skip caching if Authorization header present and private responses disabled
        if not self.config.cache_private_responses and request.headers.get('Authorization'):
            return True
        
        # Skip caching for certain paths (admin, auth, etc.)
        excluded_paths = ['/admin', '/auth', '/login', '/logout']
        for path in excluded_paths:
            if request.path.startswith(path):
                return True
        
        return False
    
    def _get_cached_response(self) -> Optional[CachedResponse]:
        """Get cached response for current request."""
        try:
            cache_key = self._generate_request_cache_key()
            
            start_time = time.perf_counter()
            cached_data = self.cache.get(cache_key)
            
            if cached_data is None:
                return None
            
            # Deserialize cached response
            if isinstance(cached_data, dict):
                cached_response = self._deserialize_cached_response(cached_data)
            else:
                # Legacy format handling
                return None
            
            # Check if response is expired
            if cached_response.is_expired(self.config.grace_period_seconds):
                # Remove expired cache entry
                self.cache.delete(cache_key)
                return None
            
            # Check conditional request headers
            if self._handle_conditional_request(cached_response):
                # Return 304 Not Modified response
                cached_response.status_code = 304
                cached_response.content = b''
            
            # Update hit count and metrics
            cached_response.increment_hit_count()
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.record_hit(
                latency_ms,
                len(cached_response.content),
                self.config.policy
            )
            
            logger.debug(
                "Response cache hit",
                cache_key=cache_key,
                status_code=cached_response.status_code,
                content_size=len(cached_response.content),
                age=cached_response.get_age(),
                hit_count=cached_response.hit_count,
                latency_ms=latency_ms
            )
            
            return cached_response
            
        except Exception as e:
            logger.warning(
                "Failed to get cached response",
                error=str(e),
                path=request.path,
                method=request.method
            )
            return None
    
    def _store_response_in_cache(self, response: Response, processing_time_ms: float) -> None:
        """Store Flask response in cache."""
        try:
            cache_key = self._generate_request_cache_key()
            
            # Create cached response object
            cached_response = self._create_cached_response(response)
            
            # Calculate TTL using strategy
            ttl_seconds = self.config.ttl_seconds
            if self.ttl_strategy:
                ttl_policy = self._get_ttl_policy_for_response(response)
                ttl_seconds = self.ttl_strategy.execute(
                    cache_key,
                    ttl_policy,
                    value_metadata={
                        'content_type': cached_response.content_type,
                        'status_code': cached_response.status_code,
                        'original_size': cached_response.original_size,
                        'processing_time_ms': processing_time_ms
                    }
                )
            
            # Set expiration time
            cached_response.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            
            start_time = time.perf_counter()
            
            # Serialize and store in cache
            serialized_data = cached_response.to_dict()
            self.cache.set(cache_key, serialized_data, timeout=ttl_seconds)
            
            store_latency_ms = (time.perf_counter() - start_time) * 1000
            
            # Record metrics
            self.metrics.record_store(
                store_latency_ms,
                cached_response.original_size,
                cached_response.compressed_size,
                self.config.policy
            )
            
            logger.debug(
                "Response cached successfully",
                cache_key=cache_key,
                ttl_seconds=ttl_seconds,
                original_size=cached_response.original_size,
                compressed_size=cached_response.compressed_size,
                compression=cached_response.compression.value,
                store_latency_ms=store_latency_ms
            )
            
        except Exception as e:
            logger.warning(
                "Failed to store response in cache",
                error=str(e),
                path=request.path,
                method=request.method,
                status_code=response.status_code
            )
    
    def _generate_request_cache_key(self) -> str:
        """Generate cache key for current request."""
        try:
            # Determine cache pattern based on request characteristics
            if self._is_user_specific_request():
                pattern_name = 'user_content'
                user_id = self._get_user_id_from_request()
                params = {
                    'user_id': user_id,
                    'method': request.method,
                    'path': request.path,
                    'params_hash': self._generate_params_hash()
                }
            elif request.path.startswith('/api/'):
                pattern_name = 'api_response'
                params = {
                    'method': request.method,
                    'path': request.path,
                    'params_hash': self._generate_params_hash(),
                    'user_hash': self._generate_user_hash()
                }
            elif self._is_static_resource():
                pattern_name = 'static_resource'
                params = {
                    'path': request.path,
                    'etag': self._generate_etag_for_request()
                }
            else:
                pattern_name = 'public_content'
                params = {
                    'method': request.method,
                    'path': request.path,
                    'params_hash': self._generate_params_hash()
                }
            
            return self.key_manager.execute(pattern_name, **params)
            
        except Exception as e:
            logger.warning(
                "Failed to generate cache key",
                error=str(e),
                path=request.path,
                method=request.method
            )
            # Fallback to simple key generation
            return self._generate_simple_cache_key()
    
    def _generate_function_cache_key(
        self, 
        func: Callable, 
        prefix: str, 
        args: tuple, 
        kwargs: dict, 
        vary_headers: Optional[List[str]]
    ) -> str:
        """Generate cache key for decorated function."""
        key_parts = [
            prefix,
            func.__module__,
            func.__name__,
            self._hash_args(args),
            self._hash_kwargs(kwargs)
        ]
        
        # Include vary headers if specified
        if vary_headers:
            vary_data = {}
            for header in vary_headers:
                vary_data[header] = request.headers.get(header, '')
            key_parts.append(self._hash_dict(vary_data))
        
        return ':'.join(key_parts)
    
    def _generate_params_hash(self) -> str:
        """Generate hash for request parameters."""
        if not self.config.cache_query_params:
            return 'no_params'
        
        # Combine query parameters and relevant headers
        params_data = {}
        
        # Add query parameters
        if request.args:
            params_data['query'] = dict(request.args)
        
        # Add specified headers to cache key
        if self.config.cache_headers:
            headers_data = {}
            for header in self.config.cache_headers:
                value = request.headers.get(header)
                if value:
                    headers_data[header] = value
            if headers_data:
                params_data['headers'] = headers_data
        
        # Add form data for POST requests if cacheable
        if request.method == 'POST' and request.is_json:
            try:
                params_data['json'] = request.get_json()
            except Exception:
                pass
        
        return self._hash_dict(params_data)
    
    def _generate_user_hash(self) -> str:
        """Generate user hash for cache key."""
        if not self.config.cache_private_responses:
            return 'public'
        
        user_id = self._get_user_id_from_request()
        if user_id:
            return hashlib.sha256(str(user_id).encode()).hexdigest()[:16]
        
        # Use session ID or IP as fallback
        session_id = request.headers.get('X-Session-ID') or request.remote_addr
        return hashlib.sha256(str(session_id).encode()).hexdigest()[:16]
    
    def _get_user_id_from_request(self) -> Optional[str]:
        """Extract user ID from request context."""
        # Try Flask-Login current_user
        try:
            from flask_login import current_user
            if hasattr(current_user, 'id') and current_user.is_authenticated:
                return str(current_user.id)
        except ImportError:
            pass
        
        # Try JWT token claims
        if hasattr(g, 'user') and g.user:
            return str(g.user.get('id') or g.user.get('sub'))
        
        # Try custom user context
        if hasattr(g, 'user_id'):
            return str(g.user_id)
        
        return None
    
    def _is_user_specific_request(self) -> bool:
        """Check if request is user-specific."""
        return (
            self.config.cache_private_responses and 
            self._get_user_id_from_request() is not None
        )
    
    def _is_static_resource(self) -> bool:
        """Check if request is for static resource."""
        static_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'}
        return any(request.path.endswith(ext) for ext in static_extensions)
    
    def _generate_etag_for_request(self) -> str:
        """Generate ETag for current request."""
        etag_data = {
            'path': request.path,
            'query': dict(request.args) if request.args else {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        return hashlib.sha256(json.dumps(etag_data, sort_keys=True).encode()).hexdigest()[:16]
    
    def _generate_simple_cache_key(self) -> str:
        """Generate simple cache key as fallback."""
        key_data = {
            'method': request.method,
            'path': request.path,
            'query': dict(request.args) if request.args else {}
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _hash_args(self, args: tuple) -> str:
        """Generate hash for function arguments."""
        if not args:
            return 'no_args'
        
        try:
            args_string = json.dumps(args, sort_keys=True, default=str)
            return hashlib.sha256(args_string.encode()).hexdigest()[:16]
        except TypeError:
            # Fallback for non-serializable arguments
            return hashlib.sha256(str(args).encode()).hexdigest()[:16]
    
    def _hash_kwargs(self, kwargs: dict) -> str:
        """Generate hash for function keyword arguments."""
        if not kwargs:
            return 'no_kwargs'
        
        return self._hash_dict(kwargs)
    
    def _hash_dict(self, data: dict) -> str:
        """Generate hash for dictionary data."""
        if not data:
            return 'empty'
        
        try:
            data_string = json.dumps(data, sort_keys=True, default=str)
            return hashlib.sha256(data_string.encode()).hexdigest()[:16]
        except TypeError:
            # Fallback for non-serializable data
            return hashlib.sha256(str(data).encode()).hexdigest()[:16]
    
    def _is_response_cacheable(self, response: Response) -> bool:
        """Determine if response is cacheable."""
        # Check status code
        if response.status_code in self.config.exclude_status_codes:
            return False
        
        # Check method
        if request.method not in ['GET', 'HEAD']:
            return False
        
        # Check content length
        content_length = len(response.get_data())
        if content_length > self.config.max_content_length:
            return False
        
        # Check cache control headers
        cache_control = response.headers.get('Cache-Control', '')
        if 'no-cache' in cache_control or 'no-store' in cache_control:
            return False
        
        # Check if private response and private caching disabled
        if 'private' in cache_control and not self.config.cache_private_responses:
            return False
        
        return True
    
    def _create_cached_response(self, response: Response) -> CachedResponse:
        """Create cached response object from Flask response."""
        content = response.get_data()
        original_size = len(content)
        
        # Apply compression if configured
        compressed_content, compression_type = self._compress_content(
            content, 
            response.content_type
        )
        compressed_size = len(compressed_content)
        
        # Generate ETag
        etag = self._generate_etag(compressed_content)
        
        # Create cached response
        cached_response = CachedResponse(
            content=compressed_content,
            status_code=response.status_code,
            headers=dict(response.headers),
            content_type=response.content_type or 'text/html',
            etag=etag,
            last_modified=datetime.now(timezone.utc),
            compression=compression_type,
            original_size=original_size,
            compressed_size=compressed_size,
            cache_tags=set(),
            vary_data=self._extract_vary_data()
        )
        
        return cached_response
    
    def _compress_content(self, content: bytes, content_type: str) -> Tuple[bytes, CompressionType]:
        """Compress response content if appropriate."""
        if self.config.compression == CompressionType.NONE:
            return content, CompressionType.NONE
        
        # Check if content type is compressible
        if not self._is_compressible_type(content_type):
            return content, CompressionType.NONE
        
        # Skip compression for small content
        if len(content) < 1024:  # Less than 1KB
            return content, CompressionType.NONE
        
        try:
            if self.config.compression in [CompressionType.GZIP, CompressionType.AUTO]:
                compressed = gzip.compress(content)
                
                # Only use compression if it provides significant savings
                compression_ratio = len(compressed) / len(content)
                if compression_ratio < 0.9:  # At least 10% savings
                    return compressed, CompressionType.GZIP
        
        except Exception as e:
            logger.warning(
                "Content compression failed",
                error=str(e),
                content_type=content_type,
                content_size=len(content)
            )
        
        return content, CompressionType.NONE
    
    def _is_compressible_type(self, content_type: str) -> bool:
        """Check if content type is compressible."""
        if not content_type:
            return False
        
        # Extract main content type
        main_type = content_type.split(';')[0].strip().lower()
        return main_type in self._compressible_types
    
    def _generate_etag(self, content: bytes) -> str:
        """Generate ETag for response content."""
        content_hash = hashlib.sha256(content).hexdigest()[:16]
        return quote_etag(content_hash)
    
    def _extract_vary_data(self) -> Dict[str, str]:
        """Extract vary header data from current request."""
        vary_data = {}
        
        for header in self.config.vary_headers:
            value = request.headers.get(header)
            if value:
                vary_data[header] = value
        
        return vary_data
    
    def _handle_conditional_request(self, cached_response: CachedResponse) -> bool:
        """Handle conditional request headers (If-None-Match, If-Modified-Since)."""
        # Check If-None-Match (ETag)
        if_none_match = request.headers.get('If-None-Match')
        if if_none_match and cached_response.matches_etag(if_none_match):
            return True
        
        # Check If-Modified-Since
        if_modified_since = request.headers.get('If-Modified-Since')
        if if_modified_since and cached_response.matches_last_modified(if_modified_since):
            return True
        
        return False
    
    def _create_flask_response(self, cached_response: CachedResponse) -> Response:
        """Create Flask Response from cached response."""
        # Decompress content if needed
        content = self._decompress_content(
            cached_response.content, 
            cached_response.compression
        )
        
        # Create Flask response
        response = Response(
            response=content,
            status=cached_response.status_code,
            headers=cached_response.headers,
            content_type=cached_response.content_type
        )
        
        # Add cache-specific headers
        if cached_response.etag:
            response.headers['ETag'] = cached_response.etag
        
        if cached_response.last_modified:
            response.headers['Last-Modified'] = http_date(cached_response.last_modified)
        
        # Add age header
        response.headers['Age'] = str(cached_response.get_age())
        
        # Add cache headers based on policy
        self._add_policy_headers(response, cached_response)
        
        return response
    
    def _decompress_content(self, content: bytes, compression: CompressionType) -> bytes:
        """Decompress cached content."""
        if compression == CompressionType.GZIP:
            try:
                return gzip.decompress(content)
            except Exception as e:
                logger.warning(
                    "Content decompression failed",
                    error=str(e),
                    compression=compression.value
                )
        
        return content
    
    def _add_cache_headers(self, response: Response) -> None:
        """Add cache-related headers to response."""
        # Add cache policy headers
        if self.config.policy == CachePolicy.NO_CACHE:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        elif self.config.policy == CachePolicy.PRIVATE:
            response.headers['Cache-Control'] = f'private, max-age={self.config.ttl_seconds}'
        elif self.config.policy == CachePolicy.PUBLIC:
            response.headers['Cache-Control'] = f'public, max-age={self.config.ttl_seconds}'
        elif self.config.policy == CachePolicy.STATIC:
            response.headers['Cache-Control'] = f'public, max-age={self.config.ttl_seconds}, immutable'
        
        # Add Vary headers
        if self.config.vary_headers:
            response.headers['Vary'] = ', '.join(self.config.vary_headers)
    
    def _add_policy_headers(self, response: Response, cached_response: CachedResponse) -> None:
        """Add policy-specific headers to cached response."""
        # Add cache hit indicator for debugging
        response.headers['X-Cache'] = 'HIT'
        response.headers['X-Cache-Hits'] = str(cached_response.hit_count)
        
        # Add compression information
        if cached_response.compression != CompressionType.NONE:
            response.headers['X-Compressed'] = cached_response.compression.value
            response.headers['X-Compression-Ratio'] = f"{(1 - cached_response.compressed_size / cached_response.original_size):.2%}"
    
    def _get_ttl_policy_for_response(self, response: Response) -> TTLPolicy:
        """Get appropriate TTL policy for response."""
        if self.config.policy == CachePolicy.STATIC:
            return TTLPolicy.FIXED
        elif self.config.policy == CachePolicy.API_RESPONSE:
            return TTLPolicy.ADAPTIVE
        elif self.config.policy == CachePolicy.DYNAMIC:
            return TTLPolicy.SLIDING
        else:
            return TTLPolicy.FIXED
    
    def _deserialize_cached_response(self, data: dict) -> CachedResponse:
        """Deserialize cached response from dictionary."""
        # Convert string dates back to datetime objects
        created_at = datetime.fromisoformat(data['created_at'])
        expires_at = datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None
        last_modified = datetime.fromisoformat(data['last_modified']) if data.get('last_modified') else None
        
        # Convert content back to bytes
        content = data['content']
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        return CachedResponse(
            content=content,
            status_code=data['status_code'],
            headers=data['headers'],
            content_type=data['content_type'],
            etag=data.get('etag'),
            last_modified=last_modified,
            created_at=created_at,
            expires_at=expires_at,
            hit_count=data.get('hit_count', 0),
            compression=CompressionType(data.get('compression', 'none')),
            original_size=data.get('original_size', 0),
            compressed_size=data.get('compressed_size', 0),
            cache_tags=set(data.get('cache_tags', [])),
            vary_data=data.get('vary_data', {})
        )
    
    def invalidate_cache(
        self, 
        keys: Optional[Union[str, List[str]]] = None,
        patterns: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        invalidation_pattern: CacheInvalidationPattern = CacheInvalidationPattern.IMMEDIATE
    ) -> Dict[str, Any]:
        """
        Invalidate cached responses using various strategies.
        
        Args:
            keys: Specific cache keys to invalidate
            patterns: Key patterns for bulk invalidation
            tags: Cache tags for tag-based invalidation
            invalidation_pattern: Invalidation strategy to use
            
        Returns:
            Dictionary containing invalidation results
        """
        if not self.invalidation_strategy:
            raise CacheError(
                "Cache invalidation strategy not initialized",
                error_code="INVALIDATION_STRATEGY_NOT_AVAILABLE"
            )
        
        start_time = time.perf_counter()
        results = {}
        
        try:
            # Invalidate specific keys
            if keys:
                key_result = self.invalidation_strategy.execute(
                    keys, 
                    invalidation_pattern
                )
                results['keys'] = key_result
            
            # Invalidate by patterns
            if patterns:
                pattern_result = self.invalidation_strategy.execute(
                    patterns,
                    CacheInvalidationPattern.PATTERN_BASED
                )
                results['patterns'] = pattern_result
            
            # Invalidate by tags
            if tags:
                tag_result = self.invalidation_strategy.invalidate_by_tags(tags)
                results['tags'] = tag_result
            
            # Record metrics
            total_invalidated = sum(
                result.get('success_count', 0) 
                for result in results.values()
            )
            self.metrics.record_invalidation(total_invalidated)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.info(
                "Cache invalidation completed",
                keys_count=len(keys) if keys else 0,
                patterns_count=len(patterns) if patterns else 0,
                tags_count=len(tags) if tags else 0,
                total_invalidated=total_invalidated,
                duration_ms=duration_ms,
                invalidation_pattern=invalidation_pattern.value
            )
            
            return {
                'status': 'success',
                'total_invalidated': total_invalidated,
                'duration_ms': duration_ms,
                'results': results,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.error(
                "Cache invalidation failed",
                error=str(e),
                duration_ms=duration_ms,
                invalidation_pattern=invalidation_pattern.value
            )
            
            raise CacheInvalidationError(
                f"Cache invalidation failed: {str(e)}",
                keys=keys,
                pattern=str(patterns) if patterns else None
            )
    
    def clear_all_cache(self) -> Dict[str, Any]:
        """Clear all cached responses."""
        try:
            start_time = time.perf_counter()
            
            # Clear Flask-Caching cache
            self.cache.clear()
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.info(
                "All caches cleared",
                duration_ms=duration_ms
            )
            
            # Reset metrics
            self.metrics = ResponseCacheMetrics()
            
            return {
                'status': 'success',
                'operation': 'clear_all',
                'duration_ms': duration_ms,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(
                "Failed to clear all caches",
                error=str(e)
            )
            
            raise CacheError(
                f"Failed to clear all caches: {str(e)}",
                error_code="CACHE_CLEAR_FAILED"
            )
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        stats = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'configuration': {
                'policy': self.config.policy.value,
                'ttl_seconds': self.config.ttl_seconds,
                'max_content_length': self.config.max_content_length,
                'compression': self.config.compression.value,
                'cache_private_responses': self.config.cache_private_responses
            },
            'performance': self.metrics.get_performance_summary(),
            'redis_health': None,
            'cache_patterns': len(self.cache_patterns)
        }
        
        # Add Redis health information
        if self.redis_client:
            try:
                redis_health = self.redis_client.health_check()
                stats['redis_health'] = redis_health
            except Exception as e:
                stats['redis_health'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
        
        return stats
    
    def warm_cache(
        self, 
        urls: List[str], 
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Warm cache by pre-loading specified URLs.
        
        Args:
            urls: List of URLs to warm
            method: HTTP method for requests
            headers: Additional headers for requests
            
        Returns:
            Dictionary containing warming results
        """
        if not self.app:
            raise CacheError(
                "Flask application not initialized",
                error_code="APP_NOT_INITIALIZED"
            )
        
        start_time = time.perf_counter()
        results = {
            'total_urls': len(urls),
            'successful': 0,
            'failed': 0,
            'errors': []
        }
        
        with self.app.test_client() as client:
            for url in urls:
                try:
                    # Make request to warm cache
                    response = client.open(
                        url,
                        method=method,
                        headers=headers or {}
                    )
                    
                    if response.status_code < 400:
                        results['successful'] += 1
                    else:
                        results['failed'] += 1
                        results['errors'].append(f"{url}: HTTP {response.status_code}")
                        
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append(f"{url}: {str(e)}")
        
        duration_ms = (time.perf_counter() - start_time) * 1000
        results['duration_ms'] = duration_ms
        results['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        logger.info(
            "Cache warming completed",
            total_urls=results['total_urls'],
            successful=results['successful'],
            failed=results['failed'],
            duration_ms=duration_ms
        )
        
        return results


def create_response_cache(
    app: Optional[Flask] = None,
    config: Optional[CacheConfiguration] = None,
    redis_client: Optional[RedisClient] = None
) -> FlaskResponseCache:
    """
    Factory function for creating Flask response cache instances.
    
    Args:
        app: Flask application instance
        config: Cache configuration
        redis_client: Redis client for cache backend
        
    Returns:
        Configured FlaskResponseCache instance
    """
    return FlaskResponseCache(
        app=app,
        config=config,
        redis_client=redis_client
    )


# Global response cache instance for Flask application integration
_response_cache: Optional[FlaskResponseCache] = None


def get_response_cache() -> FlaskResponseCache:
    """
    Get global response cache instance.
    
    Returns:
        Global FlaskResponseCache instance
        
    Raises:
        CacheError: If response cache is not initialized
    """
    global _response_cache
    
    if _response_cache is None:
        raise CacheError(
            "Response cache not initialized. Call init_response_cache() first.",
            error_code="RESPONSE_CACHE_NOT_INITIALIZED"
        )
    
    return _response_cache


def init_response_cache(
    app: Flask,
    config: Optional[CacheConfiguration] = None,
    redis_client: Optional[RedisClient] = None
) -> FlaskResponseCache:
    """
    Initialize global response cache for Flask application factory pattern.
    
    Args:
        app: Flask application instance
        config: Cache configuration
        redis_client: Redis client for cache backend
        
    Returns:
        Initialized FlaskResponseCache instance
    """
    global _response_cache
    
    _response_cache = create_response_cache(
        app=app,
        config=config,
        redis_client=redis_client
    )
    
    logger.info(
        "Global response cache initialized",
        policy=_response_cache.config.policy.value,
        ttl_seconds=_response_cache.config.ttl_seconds
    )
    
    return _response_cache


# Export public interface
__all__ = [
    'FlaskResponseCache',
    'CacheConfiguration',
    'CachePolicy',
    'CompressionType',
    'CachedResponse',
    'ResponseCacheMetrics',
    'create_response_cache',
    'get_response_cache',
    'init_response_cache'
]