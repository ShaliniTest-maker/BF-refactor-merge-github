"""
Cache Invalidation Strategies, TTL Management Policies, and Cache Key Pattern Organization

This module implements comprehensive cache invalidation strategies, intelligent TTL management
policies, cache warming strategies, and cache key namespace management for enterprise-grade
cache lifecycle optimization. Provides data consistency management, distributed cache
coordination, and performance optimization equivalent to Node.js caching patterns.

Key Features:
- Multi-tier cache invalidation strategies with data consistency guarantees
- Intelligent TTL management based on data access patterns and business rules
- Cache key pattern organization with namespace management for multi-tenant systems
- Proactive cache warming strategies for performance optimization
- Distributed cache coordination for multi-instance Flask deployments
- Cache partitioning and sharding for horizontal scaling
- Integration with monitoring and circuit breaker patterns per Section 6.1.3

Architecture Integration:
- Seamless integration with src/cache/client.py RedisClient infrastructure
- Enterprise monitoring integration via src/cache/monitoring.py metrics collection
- Circuit breaker patterns for cache resilience and graceful degradation
- Performance optimization maintaining ≤10% variance from Node.js baseline per Section 0.1.1
- Flask Blueprint integration for centralized cache strategy management

Performance Requirements:
- Cache invalidation latency: ≤5ms for single key, ≤50ms for pattern-based invalidation
- TTL calculation performance: ≤1ms for policy evaluation and expiration setting
- Cache warming throughput: ≥1000 keys/second for bulk population operations
- Distributed coordination latency: ≤10ms for multi-instance cache synchronization
- Memory efficiency: ≤20% overhead for strategy metadata and coordination structures

References:
- Section 5.2.7: Caching layer responsibilities and cache invalidation/TTL management
- Section 6.1.3: Fallback cache strategies and distributed cache coordination
- Section 5.4.1: Monitoring and observability for cache performance tracking
- Section 6.1.3: Resilience mechanisms including circuit breaker patterns
"""

import asyncio
import hashlib
import json
import math
import random
import re
import time
import traceback
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from threading import Lock, RLock
from typing import (
    Any, Dict, List, Optional, Set, Union, Callable, Tuple, 
    Pattern, TypeVar, Generic, NamedTuple, AsyncIterator
)

import structlog
from redis.exceptions import RedisError, ConnectionError, TimeoutError

from .client import RedisClient, get_redis_client
from .monitoring import CacheMonitoringManager, monitor_cache_operation
from .exceptions import (
    CacheError, CacheInvalidationError, CacheKeyError,
    CacheOperationTimeoutError, CircuitBreakerOpenError
)

# Configure structured logging for enterprise integration
logger = structlog.get_logger(__name__)

# Type variables for generic cache strategy operations
T = TypeVar('T')
KeyType = Union[str, bytes]
ValueType = Any


class CacheInvalidationPattern(Enum):
    """
    Cache invalidation pattern types for different consistency requirements.
    
    Implements various invalidation strategies optimized for different data
    consistency needs and performance characteristics per Section 5.2.7.
    """
    IMMEDIATE = "immediate"          # Immediate invalidation for critical data
    LAZY = "lazy"                   # Lazy invalidation for non-critical data
    WRITE_THROUGH = "write_through" # Immediate write-through invalidation
    WRITE_BEHIND = "write_behind"   # Delayed write-behind invalidation
    TIME_BASED = "time_based"       # Time-based expiration invalidation
    EVENT_DRIVEN = "event_driven"   # Event-triggered invalidation
    CASCADE = "cascade"             # Cascading invalidation for related data
    PATTERN_BASED = "pattern_based" # Pattern-based bulk invalidation


class TTLPolicy(Enum):
    """
    TTL (Time-To-Live) policy types for intelligent cache expiration management.
    
    Provides multiple TTL calculation strategies based on data access patterns,
    business requirements, and performance optimization needs per Section 5.2.7.
    """
    FIXED = "fixed"                 # Fixed TTL for predictable data
    SLIDING = "sliding"             # Sliding TTL based on access patterns
    ADAPTIVE = "adaptive"           # Adaptive TTL based on hit rates
    BUSINESS_HOURS = "business_hours" # Business hours-aware TTL
    DECAY = "decay"                 # Exponential decay TTL
    LAST_MODIFIED = "last_modified" # TTL based on data modification time
    ACCESS_FREQUENCY = "access_frequency" # TTL based on access frequency
    COST_AWARE = "cost_aware"       # TTL based on computation cost


class CacheWarmingStrategy(Enum):
    """
    Cache warming strategy types for proactive cache population.
    
    Implements intelligent cache warming patterns for performance optimization
    and user experience improvement per Section 5.2.7 performance optimization.
    """
    PRELOAD = "preload"             # Preload during application startup
    BACKGROUND = "background"       # Background warming during operation
    PREDICTIVE = "predictive"       # Predictive warming based on patterns
    SCHEDULE_BASED = "schedule_based" # Scheduled warming operations
    DEMAND_DRIVEN = "demand_driven" # Demand-driven warming on cache misses
    CASCADING = "cascading"         # Cascading warming for related data


@dataclass
class CacheKeyPattern:
    """
    Cache key pattern definition for organized namespace management.
    
    Provides structured cache key organization with namespace hierarchy,
    pattern matching, and validation for enterprise cache management.
    """
    namespace: str                          # Primary namespace (e.g., 'user', 'session')
    pattern: str                           # Key pattern template (e.g., 'user:{id}:profile')
    ttl_policy: TTLPolicy = TTLPolicy.FIXED # Default TTL policy for this pattern
    invalidation_pattern: CacheInvalidationPattern = CacheInvalidationPattern.IMMEDIATE
    warming_strategy: Optional[CacheWarmingStrategy] = None
    priority: int = 1                      # Cache priority (1=highest, 10=lowest)
    tags: Set[str] = field(default_factory=set) # Tags for tag-based invalidation
    metadata: Dict[str, Any] = field(default_factory=dict) # Additional metadata
    
    def __post_init__(self):
        """Validate and normalize cache key pattern."""
        if not self.namespace:
            raise CacheKeyError("Cache key pattern namespace cannot be empty")
        
        if not self.pattern:
            raise CacheKeyError("Cache key pattern cannot be empty")
        
        # Normalize namespace and pattern
        self.namespace = self.namespace.strip().lower()
        self.pattern = self.pattern.strip()
        
        # Validate pattern format
        if not re.match(r'^[a-zA-Z0-9_:\-\{\}]+$', self.pattern):
            raise CacheKeyError(
                f"Invalid cache key pattern format: {self.pattern}",
                key_pattern=self.pattern,
                validation_errors=["Pattern contains invalid characters"]
            )
    
    def generate_key(self, **kwargs) -> str:
        """
        Generate cache key from pattern template with provided parameters.
        
        Args:
            **kwargs: Parameters to substitute in pattern template
            
        Returns:
            Generated cache key
            
        Raises:
            CacheKeyError: If required parameters are missing
        """
        try:
            # Use format string replacement for key generation
            key = self.pattern.format(**kwargs)
            
            # Add namespace prefix
            full_key = f"{self.namespace}:{key}"
            
            # Validate generated key length (Redis key limit)
            if len(full_key) > 512:
                raise CacheKeyError(
                    f"Generated cache key exceeds maximum length: {len(full_key)} > 512",
                    key=full_key,
                    key_pattern=self.pattern
                )
            
            return full_key
            
        except KeyError as e:
            missing_param = str(e).strip("'")
            raise CacheKeyError(
                f"Missing required parameter for cache key pattern: {missing_param}",
                key_pattern=self.pattern,
                validation_errors=[f"Missing parameter: {missing_param}"]
            )
    
    def matches_key(self, key: str) -> bool:
        """
        Check if a cache key matches this pattern.
        
        Args:
            key: Cache key to check
            
        Returns:
            True if key matches pattern
        """
        if not key.startswith(f"{self.namespace}:"):
            return False
        
        # Convert pattern to regex for matching
        pattern_regex = self.pattern
        pattern_regex = re.escape(pattern_regex)
        pattern_regex = pattern_regex.replace(r'\{[^}]+\}', r'[^:]+')
        pattern_regex = f"^{self.namespace}:{pattern_regex}$"
        
        return bool(re.match(pattern_regex, key))


@dataclass
class TTLConfiguration:
    """
    TTL configuration for cache strategies with policy-specific parameters.
    
    Provides comprehensive TTL management configuration supporting multiple
    TTL policies and adaptive expiration strategies per Section 5.2.7.
    """
    policy: TTLPolicy                       # TTL policy type
    base_ttl: int = 300                    # Base TTL in seconds (5 minutes default)
    min_ttl: int = 60                      # Minimum TTL in seconds
    max_ttl: int = 3600                    # Maximum TTL in seconds (1 hour default)
    sliding_window: int = 300              # Sliding window for access-based TTL
    decay_factor: float = 0.5              # Decay factor for exponential decay
    business_hours_multiplier: float = 2.0  # TTL multiplier during business hours
    hit_rate_threshold: float = 0.8        # Hit rate threshold for adaptive TTL
    access_frequency_weight: float = 0.3   # Weight for access frequency in calculations
    cost_computation_factor: float = 1.0   # Factor for cost-aware TTL calculations
    
    def __post_init__(self):
        """Validate TTL configuration parameters."""
        if self.base_ttl <= 0:
            raise ValueError("Base TTL must be positive")
        
        if self.min_ttl <= 0 or self.min_ttl > self.max_ttl:
            raise ValueError("Invalid TTL range: min_ttl must be positive and <= max_ttl")
        
        if self.decay_factor <= 0 or self.decay_factor >= 1:
            raise ValueError("Decay factor must be between 0 and 1")
        
        if self.hit_rate_threshold < 0 or self.hit_rate_threshold > 1:
            raise ValueError("Hit rate threshold must be between 0 and 1")


class CacheStrategyMetrics:
    """
    Metrics collection for cache strategy performance monitoring.
    
    Tracks strategy effectiveness, performance characteristics, and provides
    insights for optimization and Node.js baseline comparison per Section 5.4.1.
    """
    
    def __init__(self):
        self.invalidation_counts = defaultdict(int)
        self.invalidation_latencies = defaultdict(list)
        self.ttl_calculation_times = defaultdict(list)
        self.warming_operations = defaultdict(int)
        self.warming_success_rates = defaultdict(list)
        self.cache_hit_rates = defaultdict(deque)
        self.pattern_usage_stats = defaultdict(int)
        self.last_reset = time.time()
        self._lock = RLock()
    
    def record_invalidation(self, pattern: CacheInvalidationPattern, latency_ms: float, 
                          keys_affected: int = 1):
        """Record cache invalidation metrics."""
        with self._lock:
            self.invalidation_counts[pattern.value] += keys_affected
            self.invalidation_latencies[pattern.value].append(latency_ms)
            
            # Keep only recent latency measurements (last 1000)
            if len(self.invalidation_latencies[pattern.value]) > 1000:
                self.invalidation_latencies[pattern.value] = \
                    self.invalidation_latencies[pattern.value][-1000:]
    
    def record_ttl_calculation(self, policy: TTLPolicy, calculation_time_ms: float):
        """Record TTL calculation performance metrics."""
        with self._lock:
            self.ttl_calculation_times[policy.value].append(calculation_time_ms)
            
            # Keep only recent measurements (last 1000)
            if len(self.ttl_calculation_times[policy.value]) > 1000:
                self.ttl_calculation_times[policy.value] = \
                    self.ttl_calculation_times[policy.value][-1000:]
    
    def record_warming_operation(self, strategy: CacheWarmingStrategy, success: bool, 
                               keys_warmed: int = 1):
        """Record cache warming operation metrics."""
        with self._lock:
            self.warming_operations[strategy.value] += keys_warmed
            self.warming_success_rates[strategy.value].append(1.0 if success else 0.0)
            
            # Keep only recent success rate measurements (last 100)
            if len(self.warming_success_rates[strategy.value]) > 100:
                self.warming_success_rates[strategy.value] = \
                    self.warming_success_rates[strategy.value][-100:]
    
    def update_hit_rate(self, namespace: str, hit_rate: float):
        """Update cache hit rate for namespace."""
        with self._lock:
            self.cache_hit_rates[namespace].append((time.time(), hit_rate))
            
            # Keep only recent hit rates (last 24 hours worth at 1-minute intervals)
            cutoff_time = time.time() - 86400  # 24 hours
            while (self.cache_hit_rates[namespace] and 
                   self.cache_hit_rates[namespace][0][0] < cutoff_time):
                self.cache_hit_rates[namespace].popleft()
    
    def record_pattern_usage(self, pattern_name: str):
        """Record cache pattern usage statistics."""
        with self._lock:
            self.pattern_usage_stats[pattern_name] += 1
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary for monitoring."""
        with self._lock:
            current_time = time.time()
            uptime_hours = (current_time - self.last_reset) / 3600
            
            summary = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'uptime_hours': uptime_hours,
                'invalidation_performance': {},
                'ttl_performance': {},
                'warming_performance': {},
                'hit_rate_trends': {},
                'pattern_usage': dict(self.pattern_usage_stats)
            }
            
            # Calculate invalidation performance metrics
            for pattern, latencies in self.invalidation_latencies.items():
                if latencies:
                    summary['invalidation_performance'][pattern] = {
                        'avg_latency_ms': sum(latencies) / len(latencies),
                        'max_latency_ms': max(latencies),
                        'min_latency_ms': min(latencies),
                        'total_operations': self.invalidation_counts[pattern],
                        'operations_per_hour': self.invalidation_counts[pattern] / max(uptime_hours, 0.1)
                    }
            
            # Calculate TTL calculation performance
            for policy, times in self.ttl_calculation_times.items():
                if times:
                    summary['ttl_performance'][policy] = {
                        'avg_calculation_time_ms': sum(times) / len(times),
                        'max_calculation_time_ms': max(times),
                        'calculations_count': len(times)
                    }
            
            # Calculate warming performance
            for strategy, success_rates in self.warming_success_rates.items():
                if success_rates:
                    summary['warming_performance'][strategy] = {
                        'success_rate': sum(success_rates) / len(success_rates),
                        'total_operations': self.warming_operations[strategy],
                        'operations_per_hour': self.warming_operations[strategy] / max(uptime_hours, 0.1)
                    }
            
            # Calculate hit rate trends
            for namespace, hit_rates in self.cache_hit_rates.items():
                if hit_rates:
                    recent_rates = [rate for _, rate in hit_rates[-60:]]  # Last hour
                    if recent_rates:
                        summary['hit_rate_trends'][namespace] = {
                            'current_hit_rate': recent_rates[-1],
                            'avg_hit_rate_1h': sum(recent_rates) / len(recent_rates),
                            'trend_direction': 'up' if len(recent_rates) > 1 and recent_rates[-1] > recent_rates[0] else 'down'
                        }
            
            return summary


class BaseCacheStrategy(ABC):
    """
    Abstract base class for cache strategies providing common infrastructure.
    
    Defines the interface and common functionality for all cache strategy
    implementations including monitoring, error handling, and performance tracking.
    """
    
    def __init__(self, redis_client: Optional[RedisClient] = None, 
                 monitoring: Optional[CacheMonitoringManager] = None):
        """
        Initialize base cache strategy with Redis client and monitoring.
        
        Args:
            redis_client: Redis client instance for cache operations
            monitoring: Cache monitoring manager for metrics collection
        """
        self.redis_client = redis_client or get_redis_client()
        self.monitoring = monitoring
        self.metrics = CacheStrategyMetrics()
        self.logger = structlog.get_logger(f"cache.strategy.{self.__class__.__name__}")
        self._lock = RLock()
        
        # Strategy configuration
        self.circuit_breaker_threshold = 5
        self.circuit_breaker_timeout = 60
        self.max_batch_size = 1000
        self.operation_timeout = 30.0
        
        self.logger.info(
            "Cache strategy initialized",
            strategy_type=self.__class__.__name__,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            max_batch_size=self.max_batch_size
        )
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Execute the cache strategy operation."""
        pass
    
    def _handle_redis_error(self, error: Exception, operation: str) -> None:
        """
        Handle Redis errors with appropriate exception translation.
        
        Args:
            error: Original Redis exception
            operation: Description of the operation that failed
            
        Raises:
            Appropriate CacheError subclass
        """
        if isinstance(error, ConnectionError):
            raise CircuitBreakerOpenError(
                message=f"Redis connection failed during {operation}",
                failure_count=self.circuit_breaker_threshold,
                recovery_timeout=self.circuit_breaker_timeout
            )
        elif isinstance(error, TimeoutError):
            raise CacheOperationTimeoutError(
                message=f"Cache operation timeout during {operation}",
                operation=operation,
                timeout_duration=self.operation_timeout
            )
        else:
            raise CacheError(
                message=f"Cache strategy operation failed: {operation}",
                error_code="CACHE_STRATEGY_ERROR",
                details={'operation': operation, 'original_error': str(error)}
            )
    
    def _validate_keys(self, keys: Union[str, List[str]]) -> List[str]:
        """
        Validate and normalize cache keys for operations.
        
        Args:
            keys: Single key or list of keys to validate
            
        Returns:
            List of validated keys
            
        Raises:
            CacheKeyError: If any keys are invalid
        """
        if isinstance(keys, str):
            keys = [keys]
        
        validated_keys = []
        validation_errors = []
        
        for key in keys:
            if not isinstance(key, str):
                validation_errors.append(f"Key must be string, got {type(key)}")
                continue
            
            if not key.strip():
                validation_errors.append("Key cannot be empty")
                continue
            
            if len(key) > 512:
                validation_errors.append(f"Key exceeds maximum length: {len(key)} > 512")
                continue
            
            validated_keys.append(key.strip())
        
        if validation_errors:
            raise CacheKeyError(
                message="Cache key validation failed",
                validation_errors=validation_errors
            )
        
        return validated_keys
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get strategy-specific metrics summary."""
        return self.metrics.get_performance_summary()


class CacheInvalidationStrategy(BaseCacheStrategy):
    """
    Comprehensive cache invalidation strategy implementing multiple invalidation
    patterns for data consistency management and distributed cache coordination.
    
    Provides intelligent cache invalidation with support for immediate, lazy,
    pattern-based, and event-driven invalidation patterns per Section 5.2.7
    cache invalidation and TTL management requirements.
    """
    
    def __init__(self, redis_client: Optional[RedisClient] = None, 
                 monitoring: Optional[CacheMonitoringManager] = None):
        super().__init__(redis_client, monitoring)
        
        # Invalidation pattern configurations
        self.pattern_configs = {
            CacheInvalidationPattern.IMMEDIATE: {'batch_size': 100, 'timeout': 5.0},
            CacheInvalidationPattern.LAZY: {'batch_size': 1000, 'timeout': 30.0},
            CacheInvalidationPattern.WRITE_THROUGH: {'batch_size': 50, 'timeout': 10.0},
            CacheInvalidationPattern.WRITE_BEHIND: {'batch_size': 500, 'timeout': 60.0},
            CacheInvalidationPattern.TIME_BASED: {'batch_size': 200, 'timeout': 15.0},
            CacheInvalidationPattern.EVENT_DRIVEN: {'batch_size': 100, 'timeout': 5.0},
            CacheInvalidationPattern.CASCADE: {'batch_size': 100, 'timeout': 20.0},
            CacheInvalidationPattern.PATTERN_BASED: {'batch_size': 1000, 'timeout': 30.0}
        }
        
        # Tag-based invalidation tracking
        self.tag_key_mapping = defaultdict(set)
        self.key_tag_mapping = defaultdict(set)
        
        # Distributed coordination tracking
        self.pending_invalidations = defaultdict(set)
        self.invalidation_locks = defaultdict(Lock)
        
        self.logger.info("Cache invalidation strategy initialized")
    
    def execute(self, keys: Union[str, List[str]], 
                pattern: CacheInvalidationPattern = CacheInvalidationPattern.IMMEDIATE,
                **kwargs) -> Dict[str, Any]:
        """
        Execute cache invalidation strategy with specified pattern.
        
        Args:
            keys: Cache keys to invalidate
            pattern: Invalidation pattern to use
            **kwargs: Additional pattern-specific parameters
            
        Returns:
            Dictionary containing invalidation results and metrics
        """
        start_time = time.perf_counter()
        validated_keys = self._validate_keys(keys)
        
        try:
            if pattern == CacheInvalidationPattern.IMMEDIATE:
                result = self._immediate_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.LAZY:
                result = self._lazy_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.WRITE_THROUGH:
                result = self._write_through_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.WRITE_BEHIND:
                result = self._write_behind_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.TIME_BASED:
                result = self._time_based_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.EVENT_DRIVEN:
                result = self._event_driven_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.CASCADE:
                result = self._cascade_invalidation(validated_keys, **kwargs)
            elif pattern == CacheInvalidationPattern.PATTERN_BASED:
                result = self._pattern_based_invalidation(validated_keys, **kwargs)
            else:
                raise CacheInvalidationError(
                    f"Unsupported invalidation pattern: {pattern}",
                    keys=validated_keys
                )
            
            # Record metrics
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.record_invalidation(pattern, duration_ms, len(validated_keys))
            
            # Update monitoring
            if self.monitoring:
                self.monitoring.record_cache_operation('invalidate', 'redis', duration_ms / 1000, 'success')
            
            self.logger.info(
                "Cache invalidation completed",
                pattern=pattern.value,
                keys_count=len(validated_keys),
                duration_ms=duration_ms,
                success_count=result.get('success_count', 0),
                error_count=result.get('error_count', 0)
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Update monitoring for failure
            if self.monitoring:
                self.monitoring.record_cache_operation('invalidate', 'redis', duration_ms / 1000, 'error')
            
            self.logger.error(
                "Cache invalidation failed",
                pattern=pattern.value,
                keys_count=len(validated_keys),
                duration_ms=duration_ms,
                error_message=str(e),
                error_type=type(e).__name__
            )
            
            self._handle_redis_error(e, f"invalidation with pattern {pattern.value}")
    
    def _immediate_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Immediate cache invalidation for critical data consistency.
        
        Args:
            keys: Cache keys to invalidate immediately
            **kwargs: Additional parameters
            
        Returns:
            Invalidation results
        """
        config = self.pattern_configs[CacheInvalidationPattern.IMMEDIATE]
        batch_size = kwargs.get('batch_size', config['batch_size'])
        
        success_count = 0
        error_count = 0
        errors = []
        
        # Process keys in batches for performance
        for i in range(0, len(keys), batch_size):
            batch_keys = keys[i:i + batch_size]
            
            try:
                deleted_count = self.redis_client.delete(*batch_keys)
                success_count += deleted_count
                
                # Log successful invalidations
                for key in batch_keys[:deleted_count]:
                    self._track_invalidation(key, CacheInvalidationPattern.IMMEDIATE)
                
            except Exception as e:
                error_count += len(batch_keys)
                error_msg = f"Failed to invalidate batch {i//batch_size + 1}: {str(e)}"
                errors.append(error_msg)
                
                self.logger.warning(
                    "Immediate invalidation batch failed",
                    batch_start=i,
                    batch_size=len(batch_keys),
                    error_message=str(e)
                )
        
        return {
            'pattern': CacheInvalidationPattern.IMMEDIATE.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _lazy_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Lazy cache invalidation for non-critical data with delayed processing.
        
        Args:
            keys: Cache keys to invalidate lazily
            **kwargs: Additional parameters including delay
            
        Returns:
            Invalidation results
        """
        delay_seconds = kwargs.get('delay_seconds', 5)
        mark_for_deletion = kwargs.get('mark_for_deletion', True)
        
        success_count = 0
        
        if mark_for_deletion:
            # Mark keys for lazy deletion with expiration
            pipeline = self.redis_client.pipeline()
            
            for key in keys:
                # Set very short TTL to mark for lazy deletion
                pipeline.expire(key, delay_seconds)
                self._track_invalidation(key, CacheInvalidationPattern.LAZY)
            
            try:
                results = pipeline.execute()
                success_count = sum(1 for result in results if result)
            except Exception as e:
                self.logger.warning(
                    "Lazy invalidation marking failed",
                    keys_count=len(keys),
                    error_message=str(e)
                )
        else:
            # Immediate deletion for lazy invalidation
            success_count = self.redis_client.delete(*keys)
            for key in keys[:success_count]:
                self._track_invalidation(key, CacheInvalidationPattern.LAZY)
        
        return {
            'pattern': CacheInvalidationPattern.LAZY.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': len(keys) - success_count,
            'delay_seconds': delay_seconds,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _write_through_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Write-through invalidation ensuring immediate consistency.
        
        Args:
            keys: Cache keys to invalidate with write-through
            **kwargs: Additional parameters including update_callback
            
        Returns:
            Invalidation results
        """
        update_callback = kwargs.get('update_callback')
        success_count = 0
        error_count = 0
        errors = []
        
        for key in keys:
            try:
                # Delete from cache
                deleted = self.redis_client.delete(key)
                
                # Execute update callback if provided
                if update_callback and callable(update_callback):
                    try:
                        update_callback(key)
                    except Exception as e:
                        self.logger.warning(
                            "Write-through update callback failed",
                            key=key,
                            error_message=str(e)
                        )
                
                if deleted:
                    success_count += 1
                    self._track_invalidation(key, CacheInvalidationPattern.WRITE_THROUGH)
                
            except Exception as e:
                error_count += 1
                error_msg = f"Write-through invalidation failed for key {key}: {str(e)}"
                errors.append(error_msg)
        
        return {
            'pattern': CacheInvalidationPattern.WRITE_THROUGH.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _write_behind_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Write-behind invalidation with delayed consistency updates.
        
        Args:
            keys: Cache keys to invalidate with write-behind
            **kwargs: Additional parameters including delay and update_callback
            
        Returns:
            Invalidation results
        """
        delay_seconds = kwargs.get('delay_seconds', 30)
        update_callback = kwargs.get('update_callback')
        
        # Immediate cache invalidation
        success_count = self.redis_client.delete(*keys)
        
        # Track invalidated keys
        for key in keys[:success_count]:
            self._track_invalidation(key, CacheInvalidationPattern.WRITE_BEHIND)
        
        # Schedule delayed update if callback provided
        if update_callback and callable(update_callback):
            # In a production system, this would use a task queue like Celery
            # For now, we'll store the pending operations
            with self._lock:
                for key in keys[:success_count]:
                    self.pending_invalidations['write_behind'].add((key, time.time() + delay_seconds))
        
        return {
            'pattern': CacheInvalidationPattern.WRITE_BEHIND.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': len(keys) - success_count,
            'delay_seconds': delay_seconds,
            'pending_updates': len(keys[:success_count]) if update_callback else 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _time_based_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Time-based invalidation with scheduled expiration.
        
        Args:
            keys: Cache keys to invalidate based on time
            **kwargs: Additional parameters including expiration_time
            
        Returns:
            Invalidation results
        """
        expiration_time = kwargs.get('expiration_time')
        ttl_seconds = kwargs.get('ttl_seconds', 3600)  # Default 1 hour
        
        if expiration_time:
            if isinstance(expiration_time, datetime):
                ttl_seconds = int((expiration_time - datetime.now(timezone.utc)).total_seconds())
            else:
                ttl_seconds = int(expiration_time)
        
        # Ensure positive TTL
        ttl_seconds = max(1, ttl_seconds)
        
        success_count = 0
        pipeline = self.redis_client.pipeline()
        
        for key in keys:
            pipeline.expire(key, ttl_seconds)
        
        try:
            results = pipeline.execute()
            success_count = sum(1 for result in results if result)
            
            # Track invalidations
            for key in keys[:success_count]:
                self._track_invalidation(key, CacheInvalidationPattern.TIME_BASED)
                
        except Exception as e:
            self.logger.warning(
                "Time-based invalidation failed",
                keys_count=len(keys),
                ttl_seconds=ttl_seconds,
                error_message=str(e)
            )
        
        return {
            'pattern': CacheInvalidationPattern.TIME_BASED.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': len(keys) - success_count,
            'ttl_seconds': ttl_seconds,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _event_driven_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Event-driven invalidation triggered by specific events.
        
        Args:
            keys: Cache keys to invalidate based on events
            **kwargs: Additional parameters including event_type and metadata
            
        Returns:
            Invalidation results
        """
        event_type = kwargs.get('event_type', 'unknown')
        event_metadata = kwargs.get('event_metadata', {})
        
        # Immediate invalidation for event-driven pattern
        success_count = self.redis_client.delete(*keys)
        
        # Track event-driven invalidations with metadata
        for key in keys[:success_count]:
            self._track_invalidation(key, CacheInvalidationPattern.EVENT_DRIVEN, {
                'event_type': event_type,
                'metadata': event_metadata
            })
        
        self.logger.info(
            "Event-driven invalidation completed",
            event_type=event_type,
            keys_count=len(keys),
            success_count=success_count,
            event_metadata=event_metadata
        )
        
        return {
            'pattern': CacheInvalidationPattern.EVENT_DRIVEN.value,
            'total_keys': len(keys),
            'success_count': success_count,
            'error_count': len(keys) - success_count,
            'event_type': event_type,
            'event_metadata': event_metadata,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _cascade_invalidation(self, keys: List[str], **kwargs) -> Dict[str, Any]:
        """
        Cascading invalidation for related data with dependency tracking.
        
        Args:
            keys: Root cache keys to invalidate with cascading
            **kwargs: Additional parameters including dependency_patterns
            
        Returns:
            Invalidation results
        """
        dependency_patterns = kwargs.get('dependency_patterns', [])
        max_cascade_depth = kwargs.get('max_cascade_depth', 3)
        
        all_keys_to_invalidate = set(keys)
        
        # Find related keys based on dependency patterns
        for pattern in dependency_patterns:
            if isinstance(pattern, str):
                # Simple pattern matching
                related_keys = self._find_keys_by_pattern(pattern)
                all_keys_to_invalidate.update(related_keys)
            elif callable(pattern):
                # Custom dependency function
                try:
                    related_keys = pattern(keys)
                    if isinstance(related_keys, (list, set)):
                        all_keys_to_invalidate.update(related_keys)
                except Exception as e:
                    self.logger.warning(
                        "Cascade dependency function failed",
                        error_message=str(e)
                    )
        
        # Limit cascade expansion
        if len(all_keys_to_invalidate) > len(keys) * 10:
            self.logger.warning(
                "Cascade invalidation limited due to excessive expansion",
                original_keys=len(keys),
                expanded_keys=len(all_keys_to_invalidate)
            )
            all_keys_to_invalidate = set(list(all_keys_to_invalidate)[:len(keys) * 10])
        
        # Execute invalidation
        final_keys = list(all_keys_to_invalidate)
        success_count = self.redis_client.delete(*final_keys)
        
        # Track cascade invalidations
        for key in final_keys[:success_count]:
            self._track_invalidation(key, CacheInvalidationPattern.CASCADE)
        
        return {
            'pattern': CacheInvalidationPattern.CASCADE.value,
            'original_keys': len(keys),
            'cascade_keys': len(final_keys),
            'success_count': success_count,
            'error_count': len(final_keys) - success_count,
            'dependency_patterns_count': len(dependency_patterns),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _pattern_based_invalidation(self, patterns: List[str], **kwargs) -> Dict[str, Any]:
        """
        Pattern-based bulk invalidation using Redis pattern matching.
        
        Args:
            patterns: Cache key patterns to invalidate (e.g., 'user:*', 'session:123:*')
            **kwargs: Additional parameters including match_limit
            
        Returns:
            Invalidation results
        """
        match_limit = kwargs.get('match_limit', 1000)
        total_deleted = 0
        patterns_processed = 0
        errors = []
        
        for pattern in patterns:
            try:
                # Find keys matching pattern
                matching_keys = self._find_keys_by_pattern(pattern, limit=match_limit)
                
                if matching_keys:
                    # Delete in batches
                    batch_size = self.pattern_configs[CacheInvalidationPattern.PATTERN_BASED]['batch_size']
                    for i in range(0, len(matching_keys), batch_size):
                        batch_keys = matching_keys[i:i + batch_size]
                        deleted_count = self.redis_client.delete(*batch_keys)
                        total_deleted += deleted_count
                        
                        # Track pattern-based invalidations
                        for key in batch_keys[:deleted_count]:
                            self._track_invalidation(key, CacheInvalidationPattern.PATTERN_BASED)
                
                patterns_processed += 1
                
            except Exception as e:
                error_msg = f"Pattern invalidation failed for '{pattern}': {str(e)}"
                errors.append(error_msg)
                self.logger.warning(
                    "Pattern-based invalidation failed",
                    pattern=pattern,
                    error_message=str(e)
                )
        
        return {
            'pattern': CacheInvalidationPattern.PATTERN_BASED.value,
            'patterns_count': len(patterns),
            'patterns_processed': patterns_processed,
            'total_keys_deleted': total_deleted,
            'errors': errors,
            'match_limit': match_limit,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _find_keys_by_pattern(self, pattern: str, limit: int = 1000) -> List[str]:
        """
        Find cache keys matching a pattern using Redis SCAN.
        
        Args:
            pattern: Redis pattern to match
            limit: Maximum number of keys to return
            
        Returns:
            List of matching cache keys
        """
        matching_keys = []
        cursor = 0
        
        try:
            while len(matching_keys) < limit:
                cursor, keys = self.redis_client._redis_client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=min(100, limit - len(matching_keys))
                )
                
                matching_keys.extend(keys)
                
                if cursor == 0:  # Scan completed
                    break
            
            return matching_keys[:limit]
            
        except Exception as e:
            self.logger.warning(
                "Pattern key search failed",
                pattern=pattern,
                error_message=str(e)
            )
            return []
    
    def _track_invalidation(self, key: str, pattern: CacheInvalidationPattern, 
                          metadata: Optional[Dict[str, Any]] = None):
        """Track invalidation for monitoring and metrics."""
        self.metrics.record_pattern_usage(f"invalidation_{pattern.value}")
        
        if self.monitoring:
            self.monitoring.record_cache_operation('invalidate', 'redis', 0.001, 'success')
    
    def invalidate_by_tags(self, tags: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Invalidate cache keys associated with specific tags.
        
        Args:
            tags: Tag or list of tags to invalidate
            
        Returns:
            Invalidation results
        """
        if isinstance(tags, str):
            tags = [tags]
        
        all_keys_to_invalidate = set()
        
        # Collect keys associated with tags
        with self._lock:
            for tag in tags:
                if tag in self.tag_key_mapping:
                    all_keys_to_invalidate.update(self.tag_key_mapping[tag])
        
        if not all_keys_to_invalidate:
            return {
                'pattern': 'tag_based',
                'tags': tags,
                'total_keys': 0,
                'success_count': 0,
                'error_count': 0,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Execute invalidation
        final_keys = list(all_keys_to_invalidate)
        result = self.execute(final_keys, CacheInvalidationPattern.IMMEDIATE)
        result['pattern'] = 'tag_based'
        result['tags'] = tags
        
        # Clean up tag mappings for successfully invalidated keys
        if result['success_count'] > 0:
            with self._lock:
                for key in final_keys[:result['success_count']]:
                    # Remove key from all tag mappings
                    for tag in self.key_tag_mapping.get(key, set()):
                        self.tag_key_mapping[tag].discard(key)
                    self.key_tag_mapping.pop(key, None)
        
        return result
    
    def register_key_tags(self, key: str, tags: Union[str, List[str]]) -> None:
        """
        Register tags for a cache key to enable tag-based invalidation.
        
        Args:
            key: Cache key to associate with tags
            tags: Tag or list of tags to associate with the key
        """
        if isinstance(tags, str):
            tags = [tags]
        
        with self._lock:
            # Update tag -> keys mapping
            for tag in tags:
                self.tag_key_mapping[tag].add(key)
            
            # Update key -> tags mapping
            self.key_tag_mapping[key].update(tags)


class TTLManagementStrategy(BaseCacheStrategy):
    """
    Intelligent TTL (Time-To-Live) management strategy implementing adaptive
    expiration policies based on data access patterns and business requirements.
    
    Provides sophisticated TTL calculation algorithms including fixed, sliding,
    adaptive, and business-aware policies per Section 5.2.7 TTL management
    requirements for cache lifecycle optimization.
    """
    
    def __init__(self, redis_client: Optional[RedisClient] = None, 
                 monitoring: Optional[CacheMonitoringManager] = None):
        super().__init__(redis_client, monitoring)
        
        # TTL policy configurations
        self.policy_configs = {
            TTLPolicy.FIXED: TTLConfiguration(TTLPolicy.FIXED, base_ttl=300),
            TTLPolicy.SLIDING: TTLConfiguration(TTLPolicy.SLIDING, base_ttl=600, sliding_window=300),
            TTLPolicy.ADAPTIVE: TTLConfiguration(TTLPolicy.ADAPTIVE, base_ttl=900, hit_rate_threshold=0.8),
            TTLPolicy.BUSINESS_HOURS: TTLConfiguration(TTLPolicy.BUSINESS_HOURS, base_ttl=1800, business_hours_multiplier=2.0),
            TTLPolicy.DECAY: TTLConfiguration(TTLPolicy.DECAY, base_ttl=1200, decay_factor=0.5),
            TTLPolicy.LAST_MODIFIED: TTLConfiguration(TTLPolicy.LAST_MODIFIED, base_ttl=3600),
            TTLPolicy.ACCESS_FREQUENCY: TTLConfiguration(TTLPolicy.ACCESS_FREQUENCY, base_ttl=1800, access_frequency_weight=0.3),
            TTLPolicy.COST_AWARE: TTLConfiguration(TTLPolicy.COST_AWARE, base_ttl=7200, cost_computation_factor=1.0)
        }
        
        # Access tracking for adaptive policies
        self.access_stats = defaultdict(lambda: {
            'hit_count': 0,
            'miss_count': 0,
            'last_access': time.time(),
            'access_frequency': 0.0,
            'creation_time': time.time(),
            'computation_cost': 1.0
        })
        
        # Business hours configuration (default: 9 AM - 5 PM UTC)
        self.business_hours_start = 9
        self.business_hours_end = 17
        self.business_timezone = timezone.utc
        
        self.logger.info("TTL management strategy initialized")
    
    def execute(self, key: str, policy: TTLPolicy, 
                value_metadata: Optional[Dict[str, Any]] = None, **kwargs) -> int:
        """
        Calculate and apply TTL for a cache key based on the specified policy.
        
        Args:
            key: Cache key to set TTL for
            policy: TTL policy to apply
            value_metadata: Metadata about the cached value
            **kwargs: Policy-specific parameters
            
        Returns:
            Calculated TTL in seconds
        """
        start_time = time.perf_counter()
        
        try:
            # Get policy configuration
            config = self.policy_configs.get(policy)
            if not config:
                raise CacheError(
                    f"Unknown TTL policy: {policy}",
                    error_code="INVALID_TTL_POLICY",
                    details={'policy': policy.value}
                )
            
            # Override config with kwargs
            if kwargs:
                config = self._merge_config(config, kwargs)
            
            # Calculate TTL based on policy
            if policy == TTLPolicy.FIXED:
                ttl = self._calculate_fixed_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.SLIDING:
                ttl = self._calculate_sliding_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.ADAPTIVE:
                ttl = self._calculate_adaptive_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.BUSINESS_HOURS:
                ttl = self._calculate_business_hours_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.DECAY:
                ttl = self._calculate_decay_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.LAST_MODIFIED:
                ttl = self._calculate_last_modified_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.ACCESS_FREQUENCY:
                ttl = self._calculate_access_frequency_ttl(key, config, value_metadata)
            elif policy == TTLPolicy.COST_AWARE:
                ttl = self._calculate_cost_aware_ttl(key, config, value_metadata)
            else:
                raise CacheError(
                    f"TTL policy not implemented: {policy}",
                    error_code="TTL_POLICY_NOT_IMPLEMENTED",
                    details={'policy': policy.value}
                )
            
            # Ensure TTL is within bounds
            ttl = max(config.min_ttl, min(config.max_ttl, ttl))
            
            # Apply TTL to Redis key
            if ttl > 0:
                success = self.redis_client.expire(key, ttl)
                if not success:
                    self.logger.warning(
                        "Failed to set TTL for key",
                        key=key,
                        ttl=ttl,
                        policy=policy.value
                    )
            
            # Record metrics
            calculation_time_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.record_ttl_calculation(policy, calculation_time_ms)
            
            # Update access statistics
            self._update_access_stats(key, 'ttl_set', value_metadata)
            
            self.logger.debug(
                "TTL calculated and applied",
                key=key,
                policy=policy.value,
                ttl=ttl,
                calculation_time_ms=calculation_time_ms
            )
            
            return ttl
            
        except Exception as e:
            calculation_time_ms = (time.perf_counter() - start_time) * 1000
            
            self.logger.error(
                "TTL calculation failed",
                key=key,
                policy=policy.value,
                calculation_time_ms=calculation_time_ms,
                error_message=str(e),
                error_type=type(e).__name__
            )
            
            self._handle_redis_error(e, f"TTL calculation for policy {policy.value}")
    
    def _merge_config(self, base_config: TTLConfiguration, overrides: Dict[str, Any]) -> TTLConfiguration:
        """Merge TTL configuration with override parameters."""
        config_dict = {
            'policy': base_config.policy,
            'base_ttl': overrides.get('base_ttl', base_config.base_ttl),
            'min_ttl': overrides.get('min_ttl', base_config.min_ttl),
            'max_ttl': overrides.get('max_ttl', base_config.max_ttl),
            'sliding_window': overrides.get('sliding_window', base_config.sliding_window),
            'decay_factor': overrides.get('decay_factor', base_config.decay_factor),
            'business_hours_multiplier': overrides.get('business_hours_multiplier', base_config.business_hours_multiplier),
            'hit_rate_threshold': overrides.get('hit_rate_threshold', base_config.hit_rate_threshold),
            'access_frequency_weight': overrides.get('access_frequency_weight', base_config.access_frequency_weight),
            'cost_computation_factor': overrides.get('cost_computation_factor', base_config.cost_computation_factor)
        }
        
        return TTLConfiguration(**config_dict)
    
    def _calculate_fixed_ttl(self, key: str, config: TTLConfiguration, 
                           metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate fixed TTL for predictable data."""
        return config.base_ttl
    
    def _calculate_sliding_ttl(self, key: str, config: TTLConfiguration, 
                             metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate sliding TTL based on access patterns."""
        stats = self.access_stats[key]
        current_time = time.time()
        
        # Calculate time since last access
        time_since_access = current_time - stats['last_access']
        
        # Sliding TTL: extend TTL if recently accessed
        if time_since_access < config.sliding_window:
            # Recent access - extend TTL
            extension_factor = 1.0 + (config.sliding_window - time_since_access) / config.sliding_window
            ttl = int(config.base_ttl * extension_factor)
        else:
            # No recent access - use base TTL
            ttl = config.base_ttl
        
        return ttl
    
    def _calculate_adaptive_ttl(self, key: str, config: TTLConfiguration, 
                              metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate adaptive TTL based on hit rates."""
        stats = self.access_stats[key]
        
        # Calculate hit rate
        total_accesses = stats['hit_count'] + stats['miss_count']
        if total_accesses == 0:
            hit_rate = 0.0
        else:
            hit_rate = stats['hit_count'] / total_accesses
        
        # Adaptive TTL based on hit rate
        if hit_rate >= config.hit_rate_threshold:
            # High hit rate - extend TTL
            hit_rate_factor = 1.0 + (hit_rate - config.hit_rate_threshold) / (1.0 - config.hit_rate_threshold)
            ttl = int(config.base_ttl * hit_rate_factor)
        else:
            # Low hit rate - reduce TTL
            hit_rate_factor = hit_rate / config.hit_rate_threshold
            ttl = int(config.base_ttl * hit_rate_factor)
        
        return ttl
    
    def _calculate_business_hours_ttl(self, key: str, config: TTLConfiguration, 
                                    metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate business hours-aware TTL."""
        current_time = datetime.now(self.business_timezone)
        current_hour = current_time.hour
        
        # Check if within business hours
        if self.business_hours_start <= current_hour < self.business_hours_end:
            # Business hours - shorter TTL for fresher data
            ttl = int(config.base_ttl / config.business_hours_multiplier)
        else:
            # Outside business hours - longer TTL
            ttl = int(config.base_ttl * config.business_hours_multiplier)
        
        return ttl
    
    def _calculate_decay_ttl(self, key: str, config: TTLConfiguration, 
                           metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate exponential decay TTL."""
        stats = self.access_stats[key]
        current_time = time.time()
        
        # Calculate age of the cached item
        age_seconds = current_time - stats['creation_time']
        age_hours = age_seconds / 3600
        
        # Exponential decay: TTL decreases over time
        decay_factor = math.exp(-config.decay_factor * age_hours)
        ttl = int(config.base_ttl * decay_factor)
        
        return max(config.min_ttl, ttl)
    
    def _calculate_last_modified_ttl(self, key: str, config: TTLConfiguration, 
                                   metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate TTL based on data modification time."""
        if not metadata or 'last_modified' not in metadata:
            return config.base_ttl
        
        last_modified = metadata['last_modified']
        if isinstance(last_modified, str):
            try:
                last_modified = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
            except ValueError:
                return config.base_ttl
        
        current_time = datetime.now(timezone.utc)
        if isinstance(last_modified, datetime):
            # Ensure timezone awareness
            if last_modified.tzinfo is None:
                last_modified = last_modified.replace(tzinfo=timezone.utc)
            
            # Calculate time since modification
            time_since_modification = (current_time - last_modified).total_seconds()
            
            # Recent modifications get longer TTL
            if time_since_modification < 3600:  # Less than 1 hour
                ttl = config.base_ttl * 2
            elif time_since_modification < 86400:  # Less than 1 day
                ttl = config.base_ttl
            else:
                # Old modifications get shorter TTL
                days_old = time_since_modification / 86400
                ttl = int(config.base_ttl / (1 + math.log(days_old)))
        else:
            ttl = config.base_ttl
        
        return ttl
    
    def _calculate_access_frequency_ttl(self, key: str, config: TTLConfiguration, 
                                      metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate TTL based on access frequency."""
        stats = self.access_stats[key]
        
        # Update access frequency (exponential moving average)
        current_time = time.time()
        time_since_creation = current_time - stats['creation_time']
        
        if time_since_creation > 0:
            current_frequency = stats['hit_count'] / time_since_creation
            
            # Exponential moving average
            alpha = config.access_frequency_weight
            stats['access_frequency'] = (alpha * current_frequency + 
                                       (1 - alpha) * stats['access_frequency'])
        
        # TTL based on access frequency
        if stats['access_frequency'] > 0:
            # Higher frequency gets longer TTL
            frequency_factor = 1.0 + math.log(1 + stats['access_frequency'])
            ttl = int(config.base_ttl * frequency_factor)
        else:
            ttl = config.base_ttl
        
        return ttl
    
    def _calculate_cost_aware_ttl(self, key: str, config: TTLConfiguration, 
                                metadata: Optional[Dict[str, Any]]) -> int:
        """Calculate cost-aware TTL based on computation cost."""
        stats = self.access_stats[key]
        
        # Get computation cost from metadata or use default
        computation_cost = 1.0
        if metadata and 'computation_cost' in metadata:
            computation_cost = float(metadata['computation_cost'])
        
        # Update stats with computation cost
        stats['computation_cost'] = computation_cost
        
        # Higher computation cost gets longer TTL
        cost_factor = 1.0 + (computation_cost - 1.0) * config.cost_computation_factor
        ttl = int(config.base_ttl * cost_factor)
        
        return ttl
    
    def _update_access_stats(self, key: str, access_type: str, 
                           metadata: Optional[Dict[str, Any]] = None):
        """Update access statistics for a cache key."""
        stats = self.access_stats[key]
        current_time = time.time()
        
        if access_type == 'hit':
            stats['hit_count'] += 1
        elif access_type == 'miss':
            stats['miss_count'] += 1
        elif access_type == 'ttl_set':
            # Update creation time if this is a new entry
            if stats['hit_count'] == 0 and stats['miss_count'] == 0:
                stats['creation_time'] = current_time
        
        stats['last_access'] = current_time
        
        # Update computation cost if provided
        if metadata and 'computation_cost' in metadata:
            stats['computation_cost'] = float(metadata['computation_cost'])
    
    def record_cache_access(self, key: str, access_type: str, 
                          metadata: Optional[Dict[str, Any]] = None):
        """
        Record cache access for TTL calculation algorithms.
        
        Args:
            key: Cache key that was accessed
            access_type: Type of access ('hit' or 'miss')
            metadata: Additional metadata about the access
        """
        self._update_access_stats(key, access_type, metadata)
    
    def get_recommended_ttl(self, key: str, policy: TTLPolicy, 
                          value_metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Get recommended TTL without applying it to Redis.
        
        Args:
            key: Cache key to calculate TTL for
            policy: TTL policy to use
            value_metadata: Metadata about the cached value
            
        Returns:
            Recommended TTL in seconds
        """
        config = self.policy_configs.get(policy, self.policy_configs[TTLPolicy.FIXED])
        
        if policy == TTLPolicy.FIXED:
            return self._calculate_fixed_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.SLIDING:
            return self._calculate_sliding_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.ADAPTIVE:
            return self._calculate_adaptive_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.BUSINESS_HOURS:
            return self._calculate_business_hours_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.DECAY:
            return self._calculate_decay_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.LAST_MODIFIED:
            return self._calculate_last_modified_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.ACCESS_FREQUENCY:
            return self._calculate_access_frequency_ttl(key, config, value_metadata)
        elif policy == TTLPolicy.COST_AWARE:
            return self._calculate_cost_aware_ttl(key, config, value_metadata)
        else:
            return config.base_ttl
    
    def configure_policy(self, policy: TTLPolicy, **config_params):
        """
        Configure TTL policy parameters.
        
        Args:
            policy: TTL policy to configure
            **config_params: Policy configuration parameters
        """
        if policy not in self.policy_configs:
            raise CacheError(
                f"Unknown TTL policy: {policy}",
                error_code="INVALID_TTL_POLICY"
            )
        
        current_config = self.policy_configs[policy]
        
        # Create new configuration with updated parameters
        config_dict = {
            'policy': policy,
            'base_ttl': config_params.get('base_ttl', current_config.base_ttl),
            'min_ttl': config_params.get('min_ttl', current_config.min_ttl),
            'max_ttl': config_params.get('max_ttl', current_config.max_ttl),
            'sliding_window': config_params.get('sliding_window', current_config.sliding_window),
            'decay_factor': config_params.get('decay_factor', current_config.decay_factor),
            'business_hours_multiplier': config_params.get('business_hours_multiplier', current_config.business_hours_multiplier),
            'hit_rate_threshold': config_params.get('hit_rate_threshold', current_config.hit_rate_threshold),
            'access_frequency_weight': config_params.get('access_frequency_weight', current_config.access_frequency_weight),
            'cost_computation_factor': config_params.get('cost_computation_factor', current_config.cost_computation_factor)
        }
        
        self.policy_configs[policy] = TTLConfiguration(**config_dict)
        
        self.logger.info(
            "TTL policy configuration updated",
            policy=policy.value,
            updated_params=list(config_params.keys())
        )


class CacheKeyPatternManager(BaseCacheStrategy):
    """
    Cache key pattern organization and namespace management for structured
    cache operations and multi-tenant cache strategies.
    
    Provides enterprise-grade cache key organization with namespace hierarchy,
    pattern validation, and distributed cache coordination per Section 5.2.7
    cache key pattern organization requirements.
    """
    
    def __init__(self, redis_client: Optional[RedisClient] = None, 
                 monitoring: Optional[CacheMonitoringManager] = None):
        super().__init__(redis_client, monitoring)
        
        # Registered cache key patterns
        self.patterns = {}  # pattern_name -> CacheKeyPattern
        self.namespace_registry = defaultdict(set)  # namespace -> set of pattern_names
        
        # Pattern usage statistics
        self.pattern_usage_stats = defaultdict(int)
        self.pattern_generation_times = defaultdict(list)
        
        # Default patterns for common use cases
        self._register_default_patterns()
        
        self.logger.info("Cache key pattern manager initialized")
    
    def execute(self, pattern_name: str, **kwargs) -> str:
        """
        Generate cache key using registered pattern.
        
        Args:
            pattern_name: Name of the registered pattern
            **kwargs: Parameters for key generation
            
        Returns:
            Generated cache key
        """
        start_time = time.perf_counter()
        
        try:
            if pattern_name not in self.patterns:
                raise CacheKeyError(
                    f"Unknown cache key pattern: {pattern_name}",
                    key_pattern=pattern_name,
                    validation_errors=[f"Pattern '{pattern_name}' not registered"]
                )
            
            pattern = self.patterns[pattern_name]
            
            # Generate key using pattern
            cache_key = pattern.generate_key(**kwargs)
            
            # Record usage statistics
            generation_time_ms = (time.perf_counter() - start_time) * 1000
            self.pattern_usage_stats[pattern_name] += 1
            self.pattern_generation_times[pattern_name].append(generation_time_ms)
            
            # Limit stored generation times
            if len(self.pattern_generation_times[pattern_name]) > 1000:
                self.pattern_generation_times[pattern_name] = \
                    self.pattern_generation_times[pattern_name][-1000:]
            
            # Update monitoring
            if self.monitoring:
                self.monitoring.record_cache_operation('key_generation', 'redis', generation_time_ms / 1000, 'success')
            
            self.metrics.record_pattern_usage(pattern_name)
            
            self.logger.debug(
                "Cache key generated",
                pattern_name=pattern_name,
                cache_key=cache_key,
                generation_time_ms=generation_time_ms,
                parameters=list(kwargs.keys())
            )
            
            return cache_key
            
        except Exception as e:
            generation_time_ms = (time.perf_counter() - start_time) * 1000
            
            # Update monitoring for failure
            if self.monitoring:
                self.monitoring.record_cache_operation('key_generation', 'redis', generation_time_ms / 1000, 'error')
            
            self.logger.error(
                "Cache key generation failed",
                pattern_name=pattern_name,
                generation_time_ms=generation_time_ms,
                error_message=str(e),
                error_type=type(e).__name__,
                parameters=list(kwargs.keys())
            )
            
            if isinstance(e, CacheKeyError):
                raise
            else:
                raise CacheKeyError(
                    f"Key generation failed for pattern '{pattern_name}': {str(e)}",
                    key_pattern=pattern_name
                )
    
    def register_pattern(self, pattern_name: str, pattern: CacheKeyPattern) -> None:
        """
        Register a cache key pattern for organized key generation.
        
        Args:
            pattern_name: Unique name for the pattern
            pattern: CacheKeyPattern instance defining the pattern
        """
        if pattern_name in self.patterns:
            self.logger.warning(
                "Overwriting existing cache key pattern",
                pattern_name=pattern_name,
                old_namespace=self.patterns[pattern_name].namespace,
                new_namespace=pattern.namespace
            )
        
        # Register pattern
        self.patterns[pattern_name] = pattern
        self.namespace_registry[pattern.namespace].add(pattern_name)
        
        self.logger.info(
            "Cache key pattern registered",
            pattern_name=pattern_name,
            namespace=pattern.namespace,
            pattern=pattern.pattern,
            ttl_policy=pattern.ttl_policy.value,
            invalidation_pattern=pattern.invalidation_pattern.value
        )
    
    def _register_default_patterns(self) -> None:
        """Register default cache key patterns for common use cases."""
        # User-related patterns
        self.register_pattern('user_profile', CacheKeyPattern(
            namespace='user',
            pattern='user:{user_id}:profile',
            ttl_policy=TTLPolicy.SLIDING,
            invalidation_pattern=CacheInvalidationPattern.IMMEDIATE,
            priority=1,
            tags={'user', 'profile'}
        ))
        
        self.register_pattern('user_session', CacheKeyPattern(
            namespace='session',
            pattern='session:{session_id}:user:{user_id}',
            ttl_policy=TTLPolicy.SLIDING,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=1,
            tags={'session', 'user'}
        ))
        
        self.register_pattern('user_permissions', CacheKeyPattern(
            namespace='auth',
            pattern='auth:permissions:user:{user_id}',
            ttl_policy=TTLPolicy.FIXED,
            invalidation_pattern=CacheInvalidationPattern.EVENT_DRIVEN,
            priority=1,
            tags={'auth', 'permissions'}
        ))
        
        # API-related patterns
        self.register_pattern('api_response', CacheKeyPattern(
            namespace='api',
            pattern='api:{endpoint}:params:{params_hash}',
            ttl_policy=TTLPolicy.BUSINESS_HOURS,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=2,
            tags={'api', 'response'}
        ))
        
        self.register_pattern('api_rate_limit', CacheKeyPattern(
            namespace='rate_limit',
            pattern='rate_limit:{client_id}:{endpoint}:{window}',
            ttl_policy=TTLPolicy.FIXED,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=1,
            tags={'rate_limit', 'api'}
        ))
        
        # Database-related patterns
        self.register_pattern('db_query_result', CacheKeyPattern(
            namespace='db',
            pattern='db:query:{query_hash}:params:{params_hash}',
            ttl_policy=TTLPolicy.COST_AWARE,
            invalidation_pattern=CacheInvalidationPattern.WRITE_THROUGH,
            priority=3,
            tags={'database', 'query'}
        ))
        
        self.register_pattern('db_entity', CacheKeyPattern(
            namespace='entity',
            pattern='entity:{entity_type}:{entity_id}',
            ttl_policy=TTLPolicy.ADAPTIVE,
            invalidation_pattern=CacheInvalidationPattern.CASCADE,
            priority=2,
            tags={'database', 'entity'}
        ))
        
        # Business logic patterns
        self.register_pattern('business_calculation', CacheKeyPattern(
            namespace='business',
            pattern='business:{operation}:input:{input_hash}',
            ttl_policy=TTLPolicy.COST_AWARE,
            invalidation_pattern=CacheInvalidationPattern.LAZY,
            priority=3,
            tags={'business', 'calculation'}
        ))
        
        # External service patterns
        self.register_pattern('external_api', CacheKeyPattern(
            namespace='external',
            pattern='external:{service}:{endpoint}:params:{params_hash}',
            ttl_policy=TTLPolicy.DECAY,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=4,
            tags={'external', 'api'}
        ))
        
        # Temporary data patterns
        self.register_pattern('temp_data', CacheKeyPattern(
            namespace='temp',
            pattern='temp:{operation}:{unique_id}',
            ttl_policy=TTLPolicy.FIXED,
            invalidation_pattern=CacheInvalidationPattern.TIME_BASED,
            priority=5,
            tags={'temporary'}
        ))
    
    def get_pattern(self, pattern_name: str) -> Optional[CacheKeyPattern]:
        """
        Get registered cache key pattern by name.
        
        Args:
            pattern_name: Name of the pattern to retrieve
            
        Returns:
            CacheKeyPattern instance or None if not found
        """
        return self.patterns.get(pattern_name)
    
    def list_patterns(self, namespace: Optional[str] = None) -> Dict[str, CacheKeyPattern]:
        """
        List registered cache key patterns, optionally filtered by namespace.
        
        Args:
            namespace: Optional namespace to filter patterns
            
        Returns:
            Dictionary of pattern_name -> CacheKeyPattern
        """
        if namespace:
            pattern_names = self.namespace_registry.get(namespace, set())
            return {name: self.patterns[name] for name in pattern_names}
        else:
            return self.patterns.copy()
    
    def validate_key_against_patterns(self, key: str) -> List[str]:
        """
        Validate cache key against registered patterns and return matching patterns.
        
        Args:
            key: Cache key to validate
            
        Returns:
            List of pattern names that match the key
        """
        matching_patterns = []
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.matches_key(key):
                matching_patterns.append(pattern_name)
        
        return matching_patterns
    
    def generate_pattern_hash(self, **params) -> str:
        """
        Generate hash for parameters to use in cache key patterns.
        
        Args:
            **params: Parameters to hash
            
        Returns:
            Hexadecimal hash string
        """
        # Sort parameters for consistent hashing
        sorted_params = sorted(params.items())
        param_string = json.dumps(sorted_params, sort_keys=True, separators=(',', ':'))
        
        # Generate SHA-256 hash
        hash_obj = hashlib.sha256(param_string.encode('utf-8'))
        return hash_obj.hexdigest()[:16]  # Use first 16 characters for brevity
    
    def create_namespace_hierarchy(self, namespace: str, parent_namespace: Optional[str] = None) -> None:
        """
        Create namespace hierarchy for organized cache management.
        
        Args:
            namespace: Namespace to create
            parent_namespace: Optional parent namespace for hierarchy
        """
        if parent_namespace and parent_namespace not in self.namespace_registry:
            raise CacheKeyError(
                f"Parent namespace does not exist: {parent_namespace}",
                validation_errors=[f"Parent namespace '{parent_namespace}' not found"]
            )
        
        if namespace not in self.namespace_registry:
            self.namespace_registry[namespace] = set()
        
        self.logger.info(
            "Cache namespace created",
            namespace=namespace,
            parent_namespace=parent_namespace
        )
    
    def get_keys_by_namespace(self, namespace: str, limit: int = 1000) -> List[str]:
        """
        Get cache keys belonging to a specific namespace.
        
        Args:
            namespace: Namespace to search
            limit: Maximum number of keys to return
            
        Returns:
            List of cache keys in the namespace
        """
        pattern = f"{namespace}:*"
        
        try:
            matching_keys = []
            cursor = 0
            
            while len(matching_keys) < limit:
                cursor, keys = self.redis_client._redis_client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=min(100, limit - len(matching_keys))
                )
                
                matching_keys.extend(keys)
                
                if cursor == 0:  # Scan completed
                    break
            
            return matching_keys[:limit]
            
        except Exception as e:
            self.logger.warning(
                "Failed to get keys by namespace",
                namespace=namespace,
                error_message=str(e)
            )
            return []
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get cache key pattern usage statistics."""
        stats = {
            'total_patterns': len(self.patterns),
            'namespaces': list(self.namespace_registry.keys()),
            'pattern_usage': dict(self.pattern_usage_stats),
            'pattern_performance': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Calculate performance metrics for each pattern
        for pattern_name, generation_times in self.pattern_generation_times.items():
            if generation_times:
                stats['pattern_performance'][pattern_name] = {
                    'avg_generation_time_ms': sum(generation_times) / len(generation_times),
                    'max_generation_time_ms': max(generation_times),
                    'min_generation_time_ms': min(generation_times),
                    'total_generations': len(generation_times),
                    'usage_count': self.pattern_usage_stats[pattern_name]
                }
        
        return stats


class CacheWarmingStrategy(BaseCacheStrategy):
    """
    Intelligent cache warming strategy for proactive cache population and
    performance optimization through predictive and scheduled cache operations.
    
    Implements sophisticated cache warming patterns including preload, background,
    predictive, and demand-driven warming strategies per Section 5.2.7 performance
    optimization requirements for enhanced user experience.
    """
    
    def __init__(self, redis_client: Optional[RedisClient] = None, 
                 monitoring: Optional[CacheMonitoringManager] = None):
        super().__init__(redis_client, monitoring)
        
        # Warming strategy configurations
        self.warming_configs = {
            CacheWarmingStrategy.PRELOAD: {
                'batch_size': 100,
                'concurrent_limit': 5,
                'timeout': 300,
                'priority': 1
            },
            CacheWarmingStrategy.BACKGROUND: {
                'batch_size': 50,
                'concurrent_limit': 2,
                'timeout': 600,
                'priority': 3
            },
            CacheWarmingStrategy.PREDICTIVE: {
                'batch_size': 20,
                'concurrent_limit': 3,
                'timeout': 180,
                'priority': 2
            },
            CacheWarmingStrategy.SCHEDULE_BASED: {
                'batch_size': 200,
                'concurrent_limit': 4,
                'timeout': 900,
                'priority': 4
            },
            CacheWarmingStrategy.DEMAND_DRIVEN: {
                'batch_size': 10,
                'concurrent_limit': 1,
                'timeout': 60,
                'priority': 1
            },
            CacheWarmingStrategy.CASCADING: {
                'batch_size': 30,
                'concurrent_limit': 2,
                'timeout': 240,
                'priority': 2
            }
        }
        
        # Warming operation tracking
        self.warming_queue = defaultdict(deque)
        self.warming_locks = defaultdict(Lock)
        self.warming_history = defaultdict(list)
        
        # Predictive warming data
        self.access_patterns = defaultdict(lambda: {
            'hourly_access_counts': defaultdict(int),
            'daily_access_patterns': defaultdict(int),
            'access_sequences': deque(maxlen=1000),
            'prediction_accuracy': 0.0
        })
        
        self.logger.info("Cache warming strategy initialized")
    
    def execute(self, strategy: CacheWarmingStrategy, warming_spec: Dict[str, Any], 
                **kwargs) -> Dict[str, Any]:
        """
        Execute cache warming strategy with specified parameters.
        
        Args:
            strategy: Cache warming strategy to execute
            warming_spec: Specification for warming operations
            **kwargs: Additional strategy-specific parameters
            
        Returns:
            Dictionary containing warming results and metrics
        """
        start_time = time.perf_counter()
        
        try:
            if strategy == CacheWarmingStrategy.PRELOAD:
                result = self._preload_warming(warming_spec, **kwargs)
            elif strategy == CacheWarmingStrategy.BACKGROUND:
                result = self._background_warming(warming_spec, **kwargs)
            elif strategy == CacheWarmingStrategy.PREDICTIVE:
                result = self._predictive_warming(warming_spec, **kwargs)
            elif strategy == CacheWarmingStrategy.SCHEDULE_BASED:
                result = self._schedule_based_warming(warming_spec, **kwargs)
            elif strategy == CacheWarmingStrategy.DEMAND_DRIVEN:
                result = self._demand_driven_warming(warming_spec, **kwargs)
            elif strategy == CacheWarmingStrategy.CASCADING:
                result = self._cascading_warming(warming_spec, **kwargs)
            else:
                raise CacheError(
                    f"Unsupported cache warming strategy: {strategy}",
                    error_code="UNSUPPORTED_WARMING_STRATEGY",
                    details={'strategy': strategy.value}
                )
            
            # Record metrics
            duration_ms = (time.perf_counter() - start_time) * 1000
            success = result.get('success_count', 0) > 0
            
            self.metrics.record_warming_operation(
                strategy, 
                success, 
                result.get('success_count', 0)
            )
            
            # Update monitoring
            if self.monitoring:
                self.monitoring.record_cache_operation('warming', 'redis', duration_ms / 1000, 'success' if success else 'error')
            
            self.logger.info(
                "Cache warming completed",
                strategy=strategy.value,
                duration_ms=duration_ms,
                success_count=result.get('success_count', 0),
                error_count=result.get('error_count', 0),
                total_operations=result.get('total_operations', 0)
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Update monitoring for failure
            if self.monitoring:
                self.monitoring.record_cache_operation('warming', 'redis', duration_ms / 1000, 'error')
            
            self.logger.error(
                "Cache warming failed",
                strategy=strategy.value,
                duration_ms=duration_ms,
                error_message=str(e),
                error_type=type(e).__name__
            )
            
            self._handle_redis_error(e, f"cache warming with strategy {strategy.value}")
    
    def _preload_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Preload cache warming during application startup.
        
        Args:
            warming_spec: Warming specification with data sources and keys
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        config = self.warming_configs[CacheWarmingStrategy.PRELOAD]
        batch_size = kwargs.get('batch_size', config['batch_size'])
        
        data_sources = warming_spec.get('data_sources', [])
        static_keys = warming_spec.get('static_keys', [])
        
        total_operations = 0
        success_count = 0
        error_count = 0
        errors = []
        
        # Warm static keys first
        if static_keys:
            static_result = self._warm_static_keys(static_keys, batch_size)
            total_operations += static_result['total_operations']
            success_count += static_result['success_count']
            error_count += static_result['error_count']
            errors.extend(static_result['errors'])
        
        # Warm data from sources
        for data_source in data_sources:
            try:
                source_result = self._warm_from_data_source(data_source, batch_size)
                total_operations += source_result['total_operations']
                success_count += source_result['success_count']
                error_count += source_result['error_count']
                errors.extend(source_result['errors'])
                
            except Exception as e:
                error_msg = f"Preload warming failed for data source: {str(e)}"
                errors.append(error_msg)
                error_count += 1
        
        return {
            'strategy': CacheWarmingStrategy.PRELOAD.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _background_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Background cache warming during normal operation.
        
        Args:
            warming_spec: Warming specification
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        warming_patterns = warming_spec.get('warming_patterns', [])
        priority_threshold = kwargs.get('priority_threshold', 3)
        
        total_operations = 0
        success_count = 0
        error_count = 0
        
        # Process warming patterns based on priority
        for pattern in warming_patterns:
            pattern_priority = pattern.get('priority', 5)
            
            if pattern_priority <= priority_threshold:
                try:
                    pattern_result = self._warm_pattern(pattern)
                    total_operations += pattern_result['total_operations']
                    success_count += pattern_result['success_count']
                    error_count += pattern_result['error_count']
                    
                except Exception as e:
                    error_count += 1
                    self.logger.warning(
                        "Background warming pattern failed",
                        pattern=pattern.get('name', 'unknown'),
                        error_message=str(e)
                    )
        
        return {
            'strategy': CacheWarmingStrategy.BACKGROUND.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'patterns_processed': len(warming_patterns),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _predictive_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Predictive cache warming based on access patterns.
        
        Args:
            warming_spec: Warming specification with prediction parameters
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        prediction_window = kwargs.get('prediction_window', 3600)  # 1 hour
        confidence_threshold = kwargs.get('confidence_threshold', 0.7)
        
        # Generate predictions based on access patterns
        predictions = self._generate_access_predictions(prediction_window, confidence_threshold)
        
        total_operations = 0
        success_count = 0
        error_count = 0
        
        # Warm predicted keys
        for prediction in predictions:
            key = prediction['key']
            confidence = prediction['confidence']
            
            if confidence >= confidence_threshold:
                try:
                    # Generate or retrieve value for predicted key
                    value_generator = warming_spec.get('value_generator')
                    if value_generator and callable(value_generator):
                        value = value_generator(key)
                        
                        # Warm cache with predicted value
                        ttl = prediction.get('predicted_ttl', 3600)
                        success = self.redis_client.set(key, value, ttl=ttl)
                        
                        if success:
                            success_count += 1
                        else:
                            error_count += 1
                        
                        total_operations += 1
                        
                except Exception as e:
                    error_count += 1
                    self.logger.warning(
                        "Predictive warming failed for key",
                        key=key,
                        confidence=confidence,
                        error_message=str(e)
                    )
        
        return {
            'strategy': CacheWarmingStrategy.PREDICTIVE.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'predictions_generated': len(predictions),
            'average_confidence': sum(p['confidence'] for p in predictions) / len(predictions) if predictions else 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _schedule_based_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Schedule-based cache warming with time-based triggers.
        
        Args:
            warming_spec: Warming specification with schedule information
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        schedule_rules = warming_spec.get('schedule_rules', [])
        current_time = datetime.now(timezone.utc)
        
        total_operations = 0
        success_count = 0
        error_count = 0
        executed_rules = 0
        
        for rule in schedule_rules:
            try:
                # Check if rule should execute
                if self._should_execute_schedule_rule(rule, current_time):
                    rule_result = self._execute_warming_rule(rule)
                    total_operations += rule_result['total_operations']
                    success_count += rule_result['success_count']
                    error_count += rule_result['error_count']
                    executed_rules += 1
                    
            except Exception as e:
                error_count += 1
                self.logger.warning(
                    "Schedule-based warming rule failed",
                    rule_name=rule.get('name', 'unknown'),
                    error_message=str(e)
                )
        
        return {
            'strategy': CacheWarmingStrategy.SCHEDULE_BASED.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'total_rules': len(schedule_rules),
            'executed_rules': executed_rules,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _demand_driven_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Demand-driven cache warming triggered by cache misses.
        
        Args:
            warming_spec: Warming specification with miss handling
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        miss_keys = warming_spec.get('miss_keys', [])
        related_keys_generator = warming_spec.get('related_keys_generator')
        
        total_operations = 0
        success_count = 0
        error_count = 0
        
        for miss_key in miss_keys:
            try:
                # Generate related keys that should be warmed
                related_keys = []
                if related_keys_generator and callable(related_keys_generator):
                    related_keys = related_keys_generator(miss_key)
                
                # Warm related keys
                for related_key in related_keys:
                    value_generator = warming_spec.get('value_generator')
                    if value_generator and callable(value_generator):
                        value = value_generator(related_key)
                        success = self.redis_client.set(related_key, value, ttl=3600)
                        
                        if success:
                            success_count += 1
                        else:
                            error_count += 1
                        
                        total_operations += 1
                        
            except Exception as e:
                error_count += 1
                self.logger.warning(
                    "Demand-driven warming failed for miss key",
                    miss_key=miss_key,
                    error_message=str(e)
                )
        
        return {
            'strategy': CacheWarmingStrategy.DEMAND_DRIVEN.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'miss_keys_processed': len(miss_keys),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _cascading_warming(self, warming_spec: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Cascading cache warming for related data.
        
        Args:
            warming_spec: Warming specification with cascade rules
            **kwargs: Additional parameters
            
        Returns:
            Warming results
        """
        root_keys = warming_spec.get('root_keys', [])
        cascade_rules = warming_spec.get('cascade_rules', [])
        max_cascade_depth = kwargs.get('max_cascade_depth', 3)
        
        total_operations = 0
        success_count = 0
        error_count = 0
        
        # Process each root key with cascading
        for root_key in root_keys:
            try:
                cascade_result = self._execute_cascade_warming(
                    root_key, 
                    cascade_rules, 
                    max_cascade_depth,
                    warming_spec.get('value_generator')
                )
                total_operations += cascade_result['total_operations']
                success_count += cascade_result['success_count']
                error_count += cascade_result['error_count']
                
            except Exception as e:
                error_count += 1
                self.logger.warning(
                    "Cascading warming failed for root key",
                    root_key=root_key,
                    error_message=str(e)
                )
        
        return {
            'strategy': CacheWarmingStrategy.CASCADING.value,
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'root_keys_processed': len(root_keys),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _warm_static_keys(self, static_keys: List[Dict[str, Any]], batch_size: int) -> Dict[str, Any]:
        """Warm cache with static key-value pairs."""
        total_operations = len(static_keys)
        success_count = 0
        error_count = 0
        errors = []
        
        # Process in batches
        for i in range(0, len(static_keys), batch_size):
            batch = static_keys[i:i + batch_size]
            
            try:
                pipeline = self.redis_client.pipeline()
                
                for key_spec in batch:
                    key = key_spec.get('key')
                    value = key_spec.get('value')
                    ttl = key_spec.get('ttl', 3600)
                    
                    pipeline.set(key, value, ttl=ttl)
                
                results = pipeline.execute()
                success_count += sum(1 for result in results if result)
                
            except Exception as e:
                error_count += len(batch)
                error_msg = f"Static key warming batch failed: {str(e)}"
                errors.append(error_msg)
        
        return {
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors
        }
    
    def _warm_from_data_source(self, data_source: Dict[str, Any], batch_size: int) -> Dict[str, Any]:
        """Warm cache from external data source."""
        source_type = data_source.get('type')
        source_config = data_source.get('config', {})
        
        # This would be implemented based on specific data source types
        # For now, return a placeholder result
        return {
            'total_operations': 0,
            'success_count': 0,
            'error_count': 0,
            'errors': []
        }
    
    def _warm_pattern(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Warm cache based on a specific pattern."""
        pattern_name = pattern.get('name', 'unknown')
        key_generator = pattern.get('key_generator')
        value_generator = pattern.get('value_generator')
        key_count = pattern.get('key_count', 10)
        
        total_operations = 0
        success_count = 0
        error_count = 0
        
        if key_generator and value_generator and callable(key_generator) and callable(value_generator):
            try:
                # Generate keys and values for warming
                keys = key_generator(key_count)
                
                for key in keys:
                    value = value_generator(key)
                    success = self.redis_client.set(key, value, ttl=3600)
                    
                    if success:
                        success_count += 1
                    else:
                        error_count += 1
                    
                    total_operations += 1
                    
            except Exception as e:
                error_count += key_count
                self.logger.warning(
                    "Pattern warming failed",
                    pattern_name=pattern_name,
                    error_message=str(e)
                )
        
        return {
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count
        }
    
    def _generate_access_predictions(self, prediction_window: int, confidence_threshold: float) -> List[Dict[str, Any]]:
        """Generate predictions for cache access patterns."""
        predictions = []
        
        for key, pattern_data in self.access_patterns.items():
            # Simple prediction based on historical access patterns
            hourly_counts = pattern_data['hourly_access_counts']
            
            if hourly_counts:
                current_hour = datetime.now(timezone.utc).hour
                next_hour = (current_hour + 1) % 24
                
                # Predict access probability for next hour
                historical_access = hourly_counts.get(next_hour, 0)
                total_historical = sum(hourly_counts.values())
                
                if total_historical > 0:
                    access_probability = historical_access / total_historical
                    
                    if access_probability >= confidence_threshold:
                        predictions.append({
                            'key': key,
                            'confidence': access_probability,
                            'predicted_time': next_hour,
                            'predicted_ttl': max(3600, int(3600 * access_probability))
                        })
        
        # Sort by confidence
        predictions.sort(key=lambda p: p['confidence'], reverse=True)
        
        return predictions[:100]  # Limit predictions
    
    def _should_execute_schedule_rule(self, rule: Dict[str, Any], current_time: datetime) -> bool:
        """Check if a schedule rule should execute at the current time."""
        schedule_type = rule.get('schedule_type', 'hourly')
        
        if schedule_type == 'hourly':
            return current_time.minute == rule.get('minute', 0)
        elif schedule_type == 'daily':
            return (current_time.hour == rule.get('hour', 0) and 
                   current_time.minute == rule.get('minute', 0))
        elif schedule_type == 'weekly':
            return (current_time.weekday() == rule.get('weekday', 0) and
                   current_time.hour == rule.get('hour', 0) and
                   current_time.minute == rule.get('minute', 0))
        
        return False
    
    def _execute_warming_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a warming rule with specified parameters."""
        rule_type = rule.get('type', 'static')
        
        if rule_type == 'static':
            static_keys = rule.get('keys', [])
            return self._warm_static_keys(static_keys, 50)
        elif rule_type == 'pattern':
            return self._warm_pattern(rule)
        else:
            return {
                'total_operations': 0,
                'success_count': 0,
                'error_count': 1
            }
    
    def _execute_cascade_warming(self, root_key: str, cascade_rules: List[Dict[str, Any]], 
                                max_depth: int, value_generator: Optional[Callable]) -> Dict[str, Any]:
        """Execute cascading warming from a root key."""
        total_operations = 0
        success_count = 0
        error_count = 0
        
        # This would implement cascade logic based on rules
        # For now, return placeholder result
        
        return {
            'total_operations': total_operations,
            'success_count': success_count,
            'error_count': error_count
        }
    
    def record_cache_access(self, key: str, access_time: Optional[datetime] = None):
        """
        Record cache access for predictive warming algorithms.
        
        Args:
            key: Cache key that was accessed
            access_time: Time of access (default: current time)
        """
        if access_time is None:
            access_time = datetime.now(timezone.utc)
        
        pattern_data = self.access_patterns[key]
        
        # Update hourly access counts
        pattern_data['hourly_access_counts'][access_time.hour] += 1
        
        # Update daily patterns (day of week)
        pattern_data['daily_access_patterns'][access_time.weekday()] += 1
        
        # Update access sequence
        pattern_data['access_sequences'].append(access_time.timestamp())
        
        # Limit historical data
        max_hourly_history = 24 * 7  # One week
        if sum(pattern_data['hourly_access_counts'].values()) > max_hourly_history:
            # Remove oldest hour data
            oldest_hour = min(pattern_data['hourly_access_counts'].keys())
            pattern_data['hourly_access_counts'][oldest_hour] -= 1
            if pattern_data['hourly_access_counts'][oldest_hour] <= 0:
                del pattern_data['hourly_access_counts'][oldest_hour]


# Export cache strategy components for application integration
__all__ = [
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
    'CacheWarmingStrategy'
]