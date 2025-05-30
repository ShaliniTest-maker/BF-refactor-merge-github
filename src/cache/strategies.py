"""
Cache Invalidation Strategies and TTL Management Module

This module implements intelligent cache invalidation patterns, TTL management policies,
cache key pattern organization, and cache warming strategies for enterprise-grade
cache lifecycle optimization and data consistency. Designed to provide equivalent
performance to Node.js caching patterns while supporting distributed cache coordination
and multi-tenant cache management per Section 5.2.7 and Section 6.1.3.

Key Features:
- Intelligent cache invalidation strategies for data consistency
- Dynamic TTL management policies for cache lifecycle optimization
- Hierarchical cache key pattern organization with namespace management
- Proactive cache warming strategies for performance optimization
- Multi-tenant cache namespace management for enterprise deployments
- Cache partitioning and distributed coordination for horizontal scaling
- Fallback cache strategies for resilience and graceful degradation

Performance Requirements:
- Maintain ≤10% variance from Node.js baseline per Section 0.1.1
- Support distributed cache coordination across multiple Flask instances
- Optimize cache effectiveness through intelligent warming and invalidation
- Provide enterprise-grade cache lifecycle management
"""

import hashlib
import json
import time
import threading
import weakref
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Union, Callable, Pattern, Tuple,
    NamedTuple, TypeVar, Generic
)
import re
import asyncio
from contextlib import asynccontextmanager
import structlog
from threading import RLock

# Import monitoring for metrics tracking
from .monitoring import cache_monitor, monitor_cache_operation

# Configure structured logging for enterprise integration
logger = structlog.get_logger(__name__)

# Type definitions for better type safety
CacheKey = str
CacheValue = Any
NamespaceId = str
TenantId = str
ExpirationTime = Union[int, float, timedelta]

T = TypeVar('T')


class CacheInvalidationTrigger(Enum):
    """
    Enumeration of cache invalidation trigger types for data consistency.
    
    Provides structured invalidation events that can trigger cache cleanup
    operations based on various system events and data changes.
    """
    MANUAL = "manual"              # Explicit invalidation request
    TTL_EXPIRED = "ttl_expired"    # Time-based expiration
    DATA_UPDATED = "data_updated"  # Underlying data modification
    DEPENDENCY_CHANGED = "dependency_changed"  # Dependent cache entry changed
    MEMORY_PRESSURE = "memory_pressure"  # Memory usage threshold exceeded
    PATTERN_MATCH = "pattern_match"  # Pattern-based bulk invalidation
    EVENT_DRIVEN = "event_driven"  # External event notification
    HEALTH_CHECK = "health_check"  # Periodic health check cleanup


class CacheWarmingPriority(Enum):
    """
    Cache warming priority levels for intelligent preloading strategies.
    
    Defines priority ordering for cache warming operations to optimize
    resource usage and ensure critical data is loaded first.
    """
    CRITICAL = 1    # Business-critical data requiring immediate availability
    HIGH = 2        # Frequently accessed data with high performance impact
    MEDIUM = 3      # Moderately accessed data for general performance
    LOW = 4         # Background data for opportunistic warming
    BACKGROUND = 5  # Lowest priority for bulk warming operations


class TTLPolicy(Enum):
    """
    TTL management policy types for cache lifecycle optimization.
    
    Defines different strategies for determining cache entry expiration
    times based on access patterns and data characteristics.
    """
    STATIC = "static"              # Fixed TTL value
    SLIDING = "sliding"            # Reset TTL on access
    ADAPTIVE = "adaptive"          # Adjust TTL based on usage patterns
    HIERARCHICAL = "hierarchical"  # TTL inheritance from parent namespaces
    PERFORMANCE_BASED = "performance_based"  # TTL based on performance metrics


@dataclass
class CacheKeyPattern:
    """
    Cache key pattern definition for organized key structure management.
    
    Provides structured approach to cache key organization with namespace
    support, versioning, and pattern-based operations for enterprise
    cache management requirements.
    """
    namespace: str                    # Primary namespace identifier
    entity_type: str                 # Type of cached entity (user, session, etc.)
    identifier: str                  # Unique entity identifier
    version: Optional[str] = None    # Optional version for cache migration
    tenant_id: Optional[str] = None  # Multi-tenant isolation identifier
    sub_namespace: Optional[str] = None  # Additional namespace subdivision
    
    def to_key(self) -> CacheKey:
        """
        Generate standardized cache key from pattern components.
        
        Returns:
            Formatted cache key string with proper namespace hierarchy
        """
        key_parts = [self.namespace]
        
        if self.tenant_id:
            key_parts.append(f"tenant:{self.tenant_id}")
        
        if self.sub_namespace:
            key_parts.append(self.sub_namespace)
        
        key_parts.extend([self.entity_type, self.identifier])
        
        if self.version:
            key_parts.append(f"v:{self.version}")
        
        return ":".join(key_parts)
    
    @classmethod
    def from_key(cls, key: CacheKey) -> Optional['CacheKeyPattern']:
        """
        Parse cache key back into pattern components.
        
        Args:
            key: Cache key string to parse
            
        Returns:
            CacheKeyPattern instance or None if parsing fails
        """
        try:
            parts = key.split(":")
            if len(parts) < 3:
                return None
            
            namespace = parts[0]
            tenant_id = None
            sub_namespace = None
            version = None
            
            # Parse optional components
            idx = 1
            if idx < len(parts) and parts[idx].startswith("tenant:"):
                tenant_id = parts[idx][7:]  # Remove "tenant:" prefix
                idx += 1
            
            if idx < len(parts) and not parts[idx] in ["user", "session", "data", "auth"]:
                sub_namespace = parts[idx]
                idx += 1
            
            if idx + 1 < len(parts):
                entity_type = parts[idx]
                identifier = parts[idx + 1]
                idx += 2
            else:
                return None
            
            if idx < len(parts) and parts[idx].startswith("v:"):
                version = parts[idx][2:]  # Remove "v:" prefix
            
            return cls(
                namespace=namespace,
                entity_type=entity_type,
                identifier=identifier,
                version=version,
                tenant_id=tenant_id,
                sub_namespace=sub_namespace
            )
        except Exception as e:
            logger.warning(
                "cache_key_parsing_failed",
                key=key,
                error_message=str(e)
            )
            return None


@dataclass
class TTLConfiguration:
    """
    TTL configuration with policy-specific parameters for cache lifecycle management.
    
    Provides comprehensive TTL management configuration supporting various
    expiration strategies and performance optimization parameters.
    """
    policy: TTLPolicy
    base_ttl_seconds: int                    # Base TTL value in seconds
    min_ttl_seconds: int = 60               # Minimum TTL to prevent thrashing
    max_ttl_seconds: int = 86400            # Maximum TTL for memory management
    sliding_window_seconds: int = 3600      # Sliding window extension on access
    adaptive_factor: float = 1.0            # Adaptive adjustment multiplier
    performance_threshold_ms: float = 100.0 # Performance threshold for adaptive TTL
    
    def calculate_ttl(self, access_count: int = 0, avg_latency_ms: float = 0.0,
                     last_access_time: Optional[float] = None) -> int:
        """
        Calculate effective TTL based on policy and access patterns.
        
        Args:
            access_count: Number of times cache entry has been accessed
            avg_latency_ms: Average access latency for performance-based TTL
            last_access_time: Unix timestamp of last access for sliding TTL
            
        Returns:
            Calculated TTL in seconds
        """
        if self.policy == TTLPolicy.STATIC:
            return self.base_ttl_seconds
        
        elif self.policy == TTLPolicy.SLIDING:
            if last_access_time is None:
                return self.base_ttl_seconds
            
            time_since_access = time.time() - last_access_time
            remaining_ttl = max(
                self.min_ttl_seconds,
                self.base_ttl_seconds - int(time_since_access)
            )
            return min(self.max_ttl_seconds, remaining_ttl + self.sliding_window_seconds)
        
        elif self.policy == TTLPolicy.ADAPTIVE:
            # Increase TTL for frequently accessed items
            access_multiplier = min(2.0, 1.0 + (access_count * 0.1))
            adaptive_ttl = int(self.base_ttl_seconds * access_multiplier * self.adaptive_factor)
            return max(self.min_ttl_seconds, min(self.max_ttl_seconds, adaptive_ttl))
        
        elif self.policy == TTLPolicy.PERFORMANCE_BASED:
            # Adjust TTL based on access performance
            if avg_latency_ms > self.performance_threshold_ms:
                # Increase TTL for slow operations to reduce cache misses
                performance_multiplier = min(3.0, avg_latency_ms / self.performance_threshold_ms)
                performance_ttl = int(self.base_ttl_seconds * performance_multiplier)
                return max(self.min_ttl_seconds, min(self.max_ttl_seconds, performance_ttl))
            else:
                return self.base_ttl_seconds
        
        else:  # HIERARCHICAL handled by namespace manager
            return self.base_ttl_seconds


@dataclass
class CacheEntry:
    """
    Cache entry metadata for comprehensive cache lifecycle management.
    
    Tracks access patterns, performance metrics, and dependencies for
    intelligent cache management and optimization strategies.
    """
    key: CacheKey
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl_seconds: int = 3600
    size_bytes: int = 0
    namespace: str = "default"
    tenant_id: Optional[str] = None
    dependencies: Set[CacheKey] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    warming_priority: CacheWarmingPriority = CacheWarmingPriority.MEDIUM
    
    def update_access(self) -> None:
        """Update access tracking for adaptive TTL calculation."""
        self.last_accessed = time.time()
        self.access_count += 1
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired based on TTL."""
        return time.time() > (self.created_at + self.ttl_seconds)
    
    def time_to_expiration(self) -> float:
        """Get remaining time until expiration in seconds."""
        return max(0.0, (self.created_at + self.ttl_seconds) - time.time())


class CacheInvalidationStrategy(ABC):
    """
    Abstract base class for cache invalidation strategies.
    
    Provides interface for implementing various cache invalidation
    patterns including time-based, event-driven, and dependency-based
    invalidation for data consistency management.
    """
    
    @abstractmethod
    def should_invalidate(self, entry: CacheEntry, trigger: CacheInvalidationTrigger,
                         context: Dict[str, Any]) -> bool:
        """
        Determine if cache entry should be invalidated based on trigger and context.
        
        Args:
            entry: Cache entry to evaluate for invalidation
            trigger: Type of invalidation trigger
            context: Additional context for invalidation decision
            
        Returns:
            True if entry should be invalidated, False otherwise
        """
        pass
    
    @abstractmethod
    def get_invalidation_keys(self, trigger: CacheInvalidationTrigger,
                             context: Dict[str, Any]) -> List[CacheKey]:
        """
        Get list of cache keys that should be invalidated for given trigger.
        
        Args:
            trigger: Type of invalidation trigger
            context: Additional context for key identification
            
        Returns:
            List of cache keys to invalidate
        """
        pass


class TimeBasedInvalidationStrategy(CacheInvalidationStrategy):
    """
    Time-based cache invalidation strategy using TTL policies.
    
    Implements TTL-based expiration with support for sliding windows,
    adaptive TTL adjustment, and performance-based TTL optimization
    for cache lifecycle management.
    """
    
    def __init__(self, ttl_config: TTLConfiguration):
        """
        Initialize time-based invalidation strategy.
        
        Args:
            ttl_config: TTL configuration with policy parameters
        """
        self.ttl_config = ttl_config
        self.logger = structlog.get_logger(__name__)
    
    def should_invalidate(self, entry: CacheEntry, trigger: CacheInvalidationTrigger,
                         context: Dict[str, Any]) -> bool:
        """Check if entry should be invalidated based on TTL policy."""
        if trigger != CacheInvalidationTrigger.TTL_EXPIRED:
            return False
        
        # Calculate effective TTL based on policy
        effective_ttl = self.ttl_config.calculate_ttl(
            access_count=entry.access_count,
            avg_latency_ms=context.get('avg_latency_ms', 0.0),
            last_access_time=entry.last_accessed
        )
        
        # Check if entry has exceeded effective TTL
        age_seconds = time.time() - entry.created_at
        should_expire = age_seconds > effective_ttl
        
        if should_expire:
            self.logger.debug(
                "cache_entry_ttl_expired",
                key=entry.key,
                age_seconds=age_seconds,
                effective_ttl=effective_ttl,
                ttl_policy=self.ttl_config.policy.value
            )
        
        return should_expire
    
    def get_invalidation_keys(self, trigger: CacheInvalidationTrigger,
                             context: Dict[str, Any]) -> List[CacheKey]:
        """Get keys for time-based invalidation (handled by cache manager)."""
        return []  # Time-based invalidation handled by individual entry checks


class PatternBasedInvalidationStrategy(CacheInvalidationStrategy):
    """
    Pattern-based cache invalidation strategy for bulk operations.
    
    Implements pattern matching for bulk invalidation operations,
    supporting namespace-based, tag-based, and regex-based cache
    invalidation for efficient cache management.
    """
    
    def __init__(self):
        """Initialize pattern-based invalidation strategy."""
        self.logger = structlog.get_logger(__name__)
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    def should_invalidate(self, entry: CacheEntry, trigger: CacheInvalidationTrigger,
                         context: Dict[str, Any]) -> bool:
        """Check if entry matches invalidation patterns."""
        if trigger != CacheInvalidationTrigger.PATTERN_MATCH:
            return False
        
        patterns = context.get('patterns', [])
        namespace_filter = context.get('namespace')
        tag_filter = context.get('tags', set())
        
        # Namespace filtering
        if namespace_filter and entry.namespace != namespace_filter:
            return False
        
        # Tag-based filtering
        if tag_filter and not entry.tags.intersection(tag_filter):
            return False
        
        # Pattern matching on cache key
        for pattern in patterns:
            if self._matches_pattern(entry.key, pattern):
                self.logger.debug(
                    "cache_entry_pattern_matched",
                    key=entry.key,
                    pattern=pattern,
                    namespace=entry.namespace
                )
                return True
        
        return False
    
    def get_invalidation_keys(self, trigger: CacheInvalidationTrigger,
                             context: Dict[str, Any]) -> List[CacheKey]:
        """Get keys matching invalidation patterns."""
        if trigger != CacheInvalidationTrigger.PATTERN_MATCH:
            return []
        
        # Pattern-based key collection handled by cache manager
        # with access to full key registry
        return []
    
    def _matches_pattern(self, key: CacheKey, pattern: str) -> bool:
        """Check if cache key matches pattern with caching for performance."""
        if pattern not in self._compiled_patterns:
            try:
                # Support both glob-style and regex patterns
                if '*' in pattern or '?' in pattern:
                    # Convert glob to regex
                    regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                    self._compiled_patterns[pattern] = re.compile(f"^{regex_pattern}$")
                else:
                    # Treat as literal prefix
                    self._compiled_patterns[pattern] = re.compile(f"^{re.escape(pattern)}")
            except re.error:
                self.logger.warning("invalid_cache_pattern", pattern=pattern)
                return False
        
        return bool(self._compiled_patterns[pattern].match(key))


class DependencyBasedInvalidationStrategy(CacheInvalidationStrategy):
    """
    Dependency-based cache invalidation strategy for data consistency.
    
    Implements cache invalidation based on dependencies between cache
    entries, supporting cascade invalidation and dependency graph
    management for complex cache relationships.
    """
    
    def __init__(self):
        """Initialize dependency-based invalidation strategy."""
        self.logger = structlog.get_logger(__name__)
        self._dependency_graph: Dict[CacheKey, Set[CacheKey]] = {}
        self._reverse_dependencies: Dict[CacheKey, Set[CacheKey]] = {}
        self._graph_lock = RLock()
    
    def should_invalidate(self, entry: CacheEntry, trigger: CacheInvalidationTrigger,
                         context: Dict[str, Any]) -> bool:
        """Check if entry should be invalidated based on dependency changes."""
        if trigger != CacheInvalidationTrigger.DEPENDENCY_CHANGED:
            return False
        
        changed_keys = context.get('changed_keys', set())
        return bool(entry.dependencies.intersection(changed_keys))
    
    def get_invalidation_keys(self, trigger: CacheInvalidationTrigger,
                             context: Dict[str, Any]) -> List[CacheKey]:
        """Get keys that depend on changed dependencies."""
        if trigger != CacheInvalidationTrigger.DEPENDENCY_CHANGED:
            return []
        
        changed_keys = context.get('changed_keys', set())
        dependent_keys = set()
        
        with self._graph_lock:
            for changed_key in changed_keys:
                dependent_keys.update(self._reverse_dependencies.get(changed_key, set()))
        
        return list(dependent_keys)
    
    def add_dependency(self, dependent_key: CacheKey, dependency_key: CacheKey) -> None:
        """Add dependency relationship between cache entries."""
        with self._graph_lock:
            if dependent_key not in self._dependency_graph:
                self._dependency_graph[dependent_key] = set()
            
            if dependency_key not in self._reverse_dependencies:
                self._reverse_dependencies[dependency_key] = set()
            
            self._dependency_graph[dependent_key].add(dependency_key)
            self._reverse_dependencies[dependency_key].add(dependent_key)
        
        self.logger.debug(
            "cache_dependency_added",
            dependent_key=dependent_key,
            dependency_key=dependency_key
        )
    
    def remove_dependency(self, dependent_key: CacheKey, dependency_key: CacheKey) -> None:
        """Remove dependency relationship between cache entries."""
        with self._graph_lock:
            if dependent_key in self._dependency_graph:
                self._dependency_graph[dependent_key].discard(dependency_key)
                if not self._dependency_graph[dependent_key]:
                    del self._dependency_graph[dependent_key]
            
            if dependency_key in self._reverse_dependencies:
                self._reverse_dependencies[dependency_key].discard(dependent_key)
                if not self._reverse_dependencies[dependency_key]:
                    del self._reverse_dependencies[dependency_key]
        
        self.logger.debug(
            "cache_dependency_removed",
            dependent_key=dependent_key,
            dependency_key=dependency_key
        )


class CacheWarmingStrategy(ABC):
    """
    Abstract base class for cache warming strategies.
    
    Provides interface for implementing proactive cache loading
    strategies to optimize cache hit rates and reduce latency
    for critical application data.
    """
    
    @abstractmethod
    async def warm_cache(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                        loader_func: Callable[[CacheKey], Any]) -> Dict[CacheKey, Any]:
        """
        Warm cache with specified keys using provided loader function.
        
        Args:
            keys: List of cache keys to warm
            priority: Warming priority level
            loader_func: Function to load data for cache keys
            
        Returns:
            Dictionary of successfully loaded key-value pairs
        """
        pass
    
    @abstractmethod
    def schedule_warming(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                        delay_seconds: int = 0) -> None:
        """
        Schedule cache warming operation for future execution.
        
        Args:
            keys: List of cache keys to warm
            priority: Warming priority level
            delay_seconds: Delay before warming execution
        """
        pass


class PredictiveWarmingStrategy(CacheWarmingStrategy):
    """
    Predictive cache warming strategy based on access patterns.
    
    Implements intelligent cache warming using historical access
    patterns, usage frequency analysis, and predictive algorithms
    to proactively load frequently accessed data.
    """
    
    def __init__(self, max_concurrent_warming: int = 10):
        """
        Initialize predictive warming strategy.
        
        Args:
            max_concurrent_warming: Maximum concurrent warming operations
        """
        self.max_concurrent_warming = max_concurrent_warming
        self.logger = structlog.get_logger(__name__)
        self._warming_executor = ThreadPoolExecutor(
            max_workers=max_concurrent_warming,
            thread_name_prefix="cache_warmer"
        )
        self._access_patterns: Dict[CacheKey, List[float]] = {}
        self._patterns_lock = RLock()
    
    async def warm_cache(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                        loader_func: Callable[[CacheKey], Any]) -> Dict[CacheKey, Any]:
        """Warm cache with predictive prioritization."""
        if not keys:
            return {}
        
        # Sort keys by warming priority and predicted access probability
        prioritized_keys = self._prioritize_warming_keys(keys, priority)
        
        warmed_data = {}
        warming_start_time = time.time()
        
        try:
            # Use ThreadPoolExecutor for concurrent warming operations
            futures = []
            for key in prioritized_keys[:self.max_concurrent_warming]:
                future = self._warming_executor.submit(self._safe_load_data, key, loader_func)
                futures.append((key, future))
            
            # Collect warming results with timeout
            for key, future in futures:
                try:
                    data = future.result(timeout=30.0)  # 30 second timeout per key
                    if data is not None:
                        warmed_data[key] = data
                        cache_monitor.record_cache_hit('redis', 'warming')
                        
                        self.logger.debug(
                            "cache_key_warmed",
                            key=key,
                            priority=priority.name,
                            size_bytes=len(str(data))
                        )
                except Exception as e:
                    self.logger.warning(
                        "cache_warming_failed",
                        key=key,
                        error_message=str(e),
                        priority=priority.name
                    )
                    cache_monitor.record_cache_miss('redis', 'warming')
            
            warming_duration = time.time() - warming_start_time
            self.logger.info(
                "cache_warming_completed",
                keys_requested=len(keys),
                keys_warmed=len(warmed_data),
                priority=priority.name,
                duration_seconds=warming_duration
            )
            
        except Exception as e:
            self.logger.error(
                "cache_warming_error",
                error_message=str(e),
                keys_count=len(keys),
                priority=priority.name
            )
        
        return warmed_data
    
    def schedule_warming(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                        delay_seconds: int = 0) -> None:
        """Schedule cache warming with delay support."""
        if delay_seconds > 0:
            # Schedule delayed warming
            threading.Timer(
                delay_seconds,
                self._execute_delayed_warming,
                args=(keys, priority)
            ).start()
        else:
            # Execute immediate warming in background
            threading.Thread(
                target=self._execute_delayed_warming,
                args=(keys, priority),
                daemon=True
            ).start()
        
        self.logger.info(
            "cache_warming_scheduled",
            keys_count=len(keys),
            priority=priority.name,
            delay_seconds=delay_seconds
        )
    
    def record_access_pattern(self, key: CacheKey) -> None:
        """Record access pattern for predictive analysis."""
        current_time = time.time()
        
        with self._patterns_lock:
            if key not in self._access_patterns:
                self._access_patterns[key] = []
            
            # Keep only recent access times (last 24 hours)
            recent_cutoff = current_time - 86400
            self._access_patterns[key] = [
                t for t in self._access_patterns[key] if t > recent_cutoff
            ]
            self._access_patterns[key].append(current_time)
            
            # Limit pattern history to prevent memory growth
            if len(self._access_patterns[key]) > 1000:
                self._access_patterns[key] = self._access_patterns[key][-500:]
    
    def _prioritize_warming_keys(self, keys: List[CacheKey],
                                priority: CacheWarmingPriority) -> List[CacheKey]:
        """Prioritize warming keys based on access patterns and priority."""
        with self._patterns_lock:
            key_scores = []
            
            for key in keys:
                # Base score from priority level
                priority_score = 6 - priority.value  # Higher number = higher priority
                
                # Access frequency score (accesses in last hour)
                recent_cutoff = time.time() - 3600
                access_times = self._access_patterns.get(key, [])
                recent_accesses = len([t for t in access_times if t > recent_cutoff])
                frequency_score = min(recent_accesses, 10) * 0.1
                
                # Access regularity score (coefficient of variation)
                regularity_score = 0.0
                if len(access_times) >= 3:
                    intervals = [access_times[i] - access_times[i-1] 
                               for i in range(1, len(access_times))]
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        if avg_interval > 0:
                            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                            cv = (variance ** 0.5) / avg_interval
                            regularity_score = max(0.0, 1.0 - cv)  # Lower CV = more regular
                
                total_score = priority_score + frequency_score + regularity_score
                key_scores.append((key, total_score))
        
        # Sort by score (descending) and return keys
        key_scores.sort(key=lambda x: x[1], reverse=True)
        return [key for key, score in key_scores]
    
    def _safe_load_data(self, key: CacheKey, loader_func: Callable[[CacheKey], Any]) -> Any:
        """Safely load data with error handling."""
        try:
            return loader_func(key)
        except Exception as e:
            self.logger.warning(
                "cache_data_loading_failed",
                key=key,
                error_message=str(e),
                error_type=type(e).__name__
            )
            return None
    
    def _execute_delayed_warming(self, keys: List[CacheKey],
                                priority: CacheWarmingPriority) -> None:
        """Execute delayed warming operation."""
        # This would need integration with actual cache client
        # For now, just log the warming attempt
        self.logger.info(
            "delayed_cache_warming_executed",
            keys_count=len(keys),
            priority=priority.name
        )


class CacheNamespaceManager:
    """
    Cache namespace manager for multi-tenant and hierarchical cache organization.
    
    Provides namespace isolation, tenant-specific cache partitioning,
    and hierarchical cache key management for enterprise deployment
    patterns and cache organization strategies.
    """
    
    def __init__(self):
        """Initialize cache namespace manager."""
        self.logger = structlog.get_logger(__name__)
        self._namespace_configs: Dict[str, TTLConfiguration] = {}
        self._tenant_namespaces: Dict[TenantId, Set[str]] = {}
        self._namespace_lock = RLock()
        
        # Default namespace configuration
        self._namespace_configs['default'] = TTLConfiguration(
            policy=TTLPolicy.STATIC,
            base_ttl_seconds=3600
        )
    
    def register_namespace(self, namespace: str, ttl_config: TTLConfiguration,
                          tenant_id: Optional[TenantId] = None) -> None:
        """
        Register cache namespace with TTL configuration.
        
        Args:
            namespace: Namespace identifier
            ttl_config: TTL configuration for namespace
            tenant_id: Optional tenant identifier for multi-tenant isolation
        """
        with self._namespace_lock:
            self._namespace_configs[namespace] = ttl_config
            
            if tenant_id:
                if tenant_id not in self._tenant_namespaces:
                    self._tenant_namespaces[tenant_id] = set()
                self._tenant_namespaces[tenant_id].add(namespace)
        
        self.logger.info(
            "cache_namespace_registered",
            namespace=namespace,
            tenant_id=tenant_id,
            ttl_policy=ttl_config.policy.value,
            base_ttl_seconds=ttl_config.base_ttl_seconds
        )
    
    def get_namespace_ttl_config(self, namespace: str) -> TTLConfiguration:
        """
        Get TTL configuration for namespace.
        
        Args:
            namespace: Namespace identifier
            
        Returns:
            TTL configuration for namespace
        """
        with self._namespace_lock:
            return self._namespace_configs.get(namespace, self._namespace_configs['default'])
    
    def get_tenant_namespaces(self, tenant_id: TenantId) -> Set[str]:
        """
        Get all namespaces for specific tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Set of namespace identifiers for tenant
        """
        with self._namespace_lock:
            return self._tenant_namespaces.get(tenant_id, set())
    
    def create_tenant_key(self, tenant_id: TenantId, base_key: CacheKey) -> CacheKey:
        """
        Create tenant-isolated cache key.
        
        Args:
            tenant_id: Tenant identifier
            base_key: Base cache key
            
        Returns:
            Tenant-isolated cache key
        """
        return f"tenant:{tenant_id}:{base_key}"
    
    def extract_tenant_id(self, key: CacheKey) -> Optional[TenantId]:
        """
        Extract tenant ID from cache key.
        
        Args:
            key: Cache key to parse
            
        Returns:
            Tenant ID if present, None otherwise
        """
        if key.startswith("tenant:"):
            parts = key.split(":", 2)
            if len(parts) >= 2:
                return parts[1]
        return None
    
    def validate_namespace_access(self, namespace: str, tenant_id: Optional[TenantId]) -> bool:
        """
        Validate namespace access for tenant.
        
        Args:
            namespace: Namespace to validate
            tenant_id: Tenant requesting access
            
        Returns:
            True if access is allowed, False otherwise
        """
        if not tenant_id:
            # Allow access to non-tenant namespaces
            return namespace not in [ns for namespaces in self._tenant_namespaces.values() 
                                   for ns in namespaces]
        
        with self._namespace_lock:
            tenant_namespaces = self._tenant_namespaces.get(tenant_id, set())
            return namespace in tenant_namespaces or namespace == 'default'


class CacheStrategiesManager:
    """
    Central cache strategies manager coordinating invalidation, warming, and namespace management.
    
    Provides comprehensive cache lifecycle management with intelligent invalidation,
    proactive warming, and multi-tenant namespace coordination for enterprise-grade
    cache optimization and data consistency.
    """
    
    def __init__(self):
        """Initialize cache strategies manager with default strategies."""
        self.logger = structlog.get_logger(__name__)
        
        # Initialize strategy components
        self.invalidation_strategies: Dict[CacheInvalidationTrigger, List[CacheInvalidationStrategy]] = {
            CacheInvalidationTrigger.TTL_EXPIRED: [],
            CacheInvalidationTrigger.PATTERN_MATCH: [],
            CacheInvalidationTrigger.DEPENDENCY_CHANGED: []
        }
        
        self.warming_strategy = PredictiveWarmingStrategy()
        self.namespace_manager = CacheNamespaceManager()
        
        # Cache entry registry for comprehensive management
        self._cache_entries: Dict[CacheKey, CacheEntry] = {}
        self._entries_lock = RLock()
        
        # Default strategy registration
        self._register_default_strategies()
        
        self.logger.info(
            "cache_strategies_manager_initialized",
            invalidation_strategies=len(self.invalidation_strategies),
            has_warming_strategy=True,
            has_namespace_manager=True
        )
    
    def register_invalidation_strategy(self, trigger: CacheInvalidationTrigger,
                                     strategy: CacheInvalidationStrategy) -> None:
        """
        Register cache invalidation strategy for specific trigger.
        
        Args:
            trigger: Invalidation trigger type
            strategy: Invalidation strategy implementation
        """
        if trigger not in self.invalidation_strategies:
            self.invalidation_strategies[trigger] = []
        
        self.invalidation_strategies[trigger].append(strategy)
        
        self.logger.info(
            "invalidation_strategy_registered",
            trigger=trigger.value,
            strategy_type=type(strategy).__name__
        )
    
    def register_cache_entry(self, key: CacheKey, value: Any, ttl_seconds: int,
                           namespace: str = "default", tenant_id: Optional[str] = None,
                           tags: Optional[Set[str]] = None) -> CacheEntry:
        """
        Register cache entry with metadata for lifecycle management.
        
        Args:
            key: Cache key
            value: Cache value
            ttl_seconds: TTL in seconds
            namespace: Cache namespace
            tenant_id: Optional tenant identifier
            tags: Optional tags for pattern-based operations
            
        Returns:
            Created cache entry
        """
        current_time = time.time()
        entry = CacheEntry(
            key=key,
            created_at=current_time,
            last_accessed=current_time,
            ttl_seconds=ttl_seconds,
            size_bytes=len(str(value)) if value is not None else 0,
            namespace=namespace,
            tenant_id=tenant_id,
            tags=tags or set()
        )
        
        with self._entries_lock:
            self._cache_entries[key] = entry
        
        # Record access pattern for warming strategy
        self.warming_strategy.record_access_pattern(key)
        
        self.logger.debug(
            "cache_entry_registered",
            key=key,
            namespace=namespace,
            tenant_id=tenant_id,
            ttl_seconds=ttl_seconds,
            size_bytes=entry.size_bytes
        )
        
        return entry
    
    def update_cache_access(self, key: CacheKey) -> None:
        """
        Update cache entry access tracking.
        
        Args:
            key: Cache key that was accessed
        """
        with self._entries_lock:
            if key in self._cache_entries:
                self._cache_entries[key].update_access()
                
                # Record access pattern for predictive warming
                self.warming_strategy.record_access_pattern(key)
                
                self.logger.debug(
                    "cache_access_updated",
                    key=key,
                    access_count=self._cache_entries[key].access_count
                )
    
    def invalidate_cache(self, trigger: CacheInvalidationTrigger,
                        context: Dict[str, Any]) -> List[CacheKey]:
        """
        Execute cache invalidation based on trigger and context.
        
        Args:
            trigger: Type of invalidation trigger
            context: Invalidation context with trigger-specific data
            
        Returns:
            List of invalidated cache keys
        """
        invalidated_keys = []
        
        # Get strategies for trigger type
        strategies = self.invalidation_strategies.get(trigger, [])
        
        for strategy in strategies:
            try:
                # Get keys to invalidate from strategy
                strategy_keys = strategy.get_invalidation_keys(trigger, context)
                
                # Check individual entries against strategy
                with self._entries_lock:
                    for key, entry in list(self._cache_entries.items()):
                        if strategy.should_invalidate(entry, trigger, context):
                            invalidated_keys.append(key)
                
                # Add strategy-specific keys
                invalidated_keys.extend(strategy_keys)
                
            except Exception as e:
                self.logger.error(
                    "cache_invalidation_strategy_error",
                    trigger=trigger.value,
                    strategy_type=type(strategy).__name__,
                    error_message=str(e)
                )
        
        # Remove invalidated entries from registry
        with self._entries_lock:
            for key in invalidated_keys:
                self._cache_entries.pop(key, None)
        
        if invalidated_keys:
            self.logger.info(
                "cache_invalidation_completed",
                trigger=trigger.value,
                invalidated_count=len(invalidated_keys),
                context_keys=list(context.keys())
            )
        
        return list(set(invalidated_keys))  # Remove duplicates
    
    async def warm_cache_async(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                              loader_func: Callable[[CacheKey], Any]) -> Dict[CacheKey, Any]:
        """
        Asynchronously warm cache with specified keys.
        
        Args:
            keys: Cache keys to warm
            priority: Warming priority level
            loader_func: Function to load data for keys
            
        Returns:
            Dictionary of warmed key-value pairs
        """
        return await self.warming_strategy.warm_cache(keys, priority, loader_func)
    
    def schedule_cache_warming(self, keys: List[CacheKey], priority: CacheWarmingPriority,
                              delay_seconds: int = 0) -> None:
        """
        Schedule cache warming for future execution.
        
        Args:
            keys: Cache keys to warm
            priority: Warming priority level
            delay_seconds: Delay before execution
        """
        self.warming_strategy.schedule_warming(keys, priority, delay_seconds)
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics and performance metrics.
        
        Returns:
            Dictionary containing cache statistics and performance data
        """
        with self._entries_lock:
            total_entries = len(self._cache_entries)
            
            namespace_stats = {}
            tenant_stats = {}
            size_total = 0
            
            for entry in self._cache_entries.values():
                # Namespace statistics
                if entry.namespace not in namespace_stats:
                    namespace_stats[entry.namespace] = {'count': 0, 'size_bytes': 0}
                namespace_stats[entry.namespace]['count'] += 1
                namespace_stats[entry.namespace]['size_bytes'] += entry.size_bytes
                
                # Tenant statistics
                if entry.tenant_id:
                    if entry.tenant_id not in tenant_stats:
                        tenant_stats[entry.tenant_id] = {'count': 0, 'size_bytes': 0}
                    tenant_stats[entry.tenant_id]['count'] += 1
                    tenant_stats[entry.tenant_id]['size_bytes'] += entry.size_bytes
                
                size_total += entry.size_bytes
        
        return {
            'total_entries': total_entries,
            'total_size_bytes': size_total,
            'namespace_statistics': namespace_stats,
            'tenant_statistics': tenant_stats,
            'invalidation_strategies': {
                trigger.value: len(strategies) 
                for trigger, strategies in self.invalidation_strategies.items()
            },
            'warming_strategy_type': type(self.warming_strategy).__name__
        }
    
    def _register_default_strategies(self) -> None:
        """Register default invalidation strategies."""
        # Time-based invalidation with static TTL
        default_ttl_config = TTLConfiguration(
            policy=TTLPolicy.STATIC,
            base_ttl_seconds=3600
        )
        time_strategy = TimeBasedInvalidationStrategy(default_ttl_config)
        self.register_invalidation_strategy(CacheInvalidationTrigger.TTL_EXPIRED, time_strategy)
        
        # Pattern-based invalidation
        pattern_strategy = PatternBasedInvalidationStrategy()
        self.register_invalidation_strategy(CacheInvalidationTrigger.PATTERN_MATCH, pattern_strategy)
        
        # Dependency-based invalidation
        dependency_strategy = DependencyBasedInvalidationStrategy()
        self.register_invalidation_strategy(CacheInvalidationTrigger.DEPENDENCY_CHANGED, dependency_strategy)


# Global cache strategies manager instance
cache_strategies = CacheStrategiesManager()


# Convenience functions for common cache operations
@monitor_cache_operation('invalidate', 'redis')
def invalidate_by_pattern(pattern: str, namespace: Optional[str] = None,
                         tags: Optional[Set[str]] = None) -> List[CacheKey]:
    """
    Invalidate cache entries matching pattern.
    
    Args:
        pattern: Pattern to match (supports glob-style wildcards)
        namespace: Optional namespace filter
        tags: Optional tag filter
        
    Returns:
        List of invalidated cache keys
    """
    context = {
        'patterns': [pattern],
        'namespace': namespace,
        'tags': tags or set()
    }
    
    return cache_strategies.invalidate_cache(
        CacheInvalidationTrigger.PATTERN_MATCH,
        context
    )


@monitor_cache_operation('invalidate', 'redis')
def invalidate_by_dependency(changed_keys: Set[CacheKey]) -> List[CacheKey]:
    """
    Invalidate cache entries dependent on changed keys.
    
    Args:
        changed_keys: Set of cache keys that have changed
        
    Returns:
        List of invalidated dependent cache keys
    """
    context = {'changed_keys': changed_keys}
    
    return cache_strategies.invalidate_cache(
        CacheInvalidationTrigger.DEPENDENCY_CHANGED,
        context
    )


def create_cache_key(namespace: str, entity_type: str, identifier: str,
                    tenant_id: Optional[str] = None, version: Optional[str] = None) -> CacheKey:
    """
    Create standardized cache key using pattern organization.
    
    Args:
        namespace: Primary namespace
        entity_type: Type of cached entity
        identifier: Unique identifier
        tenant_id: Optional tenant ID for multi-tenant isolation
        version: Optional version for cache migration
        
    Returns:
        Formatted cache key
    """
    pattern = CacheKeyPattern(
        namespace=namespace,
        entity_type=entity_type,
        identifier=identifier,
        tenant_id=tenant_id,
        version=version
    )
    
    return pattern.to_key()


def schedule_warming_by_priority(keys: List[CacheKey], priority: CacheWarmingPriority) -> None:
    """
    Schedule cache warming based on priority level.
    
    Args:
        keys: Cache keys to warm
        priority: Warming priority level
    """
    # Schedule immediate warming for critical and high priority
    if priority in [CacheWarmingPriority.CRITICAL, CacheWarmingPriority.HIGH]:
        cache_strategies.schedule_cache_warming(keys, priority, delay_seconds=0)
    # Schedule delayed warming for lower priority
    else:
        delay = 60 if priority == CacheWarmingPriority.MEDIUM else 300
        cache_strategies.schedule_cache_warming(keys, priority, delay_seconds=delay)


# Export main components for package integration
__all__ = [
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
    'schedule_warming_by_priority'
]