"""
Database performance monitoring implementing PyMongo and Motor event listeners for Prometheus metrics collection.

This module provides comprehensive database operation monitoring to ensure ≤10% variance compliance 
from Node.js baseline performance. Implements event listeners for PyMongo and Motor drivers to capture
query execution times, connection pool statistics, and transaction performance metrics.

Key components:
- PyMongo command and connection pool event listeners
- Motor async operation monitoring
- Prometheus metrics collection and exposition
- Connection health monitoring and circuit breaker integration
- Performance baseline comparison and variance tracking
"""

import time
import logging
from typing import Dict, Any, Optional
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock

import pymongo.monitoring
from pymongo.monitoring import (
    CommandListener, 
    PoolListener, 
    ServerListener,
    CommandStartedEvent,
    CommandSucceededEvent, 
    CommandFailedEvent,
    PoolCreatedEvent,
    PoolClearedEvent,
    PoolClosedEvent,
    ConnectionCreatedEvent,
    ConnectionReadyEvent,
    ConnectionClosedEvent,
    ConnectionCheckOutStartedEvent,
    ConnectionCheckOutFailedEvent,
    ConnectionCheckedOutEvent,
    ConnectionCheckedInEvent,
    ServerOpeningEvent,
    ServerClosedEvent,
    ServerDescriptionChangedEvent
)
from prometheus_client import (
    Counter, 
    Histogram, 
    Gauge, 
    Info,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST
)

# Configure module logger
logger = logging.getLogger(__name__)

# Global metrics registry for database monitoring
database_registry = CollectorRegistry()

# Performance variance tracking configuration
PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement
NODEJS_BASELINE_PERCENTILES = {
    'p50': 50.0,  # 50th percentile baseline in milliseconds
    'p95': 150.0,  # 95th percentile baseline in milliseconds  
    'p99': 300.0   # 99th percentile baseline in milliseconds
}

# Circuit breaker configuration for connection monitoring
CONNECTION_FAILURE_THRESHOLD = 5
CONNECTION_RECOVERY_TIMEOUT = 30  # seconds


@dataclass
class DatabaseMetrics:
    """Database performance metrics collection container."""
    
    # Query performance metrics
    query_duration: Histogram
    query_counter: Counter
    query_errors: Counter
    
    # Connection pool metrics
    pool_size: Gauge
    pool_checkedout: Gauge
    pool_available: Gauge
    pool_created: Counter
    pool_cleared: Counter
    
    # Connection lifecycle metrics
    connection_created: Counter
    connection_closed: Counter
    connection_checkout_time: Histogram
    connection_checkout_failed: Counter
    
    # Server monitoring metrics
    server_status: Gauge
    server_latency: Histogram
    
    # Transaction performance metrics
    transaction_duration: Histogram
    transaction_count: Counter
    transaction_errors: Counter
    
    # Performance variance tracking
    variance_percentage: Gauge
    baseline_comparison: Histogram
    
    # Motor async operation metrics
    motor_operation_duration: Histogram
    motor_operation_count: Counter
    motor_connection_pool: Gauge


class DatabaseMonitoringListener(CommandListener):
    """
    PyMongo command event listener for comprehensive database operation monitoring.
    
    Captures query execution times, error rates, and operation counts to ensure
    performance compliance with ≤10% variance requirement.
    """
    
    def __init__(self, metrics: DatabaseMetrics):
        """Initialize the command listener with metrics collection."""
        self.metrics = metrics
        self._active_commands: Dict[int, float] = {}
        self._command_lock = Lock()
        
        logger.info("Initialized DatabaseMonitoringListener for PyMongo command tracking")
    
    def started(self, event: CommandStartedEvent) -> None:
        """Record command start time for duration tracking."""
        start_time = time.perf_counter()
        
        with self._command_lock:
            self._active_commands[event.request_id] = start_time
        
        # Increment operation counter
        self.metrics.query_counter.labels(
            database=event.database_name,
            collection=self._get_collection_name(event.command),
            command=event.command_name,
            status='started'
        ).inc()
        
        logger.debug(
            f"Database command started: {event.command_name} on {event.database_name}",
            extra={
                'command_name': event.command_name,
                'database_name': event.database_name,
                'request_id': event.request_id
            }
        )
    
    def succeeded(self, event: CommandSucceededEvent) -> None:
        """Record successful command completion and performance metrics."""
        end_time = time.perf_counter()
        
        with self._command_lock:
            start_time = self._active_commands.pop(event.request_id, end_time)
        
        duration = (end_time - start_time) * 1000  # Convert to milliseconds
        collection_name = self._get_collection_name(event.reply)
        
        # Record query duration
        self.metrics.query_duration.labels(
            database=event.database_name,
            collection=collection_name,
            command=event.command_name
        ).observe(duration)
        
        # Record successful operation
        self.metrics.query_counter.labels(
            database=event.database_name,
            collection=collection_name,
            command=event.command_name,
            status='success'
        ).inc()
        
        # Track performance variance against Node.js baseline
        self._track_performance_variance(event.command_name, duration)
        
        # Record baseline comparison
        self.metrics.baseline_comparison.labels(
            command=event.command_name,
            database=event.database_name
        ).observe(duration)
        
        logger.debug(
            f"Database command succeeded: {event.command_name} in {duration:.2f}ms",
            extra={
                'command_name': event.command_name,
                'database_name': event.database_name,
                'duration_ms': duration,
                'request_id': event.request_id
            }
        )
    
    def failed(self, event: CommandFailedEvent) -> None:
        """Record failed command and error metrics."""
        end_time = time.perf_counter()
        
        with self._command_lock:
            start_time = self._active_commands.pop(event.request_id, end_time)
        
        duration = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Record error metrics
        self.metrics.query_errors.labels(
            database=event.database_name,
            command=event.command_name,
            error=str(event.failure)[:100]  # Truncate error message
        ).inc()
        
        # Record failed operation
        self.metrics.query_counter.labels(
            database=event.database_name,
            collection='unknown',
            command=event.command_name,
            status='failed'
        ).inc()
        
        logger.error(
            f"Database command failed: {event.command_name} after {duration:.2f}ms",
            extra={
                'command_name': event.command_name,
                'database_name': event.database_name,
                'duration_ms': duration,
                'error': str(event.failure),
                'request_id': event.request_id
            }
        )
    
    def _get_collection_name(self, command_or_reply: Dict[str, Any]) -> str:
        """Extract collection name from command or reply document."""
        if isinstance(command_or_reply, dict):
            # Try common collection field names
            for field in ['collection', 'find', 'insert', 'update', 'delete', 'aggregate']:
                if field in command_or_reply:
                    return str(command_or_reply[field])
        
        return 'unknown'
    
    def _track_performance_variance(self, command_name: str, duration_ms: float) -> None:
        """Track performance variance against Node.js baseline."""
        try:
            # Get baseline for this command type (default to p95 if specific baseline not available)
            baseline_duration = NODEJS_BASELINE_PERCENTILES.get('p95', 150.0)
            
            # Calculate variance percentage
            if baseline_duration > 0:
                variance = ((duration_ms - baseline_duration) / baseline_duration) * 100
                
                # Update variance gauge
                self.metrics.variance_percentage.labels(
                    command=command_name,
                    baseline_type='nodejs_p95'
                ).set(variance)
                
                # Log warning if variance exceeds threshold
                if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                    logger.warning(
                        f"Performance variance threshold exceeded: {variance:.2f}% for {command_name}",
                        extra={
                            'command_name': command_name,
                            'variance_percentage': variance,
                            'duration_ms': duration_ms,
                            'baseline_ms': baseline_duration,
                            'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                        }
                    )
        
        except Exception as e:
            logger.error(f"Error tracking performance variance: {e}")


class ConnectionPoolMonitoringListener(PoolListener):
    """
    PyMongo connection pool event listener for resource optimization monitoring.
    
    Tracks connection pool lifecycle, utilization patterns, and resource allocation
    to ensure optimal database connection management.
    """
    
    def __init__(self, metrics: DatabaseMetrics):
        """Initialize the pool listener with metrics collection."""
        self.metrics = metrics
        self._pool_stats: Dict[str, Dict[str, Any]] = {}
        self._pool_lock = Lock()
        
        logger.info("Initialized ConnectionPoolMonitoringListener for pool resource tracking")
    
    def pool_created(self, event: PoolCreatedEvent) -> None:
        """Record connection pool creation and configuration."""
        address_str = str(event.address)
        
        with self._pool_lock:
            self._pool_stats[address_str] = {
                'max_size': event.options.max_pool_size,
                'min_size': event.options.min_pool_size,
                'created_time': time.time()
            }
        
        # Set pool size metrics
        self.metrics.pool_size.labels(address=address_str).set(event.options.max_pool_size)
        self.metrics.pool_created.labels(address=address_str).inc()
        
        logger.info(
            f"Connection pool created for {address_str}",
            extra={
                'address': address_str,
                'max_pool_size': event.options.max_pool_size,
                'min_pool_size': event.options.min_pool_size
            }
        )
    
    def pool_cleared(self, event: PoolClearedEvent) -> None:
        """Record connection pool clearing event."""
        address_str = str(event.address)
        
        self.metrics.pool_cleared.labels(
            address=address_str,
            service_id=str(event.service_id) if event.service_id else 'unknown'
        ).inc()
        
        logger.warning(
            f"Connection pool cleared for {address_str}",
            extra={
                'address': address_str,
                'service_id': str(event.service_id) if event.service_id else 'unknown'
            }
        )
    
    def pool_closed(self, event: PoolClosedEvent) -> None:
        """Record connection pool closure."""
        address_str = str(event.address)
        
        with self._pool_lock:
            self._pool_stats.pop(address_str, None)
        
        # Reset pool metrics
        self.metrics.pool_size.labels(address=address_str).set(0)
        self.metrics.pool_checkedout.labels(address=address_str).set(0)
        self.metrics.pool_available.labels(address=address_str).set(0)
        
        logger.info(
            f"Connection pool closed for {address_str}",
            extra={'address': address_str}
        )
    
    def connection_created(self, event: ConnectionCreatedEvent) -> None:
        """Record new connection creation."""
        address_str = str(event.address)
        
        self.metrics.connection_created.labels(
            address=address_str,
            connection_id=str(event.connection_id)
        ).inc()
        
        logger.debug(
            f"Database connection created: {event.connection_id} for {address_str}",
            extra={
                'address': address_str,
                'connection_id': str(event.connection_id)
            }
        )
    
    def connection_ready(self, event: ConnectionReadyEvent) -> None:
        """Record connection ready state."""
        address_str = str(event.address)
        
        # Update available connections gauge
        with self._pool_lock:
            if address_str in self._pool_stats:
                # Increment available connections (rough estimate)
                current_available = self.metrics.pool_available.labels(address=address_str)._value._value
                self.metrics.pool_available.labels(address=address_str).set(current_available + 1)
        
        logger.debug(
            f"Database connection ready: {event.connection_id} for {address_str}",
            extra={
                'address': address_str,
                'connection_id': str(event.connection_id)
            }
        )
    
    def connection_closed(self, event: ConnectionClosedEvent) -> None:
        """Record connection closure."""
        address_str = str(event.address)
        
        self.metrics.connection_closed.labels(
            address=address_str,
            reason=str(event.reason)
        ).inc()
        
        logger.debug(
            f"Database connection closed: {event.connection_id} for {address_str}, reason: {event.reason}",
            extra={
                'address': address_str,
                'connection_id': str(event.connection_id),
                'reason': str(event.reason)
            }
        )
    
    def connection_check_out_started(self, event: ConnectionCheckOutStartedEvent) -> None:
        """Record connection checkout start for latency tracking."""
        # Store checkout start time for duration calculation
        setattr(event, '_checkout_start_time', time.perf_counter())
    
    def connection_checked_out(self, event: ConnectionCheckedOutEvent) -> None:
        """Record successful connection checkout."""
        address_str = str(event.address)
        
        # Calculate checkout duration if start time available
        if hasattr(event, '_checkout_start_time'):
            checkout_duration = (time.perf_counter() - event._checkout_start_time) * 1000
            self.metrics.connection_checkout_time.labels(address=address_str).observe(checkout_duration)
        
        # Update checked out connections gauge
        with self._pool_lock:
            current_checkedout = self.metrics.pool_checkedout.labels(address=address_str)._value._value
            self.metrics.pool_checkedout.labels(address=address_str).set(current_checkedout + 1)
        
        logger.debug(
            f"Database connection checked out: {event.connection_id} for {address_str}",
            extra={
                'address': address_str,
                'connection_id': str(event.connection_id)
            }
        )
    
    def connection_checked_in(self, event: ConnectionCheckedInEvent) -> None:
        """Record connection check-in."""
        address_str = str(event.address)
        
        # Update checked out connections gauge
        with self._pool_lock:
            current_checkedout = self.metrics.pool_checkedout.labels(address=address_str)._value._value
            self.metrics.pool_checkedout.labels(address=address_str).set(max(0, current_checkedout - 1))
        
        logger.debug(
            f"Database connection checked in: {event.connection_id} for {address_str}",
            extra={
                'address': address_str,
                'connection_id': str(event.connection_id)
            }
        )
    
    def connection_check_out_failed(self, event: ConnectionCheckOutFailedEvent) -> None:
        """Record failed connection checkout."""
        address_str = str(event.address)
        
        self.metrics.connection_checkout_failed.labels(
            address=address_str,
            reason=str(event.reason)
        ).inc()
        
        logger.error(
            f"Database connection checkout failed for {address_str}: {event.reason}",
            extra={
                'address': address_str,
                'reason': str(event.reason)
            }
        )


class ServerMonitoringListener(ServerListener):
    """
    PyMongo server event listener for MongoDB server health monitoring.
    
    Tracks server availability, topology changes, and connection health
    to support circuit breaker patterns and service resilience.
    """
    
    def __init__(self, metrics: DatabaseMetrics):
        """Initialize the server listener with metrics collection."""
        self.metrics = metrics
        self._server_states: Dict[str, Dict[str, Any]] = {}
        self._server_lock = Lock()
        
        logger.info("Initialized ServerMonitoringListener for MongoDB server health tracking")
    
    def opened(self, event: ServerOpeningEvent) -> None:
        """Record server connection opening."""
        address_str = str(event.server_address)
        
        with self._server_lock:
            self._server_states[address_str] = {
                'status': 'opening',
                'topology_id': str(event.topology_id),
                'opened_time': time.time()
            }
        
        self.metrics.server_status.labels(
            address=address_str,
            status='opening'
        ).set(1)
        
        logger.info(
            f"MongoDB server connection opening: {address_str}",
            extra={
                'address': address_str,
                'topology_id': str(event.topology_id)
            }
        )
    
    def closed(self, event: ServerClosedEvent) -> None:
        """Record server connection closure."""
        address_str = str(event.server_address)
        
        with self._server_lock:
            self._server_states.pop(address_str, None)
        
        self.metrics.server_status.labels(
            address=address_str,
            status='closed'
        ).set(0)
        
        logger.warning(
            f"MongoDB server connection closed: {address_str}",
            extra={
                'address': address_str,
                'topology_id': str(event.topology_id)
            }
        )
    
    def description_changed(self, event: ServerDescriptionChangedEvent) -> None:
        """Record server description changes for health monitoring."""
        address_str = str(event.server_address)
        new_description = event.new_description
        previous_description = event.previous_description
        
        # Track server status changes
        if new_description and hasattr(new_description, 'server_type'):
            server_type = str(new_description.server_type)
            self.metrics.server_status.labels(
                address=address_str,
                status=server_type.lower()
            ).set(1 if server_type != 'Unknown' else 0)
        
        # Track round trip time if available
        if new_description and hasattr(new_description, 'round_trip_time'):
            if new_description.round_trip_time is not None:
                rtt_ms = new_description.round_trip_time * 1000  # Convert to milliseconds
                self.metrics.server_latency.labels(address=address_str).observe(rtt_ms)
        
        logger.debug(
            f"MongoDB server description changed for {address_str}",
            extra={
                'address': address_str,
                'new_server_type': str(new_description.server_type) if new_description else 'unknown',
                'previous_server_type': str(previous_description.server_type) if previous_description else 'unknown',
                'topology_id': str(event.topology_id)
            }
        )


class MotorMonitoringIntegration:
    """
    Motor async operation monitoring for high-performance async database operations.
    
    Provides monitoring hooks for Motor async operations, connection pool management,
    and transaction performance tracking in async contexts.
    """
    
    def __init__(self, metrics: DatabaseMetrics):
        """Initialize Motor monitoring integration."""
        self.metrics = metrics
        self._active_operations: Dict[str, float] = {}
        self._operation_lock = Lock()
        
        logger.info("Initialized MotorMonitoringIntegration for async operation tracking")
    
    @contextmanager
    def monitor_operation(self, operation_name: str, database_name: str, collection_name: str = 'unknown'):
        """Context manager for monitoring Motor async operations."""
        operation_id = f"{operation_name}_{database_name}_{collection_name}_{time.time()}"
        start_time = time.perf_counter()
        
        try:
            with self._operation_lock:
                self._active_operations[operation_id] = start_time
            
            # Increment operation counter
            self.metrics.motor_operation_count.labels(
                database=database_name,
                collection=collection_name,
                operation=operation_name,
                status='started'
            ).inc()
            
            yield operation_id
            
            # Record successful completion
            end_time = time.perf_counter()
            duration = (end_time - start_time) * 1000  # Convert to milliseconds
            
            self.metrics.motor_operation_duration.labels(
                database=database_name,
                collection=collection_name,
                operation=operation_name
            ).observe(duration)
            
            self.metrics.motor_operation_count.labels(
                database=database_name,
                collection=collection_name,
                operation=operation_name,
                status='success'
            ).inc()
            
            logger.debug(
                f"Motor async operation completed: {operation_name} in {duration:.2f}ms",
                extra={
                    'operation_name': operation_name,
                    'database_name': database_name,
                    'collection_name': collection_name,
                    'duration_ms': duration
                }
            )
            
        except Exception as e:
            # Record operation failure
            self.metrics.motor_operation_count.labels(
                database=database_name,
                collection=collection_name,
                operation=operation_name,
                status='failed'
            ).inc()
            
            logger.error(
                f"Motor async operation failed: {operation_name}",
                extra={
                    'operation_name': operation_name,
                    'database_name': database_name,
                    'collection_name': collection_name,
                    'error': str(e)
                }
            )
            raise
        
        finally:
            with self._operation_lock:
                self._active_operations.pop(operation_id, None)
    
    def monitor_connection_pool(self, pool_info: Dict[str, Any], address: str) -> None:
        """Monitor Motor connection pool statistics."""
        try:
            # Update connection pool metrics
            if 'pool_size' in pool_info:
                self.metrics.motor_connection_pool.labels(
                    address=address,
                    metric='pool_size'
                ).set(pool_info['pool_size'])
            
            if 'checked_out' in pool_info:
                self.metrics.motor_connection_pool.labels(
                    address=address,
                    metric='checked_out'
                ).set(pool_info['checked_out'])
            
            if 'available' in pool_info:
                self.metrics.motor_connection_pool.labels(
                    address=address,
                    metric='available'
                ).set(pool_info['available'])
            
            logger.debug(
                f"Motor connection pool stats updated for {address}",
                extra={'address': address, 'pool_info': pool_info}
            )
            
        except Exception as e:
            logger.error(f"Error updating Motor connection pool metrics: {e}")


def create_database_metrics() -> DatabaseMetrics:
    """
    Create and configure comprehensive database monitoring metrics.
    
    Returns:
        DatabaseMetrics: Configured metrics collection for database monitoring
    """
    try:
        # Query performance metrics
        query_duration = Histogram(
            name='mongodb_query_duration_seconds',
            documentation='Database query execution time in seconds',
            labelnames=['database', 'collection', 'command'],
            registry=database_registry,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        query_counter = Counter(
            name='mongodb_operations_total',
            documentation='Total database operations',
            labelnames=['database', 'collection', 'command', 'status'],
            registry=database_registry
        )
        
        query_errors = Counter(
            name='mongodb_query_errors_total',
            documentation='Total database query errors',
            labelnames=['database', 'command', 'error'],
            registry=database_registry
        )
        
        # Connection pool metrics
        pool_size = Gauge(
            name='mongodb_pool_size',
            documentation='Connection pool maximum size',
            labelnames=['address'],
            registry=database_registry
        )
        
        pool_checkedout = Gauge(
            name='mongodb_pool_checkedout_connections',
            documentation='Currently checked out connections',
            labelnames=['address'],
            registry=database_registry
        )
        
        pool_available = Gauge(
            name='mongodb_pool_available_connections',
            documentation='Currently available connections',
            labelnames=['address'],
            registry=database_registry
        )
        
        pool_created = Counter(
            name='mongodb_pool_created_total',
            documentation='Total connection pools created',
            labelnames=['address'],
            registry=database_registry
        )
        
        pool_cleared = Counter(
            name='mongodb_pool_cleared_total',
            documentation='Total connection pool clear events',
            labelnames=['address', 'service_id'],
            registry=database_registry
        )
        
        # Connection lifecycle metrics
        connection_created = Counter(
            name='mongodb_connections_created_total',
            documentation='Total connections created',
            labelnames=['address', 'connection_id'],
            registry=database_registry
        )
        
        connection_closed = Counter(
            name='mongodb_connections_closed_total',
            documentation='Total connections closed',
            labelnames=['address', 'reason'],
            registry=database_registry
        )
        
        connection_checkout_time = Histogram(
            name='mongodb_connection_checkout_duration_seconds',
            documentation='Connection checkout time in seconds',
            labelnames=['address'],
            registry=database_registry,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        connection_checkout_failed = Counter(
            name='mongodb_connection_checkout_failed_total',
            documentation='Total failed connection checkouts',
            labelnames=['address', 'reason'],
            registry=database_registry
        )
        
        # Server monitoring metrics
        server_status = Gauge(
            name='mongodb_server_status',
            documentation='MongoDB server status (1=up, 0=down)',
            labelnames=['address', 'status'],
            registry=database_registry
        )
        
        server_latency = Histogram(
            name='mongodb_server_latency_seconds',
            documentation='MongoDB server round trip time in seconds',
            labelnames=['address'],
            registry=database_registry,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        # Transaction performance metrics
        transaction_duration = Histogram(
            name='mongodb_transaction_duration_seconds',
            documentation='Database transaction duration in seconds',
            labelnames=['database', 'status'],
            registry=database_registry,
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        transaction_count = Counter(
            name='mongodb_transactions_total',
            documentation='Total database transactions',
            labelnames=['database', 'status'],
            registry=database_registry
        )
        
        transaction_errors = Counter(
            name='mongodb_transaction_errors_total',
            documentation='Total database transaction errors',
            labelnames=['database', 'error_type'],
            registry=database_registry
        )
        
        # Performance variance tracking
        variance_percentage = Gauge(
            name='mongodb_performance_variance_percentage',
            documentation='Performance variance from Node.js baseline in percentage',
            labelnames=['command', 'baseline_type'],
            registry=database_registry
        )
        
        baseline_comparison = Histogram(
            name='mongodb_baseline_comparison_seconds',
            documentation='Query duration comparison with Node.js baseline',
            labelnames=['command', 'database'],
            registry=database_registry,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        # Motor async operation metrics
        motor_operation_duration = Histogram(
            name='motor_operation_duration_seconds',
            documentation='Motor async operation duration in seconds',
            labelnames=['database', 'collection', 'operation'],
            registry=database_registry,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        motor_operation_count = Counter(
            name='motor_operations_total',
            documentation='Total Motor async operations',
            labelnames=['database', 'collection', 'operation', 'status'],
            registry=database_registry
        )
        
        motor_connection_pool = Gauge(
            name='motor_connection_pool_stats',
            documentation='Motor connection pool statistics',
            labelnames=['address', 'metric'],
            registry=database_registry
        )
        
        logger.info("Database monitoring metrics created successfully")
        
        return DatabaseMetrics(
            query_duration=query_duration,
            query_counter=query_counter,
            query_errors=query_errors,
            pool_size=pool_size,
            pool_checkedout=pool_checkedout,
            pool_available=pool_available,
            pool_created=pool_created,
            pool_cleared=pool_cleared,
            connection_created=connection_created,
            connection_closed=connection_closed,
            connection_checkout_time=connection_checkout_time,
            connection_checkout_failed=connection_checkout_failed,
            server_status=server_status,
            server_latency=server_latency,
            transaction_duration=transaction_duration,
            transaction_count=transaction_count,
            transaction_errors=transaction_errors,
            variance_percentage=variance_percentage,
            baseline_comparison=baseline_comparison,
            motor_operation_duration=motor_operation_duration,
            motor_operation_count=motor_operation_count,
            motor_connection_pool=motor_connection_pool
        )
        
    except Exception as e:
        logger.error(f"Error creating database metrics: {e}")
        raise


def register_database_monitoring_listeners(metrics: DatabaseMetrics) -> Dict[str, Any]:
    """
    Register PyMongo event listeners for comprehensive database monitoring.
    
    Args:
        metrics: DatabaseMetrics instance for metrics collection
    
    Returns:
        Dict containing registered listener instances
    """
    try:
        # Create monitoring listeners
        command_listener = DatabaseMonitoringListener(metrics)
        pool_listener = ConnectionPoolMonitoringListener(metrics)
        server_listener = ServerMonitoringListener(metrics)
        
        # Register listeners with PyMongo
        pymongo.monitoring.register(command_listener)
        pymongo.monitoring.register(pool_listener)
        pymongo.monitoring.register(server_listener)
        
        logger.info("Database monitoring listeners registered successfully")
        
        return {
            'command_listener': command_listener,
            'pool_listener': pool_listener,
            'server_listener': server_listener
        }
        
    except Exception as e:
        logger.error(f"Error registering database monitoring listeners: {e}")
        raise


def create_motor_monitoring_integration(metrics: DatabaseMetrics) -> MotorMonitoringIntegration:
    """
    Create Motor async operation monitoring integration.
    
    Args:
        metrics: DatabaseMetrics instance for metrics collection
    
    Returns:
        MotorMonitoringIntegration: Configured Motor monitoring integration
    """
    try:
        motor_integration = MotorMonitoringIntegration(metrics)
        logger.info("Motor monitoring integration created successfully")
        return motor_integration
        
    except Exception as e:
        logger.error(f"Error creating Motor monitoring integration: {e}")
        raise


@contextmanager
def monitor_transaction(metrics: DatabaseMetrics, database_name: str):
    """
    Context manager for monitoring database transactions.
    
    Args:
        metrics: DatabaseMetrics instance for metrics collection
        database_name: Name of the database for the transaction
    """
    start_time = time.perf_counter()
    status = 'success'
    
    try:
        # Increment transaction counter
        metrics.transaction_count.labels(
            database=database_name,
            status='started'
        ).inc()
        
        yield
        
        logger.debug(f"Database transaction completed successfully for {database_name}")
        
    except Exception as e:
        status = 'failed'
        
        # Record transaction error
        metrics.transaction_errors.labels(
            database=database_name,
            error_type=type(e).__name__
        ).inc()
        
        logger.error(
            f"Database transaction failed for {database_name}: {e}",
            extra={'database_name': database_name, 'error': str(e)}
        )
        raise
        
    finally:
        # Record transaction duration
        end_time = time.perf_counter()
        duration = end_time - start_time
        
        metrics.transaction_duration.labels(
            database=database_name,
            status=status
        ).observe(duration)
        
        metrics.transaction_count.labels(
            database=database_name,
            status=status
        ).inc()


def get_database_metrics_exposition() -> str:
    """
    Generate Prometheus-compatible metrics exposition for database monitoring.
    
    Returns:
        str: Prometheus metrics exposition format
    """
    try:
        return generate_latest(database_registry)
    except Exception as e:
        logger.error(f"Error generating database metrics exposition: {e}")
        return ""


def get_database_metrics_content_type() -> str:
    """
    Get content type for Prometheus metrics exposition.
    
    Returns:
        str: Content type for Prometheus metrics
    """
    return CONTENT_TYPE_LATEST


class DatabaseHealthChecker:
    """
    Database health monitoring for connection status and performance validation.
    
    Provides health check capabilities for MongoDB connections, Redis cache,
    and performance validation against baseline requirements.
    """
    
    def __init__(self, metrics: DatabaseMetrics):
        """Initialize database health checker."""
        self.metrics = metrics
        self._health_status: Dict[str, Dict[str, Any]] = {}
        self._health_lock = Lock()
        
        logger.info("Initialized DatabaseHealthChecker for connection health monitoring")
    
    def check_mongodb_health(self, client, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check MongoDB connection health and performance.
        
        Args:
            client: MongoDB client instance
            timeout: Connection timeout in seconds
        
        Returns:
            Dict containing health status and metrics
        """
        health_status = {
            'status': 'unknown',
            'response_time_ms': None,
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            start_time = time.perf_counter()
            
            # Perform health check ping
            client.admin.command('ping', maxTimeMS=int(timeout * 1000))
            
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            
            health_status.update({
                'status': 'healthy',
                'response_time_ms': response_time_ms
            })
            
            # Update server latency metric
            self.metrics.server_latency.labels(
                address='health_check'
            ).observe(response_time_ms / 1000)
            
            logger.debug(
                f"MongoDB health check passed in {response_time_ms:.2f}ms",
                extra={'response_time_ms': response_time_ms}
            )
            
        except Exception as e:
            health_status.update({
                'status': 'unhealthy',
                'error': str(e)
            })
            
            logger.error(
                f"MongoDB health check failed: {e}",
                extra={'error': str(e)}
            )
        
        with self._health_lock:
            self._health_status['mongodb'] = health_status
        
        return health_status
    
    def check_redis_health(self, redis_client, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check Redis connection health and performance.
        
        Args:
            redis_client: Redis client instance
            timeout: Connection timeout in seconds
        
        Returns:
            Dict containing health status and metrics
        """
        health_status = {
            'status': 'unknown',
            'response_time_ms': None,
            'error': None,
            'timestamp': time.time()
        }
        
        try:
            start_time = time.perf_counter()
            
            # Perform health check ping
            redis_client.ping()
            
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            
            health_status.update({
                'status': 'healthy',
                'response_time_ms': response_time_ms
            })
            
            logger.debug(
                f"Redis health check passed in {response_time_ms:.2f}ms",
                extra={'response_time_ms': response_time_ms}
            )
            
        except Exception as e:
            health_status.update({
                'status': 'unhealthy',
                'error': str(e)
            })
            
            logger.error(
                f"Redis health check failed: {e}",
                extra={'error': str(e)}
            )
        
        with self._health_lock:
            self._health_status['redis'] = health_status
        
        return health_status
    
    def get_overall_health_status(self) -> Dict[str, Any]:
        """
        Get overall database health status summary.
        
        Returns:
            Dict containing overall health status and individual component status
        """
        with self._health_lock:
            health_summary = {
                'overall_status': 'healthy',
                'components': self._health_status.copy(),
                'timestamp': time.time()
            }
            
            # Determine overall status based on component health
            for component, status in self._health_status.items():
                if status.get('status') == 'unhealthy':
                    health_summary['overall_status'] = 'unhealthy'
                    break
                elif status.get('status') == 'unknown':
                    health_summary['overall_status'] = 'degraded'
        
        return health_summary


# Global instances for Flask integration
_database_metrics: Optional[DatabaseMetrics] = None
_monitoring_listeners: Optional[Dict[str, Any]] = None
_motor_integration: Optional[MotorMonitoringIntegration] = None
_health_checker: Optional[DatabaseHealthChecker] = None


def initialize_database_monitoring() -> Dict[str, Any]:
    """
    Initialize comprehensive database monitoring system.
    
    Returns:
        Dict containing initialized monitoring components
    """
    global _database_metrics, _monitoring_listeners, _motor_integration, _health_checker
    
    try:
        # Create database metrics
        _database_metrics = create_database_metrics()
        
        # Register PyMongo event listeners
        _monitoring_listeners = register_database_monitoring_listeners(_database_metrics)
        
        # Create Motor monitoring integration
        _motor_integration = create_motor_monitoring_integration(_database_metrics)
        
        # Create health checker
        _health_checker = DatabaseHealthChecker(_database_metrics)
        
        logger.info("Database monitoring system initialized successfully")
        
        return {
            'metrics': _database_metrics,
            'listeners': _monitoring_listeners,
            'motor_integration': _motor_integration,
            'health_checker': _health_checker,
            'registry': database_registry
        }
        
    except Exception as e:
        logger.error(f"Error initializing database monitoring system: {e}")
        raise


def get_database_monitoring_components() -> Optional[Dict[str, Any]]:
    """
    Get initialized database monitoring components.
    
    Returns:
        Dict containing monitoring components or None if not initialized
    """
    if not _database_metrics:
        return None
    
    return {
        'metrics': _database_metrics,
        'listeners': _monitoring_listeners,
        'motor_integration': _motor_integration,
        'health_checker': _health_checker,
        'registry': database_registry
    }


# Export key components for Flask integration
__all__ = [
    'DatabaseMetrics',
    'DatabaseMonitoringListener',
    'ConnectionPoolMonitoringListener', 
    'ServerMonitoringListener',
    'MotorMonitoringIntegration',
    'DatabaseHealthChecker',
    'create_database_metrics',
    'register_database_monitoring_listeners',
    'create_motor_monitoring_integration',
    'monitor_transaction',
    'get_database_metrics_exposition',
    'get_database_metrics_content_type',
    'initialize_database_monitoring',
    'get_database_monitoring_components',
    'database_registry',
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'NODEJS_BASELINE_PERCENTILES'
]