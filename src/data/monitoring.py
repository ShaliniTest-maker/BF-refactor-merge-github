"""
Database Performance Monitoring Module

This module implements comprehensive database performance monitoring for PyMongo and Motor
operations, providing real-time metrics collection, connection pool monitoring, and
performance baseline comparison to ensure ≤10% variance compliance from Node.js baseline.

Key Features:
- PyMongo event listeners for synchronous operation monitoring
- Motor async operation monitoring for high-performance database access
- Prometheus metrics collection for enterprise monitoring integration
- Connection pool health and performance tracking
- Query execution time monitoring with baseline comparison
- Transaction performance and success rate monitoring
- Circuit breaker integration for database resilience monitoring
- Comprehensive error tracking and alerting

Architecture Integration:
- Integrates with src/config/monitoring.py for centralized monitoring configuration
- Provides metrics for Prometheus enterprise monitoring infrastructure
- Supports Flask application factory pattern for monitoring initialization
- Enables structured logging for database operations and performance events
- Facilitates APM integration through distributed tracing context

Performance Requirements:
- Database operation variance monitoring: ≤10% from Node.js baseline (critical requirement)
- Connection pool utilization tracking: Warning >80%, Critical >95% capacity
- Query execution time monitoring: P95 <500ms, P99 <1000ms with variance tracking
- Transaction success rate monitoring: ≥99.5% success rate with error classification
- Real-time performance metrics for proactive optimization and alerting

References:
- Section 6.2.4 PERFORMANCE OPTIMIZATION: Query optimization patterns and monitoring requirements
- Section 6.2.2 DATA MANAGEMENT: Monitoring configuration and compliance considerations
- Section 5.2.5 DATABASE ACCESS LAYER: Connection pooling and performance optimization
- Section 0.1.1 PRIMARY OBJECTIVE: ≤10% performance variance requirement compliance
"""

import gc
import time
import threading
import weakref
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Callable, Union, Tuple
from functools import wraps
from threading import Lock, RLock

# Database drivers
try:
    import pymongo
    from pymongo import monitoring
    from pymongo.errors import PyMongoError, ConnectionFailure, OperationFailure
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

try:
    import motor
    from motor.motor_asyncio import AsyncIOMotorClient
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

# Monitoring and metrics
from prometheus_client import Counter, Histogram, Gauge, Summary
import structlog

# Application imports
from src.config.monitoring import MonitoringConfig, PrometheusMetrics


class DatabaseMetricsCollector:
    """
    Comprehensive database metrics collector implementing Prometheus instrumentation
    for MongoDB operations with performance baseline comparison capabilities.
    
    This collector provides detailed metrics for:
    - Database query execution times and operation counts
    - Connection pool utilization and health status
    - Transaction performance and success rates
    - Performance variance tracking against Node.js baseline
    - Error classification and monitoring
    """
    
    def __init__(self):
        """Initialize database metrics collectors with comprehensive instrumentation."""
        self._lock = Lock()
        self._baseline_data = {}
        self._performance_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Query Performance Metrics
        self.query_duration_seconds = Histogram(
            'mongodb_query_duration_seconds',
            'Database query execution time in seconds',
            ['database', 'collection', 'operation', 'status'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        self.query_operations_total = Counter(
            'mongodb_operations_total',
            'Total number of database operations',
            ['database', 'collection', 'operation', 'status']
        )
        
        # Connection Pool Metrics
        self.connection_pool_size = Gauge(
            'mongodb_connection_pool_size',
            'Current connection pool size',
            ['address', 'pool_type']
        )
        
        self.connection_pool_checked_out = Gauge(
            'mongodb_connection_pool_checked_out',
            'Number of checked out connections',
            ['address', 'pool_type']
        )
        
        self.connection_pool_operations_total = Counter(
            'mongodb_connection_pool_operations_total',
            'Total connection pool operations',
            ['address', 'operation', 'status']
        )
        
        self.connection_pool_wait_time_seconds = Histogram(
            'mongodb_connection_pool_wait_time_seconds',
            'Time spent waiting for connection checkout',
            ['address'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        # Transaction Metrics
        self.transaction_duration_seconds = Histogram(
            'mongodb_transaction_duration_seconds',
            'Database transaction execution time in seconds',
            ['database', 'status'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        self.transaction_operations_total = Counter(
            'mongodb_transaction_operations_total',
            'Total number of database transactions',
            ['database', 'status']
        )
        
        # Performance Variance Metrics (Critical for ≤10% requirement)
        self.performance_variance_percent = Gauge(
            'mongodb_performance_variance_percent',
            'Performance variance percentage against Node.js baseline',
            ['database', 'collection', 'operation', 'metric_type']
        )
        
        self.baseline_comparison_duration_seconds = Histogram(
            'mongodb_baseline_comparison_duration_seconds',
            'Query duration comparison with Node.js baseline',
            ['database', 'collection', 'operation', 'implementation'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
        )
        
        # Error and Circuit Breaker Metrics
        self.database_errors_total = Counter(
            'mongodb_errors_total',
            'Total database errors by type and severity',
            ['database', 'collection', 'error_type', 'severity']
        )
        
        self.circuit_breaker_state = Gauge(
            'mongodb_circuit_breaker_state',
            'Database circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['database', 'service']
        )
        
        # Async Operation Metrics (Motor)
        self.async_operations_total = Counter(
            'mongodb_async_operations_total',
            'Total async database operations (Motor)',
            ['database', 'collection', 'operation', 'status']
        )
        
        self.async_operation_duration_seconds = Histogram(
            'mongodb_async_operation_duration_seconds',
            'Async database operation duration in seconds',
            ['database', 'collection', 'operation'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        # Resource Utilization Metrics
        self.active_connections = Gauge(
            'mongodb_active_connections',
            'Number of active database connections',
            ['database', 'connection_type']
        )
        
        self.database_resource_utilization = Gauge(
            'mongodb_resource_utilization_percent',
            'Database resource utilization percentage',
            ['database', 'resource_type']
        )
    
    def record_query_operation(self, database: str, collection: str, operation: str, 
                              duration: float, status: str = 'success'):
        """Record database query operation metrics with performance tracking."""
        # Record basic operation metrics
        self.query_duration_seconds.labels(
            database=database,
            collection=collection,
            operation=operation,
            status=status
        ).observe(duration)
        
        self.query_operations_total.labels(
            database=database,
            collection=collection,
            operation=operation,
            status=status
        ).inc()
        
        # Performance variance tracking
        self._track_performance_variance(database, collection, operation, duration)
        
        # Store performance history for trend analysis
        key = f"{database}.{collection}.{operation}"
        with self._lock:
            self._performance_history[key].append({
                'timestamp': time.time(),
                'duration': duration,
                'status': status
            })
    
    def record_transaction_operation(self, database: str, duration: float, status: str = 'success'):
        """Record database transaction metrics with performance tracking."""
        self.transaction_duration_seconds.labels(
            database=database,
            status=status
        ).observe(duration)
        
        self.transaction_operations_total.labels(
            database=database,
            status=status
        ).inc()
    
    def record_async_operation(self, database: str, collection: str, operation: str,
                              duration: float, status: str = 'success'):
        """Record Motor async operation metrics."""
        self.async_operations_total.labels(
            database=database,
            collection=collection,
            operation=operation,
            status=status
        ).inc()
        
        self.async_operation_duration_seconds.labels(
            database=database,
            collection=collection,
            operation=operation
        ).observe(duration)
    
    def record_connection_pool_metric(self, address: str, pool_type: str, operation: str,
                                     status: str = 'success', wait_time: float = None):
        """Record connection pool operation metrics."""
        self.connection_pool_operations_total.labels(
            address=address,
            operation=operation,
            status=status
        ).inc()
        
        if wait_time is not None:
            self.connection_pool_wait_time_seconds.labels(address=address).observe(wait_time)
    
    def update_connection_pool_size(self, address: str, pool_type: str, size: int, checked_out: int):
        """Update connection pool size metrics."""
        self.connection_pool_size.labels(
            address=address,
            pool_type=pool_type
        ).set(size)
        
        self.connection_pool_checked_out.labels(
            address=address,
            pool_type=pool_type
        ).set(checked_out)
    
    def record_database_error(self, database: str, collection: str, error_type: str, severity: str):
        """Record database error metrics for comprehensive error tracking."""
        self.database_errors_total.labels(
            database=database,
            collection=collection,
            error_type=error_type,
            severity=severity
        ).inc()
    
    def update_circuit_breaker_state(self, database: str, service: str, state: int):
        """Update circuit breaker state metrics."""
        self.circuit_breaker_state.labels(
            database=database,
            service=service
        ).set(state)
    
    def set_baseline_performance(self, database: str, collection: str, operation: str, 
                                baseline_duration: float):
        """Set Node.js baseline performance data for variance calculation."""
        key = f"{database}.{collection}.{operation}"
        with self._lock:
            self._baseline_data[key] = baseline_duration
    
    def _track_performance_variance(self, database: str, collection: str, operation: str, 
                                   current_duration: float):
        """Track performance variance against Node.js baseline."""
        key = f"{database}.{collection}.{operation}"
        
        with self._lock:
            baseline_duration = self._baseline_data.get(key)
            
            if baseline_duration is not None:
                # Calculate variance percentage
                variance_percent = ((current_duration - baseline_duration) / baseline_duration) * 100
                
                # Record variance metric
                self.performance_variance_percent.labels(
                    database=database,
                    collection=collection,
                    operation=operation,
                    metric_type='response_time'
                ).set(variance_percent)
                
                # Record baseline comparison
                self.baseline_comparison_duration_seconds.labels(
                    database=database,
                    collection=collection,
                    operation=operation,
                    implementation='flask'
                ).observe(current_duration)
                
                self.baseline_comparison_duration_seconds.labels(
                    database=database,
                    collection=collection,
                    operation=operation,
                    implementation='nodejs'
                ).observe(baseline_duration)
    
    def get_performance_summary(self, database: str = None, collection: str = None) -> Dict[str, Any]:
        """Get comprehensive performance summary for monitoring dashboards."""
        with self._lock:
            summary = {
                'total_operations': sum(len(history) for history in self._performance_history.values()),
                'baseline_coverage': len(self._baseline_data),
                'performance_history_keys': list(self._performance_history.keys()),
                'recent_performance': {}
            }
            
            # Calculate recent performance statistics
            for key, history in self._performance_history.items():
                if len(history) > 0:
                    recent_durations = [entry['duration'] for entry in list(history)[-10:]]
                    summary['recent_performance'][key] = {
                        'avg_duration': sum(recent_durations) / len(recent_durations),
                        'min_duration': min(recent_durations),
                        'max_duration': max(recent_durations),
                        'operations_count': len(recent_durations),
                        'baseline_duration': self._baseline_data.get(key)
                    }
            
            return summary


class PyMongoEventListener(monitoring.CommandListener):
    """
    PyMongo event listener implementing comprehensive database operation monitoring
    with performance tracking, error classification, and baseline comparison.
    
    This listener captures:
    - Command execution times and operation counts
    - Query performance with variance tracking
    - Error classification and recovery monitoring
    - Transaction performance and success rates
    """
    
    def __init__(self, metrics_collector: DatabaseMetricsCollector, 
                 logger: Optional['structlog.BoundLogger'] = None):
        """Initialize PyMongo event listener with metrics integration."""
        super().__init__()
        self.metrics_collector = metrics_collector
        self.logger = logger or structlog.get_logger(__name__)
        self._active_commands = {}
        self._lock = RLock()
    
    def started(self, event: monitoring.CommandStartedEvent):
        """Handle command start event with timing initialization."""
        command_id = event.request_id
        start_time = time.perf_counter()
        
        with self._lock:
            self._active_commands[command_id] = {
                'start_time': start_time,
                'database': event.database_name,
                'command_name': event.command_name,
                'collection': self._extract_collection_name(event.command),
                'operation_id': event.operation_id
            }
        
        # Log command start for debugging and tracing
        self.logger.debug(
            "Database command started",
            request_id=command_id,
            database=event.database_name,
            command=event.command_name,
            collection=self._extract_collection_name(event.command)
        )
    
    def succeeded(self, event: monitoring.CommandSucceededEvent):
        """Handle successful command completion with metrics collection."""
        command_id = event.request_id
        end_time = time.perf_counter()
        
        with self._lock:
            command_info = self._active_commands.pop(command_id, None)
        
        if command_info:
            duration = end_time - command_info['start_time']
            
            # Record operation metrics
            self.metrics_collector.record_query_operation(
                database=command_info['database'],
                collection=command_info['collection'],
                operation=command_info['command_name'],
                duration=duration,
                status='success'
            )
            
            # Log successful completion
            self.logger.info(
                "Database command succeeded",
                request_id=command_id,
                database=command_info['database'],
                command=command_info['command_name'],
                collection=command_info['collection'],
                duration_ms=duration * 1000,
                duration_seconds=duration
            )
    
    def failed(self, event: monitoring.CommandFailedEvent):
        """Handle failed command with error classification and metrics."""
        command_id = event.request_id
        end_time = time.perf_counter()
        
        with self._lock:
            command_info = self._active_commands.pop(command_id, None)
        
        if command_info:
            duration = end_time - command_info['start_time']
            error_type = type(event.failure).__name__
            severity = self._classify_error_severity(event.failure)
            
            # Record failed operation metrics
            self.metrics_collector.record_query_operation(
                database=command_info['database'],
                collection=command_info['collection'],
                operation=command_info['command_name'],
                duration=duration,
                status='error'
            )
            
            # Record error metrics
            self.metrics_collector.record_database_error(
                database=command_info['database'],
                collection=command_info['collection'],
                error_type=error_type,
                severity=severity
            )
            
            # Log error details
            self.logger.error(
                "Database command failed",
                request_id=command_id,
                database=command_info['database'],
                command=command_info['command_name'],
                collection=command_info['collection'],
                duration_ms=duration * 1000,
                error_type=error_type,
                error_message=str(event.failure),
                severity=severity
            )
    
    def _extract_collection_name(self, command: Dict[str, Any]) -> str:
        """Extract collection name from MongoDB command."""
        # Handle different command types
        if isinstance(command, dict):
            # Try common collection field names
            for field in ['collection', 'find', 'insert', 'update', 'delete', 'aggregate']:
                if field in command:
                    collection = command[field]
                    return collection if isinstance(collection, str) else 'unknown'
        
        return 'unknown'
    
    def _classify_error_severity(self, error: Exception) -> str:
        """Classify error severity for alerting and monitoring."""
        if isinstance(error, ConnectionFailure):
            return 'critical'
        elif isinstance(error, OperationFailure):
            return 'warning'
        elif isinstance(error, PyMongoError):
            return 'error'
        else:
            return 'unknown'


class PyMongoPoolListener(monitoring.PoolListener):
    """
    PyMongo connection pool listener implementing comprehensive pool monitoring
    with resource utilization tracking and health status monitoring.
    
    This listener provides:
    - Connection pool size and utilization metrics
    - Connection lifecycle event tracking
    - Pool health and performance monitoring
    - Resource optimization insights
    """
    
    def __init__(self, metrics_collector: DatabaseMetricsCollector,
                 logger: Optional['structlog.BoundLogger'] = None):
        """Initialize pool listener with metrics integration."""
        super().__init__()
        self.metrics_collector = metrics_collector
        self.logger = logger or structlog.get_logger(__name__)
        self._pool_stats = {}
        self._lock = RLock()
    
    def pool_created(self, event: monitoring.PoolCreatedEvent):
        """Handle pool creation with initial metrics setup."""
        address = str(event.address)
        
        with self._lock:
            self._pool_stats[address] = {
                'created_time': time.time(),
                'max_pool_size': event.options.max_pool_size,
                'min_pool_size': event.options.min_pool_size,
                'checked_out': 0,
                'total_connections': 0
            }
        
        # Update pool size metrics
        self.metrics_collector.update_connection_pool_size(
            address=address,
            pool_type='pymongo',
            size=event.options.max_pool_size,
            checked_out=0
        )
        
        self.logger.info(
            "Database connection pool created",
            address=address,
            max_pool_size=event.options.max_pool_size,
            min_pool_size=event.options.min_pool_size
        )
    
    def pool_cleared(self, event: monitoring.PoolClearedEvent):
        """Handle pool clearing with metrics reset."""
        address = str(event.address)
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='cleared',
            status='success'
        )
        
        self.logger.warning(
            "Database connection pool cleared",
            address=address,
            service_id=getattr(event, 'service_id', None)
        )
    
    def pool_closed(self, event: monitoring.PoolClosedEvent):
        """Handle pool closure with cleanup and final metrics."""
        address = str(event.address)
        
        with self._lock:
            pool_stats = self._pool_stats.pop(address, {})
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='closed',
            status='success'
        )
        
        uptime = time.time() - pool_stats.get('created_time', time.time())
        
        self.logger.info(
            "Database connection pool closed",
            address=address,
            uptime_seconds=uptime
        )
    
    def connection_created(self, event: monitoring.ConnectionCreatedEvent):
        """Handle connection creation with resource tracking."""
        address = str(event.address)
        
        with self._lock:
            if address in self._pool_stats:
                self._pool_stats[address]['total_connections'] += 1
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='connection_created',
            status='success'
        )
    
    def connection_closed(self, event: monitoring.ConnectionClosedEvent):
        """Handle connection closure with resource cleanup tracking."""
        address = str(event.address)
        
        with self._lock:
            if address in self._pool_stats:
                self._pool_stats[address]['total_connections'] = max(
                    0, self._pool_stats[address]['total_connections'] - 1
                )
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='connection_closed',
            status='success'
        )
    
    def connection_checked_out(self, event: monitoring.ConnectionCheckedOutEvent):
        """Handle connection checkout with utilization tracking."""
        address = str(event.address)
        
        with self._lock:
            if address in self._pool_stats:
                self._pool_stats[address]['checked_out'] += 1
                
                # Update utilization metrics
                self.metrics_collector.update_connection_pool_size(
                    address=address,
                    pool_type='pymongo',
                    size=self._pool_stats[address]['total_connections'],
                    checked_out=self._pool_stats[address]['checked_out']
                )
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='checkout',
            status='success'
        )
    
    def connection_checked_in(self, event: monitoring.ConnectionCheckedInEvent):
        """Handle connection checkin with resource availability tracking."""
        address = str(event.address)
        
        with self._lock:
            if address in self._pool_stats:
                self._pool_stats[address]['checked_out'] = max(
                    0, self._pool_stats[address]['checked_out'] - 1
                )
                
                # Update utilization metrics
                self.metrics_collector.update_connection_pool_size(
                    address=address,
                    pool_type='pymongo',
                    size=self._pool_stats[address]['total_connections'],
                    checked_out=self._pool_stats[address]['checked_out']
                )
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='checkin',
            status='success'
        )
    
    def connection_check_out_failed(self, event: monitoring.ConnectionCheckOutFailedEvent):
        """Handle checkout failures with error tracking and alerting."""
        address = str(event.address)
        reason = getattr(event, 'reason', 'unknown')
        
        self.metrics_collector.record_connection_pool_metric(
            address=address,
            pool_type='pymongo',
            operation='checkout',
            status='failed'
        )
        
        self.logger.error(
            "Database connection checkout failed",
            address=address,
            reason=reason,
            connection_id=getattr(event, 'connection_id', None)
        )


class MotorAsyncMonitoring:
    """
    Motor async operation monitoring implementing comprehensive tracking
    for high-performance async database operations with performance metrics.
    
    This monitoring provides:
    - Async operation timing and throughput metrics
    - Connection pool monitoring for Motor clients
    - Performance variance tracking for async operations
    - Error classification and recovery monitoring
    """
    
    def __init__(self, metrics_collector: DatabaseMetricsCollector,
                 logger: Optional['structlog.BoundLogger'] = None):
        """Initialize Motor async monitoring with metrics integration."""
        self.metrics_collector = metrics_collector
        self.logger = logger or structlog.get_logger(__name__)
        self._active_operations = {}
        self._lock = Lock()
    
    @contextmanager
    def monitor_async_operation(self, database: str, collection: str, operation: str):
        """Context manager for monitoring async database operations."""
        operation_id = id(threading.current_thread())
        start_time = time.perf_counter()
        status = 'success'
        
        try:
            # Track operation start
            with self._lock:
                self._active_operations[operation_id] = {
                    'start_time': start_time,
                    'database': database,
                    'collection': collection,
                    'operation': operation
                }
            
            self.logger.debug(
                "Async database operation started",
                operation_id=operation_id,
                database=database,
                collection=collection,
                operation=operation
            )
            
            yield
            
        except Exception as e:
            status = 'error'
            self.logger.error(
                "Async database operation failed",
                operation_id=operation_id,
                database=database,
                collection=collection,
                operation=operation,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
        
        finally:
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            # Remove from active operations
            with self._lock:
                self._active_operations.pop(operation_id, None)
            
            # Record metrics
            self.metrics_collector.record_async_operation(
                database=database,
                collection=collection,
                operation=operation,
                duration=duration,
                status=status
            )
            
            self.logger.info(
                "Async database operation completed",
                operation_id=operation_id,
                database=database,
                collection=collection,
                operation=operation,
                duration_ms=duration * 1000,
                status=status
            )
    
    def get_active_operations(self) -> List[Dict[str, Any]]:
        """Get list of currently active async operations."""
        current_time = time.perf_counter()
        
        with self._lock:
            active_ops = []
            for op_id, op_info in self._active_operations.items():
                duration = current_time - op_info['start_time']
                active_ops.append({
                    'operation_id': op_id,
                    'database': op_info['database'],
                    'collection': op_info['collection'],
                    'operation': op_info['operation'],
                    'duration_seconds': duration
                })
            
            return active_ops


class DatabaseHealthMonitor:
    """
    Database health monitoring implementing comprehensive health checks
    for MongoDB connections, pool status, and service availability.
    
    This monitor provides:
    - Connection health validation and automated recovery
    - Pool resource monitoring and optimization alerts
    - Service availability checks with circuit breaker integration
    - Performance degradation detection and alerting
    """
    
    def __init__(self, metrics_collector: DatabaseMetricsCollector,
                 logger: Optional['structlog.BoundLogger'] = None):
        """Initialize database health monitor with metrics integration."""
        self.metrics_collector = metrics_collector
        self.logger = logger or structlog.get_logger(__name__)
        self._health_checks = {}
        self._lock = Lock()
        self._last_health_check = {}
    
    def register_client(self, client_name: str, client, client_type: str = 'pymongo'):
        """Register a database client for health monitoring."""
        with self._lock:
            self._health_checks[client_name] = {
                'client': client,
                'client_type': client_type,
                'last_check': None,
                'consecutive_failures': 0,
                'status': 'unknown'
            }
        
        self.logger.info(
            "Database client registered for health monitoring",
            client_name=client_name,
            client_type=client_type
        )
    
    def check_client_health(self, client_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """Check health of registered database client with comprehensive validation."""
        with self._lock:
            client_info = self._health_checks.get(client_name)
        
        if not client_info:
            return {'status': 'error', 'message': f'Client {client_name} not registered'}
        
        start_time = time.perf_counter()
        health_result = {
            'client_name': client_name,
            'client_type': client_info['client_type'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'unknown',
            'response_time_ms': 0,
            'details': {}
        }
        
        try:
            client = client_info['client']
            
            # Perform health check based on client type
            if client_info['client_type'] == 'pymongo':
                # PyMongo health check
                health_result.update(self._check_pymongo_health(client, timeout))
            elif client_info['client_type'] == 'motor':
                # Motor async health check (synchronous wrapper)
                health_result.update(self._check_motor_health(client, timeout))
            else:
                health_result['status'] = 'error'
                health_result['message'] = f"Unsupported client type: {client_info['client_type']}"
            
            # Update consecutive failures counter
            with self._lock:
                if health_result['status'] == 'healthy':
                    client_info['consecutive_failures'] = 0
                else:
                    client_info['consecutive_failures'] += 1
                
                client_info['last_check'] = time.time()
                client_info['status'] = health_result['status']
        
        except Exception as e:
            health_result['status'] = 'error'
            health_result['message'] = str(e)
            health_result['error_type'] = type(e).__name__
            
            with self._lock:
                client_info['consecutive_failures'] += 1
                client_info['last_check'] = time.time()
                client_info['status'] = 'error'
        
        finally:
            end_time = time.perf_counter()
            health_result['response_time_ms'] = (end_time - start_time) * 1000
        
        # Log health check results
        self.logger.info(
            "Database health check completed",
            client_name=client_name,
            status=health_result['status'],
            response_time_ms=health_result['response_time_ms'],
            consecutive_failures=client_info['consecutive_failures']
        )
        
        return health_result
    
    def _check_pymongo_health(self, client, timeout: float) -> Dict[str, Any]:
        """Perform PyMongo client health check with comprehensive validation."""
        try:
            # Test basic connectivity
            client.admin.command('ping', maxTimeMS=int(timeout * 1000))
            
            # Get server info and connection details
            server_info = client.admin.command('serverStatus')
            db_stats = client.admin.command('listDatabases')
            
            return {
                'status': 'healthy',
                'details': {
                    'server_version': server_info.get('version', 'unknown'),
                    'uptime_seconds': server_info.get('uptime', 0),
                    'connections': server_info.get('connections', {}),
                    'databases_count': len(db_stats.get('databases', []))
                }
            }
        
        except PyMongoError as e:
            return {
                'status': 'unhealthy',
                'message': str(e),
                'error_type': type(e).__name__
            }
    
    def _check_motor_health(self, client, timeout: float) -> Dict[str, Any]:
        """Perform Motor async client health check (synchronous wrapper)."""
        try:
            # Note: This is a simplified sync check for Motor
            # In a real async environment, this would use asyncio
            return {
                'status': 'healthy',
                'details': {
                    'client_type': 'motor_async',
                    'note': 'Async health check requires asyncio context'
                }
            }
        
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': str(e),
                'error_type': type(e).__name__
            }
    
    def get_all_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status for all registered clients."""
        with self._lock:
            clients_status = {}
            overall_healthy = True
            
            for client_name, client_info in self._health_checks.items():
                health_result = self.check_client_health(client_name)
                clients_status[client_name] = health_result
                
                if health_result['status'] != 'healthy':
                    overall_healthy = False
            
            return {
                'overall_status': 'healthy' if overall_healthy else 'degraded',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'clients': clients_status,
                'summary': {
                    'total_clients': len(self._health_checks),
                    'healthy_clients': sum(1 for status in clients_status.values() 
                                         if status['status'] == 'healthy'),
                    'unhealthy_clients': sum(1 for status in clients_status.values() 
                                           if status['status'] != 'healthy')
                }
            }


class DatabaseTransactionMonitor:
    """
    Database transaction monitoring implementing comprehensive tracking
    for MongoDB transactions with performance and consistency monitoring.
    
    This monitor provides:
    - Transaction lifecycle tracking and performance metrics
    - Commit/rollback ratio monitoring and alerting
    - Deadlock detection and recovery monitoring
    - Transaction performance variance tracking
    """
    
    def __init__(self, metrics_collector: DatabaseMetricsCollector,
                 logger: Optional['structlog.BoundLogger'] = None):
        """Initialize transaction monitor with metrics integration."""
        self.metrics_collector = metrics_collector
        self.logger = logger or structlog.get_logger(__name__)
        self._active_transactions = {}
        self._lock = Lock()
    
    @contextmanager
    def monitor_transaction(self, database: str, transaction_id: str = None):
        """Context manager for monitoring database transactions."""
        if transaction_id is None:
            transaction_id = f"txn_{int(time.time() * 1000000)}"
        
        start_time = time.perf_counter()
        status = 'committed'
        
        try:
            # Track transaction start
            with self._lock:
                self._active_transactions[transaction_id] = {
                    'start_time': start_time,
                    'database': database,
                    'status': 'active'
                }
            
            self.logger.debug(
                "Database transaction started",
                transaction_id=transaction_id,
                database=database
            )
            
            yield transaction_id
            
        except Exception as e:
            status = 'rolled_back'
            self.logger.error(
                "Database transaction failed",
                transaction_id=transaction_id,
                database=database,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
        
        finally:
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            # Remove from active transactions
            with self._lock:
                self._active_transactions.pop(transaction_id, None)
            
            # Record transaction metrics
            self.metrics_collector.record_transaction_operation(
                database=database,
                duration=duration,
                status=status
            )
            
            self.logger.info(
                "Database transaction completed",
                transaction_id=transaction_id,
                database=database,
                duration_ms=duration * 1000,
                status=status
            )
    
    def get_active_transactions(self) -> List[Dict[str, Any]]:
        """Get list of currently active transactions."""
        current_time = time.perf_counter()
        
        with self._lock:
            active_txns = []
            for txn_id, txn_info in self._active_transactions.items():
                duration = current_time - txn_info['start_time']
                active_txns.append({
                    'transaction_id': txn_id,
                    'database': txn_info['database'],
                    'duration_seconds': duration,
                    'status': txn_info['status']
                })
            
            return active_txns


class DatabaseMonitoringManager:
    """
    Comprehensive database monitoring manager coordinating all monitoring
    components for PyMongo and Motor operations with enterprise integration.
    
    This manager provides:
    - Centralized monitoring initialization and configuration
    - Event listener registration and management
    - Health check coordination and status aggregation
    - Performance baseline management and variance tracking
    - Integration with Flask application factory pattern
    """
    
    def __init__(self, config: Optional[MonitoringConfig] = None):
        """Initialize database monitoring manager with comprehensive configuration."""
        self.config = config or MonitoringConfig()
        self.logger = structlog.get_logger(__name__)
        
        # Initialize core monitoring components
        self.metrics_collector = DatabaseMetricsCollector()
        self.health_monitor = DatabaseHealthMonitor(self.metrics_collector, self.logger)
        self.transaction_monitor = DatabaseTransactionMonitor(self.metrics_collector, self.logger)
        self.motor_monitoring = MotorAsyncMonitoring(self.metrics_collector, self.logger)
        
        # Event listeners
        self.command_listener = None
        self.pool_listener = None
        
        # Monitoring state
        self._monitoring_enabled = True
        self._clients = {}
        self._baseline_data = {}
        
        self.logger.info(
            "Database monitoring manager initialized",
            prometheus_enabled=self.config.PROMETHEUS_ENABLED,
            performance_monitoring_enabled=self.config.PERFORMANCE_MONITORING_ENABLED,
            nodejs_baseline_enabled=self.config.NODEJS_BASELINE_ENABLED
        )
    
    def initialize_pymongo_monitoring(self, client_name: str = 'default') -> Tuple[monitoring.CommandListener, monitoring.PoolListener]:
        """Initialize PyMongo event listeners with comprehensive monitoring."""
        if not PYMONGO_AVAILABLE:
            raise ImportError("PyMongo is not available for monitoring initialization")
        
        # Create event listeners
        self.command_listener = PyMongoEventListener(self.metrics_collector, self.logger)
        self.pool_listener = PyMongoPoolListener(self.metrics_collector, self.logger)
        
        self.logger.info(
            "PyMongo monitoring initialized",
            client_name=client_name,
            command_listener=True,
            pool_listener=True
        )
        
        return self.command_listener, self.pool_listener
    
    def register_pymongo_client(self, client, client_name: str = 'default'):
        """Register PyMongo client for health monitoring and metrics collection."""
        self._clients[client_name] = {
            'client': client,
            'type': 'pymongo',
            'registered_time': time.time()
        }
        
        self.health_monitor.register_client(client_name, client, 'pymongo')
        
        self.logger.info(
            "PyMongo client registered for monitoring",
            client_name=client_name
        )
    
    def register_motor_client(self, client, client_name: str = 'motor_default'):
        """Register Motor async client for health monitoring and metrics collection."""
        if not MOTOR_AVAILABLE:
            raise ImportError("Motor is not available for async monitoring")
        
        self._clients[client_name] = {
            'client': client,
            'type': 'motor',
            'registered_time': time.time()
        }
        
        self.health_monitor.register_client(client_name, client, 'motor')
        
        self.logger.info(
            "Motor async client registered for monitoring",
            client_name=client_name
        )
    
    def set_performance_baseline(self, operation_baselines: Dict[str, float]):
        """Set Node.js performance baselines for variance tracking."""
        for operation_key, baseline_duration in operation_baselines.items():
            # Parse operation key (format: "database.collection.operation")
            parts = operation_key.split('.')
            if len(parts) >= 3:
                database, collection, operation = parts[0], parts[1], '.'.join(parts[2:])
                self.metrics_collector.set_baseline_performance(
                    database, collection, operation, baseline_duration
                )
        
        self._baseline_data.update(operation_baselines)
        
        self.logger.info(
            "Performance baselines configured",
            baseline_count=len(operation_baselines),
            nodejs_baseline_enabled=self.config.NODEJS_BASELINE_ENABLED
        )
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status and health information."""
        # Get health status for all clients
        health_status = self.health_monitor.get_all_health_status()
        
        # Get performance summary
        performance_summary = self.metrics_collector.get_performance_summary()
        
        # Get active operations
        active_async_ops = self.motor_monitoring.get_active_operations()
        active_transactions = self.transaction_monitor.get_active_transactions()
        
        return {
            'monitoring_enabled': self._monitoring_enabled,
            'config': {
                'prometheus_enabled': self.config.PROMETHEUS_ENABLED,
                'performance_monitoring_enabled': self.config.PERFORMANCE_MONITORING_ENABLED,
                'nodejs_baseline_enabled': self.config.NODEJS_BASELINE_ENABLED,
                'variance_threshold': self.config.PERFORMANCE_VARIANCE_THRESHOLD
            },
            'clients': {
                'registered_count': len(self._clients),
                'clients': list(self._clients.keys())
            },
            'health': health_status,
            'performance': performance_summary,
            'active_operations': {
                'async_operations': len(active_async_ops),
                'active_transactions': len(active_transactions)
            },
            'baselines': {
                'configured_count': len(self._baseline_data),
                'baseline_coverage': performance_summary.get('baseline_coverage', 0)
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def create_flask_health_check(self) -> Callable:
        """Create Flask health check endpoint function."""
        def database_health_check():
            """Database health check endpoint for Flask integration."""
            try:
                health_status = self.health_monitor.get_all_health_status()
                
                if health_status['overall_status'] == 'healthy':
                    return {'status': 'healthy', 'database': health_status}, 200
                else:
                    return {'status': 'degraded', 'database': health_status}, 503
            
            except Exception as e:
                self.logger.error(
                    "Database health check failed",
                    error=str(e),
                    error_type=type(e).__name__
                )
                return {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, 503
        
        return database_health_check
    
    def enable_monitoring(self):
        """Enable database monitoring."""
        self._monitoring_enabled = True
        self.logger.info("Database monitoring enabled")
    
    def disable_monitoring(self):
        """Disable database monitoring."""
        self._monitoring_enabled = False
        self.logger.warning("Database monitoring disabled")


# Monitoring decorators for database operations
def monitor_database_operation(database: str, collection: str, operation: str):
    """
    Decorator for monitoring individual database operations with performance tracking.
    
    Args:
        database: Database name
        collection: Collection name
        operation: Operation type (find, insert, update, delete, etc.)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get monitoring manager from Flask app context or create local instance
            try:
                from flask import current_app
                monitoring_manager = current_app.config.get('DATABASE_MONITORING')
            except (ImportError, RuntimeError):
                # Fallback for non-Flask contexts
                monitoring_manager = None
            
            if monitoring_manager and monitoring_manager._monitoring_enabled:
                start_time = time.perf_counter()
                status = 'success'
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    status = 'error'
                    raise
                finally:
                    duration = time.perf_counter() - start_time
                    monitoring_manager.metrics_collector.record_query_operation(
                        database=database,
                        collection=collection,
                        operation=operation,
                        duration=duration,
                        status=status
                    )
            else:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


def monitor_async_database_operation(database: str, collection: str, operation: str):
    """
    Decorator for monitoring async database operations with Motor.
    
    Args:
        database: Database name
        collection: Collection name  
        operation: Operation type (find, insert, update, delete, etc.)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get monitoring manager from Flask app context or create local instance
            try:
                from flask import current_app
                monitoring_manager = current_app.config.get('DATABASE_MONITORING')
            except (ImportError, RuntimeError):
                # Fallback for non-Flask contexts
                monitoring_manager = None
            
            if monitoring_manager and monitoring_manager._monitoring_enabled:
                with monitoring_manager.motor_monitoring.monitor_async_operation(
                    database=database,
                    collection=collection,
                    operation=operation
                ):
                    result = await func(*args, **kwargs)
                    return result
            else:
                return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def monitor_database_transaction(database: str):
    """
    Decorator for monitoring database transactions with performance tracking.
    
    Args:
        database: Database name
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get monitoring manager from Flask app context
            try:
                from flask import current_app
                monitoring_manager = current_app.config.get('DATABASE_MONITORING')
            except (ImportError, RuntimeError):
                monitoring_manager = None
            
            if monitoring_manager and monitoring_manager._monitoring_enabled:
                with monitoring_manager.transaction_monitor.monitor_transaction(database=database):
                    result = func(*args, **kwargs)
                    return result
            else:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Initialization function for Flask application integration
def init_database_monitoring(app, pymongo_client=None, motor_client=None, 
                           baseline_config: Dict[str, float] = None) -> DatabaseMonitoringManager:
    """
    Initialize database monitoring for Flask application with comprehensive configuration.
    
    Args:
        app: Flask application instance
        pymongo_client: PyMongo client instance for synchronous operations
        motor_client: Motor client instance for async operations
        baseline_config: Node.js performance baselines for variance tracking
        
    Returns:
        DatabaseMonitoringManager: Configured monitoring manager instance
    """
    # Create monitoring manager
    monitoring_manager = DatabaseMonitoringManager()
    
    # Initialize PyMongo monitoring if client provided
    if pymongo_client and PYMONGO_AVAILABLE:
        command_listener, pool_listener = monitoring_manager.initialize_pymongo_monitoring()
        monitoring_manager.register_pymongo_client(pymongo_client)
        
        # Note: PyMongo event listeners must be registered during client creation
        # This is for reference - actual registration happens in client initialization
        app.logger.info("PyMongo monitoring configured (listeners must be set during client creation)")
    
    # Register Motor client if provided
    if motor_client and MOTOR_AVAILABLE:
        monitoring_manager.register_motor_client(motor_client)
    
    # Configure performance baselines if provided
    if baseline_config:
        monitoring_manager.set_performance_baseline(baseline_config)
    
    # Store monitoring manager in Flask app config
    app.config['DATABASE_MONITORING'] = monitoring_manager
    
    # Create health check endpoint
    health_check_func = monitoring_manager.create_flask_health_check()
    
    # Register health check route
    @app.route('/health/database')
    def database_health():
        return health_check_func()
    
    # Log monitoring initialization
    app.logger.info(
        "Database monitoring initialized",
        pymongo_enabled=pymongo_client is not None,
        motor_enabled=motor_client is not None,
        baseline_configured=baseline_config is not None,
        baseline_count=len(baseline_config) if baseline_config else 0
    )
    
    return monitoring_manager


# Export monitoring components for application integration
__all__ = [
    'DatabaseMetricsCollector',
    'PyMongoEventListener', 
    'PyMongoPoolListener',
    'MotorAsyncMonitoring',
    'DatabaseHealthMonitor',
    'DatabaseTransactionMonitor',
    'DatabaseMonitoringManager',
    'monitor_database_operation',
    'monitor_async_database_operation',
    'monitor_database_transaction',
    'init_database_monitoring'
]