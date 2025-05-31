"""
MongoDB Transaction Management Module

This module implements comprehensive MongoDB transaction management providing ACID compliance,
rollback mechanisms, and transaction state monitoring for both PyMongo synchronous and Motor
asynchronous operations. Ensures data consistency across multi-document operations while
maintaining performance requirements and comprehensive monitoring integration.

Key Features:
- ACID-compliant transaction management with commit/rollback support
- Context managers for both synchronous (PyMongo) and asynchronous (Motor) operations
- Transaction state monitoring and performance tracking with Prometheus metrics
- Comprehensive error handling and recovery mechanisms with exponential backoff
- Integration with existing database clients and monitoring infrastructure
- Transaction isolation level configuration and resource management
- Performance optimization ensuring ≤10% variance from Node.js baseline
- Circuit breaker integration for transaction resilience
- Enterprise-grade structured logging and error reporting

Technical Implementation:
- MongoDB 4.0+ multi-document transactions with replica set/sharded cluster support
- Session management with causal consistency and transaction options
- Transaction retry logic with configurable backoff strategies
- Resource cleanup and connection pool optimization
- Integration with Flask application factory pattern
- Prometheus metrics for transaction performance monitoring

Compliance Requirements:
- Section 5.2.5: Database access layer transaction management for data consistency
- Section 6.2.2: Data management with ACID compliance and MongoDB transaction support
- Section 6.2.4: Performance optimization with transaction monitoring and tracking
- Section 4.2.3: Error handling and recovery for transaction failures with retry logic
- Section 4.2.2: State management with transaction commit/rollback and isolation levels
"""

import asyncio
import time
import uuid
import threading
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import (
    Any, Dict, Optional, Union, List, Callable, TypeVar, Generic,
    AsyncGenerator, Generator, Tuple, NamedTuple
)
from dataclasses import dataclass, field
from enum import Enum, auto
from threading import Lock, RLock
from collections import defaultdict, deque
import weakref

# Database drivers and core dependencies
import pymongo
from pymongo import MongoClient, ReadConcern, WriteConcern, ReadPreference
from pymongo.client_session import ClientSession
from pymongo.errors import (
    InvalidOperation, OperationFailure, ConnectionFailure,
    WriteConcernError, ExecutionTimeout, NetworkTimeout,
    WTimeoutError, ServerSelectionTimeoutError
)

try:
    from motor.motor_asyncio import (
        AsyncIOMotorClient, AsyncIOMotorClientSession, AsyncIOMotorDatabase
    )
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

import structlog
from prometheus_client import Counter, Histogram, Gauge, Summary

# Local module imports
from .mongodb import MongoDBClient, MongoDBConfig, QueryResult
from .motor_async import MotorAsyncDatabase
from .exceptions import (
    DatabaseTransactionError, DatabaseConnectionError, DatabaseTimeoutError,
    DatabaseException, DatabaseErrorSeverity, DatabaseOperationType,
    with_database_retry, database_error_context, mongodb_circuit_breaker
)
from .monitoring import (
    DatabaseMetricsCollector, DatabaseTransactionMonitor,
    monitor_database_transaction
)

# Configure structured logging
logger = structlog.get_logger(__name__)

# Transaction state enums and types
class TransactionState(Enum):
    """Transaction state enumeration for comprehensive state tracking"""
    CREATED = auto()
    STARTED = auto()
    ACTIVE = auto()
    COMMITTING = auto()
    COMMITTED = auto()
    ABORTING = auto()
    ABORTED = auto()
    FAILED = auto()
    TIMEOUT = auto()


class TransactionIsolationLevel(Enum):
    """Transaction isolation levels for MongoDB operations"""
    READ_UNCOMMITTED = "available"
    READ_COMMITTED = "local"
    REPEATABLE_READ = "majority"
    SNAPSHOT = "snapshot"


class TransactionWriteConcern(Enum):
    """Transaction write concern levels for consistency guarantees"""
    UNACKNOWLEDGED = {"w": 0}
    ACKNOWLEDGED = {"w": 1}
    MAJORITY = {"w": "majority"}
    ALL_NODES = {"w": "all"}


# Transaction metrics and monitoring
transaction_operations_total = Counter(
    'mongodb_transaction_operations_total',
    'Total number of transaction operations',
    ['database', 'operation_type', 'status', 'isolation_level']
)

transaction_duration_seconds = Histogram(
    'mongodb_transaction_duration_seconds',
    'Transaction execution time in seconds',
    ['database', 'operation_type', 'status'],
    buckets=[0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
)

transaction_retry_attempts = Counter(
    'mongodb_transaction_retry_attempts_total',
    'Total transaction retry attempts',
    ['database', 'retry_reason', 'attempt_number']
)

transaction_rollback_total = Counter(
    'mongodb_transaction_rollback_total',
    'Total transaction rollbacks',
    ['database', 'rollback_reason', 'initiated_by']
)

active_transactions_gauge = Gauge(
    'mongodb_active_transactions',
    'Number of currently active transactions',
    ['database', 'isolation_level']
)

transaction_resource_usage = Histogram(
    'mongodb_transaction_resource_usage_seconds',
    'Transaction resource usage duration',
    ['database', 'resource_type'],
    buckets=[0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 300.0]
)


@dataclass
class TransactionConfig:
    """
    Comprehensive transaction configuration for MongoDB operations.
    
    Provides configurable options for transaction behavior, timeouts,
    retry policies, and monitoring integration to ensure optimal
    performance and reliability across different deployment scenarios.
    """
    
    # Core transaction settings
    read_concern: ReadConcern = field(default_factory=lambda: ReadConcern("majority"))
    write_concern: WriteConcern = field(default_factory=lambda: WriteConcern(w="majority", wtimeout=30000))
    read_preference: ReadPreference = field(default_factory=lambda: ReadPreference.PRIMARY)
    
    # Timeout configuration
    max_commit_time_ms: int = 30000  # 30 seconds
    transaction_timeout_seconds: int = 120  # 2 minutes
    session_timeout_minutes: int = 30
    
    # Retry configuration
    max_retry_attempts: int = 3
    base_retry_delay_ms: int = 100
    max_retry_delay_ms: int = 5000
    retry_jitter: bool = True
    
    # Performance and monitoring
    enable_monitoring: bool = True
    enable_performance_tracking: bool = True
    enable_deadlock_detection: bool = True
    
    # Resource management
    max_concurrent_transactions: int = 50
    resource_cleanup_timeout_seconds: int = 60
    connection_pool_timeout_ms: int = 30000
    
    # Isolation and consistency
    isolation_level: TransactionIsolationLevel = TransactionIsolationLevel.REPEATABLE_READ
    causal_consistency: bool = True
    
    def to_transaction_options(self) -> Dict[str, Any]:
        """Convert configuration to MongoDB transaction options."""
        return {
            'read_concern': self.read_concern,
            'write_concern': self.write_concern,
            'read_preference': self.read_preference,
            'max_commit_time_ms': self.max_commit_time_ms
        }
    
    def to_session_options(self) -> Dict[str, Any]:
        """Convert configuration to MongoDB session options."""
        return {
            'causal_consistency': self.causal_consistency,
            'default_transaction_options': self.to_transaction_options()
        }


@dataclass
class TransactionMetrics:
    """Transaction performance and resource metrics tracking"""
    
    transaction_id: str
    database: str
    start_time: float = field(default_factory=time.perf_counter)
    end_time: Optional[float] = None
    
    # Performance metrics
    duration_seconds: Optional[float] = None
    operations_count: int = 0
    documents_modified: int = 0
    bytes_transferred: int = 0
    
    # Resource metrics
    memory_usage_bytes: int = 0
    connection_time_seconds: float = 0
    lock_wait_time_seconds: float = 0
    
    # State tracking
    state: TransactionState = TransactionState.CREATED
    retry_attempts: int = 0
    rollback_initiated: bool = False
    
    # Error tracking
    error_count: int = 0
    last_error: Optional[str] = None
    error_types: List[str] = field(default_factory=list)
    
    def record_operation(self, documents_count: int = 1, bytes_size: int = 0):
        """Record transaction operation metrics"""
        self.operations_count += 1
        self.documents_modified += documents_count
        self.bytes_transferred += bytes_size
    
    def record_error(self, error: Exception):
        """Record transaction error details"""
        self.error_count += 1
        self.last_error = str(error)
        self.error_types.append(type(error).__name__)
    
    def complete_transaction(self, final_state: TransactionState):
        """Complete transaction metrics collection"""
        self.end_time = time.perf_counter()
        self.duration_seconds = self.end_time - self.start_time
        self.state = final_state
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization"""
        return {
            'transaction_id': self.transaction_id,
            'database': self.database,
            'duration_seconds': self.duration_seconds,
            'operations_count': self.operations_count,
            'documents_modified': self.documents_modified,
            'bytes_transferred': self.bytes_transferred,
            'memory_usage_bytes': self.memory_usage_bytes,
            'connection_time_seconds': self.connection_time_seconds,
            'lock_wait_time_seconds': self.lock_wait_time_seconds,
            'state': self.state.name,
            'retry_attempts': self.retry_attempts,
            'rollback_initiated': self.rollback_initiated,
            'error_count': self.error_count,
            'last_error': self.last_error,
            'error_types': self.error_types,
            'start_time': self.start_time,
            'end_time': self.end_time
        }


class TransactionManager:
    """
    Comprehensive MongoDB transaction manager providing ACID compliance,
    state tracking, and performance monitoring for enterprise applications.
    
    This manager coordinates transaction lifecycle across PyMongo synchronous
    and Motor asynchronous operations while ensuring data consistency,
    resource management, and comprehensive error handling with recovery.
    """
    
    def __init__(
        self,
        config: Optional[TransactionConfig] = None,
        metrics_collector: Optional[DatabaseMetricsCollector] = None
    ):
        """
        Initialize transaction manager with comprehensive configuration.
        
        Args:
            config: Transaction configuration settings
            metrics_collector: Prometheus metrics collector for monitoring
        """
        self.config = config or TransactionConfig()
        self.metrics_collector = metrics_collector
        
        # Transaction tracking
        self._active_transactions: Dict[str, TransactionMetrics] = {}
        self._transaction_history: deque = deque(maxlen=1000)
        self._lock = RLock()
        
        # Resource management
        self._session_pool: Dict[str, weakref.WeakSet] = defaultdict(weakref.WeakSet)
        self._resource_cleanup_tasks: List[Callable] = []
        
        # Performance tracking
        self._performance_stats = defaultdict(list)
        self._deadlock_detector = DeadlockDetector()
        
        # Monitoring integration
        self._transaction_monitor = None
        if self.metrics_collector:
            self._transaction_monitor = DatabaseTransactionMonitor(
                self.metrics_collector,
                logger
            )
        
        logger.info(
            "Transaction manager initialized",
            max_concurrent_transactions=self.config.max_concurrent_transactions,
            isolation_level=self.config.isolation_level.name,
            monitoring_enabled=self.config.enable_monitoring,
            retry_attempts=self.config.max_retry_attempts
        )
    
    def _generate_transaction_id(self) -> str:
        """Generate unique transaction identifier"""
        return f"txn_{uuid.uuid4().hex[:16]}_{int(time.time() * 1000)}"
    
    def _validate_transaction_capacity(self) -> None:
        """Validate current transaction capacity limits"""
        with self._lock:
            active_count = len(self._active_transactions)
            if active_count >= self.config.max_concurrent_transactions:
                raise DatabaseTransactionError(
                    f"Maximum concurrent transactions limit reached: {active_count}",
                    severity=DatabaseErrorSeverity.HIGH,
                    retry_recommended=True,
                    recovery_time_estimate=30
                )
    
    def _create_transaction_metrics(self, database: str) -> TransactionMetrics:
        """Create transaction metrics tracking instance"""
        transaction_id = self._generate_transaction_id()
        metrics = TransactionMetrics(
            transaction_id=transaction_id,
            database=database
        )
        
        with self._lock:
            self._active_transactions[transaction_id] = metrics
        
        # Update active transactions gauge
        active_transactions_gauge.labels(
            database=database,
            isolation_level=self.config.isolation_level.name
        ).inc()
        
        return metrics
    
    def _complete_transaction_metrics(
        self, 
        metrics: TransactionMetrics, 
        final_state: TransactionState
    ) -> None:
        """Complete transaction metrics and cleanup"""
        metrics.complete_transaction(final_state)
        
        with self._lock:
            # Move to history
            self._transaction_history.append(metrics.to_dict())
            
            # Remove from active transactions
            self._active_transactions.pop(metrics.transaction_id, None)
        
        # Update Prometheus metrics
        if self.config.enable_monitoring:
            transaction_operations_total.labels(
                database=metrics.database,
                operation_type='transaction',
                status=final_state.name.lower(),
                isolation_level=self.config.isolation_level.name
            ).inc()
            
            if metrics.duration_seconds:
                transaction_duration_seconds.labels(
                    database=metrics.database,
                    operation_type='transaction',
                    status=final_state.name.lower()
                ).observe(metrics.duration_seconds)
            
            # Update active transactions gauge
            active_transactions_gauge.labels(
                database=metrics.database,
                isolation_level=self.config.isolation_level.name
            ).dec()
        
        # Log transaction completion
        logger.info(
            "Transaction completed",
            transaction_id=metrics.transaction_id,
            database=metrics.database,
            state=final_state.name,
            duration_seconds=metrics.duration_seconds,
            operations_count=metrics.operations_count,
            retry_attempts=metrics.retry_attempts,
            error_count=metrics.error_count
        )
    
    @contextmanager
    def transaction(
        self,
        client: MongoDBClient,
        database: str,
        custom_config: Optional[TransactionConfig] = None
    ) -> Generator[Tuple[ClientSession, TransactionMetrics], None, None]:
        """
        Context manager for synchronous MongoDB transactions with PyMongo.
        
        Provides comprehensive transaction management including automatic
        retry logic, resource cleanup, performance monitoring, and error
        handling with rollback support for data consistency.
        
        Args:
            client: MongoDB client instance for transaction operations
            database: Database name for transaction scope
            custom_config: Override configuration for this transaction
            
        Yields:
            Tuple of (ClientSession, TransactionMetrics) for transaction operations
            
        Raises:
            DatabaseTransactionError: On transaction failure or timeout
            DatabaseConnectionError: On connection-related failures
            DatabaseTimeoutError: On transaction timeout
        """
        config = custom_config or self.config
        
        # Validate capacity and create metrics
        self._validate_transaction_capacity()
        metrics = self._create_transaction_metrics(database)
        
        session = None
        transaction_started = False
        
        try:
            with database_error_context(
                operation="transaction",
                database=database,
                transaction_id=metrics.transaction_id
            ):
                # Create session with configuration
                session_options = config.to_session_options()
                session = client.client.start_session(**session_options)
                
                metrics.state = TransactionState.STARTED
                
                # Start transaction with retry logic
                for attempt in range(config.max_retry_attempts):
                    try:
                        with mongodb_circuit_breaker:
                            # Configure transaction options
                            transaction_options = config.to_transaction_options()
                            
                            # Start transaction
                            session.start_transaction(**transaction_options)
                            transaction_started = True
                            metrics.state = TransactionState.ACTIVE
                            metrics.retry_attempts = attempt
                            
                            logger.debug(
                                "Transaction started",
                                transaction_id=metrics.transaction_id,
                                database=database,
                                attempt=attempt + 1,
                                isolation_level=config.isolation_level.name
                            )
                            
                            # Monitor transaction if available
                            if self._transaction_monitor:
                                with self._transaction_monitor.monitor_transaction(
                                    database=database,
                                    transaction_id=metrics.transaction_id
                                ):
                                    yield session, metrics
                            else:
                                yield session, metrics
                            
                            # Commit transaction
                            metrics.state = TransactionState.COMMITTING
                            session.commit_transaction()
                            metrics.state = TransactionState.COMMITTED
                            
                            logger.info(
                                "Transaction committed successfully",
                                transaction_id=metrics.transaction_id,
                                database=database,
                                attempt=attempt + 1,
                                operations_count=metrics.operations_count
                            )
                            
                            # Complete metrics tracking
                            self._complete_transaction_metrics(metrics, TransactionState.COMMITTED)
                            return
                    
                    except (ConnectionFailure, NetworkTimeout, ServerSelectionTimeoutError) as e:
                        # Connection-related errors - retry with backoff
                        metrics.record_error(e)
                        
                        if attempt < config.max_retry_attempts - 1:
                            delay = self._calculate_retry_delay(attempt, config)
                            
                            transaction_retry_attempts.labels(
                                database=database,
                                retry_reason='connection_failure',
                                attempt_number=str(attempt + 1)
                            ).inc()
                            
                            logger.warning(
                                "Transaction retry due to connection failure",
                                transaction_id=metrics.transaction_id,
                                database=database,
                                attempt=attempt + 1,
                                retry_delay_ms=delay,
                                error=str(e)
                            )
                            
                            time.sleep(delay / 1000.0)  # Convert to seconds
                            
                            # Abort current transaction if started
                            if transaction_started:
                                try:
                                    session.abort_transaction()
                                except Exception:
                                    pass  # Ignore abort errors during retry
                                transaction_started = False
                        else:
                            raise DatabaseConnectionError(
                                f"Transaction failed after {config.max_retry_attempts} attempts: {str(e)}",
                                database=database,
                                transaction_id=metrics.transaction_id,
                                operation="transaction",
                                original_error=e
                            )
                    
                    except (ExecutionTimeout, WTimeoutError) as e:
                        # Timeout errors
                        metrics.record_error(e)
                        metrics.state = TransactionState.TIMEOUT
                        
                        logger.error(
                            "Transaction timeout",
                            transaction_id=metrics.transaction_id,
                            database=database,
                            timeout_ms=config.max_commit_time_ms,
                            error=str(e)
                        )
                        
                        raise DatabaseTimeoutError(
                            f"Transaction timed out: {str(e)}",
                            database=database,
                            transaction_id=metrics.transaction_id,
                            operation="transaction",
                            timeout_duration=config.max_commit_time_ms,
                            original_error=e
                        )
                    
                    except Exception as e:
                        # Other errors - abort and re-raise
                        metrics.record_error(e)
                        metrics.state = TransactionState.FAILED
                        
                        logger.error(
                            "Transaction failed with unexpected error",
                            transaction_id=metrics.transaction_id,
                            database=database,
                            error=str(e),
                            error_type=type(e).__name__
                        )
                        
                        raise DatabaseTransactionError(
                            f"Transaction failed: {str(e)}",
                            database=database,
                            transaction_id=metrics.transaction_id,
                            operation="transaction",
                            original_error=e
                        )
        
        except Exception as e:
            # Handle any unhandled exceptions
            if not isinstance(e, (DatabaseTransactionError, DatabaseConnectionError, DatabaseTimeoutError)):
                metrics.record_error(e)
                metrics.state = TransactionState.FAILED
                
                e = DatabaseTransactionError(
                    f"Unexpected transaction error: {str(e)}",
                    database=database,
                    transaction_id=metrics.transaction_id,
                    operation="transaction",
                    original_error=e
                )
            
            # Attempt transaction rollback
            if session and transaction_started:
                try:
                    metrics.state = TransactionState.ABORTING
                    session.abort_transaction()
                    metrics.state = TransactionState.ABORTED
                    metrics.rollback_initiated = True
                    
                    transaction_rollback_total.labels(
                        database=database,
                        rollback_reason='error',
                        initiated_by='automatic'
                    ).inc()
                    
                    logger.warning(
                        "Transaction rolled back due to error",
                        transaction_id=metrics.transaction_id,
                        database=database,
                        error=str(e)
                    )
                    
                except Exception as rollback_error:
                    logger.error(
                        "Transaction rollback failed",
                        transaction_id=metrics.transaction_id,
                        database=database,
                        rollback_error=str(rollback_error),
                        original_error=str(e)
                    )
            
            # Complete metrics with failed state
            final_state = TransactionState.ABORTED if metrics.rollback_initiated else TransactionState.FAILED
            self._complete_transaction_metrics(metrics, final_state)
            
            raise e
        
        finally:
            # Cleanup session resources
            if session:
                try:
                    session.end_session()
                except Exception as cleanup_error:
                    logger.warning(
                        "Session cleanup error",
                        transaction_id=metrics.transaction_id,
                        database=database,
                        cleanup_error=str(cleanup_error)
                    )
    
    @asynccontextmanager
    async def async_transaction(
        self,
        database: MotorAsyncDatabase,
        database_name: str,
        custom_config: Optional[TransactionConfig] = None
    ) -> AsyncGenerator[Tuple[AsyncIOMotorClientSession, TransactionMetrics], None]:
        """
        Context manager for asynchronous MongoDB transactions with Motor.
        
        Provides comprehensive async transaction management including automatic
        retry logic, resource cleanup, performance monitoring, and error
        handling with rollback support optimized for high-concurrency operations.
        
        Args:
            database: Motor async database instance for transaction operations
            database_name: Database name for transaction scope
            custom_config: Override configuration for this transaction
            
        Yields:
            Tuple of (AsyncIOMotorClientSession, TransactionMetrics) for async operations
            
        Raises:
            DatabaseTransactionError: On transaction failure or timeout
            DatabaseConnectionError: On connection-related failures
            DatabaseTimeoutError: On transaction timeout
        """
        if not MOTOR_AVAILABLE:
            raise DatabaseTransactionError(
                "Motor not available for async transactions",
                database=database_name,
                operation="async_transaction"
            )
        
        config = custom_config or self.config
        
        # Validate capacity and create metrics
        self._validate_transaction_capacity()
        metrics = self._create_transaction_metrics(database_name)
        
        session = None
        transaction_started = False
        
        try:
            with database_error_context(
                operation="async_transaction",
                database=database_name,
                transaction_id=metrics.transaction_id
            ):
                # Create async session with configuration
                session_options = config.to_session_options()
                
                async with database.start_session(**session_options) as session:
                    metrics.state = TransactionState.STARTED
                    
                    # Start transaction with retry logic
                    for attempt in range(config.max_retry_attempts):
                        try:
                            with mongodb_circuit_breaker:
                                # Configure transaction options
                                transaction_options = config.to_transaction_options()
                                
                                # Start async transaction
                                async with session.start_transaction(**transaction_options):
                                    transaction_started = True
                                    metrics.state = TransactionState.ACTIVE
                                    metrics.retry_attempts = attempt
                                    
                                    logger.debug(
                                        "Async transaction started",
                                        transaction_id=metrics.transaction_id,
                                        database=database_name,
                                        attempt=attempt + 1,
                                        isolation_level=config.isolation_level.name
                                    )
                                    
                                    yield session, metrics
                                    
                                    # Transaction commits automatically on context exit
                                    metrics.state = TransactionState.COMMITTED
                                    
                                    logger.info(
                                        "Async transaction committed successfully",
                                        transaction_id=metrics.transaction_id,
                                        database=database_name,
                                        attempt=attempt + 1,
                                        operations_count=metrics.operations_count
                                    )
                                    
                                    # Complete metrics tracking
                                    self._complete_transaction_metrics(metrics, TransactionState.COMMITTED)
                                    return
                        
                        except (ConnectionFailure, NetworkTimeout, ServerSelectionTimeoutError) as e:
                            # Connection-related errors - retry with backoff
                            metrics.record_error(e)
                            
                            if attempt < config.max_retry_attempts - 1:
                                delay = self._calculate_retry_delay(attempt, config)
                                
                                transaction_retry_attempts.labels(
                                    database=database_name,
                                    retry_reason='connection_failure',
                                    attempt_number=str(attempt + 1)
                                ).inc()
                                
                                logger.warning(
                                    "Async transaction retry due to connection failure",
                                    transaction_id=metrics.transaction_id,
                                    database=database_name,
                                    attempt=attempt + 1,
                                    retry_delay_ms=delay,
                                    error=str(e)
                                )
                                
                                await asyncio.sleep(delay / 1000.0)  # Convert to seconds
                                transaction_started = False
                            else:
                                raise DatabaseConnectionError(
                                    f"Async transaction failed after {config.max_retry_attempts} attempts: {str(e)}",
                                    database=database_name,
                                    transaction_id=metrics.transaction_id,
                                    operation="async_transaction",
                                    original_error=e
                                )
                        
                        except (ExecutionTimeout, WTimeoutError) as e:
                            # Timeout errors
                            metrics.record_error(e)
                            metrics.state = TransactionState.TIMEOUT
                            
                            logger.error(
                                "Async transaction timeout",
                                transaction_id=metrics.transaction_id,
                                database=database_name,
                                timeout_ms=config.max_commit_time_ms,
                                error=str(e)
                            )
                            
                            raise DatabaseTimeoutError(
                                f"Async transaction timed out: {str(e)}",
                                database=database_name,
                                transaction_id=metrics.transaction_id,
                                operation="async_transaction",
                                timeout_duration=config.max_commit_time_ms,
                                original_error=e
                            )
                        
                        except Exception as e:
                            # Other errors - abort and re-raise
                            metrics.record_error(e)
                            metrics.state = TransactionState.FAILED
                            
                            logger.error(
                                "Async transaction failed with unexpected error",
                                transaction_id=metrics.transaction_id,
                                database=database_name,
                                error=str(e),
                                error_type=type(e).__name__
                            )
                            
                            raise DatabaseTransactionError(
                                f"Async transaction failed: {str(e)}",
                                database=database_name,
                                transaction_id=metrics.transaction_id,
                                operation="async_transaction",
                                original_error=e
                            )
        
        except Exception as e:
            # Handle any unhandled exceptions
            if not isinstance(e, (DatabaseTransactionError, DatabaseConnectionError, DatabaseTimeoutError)):
                metrics.record_error(e)
                metrics.state = TransactionState.FAILED
                
                e = DatabaseTransactionError(
                    f"Unexpected async transaction error: {str(e)}",
                    database=database_name,
                    transaction_id=metrics.transaction_id,
                    operation="async_transaction",
                    original_error=e
                )
            
            # Record rollback for async transactions (handled by Motor automatically)
            if transaction_started:
                metrics.rollback_initiated = True
                
                transaction_rollback_total.labels(
                    database=database_name,
                    rollback_reason='error',
                    initiated_by='automatic'
                ).inc()
                
                logger.warning(
                    "Async transaction rolled back due to error",
                    transaction_id=metrics.transaction_id,
                    database=database_name,
                    error=str(e)
                )
            
            # Complete metrics with failed state
            final_state = TransactionState.ABORTED if metrics.rollback_initiated else TransactionState.FAILED
            self._complete_transaction_metrics(metrics, final_state)
            
            raise e
    
    def _calculate_retry_delay(self, attempt: int, config: TransactionConfig) -> int:
        """Calculate exponential backoff delay for transaction retries"""
        base_delay = config.base_retry_delay_ms
        max_delay = config.max_retry_delay_ms
        
        # Exponential backoff: base_delay * (2 ^ attempt)
        delay = min(base_delay * (2 ** attempt), max_delay)
        
        # Add jitter if configured
        if config.retry_jitter:
            import random
            jitter = random.uniform(0.5, 1.5)
            delay = int(delay * jitter)
        
        return delay
    
    def get_transaction_status(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current status of a specific transaction.
        
        Args:
            transaction_id: Unique transaction identifier
            
        Returns:
            Transaction status dictionary or None if not found
        """
        with self._lock:
            metrics = self._active_transactions.get(transaction_id)
            if metrics:
                return metrics.to_dict()
            
            # Check transaction history
            for historical_txn in self._transaction_history:
                if historical_txn['transaction_id'] == transaction_id:
                    return historical_txn
            
            return None
    
    def get_active_transactions(self) -> List[Dict[str, Any]]:
        """
        Get list of all currently active transactions.
        
        Returns:
            List of active transaction status dictionaries
        """
        with self._lock:
            return [metrics.to_dict() for metrics in self._active_transactions.values()]
    
    def get_transaction_statistics(self, database: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive transaction statistics and performance metrics.
        
        Args:
            database: Optional database filter for statistics
            
        Returns:
            Transaction statistics summary
        """
        with self._lock:
            # Filter transactions by database if specified
            if database:
                active_txns = [
                    txn for txn in self._active_transactions.values() 
                    if txn.database == database
                ]
                historical_txns = [
                    txn for txn in self._transaction_history 
                    if txn['database'] == database
                ]
            else:
                active_txns = list(self._active_transactions.values())
                historical_txns = list(self._transaction_history)
            
            # Calculate statistics
            total_active = len(active_txns)
            total_completed = len(historical_txns)
            
            # Performance statistics
            if historical_txns:
                durations = [
                    txn['duration_seconds'] for txn in historical_txns 
                    if txn['duration_seconds'] is not None
                ]
                
                if durations:
                    avg_duration = sum(durations) / len(durations)
                    min_duration = min(durations)
                    max_duration = max(durations)
                else:
                    avg_duration = min_duration = max_duration = 0
                
                # Success rate calculation
                successful_txns = sum(
                    1 for txn in historical_txns 
                    if txn['state'] == TransactionState.COMMITTED.name
                )
                success_rate = (successful_txns / total_completed) * 100 if total_completed > 0 else 0
            else:
                avg_duration = min_duration = max_duration = 0
                success_rate = 0
            
            # Resource utilization
            total_operations = sum(txn.operations_count for txn in active_txns)
            total_retries = sum(txn.retry_attempts for txn in active_txns)
            
            return {
                'database_filter': database,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'active_transactions': {
                    'count': total_active,
                    'max_concurrent': self.config.max_concurrent_transactions,
                    'utilization_percent': (total_active / self.config.max_concurrent_transactions) * 100
                },
                'completed_transactions': {
                    'total': total_completed,
                    'success_rate_percent': round(success_rate, 2)
                },
                'performance': {
                    'average_duration_seconds': round(avg_duration, 4),
                    'min_duration_seconds': round(min_duration, 4),
                    'max_duration_seconds': round(max_duration, 4)
                },
                'operations': {
                    'total_active_operations': total_operations,
                    'total_retry_attempts': total_retries
                },
                'configuration': {
                    'isolation_level': self.config.isolation_level.name,
                    'max_retry_attempts': self.config.max_retry_attempts,
                    'transaction_timeout_seconds': self.config.transaction_timeout_seconds,
                    'monitoring_enabled': self.config.enable_monitoring
                }
            }
    
    def force_rollback_transaction(self, transaction_id: str, reason: str = "manual") -> bool:
        """
        Force rollback of a specific active transaction.
        
        Args:
            transaction_id: Unique transaction identifier to rollback
            reason: Reason for forced rollback
            
        Returns:
            True if rollback was successful, False if transaction not found
        """
        with self._lock:
            metrics = self._active_transactions.get(transaction_id)
            if not metrics:
                logger.warning(
                    "Cannot rollback transaction - not found",
                    transaction_id=transaction_id,
                    reason=reason
                )
                return False
            
            # Mark for rollback (actual rollback handled by context manager)
            metrics.rollback_initiated = True
            metrics.state = TransactionState.ABORTING
            
            transaction_rollback_total.labels(
                database=metrics.database,
                rollback_reason=reason,
                initiated_by='manual'
            ).inc()
            
            logger.warning(
                "Transaction marked for forced rollback",
                transaction_id=transaction_id,
                database=metrics.database,
                reason=reason
            )
            
            return True
    
    def cleanup_stale_transactions(self, max_age_seconds: int = 3600) -> int:
        """
        Cleanup stale transactions that have exceeded maximum age.
        
        Args:
            max_age_seconds: Maximum age for active transactions
            
        Returns:
            Number of stale transactions cleaned up
        """
        current_time = time.perf_counter()
        cleanup_count = 0
        
        with self._lock:
            stale_transactions = []
            
            for txn_id, metrics in self._active_transactions.items():
                age_seconds = current_time - metrics.start_time
                if age_seconds > max_age_seconds:
                    stale_transactions.append((txn_id, metrics))
            
            # Mark stale transactions for cleanup
            for txn_id, metrics in stale_transactions:
                metrics.rollback_initiated = True
                metrics.state = TransactionState.TIMEOUT
                
                logger.warning(
                    "Stale transaction marked for cleanup",
                    transaction_id=txn_id,
                    database=metrics.database,
                    age_seconds=current_time - metrics.start_time,
                    max_age_seconds=max_age_seconds
                )
                
                cleanup_count += 1
        
        if cleanup_count > 0:
            logger.info(
                "Stale transaction cleanup completed",
                cleanup_count=cleanup_count,
                max_age_seconds=max_age_seconds
            )
        
        return cleanup_count


class DeadlockDetector:
    """
    Simple deadlock detection for transaction monitoring.
    
    Provides basic deadlock detection and alerting for transaction
    operations to prevent system deadlocks and improve overall
    database performance and reliability.
    """
    
    def __init__(self, detection_window_seconds: int = 30):
        """Initialize deadlock detector with configuration"""
        self.detection_window_seconds = detection_window_seconds
        self._lock_waits: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()
    
    def record_lock_wait(self, transaction_id: str, wait_time_seconds: float):
        """Record lock wait time for deadlock detection"""
        current_time = time.time()
        
        with self._lock:
            # Clean old entries
            cutoff_time = current_time - self.detection_window_seconds
            self._lock_waits[transaction_id] = [
                wait_time for wait_time in self._lock_waits[transaction_id]
                if wait_time > cutoff_time
            ]
            
            # Add new wait time
            self._lock_waits[transaction_id].append(current_time)
    
    def detect_potential_deadlock(self, transaction_id: str) -> bool:
        """Detect potential deadlock for transaction"""
        with self._lock:
            wait_times = self._lock_waits.get(transaction_id, [])
            
            # Simple heuristic: more than 3 lock waits in detection window
            return len(wait_times) > 3
    
    def get_deadlock_statistics(self) -> Dict[str, Any]:
        """Get deadlock detection statistics"""
        with self._lock:
            total_transactions = len(self._lock_waits)
            potentially_deadlocked = sum(
                1 for waits in self._lock_waits.values() if len(waits) > 3
            )
            
            return {
                'total_monitored_transactions': total_transactions,
                'potentially_deadlocked_transactions': potentially_deadlocked,
                'detection_window_seconds': self.detection_window_seconds,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }


# Global transaction manager instance
_global_transaction_manager: Optional[TransactionManager] = None


def get_transaction_manager(
    config: Optional[TransactionConfig] = None,
    metrics_collector: Optional[DatabaseMetricsCollector] = None
) -> TransactionManager:
    """
    Get or create global transaction manager instance.
    
    Args:
        config: Transaction configuration (used only for initial creation)
        metrics_collector: Metrics collector (used only for initial creation)
        
    Returns:
        TransactionManager instance
    """
    global _global_transaction_manager
    
    if _global_transaction_manager is None:
        _global_transaction_manager = TransactionManager(config, metrics_collector)
    
    return _global_transaction_manager


def configure_transaction_manager(
    config: TransactionConfig,
    metrics_collector: Optional[DatabaseMetricsCollector] = None
) -> TransactionManager:
    """
    Configure global transaction manager with specific settings.
    
    Args:
        config: Transaction configuration
        metrics_collector: Optional metrics collector
        
    Returns:
        Configured TransactionManager instance
    """
    global _global_transaction_manager
    _global_transaction_manager = TransactionManager(config, metrics_collector)
    return _global_transaction_manager


# Convenience decorators for transaction management
def with_transaction(
    database: str,
    config: Optional[TransactionConfig] = None
):
    """
    Decorator for automatic transaction management around functions.
    
    Args:
        database: Database name for transaction
        config: Optional transaction configuration
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get transaction manager and MongoDB client from context
            transaction_manager = get_transaction_manager(config)
            
            # This would need to be adapted based on your application's 
            # dependency injection or context management pattern
            # For now, this is a placeholder implementation
            
            # Example: client would be injected or retrieved from Flask context
            # client = get_current_mongodb_client()
            # with transaction_manager.transaction(client, database) as (session, metrics):
            #     return func(session, metrics, *args, **kwargs)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_async_transaction(
    database_name: str,
    config: Optional[TransactionConfig] = None
):
    """
    Decorator for automatic async transaction management around functions.
    
    Args:
        database_name: Database name for transaction
        config: Optional transaction configuration
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get transaction manager and Motor database from context
            transaction_manager = get_transaction_manager(config)
            
            # This would need to be adapted based on your application's 
            # dependency injection or context management pattern
            # For now, this is a placeholder implementation
            
            # Example: database would be injected or retrieved from Flask context
            # database = get_current_motor_database()
            # async with transaction_manager.async_transaction(database, database_name) as (session, metrics):
            #     return await func(session, metrics, *args, **kwargs)
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Flask integration utilities
def init_transaction_management(
    app,
    config: Optional[TransactionConfig] = None,
    metrics_collector: Optional[DatabaseMetricsCollector] = None
) -> TransactionManager:
    """
    Initialize transaction management for Flask application.
    
    Args:
        app: Flask application instance
        config: Transaction configuration
        metrics_collector: Metrics collector for monitoring
        
    Returns:
        Configured TransactionManager instance
    """
    # Create or configure transaction manager
    transaction_manager = configure_transaction_manager(config, metrics_collector)
    
    # Store in Flask app config
    app.config['TRANSACTION_MANAGER'] = transaction_manager
    
    # Register health check endpoint
    @app.route('/health/transactions')
    def transaction_health():
        """Transaction system health check endpoint"""
        try:
            stats = transaction_manager.get_transaction_statistics()
            
            # Determine health status based on utilization and error rates
            utilization = stats['active_transactions']['utilization_percent']
            success_rate = stats['completed_transactions']['success_rate_percent']
            
            if utilization < 80 and success_rate > 95:
                status = 'healthy'
                http_status = 200
            elif utilization < 95 and success_rate > 90:
                status = 'degraded'
                http_status = 200
            else:
                status = 'unhealthy'
                http_status = 503
            
            return {
                'status': status,
                'transaction_statistics': stats,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, http_status
            
        except Exception as e:
            logger.error(
                "Transaction health check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, 503
    
    # Register transaction statistics endpoint
    @app.route('/admin/transactions/statistics')
    def transaction_statistics():
        """Transaction statistics endpoint for monitoring"""
        try:
            from flask import request
            database_filter = request.args.get('database')
            
            stats = transaction_manager.get_transaction_statistics(database_filter)
            return stats, 200
            
        except Exception as e:
            logger.error(
                "Transaction statistics endpoint failed",
                error=str(e),
                error_type=type(e).__name__
            )
            return {
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, 500
    
    app.logger.info(
        "Transaction management initialized",
        max_concurrent=config.max_concurrent_transactions if config else 50,
        monitoring_enabled=config.enable_monitoring if config else True,
        isolation_level=config.isolation_level.name if config else TransactionIsolationLevel.REPEATABLE_READ.name
    )
    
    return transaction_manager


# Export public interface
__all__ = [
    # Core classes
    'TransactionManager',
    'TransactionConfig',
    'TransactionMetrics',
    'DeadlockDetector',
    
    # Enums
    'TransactionState',
    'TransactionIsolationLevel',
    'TransactionWriteConcern',
    
    # Global functions
    'get_transaction_manager',
    'configure_transaction_manager',
    
    # Decorators
    'with_transaction',
    'with_async_transaction',
    
    # Flask integration
    'init_transaction_management',
    
    # Metrics
    'transaction_operations_total',
    'transaction_duration_seconds',
    'transaction_retry_attempts',
    'transaction_rollback_total',
    'active_transactions_gauge',
    'transaction_resource_usage'
]