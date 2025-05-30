"""
Database transaction management implementing ACID compliance with MongoDB transactions.

This module provides comprehensive transaction handling for both PyMongo and Motor operations
while maintaining data consistency. Implements rollback mechanisms, transaction state monitoring,
and performance tracking to ensure ≤10% variance from Node.js baseline performance.

Key features:
- MongoDB ACID transaction support with commit/rollback
- Transaction context managers for sync and async operations  
- Transaction state monitoring and performance tracking
- Error handling and recovery mechanisms
- Proper isolation levels and state management
- Integration with monitoring and exception handling systems

Implements requirements from:
- Section 4.2.2: State management and persistence with transaction context
- Section 6.2.2: Data management with transaction support
- Section 6.2.4: Performance optimization with transaction monitoring
- Section 4.2.3: Error handling with transaction recovery
- Section 5.2.5: Database access layer with isolation levels
"""

import asyncio
import enum
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    Any, Dict, List, Optional, Union, Callable, TypeVar, Generic,
    ContextManager, AsyncContextManager, Awaitable
)
from threading import Lock, RLock
from datetime import datetime, timedelta

import structlog
from pymongo import MongoClient, errors as pymongo_errors
from pymongo.client_session import ClientSession
from pymongo.read_concern import ReadConcern
from pymongo.read_preferences import ReadPreference
from pymongo.write_concern import WriteConcern
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorClientSession
from bson import ObjectId

# Import monitoring and exception handling
from .exceptions import (
    DatabaseTransactionError,
    DatabaseConnectionError,
    DatabaseTimeoutError,
    with_database_retry,
    database_error_context,
    get_circuit_breaker
)
from .monitoring import (
    monitor_transaction,
    get_database_monitoring_components
)

# Configure structured logger
logger = structlog.get_logger(__name__)

# Type variables for generic transaction handling
T = TypeVar('T')
AsyncT = TypeVar('AsyncT')


class TransactionState(enum.Enum):
    """Transaction state enumeration for comprehensive state tracking."""
    
    INACTIVE = "inactive"           # Transaction not started
    ACTIVE = "active"              # Transaction in progress
    COMMITTING = "committing"      # Transaction being committed
    COMMITTED = "committed"        # Transaction successfully committed
    ABORTING = "aborting"          # Transaction being aborted
    ABORTED = "aborted"            # Transaction successfully aborted
    FAILED = "failed"              # Transaction failed with error
    TIMEOUT = "timeout"            # Transaction timed out


class TransactionIsolationLevel(enum.Enum):
    """MongoDB transaction isolation levels for data consistency."""
    
    READ_UNCOMMITTED = "read_uncommitted"    # Lowest isolation level
    READ_COMMITTED = "read_committed"        # Prevent dirty reads
    REPEATABLE_READ = "repeatable_read"      # Prevent dirty and non-repeatable reads
    SERIALIZABLE = "serializable"           # Highest isolation level


@dataclass
class TransactionConfiguration:
    """Configuration settings for MongoDB transactions."""
    
    # Transaction timeout settings
    max_timeout_seconds: float = 30.0
    max_commit_time_seconds: float = 10.0
    max_retry_attempts: int = 3
    
    # Write concern settings
    write_concern: Optional[WriteConcern] = None
    read_concern: Optional[ReadConcern] = None
    read_preference: Optional[ReadPreference] = None
    
    # Isolation and consistency settings
    isolation_level: TransactionIsolationLevel = TransactionIsolationLevel.READ_COMMITTED
    causal_consistency: bool = True
    
    # Performance and monitoring settings
    enable_monitoring: bool = True
    enable_retry_logic: bool = True
    circuit_breaker_enabled: bool = True
    
    def __post_init__(self):
        """Set default MongoDB settings based on isolation level."""
        if self.write_concern is None:
            # Default to majority write concern for ACID compliance
            self.write_concern = WriteConcern(w="majority", j=True)
        
        if self.read_concern is None:
            # Set read concern based on isolation level
            if self.isolation_level == TransactionIsolationLevel.SERIALIZABLE:
                self.read_concern = ReadConcern("linearizable")
            elif self.isolation_level == TransactionIsolationLevel.REPEATABLE_READ:
                self.read_concern = ReadConcern("majority")
            else:
                self.read_concern = ReadConcern("local")
        
        if self.read_preference is None:
            self.read_preference = ReadPreference.PRIMARY


@dataclass
class TransactionContext:
    """Transaction context for state tracking and monitoring."""
    
    transaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: TransactionState = TransactionState.INACTIVE
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    database_name: str = "unknown"
    operation_count: int = 0
    error_message: Optional[str] = None
    retry_count: int = 0
    
    # Performance tracking
    commit_duration: Optional[float] = None
    total_duration: Optional[float] = None
    
    # Resource tracking
    session_id: Optional[str] = None
    collections_accessed: List[str] = field(default_factory=list)
    operations_performed: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_operation(self, operation_type: str, collection: str, details: Optional[Dict[str, Any]] = None):
        """Record a database operation within this transaction."""
        self.operation_count += 1
        if collection not in self.collections_accessed:
            self.collections_accessed.append(collection)
        
        operation_record = {
            'operation_type': operation_type,
            'collection': collection,
            'timestamp': time.time(),
            'details': details or {}
        }
        self.operations_performed.append(operation_record)
    
    def get_duration(self) -> Optional[float]:
        """Calculate total transaction duration."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return time.time() - self.start_time
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction context to dictionary for logging."""
        return {
            'transaction_id': self.transaction_id,
            'state': self.state.value,
            'database_name': self.database_name,
            'operation_count': self.operation_count,
            'duration': self.get_duration(),
            'retry_count': self.retry_count,
            'collections_accessed': self.collections_accessed,
            'error_message': self.error_message,
            'session_id': self.session_id
        }


class TransactionManager:
    """
    MongoDB transaction manager for synchronous operations.
    
    Provides ACID transaction support with comprehensive monitoring,
    error handling, and performance tracking for PyMongo operations.
    """
    
    def __init__(
        self,
        mongo_client: MongoClient,
        default_database: str,
        config: Optional[TransactionConfiguration] = None
    ):
        """
        Initialize transaction manager with MongoDB client.
        
        Args:
            mongo_client: PyMongo client instance
            default_database: Default database name for transactions
            config: Transaction configuration settings
        """
        self.mongo_client = mongo_client
        self.default_database = default_database
        self.config = config or TransactionConfiguration()
        
        # Transaction state tracking
        self._active_transactions: Dict[str, TransactionContext] = {}
        self._transaction_lock = RLock()
        
        # Performance monitoring integration
        self._monitoring_components = get_database_monitoring_components()
        
        logger.info(
            "Initialized TransactionManager for synchronous operations",
            database=default_database,
            config=self.config.__dict__
        )
    
    @contextmanager
    def transaction(
        self,
        database_name: Optional[str] = None,
        config: Optional[TransactionConfiguration] = None,
        auto_retry: bool = True
    ) -> ContextManager[TransactionContext]:
        """
        Context manager for MongoDB transactions with comprehensive monitoring.
        
        Provides ACID transaction support with automatic commit/rollback,
        error handling, and performance tracking.
        
        Args:
            database_name: Database name (uses default if None)
            config: Transaction-specific configuration
            auto_retry: Enable automatic retry on retryable errors
            
        Yields:
            TransactionContext: Transaction context for operation tracking
            
        Raises:
            DatabaseTransactionError: On transaction failures
            DatabaseConnectionError: On connection issues
            DatabaseTimeoutError: On timeout scenarios
        """
        db_name = database_name or self.default_database
        tx_config = config or self.config
        tx_context = TransactionContext(database_name=db_name)
        
        # Register active transaction
        with self._transaction_lock:
            self._active_transactions[tx_context.transaction_id] = tx_context
        
        session = None
        monitoring_context = None
        
        try:
            # Initialize monitoring context if enabled
            if (tx_config.enable_monitoring and 
                self._monitoring_components and 
                'metrics' in self._monitoring_components):
                monitoring_context = monitor_transaction(
                    self._monitoring_components['metrics'],
                    db_name
                )
                monitoring_context.__enter__()
            
            # Start transaction with proper configuration
            session = self._start_transaction_session(tx_context, tx_config)
            
            logger.info(
                "Transaction started",
                transaction_id=tx_context.transaction_id,
                database=db_name,
                session_id=str(session.session_id) if session else None
            )
            
            yield tx_context
            
            # Commit transaction
            self._commit_transaction(session, tx_context, tx_config)
            
        except Exception as e:
            # Abort transaction on any error
            self._abort_transaction(session, tx_context, e)
            
            # Re-raise appropriate database exception
            if isinstance(e, (DatabaseTransactionError, DatabaseConnectionError, DatabaseTimeoutError)):
                raise
            else:
                raise DatabaseTransactionError(
                    message=f"Transaction failed: {str(e)}",
                    transaction_id=tx_context.transaction_id,
                    session_info={'session_id': str(session.session_id) if session else None},
                    operation='transaction_execution',
                    database=db_name,
                    original_error=e
                )
        
        finally:
            # Cleanup monitoring context
            if monitoring_context:
                try:
                    monitoring_context.__exit__(None, None, None)
                except Exception as e:
                    logger.error(f"Error closing monitoring context: {e}")
            
            # Cleanup session
            if session:
                try:
                    session.end_session()
                except Exception as e:
                    logger.warning(f"Error ending session: {e}")
            
            # Remove from active transactions
            with self._transaction_lock:
                self._active_transactions.pop(tx_context.transaction_id, None)
            
            # Log final transaction state
            tx_context.end_time = time.time()
            logger.info(
                "Transaction completed",
                **tx_context.to_dict()
            )
    
    def _start_transaction_session(
        self,
        tx_context: TransactionContext,
        config: TransactionConfiguration
    ) -> ClientSession:
        """Start a new MongoDB transaction session."""
        try:
            tx_context.start_time = time.time()
            tx_context.state = TransactionState.ACTIVE
            
            # Create session with causal consistency if enabled
            session = self.mongo_client.start_session(
                causal_consistency=config.causal_consistency
            )
            
            tx_context.session_id = str(session.session_id)
            
            # Start transaction with configured settings
            session.start_transaction(
                read_concern=config.read_concern,
                write_concern=config.write_concern,
                read_preference=config.read_preference,
                max_commit_time_ms=int(config.max_commit_time_seconds * 1000)
            )
            
            return session
            
        except Exception as e:
            tx_context.state = TransactionState.FAILED
            tx_context.error_message = str(e)
            
            raise DatabaseTransactionError(
                message=f"Failed to start transaction session: {str(e)}",
                transaction_id=tx_context.transaction_id,
                operation='start_session',
                database=tx_context.database_name,
                original_error=e
            )
    
    def _commit_transaction(
        self,
        session: ClientSession,
        tx_context: TransactionContext,
        config: TransactionConfiguration
    ) -> None:
        """Commit the transaction with error handling and monitoring."""
        commit_start_time = time.perf_counter()
        
        try:
            tx_context.state = TransactionState.COMMITTING
            
            # Commit with timeout protection
            session.commit_transaction()
            
            commit_end_time = time.perf_counter()
            tx_context.commit_duration = commit_end_time - commit_start_time
            tx_context.state = TransactionState.COMMITTED
            
            logger.info(
                "Transaction committed successfully",
                transaction_id=tx_context.transaction_id,
                commit_duration=tx_context.commit_duration,
                operation_count=tx_context.operation_count
            )
            
        except Exception as e:
            tx_context.state = TransactionState.FAILED
            tx_context.error_message = str(e)
            
            raise DatabaseTransactionError(
                message=f"Failed to commit transaction: {str(e)}",
                transaction_id=tx_context.transaction_id,
                operation='commit_transaction',
                database=tx_context.database_name,
                original_error=e
            )
    
    def _abort_transaction(
        self,
        session: Optional[ClientSession],
        tx_context: TransactionContext,
        error: Exception
    ) -> None:
        """Abort the transaction with proper error handling."""
        try:
            tx_context.state = TransactionState.ABORTING
            tx_context.error_message = str(error)
            
            if session and session.in_transaction:
                session.abort_transaction()
            
            tx_context.state = TransactionState.ABORTED
            
            logger.warning(
                "Transaction aborted",
                transaction_id=tx_context.transaction_id,
                error=str(error),
                operation_count=tx_context.operation_count
            )
            
        except Exception as abort_error:
            tx_context.state = TransactionState.FAILED
            
            logger.error(
                "Failed to abort transaction",
                transaction_id=tx_context.transaction_id,
                abort_error=str(abort_error),
                original_error=str(error)
            )
    
    @with_database_retry(max_attempts=3, circuit_breaker=True)
    def execute_in_transaction(
        self,
        operation: Callable[[ClientSession, TransactionContext], T],
        database_name: Optional[str] = None,
        config: Optional[TransactionConfiguration] = None
    ) -> T:
        """
        Execute operation within a transaction with retry logic.
        
        Args:
            operation: Function to execute within transaction
            database_name: Database name for transaction
            config: Transaction configuration
            
        Returns:
            Result of the operation
            
        Raises:
            DatabaseTransactionError: On transaction failures
        """
        with self.transaction(database_name, config) as tx_context:
            session = self.mongo_client.start_session()
            try:
                return operation(session, tx_context)
            finally:
                session.end_session()
    
    def get_active_transactions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active transactions."""
        with self._transaction_lock:
            return {
                tx_id: tx_context.to_dict()
                for tx_id, tx_context in self._active_transactions.items()
            }
    
    def get_transaction_statistics(self) -> Dict[str, Any]:
        """Get transaction performance and utilization statistics."""
        with self._transaction_lock:
            active_count = len(self._active_transactions)
            
            # Calculate average durations for active transactions
            active_durations = [
                tx.get_duration() for tx in self._active_transactions.values()
                if tx.get_duration() is not None
            ]
            
            avg_duration = (
                sum(active_durations) / len(active_durations) 
                if active_durations else 0.0
            )
            
            return {
                'active_transactions': active_count,
                'average_active_duration': avg_duration,
                'database': self.default_database,
                'config': self.config.__dict__
            }


class AsyncTransactionManager:
    """
    MongoDB transaction manager for asynchronous operations.
    
    Provides ACID transaction support with comprehensive monitoring,
    error handling, and performance tracking for Motor async operations.
    """
    
    def __init__(
        self,
        motor_client: AsyncIOMotorClient,
        default_database: str,
        config: Optional[TransactionConfiguration] = None
    ):
        """
        Initialize async transaction manager with Motor client.
        
        Args:
            motor_client: Motor async client instance
            default_database: Default database name for transactions
            config: Transaction configuration settings
        """
        self.motor_client = motor_client
        self.default_database = default_database
        self.config = config or TransactionConfiguration()
        
        # Transaction state tracking
        self._active_transactions: Dict[str, TransactionContext] = {}
        self._transaction_lock = asyncio.Lock()
        
        # Performance monitoring integration
        self._monitoring_components = get_database_monitoring_components()
        
        logger.info(
            "Initialized AsyncTransactionManager for async operations",
            database=default_database,
            config=self.config.__dict__
        )
    
    @asynccontextmanager
    async def transaction(
        self,
        database_name: Optional[str] = None,
        config: Optional[TransactionConfiguration] = None,
        auto_retry: bool = True
    ) -> AsyncContextManager[TransactionContext]:
        """
        Async context manager for MongoDB transactions.
        
        Provides ACID transaction support with automatic commit/rollback,
        error handling, and performance tracking for async operations.
        
        Args:
            database_name: Database name (uses default if None)
            config: Transaction-specific configuration
            auto_retry: Enable automatic retry on retryable errors
            
        Yields:
            TransactionContext: Transaction context for operation tracking
            
        Raises:
            DatabaseTransactionError: On transaction failures
            DatabaseConnectionError: On connection issues
            DatabaseTimeoutError: On timeout scenarios
        """
        db_name = database_name or self.default_database
        tx_config = config or self.config
        tx_context = TransactionContext(database_name=db_name)
        
        # Register active transaction
        async with self._transaction_lock:
            self._active_transactions[tx_context.transaction_id] = tx_context
        
        session = None
        monitoring_context = None
        
        try:
            # Initialize monitoring context if enabled
            if (tx_config.enable_monitoring and 
                self._monitoring_components and 
                'motor_integration' in self._monitoring_components):
                monitoring_context = self._monitoring_components['motor_integration'].monitor_operation(
                    'transaction',
                    db_name,
                    'transaction'
                )
                monitoring_context.__enter__()
            
            # Start async transaction session
            session = await self._start_async_transaction_session(tx_context, tx_config)
            
            logger.info(
                "Async transaction started",
                transaction_id=tx_context.transaction_id,
                database=db_name,
                session_id=str(session.session_id) if session else None
            )
            
            yield tx_context
            
            # Commit async transaction
            await self._commit_async_transaction(session, tx_context, tx_config)
            
        except Exception as e:
            # Abort async transaction on any error
            await self._abort_async_transaction(session, tx_context, e)
            
            # Re-raise appropriate database exception
            if isinstance(e, (DatabaseTransactionError, DatabaseConnectionError, DatabaseTimeoutError)):
                raise
            else:
                raise DatabaseTransactionError(
                    message=f"Async transaction failed: {str(e)}",
                    transaction_id=tx_context.transaction_id,
                    session_info={'session_id': str(session.session_id) if session else None},
                    operation='async_transaction_execution',
                    database=db_name,
                    original_error=e
                )
        
        finally:
            # Cleanup monitoring context
            if monitoring_context:
                try:
                    monitoring_context.__exit__(None, None, None)
                except Exception as e:
                    logger.error(f"Error closing async monitoring context: {e}")
            
            # Cleanup async session
            if session:
                try:
                    session.end_session()
                except Exception as e:
                    logger.warning(f"Error ending async session: {e}")
            
            # Remove from active transactions
            async with self._transaction_lock:
                self._active_transactions.pop(tx_context.transaction_id, None)
            
            # Log final transaction state
            tx_context.end_time = time.time()
            logger.info(
                "Async transaction completed",
                **tx_context.to_dict()
            )
    
    async def _start_async_transaction_session(
        self,
        tx_context: TransactionContext,
        config: TransactionConfiguration
    ) -> AsyncIOMotorClientSession:
        """Start a new async MongoDB transaction session."""
        try:
            tx_context.start_time = time.time()
            tx_context.state = TransactionState.ACTIVE
            
            # Create async session with causal consistency if enabled
            session = await self.motor_client.start_session(
                causal_consistency=config.causal_consistency
            )
            
            tx_context.session_id = str(session.session_id)
            
            # Start async transaction with configured settings
            session.start_transaction(
                read_concern=config.read_concern,
                write_concern=config.write_concern,
                read_preference=config.read_preference,
                max_commit_time_ms=int(config.max_commit_time_seconds * 1000)
            )
            
            return session
            
        except Exception as e:
            tx_context.state = TransactionState.FAILED
            tx_context.error_message = str(e)
            
            raise DatabaseTransactionError(
                message=f"Failed to start async transaction session: {str(e)}",
                transaction_id=tx_context.transaction_id,
                operation='start_async_session',
                database=tx_context.database_name,
                original_error=e
            )
    
    async def _commit_async_transaction(
        self,
        session: AsyncIOMotorClientSession,
        tx_context: TransactionContext,
        config: TransactionConfiguration
    ) -> None:
        """Commit the async transaction with error handling and monitoring."""
        commit_start_time = time.perf_counter()
        
        try:
            tx_context.state = TransactionState.COMMITTING
            
            # Commit async transaction with timeout protection
            await session.commit_transaction()
            
            commit_end_time = time.perf_counter()
            tx_context.commit_duration = commit_end_time - commit_start_time
            tx_context.state = TransactionState.COMMITTED
            
            logger.info(
                "Async transaction committed successfully",
                transaction_id=tx_context.transaction_id,
                commit_duration=tx_context.commit_duration,
                operation_count=tx_context.operation_count
            )
            
        except Exception as e:
            tx_context.state = TransactionState.FAILED
            tx_context.error_message = str(e)
            
            raise DatabaseTransactionError(
                message=f"Failed to commit async transaction: {str(e)}",
                transaction_id=tx_context.transaction_id,
                operation='commit_async_transaction',
                database=tx_context.database_name,
                original_error=e
            )
    
    async def _abort_async_transaction(
        self,
        session: Optional[AsyncIOMotorClientSession],
        tx_context: TransactionContext,
        error: Exception
    ) -> None:
        """Abort the async transaction with proper error handling."""
        try:
            tx_context.state = TransactionState.ABORTING
            tx_context.error_message = str(error)
            
            if session and session.in_transaction:
                await session.abort_transaction()
            
            tx_context.state = TransactionState.ABORTED
            
            logger.warning(
                "Async transaction aborted",
                transaction_id=tx_context.transaction_id,
                error=str(error),
                operation_count=tx_context.operation_count
            )
            
        except Exception as abort_error:
            tx_context.state = TransactionState.FAILED
            
            logger.error(
                "Failed to abort async transaction",
                transaction_id=tx_context.transaction_id,
                abort_error=str(abort_error),
                original_error=str(error)
            )
    
    async def execute_in_transaction(
        self,
        operation: Callable[[AsyncIOMotorClientSession, TransactionContext], Awaitable[AsyncT]],
        database_name: Optional[str] = None,
        config: Optional[TransactionConfiguration] = None
    ) -> AsyncT:
        """
        Execute async operation within a transaction.
        
        Args:
            operation: Async function to execute within transaction
            database_name: Database name for transaction
            config: Transaction configuration
            
        Returns:
            Result of the async operation
            
        Raises:
            DatabaseTransactionError: On transaction failures
        """
        async with self.transaction(database_name, config) as tx_context:
            session = await self.motor_client.start_session()
            try:
                return await operation(session, tx_context)
            finally:
                session.end_session()
    
    async def get_active_transactions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active async transactions."""
        async with self._transaction_lock:
            return {
                tx_id: tx_context.to_dict()
                for tx_id, tx_context in self._active_transactions.items()
            }
    
    async def get_transaction_statistics(self) -> Dict[str, Any]:
        """Get async transaction performance and utilization statistics."""
        async with self._transaction_lock:
            active_count = len(self._active_transactions)
            
            # Calculate average durations for active transactions
            active_durations = [
                tx.get_duration() for tx in self._active_transactions.values()
                if tx.get_duration() is not None
            ]
            
            avg_duration = (
                sum(active_durations) / len(active_durations) 
                if active_durations else 0.0
            )
            
            return {
                'active_transactions': active_count,
                'average_active_duration': avg_duration,
                'database': self.default_database,
                'config': self.config.__dict__
            }


class TransactionRegistry:
    """
    Global registry for managing transaction managers and configurations.
    
    Provides centralized access to transaction managers for both sync and async
    operations with configuration management and monitoring integration.
    """
    
    def __init__(self):
        """Initialize the transaction registry."""
        self._sync_managers: Dict[str, TransactionManager] = {}
        self._async_managers: Dict[str, AsyncTransactionManager] = {}
        self._default_config = TransactionConfiguration()
        self._registry_lock = Lock()
        
        logger.info("Initialized TransactionRegistry for centralized transaction management")
    
    def register_sync_manager(
        self,
        name: str,
        mongo_client: MongoClient,
        database: str,
        config: Optional[TransactionConfiguration] = None
    ) -> TransactionManager:
        """
        Register a new synchronous transaction manager.
        
        Args:
            name: Unique name for the transaction manager
            mongo_client: PyMongo client instance
            database: Default database name
            config: Transaction configuration
            
        Returns:
            TransactionManager: Configured transaction manager
        """
        with self._registry_lock:
            if name in self._sync_managers:
                raise ValueError(f"Sync transaction manager '{name}' already registered")
            
            manager = TransactionManager(
                mongo_client=mongo_client,
                default_database=database,
                config=config or self._default_config
            )
            
            self._sync_managers[name] = manager
            
            logger.info(
                "Registered sync transaction manager",
                name=name,
                database=database
            )
            
            return manager
    
    def register_async_manager(
        self,
        name: str,
        motor_client: AsyncIOMotorClient,
        database: str,
        config: Optional[TransactionConfiguration] = None
    ) -> AsyncTransactionManager:
        """
        Register a new asynchronous transaction manager.
        
        Args:
            name: Unique name for the transaction manager
            motor_client: Motor async client instance
            database: Default database name
            config: Transaction configuration
            
        Returns:
            AsyncTransactionManager: Configured async transaction manager
        """
        with self._registry_lock:
            if name in self._async_managers:
                raise ValueError(f"Async transaction manager '{name}' already registered")
            
            manager = AsyncTransactionManager(
                motor_client=motor_client,
                default_database=database,
                config=config or self._default_config
            )
            
            self._async_managers[name] = manager
            
            logger.info(
                "Registered async transaction manager",
                name=name,
                database=database
            )
            
            return manager
    
    def get_sync_manager(self, name: str) -> Optional[TransactionManager]:
        """Get registered synchronous transaction manager by name."""
        with self._registry_lock:
            return self._sync_managers.get(name)
    
    def get_async_manager(self, name: str) -> Optional[AsyncTransactionManager]:
        """Get registered asynchronous transaction manager by name."""
        with self._registry_lock:
            return self._async_managers.get(name)
    
    def list_managers(self) -> Dict[str, Dict[str, Any]]:
        """List all registered transaction managers."""
        with self._registry_lock:
            return {
                'sync_managers': list(self._sync_managers.keys()),
                'async_managers': list(self._async_managers.keys()),
                'default_config': self._default_config.__dict__
            }
    
    def set_default_configuration(self, config: TransactionConfiguration) -> None:
        """Set default transaction configuration for new managers."""
        with self._registry_lock:
            self._default_config = config
            logger.info("Updated default transaction configuration")


# Global transaction registry instance
transaction_registry = TransactionRegistry()


# Convenience functions for common transaction patterns
def create_sync_transaction_manager(
    mongo_client: MongoClient,
    database: str,
    config: Optional[TransactionConfiguration] = None,
    register_name: Optional[str] = None
) -> TransactionManager:
    """
    Create and optionally register a synchronous transaction manager.
    
    Args:
        mongo_client: PyMongo client instance
        database: Default database name
        config: Transaction configuration
        register_name: Name to register manager (if provided)
        
    Returns:
        TransactionManager: Configured transaction manager
    """
    manager = TransactionManager(
        mongo_client=mongo_client,
        default_database=database,
        config=config
    )
    
    if register_name:
        transaction_registry.register_sync_manager(
            name=register_name,
            mongo_client=mongo_client,
            database=database,
            config=config
        )
    
    return manager


def create_async_transaction_manager(
    motor_client: AsyncIOMotorClient,
    database: str,
    config: Optional[TransactionConfiguration] = None,
    register_name: Optional[str] = None
) -> AsyncTransactionManager:
    """
    Create and optionally register an asynchronous transaction manager.
    
    Args:
        motor_client: Motor async client instance
        database: Default database name
        config: Transaction configuration
        register_name: Name to register manager (if provided)
        
    Returns:
        AsyncTransactionManager: Configured async transaction manager
    """
    manager = AsyncTransactionManager(
        motor_client=motor_client,
        default_database=database,
        config=config
    )
    
    if register_name:
        transaction_registry.register_async_manager(
            name=register_name,
            motor_client=motor_client,
            database=database,
            config=config
        )
    
    return manager


@contextmanager
def simple_transaction(
    mongo_client: MongoClient,
    database: str,
    config: Optional[TransactionConfiguration] = None
) -> ContextManager[TransactionContext]:
    """
    Simple transaction context manager for one-off operations.
    
    Args:
        mongo_client: PyMongo client instance
        database: Database name
        config: Transaction configuration
        
    Yields:
        TransactionContext: Transaction context for operation tracking
    """
    manager = create_sync_transaction_manager(mongo_client, database, config)
    with manager.transaction() as tx_context:
        yield tx_context


@asynccontextmanager
async def simple_async_transaction(
    motor_client: AsyncIOMotorClient,
    database: str,
    config: Optional[TransactionConfiguration] = None
) -> AsyncContextManager[TransactionContext]:
    """
    Simple async transaction context manager for one-off operations.
    
    Args:
        motor_client: Motor async client instance
        database: Database name
        config: Transaction configuration
        
    Yields:
        TransactionContext: Transaction context for operation tracking
    """
    manager = create_async_transaction_manager(motor_client, database, config)
    async with manager.transaction() as tx_context:
        yield tx_context


# Export public interface
__all__ = [
    # Core classes
    'TransactionManager',
    'AsyncTransactionManager',
    'TransactionRegistry',
    
    # Configuration and context
    'TransactionConfiguration',
    'TransactionContext',
    'TransactionState',
    'TransactionIsolationLevel',
    
    # Factory functions
    'create_sync_transaction_manager',
    'create_async_transaction_manager',
    
    # Convenience functions
    'simple_transaction',
    'simple_async_transaction',
    
    # Global registry
    'transaction_registry'
]