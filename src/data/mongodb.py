"""
MongoDB Database Access Layer for Python/Flask Migration

This module implements comprehensive MongoDB database operations using PyMongo 4.5+ synchronous
driver, providing CRUD functionality, query execution, transaction management, and performance
monitoring to maintain ≤10% variance from Node.js baseline performance.

Key Features:
- PyMongo 4.5+ synchronous MongoDB driver implementation
- Complete CRUD operations maintaining identical query patterns from Node.js
- Transaction management with commit/rollback support for data consistency
- Connection pool monitoring and health checks for enterprise-grade reliability
- Prometheus metrics integration for performance baseline comparison
- Comprehensive error handling with retry logic and circuit breaker patterns
- Thread-safe database operations with optimized connection pooling
- Performance monitoring integration for ≤10% variance compliance

Architecture Integration:
- Integrates with src/config/database.py for centralized connection management
- Uses src/data/exceptions.py for comprehensive error handling and recovery
- Leverages src/data/monitoring.py for performance metrics and observability
- Supports Flask application factory pattern with monitoring initialization
- Enables structured logging for database operations and performance events

Technical Requirements Compliance:
- Section 0.1.2: MongoDB driver conversion from Node.js to PyMongo 4.5+
- Section 6.2.1: Complete preservation of existing MongoDB document structures
- Section 3.4.3: Query pattern compatibility maintaining identical patterns from Node.js
- Section 5.2.5: Connection pool management for resource efficiency and optimization
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
"""

import asyncio
import gc
import logging
import time
import threading
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple, Callable, AsyncGenerator
from functools import wraps
from threading import Lock, RLock

# MongoDB drivers and operations
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    PyMongoError, ConnectionFailure, OperationFailure, 
    ServerSelectionTimeoutError, DuplicateKeyError,
    ExecutionTimeout, NetworkTimeout, WriteError,
    WriteConcernError, BulkWriteError
)
from pymongo.results import (
    InsertOneResult, InsertManyResult, UpdateResult, 
    DeleteResult, BulkWriteResult
)
from bson import ObjectId
from bson.errors import InvalidId

# Motor async driver for high-performance operations
try:
    import motor.motor_asyncio
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

# Application imports
from src.config.database import (
    get_database_config, get_mongodb_client, get_motor_client,
    get_database, get_async_database, DatabaseConnectionError
)
from src.data.exceptions import (
    DatabaseException, ConnectionException, TimeoutException,
    TransactionException, QueryException, ResourceException,
    with_database_retry, handle_database_error, mongodb_circuit_breaker,
    DatabaseOperationType, DatabaseErrorSeverity, DatabaseErrorCategory
)
from src.data.monitoring import (
    DatabaseMonitoringManager, monitor_database_operation,
    monitor_async_database_operation, monitor_database_transaction
)

# Configure module logger
logger = logging.getLogger(__name__)


class MongoDBManager:
    """
    Comprehensive MongoDB database manager implementing PyMongo 4.5+ synchronous operations
    with transaction management, connection pooling, and performance monitoring.
    
    This manager provides enterprise-grade MongoDB operations including:
    - CRUD operations maintaining Node.js query pattern compatibility
    - Transaction management with commit/rollback support
    - Connection pool optimization and health monitoring
    - Performance metrics collection for baseline comparison
    - Comprehensive error handling with retry logic and circuit breakers
    - Thread-safe operations with optimized resource utilization
    
    Features:
    - PyMongo 4.5+ driver with optimized connection pooling per Section 5.2.5
    - Complete MongoDB document structure preservation per Section 6.2.1
    - Query execution patterns identical to Node.js implementation per Section 3.4.3
    - Performance monitoring ensuring ≤10% variance compliance per Section 0.1.1
    - Integration with monitoring infrastructure per Section 6.2.4
    """
    
    def __init__(self, database_name: Optional[str] = None, monitoring_enabled: bool = True):
        """
        Initialize MongoDB manager with comprehensive configuration.
        
        Args:
            database_name: Target database name (defaults to configured database)
            monitoring_enabled: Enable performance monitoring and metrics collection
        """
        self.database_name = database_name
        self.monitoring_enabled = monitoring_enabled
        self._lock = RLock()
        self._transaction_sessions = {}
        self._operation_stats = defaultdict(lambda: {'count': 0, 'total_time': 0.0})
        
        # Initialize database connections
        self._initialize_connections()
        
        # Initialize monitoring if enabled
        self._monitoring_manager = None
        if monitoring_enabled:
            self._initialize_monitoring()
        
        logger.info(
            "MongoDB manager initialized",
            database_name=self.database_name,
            monitoring_enabled=monitoring_enabled,
            pymongo_available=True,
            motor_available=MOTOR_AVAILABLE
        )
    
    def _initialize_connections(self):
        """Initialize PyMongo and Motor database connections with validation."""
        try:
            # Initialize synchronous PyMongo connection
            self._client = get_mongodb_client()
            self._database = get_database(self.database_name)
            
            # Test connection
            self._client.admin.command('ping')
            
            # Initialize async Motor connection if available
            if MOTOR_AVAILABLE:
                self._motor_client = get_motor_client()
                self._async_database = get_async_database(self.database_name)
            else:
                self._motor_client = None
                self._async_database = None
            
            logger.info(
                "Database connections initialized successfully",
                sync_connection=True,
                async_connection=MOTOR_AVAILABLE
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize database connections: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(
                error_msg,
                database=self.database_name,
                original_error=e
            )
    
    def _initialize_monitoring(self):
        """Initialize database monitoring and metrics collection."""
        try:
            # Initialize monitoring manager (would typically be provided by Flask app)
            # For now, create a local instance for development
            self._monitoring_manager = DatabaseMonitoringManager()
            
            # Register clients for monitoring
            if hasattr(self, '_client'):
                self._monitoring_manager.register_pymongo_client(self._client)
            
            if hasattr(self, '_motor_client') and self._motor_client:
                self._monitoring_manager.register_motor_client(self._motor_client)
            
            logger.info("Database monitoring initialized successfully")
            
        except Exception as e:
            logger.warning(f"Failed to initialize monitoring: {str(e)}")
            self._monitoring_manager = None
    
    @property
    def client(self) -> MongoClient:
        """Get PyMongo synchronous client instance."""
        return self._client
    
    @property
    def database(self) -> Database:
        """Get PyMongo synchronous database instance."""
        return self._database
    
    @property
    def motor_client(self) -> Optional['AsyncIOMotorClient']:
        """Get Motor async client instance if available."""
        return getattr(self, '_motor_client', None)
    
    @property
    def async_database(self) -> Optional['AsyncIOMotorDatabase']:
        """Get Motor async database instance if available."""
        return getattr(self, '_async_database', None)
    
    def get_collection(self, collection_name: str) -> Collection:
        """
        Get MongoDB collection instance for synchronous operations.
        
        Args:
            collection_name: Name of the MongoDB collection
            
        Returns:
            Collection: PyMongo collection instance
        """
        return self.database[collection_name]
    
    def get_async_collection(self, collection_name: str) -> Optional['AsyncIOMotorCollection']:
        """
        Get MongoDB collection instance for asynchronous operations.
        
        Args:
            collection_name: Name of the MongoDB collection
            
        Returns:
            AsyncIOMotorCollection: Motor async collection instance or None
        """
        if self.async_database:
            return self.async_database[collection_name]
        return None
    
    # CRUD Operations - Create
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "insert_one")
    def insert_one(self, collection_name: str, document: Dict[str, Any], 
                   session=None, **kwargs) -> InsertOneResult:
        """
        Insert a single document into MongoDB collection.
        
        Implements PyMongo insert operation maintaining identical patterns from Node.js
        implementation with comprehensive error handling and performance monitoring.
        
        Args:
            collection_name: Target collection name
            document: Document to insert
            session: Transaction session (optional)
            **kwargs: Additional PyMongo insert options
            
        Returns:
            InsertOneResult: Result of insert operation
            
        Raises:
            QueryException: On document validation or insertion errors
            ConnectionException: On database connection failures
            TransactionException: On transaction-related errors
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Add timestamp if not present (maintaining Node.js patterns)
            if 'created_at' not in document:
                document['created_at'] = datetime.now(timezone.utc)
            if 'updated_at' not in document:
                document['updated_at'] = datetime.now(timezone.utc)
            
            # Execute insert operation
            result = collection.insert_one(document, session=session, **kwargs)
            
            # Record operation metrics
            self._record_operation_stats('insert_one', collection_name, start_time)
            
            logger.info(
                "Document inserted successfully",
                collection=collection_name,
                document_id=str(result.inserted_id),
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except DuplicateKeyError as e:
            raise QueryException(
                f"Duplicate key error in collection '{collection_name}': {str(e)}",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.WRITE,
                original_error=e
            )
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            raise ConnectionException(
                f"Database connection error during insert: {str(e)}",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.WRITE,
                original_error=e
            )
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "insert_many")
    def insert_many(self, collection_name: str, documents: List[Dict[str, Any]], 
                    ordered: bool = True, session=None, **kwargs) -> InsertManyResult:
        """
        Insert multiple documents into MongoDB collection with bulk optimization.
        
        Args:
            collection_name: Target collection name
            documents: List of documents to insert
            ordered: Whether to execute inserts in order (affects error handling)
            session: Transaction session (optional)
            **kwargs: Additional PyMongo insert options
            
        Returns:
            InsertManyResult: Result of bulk insert operation
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Add timestamps to all documents
            current_time = datetime.now(timezone.utc)
            for doc in documents:
                if 'created_at' not in doc:
                    doc['created_at'] = current_time
                if 'updated_at' not in doc:
                    doc['updated_at'] = current_time
            
            # Execute bulk insert operation
            result = collection.insert_many(
                documents, ordered=ordered, session=session, **kwargs
            )
            
            # Record operation metrics
            self._record_operation_stats('insert_many', collection_name, start_time)
            
            logger.info(
                "Documents inserted successfully",
                collection=collection_name,
                inserted_count=len(result.inserted_ids),
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except BulkWriteError as e:
            # Extract successful and failed operations
            successful_count = len(e.details.get('writeErrors', []))
            total_count = len(documents)
            
            raise QueryException(
                f"Bulk insert partially failed: {successful_count}/{total_count} succeeded",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.WRITE,
                original_error=e
            )
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    # CRUD Operations - Read
    
    @with_database_retry(operation_type=DatabaseOperationType.READ)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "find_one")
    def find_one(self, collection_name: str, filter_dict: Dict[str, Any] = None,
                 projection: Dict[str, Any] = None, session=None, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Find a single document in MongoDB collection.
        
        Implements PyMongo find_one operation maintaining identical query patterns
        from Node.js implementation with performance optimization and monitoring.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter (defaults to empty dict)
            projection: Fields to include/exclude in result
            session: Transaction session (optional)
            **kwargs: Additional PyMongo find options
            
        Returns:
            Optional[Dict[str, Any]]: Found document or None
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            filter_dict = filter_dict or {}
            
            # Execute find operation
            result = collection.find_one(
                filter_dict, projection=projection, session=session, **kwargs
            )
            
            # Record operation metrics
            self._record_operation_stats('find_one', collection_name, start_time)
            
            logger.debug(
                "Find one operation completed",
                collection=collection_name,
                filter_fields=list(filter_dict.keys()) if filter_dict else [],
                found=result is not None,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except (ExecutionTimeout, NetworkTimeout) as e:
            raise TimeoutException(
                f"Query timeout in collection '{collection_name}': {str(e)}",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.READ,
                original_error=e
            )
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.READ, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.READ)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "find_many")
    def find_many(self, collection_name: str, filter_dict: Dict[str, Any] = None,
                  projection: Dict[str, Any] = None, sort: List[Tuple[str, int]] = None,
                  limit: int = None, skip: int = None, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        Find multiple documents in MongoDB collection with cursor optimization.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter (defaults to empty dict)
            projection: Fields to include/exclude in result
            sort: Sort specification as list of (field, direction) tuples
            limit: Maximum number of documents to return
            skip: Number of documents to skip
            session: Transaction session (optional)
            **kwargs: Additional PyMongo find options
            
        Returns:
            List[Dict[str, Any]]: List of found documents
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            filter_dict = filter_dict or {}
            
            # Build cursor with options
            cursor = collection.find(filter_dict, projection=projection, session=session, **kwargs)
            
            if sort:
                cursor = cursor.sort(sort)
            if skip:
                cursor = cursor.skip(skip)
            if limit:
                cursor = cursor.limit(limit)
            
            # Execute query and convert to list
            result = list(cursor)
            
            # Record operation metrics
            self._record_operation_stats('find_many', collection_name, start_time)
            
            logger.debug(
                "Find many operation completed",
                collection=collection_name,
                filter_fields=list(filter_dict.keys()) if filter_dict else [],
                result_count=len(result),
                limit=limit,
                skip=skip,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except (ExecutionTimeout, NetworkTimeout) as e:
            raise TimeoutException(
                f"Query timeout in collection '{collection_name}': {str(e)}",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.READ,
                original_error=e
            )
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.READ, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.READ)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "count_documents")
    def count_documents(self, collection_name: str, filter_dict: Dict[str, Any] = None,
                       session=None, **kwargs) -> int:
        """
        Count documents in MongoDB collection matching filter criteria.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter (defaults to empty dict)
            session: Transaction session (optional)
            **kwargs: Additional PyMongo count options
            
        Returns:
            int: Number of matching documents
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            filter_dict = filter_dict or {}
            
            # Execute count operation
            result = collection.count_documents(filter_dict, session=session, **kwargs)
            
            # Record operation metrics
            self._record_operation_stats('count_documents', collection_name, start_time)
            
            logger.debug(
                "Count documents operation completed",
                collection=collection_name,
                filter_fields=list(filter_dict.keys()) if filter_dict else [],
                count=result,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.READ, self.database_name, collection_name
            )
    
    # CRUD Operations - Update
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "update_one")
    def update_one(self, collection_name: str, filter_dict: Dict[str, Any],
                   update_dict: Dict[str, Any], upsert: bool = False,
                   session=None, **kwargs) -> UpdateResult:
        """
        Update a single document in MongoDB collection.
        
        Implements PyMongo update operation maintaining identical update patterns
        from Node.js implementation with automatic timestamp management.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter to identify document
            update_dict: Update operations to apply
            upsert: Create document if not found
            session: Transaction session (optional)
            **kwargs: Additional PyMongo update options
            
        Returns:
            UpdateResult: Result of update operation
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Add updated_at timestamp (maintaining Node.js patterns)
            if '$set' not in update_dict:
                update_dict['$set'] = {}
            update_dict['$set']['updated_at'] = datetime.now(timezone.utc)
            
            # Add created_at for upsert operations
            if upsert and '$setOnInsert' not in update_dict:
                update_dict['$setOnInsert'] = {}
            if upsert:
                update_dict['$setOnInsert']['created_at'] = datetime.now(timezone.utc)
            
            # Execute update operation
            result = collection.update_one(
                filter_dict, update_dict, upsert=upsert, session=session, **kwargs
            )
            
            # Record operation metrics
            self._record_operation_stats('update_one', collection_name, start_time)
            
            logger.info(
                "Document updated successfully",
                collection=collection_name,
                matched_count=result.matched_count,
                modified_count=result.modified_count,
                upserted_id=str(result.upserted_id) if result.upserted_id else None,
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "update_many")
    def update_many(self, collection_name: str, filter_dict: Dict[str, Any],
                    update_dict: Dict[str, Any], upsert: bool = False,
                    session=None, **kwargs) -> UpdateResult:
        """
        Update multiple documents in MongoDB collection with bulk optimization.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter to identify documents
            update_dict: Update operations to apply
            upsert: Create document if not found
            session: Transaction session (optional)
            **kwargs: Additional PyMongo update options
            
        Returns:
            UpdateResult: Result of bulk update operation
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Add updated_at timestamp
            if '$set' not in update_dict:
                update_dict['$set'] = {}
            update_dict['$set']['updated_at'] = datetime.now(timezone.utc)
            
            # Execute bulk update operation
            result = collection.update_many(
                filter_dict, update_dict, upsert=upsert, session=session, **kwargs
            )
            
            # Record operation metrics
            self._record_operation_stats('update_many', collection_name, start_time)
            
            logger.info(
                "Documents updated successfully",
                collection=collection_name,
                matched_count=result.matched_count,
                modified_count=result.modified_count,
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    # CRUD Operations - Delete
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "delete_one")
    def delete_one(self, collection_name: str, filter_dict: Dict[str, Any],
                   session=None, **kwargs) -> DeleteResult:
        """
        Delete a single document from MongoDB collection.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter to identify document
            session: Transaction session (optional)
            **kwargs: Additional PyMongo delete options
            
        Returns:
            DeleteResult: Result of delete operation
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Execute delete operation
            result = collection.delete_one(filter_dict, session=session, **kwargs)
            
            # Record operation metrics
            self._record_operation_stats('delete_one', collection_name, start_time)
            
            logger.info(
                "Document deleted successfully",
                collection=collection_name,
                deleted_count=result.deleted_count,
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.WRITE)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "delete_many")
    def delete_many(self, collection_name: str, filter_dict: Dict[str, Any],
                    session=None, **kwargs) -> DeleteResult:
        """
        Delete multiple documents from MongoDB collection with bulk optimization.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter to identify documents
            session: Transaction session (optional)
            **kwargs: Additional PyMongo delete options
            
        Returns:
            DeleteResult: Result of bulk delete operation
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Execute bulk delete operation
            result = collection.delete_many(filter_dict, session=session, **kwargs)
            
            # Record operation metrics
            self._record_operation_stats('delete_many', collection_name, start_time)
            
            logger.info(
                "Documents deleted successfully",
                collection=collection_name,
                deleted_count=result.deleted_count,
                acknowledged=result.acknowledged,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    # Advanced Query Operations
    
    @with_database_retry(operation_type=DatabaseOperationType.READ)
    @mongodb_circuit_breaker
    @monitor_database_operation("", "", "aggregate")
    def aggregate(self, collection_name: str, pipeline: List[Dict[str, Any]],
                  session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute MongoDB aggregation pipeline with performance optimization.
        
        Implements PyMongo aggregation maintaining identical pipeline patterns
        from Node.js implementation with comprehensive error handling.
        
        Args:
            collection_name: Target collection name
            pipeline: Aggregation pipeline stages
            session: Transaction session (optional)
            **kwargs: Additional PyMongo aggregation options
            
        Returns:
            List[Dict[str, Any]]: Aggregation results
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Execute aggregation pipeline
            cursor = collection.aggregate(pipeline, session=session, **kwargs)
            result = list(cursor)
            
            # Record operation metrics
            self._record_operation_stats('aggregate', collection_name, start_time)
            
            logger.info(
                "Aggregation pipeline completed",
                collection=collection_name,
                pipeline_stages=len(pipeline),
                result_count=len(result),
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except (ExecutionTimeout, NetworkTimeout) as e:
            raise TimeoutException(
                f"Aggregation timeout in collection '{collection_name}': {str(e)}",
                database=self.database_name,
                collection=collection_name,
                operation=DatabaseOperationType.AGGREGATION,
                original_error=e
            )
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.AGGREGATION, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.READ)
    @mongodb_circuit_breaker
    def find_one_by_id(self, collection_name: str, document_id: Union[str, ObjectId],
                       projection: Dict[str, Any] = None, session=None) -> Optional[Dict[str, Any]]:
        """
        Find document by ObjectId with validation and error handling.
        
        Args:
            collection_name: Target collection name
            document_id: Document ObjectId (string or ObjectId)
            projection: Fields to include/exclude in result
            session: Transaction session (optional)
            
        Returns:
            Optional[Dict[str, Any]]: Found document or None
            
        Raises:
            QueryException: On invalid ObjectId format
        """
        try:
            # Convert string ID to ObjectId if necessary
            if isinstance(document_id, str):
                try:
                    object_id = ObjectId(document_id)
                except InvalidId as e:
                    raise QueryException(
                        f"Invalid ObjectId format: {document_id}",
                        database=self.database_name,
                        collection=collection_name,
                        operation=DatabaseOperationType.READ,
                        original_error=e
                    )
            else:
                object_id = document_id
            
            return self.find_one(
                collection_name,
                {'_id': object_id},
                projection=projection,
                session=session
            )
            
        except Exception as e:
            if isinstance(e, (DatabaseException, QueryException)):
                raise
            raise handle_database_error(
                e, DatabaseOperationType.READ, self.database_name, collection_name
            )
    
    # Transaction Management
    
    @contextmanager
    @monitor_database_transaction("")
    def transaction(self, read_concern=None, write_concern=None, read_preference=None):
        """
        Context manager for MongoDB transactions with comprehensive error handling.
        
        Implements MongoDB multi-document transactions with automatic commit/rollback
        and performance monitoring per Section 4.2.2 state management requirements.
        
        Args:
            read_concern: Read concern for transaction
            write_concern: Write concern for transaction
            read_preference: Read preference for transaction
            
        Yields:
            session: MongoDB session for transaction operations
            
        Example:
            with mongodb_manager.transaction() as session:
                mongodb_manager.insert_one('collection1', doc1, session=session)
                mongodb_manager.update_one('collection2', filter, update, session=session)
        """
        session = None
        transaction_id = f"txn_{uuid.uuid4().hex[:8]}"
        
        try:
            # Start client session
            session = self.client.start_session()
            
            # Configure transaction options
            transaction_options = {}
            if read_concern:
                transaction_options['read_concern'] = read_concern
            if write_concern:
                transaction_options['write_concern'] = write_concern
            if read_preference:
                transaction_options['read_preference'] = read_preference
            
            # Start transaction
            session.start_transaction(**transaction_options)
            
            # Track active transaction
            with self._lock:
                self._transaction_sessions[transaction_id] = {
                    'session': session,
                    'start_time': time.perf_counter(),
                    'status': 'active'
                }
            
            logger.info(
                "Transaction started",
                transaction_id=transaction_id,
                database=self.database_name
            )
            
            yield session
            
            # Commit transaction if successful
            session.commit_transaction()
            
            with self._lock:
                if transaction_id in self._transaction_sessions:
                    self._transaction_sessions[transaction_id]['status'] = 'committed'
            
            logger.info(
                "Transaction committed successfully",
                transaction_id=transaction_id,
                database=self.database_name
            )
            
        except Exception as e:
            # Rollback transaction on any error
            if session and session.in_transaction:
                try:
                    session.abort_transaction()
                    
                    with self._lock:
                        if transaction_id in self._transaction_sessions:
                            self._transaction_sessions[transaction_id]['status'] = 'rolled_back'
                    
                    logger.warning(
                        "Transaction rolled back due to error",
                        transaction_id=transaction_id,
                        database=self.database_name,
                        error=str(e)
                    )
                except Exception as rollback_error:
                    logger.error(
                        "Failed to rollback transaction",
                        transaction_id=transaction_id,
                        rollback_error=str(rollback_error)
                    )
            
            # Convert to appropriate exception type
            if isinstance(e, PyMongoError):
                raise TransactionException(
                    f"Transaction failed: {str(e)}",
                    database=self.database_name,
                    transaction_id=transaction_id,
                    original_error=e
                )
            raise
        
        finally:
            # Clean up session and tracking
            if session:
                try:
                    session.end_session()
                except Exception as e:
                    logger.warning(f"Error ending session: {str(e)}")
            
            with self._lock:
                self._transaction_sessions.pop(transaction_id, None)
    
    # Index Management
    
    @with_database_retry(operation_type=DatabaseOperationType.INDEX)
    @mongodb_circuit_breaker
    def create_index(self, collection_name: str, keys: Union[str, List[Tuple[str, int]]],
                     **kwargs) -> str:
        """
        Create index on MongoDB collection with performance optimization.
        
        Args:
            collection_name: Target collection name
            keys: Index specification (field name or list of (field, direction) tuples)
            **kwargs: Additional index options (unique, sparse, etc.)
            
        Returns:
            str: Name of created index
        """
        try:
            collection = self.get_collection(collection_name)
            
            # Normalize keys specification
            if isinstance(keys, str):
                index_keys = [(keys, ASCENDING)]
            else:
                index_keys = keys
            
            result = collection.create_index(index_keys, **kwargs)
            
            logger.info(
                "Index created successfully",
                collection=collection_name,
                index_name=result,
                keys=index_keys
            )
            
            return result
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.INDEX, self.database_name, collection_name
            )
    
    @with_database_retry(operation_type=DatabaseOperationType.INDEX)
    @mongodb_circuit_breaker
    def list_indexes(self, collection_name: str) -> List[Dict[str, Any]]:
        """
        List all indexes on MongoDB collection.
        
        Args:
            collection_name: Target collection name
            
        Returns:
            List[Dict[str, Any]]: List of index specifications
        """
        try:
            collection = self.get_collection(collection_name)
            return list(collection.list_indexes())
            
        except PyMongoError as e:
            raise handle_database_error(
                e, DatabaseOperationType.INDEX, self.database_name, collection_name
            )
    
    # Health Check and Monitoring
    
    def health_check(self) -> Dict[str, Any]:
        """
        Comprehensive database health check with connection validation.
        
        Returns:
            Dict[str, Any]: Health status information
        """
        health_status = {
            'status': 'unknown',
            'database': self.database_name,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'connections': {},
            'operations': {},
            'monitoring': {}
        }
        
        try:
            # Test PyMongo connection
            start_time = time.perf_counter()
            self.client.admin.command('ping')
            pymongo_latency = (time.perf_counter() - start_time) * 1000
            
            health_status['connections']['pymongo'] = {
                'status': 'healthy',
                'latency_ms': pymongo_latency
            }
            
            # Test Motor connection if available
            if self.motor_client:
                health_status['connections']['motor'] = {
                    'status': 'available',
                    'note': 'async health check requires asyncio context'
                }
            
            # Get operation statistics
            health_status['operations'] = self._get_operation_stats()
            
            # Get monitoring status
            if self._monitoring_manager:
                health_status['monitoring'] = {
                    'enabled': True,
                    'status': 'active'
                }
            else:
                health_status['monitoring'] = {
                    'enabled': False,
                    'status': 'disabled'
                }
            
            health_status['status'] = 'healthy'
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
            health_status['error_type'] = type(e).__name__
        
        return health_status
    
    def _record_operation_stats(self, operation: str, collection: str, start_time: float):
        """Record operation statistics for performance monitoring."""
        duration = time.perf_counter() - start_time
        
        with self._lock:
            key = f"{operation}:{collection}"
            stats = self._operation_stats[key]
            stats['count'] += 1
            stats['total_time'] += duration
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['last_operation'] = time.time()
    
    def _get_operation_stats(self) -> Dict[str, Any]:
        """Get comprehensive operation statistics for monitoring."""
        with self._lock:
            return {
                'total_operations': sum(stats['count'] for stats in self._operation_stats.values()),
                'operations_by_type': dict(self._operation_stats),
                'active_transactions': len(self._transaction_sessions)
            }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get detailed performance metrics for baseline comparison.
        
        Returns:
            Dict[str, Any]: Performance metrics and statistics
        """
        return {
            'database': self.database_name,
            'operations': self._get_operation_stats(),
            'health': self.health_check(),
            'monitoring_enabled': self.monitoring_enabled,
            'pymongo_available': True,
            'motor_available': MOTOR_AVAILABLE,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Async MongoDB Operations (Motor Driver)

class AsyncMongoDBManager:
    """
    Asynchronous MongoDB manager implementing Motor 3.3+ driver for high-performance
    async database operations with comprehensive monitoring and error handling.
    
    This manager provides async MongoDB operations including:
    - High-performance async CRUD operations using Motor 3.3+
    - Async transaction management with commit/rollback support
    - Connection pool optimization for async operations
    - Performance monitoring integration for baseline comparison
    - Comprehensive error handling with async retry patterns
    """
    
    def __init__(self, database_name: Optional[str] = None, monitoring_enabled: bool = True):
        """
        Initialize async MongoDB manager.
        
        Args:
            database_name: Target database name
            monitoring_enabled: Enable performance monitoring
        """
        if not MOTOR_AVAILABLE:
            raise ImportError("Motor async driver not available")
        
        self.database_name = database_name
        self.monitoring_enabled = monitoring_enabled
        self._lock = asyncio.Lock()
        self._operation_stats = defaultdict(lambda: {'count': 0, 'total_time': 0.0})
        
        # Initialize async connections
        self._motor_client = None
        self._async_database = None
        
        logger.info(
            "Async MongoDB manager initialized",
            database_name=database_name,
            monitoring_enabled=monitoring_enabled
        )
    
    async def initialize(self):
        """Initialize async database connections."""
        try:
            self._motor_client = get_motor_client()
            self._async_database = get_async_database(self.database_name)
            
            # Test async connection
            await self._motor_client.admin.command('ping')
            
            logger.info("Async database connections initialized successfully")
            
        except Exception as e:
            error_msg = f"Failed to initialize async database connections: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(
                error_msg,
                database=self.database_name,
                original_error=e
            )
    
    @property
    def motor_client(self) -> 'AsyncIOMotorClient':
        """Get Motor async client instance."""
        if not self._motor_client:
            raise RuntimeError("Async client not initialized. Call initialize() first.")
        return self._motor_client
    
    @property
    def database(self) -> 'AsyncIOMotorDatabase':
        """Get Motor async database instance."""
        if not self._async_database:
            raise RuntimeError("Async database not initialized. Call initialize() first.")
        return self._async_database
    
    def get_collection(self, collection_name: str) -> 'AsyncIOMotorCollection':
        """Get Motor async collection instance."""
        return self.database[collection_name]
    
    @monitor_async_database_operation("", "", "insert_one")
    async def insert_one(self, collection_name: str, document: Dict[str, Any],
                        session=None, **kwargs) -> 'motor.core.AgnosticInsertOneResult':
        """
        Async insert single document with performance monitoring.
        
        Args:
            collection_name: Target collection name
            document: Document to insert
            session: Transaction session (optional)
            **kwargs: Additional Motor insert options
            
        Returns:
            Motor InsertOneResult
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            
            # Add timestamps
            if 'created_at' not in document:
                document['created_at'] = datetime.now(timezone.utc)
            if 'updated_at' not in document:
                document['updated_at'] = datetime.now(timezone.utc)
            
            result = await collection.insert_one(document, session=session, **kwargs)
            
            # Record operation metrics
            await self._record_operation_stats('async_insert_one', collection_name, start_time)
            
            logger.info(
                "Async document inserted successfully",
                collection=collection_name,
                document_id=str(result.inserted_id),
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except Exception as e:
            raise handle_database_error(
                e, DatabaseOperationType.WRITE, self.database_name, collection_name
            )
    
    @monitor_async_database_operation("", "", "find_one")
    async def find_one(self, collection_name: str, filter_dict: Dict[str, Any] = None,
                      projection: Dict[str, Any] = None, session=None, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Async find single document with performance monitoring.
        
        Args:
            collection_name: Target collection name
            filter_dict: Query filter
            projection: Fields to include/exclude
            session: Transaction session (optional)
            **kwargs: Additional Motor find options
            
        Returns:
            Optional[Dict[str, Any]]: Found document or None
        """
        start_time = time.perf_counter()
        
        try:
            collection = self.get_collection(collection_name)
            filter_dict = filter_dict or {}
            
            result = await collection.find_one(
                filter_dict, projection=projection, session=session, **kwargs
            )
            
            # Record operation metrics
            await self._record_operation_stats('async_find_one', collection_name, start_time)
            
            logger.debug(
                "Async find one operation completed",
                collection=collection_name,
                found=result is not None,
                duration_ms=(time.perf_counter() - start_time) * 1000
            )
            
            return result
            
        except Exception as e:
            raise handle_database_error(
                e, DatabaseOperationType.READ, self.database_name, collection_name
            )
    
    async def _record_operation_stats(self, operation: str, collection: str, start_time: float):
        """Record async operation statistics."""
        duration = time.perf_counter() - start_time
        
        async with self._lock:
            key = f"{operation}:{collection}"
            stats = self._operation_stats[key]
            stats['count'] += 1
            stats['total_time'] += duration
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['last_operation'] = time.time()
    
    async def health_check(self) -> Dict[str, Any]:
        """Async database health check."""
        health_status = {
            'status': 'unknown',
            'database': self.database_name,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': 'async_motor'
        }
        
        try:
            # Test Motor connection
            start_time = time.perf_counter()
            await self.motor_client.admin.command('ping')
            latency = (time.perf_counter() - start_time) * 1000
            
            health_status['status'] = 'healthy'
            health_status['latency_ms'] = latency
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status


# Factory Functions and Utilities

def create_mongodb_manager(database_name: Optional[str] = None, 
                          monitoring_enabled: bool = True) -> MongoDBManager:
    """
    Factory function to create MongoDB manager instance.
    
    Args:
        database_name: Target database name
        monitoring_enabled: Enable performance monitoring
        
    Returns:
        MongoDBManager: Configured MongoDB manager instance
    """
    return MongoDBManager(database_name=database_name, monitoring_enabled=monitoring_enabled)


async def create_async_mongodb_manager(database_name: Optional[str] = None,
                                     monitoring_enabled: bool = True) -> AsyncMongoDBManager:
    """
    Factory function to create async MongoDB manager instance.
    
    Args:
        database_name: Target database name
        monitoring_enabled: Enable performance monitoring
        
    Returns:
        AsyncMongoDBManager: Configured async MongoDB manager instance
    """
    manager = AsyncMongoDBManager(database_name=database_name, monitoring_enabled=monitoring_enabled)
    await manager.initialize()
    return manager


def validate_object_id(object_id: Union[str, ObjectId]) -> ObjectId:
    """
    Validate and convert ObjectId with comprehensive error handling.
    
    Args:
        object_id: ObjectId string or ObjectId instance
        
    Returns:
        ObjectId: Validated ObjectId instance
        
    Raises:
        QueryException: On invalid ObjectId format
    """
    try:
        if isinstance(object_id, str):
            return ObjectId(object_id)
        elif isinstance(object_id, ObjectId):
            return object_id
        else:
            raise ValueError(f"Invalid ObjectId type: {type(object_id)}")
    except (InvalidId, ValueError) as e:
        raise QueryException(
            f"Invalid ObjectId format: {object_id}",
            operation=DatabaseOperationType.READ,
            original_error=e
        )


# Global MongoDB manager instance for application use
_mongodb_manager: Optional[MongoDBManager] = None
_async_mongodb_manager: Optional[AsyncMongoDBManager] = None


def init_mongodb_manager(database_name: Optional[str] = None, 
                        monitoring_enabled: bool = True) -> MongoDBManager:
    """
    Initialize global MongoDB manager instance.
    
    Args:
        database_name: Target database name
        monitoring_enabled: Enable performance monitoring
        
    Returns:
        MongoDBManager: Global MongoDB manager instance
    """
    global _mongodb_manager
    _mongodb_manager = create_mongodb_manager(database_name, monitoring_enabled)
    logger.info(f"Global MongoDB manager initialized: {database_name}")
    return _mongodb_manager


async def init_async_mongodb_manager(database_name: Optional[str] = None,
                                   monitoring_enabled: bool = True) -> AsyncMongoDBManager:
    """
    Initialize global async MongoDB manager instance.
    
    Args:
        database_name: Target database name
        monitoring_enabled: Enable performance monitoring
        
    Returns:
        AsyncMongoDBManager: Global async MongoDB manager instance
    """
    global _async_mongodb_manager
    _async_mongodb_manager = await create_async_mongodb_manager(database_name, monitoring_enabled)
    logger.info(f"Global async MongoDB manager initialized: {database_name}")
    return _async_mongodb_manager


def get_mongodb_manager() -> MongoDBManager:
    """
    Get global MongoDB manager instance.
    
    Returns:
        MongoDBManager: Global MongoDB manager instance
        
    Raises:
        RuntimeError: If manager not initialized
    """
    if _mongodb_manager is None:
        raise RuntimeError("MongoDB manager not initialized. Call init_mongodb_manager() first.")
    return _mongodb_manager


def get_async_mongodb_manager() -> AsyncMongoDBManager:
    """
    Get global async MongoDB manager instance.
    
    Returns:
        AsyncMongoDBManager: Global async MongoDB manager instance
        
    Raises:
        RuntimeError: If async manager not initialized
    """
    if _async_mongodb_manager is None:
        raise RuntimeError("Async MongoDB manager not initialized. Call init_async_mongodb_manager() first.")
    return _async_mongodb_manager


# Export public interface for application use
__all__ = [
    'MongoDBManager',
    'AsyncMongoDBManager',
    'create_mongodb_manager',
    'create_async_mongodb_manager',
    'init_mongodb_manager',
    'init_async_mongodb_manager', 
    'get_mongodb_manager',
    'get_async_mongodb_manager',
    'validate_object_id'
]