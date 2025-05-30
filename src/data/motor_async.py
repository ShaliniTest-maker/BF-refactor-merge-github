"""
Motor 3.3+ asynchronous database operations providing high-performance non-blocking MongoDB operations.

This module implements comprehensive async database operations using Motor 3.3+ for high-performance
concurrent request handling. Provides async CRUD operations, connection pooling optimization,
transaction management with proper context handling, and monitoring integration while maintaining
compatibility with existing data patterns from the Node.js implementation.

Key features:
- Motor 3.3+ async MongoDB driver for non-blocking operations
- Async CRUD operations maintaining existing query patterns
- Transaction management with commit/rollback support
- Connection pool optimization for concurrent operations
- Comprehensive monitoring integration with Prometheus metrics
- Circuit breaker patterns for fault tolerance
- Performance optimization ensuring ≤10% variance from Node.js baseline

Implements requirements from:
- Section 0.1.2: Motor 3.3+ implementation for high-performance async database access
- Section 5.2.5: Database access layer with async operations for concurrent requests
- Section 6.2.4: Performance optimization for high-throughput operations
- Section 4.2.2: Async transaction support for data consistency
- Section 6.2.2: Performance monitoring with Motor async operation metrics
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import (
    Any, Dict, List, Optional, Union, Tuple, AsyncIterator, 
    Callable, TypeVar, Generic, Awaitable
)
from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import (
    AsyncIOMotorClient, 
    AsyncIOMotorDatabase, 
    AsyncIOMotorCollection,
    AsyncIOMotorClientSession,
    AsyncIOMotorCursor
)
from pymongo import (
    ASCENDING, DESCENDING, 
    IndexModel, 
    ReturnDocument,
    ReadPreference,
    WriteConcern,
    ReadConcern
)
from pymongo.errors import (
    DuplicateKeyError,
    BulkWriteError,
    InvalidOperation,
    OperationFailure,
    ConnectionFailure,
    ServerSelectionTimeoutError,
    NetworkTimeout,
    AutoReconnect,
    ExecutionTimeout,
    WTimeoutError
)
import structlog

# Import local dependencies
from .exceptions import (
    DatabaseException,
    DatabaseConnectionError,
    DatabaseQueryError,
    DatabaseTransactionError,
    DatabaseTimeoutError,
    DatabaseValidationError,
    with_database_retry,
    database_error_context
)
from .monitoring import (
    get_database_monitoring_components,
    monitor_transaction,
    MotorMonitoringIntegration,
    DatabaseMetrics
)

# Configure module logger
logger = structlog.get_logger(__name__)

# Type variables for generic operations
T = TypeVar('T')
DocumentType = Dict[str, Any]
FilterType = Dict[str, Any]
UpdateType = Dict[str, Any]
ProjectionType = Optional[Union[Dict[str, Any], List[str]]]


class MotorAsyncDatabase:
    """
    High-performance async MongoDB operations using Motor 3.3+ driver.
    
    Provides comprehensive async database operations with connection pooling,
    transaction management, monitoring integration, and fault tolerance patterns.
    Maintains compatibility with existing MongoDB query patterns while enabling
    concurrent request handling for optimal performance.
    """
    
    def __init__(
        self,
        client: AsyncIOMotorClient,
        database_name: str,
        default_write_concern: Optional[WriteConcern] = None,
        default_read_concern: Optional[ReadConcern] = None,
        default_read_preference: Optional[ReadPreference] = None
    ):
        """
        Initialize Motor async database operations.
        
        Args:
            client: Motor async client instance with optimized connection pool
            database_name: Name of the MongoDB database
            default_write_concern: Default write concern for operations
            default_read_concern: Default read concern for operations  
            default_read_preference: Default read preference for operations
        """
        self.client = client
        self.database_name = database_name
        self.database: AsyncIOMotorDatabase = client[database_name]
        
        # Configure default operation concerns
        self.default_write_concern = default_write_concern or WriteConcern(w="majority", wtimeout=10000)
        self.default_read_concern = default_read_concern or ReadConcern(level="majority")
        self.default_read_preference = default_read_preference or ReadPreference.PRIMARY
        
        # Initialize monitoring integration
        self._monitoring_components = get_database_monitoring_components()
        self._motor_integration: Optional[MotorMonitoringIntegration] = None
        self._metrics: Optional[DatabaseMetrics] = None
        
        if self._monitoring_components:
            self._motor_integration = self._monitoring_components['motor_integration']
            self._metrics = self._monitoring_components['metrics']
        
        # Connection pool health tracking
        self._pool_health_cache: Dict[str, Dict[str, Any]] = {}
        self._pool_health_ttl = 30  # seconds
        
        logger.info(
            f"Initialized MotorAsyncDatabase for {database_name}",
            database_name=database_name,
            write_concern=str(self.default_write_concern),
            read_concern=str(self.default_read_concern),
            read_preference=str(self.default_read_preference)
        )
    
    async def get_collection(
        self, 
        collection_name: str,
        write_concern: Optional[WriteConcern] = None,
        read_concern: Optional[ReadConcern] = None,
        read_preference: Optional[ReadPreference] = None
    ) -> AsyncIOMotorCollection:
        """
        Get async collection with configured concerns and preferences.
        
        Args:
            collection_name: Name of the MongoDB collection
            write_concern: Override default write concern
            read_concern: Override default read concern
            read_preference: Override default read preference
            
        Returns:
            Configured AsyncIOMotorCollection instance
        """
        collection = self.database[collection_name]
        
        # Apply operation concerns if specified
        if write_concern or read_concern or read_preference:
            collection = collection.with_options(
                write_concern=write_concern or self.default_write_concern,
                read_concern=read_concern or self.default_read_concern,
                read_preference=read_preference or self.default_read_preference
            )
        
        return collection
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def find_one(
        self,
        collection_name: str,
        filter_doc: FilterType,
        projection: ProjectionType = None,
        sort: Optional[List[Tuple[str, int]]] = None,
        skip: Optional[int] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        max_time_ms: Optional[int] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Optional[DocumentType]:
        """
        Find a single document matching the filter criteria.
        
        Provides async single document retrieval with comprehensive query options,
        monitoring integration, and error handling. Maintains compatibility with
        existing Node.js query patterns while leveraging Motor async capabilities.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter document
            projection: Fields to include/exclude in results
            sort: Sort specification for document selection
            skip: Number of documents to skip
            hint: Index hint for query optimization
            max_time_ms: Maximum execution time in milliseconds
            session: Client session for transaction context
            
        Returns:
            Document matching filter or None if not found
            
        Raises:
            DatabaseQueryError: On query execution failure
            DatabaseTimeoutError: On operation timeout
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('find_one', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build query options
                query_options = {}
                if projection is not None:
                    query_options['projection'] = projection
                if sort is not None:
                    query_options['sort'] = sort
                if skip is not None:
                    query_options['skip'] = skip
                if hint is not None:
                    query_options['hint'] = hint
                if max_time_ms is not None:
                    query_options['max_time_ms'] = max_time_ms
                if session is not None:
                    query_options['session'] = session
                
                # Execute async query
                result = await collection.find_one(filter_doc, **query_options)
                
                logger.debug(
                    f"find_one completed on {collection_name}",
                    collection_name=collection_name,
                    filter_keys=list(filter_doc.keys()) if filter_doc else [],
                    result_found=result is not None,
                    projection_fields=list(projection.keys()) if isinstance(projection, dict) else projection
                )
                
                return result
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during find_one on {collection_name}: {str(e)}",
                    operation='find_one',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except (ExecutionTimeout, WTimeoutError) as e:
                raise DatabaseTimeoutError(
                    f"find_one timed out on {collection_name}: {str(e)}",
                    operation='find_one',
                    database=self.database_name,
                    collection=collection_name,
                    timeout_duration=max_time_ms,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"find_one failed on {collection_name}: {str(e)}",
                    operation='find_one',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def find_many(
        self,
        collection_name: str,
        filter_doc: FilterType,
        projection: ProjectionType = None,
        sort: Optional[List[Tuple[str, int]]] = None,
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        max_time_ms: Optional[int] = None,
        batch_size: Optional[int] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[DocumentType]:
        """
        Find multiple documents matching the filter criteria.
        
        Provides async multi-document retrieval with cursor management,
        batch processing, and comprehensive query options. Optimized for
        high-throughput operations while maintaining query pattern compatibility.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter document
            projection: Fields to include/exclude in results
            sort: Sort specification for results
            limit: Maximum number of documents to return
            skip: Number of documents to skip
            hint: Index hint for query optimization
            max_time_ms: Maximum execution time in milliseconds
            batch_size: Cursor batch size for network optimization
            session: Client session for transaction context
            
        Returns:
            List of documents matching filter criteria
            
        Raises:
            DatabaseQueryError: On query execution failure
            DatabaseTimeoutError: On operation timeout
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('find_many', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Create cursor with query options
                cursor = collection.find(filter_doc)
                
                if projection is not None:
                    cursor = cursor.projection(projection)
                if sort is not None:
                    cursor = cursor.sort(sort)
                if limit is not None:
                    cursor = cursor.limit(limit)
                if skip is not None:
                    cursor = cursor.skip(skip)
                if hint is not None:
                    cursor = cursor.hint(hint)
                if max_time_ms is not None:
                    cursor = cursor.max_time_ms(max_time_ms)
                if batch_size is not None:
                    cursor = cursor.batch_size(batch_size)
                
                # Convert cursor to list with session context
                if session is not None:
                    results = await cursor.session(session).to_list(length=limit)
                else:
                    results = await cursor.to_list(length=limit)
                
                logger.debug(
                    f"find_many completed on {collection_name}",
                    collection_name=collection_name,
                    filter_keys=list(filter_doc.keys()) if filter_doc else [],
                    result_count=len(results),
                    limit=limit,
                    skip=skip
                )
                
                return results
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during find_many on {collection_name}: {str(e)}",
                    operation='find_many',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except (ExecutionTimeout, WTimeoutError) as e:
                raise DatabaseTimeoutError(
                    f"find_many timed out on {collection_name}: {str(e)}",
                    operation='find_many',
                    database=self.database_name,
                    collection=collection_name,
                    timeout_duration=max_time_ms,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"find_many failed on {collection_name}: {str(e)}",
                    operation='find_many',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    async def find_cursor(
        self,
        collection_name: str,
        filter_doc: FilterType,
        projection: ProjectionType = None,
        sort: Optional[List[Tuple[str, int]]] = None,
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        max_time_ms: Optional[int] = None,
        batch_size: Optional[int] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> AsyncIOMotorCursor:
        """
        Create an async cursor for streaming large result sets.
        
        Provides memory-efficient streaming of large document collections
        using Motor async cursors. Enables processing of large datasets
        without loading all documents into memory simultaneously.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter document
            projection: Fields to include/exclude in results
            sort: Sort specification for results
            limit: Maximum number of documents to return
            skip: Number of documents to skip
            hint: Index hint for query optimization
            max_time_ms: Maximum execution time in milliseconds
            batch_size: Cursor batch size for network optimization
            session: Client session for transaction context
            
        Returns:
            AsyncIOMotorCursor for streaming results
            
        Raises:
            DatabaseQueryError: On cursor creation failure
            DatabaseConnectionError: On connection failure
        """
        try:
            collection = await self.get_collection(collection_name)
            
            # Create cursor with query options
            cursor = collection.find(filter_doc)
            
            if projection is not None:
                cursor = cursor.projection(projection)
            if sort is not None:
                cursor = cursor.sort(sort)
            if limit is not None:
                cursor = cursor.limit(limit)
            if skip is not None:
                cursor = cursor.skip(skip)
            if hint is not None:
                cursor = cursor.hint(hint)
            if max_time_ms is not None:
                cursor = cursor.max_time_ms(max_time_ms)
            if batch_size is not None:
                cursor = cursor.batch_size(batch_size)
            if session is not None:
                cursor = cursor.session(session)
            
            logger.debug(
                f"Created async cursor for {collection_name}",
                collection_name=collection_name,
                filter_keys=list(filter_doc.keys()) if filter_doc else [],
                limit=limit,
                skip=skip,
                batch_size=batch_size
            )
            
            return cursor
            
        except Exception as e:
            raise DatabaseQueryError(
                f"Failed to create cursor for {collection_name}: {str(e)}",
                operation='find_cursor',
                database=self.database_name,
                collection=collection_name,
                query=filter_doc,
                original_error=e
            )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def insert_one(
        self,
        collection_name: str,
        document: DocumentType,
        bypass_document_validation: bool = False,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> ObjectId:
        """
        Insert a single document into the collection.
        
        Provides async single document insertion with validation bypass options,
        transaction support, and comprehensive error handling. Returns the inserted
        document's ObjectId for reference.
        
        Args:
            collection_name: Name of the MongoDB collection
            document: Document to insert
            bypass_document_validation: Skip document validation
            session: Client session for transaction context
            
        Returns:
            ObjectId of the inserted document
            
        Raises:
            DatabaseValidationError: On document validation failure
            DatabaseConnectionError: On connection failure
            DatabaseQueryError: On insertion failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('insert_one', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Execute async insertion
                insert_options = {
                    'bypass_document_validation': bypass_document_validation
                }
                if session is not None:
                    insert_options['session'] = session
                
                result = await collection.insert_one(document, **insert_options)
                
                logger.debug(
                    f"insert_one completed on {collection_name}",
                    collection_name=collection_name,
                    inserted_id=str(result.inserted_id),
                    document_keys=list(document.keys()) if document else []
                )
                
                return result.inserted_id
                
            except DuplicateKeyError as e:
                raise DatabaseValidationError(
                    f"Duplicate key error during insert_one on {collection_name}: {str(e)}",
                    operation='insert_one',
                    database=self.database_name,
                    collection=collection_name,
                    document=document,
                    original_error=e
                )
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during insert_one on {collection_name}: {str(e)}",
                    operation='insert_one',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"insert_one failed on {collection_name}: {str(e)}",
                    operation='insert_one',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def insert_many(
        self,
        collection_name: str,
        documents: List[DocumentType],
        ordered: bool = True,
        bypass_document_validation: bool = False,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[ObjectId]:
        """
        Insert multiple documents into the collection.
        
        Provides async bulk document insertion with ordered/unordered options,
        validation bypass, and comprehensive error handling. Optimized for
        high-throughput batch operations.
        
        Args:
            collection_name: Name of the MongoDB collection
            documents: List of documents to insert
            ordered: Whether to stop on first error (ordered) or continue (unordered)
            bypass_document_validation: Skip document validation
            session: Client session for transaction context
            
        Returns:
            List of ObjectIds of the inserted documents
            
        Raises:
            DatabaseValidationError: On document validation failure
            DatabaseConnectionError: On connection failure
            DatabaseQueryError: On insertion failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('insert_many', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Execute async bulk insertion
                insert_options = {
                    'ordered': ordered,
                    'bypass_document_validation': bypass_document_validation
                }
                if session is not None:
                    insert_options['session'] = session
                
                result = await collection.insert_many(documents, **insert_options)
                
                logger.debug(
                    f"insert_many completed on {collection_name}",
                    collection_name=collection_name,
                    inserted_count=len(result.inserted_ids),
                    ordered=ordered
                )
                
                return result.inserted_ids
                
            except BulkWriteError as e:
                # Extract validation errors from bulk write error
                validation_errors = []
                for error in e.details.get('writeErrors', []):
                    validation_errors.append(f"Index {error['index']}: {error['errmsg']}")
                
                raise DatabaseValidationError(
                    f"Bulk validation errors during insert_many on {collection_name}: {str(e)}",
                    operation='insert_many',
                    database=self.database_name,
                    collection=collection_name,
                    validation_errors=validation_errors,
                    original_error=e
                )
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during insert_many on {collection_name}: {str(e)}",
                    operation='insert_many',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"insert_many failed on {collection_name}: {str(e)}",
                    operation='insert_many',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def update_one(
        self,
        collection_name: str,
        filter_doc: FilterType,
        update_doc: UpdateType,
        upsert: bool = False,
        bypass_document_validation: bool = False,
        array_filters: Optional[List[Dict[str, Any]]] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Dict[str, Any]:
        """
        Update a single document matching the filter criteria.
        
        Provides async single document update with upsert support,
        array filtering, and comprehensive options. Returns detailed
        update result information for validation.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            update_doc: Update operations to apply
            upsert: Create document if no match found
            bypass_document_validation: Skip document validation
            array_filters: Filters for array field updates
            hint: Index hint for query optimization
            session: Client session for transaction context
            
        Returns:
            Dict containing update result details
            
        Raises:
            DatabaseValidationError: On validation failure
            DatabaseQueryError: On update failure
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('update_one', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build update options
                update_options = {
                    'upsert': upsert,
                    'bypass_document_validation': bypass_document_validation
                }
                if array_filters is not None:
                    update_options['array_filters'] = array_filters
                if hint is not None:
                    update_options['hint'] = hint
                if session is not None:
                    update_options['session'] = session
                
                # Execute async update
                result = await collection.update_one(filter_doc, update_doc, **update_options)
                
                update_result = {
                    'matched_count': result.matched_count,
                    'modified_count': result.modified_count,
                    'upserted_id': result.upserted_id,
                    'acknowledged': result.acknowledged
                }
                
                logger.debug(
                    f"update_one completed on {collection_name}",
                    collection_name=collection_name,
                    matched_count=result.matched_count,
                    modified_count=result.modified_count,
                    upserted=result.upserted_id is not None
                )
                
                return update_result
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during update_one on {collection_name}: {str(e)}",
                    operation='update_one',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"update_one failed on {collection_name}: {str(e)}",
                    operation='update_one',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def update_many(
        self,
        collection_name: str,
        filter_doc: FilterType,
        update_doc: UpdateType,
        upsert: bool = False,
        bypass_document_validation: bool = False,
        array_filters: Optional[List[Dict[str, Any]]] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Dict[str, Any]:
        """
        Update multiple documents matching the filter criteria.
        
        Provides async multi-document update with comprehensive options
        and detailed result tracking. Optimized for bulk update operations
        while maintaining transaction consistency.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            update_doc: Update operations to apply
            upsert: Create document if no match found
            bypass_document_validation: Skip document validation
            array_filters: Filters for array field updates
            hint: Index hint for query optimization
            session: Client session for transaction context
            
        Returns:
            Dict containing update result details
            
        Raises:
            DatabaseValidationError: On validation failure
            DatabaseQueryError: On update failure
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('update_many', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build update options
                update_options = {
                    'upsert': upsert,
                    'bypass_document_validation': bypass_document_validation
                }
                if array_filters is not None:
                    update_options['array_filters'] = array_filters
                if hint is not None:
                    update_options['hint'] = hint
                if session is not None:
                    update_options['session'] = session
                
                # Execute async update
                result = await collection.update_many(filter_doc, update_doc, **update_options)
                
                update_result = {
                    'matched_count': result.matched_count,
                    'modified_count': result.modified_count,
                    'upserted_id': result.upserted_id,
                    'acknowledged': result.acknowledged
                }
                
                logger.debug(
                    f"update_many completed on {collection_name}",
                    collection_name=collection_name,
                    matched_count=result.matched_count,
                    modified_count=result.modified_count,
                    upserted=result.upserted_id is not None
                )
                
                return update_result
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during update_many on {collection_name}: {str(e)}",
                    operation='update_many',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"update_many failed on {collection_name}: {str(e)}",
                    operation='update_many',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def find_one_and_update(
        self,
        collection_name: str,
        filter_doc: FilterType,
        update_doc: UpdateType,
        projection: ProjectionType = None,
        sort: Optional[List[Tuple[str, int]]] = None,
        upsert: bool = False,
        return_document: ReturnDocument = ReturnDocument.BEFORE,
        bypass_document_validation: bool = False,
        array_filters: Optional[List[Dict[str, Any]]] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        max_time_ms: Optional[int] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Optional[DocumentType]:
        """
        Find a document and update it atomically.
        
        Provides atomic find-and-modify operations with comprehensive options
        for document updates. Returns either the original or updated document
        based on return_document parameter.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            update_doc: Update operations to apply
            projection: Fields to include/exclude in result
            sort: Sort specification for document selection
            upsert: Create document if no match found
            return_document: Return original (BEFORE) or updated (AFTER) document
            bypass_document_validation: Skip document validation
            array_filters: Filters for array field updates
            hint: Index hint for query optimization
            max_time_ms: Maximum execution time in milliseconds
            session: Client session for transaction context
            
        Returns:
            Updated document or None if no document matched
            
        Raises:
            DatabaseValidationError: On validation failure
            DatabaseQueryError: On operation failure
            DatabaseTimeoutError: On operation timeout
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('find_one_and_update', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build operation options
                operation_options = {
                    'upsert': upsert,
                    'return_document': return_document,
                    'bypass_document_validation': bypass_document_validation
                }
                if projection is not None:
                    operation_options['projection'] = projection
                if sort is not None:
                    operation_options['sort'] = sort
                if array_filters is not None:
                    operation_options['array_filters'] = array_filters
                if hint is not None:
                    operation_options['hint'] = hint
                if max_time_ms is not None:
                    operation_options['max_time_ms'] = max_time_ms
                if session is not None:
                    operation_options['session'] = session
                
                # Execute atomic find and update
                result = await collection.find_one_and_update(filter_doc, update_doc, **operation_options)
                
                logger.debug(
                    f"find_one_and_update completed on {collection_name}",
                    collection_name=collection_name,
                    result_found=result is not None,
                    return_document=return_document.name,
                    upsert=upsert
                )
                
                return result
                
            except (ExecutionTimeout, WTimeoutError) as e:
                raise DatabaseTimeoutError(
                    f"find_one_and_update timed out on {collection_name}: {str(e)}",
                    operation='find_one_and_update',
                    database=self.database_name,
                    collection=collection_name,
                    timeout_duration=max_time_ms,
                    original_error=e
                )
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during find_one_and_update on {collection_name}: {str(e)}",
                    operation='find_one_and_update',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"find_one_and_update failed on {collection_name}: {str(e)}",
                    operation='find_one_and_update',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def delete_one(
        self,
        collection_name: str,
        filter_doc: FilterType,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Dict[str, Any]:
        """
        Delete a single document matching the filter criteria.
        
        Provides async single document deletion with index hints
        and transaction support. Returns deletion result details
        for validation and monitoring.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            hint: Index hint for query optimization
            session: Client session for transaction context
            
        Returns:
            Dict containing deletion result details
            
        Raises:
            DatabaseQueryError: On deletion failure
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('delete_one', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build delete options
                delete_options = {}
                if hint is not None:
                    delete_options['hint'] = hint
                if session is not None:
                    delete_options['session'] = session
                
                # Execute async deletion
                result = await collection.delete_one(filter_doc, **delete_options)
                
                delete_result = {
                    'deleted_count': result.deleted_count,
                    'acknowledged': result.acknowledged
                }
                
                logger.debug(
                    f"delete_one completed on {collection_name}",
                    collection_name=collection_name,
                    deleted_count=result.deleted_count
                )
                
                return delete_result
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during delete_one on {collection_name}: {str(e)}",
                    operation='delete_one',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"delete_one failed on {collection_name}: {str(e)}",
                    operation='delete_one',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def delete_many(
        self,
        collection_name: str,
        filter_doc: FilterType,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Dict[str, Any]:
        """
        Delete multiple documents matching the filter criteria.
        
        Provides async multi-document deletion with comprehensive
        result tracking. Optimized for bulk deletion operations
        while maintaining transaction consistency.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            hint: Index hint for query optimization
            session: Client session for transaction context
            
        Returns:
            Dict containing deletion result details
            
        Raises:
            DatabaseQueryError: On deletion failure
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('delete_many', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build delete options
                delete_options = {}
                if hint is not None:
                    delete_options['hint'] = hint
                if session is not None:
                    delete_options['session'] = session
                
                # Execute async deletion
                result = await collection.delete_many(filter_doc, **delete_options)
                
                delete_result = {
                    'deleted_count': result.deleted_count,
                    'acknowledged': result.acknowledged
                }
                
                logger.debug(
                    f"delete_many completed on {collection_name}",
                    collection_name=collection_name,
                    deleted_count=result.deleted_count
                )
                
                return delete_result
                
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during delete_many on {collection_name}: {str(e)}",
                    operation='delete_many',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"delete_many failed on {collection_name}: {str(e)}",
                    operation='delete_many',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def aggregate(
        self,
        collection_name: str,
        pipeline: List[Dict[str, Any]],
        allow_disk_use: bool = False,
        max_time_ms: Optional[int] = None,
        batch_size: Optional[int] = None,
        bypass_document_validation: bool = False,
        read_concern: Optional[ReadConcern] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[DocumentType]:
        """
        Execute an aggregation pipeline on the collection.
        
        Provides async aggregation operations with comprehensive pipeline support,
        disk usage options, and performance optimization. Maintains compatibility
        with existing aggregation patterns while leveraging Motor async capabilities.
        
        Args:
            collection_name: Name of the MongoDB collection
            pipeline: Aggregation pipeline stages
            allow_disk_use: Allow pipeline stages to write to temporary files
            max_time_ms: Maximum execution time in milliseconds
            batch_size: Cursor batch size for network optimization
            bypass_document_validation: Skip document validation
            read_concern: Read concern for the operation
            hint: Index hint for pipeline optimization
            session: Client session for transaction context
            
        Returns:
            List of aggregation result documents
            
        Raises:
            DatabaseQueryError: On aggregation failure
            DatabaseTimeoutError: On operation timeout
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('aggregate', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name, read_concern=read_concern)
                
                # Build aggregation options
                aggregate_options = {
                    'allowDiskUse': allow_disk_use,
                    'bypassDocumentValidation': bypass_document_validation
                }
                if max_time_ms is not None:
                    aggregate_options['maxTimeMS'] = max_time_ms
                if batch_size is not None:
                    aggregate_options['batchSize'] = batch_size
                if hint is not None:
                    aggregate_options['hint'] = hint
                if session is not None:
                    aggregate_options['session'] = session
                
                # Execute aggregation pipeline
                cursor = collection.aggregate(pipeline, **aggregate_options)
                results = await cursor.to_list(length=None)
                
                logger.debug(
                    f"aggregation completed on {collection_name}",
                    collection_name=collection_name,
                    pipeline_stages=len(pipeline),
                    result_count=len(results),
                    allow_disk_use=allow_disk_use
                )
                
                return results
                
            except (ExecutionTimeout, WTimeoutError) as e:
                raise DatabaseTimeoutError(
                    f"Aggregation timed out on {collection_name}: {str(e)}",
                    operation='aggregate',
                    database=self.database_name,
                    collection=collection_name,
                    timeout_duration=max_time_ms,
                    original_error=e
                )
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during aggregation on {collection_name}: {str(e)}",
                    operation='aggregate',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"Aggregation failed on {collection_name}: {str(e)}",
                    operation='aggregate',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, min_wait=1.0, max_wait=10.0)
    async def count_documents(
        self,
        collection_name: str,
        filter_doc: FilterType,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
        hint: Optional[Union[str, List[Tuple[str, int]]]] = None,
        max_time_ms: Optional[int] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> int:
        """
        Count documents matching the filter criteria.
        
        Provides async document counting with query optimization and
        comprehensive filtering options. Uses count_documents for
        accurate counting with filter support.
        
        Args:
            collection_name: Name of the MongoDB collection
            filter_doc: Query filter for document selection
            skip: Number of documents to skip
            limit: Maximum number of documents to count
            hint: Index hint for query optimization
            max_time_ms: Maximum execution time in milliseconds
            session: Client session for transaction context
            
        Returns:
            Number of documents matching the filter
            
        Raises:
            DatabaseQueryError: On count failure
            DatabaseTimeoutError: On operation timeout
            DatabaseConnectionError: On connection failure
        """
        if not self._motor_integration:
            raise DatabaseException("Motor monitoring integration not initialized")
        
        async with self._motor_integration.monitor_operation('count_documents', self.database_name, collection_name):
            try:
                collection = await self.get_collection(collection_name)
                
                # Build count options
                count_options = {}
                if skip is not None:
                    count_options['skip'] = skip
                if limit is not None:
                    count_options['limit'] = limit
                if hint is not None:
                    count_options['hint'] = hint
                if max_time_ms is not None:
                    count_options['maxTimeMS'] = max_time_ms
                if session is not None:
                    count_options['session'] = session
                
                # Execute async count
                count = await collection.count_documents(filter_doc, **count_options)
                
                logger.debug(
                    f"count_documents completed on {collection_name}",
                    collection_name=collection_name,
                    count=count,
                    filter_keys=list(filter_doc.keys()) if filter_doc else []
                )
                
                return count
                
            except (ExecutionTimeout, WTimeoutError) as e:
                raise DatabaseTimeoutError(
                    f"count_documents timed out on {collection_name}: {str(e)}",
                    operation='count_documents',
                    database=self.database_name,
                    collection=collection_name,
                    timeout_duration=max_time_ms,
                    original_error=e
                )
            except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
                raise DatabaseConnectionError(
                    f"Connection failed during count_documents on {collection_name}: {str(e)}",
                    operation='count_documents',
                    database=self.database_name,
                    collection=collection_name,
                    original_error=e
                )
            except Exception as e:
                raise DatabaseQueryError(
                    f"count_documents failed on {collection_name}: {str(e)}",
                    operation='count_documents',
                    database=self.database_name,
                    collection=collection_name,
                    query=filter_doc,
                    original_error=e
                )
    
    @asynccontextmanager
    async def start_session(
        self, 
        causal_consistency: bool = True,
        default_transaction_options: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[AsyncIOMotorClientSession]:
        """
        Create a client session for transaction and causal consistency support.
        
        Provides async session management with automatic cleanup and
        comprehensive configuration options. Enables multi-document
        transactions and causal consistency patterns.
        
        Args:
            causal_consistency: Enable causal consistency for session
            default_transaction_options: Default options for transactions
            
        Yields:
            AsyncIOMotorClientSession: Configured client session
            
        Raises:
            DatabaseConnectionError: On session creation failure
        """
        session = None
        try:
            # Configure session options
            session_options = {
                'causal_consistency': causal_consistency
            }
            if default_transaction_options:
                session_options['default_transaction_options'] = default_transaction_options
            
            # Create async client session
            session = await self.client.start_session(**session_options)
            
            logger.debug(
                f"Started client session for {self.database_name}",
                database_name=self.database_name,
                causal_consistency=causal_consistency,
                session_id=str(session.session_id) if session else None
            )
            
            yield session
            
        except Exception as e:
            logger.error(
                f"Failed to create client session for {self.database_name}: {str(e)}",
                database_name=self.database_name,
                error=str(e)
            )
            raise DatabaseConnectionError(
                f"Failed to create client session: {str(e)}",
                operation='start_session',
                database=self.database_name,
                original_error=e
            )
        finally:
            if session:
                try:
                    await session.end_session()
                    logger.debug(
                        f"Ended client session for {self.database_name}",
                        database_name=self.database_name,
                        session_id=str(session.session_id)
                    )
                except Exception as e:
                    logger.warning(
                        f"Error ending session for {self.database_name}: {str(e)}",
                        database_name=self.database_name,
                        error=str(e)
                    )
    
    @asynccontextmanager
    async def start_transaction(
        self,
        session: Optional[AsyncIOMotorClientSession] = None,
        read_concern: Optional[ReadConcern] = None,
        write_concern: Optional[WriteConcern] = None,
        read_preference: Optional[ReadPreference] = None,
        max_commit_time_ms: Optional[int] = None
    ) -> AsyncIterator[AsyncIOMotorClientSession]:
        """
        Start a multi-document transaction with comprehensive options.
        
        Provides async transaction management with automatic commit/rollback,
        monitoring integration, and comprehensive configuration options.
        Implements ACID compliance for multi-document operations.
        
        Args:
            session: Existing session or create new one
            read_concern: Read concern for transaction
            write_concern: Write concern for transaction
            read_preference: Read preference for transaction
            max_commit_time_ms: Maximum commit time in milliseconds
            
        Yields:
            AsyncIOMotorClientSession: Session with active transaction
            
        Raises:
            DatabaseTransactionError: On transaction failure
            DatabaseConnectionError: On connection failure
        """
        transaction_session = session
        session_created = False
        
        # Monitor transaction performance if monitoring available
        if self._metrics:
            transaction_monitor = monitor_transaction(self._metrics, self.database_name)
        else:
            # Create a no-op context manager if monitoring unavailable
            @asynccontextmanager
            async def no_op_monitor():
                yield
            transaction_monitor = no_op_monitor()
        
        async with transaction_monitor:
            try:
                # Create session if not provided
                if transaction_session is None:
                    async with self.start_session() as new_session:
                        transaction_session = new_session
                        session_created = True
                
                # Configure transaction options
                transaction_options = {}
                if read_concern:
                    transaction_options['read_concern'] = read_concern
                if write_concern:
                    transaction_options['write_concern'] = write_concern
                if read_preference:
                    transaction_options['read_preference'] = read_preference
                if max_commit_time_ms:
                    transaction_options['max_commit_time_ms'] = max_commit_time_ms
                
                # Start async transaction
                async with transaction_session.start_transaction(**transaction_options):
                    logger.debug(
                        f"Started transaction for {self.database_name}",
                        database_name=self.database_name,
                        session_id=str(transaction_session.session_id),
                        transaction_options=transaction_options
                    )
                    
                    yield transaction_session
                    
                    logger.debug(
                        f"Transaction committed successfully for {self.database_name}",
                        database_name=self.database_name,
                        session_id=str(transaction_session.session_id)
                    )
                
            except Exception as e:
                logger.error(
                    f"Transaction failed for {self.database_name}: {str(e)}",
                    database_name=self.database_name,
                    session_id=str(transaction_session.session_id) if transaction_session else None,
                    error=str(e)
                )
                
                raise DatabaseTransactionError(
                    f"Transaction failed: {str(e)}",
                    operation='transaction',
                    database=self.database_name,
                    transaction_id=str(transaction_session.session_id) if transaction_session else None,
                    original_error=e
                )
    
    async def create_index(
        self,
        collection_name: str,
        keys: Union[str, List[Tuple[str, int]]],
        name: Optional[str] = None,
        unique: bool = False,
        background: bool = True,
        sparse: bool = False,
        expire_after_seconds: Optional[int] = None,
        partial_filter_expression: Optional[Dict[str, Any]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> str:
        """
        Create an index on the collection.
        
        Provides async index creation with comprehensive options
        for performance optimization and constraint enforcement.
        
        Args:
            collection_name: Name of the MongoDB collection
            keys: Index specification (field name or list of (field, direction) tuples)
            name: Index name (generated if not provided)
            unique: Create unique index
            background: Create index in background
            sparse: Create sparse index
            expire_after_seconds: TTL for documents (TTL index)
            partial_filter_expression: Partial index filter
            session: Client session for transaction context
            
        Returns:
            Name of the created index
            
        Raises:
            DatabaseQueryError: On index creation failure
            DatabaseConnectionError: On connection failure
        """
        try:
            collection = await self.get_collection(collection_name)
            
            # Build index options
            index_options = {
                'background': background,
                'unique': unique,
                'sparse': sparse
            }
            if name:
                index_options['name'] = name
            if expire_after_seconds is not None:
                index_options['expireAfterSeconds'] = expire_after_seconds
            if partial_filter_expression:
                index_options['partialFilterExpression'] = partial_filter_expression
            if session:
                index_options['session'] = session
            
            # Create async index
            index_name = await collection.create_index(keys, **index_options)
            
            logger.info(
                f"Created index '{index_name}' on {collection_name}",
                collection_name=collection_name,
                index_name=index_name,
                keys=keys,
                unique=unique,
                background=background
            )
            
            return index_name
            
        except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
            raise DatabaseConnectionError(
                f"Connection failed during index creation on {collection_name}: {str(e)}",
                operation='create_index',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
        except Exception as e:
            raise DatabaseQueryError(
                f"Index creation failed on {collection_name}: {str(e)}",
                operation='create_index',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
    
    async def drop_index(
        self,
        collection_name: str,
        index: Union[str, List[Tuple[str, int]]],
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> None:
        """
        Drop an index from the collection.
        
        Args:
            collection_name: Name of the MongoDB collection
            index: Index name or specification to drop
            session: Client session for transaction context
            
        Raises:
            DatabaseQueryError: On index drop failure
            DatabaseConnectionError: On connection failure
        """
        try:
            collection = await self.get_collection(collection_name)
            
            drop_options = {}
            if session:
                drop_options['session'] = session
            
            await collection.drop_index(index, **drop_options)
            
            logger.info(
                f"Dropped index '{index}' from {collection_name}",
                collection_name=collection_name,
                index=str(index)
            )
            
        except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
            raise DatabaseConnectionError(
                f"Connection failed during index drop on {collection_name}: {str(e)}",
                operation='drop_index',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
        except Exception as e:
            raise DatabaseQueryError(
                f"Index drop failed on {collection_name}: {str(e)}",
                operation='drop_index',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
    
    async def list_indexes(
        self,
        collection_name: str,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[Dict[str, Any]]:
        """
        List all indexes for the collection.
        
        Args:
            collection_name: Name of the MongoDB collection
            session: Client session for transaction context
            
        Returns:
            List of index specifications
            
        Raises:
            DatabaseQueryError: On index listing failure
            DatabaseConnectionError: On connection failure
        """
        try:
            collection = await self.get_collection(collection_name)
            
            list_options = {}
            if session:
                list_options['session'] = session
            
            indexes = await collection.list_indexes(**list_options).to_list(length=None)
            
            logger.debug(
                f"Listed {len(indexes)} indexes for {collection_name}",
                collection_name=collection_name,
                index_count=len(indexes)
            )
            
            return indexes
            
        except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout, AutoReconnect) as e:
            raise DatabaseConnectionError(
                f"Connection failed during index listing on {collection_name}: {str(e)}",
                operation='list_indexes',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
        except Exception as e:
            raise DatabaseQueryError(
                f"Index listing failed on {collection_name}: {str(e)}",
                operation='list_indexes',
                database=self.database_name,
                collection=collection_name,
                original_error=e
            )
    
    async def get_connection_pool_stats(self) -> Dict[str, Any]:
        """
        Get connection pool statistics for monitoring.
        
        Returns:
            Dict containing connection pool statistics
        """
        try:
            # Get pool information from client
            pool_info = {}
            
            if hasattr(self.client, 'nodes'):
                for address, server in self.client.nodes.items():
                    if hasattr(server, 'pool'):
                        pool = server.pool
                        pool_stats = {
                            'address': str(address),
                            'pool_size': getattr(pool, 'max_pool_size', 0),
                            'checked_out': getattr(pool, 'checked_out_count', 0),
                            'available': getattr(pool, 'available_count', 0),
                            'created': getattr(pool, 'total_created', 0)
                        }
                        pool_info[str(address)] = pool_stats
                        
                        # Update Motor connection pool metrics if monitoring available
                        if self._motor_integration:
                            self._motor_integration.monitor_connection_pool(pool_stats, str(address))
            
            logger.debug(
                f"Retrieved connection pool stats for {self.database_name}",
                database_name=self.database_name,
                pool_count=len(pool_info)
            )
            
            return pool_info
            
        except Exception as e:
            logger.warning(
                f"Failed to retrieve connection pool stats for {self.database_name}: {str(e)}",
                database_name=self.database_name,
                error=str(e)
            )
            return {}
    
    async def ping(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Test database connectivity and performance.
        
        Args:
            timeout: Connection timeout in seconds
            
        Returns:
            Dict containing ping result and performance metrics
            
        Raises:
            DatabaseConnectionError: On connection failure
        """
        try:
            start_time = time.perf_counter()
            
            # Execute ping command with timeout
            await self.database.command('ping', maxTimeMS=int(timeout * 1000))
            
            end_time = time.perf_counter()
            response_time_ms = (end_time - start_time) * 1000
            
            result = {
                'status': 'ok',
                'response_time_ms': response_time_ms,
                'database': self.database_name,
                'timestamp': time.time()
            }
            
            logger.debug(
                f"Database ping successful for {self.database_name}",
                database_name=self.database_name,
                response_time_ms=response_time_ms
            )
            
            return result
            
        except Exception as e:
            logger.error(
                f"Database ping failed for {self.database_name}: {str(e)}",
                database_name=self.database_name,
                error=str(e)
            )
            
            raise DatabaseConnectionError(
                f"Database ping failed: {str(e)}",
                operation='ping',
                database=self.database_name,
                original_error=e
            )


# Convenience functions for global Motor client management
_motor_client: Optional[AsyncIOMotorClient] = None
_motor_databases: Dict[str, MotorAsyncDatabase] = {}


async def initialize_motor_client(
    connection_string: str,
    max_pool_size: int = 50,
    min_pool_size: int = 5,
    max_idle_time_ms: int = 30000,
    wait_queue_timeout_ms: int = 30000,
    server_selection_timeout_ms: int = 30000,
    socket_timeout_ms: int = 20000,
    connect_timeout_ms: int = 20000,
    heartbeat_frequency_ms: int = 10000,
    **kwargs
) -> AsyncIOMotorClient:
    """
    Initialize global Motor async client with optimized connection pool settings.
    
    Configures Motor client with performance-optimized connection pool settings
    and comprehensive monitoring integration for enterprise-grade deployments.
    
    Args:
        connection_string: MongoDB connection string
        max_pool_size: Maximum connections in pool
        min_pool_size: Minimum connections in pool  
        max_idle_time_ms: Maximum connection idle time
        wait_queue_timeout_ms: Connection checkout timeout
        server_selection_timeout_ms: Server selection timeout
        socket_timeout_ms: Socket operation timeout
        connect_timeout_ms: Initial connection timeout
        heartbeat_frequency_ms: Server heartbeat frequency
        **kwargs: Additional Motor client options
        
    Returns:
        Configured AsyncIOMotorClient instance
        
    Raises:
        DatabaseConnectionError: On client initialization failure
    """
    global _motor_client
    
    try:
        # Configure optimized connection pool settings
        client_options = {
            'maxPoolSize': max_pool_size,
            'minPoolSize': min_pool_size,
            'maxIdleTimeMS': max_idle_time_ms,
            'waitQueueTimeoutMS': wait_queue_timeout_ms,
            'serverSelectionTimeoutMS': server_selection_timeout_ms,
            'socketTimeoutMS': socket_timeout_ms,
            'connectTimeoutMS': connect_timeout_ms,
            'heartbeatFrequencyMS': heartbeat_frequency_ms,
            **kwargs
        }
        
        # Create Motor async client
        _motor_client = AsyncIOMotorClient(connection_string, **client_options)
        
        # Test connection
        await _motor_client.admin.command('ping')
        
        logger.info(
            "Motor async client initialized successfully",
            max_pool_size=max_pool_size,
            min_pool_size=min_pool_size,
            connection_timeout_ms=connect_timeout_ms
        )
        
        return _motor_client
        
    except Exception as e:
        logger.error(f"Failed to initialize Motor client: {str(e)}")
        raise DatabaseConnectionError(
            f"Motor client initialization failed: {str(e)}",
            operation='initialize_motor_client',
            original_error=e
        )


async def get_motor_database(
    database_name: str,
    client: Optional[AsyncIOMotorClient] = None,
    **kwargs
) -> MotorAsyncDatabase:
    """
    Get or create Motor async database instance.
    
    Args:
        database_name: Name of the MongoDB database
        client: Motor client instance (uses global if not provided)
        **kwargs: Additional MotorAsyncDatabase options
        
    Returns:
        MotorAsyncDatabase instance
        
    Raises:
        DatabaseConnectionError: If no client available
    """
    global _motor_client, _motor_databases
    
    if database_name in _motor_databases:
        return _motor_databases[database_name]
    
    motor_client = client or _motor_client
    if not motor_client:
        raise DatabaseConnectionError(
            "No Motor client available. Call initialize_motor_client() first.",
            operation='get_motor_database'
        )
    
    # Create new database instance
    database = MotorAsyncDatabase(motor_client, database_name, **kwargs)
    _motor_databases[database_name] = database
    
    logger.info(f"Created Motor async database instance for {database_name}")
    
    return database


async def close_motor_client() -> None:
    """
    Close global Motor client and cleanup resources.
    """
    global _motor_client, _motor_databases
    
    if _motor_client:
        try:
            _motor_client.close()
            logger.info("Motor async client closed successfully")
        except Exception as e:
            logger.warning(f"Error closing Motor client: {str(e)}")
        finally:
            _motor_client = None
            _motor_databases.clear()


# Export public interface
__all__ = [
    'MotorAsyncDatabase',
    'initialize_motor_client',
    'get_motor_database', 
    'close_motor_client',
    'DocumentType',
    'FilterType',
    'UpdateType',
    'ProjectionType'
]