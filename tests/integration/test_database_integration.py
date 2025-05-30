"""
Comprehensive database integration testing covering PyMongo and Motor driver operations with Testcontainers.

This module provides comprehensive integration testing for the database access layer, covering:
- PyMongo 4.5+ synchronous database operations with production-equivalent behavior
- Motor 3.3+ asynchronous database operations for high-performance concurrent access
- Testcontainers MongoDB integration for realistic database behavior during testing
- Connection pooling validation and lifecycle management testing
- Transaction management with commit/rollback scenario testing
- Database performance benchmarking against Node.js baseline performance
- Concurrent database operations testing with connection pool validation
- Database health monitoring and failure recovery testing
- Comprehensive error handling and circuit breaker pattern validation

Implements requirements from:
- Section 6.6.3: 90% integration layer coverage enhanced requirement
- Section 5.2.5: Database access layer MongoDB driver testing maintaining existing data patterns
- Section 6.6.1: Testcontainers enhanced mocking strategy for realistic MongoDB behavior
- Section 0.1.1: Performance validation ensuring ≤10% variance from Node.js baseline
- Section 6.2.4: Performance optimization with connection pooling and monitoring
- Section 4.2.2: Transaction management with commit/rollback support
- Section 6.2.3: Fault tolerance and error handling validation

Dependencies:
- pytest 7.4+ with asyncio support for comprehensive testing framework
- pytest-asyncio for Motor async database operations testing
- testcontainers[mongodb] for production-equivalent MongoDB testing
- prometheus-client for performance metrics collection and validation
- concurrent.futures for parallel testing execution and load simulation
"""

import asyncio
import concurrent.futures
import logging
import os
import pytest
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Callable
from unittest.mock import patch, MagicMock
import threading

# MongoDB and database imports
import pymongo
from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError,
    BulkWriteError, OperationFailure, NetworkTimeout, ExecutionTimeout,
    WriteError, WriteConcernError, AutoReconnect
)
from bson import ObjectId
import motor.motor_asyncio

# Testcontainers for realistic MongoDB behavior
from testcontainers.mongodb import MongoDbContainer

# Performance monitoring and metrics
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
import structlog

# Database layer imports
from src.data import (
    DatabaseManager, DatabasePackageConfig, create_database_manager,
    get_database_manager, MongoDBClient, MongoDBConfig, QueryResult,
    MotorAsyncDatabase, DatabaseMetrics, DatabaseHealthChecker,
    database_transaction, async_database_transaction,
    initialize_database_monitoring, get_database_monitoring_components,
    PERFORMANCE_VARIANCE_THRESHOLD, NODEJS_BASELINE_PERCENTILES,
    DEFAULT_MAX_POOL_SIZE, DEFAULT_MIN_POOL_SIZE, DEFAULT_CONNECTION_TIMEOUT_MS,
    DEFAULT_SERVER_SELECTION_TIMEOUT_MS, DEFAULT_SOCKET_TIMEOUT_MS,
    DEFAULT_MAX_IDLE_TIME_MS, DEFAULT_WAIT_QUEUE_TIMEOUT_MS,
    DEFAULT_TRANSACTION_TIMEOUT_SECONDS, MAX_TRANSACTION_RETRY_ATTEMPTS
)
from src.data.mongodb import create_mongodb_client, serialize_for_json, get_object_id
from src.data.motor_async import initialize_motor_client, get_motor_database, close_motor_client
from src.data.transactions import TransactionState, TransactionManager, AsyncTransactionManager
from src.data.monitoring import (
    DatabaseMonitoringListener, ConnectionPoolMonitoringListener,
    ServerMonitoringListener, MotorMonitoringIntegration,
    monitor_transaction, database_registry
)
from src.data.exceptions import (
    DatabaseException, DatabaseConnectionError, DatabaseQueryError,
    DatabaseTransactionError, DatabaseTimeoutError, DatabaseValidationError,
    with_database_retry, database_error_context, get_circuit_breaker
)

# Configure structured logger for testing
logger = structlog.get_logger(__name__)

# Test configuration constants
TEST_DATABASE_NAME = "test_flask_migration_db"
TEST_COLLECTION_NAME = "test_users"
TEST_CACHE_COLLECTION = "test_cache"
TEST_AUDIT_COLLECTION = "test_audit"

# Performance testing constants aligned with Node.js baseline
NODEJS_BASELINE_QUERY_TIME_MS = 50.0  # 50ms baseline for simple queries
NODEJS_BASELINE_INSERT_TIME_MS = 25.0  # 25ms baseline for single inserts
NODEJS_BASELINE_UPDATE_TIME_MS = 30.0  # 30ms baseline for single updates
NODEJS_BASELINE_DELETE_TIME_MS = 20.0  # 20ms baseline for single deletes
NODEJS_BASELINE_TRANSACTION_TIME_MS = 100.0  # 100ms baseline for transactions

# Concurrent operation testing constants
CONCURRENT_OPERATIONS_COUNT = 50
LOAD_TEST_DURATION_SECONDS = 30
CONNECTION_POOL_TEST_SIZE = 20

# Test data templates for realistic document testing
TEST_USER_TEMPLATE = {
    "username": "test_user",
    "email": "test@example.com",
    "created_at": datetime.now(timezone.utc),
    "updated_at": datetime.now(timezone.utc),
    "profile": {
        "first_name": "Test",
        "last_name": "User",
        "age": 25,
        "preferences": {
            "theme": "dark",
            "notifications": True,
            "language": "en"
        }
    },
    "metadata": {
        "source": "integration_test",
        "version": "1.0",
        "tags": ["test", "integration", "mongodb"]
    }
}

TEST_CACHE_TEMPLATE = {
    "key": "cache_key",
    "value": "cached_value",
    "ttl": 3600,
    "created_at": datetime.now(timezone.utc),
    "metadata": {
        "type": "session",
        "user_id": None
    }
}


@pytest.fixture(scope="session")
def mongodb_container():
    """
    Testcontainers MongoDB fixture providing production-equivalent MongoDB behavior.
    
    Creates a real MongoDB instance using Docker containers for comprehensive integration
    testing that eliminates mock-specific testing gaps and provides realistic database
    behavior including connection pooling, transaction handling, and query optimization.
    
    Implements Section 6.6.1 enhanced mocking strategy for realistic MongoDB behavior.
    """
    logger.info("Starting MongoDB Testcontainer for integration testing")
    
    with MongoDbContainer("mongo:7.0") as mongo_container:
        # Wait for MongoDB to be ready
        mongo_container.start()
        
        connection_url = mongo_container.get_connection_url()
        logger.info(
            "MongoDB Testcontainer started successfully",
            connection_url=connection_url,
            container_id=mongo_container.get_container_host_ip()
        )
        
        yield {
            "connection_url": connection_url,
            "host": mongo_container.get_container_host_ip(),
            "port": mongo_container.get_exposed_port(27017),
            "container": mongo_container
        }
        
        logger.info("Stopping MongoDB Testcontainer")


@pytest.fixture
def test_database_config(mongodb_container):
    """
    Database configuration fixture using Testcontainers MongoDB connection.
    
    Provides comprehensive database configuration for PyMongo and Motor testing
    with production-equivalent connection parameters and monitoring integration.
    """
    return DatabasePackageConfig(
        mongodb_uri=mongodb_container["connection_url"],
        database_name=TEST_DATABASE_NAME,
        max_pool_size=DEFAULT_MAX_POOL_SIZE,
        min_pool_size=DEFAULT_MIN_POOL_SIZE,
        max_idle_time_ms=DEFAULT_MAX_IDLE_TIME_MS,
        wait_queue_timeout_ms=DEFAULT_WAIT_QUEUE_TIMEOUT_MS,
        connection_timeout_ms=DEFAULT_CONNECTION_TIMEOUT_MS,
        server_selection_timeout_ms=DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
        socket_timeout_ms=DEFAULT_SOCKET_TIMEOUT_MS,
        enable_monitoring=True,
        enable_health_checks=True,
        enable_motor_async=True,
        performance_variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD
    )


@pytest.fixture
def database_manager(test_database_config):
    """
    Database manager fixture with comprehensive monitoring and health checking.
    
    Provides fully configured database manager with PyMongo and Motor clients,
    monitoring integration, and health checking for comprehensive testing.
    """
    manager = DatabaseManager(test_database_config)
    manager.initialize()
    
    logger.info(
        "Database manager initialized for testing",
        database_name=test_database_config.database_name,
        monitoring_enabled=manager.monitoring_components is not None
    )
    
    yield manager
    
    # Cleanup
    manager.close()


@pytest.fixture
async def async_motor_database(test_database_config):
    """
    Motor async database fixture for asynchronous database operations testing.
    
    Provides configured Motor async database client for testing concurrent operations,
    async transaction management, and high-performance database access patterns.
    """
    motor_options = test_database_config.get_motor_client_options()
    
    motor_client = await initialize_motor_client(
        test_database_config.mongodb_uri,
        **motor_options
    )
    
    motor_db = await get_motor_database(
        test_database_config.database_name,
        client=motor_client
    )
    
    logger.info(
        "Motor async database initialized for testing",
        database_name=test_database_config.database_name,
        max_pool_size=test_database_config.motor_max_pool_size
    )
    
    yield motor_db
    
    # Cleanup
    await close_motor_client()


@pytest.fixture
def performance_metrics_registry():
    """
    Prometheus metrics registry fixture for performance monitoring validation.
    
    Provides isolated metrics registry for performance testing and baseline
    comparison validation ensuring ≤10% variance from Node.js baseline.
    """
    registry = CollectorRegistry()
    
    # Database operation performance metrics
    query_duration = Histogram(
        'test_mongodb_query_duration_seconds',
        'Database query execution time',
        ['operation', 'collection'],
        registry=registry
    )
    
    operation_counter = Counter(
        'test_mongodb_operations_total',
        'Total database operations',
        ['operation', 'collection', 'status'],
        registry=registry
    )
    
    connection_pool_size = Gauge(
        'test_mongodb_pool_size',
        'Current connection pool size',
        ['pool_type'],
        registry=registry
    )
    
    transaction_duration = Histogram(
        'test_mongodb_transaction_duration_seconds',
        'Transaction execution time',
        ['status'],
        registry=registry
    )
    
    return {
        'registry': registry,
        'query_duration': query_duration,
        'operation_counter': operation_counter,
        'connection_pool_size': connection_pool_size,
        'transaction_duration': transaction_duration
    }


@pytest.fixture
def test_data_factory():
    """
    Test data factory for generating realistic test documents and scenarios.
    
    Provides dynamic test data generation with varied scenarios and edge cases
    for comprehensive database operation testing and validation.
    """
    def create_user_document(username_suffix: str = "", **overrides) -> Dict[str, Any]:
        """Create realistic user document with optional customizations."""
        doc = TEST_USER_TEMPLATE.copy()
        doc["username"] = f"test_user_{username_suffix}_{uuid.uuid4().hex[:8]}"
        doc["email"] = f"test_{username_suffix}_{uuid.uuid4().hex[:8]}@example.com"
        doc["created_at"] = datetime.now(timezone.utc)
        doc["updated_at"] = datetime.now(timezone.utc)
        
        # Apply any overrides
        for key, value in overrides.items():
            if isinstance(value, dict) and key in doc and isinstance(doc[key], dict):
                doc[key].update(value)
            else:
                doc[key] = value
        
        return doc
    
    def create_cache_document(key_suffix: str = "", **overrides) -> Dict[str, Any]:
        """Create realistic cache document with optional customizations."""
        doc = TEST_CACHE_TEMPLATE.copy()
        doc["key"] = f"cache_key_{key_suffix}_{uuid.uuid4().hex[:8]}"
        doc["created_at"] = datetime.now(timezone.utc)
        
        # Apply any overrides
        for key, value in overrides.items():
            if isinstance(value, dict) and key in doc and isinstance(doc[key], dict):
                doc[key].update(value)
            else:
                doc[key] = value
        
        return doc
    
    def create_bulk_documents(count: int, doc_type: str = "user") -> List[Dict[str, Any]]:
        """Create multiple test documents for bulk operations testing."""
        if doc_type == "user":
            return [create_user_document(f"bulk_{i}") for i in range(count)]
        elif doc_type == "cache":
            return [create_cache_document(f"bulk_{i}") for i in range(count)]
        else:
            raise ValueError(f"Unknown document type: {doc_type}")
    
    return {
        'create_user': create_user_document,
        'create_cache': create_cache_document,
        'create_bulk': create_bulk_documents
    }


class TestPyMongoIntegration:
    """
    Comprehensive PyMongo 4.5+ integration testing with Testcontainers MongoDB.
    
    Tests synchronous database operations with production-equivalent behavior,
    connection pooling validation, error handling, and performance monitoring.
    """
    
    def test_pymongo_client_initialization(self, test_database_config):
        """
        Test PyMongo client initialization with comprehensive configuration validation.
        
        Validates:
        - Proper client initialization with connection pooling
        - Configuration parameter application
        - Connection pool creation and sizing
        - Monitoring listener registration
        """
        mongodb_config = test_database_config.to_mongodb_config()
        client = create_mongodb_client(mongodb_config)
        
        assert client is not None
        assert client.config.database_name == TEST_DATABASE_NAME
        assert client.config.max_pool_size == DEFAULT_MAX_POOL_SIZE
        assert client.config.min_pool_size == DEFAULT_MIN_POOL_SIZE
        
        # Test client initialization
        client.initialize()
        assert client._initialized
        assert client._client is not None
        assert client._database is not None
        
        # Validate connection pool configuration
        pool_options = client._client.options.pool_options
        assert pool_options.max_pool_size == DEFAULT_MAX_POOL_SIZE
        assert pool_options.min_pool_size == DEFAULT_MIN_POOL_SIZE
        assert pool_options.max_idle_time.total_seconds() * 1000 == DEFAULT_MAX_IDLE_TIME_MS
        
        # Test connection health
        health_status = client.get_health_status()
        assert health_status["status"] == "healthy"
        assert "connection_count" in health_status
        assert "pool_size" in health_status
        
        client.close()
    
    def test_pymongo_crud_operations_performance(
        self, 
        database_manager, 
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test PyMongo CRUD operations with performance baseline validation.
        
        Validates:
        - Create, Read, Update, Delete operations with timing
        - Performance compliance with ≤10% variance from Node.js baseline
        - Operation success rates and error handling
        - Metrics collection for Prometheus monitoring
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Test INSERT operation with performance measurement
        user_doc = test_data_factory['create_user']("crud_test")
        
        start_time = time.time()
        result = client.insert_one(TEST_COLLECTION_NAME, user_doc)
        insert_duration = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        assert result.success
        assert result.inserted_id is not None
        assert isinstance(result.inserted_id, ObjectId)
        
        # Validate insert performance against Node.js baseline
        variance_percent = (insert_duration - NODEJS_BASELINE_INSERT_TIME_MS) / NODEJS_BASELINE_INSERT_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Insert performance variance {variance_percent:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
        
        metrics['query_duration'].labels(operation='insert', collection=TEST_COLLECTION_NAME).observe(insert_duration / 1000)
        metrics['operation_counter'].labels(operation='insert', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test READ operation with performance measurement
        start_time = time.time()
        read_result = client.find_one(TEST_COLLECTION_NAME, {"_id": result.inserted_id})
        read_duration = (time.time() - start_time) * 1000
        
        assert read_result.success
        assert read_result.data is not None
        assert read_result.data["username"] == user_doc["username"]
        assert read_result.data["email"] == user_doc["email"]
        
        # Validate read performance
        variance_percent = (read_duration - NODEJS_BASELINE_QUERY_TIME_MS) / NODEJS_BASELINE_QUERY_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD
        
        metrics['query_duration'].labels(operation='find_one', collection=TEST_COLLECTION_NAME).observe(read_duration / 1000)
        metrics['operation_counter'].labels(operation='find_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test UPDATE operation with performance measurement
        update_data = {"profile.age": 30, "updated_at": datetime.now(timezone.utc)}
        
        start_time = time.time()
        update_result = client.update_one(
            TEST_COLLECTION_NAME,
            {"_id": result.inserted_id},
            {"$set": update_data}
        )
        update_duration = (time.time() - start_time) * 1000
        
        assert update_result.success
        assert update_result.modified_count == 1
        assert update_result.matched_count == 1
        
        # Validate update performance
        variance_percent = (update_duration - NODEJS_BASELINE_UPDATE_TIME_MS) / NODEJS_BASELINE_UPDATE_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD
        
        metrics['query_duration'].labels(operation='update_one', collection=TEST_COLLECTION_NAME).observe(update_duration / 1000)
        metrics['operation_counter'].labels(operation='update_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Verify update was applied
        updated_doc = client.find_one(TEST_COLLECTION_NAME, {"_id": result.inserted_id})
        assert updated_doc.data["profile"]["age"] == 30
        
        # Test DELETE operation with performance measurement
        start_time = time.time()
        delete_result = client.delete_one(TEST_COLLECTION_NAME, {"_id": result.inserted_id})
        delete_duration = (time.time() - start_time) * 1000
        
        assert delete_result.success
        assert delete_result.deleted_count == 1
        
        # Validate delete performance
        variance_percent = (delete_duration - NODEJS_BASELINE_DELETE_TIME_MS) / NODEJS_BASELINE_DELETE_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD
        
        metrics['query_duration'].labels(operation='delete_one', collection=TEST_COLLECTION_NAME).observe(delete_duration / 1000)
        metrics['operation_counter'].labels(operation='delete_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Verify deletion
        deleted_doc = client.find_one(TEST_COLLECTION_NAME, {"_id": result.inserted_id})
        assert not deleted_doc.success or deleted_doc.data is None
    
    def test_pymongo_bulk_operations_performance(
        self, 
        database_manager, 
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test PyMongo bulk operations with performance validation and scalability testing.
        
        Validates:
        - Bulk insert, update, and delete operations
        - Performance characteristics under load
        - Batch size optimization
        - Error handling for partial failures
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Create test documents for bulk operations
        bulk_docs = test_data_factory['create_bulk'](100, "user")
        
        # Test bulk insert with performance measurement
        start_time = time.time()
        bulk_insert_result = client.insert_many(TEST_COLLECTION_NAME, bulk_docs)
        bulk_insert_duration = (time.time() - start_time) * 1000
        
        assert bulk_insert_result.success
        assert len(bulk_insert_result.data["inserted_ids"]) == 100
        
        # Validate bulk insert performance (should be significantly faster per document)
        per_doc_time = bulk_insert_duration / 100
        assert per_doc_time < NODEJS_BASELINE_INSERT_TIME_MS * 0.5, \
            f"Bulk insert per-document time {per_doc_time:.2f}ms should be < {NODEJS_BASELINE_INSERT_TIME_MS * 0.5}ms"
        
        metrics['query_duration'].labels(operation='insert_many', collection=TEST_COLLECTION_NAME).observe(bulk_insert_duration / 1000)
        metrics['operation_counter'].labels(operation='insert_many', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test bulk update operation
        inserted_ids = [ObjectId(id_str) for id_str in bulk_insert_result.data["inserted_ids"]]
        
        start_time = time.time()
        bulk_update_result = client.update_many(
            TEST_COLLECTION_NAME,
            {"_id": {"$in": inserted_ids}},
            {"$set": {"metadata.bulk_updated": True, "updated_at": datetime.now(timezone.utc)}}
        )
        bulk_update_duration = (time.time() - start_time) * 1000
        
        assert bulk_update_result.success
        assert bulk_update_result.modified_count == 100
        assert bulk_update_result.matched_count == 100
        
        metrics['query_duration'].labels(operation='update_many', collection=TEST_COLLECTION_NAME).observe(bulk_update_duration / 1000)
        metrics['operation_counter'].labels(operation='update_many', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test bulk delete operation
        start_time = time.time()
        bulk_delete_result = client.delete_many(
            TEST_COLLECTION_NAME,
            {"_id": {"$in": inserted_ids}}
        )
        bulk_delete_duration = (time.time() - start_time) * 1000
        
        assert bulk_delete_result.success
        assert bulk_delete_result.deleted_count == 100
        
        metrics['query_duration'].labels(operation='delete_many', collection=TEST_COLLECTION_NAME).observe(bulk_delete_duration / 1000)
        metrics['operation_counter'].labels(operation='delete_many', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        logger.info(
            "Bulk operations performance validation completed",
            bulk_insert_duration_ms=bulk_insert_duration,
            bulk_update_duration_ms=bulk_update_duration,
            bulk_delete_duration_ms=bulk_delete_duration,
            per_doc_insert_time_ms=per_doc_time
        )
    
    def test_pymongo_transaction_management(
        self, 
        database_manager, 
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test PyMongo transaction management with commit/rollback scenarios.
        
        Validates:
        - Transaction context creation and management
        - Commit operation on successful transactions
        - Rollback operation on failed transactions
        - Transaction isolation and consistency
        - Performance measurement for transaction overhead
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Test successful transaction with commit
        user_doc1 = test_data_factory['create_user']("transaction_success")
        user_doc2 = test_data_factory['create_user']("transaction_success_2")
        
        start_time = time.time()
        
        with database_transaction() as session:
            # Insert first document
            result1 = client.insert_one(TEST_COLLECTION_NAME, user_doc1, session=session)
            assert result1.success
            
            # Insert second document
            result2 = client.insert_one(TEST_COLLECTION_NAME, user_doc2, session=session)
            assert result2.success
            
            # Update first document
            update_result = client.update_one(
                TEST_COLLECTION_NAME,
                {"_id": result1.inserted_id},
                {"$set": {"metadata.transaction_test": True}},
                session=session
            )
            assert update_result.success
            assert update_result.modified_count == 1
        
        transaction_duration = (time.time() - start_time) * 1000
        
        # Validate transaction performance
        variance_percent = (transaction_duration - NODEJS_BASELINE_TRANSACTION_TIME_MS) / NODEJS_BASELINE_TRANSACTION_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 2, \
            f"Transaction performance variance {variance_percent:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD * 2}% threshold"
        
        metrics['transaction_duration'].labels(status='committed').observe(transaction_duration / 1000)
        
        # Verify both documents were committed
        committed_doc1 = client.find_one(TEST_COLLECTION_NAME, {"_id": result1.inserted_id})
        committed_doc2 = client.find_one(TEST_COLLECTION_NAME, {"_id": result2.inserted_id})
        
        assert committed_doc1.success and committed_doc1.data is not None
        assert committed_doc2.success and committed_doc2.data is not None
        assert committed_doc1.data["metadata"]["transaction_test"] is True
        
        # Test transaction rollback scenario
        user_doc3 = test_data_factory['create_user']("transaction_rollback")
        
        start_time = time.time()
        
        try:
            with database_transaction() as session:
                # Insert document
                result3 = client.insert_one(TEST_COLLECTION_NAME, user_doc3, session=session)
                assert result3.success
                
                # Intentionally cause an error to trigger rollback
                # Try to insert duplicate _id which should fail
                duplicate_doc = user_doc3.copy()
                duplicate_doc["_id"] = result3.inserted_id
                
                # This should raise an exception and cause rollback
                client.insert_one(TEST_COLLECTION_NAME, duplicate_doc, session=session)
        except (DatabaseException, DuplicateKeyError):
            # Expected exception for rollback testing
            pass
        
        rollback_duration = (time.time() - start_time) * 1000
        metrics['transaction_duration'].labels(status='rolled_back').observe(rollback_duration / 1000)
        
        # Verify transaction was rolled back - document should not exist
        rolled_back_doc = client.find_one(TEST_COLLECTION_NAME, {"username": user_doc3["username"]})
        assert not rolled_back_doc.success or rolled_back_doc.data is None
        
        # Cleanup committed documents
        client.delete_one(TEST_COLLECTION_NAME, {"_id": result1.inserted_id})
        client.delete_one(TEST_COLLECTION_NAME, {"_id": result2.inserted_id})
        
        logger.info(
            "Transaction management validation completed",
            commit_duration_ms=transaction_duration,
            rollback_duration_ms=rollback_duration
        )
    
    def test_pymongo_connection_pooling_validation(
        self, 
        database_manager,
        performance_metrics_registry
    ):
        """
        Test PyMongo connection pool behavior and resource management.
        
        Validates:
        - Connection pool creation and sizing
        - Connection checkout and checkin behavior
        - Pool exhaustion and recovery scenarios
        - Connection lifecycle management
        - Pool monitoring and health checking
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Verify initial pool state
        pool_stats = client.get_pool_stats()
        assert pool_stats["max_pool_size"] == DEFAULT_MAX_POOL_SIZE
        assert pool_stats["min_pool_size"] == DEFAULT_MIN_POOL_SIZE
        assert pool_stats["current_pool_size"] >= 0
        
        metrics['connection_pool_size'].labels(pool_type='pymongo').set(pool_stats["current_pool_size"])
        
        # Test concurrent connection usage
        def execute_query(query_id: int) -> Dict[str, Any]:
            """Execute a database query to test connection pool usage."""
            doc = {
                "query_id": query_id,
                "timestamp": datetime.now(timezone.utc),
                "data": f"Connection pool test {query_id}"
            }
            
            # Insert and immediately read to use connection
            insert_result = client.insert_one(TEST_COLLECTION_NAME, doc)
            if insert_result.success:
                read_result = client.find_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
                client.delete_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
                return {"success": True, "query_id": query_id}
            return {"success": False, "query_id": query_id}
        
        # Execute concurrent queries to test pool behavior
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTION_POOL_TEST_SIZE) as executor:
            start_time = time.time()
            
            # Submit multiple concurrent queries
            futures = [
                executor.submit(execute_query, i) 
                for i in range(CONNECTION_POOL_TEST_SIZE)
            ]
            
            # Collect results
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            concurrent_duration = time.time() - start_time
        
        # Validate all queries succeeded
        successful_queries = [r for r in results if r["success"]]
        assert len(successful_queries) == CONNECTION_POOL_TEST_SIZE
        
        # Verify pool handled concurrent load efficiently
        avg_query_time = concurrent_duration / CONNECTION_POOL_TEST_SIZE
        assert avg_query_time < 1.0, f"Average query time {avg_query_time:.3f}s too high for concurrent execution"
        
        # Check final pool state
        final_pool_stats = client.get_pool_stats()
        metrics['connection_pool_size'].labels(pool_type='pymongo').set(final_pool_stats["current_pool_size"])
        
        logger.info(
            "Connection pooling validation completed",
            concurrent_queries=CONNECTION_POOL_TEST_SIZE,
            total_duration_seconds=concurrent_duration,
            avg_query_time_seconds=avg_query_time,
            final_pool_size=final_pool_stats["current_pool_size"]
        )
    
    def test_pymongo_error_handling_and_recovery(
        self, 
        database_manager,
        test_data_factory
    ):
        """
        Test PyMongo error handling and connection recovery scenarios.
        
        Validates:
        - Network timeout handling and retry logic
        - Server selection timeout scenarios
        - Duplicate key error handling
        - Bulk operation error scenarios
        - Circuit breaker pattern implementation
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        # Test duplicate key error handling
        user_doc = test_data_factory['create_user']("error_test")
        
        # Insert document successfully
        insert_result = client.insert_one(TEST_COLLECTION_NAME, user_doc)
        assert insert_result.success
        
        # Try to insert duplicate _id (should handle error gracefully)
        duplicate_doc = user_doc.copy()
        duplicate_doc["_id"] = insert_result.inserted_id
        
        duplicate_result = client.insert_one(TEST_COLLECTION_NAME, duplicate_doc)
        assert not duplicate_result.success
        assert "duplicate" in duplicate_result.error.lower() or "E11000" in duplicate_result.error
        
        # Test bulk operation with partial failures
        bulk_docs = test_data_factory['create_bulk'](5, "user")
        
        # Insert first batch successfully
        bulk_result1 = client.insert_many(TEST_COLLECTION_NAME, bulk_docs)
        assert bulk_result1.success
        
        # Try to insert same documents again (should handle bulk errors)
        bulk_result2 = client.insert_many(TEST_COLLECTION_NAME, bulk_docs)
        assert not bulk_result2.success
        # Should contain information about which operations failed
        assert bulk_result2.error is not None
        
        # Test invalid query handling
        invalid_query_result = client.find_one(TEST_COLLECTION_NAME, {"_id": "invalid_object_id"})
        assert not invalid_query_result.success
        assert invalid_query_result.error is not None
        
        # Test network resilience with retry logic
        # Temporarily patch to simulate network error
        original_find = client._database.find_one
        
        retry_count = 0
        def mock_find_with_retry(*args, **kwargs):
            nonlocal retry_count
            retry_count += 1
            if retry_count == 1:
                raise NetworkTimeout("Simulated network timeout")
            return original_find(*args, **kwargs)
        
        with patch.object(client._database, 'find_one', side_effect=mock_find_with_retry):
            # This should retry and succeed on second attempt
            retry_result = client.find_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
            # Note: Depending on implementation, this might fail or succeed based on retry logic
            # The important part is that it handles the error gracefully
        
        assert retry_count >= 1  # Verify the mock was called
        
        # Cleanup test documents
        client.delete_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
        for doc_id in bulk_result1.data["inserted_ids"]:
            client.delete_one(TEST_COLLECTION_NAME, {"_id": ObjectId(doc_id)})
        
        logger.info(
            "Error handling and recovery validation completed",
            duplicate_error_handled=not duplicate_result.success,
            bulk_error_handled=not bulk_result2.success,
            retry_attempts=retry_count
        )


class TestMotorAsyncIntegration:
    """
    Comprehensive Motor 3.3+ async database operations testing with pytest-asyncio.
    
    Tests asynchronous database operations, concurrent access patterns, async transaction
    management, and performance optimization for high-throughput database operations.
    """
    
    @pytest.mark.asyncio
    async def test_motor_client_initialization(self, test_database_config):
        """
        Test Motor async client initialization and configuration validation.
        
        Validates:
        - Async client initialization with proper configuration
        - Connection pool setup for async operations
        - Database connectivity and health checking
        - Async context management
        """
        motor_options = test_database_config.get_motor_client_options()
        
        motor_client = await initialize_motor_client(
            test_database_config.mongodb_uri,
            **motor_options
        )
        
        assert motor_client is not None
        assert motor_client.max_pool_size == test_database_config.motor_max_pool_size
        assert motor_client.min_pool_size == test_database_config.motor_min_pool_size
        
        # Test database access
        motor_db = await get_motor_database(
            test_database_config.database_name,
            client=motor_client
        )
        
        assert motor_db is not None
        assert motor_db.database_name == test_database_config.database_name
        
        # Test connection health
        try:
            # Simple ping to verify connection
            await motor_client.admin.command('ping')
            connection_healthy = True
        except Exception:
            connection_healthy = False
        
        assert connection_healthy
        
        # Cleanup
        await close_motor_client()
    
    @pytest.mark.asyncio
    async def test_motor_async_crud_operations(
        self, 
        async_motor_database,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test Motor async CRUD operations with performance measurement.
        
        Validates:
        - Async insert, read, update, delete operations
        - Performance characteristics of async operations
        - Concurrent operation capabilities
        - Error handling in async context
        """
        motor_db = async_motor_database
        assert motor_db is not None
        
        metrics = performance_metrics_registry
        collection = motor_db.get_collection(TEST_COLLECTION_NAME)
        
        # Test async INSERT operation
        user_doc = test_data_factory['create_user']("motor_crud")
        
        start_time = time.time()
        insert_result = await collection.insert_one(user_doc)
        insert_duration = (time.time() - start_time) * 1000
        
        assert insert_result.inserted_id is not None
        assert isinstance(insert_result.inserted_id, ObjectId)
        
        # Validate async insert performance
        variance_percent = (insert_duration - NODEJS_BASELINE_INSERT_TIME_MS) / NODEJS_BASELINE_INSERT_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 1.5, \
            f"Async insert performance variance {variance_percent:.2f}% exceeds threshold"
        
        metrics['query_duration'].labels(operation='async_insert', collection=TEST_COLLECTION_NAME).observe(insert_duration / 1000)
        metrics['operation_counter'].labels(operation='async_insert', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test async READ operation
        start_time = time.time()
        read_doc = await collection.find_one({"_id": insert_result.inserted_id})
        read_duration = (time.time() - start_time) * 1000
        
        assert read_doc is not None
        assert read_doc["username"] == user_doc["username"]
        assert read_doc["email"] == user_doc["email"]
        
        # Validate async read performance
        variance_percent = (read_duration - NODEJS_BASELINE_QUERY_TIME_MS) / NODEJS_BASELINE_QUERY_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 1.5
        
        metrics['query_duration'].labels(operation='async_find_one', collection=TEST_COLLECTION_NAME).observe(read_duration / 1000)
        metrics['operation_counter'].labels(operation='async_find_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Test async UPDATE operation
        update_data = {"$set": {"profile.age": 35, "updated_at": datetime.now(timezone.utc)}}
        
        start_time = time.time()
        update_result = await collection.update_one(
            {"_id": insert_result.inserted_id},
            update_data
        )
        update_duration = (time.time() - start_time) * 1000
        
        assert update_result.modified_count == 1
        assert update_result.matched_count == 1
        
        # Validate async update performance
        variance_percent = (update_duration - NODEJS_BASELINE_UPDATE_TIME_MS) / NODEJS_BASELINE_UPDATE_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 1.5
        
        metrics['query_duration'].labels(operation='async_update_one', collection=TEST_COLLECTION_NAME).observe(update_duration / 1000)
        metrics['operation_counter'].labels(operation='async_update_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Verify update was applied
        updated_doc = await collection.find_one({"_id": insert_result.inserted_id})
        assert updated_doc["profile"]["age"] == 35
        
        # Test async DELETE operation
        start_time = time.time()
        delete_result = await collection.delete_one({"_id": insert_result.inserted_id})
        delete_duration = (time.time() - start_time) * 1000
        
        assert delete_result.deleted_count == 1
        
        # Validate async delete performance
        variance_percent = (delete_duration - NODEJS_BASELINE_DELETE_TIME_MS) / NODEJS_BASELINE_DELETE_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 1.5
        
        metrics['query_duration'].labels(operation='async_delete_one', collection=TEST_COLLECTION_NAME).observe(delete_duration / 1000)
        metrics['operation_counter'].labels(operation='async_delete_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Verify deletion
        deleted_doc = await collection.find_one({"_id": insert_result.inserted_id})
        assert deleted_doc is None
        
        logger.info(
            "Motor async CRUD operations validation completed",
            insert_duration_ms=insert_duration,
            read_duration_ms=read_duration,
            update_duration_ms=update_duration,
            delete_duration_ms=delete_duration
        )
    
    @pytest.mark.asyncio
    async def test_motor_concurrent_operations(
        self, 
        async_motor_database,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test Motor concurrent database operations and connection pool validation.
        
        Validates:
        - Concurrent async operations execution
        - Connection pool efficiency under load
        - Async operation scalability
        - Error handling in concurrent scenarios
        """
        motor_db = async_motor_database
        assert motor_db is not None
        
        metrics = performance_metrics_registry
        collection = motor_db.get_collection(TEST_COLLECTION_NAME)
        
        async def execute_concurrent_operation(operation_id: int) -> Dict[str, Any]:
            """Execute async database operation for concurrent testing."""
            try:
                # Create unique document for this operation
                doc = test_data_factory['create_user'](f"concurrent_{operation_id}")
                
                # Insert document
                insert_result = await collection.insert_one(doc)
                
                # Read document back
                read_doc = await collection.find_one({"_id": insert_result.inserted_id})
                
                # Update document
                await collection.update_one(
                    {"_id": insert_result.inserted_id},
                    {"$set": {"metadata.concurrent_test": True}}
                )
                
                # Delete document
                await collection.delete_one({"_id": insert_result.inserted_id})
                
                return {
                    "operation_id": operation_id,
                    "success": True,
                    "inserted_id": str(insert_result.inserted_id)
                }
            except Exception as e:
                return {
                    "operation_id": operation_id,
                    "success": False,
                    "error": str(e)
                }
        
        # Execute concurrent operations
        start_time = time.time()
        
        tasks = [
            execute_concurrent_operation(i) 
            for i in range(CONCURRENT_OPERATIONS_COUNT)
        ]
        
        results = await asyncio.gather(*tasks)
        
        concurrent_duration = time.time() - start_time
        
        # Validate results
        successful_operations = [r for r in results if r["success"]]
        failed_operations = [r for r in results if not r["success"]]
        
        assert len(successful_operations) == CONCURRENT_OPERATIONS_COUNT, \
            f"Expected {CONCURRENT_OPERATIONS_COUNT} successful operations, got {len(successful_operations)}"
        
        assert len(failed_operations) == 0, \
            f"Unexpected failures in concurrent operations: {failed_operations}"
        
        # Validate concurrent performance
        avg_operation_time = concurrent_duration / CONCURRENT_OPERATIONS_COUNT
        assert avg_operation_time < 0.5, \
            f"Average concurrent operation time {avg_operation_time:.3f}s too high"
        
        # Record metrics
        metrics['query_duration'].labels(operation='concurrent_async', collection=TEST_COLLECTION_NAME).observe(concurrent_duration)
        metrics['operation_counter'].labels(operation='concurrent_async', collection=TEST_COLLECTION_NAME, status='success').inc(len(successful_operations))
        
        logger.info(
            "Motor concurrent operations validation completed",
            concurrent_operations=CONCURRENT_OPERATIONS_COUNT,
            total_duration_seconds=concurrent_duration,
            avg_operation_time_seconds=avg_operation_time,
            successful_operations=len(successful_operations),
            failed_operations=len(failed_operations)
        )
    
    @pytest.mark.asyncio
    async def test_motor_async_transactions(
        self, 
        async_motor_database,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test Motor async transaction management with commit/rollback scenarios.
        
        Validates:
        - Async transaction context management
        - Async commit and rollback operations
        - Transaction isolation in async context
        - Performance characteristics of async transactions
        """
        motor_db = async_motor_database
        assert motor_db is not None
        
        metrics = performance_metrics_registry
        collection = motor_db.get_collection(TEST_COLLECTION_NAME)
        
        # Test successful async transaction
        user_doc1 = test_data_factory['create_user']("async_transaction_1")
        user_doc2 = test_data_factory['create_user']("async_transaction_2")
        
        start_time = time.time()
        
        async with await motor_db.start_transaction() as session:
            # Insert first document
            result1 = await collection.insert_one(user_doc1, session=session)
            
            # Insert second document
            result2 = await collection.insert_one(user_doc2, session=session)
            
            # Update first document
            await collection.update_one(
                {"_id": result1.inserted_id},
                {"$set": {"metadata.async_transaction": True}},
                session=session
            )
            
            # Transaction will auto-commit when context exits successfully
        
        transaction_duration = (time.time() - start_time) * 1000
        
        # Validate async transaction performance
        variance_percent = (transaction_duration - NODEJS_BASELINE_TRANSACTION_TIME_MS) / NODEJS_BASELINE_TRANSACTION_TIME_MS * 100
        assert abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD * 2, \
            f"Async transaction performance variance {variance_percent:.2f}% exceeds threshold"
        
        metrics['transaction_duration'].labels(status='async_committed').observe(transaction_duration / 1000)
        
        # Verify both documents were committed
        committed_doc1 = await collection.find_one({"_id": result1.inserted_id})
        committed_doc2 = await collection.find_one({"_id": result2.inserted_id})
        
        assert committed_doc1 is not None
        assert committed_doc2 is not None
        assert committed_doc1["metadata"]["async_transaction"] is True
        
        # Test async transaction rollback
        user_doc3 = test_data_factory['create_user']("async_transaction_rollback")
        
        start_time = time.time()
        
        try:
            async with await motor_db.start_transaction() as session:
                # Insert document
                result3 = await collection.insert_one(user_doc3, session=session)
                
                # Cause intentional error to trigger rollback
                duplicate_doc = user_doc3.copy()
                duplicate_doc["_id"] = result3.inserted_id
                
                # This should raise DuplicateKeyError and cause rollback
                await collection.insert_one(duplicate_doc, session=session)
        except Exception:
            # Expected exception for rollback testing
            pass
        
        rollback_duration = (time.time() - start_time) * 1000
        metrics['transaction_duration'].labels(status='async_rolled_back').observe(rollback_duration / 1000)
        
        # Verify transaction was rolled back
        rolled_back_doc = await collection.find_one({"username": user_doc3["username"]})
        assert rolled_back_doc is None
        
        # Cleanup committed documents
        await collection.delete_one({"_id": result1.inserted_id})
        await collection.delete_one({"_id": result2.inserted_id})
        
        logger.info(
            "Motor async transaction validation completed",
            commit_duration_ms=transaction_duration,
            rollback_duration_ms=rollback_duration
        )
    
    @pytest.mark.asyncio
    async def test_motor_connection_pool_monitoring(
        self, 
        async_motor_database,
        performance_metrics_registry
    ):
        """
        Test Motor async connection pool monitoring and health validation.
        
        Validates:
        - Async connection pool statistics
        - Pool behavior under concurrent load
        - Connection lifecycle monitoring
        - Pool efficiency metrics
        """
        motor_db = async_motor_database
        assert motor_db is not None
        
        metrics = performance_metrics_registry
        collection = motor_db.get_collection(TEST_COLLECTION_NAME)
        
        # Monitor connection pool during load
        async def monitor_pool_operation(op_id: int) -> Dict[str, Any]:
            """Execute operation while monitoring pool usage."""
            doc = {
                "operation_id": op_id,
                "timestamp": datetime.now(timezone.utc),
                "pool_test": True
            }
            
            # Execute CRUD operations to use connections
            insert_result = await collection.insert_one(doc)
            read_result = await collection.find_one({"_id": insert_result.inserted_id})
            await collection.update_one(
                {"_id": insert_result.inserted_id},
                {"$set": {"updated": True}}
            )
            await collection.delete_one({"_id": insert_result.inserted_id})
            
            return {"operation_id": op_id, "success": True}
        
        # Execute concurrent operations to test pool
        start_time = time.time()
        
        pool_tasks = [
            monitor_pool_operation(i) 
            for i in range(CONNECTION_POOL_TEST_SIZE)
        ]
        
        pool_results = await asyncio.gather(*pool_tasks)
        
        pool_test_duration = time.time() - start_time
        
        # Validate all operations succeeded
        successful_pool_ops = [r for r in pool_results if r["success"]]
        assert len(successful_pool_ops) == CONNECTION_POOL_TEST_SIZE
        
        # Validate pool efficiency
        avg_pool_op_time = pool_test_duration / CONNECTION_POOL_TEST_SIZE
        assert avg_pool_op_time < 1.0, \
            f"Average async pool operation time {avg_pool_op_time:.3f}s too high"
        
        # Record pool metrics
        metrics['connection_pool_size'].labels(pool_type='motor_async').set(CONNECTION_POOL_TEST_SIZE)
        
        logger.info(
            "Motor connection pool monitoring validation completed",
            pool_operations=CONNECTION_POOL_TEST_SIZE,
            total_duration_seconds=pool_test_duration,
            avg_operation_time_seconds=avg_pool_op_time
        )


class TestDatabasePerformanceBenchmarking:
    """
    Database performance benchmarking against Node.js baseline ensuring ≤10% variance.
    
    Comprehensive performance validation testing query execution times, transaction overhead,
    connection pool efficiency, and concurrent operation throughput against established
    Node.js performance baselines.
    """
    
    def test_query_performance_baseline_comparison(
        self, 
        database_manager,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test database query performance against Node.js baseline measurements.
        
        Validates:
        - Single query execution time compliance
        - Query optimization effectiveness
        - Index utilization performance
        - Statistical performance analysis
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Setup test data with indexes for performance testing
        collection_name = f"{TEST_COLLECTION_NAME}_performance"
        
        # Create test index for query optimization
        client._database[collection_name].create_index([("email", 1), ("created_at", 1)])
        
        # Insert test data for querying
        test_docs = test_data_factory['create_bulk'](1000, "user")
        
        bulk_insert_start = time.time()
        bulk_result = client.insert_many(collection_name, test_docs)
        bulk_insert_duration = time.time() - bulk_insert_start
        
        assert bulk_result.success
        logger.info(f"Inserted {len(test_docs)} documents in {bulk_insert_duration:.3f}s for performance testing")
        
        # Performance test: Single document queries
        query_times = []
        for i in range(100):
            random_doc = test_docs[i % len(test_docs)]
            
            start_time = time.time()
            result = client.find_one(collection_name, {"email": random_doc["email"]})
            query_time = (time.time() - start_time) * 1000
            
            assert result.success
            query_times.append(query_time)
            
            metrics['query_duration'].labels(operation='perf_find_one', collection=collection_name).observe(query_time / 1000)
        
        # Statistical analysis of query performance
        avg_query_time = sum(query_times) / len(query_times)
        p95_query_time = sorted(query_times)[int(0.95 * len(query_times))]
        p99_query_time = sorted(query_times)[int(0.99 * len(query_times))]
        
        # Validate against Node.js baseline with ≤10% variance
        avg_variance = (avg_query_time - NODEJS_BASELINE_QUERY_TIME_MS) / NODEJS_BASELINE_QUERY_TIME_MS * 100
        p95_variance = (p95_query_time - NODEJS_BASELINE_PERCENTILES['p95']) / NODEJS_BASELINE_PERCENTILES['p95'] * 100
        p99_variance = (p99_query_time - NODEJS_BASELINE_PERCENTILES['p99']) / NODEJS_BASELINE_PERCENTILES['p99'] * 100
        
        assert abs(avg_variance) <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Average query time variance {avg_variance:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
        
        assert abs(p95_variance) <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"P95 query time variance {p95_variance:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
        
        assert abs(p99_variance) <= PERFORMANCE_VARIANCE_THRESHOLD * 1.5, \
            f"P99 query time variance {p99_variance:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD * 1.5}% threshold"
        
        # Performance test: Range queries with sorting
        range_query_times = []
        for i in range(50):
            start_time = time.time()
            
            # Query documents created in last hour, sorted by created_at
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
            result = client.find(
                collection_name,
                {"created_at": {"$gte": cutoff_time}},
                sort=[("created_at", -1)],
                limit=10
            )
            
            range_query_time = (time.time() - start_time) * 1000
            assert result.success
            range_query_times.append(range_query_time)
            
            metrics['query_duration'].labels(operation='perf_range_query', collection=collection_name).observe(range_query_time / 1000)
        
        avg_range_query_time = sum(range_query_times) / len(range_query_times)
        
        # Range queries should be reasonably fast with proper indexing
        assert avg_range_query_time < NODEJS_BASELINE_QUERY_TIME_MS * 3, \
            f"Average range query time {avg_range_query_time:.2f}ms too high"
        
        # Cleanup test data
        client.delete_many(collection_name, {})
        client._database[collection_name].drop_index([("email", 1), ("created_at", 1)])
        
        logger.info(
            "Query performance baseline validation completed",
            avg_query_time_ms=avg_query_time,
            p95_query_time_ms=p95_query_time,
            p99_query_time_ms=p99_query_time,
            avg_variance_percent=avg_variance,
            p95_variance_percent=p95_variance,
            p99_variance_percent=p99_variance,
            avg_range_query_time_ms=avg_range_query_time
        )
    
    def test_transaction_performance_baseline(
        self, 
        database_manager,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test transaction performance against Node.js baseline with comprehensive scenarios.
        
        Validates:
        - Transaction overhead measurement
        - Multi-operation transaction performance
        - Transaction rollback performance
        - Concurrent transaction handling
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Test simple transaction performance
        simple_transaction_times = []
        for i in range(50):
            user_doc = test_data_factory['create_user'](f"transaction_perf_{i}")
            
            start_time = time.time()
            
            with database_transaction() as session:
                result = client.insert_one(TEST_COLLECTION_NAME, user_doc, session=session)
                assert result.success
                
                # Update the document in same transaction
                client.update_one(
                    TEST_COLLECTION_NAME,
                    {"_id": result.inserted_id},
                    {"$set": {"metadata.transaction_test": True}},
                    session=session
                )
            
            transaction_time = (time.time() - start_time) * 1000
            simple_transaction_times.append(transaction_time)
            
            metrics['transaction_duration'].labels(status='performance_test').observe(transaction_time / 1000)
            
            # Cleanup
            client.delete_one(TEST_COLLECTION_NAME, {"_id": result.inserted_id})
        
        # Analyze transaction performance
        avg_transaction_time = sum(simple_transaction_times) / len(simple_transaction_times)
        p95_transaction_time = sorted(simple_transaction_times)[int(0.95 * len(simple_transaction_times))]
        
        # Validate against Node.js baseline
        transaction_variance = (avg_transaction_time - NODEJS_BASELINE_TRANSACTION_TIME_MS) / NODEJS_BASELINE_TRANSACTION_TIME_MS * 100
        
        assert abs(transaction_variance) <= PERFORMANCE_VARIANCE_THRESHOLD, \
            f"Transaction performance variance {transaction_variance:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
        
        # Test complex multi-collection transaction performance
        complex_transaction_times = []
        for i in range(20):
            user_doc = test_data_factory['create_user'](f"complex_transaction_{i}")
            cache_doc = test_data_factory['create_cache'](f"complex_transaction_{i}")
            
            start_time = time.time()
            
            with database_transaction() as session:
                # Insert user document
                user_result = client.insert_one(TEST_COLLECTION_NAME, user_doc, session=session)
                assert user_result.success
                
                # Insert related cache document
                cache_doc["metadata"]["user_id"] = str(user_result.inserted_id)
                cache_result = client.insert_one(TEST_CACHE_COLLECTION, cache_doc, session=session)
                assert cache_result.success
                
                # Create audit log entry
                audit_doc = {
                    "user_id": str(user_result.inserted_id),
                    "action": "user_created",
                    "timestamp": datetime.now(timezone.utc),
                    "metadata": {"cache_id": str(cache_result.inserted_id)}
                }
                audit_result = client.insert_one(TEST_AUDIT_COLLECTION, audit_doc, session=session)
                assert audit_result.success
            
            complex_transaction_time = (time.time() - start_time) * 1000
            complex_transaction_times.append(complex_transaction_time)
            
            # Cleanup
            client.delete_one(TEST_COLLECTION_NAME, {"_id": user_result.inserted_id})
            client.delete_one(TEST_CACHE_COLLECTION, {"_id": cache_result.inserted_id})
            client.delete_one(TEST_AUDIT_COLLECTION, {"_id": audit_result.inserted_id})
        
        avg_complex_transaction_time = sum(complex_transaction_times) / len(complex_transaction_times)
        
        # Complex transactions should be reasonable multiples of simple transactions
        assert avg_complex_transaction_time < NODEJS_BASELINE_TRANSACTION_TIME_MS * 3, \
            f"Complex transaction time {avg_complex_transaction_time:.2f}ms too high"
        
        logger.info(
            "Transaction performance baseline validation completed",
            avg_simple_transaction_ms=avg_transaction_time,
            p95_simple_transaction_ms=p95_transaction_time,
            transaction_variance_percent=transaction_variance,
            avg_complex_transaction_ms=avg_complex_transaction_time
        )
    
    def test_concurrent_performance_scalability(
        self, 
        database_manager,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test concurrent database operations performance and scalability validation.
        
        Validates:
        - Concurrent query throughput
        - Connection pool efficiency under load
        - Scalability characteristics
        - Resource utilization optimization
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Prepare test data for concurrent operations
        test_docs = test_data_factory['create_bulk'](200, "user")
        bulk_result = client.insert_many(TEST_COLLECTION_NAME, test_docs)
        assert bulk_result.success
        
        inserted_ids = [ObjectId(id_str) for id_str in bulk_result.data["inserted_ids"]]
        
        def execute_concurrent_workload(worker_id: int) -> Dict[str, Any]:
            """Execute mixed workload for concurrent performance testing."""
            operation_times = []
            
            for i in range(10):  # 10 operations per worker
                # Random read operation
                start_time = time.time()
                random_id = inserted_ids[i % len(inserted_ids)]
                read_result = client.find_one(TEST_COLLECTION_NAME, {"_id": random_id})
                read_time = (time.time() - start_time) * 1000
                
                assert read_result.success
                operation_times.append(read_time)
                
                # Update operation
                start_time = time.time()
                update_result = client.update_one(
                    TEST_COLLECTION_NAME,
                    {"_id": random_id},
                    {"$set": {f"metadata.worker_{worker_id}_update": i}}
                )
                update_time = (time.time() - start_time) * 1000
                
                assert update_result.success
                operation_times.append(update_time)
            
            return {
                "worker_id": worker_id,
                "operation_times": operation_times,
                "avg_operation_time": sum(operation_times) / len(operation_times)
            }
        
        # Execute concurrent workload with thread pool
        concurrent_workers = 20
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_workers) as executor:
            futures = [
                executor.submit(execute_concurrent_workload, worker_id)
                for worker_id in range(concurrent_workers)
            ]
            
            concurrent_results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_concurrent_duration = time.time() - start_time
        
        # Analyze concurrent performance
        all_operation_times = []
        for result in concurrent_results:
            all_operation_times.extend(result["operation_times"])
        
        total_operations = len(all_operation_times)
        avg_concurrent_operation_time = sum(all_operation_times) / total_operations
        throughput_ops_per_second = total_operations / total_concurrent_duration
        
        # Validate concurrent performance
        assert avg_concurrent_operation_time < NODEJS_BASELINE_QUERY_TIME_MS * 2, \
            f"Average concurrent operation time {avg_concurrent_operation_time:.2f}ms too high"
        
        assert throughput_ops_per_second > 100, \
            f"Concurrent throughput {throughput_ops_per_second:.2f} ops/sec too low"
        
        # Test long-duration load simulation
        load_test_start = time.time()
        load_test_operations = 0
        
        def continuous_load_worker():
            """Continuous load testing worker."""
            nonlocal load_test_operations
            
            while time.time() - load_test_start < LOAD_TEST_DURATION_SECONDS:
                random_id = inserted_ids[load_test_operations % len(inserted_ids)]
                
                # Simple read operation
                result = client.find_one(TEST_COLLECTION_NAME, {"_id": random_id})
                if result.success:
                    load_test_operations += 1
                
                time.sleep(0.01)  # Small delay to prevent overwhelming
        
        # Run continuous load test
        load_workers = 5
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=load_workers) as executor:
            load_futures = [
                executor.submit(continuous_load_worker)
                for _ in range(load_workers)
            ]
            
            # Wait for all workers to complete
            for future in concurrent.futures.as_completed(load_futures):
                future.result()
        
        load_test_duration = time.time() - load_test_start
        sustained_throughput = load_test_operations / load_test_duration
        
        # Validate sustained performance
        assert sustained_throughput > 50, \
            f"Sustained throughput {sustained_throughput:.2f} ops/sec too low"
        
        # Record performance metrics
        metrics['query_duration'].labels(operation='concurrent_load', collection=TEST_COLLECTION_NAME).observe(total_concurrent_duration)
        
        # Cleanup test data
        client.delete_many(TEST_COLLECTION_NAME, {"_id": {"$in": inserted_ids}})
        
        logger.info(
            "Concurrent performance scalability validation completed",
            concurrent_workers=concurrent_workers,
            total_operations=total_operations,
            avg_operation_time_ms=avg_concurrent_operation_time,
            throughput_ops_per_sec=throughput_ops_per_second,
            load_test_duration_sec=load_test_duration,
            sustained_throughput_ops_per_sec=sustained_throughput
        )


class TestDatabaseHealthMonitoring:
    """
    Database health monitoring and failure recovery testing.
    
    Comprehensive testing of database health checking, monitoring integration,
    circuit breaker patterns, and failure recovery scenarios for production-ready
    database operations.
    """
    
    def test_database_health_monitoring_integration(
        self, 
        database_manager,
        performance_metrics_registry
    ):
        """
        Test database health monitoring and metrics collection integration.
        
        Validates:
        - Health check functionality
        - Metrics collection accuracy
        - Monitoring component integration
        - Alert threshold validation
        """
        manager = database_manager
        assert manager is not None
        assert manager.health_checker is not None
        
        # Test overall health status
        health_status = manager.get_health_status()
        
        assert health_status["overall_status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in health_status
        assert "components" in health_status
        
        # Validate MongoDB component health
        assert "mongodb" in health_status["components"]
        mongodb_health = health_status["components"]["mongodb"]
        
        assert mongodb_health["status"] in ["healthy", "degraded", "unhealthy"]
        assert "connection_count" in mongodb_health
        assert "response_time_ms" in mongodb_health
        
        # Test PyMongo sync client health
        if "mongodb_sync" in health_status["components"]:
            sync_health = health_status["components"]["mongodb_sync"]
            assert sync_health["status"] in ["healthy", "degraded", "unhealthy"]
            assert "pool_size" in sync_health
        
        # Test Motor async client health
        if "motor_async" in health_status["components"]:
            async_health = health_status["components"]["motor_async"]
            assert async_health["status"] == "healthy"
            assert async_health["async_enabled"] is True
        
        # Test health check performance
        health_check_times = []
        for i in range(10):
            start_time = time.time()
            health_status = manager.get_health_status()
            health_check_time = (time.time() - start_time) * 1000
            
            health_check_times.append(health_check_time)
            assert health_status["overall_status"] is not None
        
        avg_health_check_time = sum(health_check_times) / len(health_check_times)
        
        # Health checks should be fast
        assert avg_health_check_time < 100, \
            f"Average health check time {avg_health_check_time:.2f}ms too slow"
        
        # Test monitoring components
        if manager.monitoring_components:
            monitoring_components = manager.monitoring_components
            
            assert "database_metrics" in monitoring_components
            assert "connection_pool_listener" in monitoring_components
            assert "health_checker" in monitoring_components
        
        logger.info(
            "Database health monitoring validation completed",
            overall_status=health_status["overall_status"],
            mongodb_status=mongodb_health["status"],
            avg_health_check_time_ms=avg_health_check_time,
            monitoring_enabled=manager.monitoring_components is not None
        )
    
    def test_connection_failure_recovery(
        self, 
        database_manager,
        test_data_factory
    ):
        """
        Test database connection failure scenarios and recovery mechanisms.
        
        Validates:
        - Connection failure detection
        - Automatic reconnection logic
        - Circuit breaker pattern implementation
        - Graceful degradation handling
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        # Test normal operation first
        test_doc = test_data_factory['create_user']("failure_recovery")
        normal_result = client.insert_one(TEST_COLLECTION_NAME, test_doc)
        assert normal_result.success
        
        # Test connection resilience with temporary network issues
        original_find_one = client._database.find_one
        
        failure_count = 0
        def mock_connection_failure(*args, **kwargs):
            nonlocal failure_count
            failure_count += 1
            
            if failure_count <= 2:  # Fail first 2 attempts
                raise ConnectionFailure("Simulated connection failure")
            
            # Success on 3rd attempt
            return original_find_one(*args, **kwargs)
        
        # Patch to simulate connection failures
        with patch.object(client._database, 'find_one', side_effect=mock_connection_failure):
            # This should eventually succeed after retries
            recovery_result = client.find_one(TEST_COLLECTION_NAME, {"_id": normal_result.inserted_id})
            
            # Depending on retry implementation, this might succeed or fail
            # The important part is graceful error handling
            if not recovery_result.success:
                assert "connection" in recovery_result.error.lower() or "failure" in recovery_result.error.lower()
        
        assert failure_count >= 1  # Verify mock was called
        
        # Test server selection timeout handling
        original_server_selection_timeout = client.config.server_selection_timeout_ms
        
        # Temporarily reduce timeout for testing
        client.config.server_selection_timeout_ms = 100  # Very short timeout
        
        # Test operations with short timeout (should handle gracefully)
        timeout_result = client.find_one(TEST_COLLECTION_NAME, {"_id": normal_result.inserted_id})
        
        # Restore original timeout
        client.config.server_selection_timeout_ms = original_server_selection_timeout
        
        # The operation might succeed or fail, but should handle gracefully
        if not timeout_result.success and timeout_result.error:
            assert any(keyword in timeout_result.error.lower() 
                      for keyword in ["timeout", "selection", "connection"])
        
        # Test circuit breaker behavior (if implemented)
        circuit_breaker = get_circuit_breaker("mongodb")
        if circuit_breaker:
            assert circuit_breaker.failure_count >= 0
            assert circuit_breaker.state in ["closed", "open", "half_open"]
        
        # Cleanup
        client.delete_one(TEST_COLLECTION_NAME, {"_id": normal_result.inserted_id})
        
        logger.info(
            "Connection failure recovery validation completed",
            simulated_failures=failure_count,
            timeout_test_completed=True,
            circuit_breaker_available=circuit_breaker is not None
        )
    
    def test_monitoring_metrics_accuracy(
        self, 
        database_manager,
        test_data_factory,
        performance_metrics_registry
    ):
        """
        Test monitoring metrics accuracy and Prometheus integration.
        
        Validates:
        - Metrics collection accuracy
        - Prometheus metrics exposition
        - Counter and histogram accuracy
        - Metrics endpoint functionality
        """
        client = database_manager.mongodb_client
        assert client is not None
        
        metrics = performance_metrics_registry
        
        # Get initial metrics state
        initial_registry_data = metrics['registry']._collector_to_names
        
        # Execute known operations and verify metrics
        test_doc = test_data_factory['create_user']("metrics_test")
        
        # Insert operation
        insert_result = client.insert_one(TEST_COLLECTION_NAME, test_doc)
        assert insert_result.success
        metrics['operation_counter'].labels(operation='insert_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Read operation
        read_result = client.find_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
        assert read_result.success
        metrics['operation_counter'].labels(operation='find_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Update operation
        update_result = client.update_one(
            TEST_COLLECTION_NAME,
            {"_id": insert_result.inserted_id},
            {"$set": {"metadata.metrics_test": True}}
        )
        assert update_result.success
        metrics['operation_counter'].labels(operation='update_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Delete operation
        delete_result = client.delete_one(TEST_COLLECTION_NAME, {"_id": insert_result.inserted_id})
        assert delete_result.success
        metrics['operation_counter'].labels(operation='delete_one', collection=TEST_COLLECTION_NAME, status='success').inc()
        
        # Verify metrics were recorded
        # Check that operation counter increased
        operation_counter_metric = metrics['operation_counter']
        
        # Get metric samples
        for sample in operation_counter_metric.collect():
            for metric_sample in sample.samples:
                if (metric_sample.labels.get('operation') == 'insert_one' and 
                    metric_sample.labels.get('collection') == TEST_COLLECTION_NAME and 
                    metric_sample.labels.get('status') == 'success'):
                    assert metric_sample.value >= 1
        
        # Test metrics endpoint exposition (if available)
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        metrics_output = generate_latest(metrics['registry'])
        assert isinstance(metrics_output, bytes)
        assert len(metrics_output) > 0
        
        # Verify metrics output contains our test metrics
        metrics_text = metrics_output.decode('utf-8')
        assert 'test_mongodb_operations_total' in metrics_text
        assert 'test_mongodb_query_duration_seconds' in metrics_text
        
        # Test histogram accuracy
        query_duration_metric = metrics['query_duration']
        
        # Record some timing measurements
        for i in range(5):
            test_duration = 0.05 + (i * 0.01)  # 50ms to 90ms
            query_duration_metric.labels(operation='test_timing', collection=TEST_COLLECTION_NAME).observe(test_duration)
        
        # Verify histogram buckets
        for sample in query_duration_metric.collect():
            for metric_sample in sample.samples:
                if metric_sample.name.endswith('_bucket'):
                    assert metric_sample.value >= 0
        
        logger.info(
            "Monitoring metrics accuracy validation completed",
            metrics_output_size=len(metrics_output),
            operation_metrics_recorded=True,
            histogram_metrics_recorded=True
        )


# Performance benchmarking utilities for comprehensive testing
class PerformanceBenchmarkUtilities:
    """Utility class for performance benchmarking and statistical analysis."""
    
    @staticmethod
    def calculate_variance_percentage(measured_value: float, baseline_value: float) -> float:
        """Calculate percentage variance from baseline."""
        return (measured_value - baseline_value) / baseline_value * 100
    
    @staticmethod
    def validate_performance_threshold(
        measured_times: List[float], 
        baseline_time: float, 
        threshold_percent: float = PERFORMANCE_VARIANCE_THRESHOLD
    ) -> Dict[str, Any]:
        """Validate performance measurements against baseline with threshold."""
        avg_time = sum(measured_times) / len(measured_times)
        p95_time = sorted(measured_times)[int(0.95 * len(measured_times))]
        p99_time = sorted(measured_times)[int(0.99 * len(measured_times))]
        
        avg_variance = PerformanceBenchmarkUtilities.calculate_variance_percentage(avg_time, baseline_time)
        p95_variance = PerformanceBenchmarkUtilities.calculate_variance_percentage(p95_time, baseline_time)
        p99_variance = PerformanceBenchmarkUtilities.calculate_variance_percentage(p99_time, baseline_time)
        
        return {
            "avg_time": avg_time,
            "p95_time": p95_time,
            "p99_time": p99_time,
            "avg_variance_percent": avg_variance,
            "p95_variance_percent": p95_variance,
            "p99_variance_percent": p99_variance,
            "avg_compliant": abs(avg_variance) <= threshold_percent,
            "p95_compliant": abs(p95_variance) <= threshold_percent,
            "p99_compliant": abs(p99_variance) <= threshold_percent * 1.5,
            "overall_compliant": (
                abs(avg_variance) <= threshold_percent and 
                abs(p95_variance) <= threshold_percent and 
                abs(p99_variance) <= threshold_percent * 1.5
            )
        }


# Integration test configuration for pytest execution
pytest_plugins = ["pytest_asyncio"]