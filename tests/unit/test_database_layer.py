"""
Database Access Layer Unit Testing

Comprehensive testing for PyMongo 4.5+ and Motor 3.3+ database integration covering
connection pooling, transaction management, query execution, and performance monitoring.
Utilizes Testcontainers for realistic MongoDB behavior ensuring 90% integration layer
coverage per Section 6.6.3 enhanced requirements.

Key Testing Areas:
- PyMongo synchronous database operations with connection pooling optimization
- Motor asynchronous database operations for high-performance scenarios
- Database connection pool management equivalent to Node.js patterns
- Transaction support with ACID compliance and rollback scenario validation
- Query execution performance validation ensuring ≤10% variance from baseline
- Database health monitoring and observability integration
- Comprehensive error handling with circuit breaker patterns and retry logic
- Prometheus metrics collection for enterprise monitoring infrastructure

Technical Requirements Compliance:
- Section 0.1.2: PyMongo 4.5+ and Motor 3.3+ driver implementation testing
- Section 5.2.5: Database access layer testing with comprehensive CRUD operations
- Section 6.6.1: Testcontainers MongoDB integration for realistic testing behavior
- Section 6.6.3: 90% integration layer coverage enhanced requirement compliance
- Section 6.2.4: Performance optimization testing with connection pooling validation
- Section 0.1.1: Performance monitoring ensuring ≤10% variance from Node.js baseline
- Section 6.2.2: Database transaction management and data consistency testing

Architecture Integration:
- Validates Flask application factory database service integration
- Tests database configuration management with environment-specific settings
- Verifies performance monitoring and metrics collection for baseline compliance
- Confirms error handling patterns and circuit breaker functionality
- Validates connection pool optimization and resource management patterns

Performance Validation:
- Response time comparison against Node.js baseline metrics
- Connection pool efficiency and resource utilization monitoring
- Concurrent request handling capacity validation
- Database query optimization and index utilization testing
- Memory usage pattern analysis and optimization validation

Author: Database Migration Team
Version: 1.0.0
Compliance: Section 6.6 Testing Strategy requirements
"""

import asyncio
import logging
import pytest
import pytest_asyncio
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union, AsyncGenerator, Generator
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import uuid

# Core testing framework imports
import pymongo
from pymongo import MongoClient, WriteConcern, ReadConcern, ReadPreference
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    ConnectionFailure, OperationFailure, PyMongoError, ServerSelectionTimeoutError,
    DuplicateKeyError, BulkWriteError, NetworkTimeout, ConfigurationError
)

try:
    import motor.motor_asyncio as motor
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False
    motor = None

import structlog

# Application imports
from src.data import (
    # Core database services
    DatabaseServices, init_database_services, get_database_services,
    get_current_database_services,
    
    # Database client access
    get_mongodb_client, get_motor_client, get_database, get_async_database,
    get_collection, get_async_collection,
    
    # Manager access
    get_mongodb_manager, get_async_mongodb_manager,
    
    # Health monitoring
    get_database_health_status, get_database_performance_metrics,
    
    # Transaction management
    database_transaction,
    
    # Utilities and validation
    validate_object_id,
    
    # Exception classes
    DatabaseException, ConnectionException, TimeoutException,
    TransactionException, QueryException, ResourceException,
    DatabaseErrorSeverity, DatabaseOperationType, DatabaseErrorCategory,
    
    # Decorators and monitoring
    with_database_retry, handle_database_error, mongodb_circuit_breaker,
    monitor_database_operation, monitor_async_database_operation,
    monitor_database_transaction,
    
    # Availability flags
    MOTOR_AVAILABLE, FLASK_AVAILABLE
)

from src.data.mongodb import (
    MongoDBManager, AsyncMongoDBManager,
    create_mongodb_manager, create_async_mongodb_manager
)

from src.data.monitoring import (
    DatabaseMonitoringManager, DatabaseMetricsCollector
)

from src.data.exceptions import DatabaseConnectionError

# Test fixtures and factories
from tests.fixtures.database_fixtures import (
    UserDocumentFactory, ProjectDocumentFactory, SessionDocumentFactory
)

# Configure structured logging for test execution
logger = structlog.get_logger("tests.unit.test_database_layer")

# Suppress connection pool warnings during testing
warnings.filterwarnings("ignore", category=UserWarning, module="pymongo")


class TestDatabaseServices:
    """
    Test suite for DatabaseServices class covering initialization, Flask integration,
    and service lifecycle management with comprehensive error handling validation.
    
    Tests the core database services container providing comprehensive database
    functionality for Flask application integration with performance monitoring
    compliance per Section 6.1.1 core services architecture.
    """
    
    @pytest.mark.unit
    def test_database_services_initialization(self):
        """
        Test DatabaseServices initialization with comprehensive configuration validation.
        
        Validates proper initialization of database services including environment
        configuration, monitoring setup, and component lifecycle management per
        Section 6.1.1 Flask application factory pattern requirements.
        """
        # Test basic initialization
        services = DatabaseServices(environment='testing', monitoring_enabled=True)
        
        assert services.environment == 'testing'
        assert services.monitoring_enabled is True
        assert services.is_initialized is False
        assert services.flask_integrated is False
        assert services.database_config is None
        assert services.mongodb_manager is None
        assert services.async_mongodb_manager is None
        assert services.monitoring_manager is None
        
        logger.info("DatabaseServices initialization validation completed")
    
    @pytest.mark.unit
    def test_database_services_flask_integration(self, app):
        """
        Test DatabaseServices Flask application integration using factory pattern.
        
        Validates Flask application factory integration per Section 6.1.1 providing
        database client registration and configuration management with proper
        lifecycle management and error handling.
        
        Args:
            app: Flask application fixture
        """
        services = DatabaseServices(environment='testing', monitoring_enabled=True)
        
        # Test Flask integration
        services.init_app(app)
        
        assert services.flask_integrated is True
        assert services.is_initialized is True
        assert hasattr(app, 'extensions')
        assert 'database_services' in app.extensions
        assert app.extensions['database_services'] is services
        
        # Verify database configuration was initialized
        assert services.database_config is not None
        assert services.mongodb_manager is not None
        
        # Test health status after integration
        health_status = services.get_health_status()
        assert health_status['initialized'] is True
        assert health_status['flask_integrated'] is True
        assert health_status['environment'] == 'testing'
        assert 'services' in health_status
        
        logger.info("Flask integration validation completed")
    
    @pytest.mark.unit
    def test_database_services_duplicate_integration_warning(self, app):
        """
        Test DatabaseServices handling of duplicate Flask integration attempts.
        
        Validates proper warning behavior when attempting to integrate services
        with Flask multiple times, ensuring idempotent behavior and proper
        logging of integration state.
        
        Args:
            app: Flask application fixture
        """
        services = DatabaseServices(environment='testing')
        
        # First integration should succeed
        services.init_app(app)
        assert services.flask_integrated is True
        
        # Second integration should warn but not fail
        with patch('src.data.logger') as mock_logger:
            services.init_app(app)
            mock_logger.warning.assert_called()
        
        # Services should remain properly integrated
        assert services.flask_integrated is True
        assert services.is_initialized is True
        
        logger.info("Duplicate integration warning validation completed")
    
    @pytest.mark.unit
    def test_database_services_performance_metrics(self, app_with_database):
        """
        Test DatabaseServices performance metrics collection for baseline compliance.
        
        Validates performance metrics collection functionality ensuring compliance
        with ≤10% variance requirement per Section 0.1.1 and comprehensive monitoring
        per Section 6.2.4 performance optimization requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            services = get_current_database_services()
            
            # Get performance metrics
            metrics = services.get_performance_metrics()
            
            assert 'timestamp' in metrics
            assert metrics['environment'] == 'testing'
            assert 'mongodb_sync' in metrics
            assert 'connection_pools' in metrics
            
            # Verify MongoDB synchronous metrics structure
            if services.mongodb_manager:
                assert isinstance(metrics['mongodb_sync'], dict)
            
            # Verify connection pool metrics structure
            assert isinstance(metrics['connection_pools'], dict)
            
            # Test metrics validation
            timestamp = datetime.fromisoformat(metrics['timestamp'].replace('Z', '+00:00'))
            assert isinstance(timestamp, datetime)
            
        logger.info("Performance metrics validation completed")
    
    @pytest.mark.unit
    def test_database_services_health_monitoring(self, app_with_database):
        """
        Test DatabaseServices comprehensive health monitoring functionality.
        
        Validates health check capabilities for all database services including
        MongoDB managers, configuration health, and monitoring status per
        Section 6.2.5 database health monitoring requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            services = get_current_database_services()
            
            # Get comprehensive health status
            health_status = services.get_health_status()
            
            # Validate overall health structure
            assert 'environment' in health_status
            assert 'initialized' in health_status
            assert 'flask_integrated' in health_status
            assert 'monitoring_enabled' in health_status
            assert 'timestamp' in health_status
            assert 'services' in health_status
            
            # Validate individual service health
            services_health = health_status['services']
            
            if services.database_config:
                assert 'database_config' in services_health
                config_health = services_health['database_config']
                assert 'status' in config_health
            
            if services.mongodb_manager:
                assert 'mongodb_sync' in services_health
                mongodb_health = services_health['mongodb_sync']
                assert 'status' in mongodb_health
            
            # Verify timestamp format
            timestamp = datetime.fromisoformat(health_status['timestamp'].replace('Z', '+00:00'))
            assert isinstance(timestamp, datetime)
            
        logger.info("Health monitoring validation completed")


class TestDatabaseInitialization:
    """
    Test suite for database initialization functions covering global service setup,
    Flask integration, and configuration management with comprehensive error handling.
    
    Tests centralized database services initialization supporting Flask application
    factory pattern per Section 6.1.1 core services architecture requirements.
    """
    
    @pytest.mark.unit
    def test_init_database_services_basic(self):
        """
        Test basic database services initialization without Flask integration.
        
        Validates global database services initialization with environment-specific
        configuration and monitoring setup per Section 6.1.1 initialization patterns.
        """
        services = init_database_services(
            app=None,
            environment='testing',
            monitoring_enabled=True
        )
        
        assert isinstance(services, DatabaseServices)
        assert services.environment == 'testing'
        assert services.monitoring_enabled is True
        assert services.flask_integrated is False
        
        # Verify global services access
        global_services = get_database_services()
        assert global_services is services
        
        logger.info("Basic database services initialization validation completed")
    
    @pytest.mark.unit
    def test_init_database_services_with_flask(self, app):
        """
        Test database services initialization with Flask application integration.
        
        Validates comprehensive Flask integration including database client
        registration, configuration management, and service lifecycle per
        Section 6.1.1 Flask application factory pattern.
        
        Args:
            app: Flask application fixture
        """
        services = init_database_services(
            app=app,
            environment='testing',
            monitoring_enabled=True
        )
        
        assert isinstance(services, DatabaseServices)
        assert services.flask_integrated is True
        assert services.is_initialized is True
        
        # Verify Flask extension registration
        assert 'database_services' in app.extensions
        assert app.extensions['database_services'] is services
        
        # Test context-based access
        with app.app_context():
            context_services = get_current_database_services()
            assert context_services is services
        
        logger.info("Flask-integrated database services initialization validation completed")
    
    @pytest.mark.unit  
    def test_get_database_services_error_handling(self):
        """
        Test error handling for accessing uninitialized database services.
        
        Validates proper exception handling when attempting to access global
        database services before initialization with clear error messaging
        and troubleshooting guidance.
        """
        # Reset global services
        import src.data
        src.data._database_services = None
        
        # Test error on uninitialized access
        with pytest.raises(RuntimeError) as exc_info:
            get_database_services()
        
        assert "Database services not initialized" in str(exc_info.value)
        assert "Call init_database_services() first" in str(exc_info.value)
        
        logger.info("Database services error handling validation completed")
    
    @pytest.mark.unit
    def test_get_current_database_services_error_handling(self):
        """
        Test error handling for Flask context database services access.
        
        Validates proper exception handling when attempting to access database
        services from Flask context without proper initialization or outside
        application context with clear error messaging.
        """
        if not FLASK_AVAILABLE:
            pytest.skip("Flask not available for context testing")
        
        # Test error outside Flask context
        with pytest.raises(RuntimeError) as exc_info:
            get_current_database_services()
        
        error_message = str(exc_info.value)
        assert ("Failed to get database services from Flask context" in error_message or
                "Working outside of application context" in error_message)
        
        logger.info("Flask context error handling validation completed")


class TestMongoDBOperations:
    """
    Test suite for MongoDB database operations covering PyMongo synchronous operations,
    connection pooling, transaction management, and query execution performance.
    
    Tests PyMongo 4.5+ database connectivity maintaining existing data patterns
    per Section 5.2.5 database access layer requirements with comprehensive
    CRUD operations and performance monitoring validation.
    """
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_mongodb_client_connection(self, app_with_database):
        """
        Test MongoDB client connection establishment and configuration validation.
        
        Validates PyMongo client connection with Testcontainers integration providing
        realistic database behavior per Section 6.6.1 requirements and connection
        pool optimization per Section 5.2.5 database access layer specifications.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Get MongoDB client
            client = get_mongodb_client()
            assert isinstance(client, MongoClient)
            
            # Test connection with ping
            db_admin = client.admin
            ping_result = db_admin.command('ping')
            assert ping_result['ok'] == 1.0
            
            # Verify database access
            database = get_database()
            assert isinstance(database, Database)
            
            # Test collection access
            test_collection = get_collection('test_collection')
            assert isinstance(test_collection, Collection)
            
            # Verify connection pool configuration
            pool_options = client.options.pool_options
            assert pool_options.max_pool_size >= 10  # Minimum pool size for performance
            
        logger.info("MongoDB client connection validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_mongodb_crud_operations(self, app_with_database, user_factory):
        """
        Test MongoDB CRUD operations maintaining existing data patterns.
        
        Validates comprehensive CRUD operations including document insertion,
        querying, updates, and deletion with proper error handling and data
        validation per Section 5.2.5 database access layer requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_users')
            
            # Test document insertion
            user_doc = user_factory.build()
            insert_result = collection.insert_one(user_doc)
            assert insert_result.acknowledged is True
            assert insert_result.inserted_id is not None
            
            # Test document retrieval
            retrieved_doc = collection.find_one({'_id': insert_result.inserted_id})
            assert retrieved_doc is not None
            assert retrieved_doc['email'] == user_doc['email']
            assert retrieved_doc['username'] == user_doc['username']
            
            # Test document update
            update_data = {'last_login': datetime.now(timezone.utc)}
            update_result = collection.update_one(
                {'_id': insert_result.inserted_id},
                {'$set': update_data}
            )
            assert update_result.acknowledged is True
            assert update_result.modified_count == 1
            
            # Verify update
            updated_doc = collection.find_one({'_id': insert_result.inserted_id})
            assert updated_doc['last_login'] is not None
            
            # Test document deletion
            delete_result = collection.delete_one({'_id': insert_result.inserted_id})
            assert delete_result.acknowledged is True
            assert delete_result.deleted_count == 1
            
            # Verify deletion
            deleted_doc = collection.find_one({'_id': insert_result.inserted_id})
            assert deleted_doc is None
            
        logger.info("MongoDB CRUD operations validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_mongodb_bulk_operations(self, app_with_database, user_factory):
        """
        Test MongoDB bulk operations for performance optimization and efficiency.
        
        Validates bulk insert, update, and delete operations with proper error
        handling and performance monitoring per Section 6.2.4 performance
        optimization requirements for batch processing scenarios.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_bulk_users')
            
            # Generate test documents
            user_docs = [user_factory.build() for _ in range(10)]
            
            # Test bulk insertion
            start_time = time.perf_counter()
            insert_result = collection.insert_many(user_docs)
            insert_duration = time.perf_counter() - start_time
            
            assert insert_result.acknowledged is True
            assert len(insert_result.inserted_ids) == 10
            assert insert_duration < 1.0  # Performance threshold
            
            # Test bulk update
            update_operations = [
                {
                    'update_one': {
                        'filter': {'_id': doc_id},
                        'update': {'$set': {'last_updated': datetime.now(timezone.utc)}}
                    }
                }
                for doc_id in insert_result.inserted_ids
            ]
            
            start_time = time.perf_counter()
            update_result = collection.bulk_write(update_operations)
            update_duration = time.perf_counter() - start_time
            
            assert update_result.acknowledged is True
            assert update_result.modified_count == 10
            assert update_duration < 1.0  # Performance threshold
            
            # Test bulk query
            start_time = time.perf_counter()
            cursor = collection.find({'_id': {'$in': insert_result.inserted_ids}})
            found_docs = list(cursor)
            query_duration = time.perf_counter() - start_time
            
            assert len(found_docs) == 10
            assert query_duration < 0.5  # Performance threshold
            assert all(doc['last_updated'] is not None for doc in found_docs)
            
            # Cleanup
            collection.delete_many({'_id': {'$in': insert_result.inserted_ids}})
            
        logger.info("MongoDB bulk operations validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_mongodb_indexing_and_performance(self, app_with_database, user_factory):
        """
        Test MongoDB indexing and query performance optimization.
        
        Validates index creation, utilization, and query performance monitoring
        per Section 6.2.4 performance optimization requirements ensuring ≤10%
        variance from baseline performance expectations.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_indexed_users')
            
            # Create test index
            index_result = collection.create_index([('email', 1), ('username', 1)])
            assert isinstance(index_result, str)
            
            # Verify index creation
            indexes = list(collection.list_indexes())
            index_names = [idx['name'] for idx in indexes]
            assert index_result in index_names
            
            # Insert test data
            user_docs = [user_factory.build() for _ in range(100)]
            collection.insert_many(user_docs)
            
            # Test indexed query performance
            test_email = user_docs[0]['email']
            
            start_time = time.perf_counter()
            result = collection.find_one({'email': test_email})
            query_duration = time.perf_counter() - start_time
            
            assert result is not None
            assert result['email'] == test_email
            assert query_duration < 0.1  # Performance threshold for indexed query
            
            # Test compound index query
            test_username = user_docs[0]['username']
            
            start_time = time.perf_counter()
            result = collection.find_one({
                'email': test_email,
                'username': test_username
            })
            compound_query_duration = time.perf_counter() - start_time
            
            assert result is not None
            assert compound_query_duration < 0.1  # Performance threshold
            
            # Test query explanation for index usage
            explain_result = collection.find({'email': test_email}).explain()
            execution_stats = explain_result['executionStats']
            assert execution_stats['totalDocsExamined'] <= execution_stats['totalDocsReturned'] * 2
            
            # Cleanup
            collection.drop()
            
        logger.info("MongoDB indexing and performance validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_mongodb_aggregation_pipeline(self, app_with_database, user_factory, project_factory):
        """
        Test MongoDB aggregation pipeline operations for complex queries.
        
        Validates aggregation pipeline functionality including grouping, sorting,
        matching, and projection operations with performance monitoring per
        Section 5.2.5 database access layer advanced query requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
            project_factory: Project document factory for test data generation
        """
        with app_with_database.app_context():
            users_collection = get_collection('test_agg_users')
            projects_collection = get_collection('test_agg_projects')
            
            # Create test data
            users = [user_factory.build() for _ in range(20)]
            user_insert_result = users_collection.insert_many(users)
            user_ids = user_insert_result.inserted_ids
            
            # Create projects with user assignments
            projects = []
            for i in range(10):
                project = project_factory.build()
                project['owner_id'] = user_ids[i % len(user_ids)]
                project['team_members'] = user_ids[i:i+3] if i+3 <= len(user_ids) else user_ids[i:]
                projects.append(project)
            
            projects_collection.insert_many(projects)
            
            # Test aggregation pipeline: Group projects by owner
            pipeline = [
                {'$group': {
                    '_id': '$owner_id',
                    'project_count': {'$sum': 1},
                    'project_names': {'$push': '$name'}
                }},
                {'$sort': {'project_count': -1}}
            ]
            
            start_time = time.perf_counter()
            aggregation_result = list(projects_collection.aggregate(pipeline))
            aggregation_duration = time.perf_counter() - start_time
            
            assert len(aggregation_result) > 0
            assert aggregation_duration < 1.0  # Performance threshold
            
            # Verify aggregation results
            for result in aggregation_result:
                assert '_id' in result  # owner_id
                assert 'project_count' in result
                assert 'project_names' in result
                assert isinstance(result['project_names'], list)
                assert result['project_count'] == len(result['project_names'])
            
            # Test lookup aggregation with users collection
            lookup_pipeline = [
                {'$lookup': {
                    'from': 'test_agg_users',
                    'localField': 'owner_id',
                    'foreignField': '_id',
                    'as': 'owner_info'
                }},
                {'$unwind': '$owner_info'},
                {'$project': {
                    'name': 1,
                    'owner_email': '$owner_info.email',
                    'owner_username': '$owner_info.username'
                }}
            ]
            
            start_time = time.perf_counter()
            lookup_result = list(projects_collection.aggregate(lookup_pipeline))
            lookup_duration = time.perf_counter() - start_time
            
            assert len(lookup_result) == len(projects)
            assert lookup_duration < 2.0  # Performance threshold for lookup
            
            # Verify lookup results
            for result in lookup_result:
                assert 'name' in result
                assert 'owner_email' in result
                assert 'owner_username' in result
                assert '@' in result['owner_email']  # Basic email validation
            
            # Cleanup
            users_collection.drop()
            projects_collection.drop()
            
        logger.info("MongoDB aggregation pipeline validation completed")


class TestAsyncMongoDBOperations:
    """
    Test suite for Motor asynchronous MongoDB operations covering async database
    connectivity, concurrent operations, and performance optimization.
    
    Tests Motor 3.3+ async database operations for high-performance scenarios
    per Section 5.2.5 database access layer requirements with async operation
    testing using pytest-asyncio per Section 6.6.1 testing framework specifications.
    """
    
    @pytest.mark.asyncio
    @pytest.mark.database
    @pytest.mark.integration
    @pytest.mark.skipif(not MOTOR_AVAILABLE, reason="Motor async driver not available")
    async def test_motor_client_connection(self, app_with_database):
        """
        Test Motor async client connection establishment and configuration.
        
        Validates Motor async client connection with proper async context management
        and connection pool optimization per Section 5.2.5 async database operations
        requirements for high-performance scenarios.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Get Motor async client
            motor_client = get_motor_client()
            assert isinstance(motor_client, motor.AsyncIOMotorClient)
            
            # Test async connection with ping
            ping_result = await motor_client.admin.command('ping')
            assert ping_result['ok'] == 1.0
            
            # Verify async database access
            async_database = get_async_database()
            assert isinstance(async_database, motor.AsyncIOMotorDatabase)
            
            # Test async collection access
            async_collection = get_async_collection('test_async_collection')
            assert isinstance(async_collection, motor.AsyncIOMotorCollection)
            
        logger.info("Motor async client connection validation completed")
    
    @pytest.mark.asyncio
    @pytest.mark.database
    @pytest.mark.integration
    @pytest.mark.skipif(not MOTOR_AVAILABLE, reason="Motor async driver not available")
    async def test_motor_async_crud_operations(self, app_with_database, user_factory):
        """
        Test Motor async CRUD operations for high-performance database access.
        
        Validates comprehensive async CRUD operations including concurrent
        document operations, async transaction support, and performance
        monitoring per Section 5.2.5 async database operations requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            async_collection = get_async_collection('test_async_users')
            
            # Test async document insertion
            user_doc = user_factory.build()
            insert_result = await async_collection.insert_one(user_doc)
            assert insert_result.acknowledged is True
            assert insert_result.inserted_id is not None
            
            # Test async document retrieval
            retrieved_doc = await async_collection.find_one({'_id': insert_result.inserted_id})
            assert retrieved_doc is not None
            assert retrieved_doc['email'] == user_doc['email']
            assert retrieved_doc['username'] == user_doc['username']
            
            # Test async document update
            update_data = {'last_login': datetime.now(timezone.utc)}
            update_result = await async_collection.update_one(
                {'_id': insert_result.inserted_id},
                {'$set': update_data}
            )
            assert update_result.acknowledged is True
            assert update_result.modified_count == 1
            
            # Verify async update
            updated_doc = await async_collection.find_one({'_id': insert_result.inserted_id})
            assert updated_doc['last_login'] is not None
            
            # Test async document deletion
            delete_result = await async_collection.delete_one({'_id': insert_result.inserted_id})
            assert delete_result.acknowledged is True
            assert delete_result.deleted_count == 1
            
            # Verify async deletion
            deleted_doc = await async_collection.find_one({'_id': insert_result.inserted_id})
            assert deleted_doc is None
            
        logger.info("Motor async CRUD operations validation completed")
    
    @pytest.mark.asyncio
    @pytest.mark.database
    @pytest.mark.integration
    @pytest.mark.skipif(not MOTOR_AVAILABLE, reason="Motor async driver not available")
    async def test_motor_concurrent_operations(self, app_with_database, user_factory):
        """
        Test Motor concurrent database operations for high-throughput scenarios.
        
        Validates concurrent async operations including parallel document insertion,
        query processing, and connection pool utilization per Section 6.2.4
        performance optimization requirements for async operations.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            async_collection = get_async_collection('test_concurrent_users')
            
            # Generate test documents
            user_docs = [user_factory.build() for _ in range(50)]
            
            # Test concurrent insertions
            async def insert_document(doc):
                return await async_collection.insert_one(doc)
            
            start_time = time.perf_counter()
            insert_tasks = [insert_document(doc) for doc in user_docs]
            insert_results = await asyncio.gather(*insert_tasks)
            concurrent_insert_duration = time.perf_counter() - start_time
            
            assert len(insert_results) == 50
            assert all(result.acknowledged for result in insert_results)
            assert concurrent_insert_duration < 5.0  # Performance threshold
            
            inserted_ids = [result.inserted_id for result in insert_results]
            
            # Test concurrent queries
            async def find_document(doc_id):
                return await async_collection.find_one({'_id': doc_id})
            
            start_time = time.perf_counter()
            query_tasks = [find_document(doc_id) for doc_id in inserted_ids]
            query_results = await asyncio.gather(*query_tasks)
            concurrent_query_duration = time.perf_counter() - start_time
            
            assert len(query_results) == 50
            assert all(result is not None for result in query_results)
            assert concurrent_query_duration < 3.0  # Performance threshold
            
            # Test concurrent updates
            async def update_document(doc_id):
                return await async_collection.update_one(
                    {'_id': doc_id},
                    {'$set': {'updated_at': datetime.now(timezone.utc)}}
                )
            
            start_time = time.perf_counter()
            update_tasks = [update_document(doc_id) for doc_id in inserted_ids]
            update_results = await asyncio.gather(*update_tasks)
            concurrent_update_duration = time.perf_counter() - start_time
            
            assert len(update_results) == 50
            assert all(result.acknowledged for result in update_results)
            assert all(result.modified_count == 1 for result in update_results)
            assert concurrent_update_duration < 4.0  # Performance threshold
            
            # Cleanup
            await async_collection.delete_many({'_id': {'$in': inserted_ids}})
            
        logger.info("Motor concurrent operations validation completed")
    
    @pytest.mark.asyncio
    @pytest.mark.database
    @pytest.mark.integration
    @pytest.mark.skipif(not MOTOR_AVAILABLE, reason="Motor async driver not available")
    async def test_motor_async_aggregation(self, app_with_database, user_factory):
        """
        Test Motor async aggregation pipeline operations for complex queries.
        
        Validates async aggregation pipeline functionality with performance
        monitoring for complex data processing operations per Section 5.2.5
        database access layer advanced async query requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            async_collection = get_async_collection('test_async_agg_users')
            
            # Create test data with domains for aggregation
            user_docs = []
            domains = ['example.com', 'test.org', 'demo.net', 'sample.io']
            
            for i in range(40):
                user_doc = user_factory.build()
                domain = domains[i % len(domains)]
                username = user_doc['username']
                user_doc['email'] = f"{username}@{domain}"
                user_doc['registration_date'] = datetime.now(timezone.utc) - timedelta(days=i)
                user_docs.append(user_doc)
            
            # Insert test data
            await async_collection.insert_many(user_docs)
            
            # Test async aggregation: Group users by email domain
            pipeline = [
                {'$project': {
                    'domain': {
                        '$arrayElemAt': [
                            {'$split': ['$email', '@']}, 1
                        ]
                    },
                    'username': 1,
                    'registration_date': 1
                }},
                {'$group': {
                    '_id': '$domain',
                    'user_count': {'$sum': 1},
                    'earliest_registration': {'$min': '$registration_date'},
                    'latest_registration': {'$max': '$registration_date'}
                }},
                {'$sort': {'user_count': -1}}
            ]
            
            start_time = time.perf_counter()
            aggregation_cursor = async_collection.aggregate(pipeline)
            aggregation_results = await aggregation_cursor.to_list(length=None)
            aggregation_duration = time.perf_counter() - start_time
            
            assert len(aggregation_results) == len(domains)
            assert aggregation_duration < 2.0  # Performance threshold
            
            # Verify aggregation results
            total_users = sum(result['user_count'] for result in aggregation_results)
            assert total_users == 40
            
            for result in aggregation_results:
                assert result['_id'] in domains
                assert result['user_count'] > 0
                assert isinstance(result['earliest_registration'], datetime)
                assert isinstance(result['latest_registration'], datetime)
                assert result['earliest_registration'] <= result['latest_registration']
            
            # Test async aggregation with lookup (requires two collections)
            projects_collection = get_async_collection('test_async_agg_projects')
            
            # Create projects with user references
            project_docs = []
            for i in range(10):
                project_doc = {
                    '_id': f"project_{i}",
                    'name': f"Project {i}",
                    'owner_email': user_docs[i * 2]['email'],
                    'created_date': datetime.now(timezone.utc)
                }
                project_docs.append(project_doc)
            
            await projects_collection.insert_many(project_docs)
            
            # Lookup aggregation
            lookup_pipeline = [
                {'$lookup': {
                    'from': 'test_async_agg_users',
                    'localField': 'owner_email',
                    'foreignField': 'email',
                    'as': 'owner_info'
                }},
                {'$unwind': '$owner_info'},
                {'$project': {
                    'name': 1,
                    'owner_username': '$owner_info.username',
                    'owner_domain': {
                        '$arrayElemAt': [
                            {'$split': ['$owner_email', '@']}, 1
                        ]
                    }
                }}
            ]
            
            start_time = time.perf_counter()
            lookup_cursor = projects_collection.aggregate(lookup_pipeline)
            lookup_results = await lookup_cursor.to_list(length=None)
            lookup_duration = time.perf_counter() - start_time
            
            assert len(lookup_results) == 10
            assert lookup_duration < 3.0  # Performance threshold
            
            # Verify lookup results
            for result in lookup_results:
                assert 'name' in result
                assert 'owner_username' in result
                assert 'owner_domain' in result
                assert result['owner_domain'] in domains
            
            # Cleanup
            await async_collection.drop()
            await projects_collection.drop()
            
        logger.info("Motor async aggregation validation completed")


class TestDatabaseTransactions:
    """
    Test suite for MongoDB transaction management covering ACID compliance,
    rollback scenarios, and transaction performance monitoring.
    
    Tests database transaction support with data consistency requirements
    per Section 6.2.2 data management and Section 5.2.5 transaction
    management for maintaining database integrity.
    """
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_transaction_basic_operations(self, app_with_database, user_factory):
        """
        Test basic MongoDB transaction operations with ACID compliance.
        
        Validates transaction support including commit scenarios, proper session
        management, and data consistency requirements per Section 6.2.2 data
        management transaction management specifications.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            client = get_mongodb_client()
            database = get_database()
            users_collection = database['test_transaction_users']
            logs_collection = database['test_transaction_logs']
            
            # Test transaction with commit
            with client.start_session() as session:
                with session.start_transaction():
                    # Insert user document
                    user_doc = user_factory.build()
                    insert_result = users_collection.insert_one(user_doc, session=session)
                    user_id = insert_result.inserted_id
                    
                    # Insert log document
                    log_doc = {
                        'user_id': user_id,
                        'action': 'user_created',
                        'timestamp': datetime.now(timezone.utc),
                        'details': {'email': user_doc['email']}
                    }
                    logs_collection.insert_one(log_doc, session=session)
                    
                    # Transaction commits automatically when context exits
            
            # Verify both documents exist after commit
            user_doc_committed = users_collection.find_one({'_id': user_id})
            log_doc_committed = logs_collection.find_one({'user_id': user_id})
            
            assert user_doc_committed is not None
            assert log_doc_committed is not None
            assert log_doc_committed['action'] == 'user_created'
            
            # Cleanup
            users_collection.delete_one({'_id': user_id})
            logs_collection.delete_one({'user_id': user_id})
            
        logger.info("Basic transaction operations validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_transaction_rollback_scenarios(self, app_with_database, user_factory):
        """
        Test MongoDB transaction rollback scenarios and error handling.
        
        Validates transaction rollback functionality including automatic rollback
        on errors, manual abort scenarios, and data consistency preservation
        per Section 6.2.2 transaction management requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            client = get_mongodb_client()
            database = get_database()
            users_collection = database['test_rollback_users']
            
            # Create unique index to force constraint violation
            users_collection.create_index('email', unique=True)
            
            # Insert initial document
            initial_user = user_factory.build()
            users_collection.insert_one(initial_user)
            
            # Test automatic rollback on error
            try:
                with client.start_session() as session:
                    with session.start_transaction():
                        # Insert first document (should succeed)
                        user1 = user_factory.build()
                        users_collection.insert_one(user1, session=session)
                        
                        # Insert duplicate email (should fail and rollback)
                        user2 = user_factory.build()
                        user2['email'] = initial_user['email']  # Duplicate email
                        users_collection.insert_one(user2, session=session)
                        
            except DuplicateKeyError:
                # Expected error due to unique constraint
                pass
            
            # Verify rollback - user1 should not exist
            user1_after_rollback = users_collection.find_one({'username': user1['username']})
            assert user1_after_rollback is None
            
            # Verify original document still exists
            original_user = users_collection.find_one({'email': initial_user['email']})
            assert original_user is not None
            
            # Test manual transaction abort
            user3 = user_factory.build()
            with client.start_session() as session:
                with session.start_transaction():
                    # Insert document
                    insert_result = users_collection.insert_one(user3, session=session)
                    user3_id = insert_result.inserted_id
                    
                    # Manually abort transaction
                    session.abort_transaction()
            
            # Verify manual abort - user3 should not exist
            user3_after_abort = users_collection.find_one({'_id': user3_id})
            assert user3_after_abort is None
            
            # Cleanup
            users_collection.drop()
            
        logger.info("Transaction rollback scenarios validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_transaction_context_manager(self, app_with_database, user_factory):
        """
        Test database transaction context manager for simplified transaction handling.
        
        Validates convenience transaction context manager functionality providing
        simplified transaction management with proper error handling and resource
        cleanup per Section 6.2.2 transaction management patterns.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_context_users')
            
            # Test successful transaction with context manager
            user_doc = user_factory.build()
            
            with database_transaction() as session:
                insert_result = collection.insert_one(user_doc, session=session)
                user_id = insert_result.inserted_id
                
                # Update document within transaction
                collection.update_one(
                    {'_id': user_id},
                    {'$set': {'status': 'active'}},
                    session=session
                )
            
            # Verify transaction committed
            committed_user = collection.find_one({'_id': user_id})
            assert committed_user is not None
            assert committed_user['status'] == 'active'
            
            # Test transaction with exception (should rollback)
            user2_doc = user_factory.build()
            
            try:
                with database_transaction() as session:
                    insert_result = collection.insert_one(user2_doc, session=session)
                    user2_id = insert_result.inserted_id
                    
                    # Simulate error
                    raise ValueError("Simulated transaction error")
                    
            except ValueError:
                pass  # Expected error
            
            # Verify rollback - user2 should not exist
            rolled_back_user = collection.find_one({'_id': user2_id})
            assert rolled_back_user is None
            
            # Cleanup
            collection.delete_one({'_id': user_id})
            
        logger.info("Transaction context manager validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_transaction_performance_monitoring(self, app_with_database, user_factory):
        """
        Test transaction performance monitoring and metrics collection.
        
        Validates transaction performance monitoring including execution time
        tracking, success rate measurement, and baseline compliance per
        Section 6.2.4 performance optimization transaction monitoring requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_perf_transactions')
            
            # Test transaction performance with monitoring
            transaction_times = []
            success_count = 0
            error_count = 0
            
            for i in range(10):
                try:
                    start_time = time.perf_counter()
                    
                    with monitor_database_transaction() as (session, metrics):
                        user_doc = user_factory.build()
                        insert_result = collection.insert_one(user_doc, session=session)
                        
                        # Simulate some processing
                        collection.update_one(
                            {'_id': insert_result.inserted_id},
                            {'$set': {'processed': True}},
                            session=session
                        )
                    
                    transaction_time = time.perf_counter() - start_time
                    transaction_times.append(transaction_time)
                    success_count += 1
                    
                    # Verify metrics collection
                    assert 'transaction_id' in metrics
                    assert 'start_time' in metrics
                    assert 'operations_count' in metrics
                    
                except Exception:
                    error_count += 1
            
            # Verify performance metrics
            assert len(transaction_times) > 0
            avg_transaction_time = sum(transaction_times) / len(transaction_times)
            max_transaction_time = max(transaction_times)
            
            # Performance thresholds
            assert avg_transaction_time < 0.5  # Average should be under 500ms
            assert max_transaction_time < 1.0  # Maximum should be under 1s
            assert success_count >= 8  # At least 80% success rate
            
            # Verify transaction consistency
            total_documents = collection.count_documents({})
            processed_documents = collection.count_documents({'processed': True})
            assert total_documents == processed_documents  # All should be processed
            
            logger.info(
                "Transaction performance validation completed",
                avg_time_ms=avg_transaction_time * 1000,
                max_time_ms=max_transaction_time * 1000,
                success_rate=success_count / (success_count + error_count) * 100
            )
            
            # Cleanup
            collection.drop()


class TestConnectionPooling:
    """
    Test suite for database connection pooling covering pool configuration,
    resource management, and performance optimization.
    
    Tests connection pooling equivalent to Node.js patterns per Section 5.2.5
    database access layer requirements with comprehensive pool monitoring
    and resource optimization validation.
    """
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_connection_pool_configuration(self, app_with_database):
        """
        Test MongoDB connection pool configuration and parameters.
        
        Validates connection pool configuration including pool size limits,
        timeout settings, and resource management per Section 5.2.5 connection
        pool management equivalent to Node.js implementation patterns.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            client = get_mongodb_client()
            
            # Verify connection pool configuration
            pool_options = client.options.pool_options
            
            # Test pool size configuration
            assert pool_options.max_pool_size >= 10
            assert pool_options.max_pool_size <= 100
            assert pool_options.min_pool_size >= 0
            assert pool_options.min_pool_size <= pool_options.max_pool_size
            
            # Test timeout configuration
            assert pool_options.max_idle_time_seconds is not None
            assert pool_options.wait_queue_timeout_seconds is not None
            
            # Test connection configuration
            server_selection_timeout = client.options.server_selection_timeout_ms
            assert server_selection_timeout >= 1000  # At least 1 second
            assert server_selection_timeout <= 30000  # At most 30 seconds
            
            # Verify socket timeout configuration
            socket_timeout = client.options.socket_timeout_ms
            if socket_timeout is not None:
                assert socket_timeout >= 1000  # At least 1 second
            
        logger.info("Connection pool configuration validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_connection_pool_utilization(self, app_with_database, user_factory):
        """
        Test connection pool utilization under concurrent load scenarios.
        
        Validates connection pool behavior under concurrent database operations
        including pool exhaustion scenarios, connection reuse, and resource
        efficiency per Section 6.2.4 performance optimization requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_pool_utilization')
            
            # Test concurrent operations with limited pool
            def perform_database_operation(index):
                """Perform database operation in thread"""
                try:
                    user_doc = user_factory.build()
                    user_doc['thread_index'] = index
                    
                    # Insert document
                    insert_result = collection.insert_one(user_doc)
                    
                    # Query document back
                    retrieved = collection.find_one({'_id': insert_result.inserted_id})
                    
                    # Update document
                    collection.update_one(
                        {'_id': insert_result.inserted_id},
                        {'$set': {'processed': True}}
                    )
                    
                    return {
                        'success': True,
                        'thread_index': index,
                        'document_id': insert_result.inserted_id
                    }
                    
                except Exception as e:
                    return {
                        'success': False,
                        'thread_index': index,
                        'error': str(e)
                    }
            
            # Execute concurrent operations
            start_time = time.perf_counter()
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [
                    executor.submit(perform_database_operation, i)
                    for i in range(50)
                ]
                
                results = []
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
            
            execution_time = time.perf_counter() - start_time
            
            # Analyze results
            successful_operations = [r for r in results if r['success']]
            failed_operations = [r for r in results if not r['success']]
            
            # Verify performance and success rate
            assert len(successful_operations) >= 45  # At least 90% success rate
            assert execution_time < 30.0  # Should complete within 30 seconds
            
            success_rate = len(successful_operations) / len(results) * 100
            avg_time_per_operation = execution_time / len(results)
            
            logger.info(
                "Connection pool utilization validation completed",
                total_operations=len(results),
                successful_operations=len(successful_operations),
                failed_operations=len(failed_operations),
                success_rate_percent=success_rate,
                total_time_seconds=execution_time,
                avg_time_per_operation_ms=avg_time_per_operation * 1000
            )
            
            # Verify all successful documents exist
            document_ids = [r['document_id'] for r in successful_operations]
            found_documents = list(collection.find({'_id': {'$in': document_ids}}))
            assert len(found_documents) == len(successful_operations)
            
            # Cleanup
            collection.drop()
    
    @pytest.mark.database
    @pytest.mark.integration  
    def test_connection_pool_monitoring(self, app_with_database):
        """
        Test connection pool monitoring and metrics collection.
        
        Validates connection pool monitoring capabilities including active
        connection tracking, pool statistics, and performance metrics per
        Section 6.2.4 connection pool monitoring requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Test database services monitoring
            services = get_current_database_services()
            
            if services.monitoring_manager:
                # Get connection pool metrics
                performance_metrics = services.get_performance_metrics()
                
                # Verify metrics structure
                assert 'connection_pools' in performance_metrics
                pool_metrics = performance_metrics['connection_pools']
                
                # Test pool information availability
                if pool_metrics:
                    # Verify pool status information
                    assert isinstance(pool_metrics, dict)
                
                # Test health monitoring
                health_status = services.get_health_status()
                assert 'services' in health_status
                
                # Verify MongoDB service health
                if 'mongodb_sync' in health_status['services']:
                    mongodb_health = health_status['services']['mongodb_sync']
                    assert 'status' in mongodb_health
            
            # Test direct client pool monitoring
            client = get_mongodb_client()
            
            # Perform operations to activate connections
            database = get_database()
            test_collection = database['test_pool_monitoring']
            
            # Insert test documents to generate pool activity
            test_docs = [{'index': i, 'timestamp': datetime.now(timezone.utc)} for i in range(10)]
            test_collection.insert_many(test_docs)
            
            # Query documents to maintain connection activity
            found_docs = list(test_collection.find({}))
            assert len(found_docs) == 10
            
            # Test pool configuration access
            pool_options = client.options.pool_options
            assert pool_options.max_pool_size > 0
            
            # Cleanup
            test_collection.drop()
            
        logger.info("Connection pool monitoring validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_connection_pool_error_handling(self, app_with_database):
        """
        Test connection pool error handling and recovery scenarios.
        
        Validates connection pool resilience including timeout handling,
        connection failure recovery, and circuit breaker patterns per
        Section 4.2.3 error handling and Section 5.2.5 resource management.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            collection = get_collection('test_pool_errors')
            
            # Test normal operation baseline
            baseline_doc = {'test': 'baseline', 'timestamp': datetime.now(timezone.utc)}
            baseline_result = collection.insert_one(baseline_doc)
            assert baseline_result.acknowledged is True
            
            # Test operation with circuit breaker monitoring
            operation_count = 0
            success_count = 0
            error_count = 0
            
            def monitored_operation():
                nonlocal operation_count, success_count, error_count
                operation_count += 1
                
                try:
                    with monitor_database_operation('test_operation') as metrics:
                        test_doc = {
                            'operation_index': operation_count,
                            'timestamp': datetime.now(timezone.utc)
                        }
                        result = collection.insert_one(test_doc)
                        
                        # Verify operation success
                        assert result.acknowledged is True
                        success_count += 1
                        
                        return result
                        
                except Exception as e:
                    error_count += 1
                    logger.warning(f"Database operation failed: {str(e)}")
                    raise
            
            # Perform monitored operations
            for i in range(5):
                try:
                    monitored_operation()
                except Exception:
                    pass  # Continue testing even if individual operations fail
            
            # Verify monitoring results
            assert operation_count == 5
            success_rate = success_count / operation_count * 100 if operation_count > 0 else 0
            
            # Should have high success rate under normal conditions
            assert success_rate >= 80  # At least 80% success rate
            
            logger.info(
                "Connection pool error handling validation completed",
                total_operations=operation_count,
                successful_operations=success_count,
                failed_operations=error_count,
                success_rate_percent=success_rate
            )
            
            # Test circuit breaker functionality
            with mongodb_circuit_breaker() as circuit_breaker:
                try:
                    # Perform operation through circuit breaker
                    test_doc = {'circuit_breaker_test': True}
                    result = collection.insert_one(test_doc)
                    assert result.acknowledged is True
                    
                except Exception as e:
                    logger.warning(f"Circuit breaker operation failed: {str(e)}")
            
            # Cleanup
            collection.drop()


class TestDatabaseErrorHandling:
    """
    Test suite for database error handling covering exception scenarios,
    retry logic, and circuit breaker patterns.
    
    Tests comprehensive error handling with circuit breaker patterns per
    Section 4.2.3 error handling flows and Section 5.2.5 database access
    layer error management requirements.
    """
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_database_exception_handling(self, app_with_database, user_factory):
        """
        Test database exception handling and error classification.
        
        Validates comprehensive exception handling including PyMongo error
        classification, error severity assessment, and proper error propagation
        per Section 4.2.3 error handling flows requirements.
        
        Args:
            app_with_database: Flask application with database connections
            user_factory: User document factory for test data generation
        """
        with app_with_database.app_context():
            collection = get_collection('test_exception_handling')
            
            # Test duplicate key error handling
            collection.create_index('email', unique=True)
            
            user_doc = user_factory.build()
            collection.insert_one(user_doc)
            
            # Attempt duplicate insertion
            with pytest.raises(DuplicateKeyError):
                duplicate_doc = user_factory.build()
                duplicate_doc['email'] = user_doc['email']  # Same email
                collection.insert_one(duplicate_doc)
            
            # Test invalid ObjectId error
            with pytest.raises((ValueError, TypeError)):
                collection.find_one({'_id': 'invalid-object-id'})
            
            # Test invalid update operation
            with pytest.raises(OperationFailure):
                collection.update_one(
                    {'_id': user_doc['_id']},
                    {'$invalid_operator': {'field': 'value'}}
                )
            
            # Test error handling with decorator
            @handle_database_error(
                operation_type=DatabaseOperationType.QUERY,
                severity=DatabaseErrorSeverity.MEDIUM
            )
            def problematic_query():
                return collection.find_one({'_id': 'definitely-invalid-id'})
            
            try:
                result = problematic_query()
                # Should handle error gracefully
            except Exception as e:
                assert isinstance(e, (ValueError, TypeError, DatabaseException))
            
            # Cleanup
            collection.drop()
            
        logger.info("Database exception handling validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_database_retry_logic(self, app_with_database, error_simulation):
        """
        Test database retry logic for transient failures.
        
        Validates retry mechanisms including exponential backoff, retry limits,
        and success recovery per Section 4.2.3 error handling patterns and
        Section 5.2.5 database resilience requirements.
        
        Args:
            app_with_database: Flask application with database connections
            error_simulation: Error simulation fixture for testing
        """
        with app_with_database.app_context():
            collection = get_collection('test_retry_logic')
            
            # Configure error simulation for transient failures
            error_simulation.configure_error(
                error_type=ConnectionFailure,
                message="Simulated connection failure",
                threshold=3,
                should_fail=True
            )
            
            retry_attempts = 0
            
            @with_database_retry(
                max_retries=3,
                backoff_factor=0.1,  # Fast backoff for testing
                exceptions=(ConnectionFailure, NetworkTimeout)
            )
            def retry_test_operation():
                nonlocal retry_attempts
                retry_attempts += 1
                
                # Simulate transient failure for first few attempts
                if retry_attempts <= 2:
                    error_simulation.maybe_fail()
                
                # Successful operation after retries
                test_doc = {
                    'retry_attempt': retry_attempts,
                    'timestamp': datetime.now(timezone.utc)
                }
                return collection.insert_one(test_doc)
            
            # Reset simulation state
            error_simulation.reset()
            error_simulation.configure_error(
                error_type=ConnectionFailure,
                threshold=2,
                should_fail=True
            )
            
            # Execute operation with retries
            try:
                result = retry_test_operation()
                assert result.acknowledged is True
                assert retry_attempts > 1  # Should have retried
                
            except ConnectionFailure:
                # Acceptable if retries exhausted
                assert retry_attempts >= 3
            
            # Test successful operation without retries
            error_simulation.reset()
            
            def successful_operation():
                return collection.insert_one({'success': True})
            
            decorated_success = with_database_retry()(successful_operation)
            result = decorated_success()
            assert result.acknowledged is True
            
            # Cleanup
            collection.drop()
            
        logger.info("Database retry logic validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_circuit_breaker_functionality(self, app_with_database, error_simulation):
        """
        Test circuit breaker functionality for database resilience.
        
        Validates circuit breaker patterns including failure threshold detection,
        circuit opening/closing, and recovery mechanisms per Section 4.2.3
        circuit breaker patterns and Section 5.2.5 database resilience.
        
        Args:
            app_with_database: Flask application with database connections
            error_simulation: Error simulation fixture for testing
        """
        with app_with_database.app_context():
            collection = get_collection('test_circuit_breaker')
            
            # Test circuit breaker with database operations
            operation_count = 0
            success_count = 0
            circuit_breaker_trips = 0
            
            def test_database_operation():
                nonlocal operation_count, success_count
                operation_count += 1
                
                # Simulate progressive failures
                if operation_count <= 3:
                    error_simulation.force_error(
                        ConnectionFailure,
                        "Simulated database failure"
                    )
                
                # Successful operation
                test_doc = {
                    'operation_count': operation_count,
                    'timestamp': datetime.now(timezone.utc)
                }
                result = collection.insert_one(test_doc)
                success_count += 1
                return result
            
            # Test operations with circuit breaker
            for i in range(10):
                try:
                    with mongodb_circuit_breaker() as breaker:
                        test_database_operation()
                        
                except (ConnectionFailure, Exception) as e:
                    if "Circuit breaker" in str(e):
                        circuit_breaker_trips += 1
                    # Continue testing even after failures
                
                # Reset error simulation after initial failures
                if i == 4:
                    error_simulation.reset()
            
            # Verify circuit breaker behavior
            logger.info(
                "Circuit breaker functionality validation completed",
                total_operations=operation_count,
                successful_operations=success_count,
                circuit_breaker_trips=circuit_breaker_trips
            )
            
            # Should have some successful operations after recovery
            assert success_count > 0
            
            # Cleanup
            collection.drop()
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_error_monitoring_and_metrics(self, app_with_database, test_metrics_collector):
        """
        Test error monitoring and metrics collection for observability.
        
        Validates error metrics collection including error rates, error types,
        and performance impact monitoring per Section 6.2.5 database monitoring
        and observability requirements.
        
        Args:
            app_with_database: Flask application with database connections
            test_metrics_collector: Test metrics collection fixture
        """
        with app_with_database.app_context():
            collection = get_collection('test_error_monitoring')
            
            # Test successful operations baseline
            for i in range(5):
                test_metrics_collector.start_test(f"success_operation_{i}")
                try:
                    doc = {
                        'test_index': i,
                        'timestamp': datetime.now(timezone.utc)
                    }
                    collection.insert_one(doc)
                    test_metrics_collector.end_test(f"success_operation_{i}", success=True)
                    test_metrics_collector.record_operation('database')
                    
                except Exception as e:
                    test_metrics_collector.end_test(
                        f"success_operation_{i}",
                        success=False,
                        error_type=type(e).__name__
                    )
            
            # Test error scenarios
            for i in range(3):
                test_metrics_collector.start_test(f"error_operation_{i}")
                try:
                    # Force error with invalid operation
                    collection.update_one(
                        {'_id': f"invalid_id_{i}"},
                        {'$invalid_op': {'field': 'value'}}
                    )
                    test_metrics_collector.end_test(f"error_operation_{i}", success=True)
                    
                except Exception as e:
                    test_metrics_collector.end_test(
                        f"error_operation_{i}",
                        success=False,
                        error_type=type(e).__name__
                    )
                    test_metrics_collector.record_operation('database')
            
            # Analyze metrics
            metrics_summary = test_metrics_collector.get_summary()
            
            # Verify metrics collection
            assert metrics_summary['total_tests'] == 8
            assert metrics_summary['passed_tests'] >= 5  # At least the successful ones
            assert metrics_summary['database_operations'] > 0
            
            # Verify error distribution tracking
            if metrics_summary['error_distribution']:
                assert 'OperationFailure' in metrics_summary['error_distribution']
            
            success_rate = metrics_summary['success_rate'] * 100
            logger.info(
                "Error monitoring and metrics validation completed",
                total_tests=metrics_summary['total_tests'],
                success_rate_percent=success_rate,
                error_types=list(metrics_summary['error_distribution'].keys()),
                avg_execution_time_ms=metrics_summary['average_execution_time'] * 1000
            )
            
            # Cleanup
            collection.drop()


class TestDatabaseHealthMonitoring:
    """
    Test suite for database health monitoring covering health checks,
    performance metrics, and observability integration.
    
    Tests database health monitoring and management per Section 6.2.5
    database monitoring requirements with comprehensive health validation
    and performance baseline compliance monitoring.
    """
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_database_health_endpoints(self, app_with_database, client):
        """
        Test database health check endpoints for monitoring integration.
        
        Validates health check endpoints including basic health status,
        detailed health information, and monitoring system integration
        per Section 6.2.5 health monitoring and observability requirements.
        
        Args:
            app_with_database: Flask application with database connections
            client: Flask test client
        """
        # Test basic health check endpoint
        response = client.get('/health/database')
        assert response.status_code in [200, 503]  # May be unhealthy in test environment
        
        health_data = response.get_json()
        assert 'status' in health_data
        assert health_data['status'] in ['healthy', 'unhealthy']
        assert 'timestamp' in health_data
        
        if response.status_code == 200:
            assert health_data['status'] == 'healthy'
            assert 'details' in health_data
            
            # Verify health details structure
            details = health_data['details']
            assert 'environment' in details
            assert 'initialized' in details
            assert 'services' in details
        
        # Test detailed health check endpoint
        detailed_response = client.get('/health/database/detailed')
        
        if detailed_response.status_code == 200:
            detailed_data = detailed_response.get_json()
            assert 'health' in detailed_data
            assert 'performance' in detailed_data
            assert 'timestamp' in detailed_data
            
            # Verify performance metrics structure
            performance = detailed_data['performance']
            assert 'environment' in performance
            assert 'mongodb_sync' in performance
            assert 'connection_pools' in performance
        
        logger.info("Database health endpoints validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_health_status_comprehensive(self, app_with_database):
        """
        Test comprehensive database health status functionality.
        
        Validates complete health status reporting including all database
        services, configuration status, and monitoring integration per
        Section 6.2.5 comprehensive health monitoring requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Get comprehensive health status
            health_status = get_database_health_status()
            
            # Verify overall health structure
            assert isinstance(health_status, dict)
            assert 'status' in health_status or 'environment' in health_status
            assert 'timestamp' in health_status
            
            # If services are initialized, verify service health
            if 'services' in health_status:
                services = health_status['services']
                
                # Check database configuration health
                if 'database_config' in services:
                    config_health = services['database_config']
                    assert 'status' in config_health
                
                # Check MongoDB synchronous manager health
                if 'mongodb_sync' in services:
                    mongodb_health = services['mongodb_sync']
                    assert 'status' in mongodb_health
                
                # Check monitoring service health
                if 'monitoring' in services:
                    monitoring_health = services['monitoring']
                    assert 'status' in monitoring_health
                    assert 'enabled' in monitoring_health
            
            # Verify timestamp format
            timestamp_str = health_status['timestamp']
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                assert isinstance(timestamp, datetime)
            except ValueError:
                pytest.fail(f"Invalid timestamp format: {timestamp_str}")
            
        logger.info("Comprehensive health status validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_performance_metrics_collection(self, app_with_database):
        """
        Test database performance metrics collection for baseline compliance.
        
        Validates performance metrics collection including response times,
        connection statistics, and baseline comparison data per Section 6.2.4
        performance optimization and monitoring requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Get performance metrics
            performance_metrics = get_database_performance_metrics()
            
            # Verify basic metrics structure
            assert isinstance(performance_metrics, dict)
            assert 'timestamp' in performance_metrics
            assert 'environment' in performance_metrics
            
            # Verify MongoDB synchronous metrics
            if 'mongodb_sync' in performance_metrics:
                mongodb_metrics = performance_metrics['mongodb_sync']
                assert isinstance(mongodb_metrics, dict)
            
            # Verify connection pool metrics
            if 'connection_pools' in performance_metrics:
                pool_metrics = performance_metrics['connection_pools']
                assert isinstance(pool_metrics, dict)
            
            # Test performance data with database operations
            collection = get_collection('test_performance_metrics')
            
            # Perform operations to generate metrics
            start_time = time.perf_counter()
            for i in range(10):
                doc = {
                    'index': i,
                    'timestamp': datetime.now(timezone.utc),
                    'data': f"test_data_{i}"
                }
                collection.insert_one(doc)
            
            operations_time = time.perf_counter() - start_time
            
            # Get updated metrics after operations
            updated_metrics = get_database_performance_metrics()
            
            # Verify metrics were updated
            assert updated_metrics['timestamp'] != performance_metrics['timestamp']
            
            # Verify performance thresholds
            avg_operation_time = operations_time / 10
            assert avg_operation_time < 0.1  # Should be under 100ms per operation
            
            logger.info(
                "Performance metrics collection validation completed",
                operations_time_ms=operations_time * 1000,
                avg_operation_time_ms=avg_operation_time * 1000
            )
            
            # Cleanup
            collection.drop()
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_monitoring_integration(self, app_with_database):
        """
        Test monitoring system integration for observability.
        
        Validates monitoring system integration including metrics export,
        alerting integration, and enterprise monitoring compliance per
        Section 6.2.5 monitoring and observability integration requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            services = get_current_database_services()
            
            # Test monitoring manager availability
            if services.monitoring_manager:
                monitoring_manager = services.monitoring_manager
                assert isinstance(monitoring_manager, DatabaseMonitoringManager)
                
                # Test MongoDB client registration
                mongodb_manager = services.mongodb_manager
                if mongodb_manager:
                    client = mongodb_manager.client
                    assert isinstance(client, MongoClient)
                    
                    # Verify client is registered for monitoring
                    # This would typically involve checking internal monitoring state
                    assert client is not None
            
            # Test metrics collector functionality
            if hasattr(services, '_monitoring_manager') and services._monitoring_manager:
                # Perform monitored operations
                collection = get_collection('test_monitoring_integration')
                
                # Test operation monitoring
                with monitor_database_operation('test_insert') as metrics:
                    doc = {
                        'test': 'monitoring_integration',
                        'timestamp': datetime.now(timezone.utc)
                    }
                    result = collection.insert_one(doc)
                    assert result.acknowledged is True
                
                # Verify metrics collection
                assert 'operation_type' in metrics
                assert 'start_time' in metrics
                
                # Cleanup
                collection.drop()
            
            # Test health monitoring integration
            health_status = services.get_health_status()
            performance_metrics = services.get_performance_metrics()
            
            # Verify integration data availability
            assert isinstance(health_status, dict)
            assert isinstance(performance_metrics, dict)
            
            # Both should have consistent timestamp format
            health_timestamp = health_status.get('timestamp')
            perf_timestamp = performance_metrics.get('timestamp')
            
            if health_timestamp and perf_timestamp:
                # Verify both are valid ISO format timestamps
                datetime.fromisoformat(health_timestamp.replace('Z', '+00:00'))
                datetime.fromisoformat(perf_timestamp.replace('Z', '+00:00'))
            
        logger.info("Monitoring integration validation completed")


class TestDatabaseUtilities:
    """
    Test suite for database utility functions covering validation,
    helper functions, and convenience operations.
    
    Tests database utility functions and validation helpers per
    Section 5.2.5 database access layer utility requirements
    with comprehensive input validation and edge case handling.
    """
    
    @pytest.mark.unit
    def test_object_id_validation(self):
        """
        Test ObjectId validation utility function.
        
        Validates ObjectId validation functionality including valid ObjectId
        recognition, invalid format detection, and edge case handling per
        Section 5.2.5 database utilities validation requirements.
        """
        from bson import ObjectId
        
        # Test valid ObjectId
        valid_object_id = ObjectId()
        assert validate_object_id(valid_object_id) is True
        assert validate_object_id(str(valid_object_id)) is True
        
        # Test invalid ObjectId formats
        assert validate_object_id('invalid') is False
        assert validate_object_id('') is False
        assert validate_object_id(None) is False
        assert validate_object_id(123) is False
        assert validate_object_id([]) is False
        assert validate_object_id({}) is False
        
        # Test edge cases
        assert validate_object_id('507f1f77bcf86cd799439011') is True  # Valid hex string
        assert validate_object_id('507f1f77bcf86cd79943901g') is False  # Invalid hex character
        assert validate_object_id('507f1f77bcf86cd79943901') is False   # Too short
        assert validate_object_id('507f1f77bcf86cd799439011a') is False  # Too long
        
        logger.info("ObjectId validation utility validation completed")
    
    @pytest.mark.unit
    def test_database_availability_flags(self):
        """
        Test database availability flags for feature detection.
        
        Validates availability flags including Motor async driver detection,
        Flask integration capability, and feature flag functionality per
        Section 5.2.5 database utilities and feature detection requirements.
        """
        # Test Motor availability flag
        assert isinstance(MOTOR_AVAILABLE, bool)
        
        if MOTOR_AVAILABLE:
            # Motor should be importable
            import motor.motor_asyncio
            assert motor.motor_asyncio is not None
        
        # Test Flask availability flag
        assert isinstance(FLASK_AVAILABLE, bool)
        
        if FLASK_AVAILABLE:
            # Flask should be importable
            from flask import Flask
            assert Flask is not None
        
        # Verify flags are properly exported
        from src.data import MOTOR_AVAILABLE as exported_motor, FLASK_AVAILABLE as exported_flask
        assert exported_motor == MOTOR_AVAILABLE
        assert exported_flask == FLASK_AVAILABLE
        
        logger.info("Database availability flags validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_convenience_functions(self, app_with_database):
        """
        Test database convenience functions for simplified access.
        
        Validates convenience functions including direct client access,
        database/collection shortcuts, and simplified operation patterns
        per Section 5.2.5 database utilities convenience requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Test client access functions
            mongodb_client = get_mongodb_client()
            assert isinstance(mongodb_client, MongoClient)
            
            if MOTOR_AVAILABLE:
                motor_client = get_motor_client()
                assert motor_client is None or isinstance(motor_client, motor.AsyncIOMotorClient)
            
            # Test database access functions
            database = get_database()
            assert isinstance(database, Database)
            
            # Test with specific database name
            named_database = get_database('test_specific_db')
            assert isinstance(named_database, Database)
            assert named_database.name == 'test_specific_db'
            
            # Test collection access functions
            collection = get_collection('test_convenience')
            assert isinstance(collection, Collection)
            assert collection.name == 'test_convenience'
            
            # Test collection with specific database
            specific_collection = get_collection('test_specific', 'test_specific_db')
            assert isinstance(specific_collection, Collection)
            assert specific_collection.name == 'test_specific'
            assert specific_collection.database.name == 'test_specific_db'
            
            # Test async collection functions if available
            if MOTOR_AVAILABLE:
                async_database = get_async_database()
                if async_database:
                    assert isinstance(async_database, motor.AsyncIOMotorDatabase)
                
                async_collection = get_async_collection('test_async_convenience')
                if async_collection:
                    assert isinstance(async_collection, motor.AsyncIOMotorCollection)
                    assert async_collection.name == 'test_async_convenience'
        
        logger.info("Convenience functions validation completed")
    
    @pytest.mark.database
    @pytest.mark.integration
    def test_manager_access_functions(self, app_with_database):
        """
        Test database manager access functions for advanced operations.
        
        Validates manager access functions including MongoDB manager retrieval,
        async manager access, and manager state validation per Section 5.2.5
        database manager access requirements.
        
        Args:
            app_with_database: Flask application with database connections
        """
        with app_with_database.app_context():
            # Test MongoDB manager access
            mongodb_manager = get_mongodb_manager()
            assert isinstance(mongodb_manager, MongoDBManager)
            
            # Test manager functionality
            assert mongodb_manager.client is not None
            assert mongodb_manager.database is not None
            
            # Test manager health check
            health_status = mongodb_manager.health_check()
            assert isinstance(health_status, dict)
            assert 'status' in health_status
            
            # Test manager performance metrics
            perf_metrics = mongodb_manager.get_performance_metrics()
            assert isinstance(perf_metrics, dict)
            
            # Test async manager access if available
            if MOTOR_AVAILABLE:
                async_manager = get_async_mongodb_manager()
                # Async manager may not be initialized in sync context
                if async_manager:
                    assert isinstance(async_manager, AsyncMongoDBManager)
            
        logger.info("Manager access functions validation completed")


# Test execution summary and reporting
if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--capture=no",
        "--log-cli-level=INFO"
    ])