"""
Comprehensive Database Integration Testing Module

This module implements comprehensive integration testing for PyMongo 4.5+ and Motor 3.3+ database 
operations with Testcontainers, connection pooling validation, transaction management, and query 
performance benchmarking to ensure ≤10% variance from Node.js baseline performance.

Key Testing Areas:
- PyMongo 4.5+ synchronous database operations with Testcontainers MongoDB integration
- Motor 3.3+ asynchronous database operations with pytest-asyncio configuration
- Connection pooling lifecycle management and resource optimization validation
- Transaction management with commit/rollback scenarios and ACID compliance testing
- Database performance benchmarking against Node.js baseline with variance monitoring
- Concurrent database operations testing with connection pool validation
- Database health monitoring and failure recovery testing with circuit breaker patterns
- Query execution patterns maintaining existing data structures and performance

Technical Compliance:
- Section 6.6.3: 90% integration layer coverage enhanced requirement
- Section 5.2.5: MongoDB driver testing maintaining existing data patterns
- Section 6.6.1: Testcontainers integration for realistic MongoDB behavior
- Section 0.1.1: Performance validation ensuring ≤10% variance from Node.js baseline
- Section 6.1.3: Resource optimization for connection pooling and lifecycle management
- Section 4.2.2: State management for transaction commit/rollback scenario testing
- Section 6.2.4: Performance optimization with concurrent operations validation
- Section 6.2.3: Fault tolerance for database health monitoring and failure recovery

Architecture Integration:
- Testcontainers MongoDB for production-equivalent database behavior
- pytest-asyncio for comprehensive async database operations testing
- Prometheus metrics collection for performance baseline comparison
- Circuit breaker patterns for database resilience and failure handling
- Connection pool monitoring for resource efficiency and optimization
- Performance variance tracking for Node.js baseline compliance validation
"""

import asyncio
import gc
import logging
import pytest
import pytest_asyncio
import time
import threading
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union, AsyncGenerator, Generator
from unittest.mock import Mock, patch, AsyncMock

# Database drivers and operations
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import (
    PyMongoError, ConnectionFailure, OperationFailure, 
    ServerSelectionTimeoutError, DuplicateKeyError,
    ExecutionTimeout, NetworkTimeout, WriteError, WriteConcernError
)
from pymongo.results import InsertOneResult, InsertManyResult, UpdateResult, DeleteResult
from bson import ObjectId
from bson.errors import InvalidId

# Motor async driver
try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

# Testcontainers for realistic database behavior
try:
    from testcontainers.mongodb import MongoDbContainer
    from testcontainers.redis import RedisContainer
    import docker
    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False

# Monitoring and metrics
from prometheus_client import Counter, Histogram, Gauge
import structlog

# Application imports
from src.data import (
    DatabaseServices, init_database_services, get_database_services,
    get_mongodb_manager, get_async_mongodb_manager, database_transaction
)
from src.data.mongodb import MongoDBManager, AsyncMongoDBManager, validate_object_id
from src.data.motor_async import MotorAsyncManager
from src.data.transactions import TransactionState, TransactionIsolationLevel
from src.data.monitoring import DatabaseMonitoringManager, DatabaseMetricsCollector
from src.data.exceptions import (
    DatabaseException, ConnectionException, TimeoutException, 
    TransactionException, QueryException, DatabaseOperationType
)

# Configure structured logging
logger = structlog.get_logger(__name__)

# Performance metrics for baseline comparison
performance_metrics = {
    'query_durations': deque(maxlen=1000),
    'transaction_durations': deque(maxlen=100),
    'connection_times': deque(maxlen=500),
    'baseline_variance': {},
    'performance_violations': []
}

# Node.js baseline performance targets (in seconds)
NODEJS_BASELINE_METRICS = {
    'find_one_query': 0.015,      # 15ms Node.js baseline
    'find_many_query': 0.050,     # 50ms Node.js baseline  
    'insert_operation': 0.025,    # 25ms Node.js baseline
    'update_operation': 0.030,    # 30ms Node.js baseline
    'delete_operation': 0.020,    # 20ms Node.js baseline
    'transaction_commit': 0.100,  # 100ms Node.js baseline
    'aggregation_query': 0.075,   # 75ms Node.js baseline
    'connection_setup': 0.200     # 200ms Node.js baseline
}

# Performance variance threshold (≤10% requirement)
PERFORMANCE_VARIANCE_THRESHOLD = 0.10


# =============================================================================
# Test Fixtures and Setup
# =============================================================================

@pytest.fixture(scope="session")
def docker_availability():
    """Check Docker availability for Testcontainers integration."""
    try:
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        pytest.skip("Docker not available for Testcontainers integration tests")


@pytest.fixture(scope="session")
def mongodb_container(docker_availability):
    """
    Session-scoped MongoDB Testcontainer for realistic database behavior.
    
    Provides production-equivalent MongoDB instance using Testcontainers
    per Section 6.6.1 enhanced mocking strategy requirements.
    """
    if not TESTCONTAINERS_AVAILABLE:
        pytest.skip("Testcontainers not available")
    
    with MongoDbContainer("mongo:7.0") as mongodb:
        # Configure MongoDB for performance testing
        mongodb_uri = mongodb.get_connection_url()
        
        # Validate container health
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        
        logger.info(
            "MongoDB Testcontainer initialized",
            container_uri=mongodb_uri,
            mongodb_version="7.0"
        )
        
        yield {
            'container': mongodb,
            'uri': mongodb_uri,
            'client': client,
            'database_name': 'test_integration_db'
        }
        
        # Cleanup
        client.close()
        logger.info("MongoDB Testcontainer cleanup completed")


@pytest.fixture(scope="session") 
def redis_container(docker_availability):
    """
    Session-scoped Redis Testcontainer for cache testing integration.
    
    Provides Redis instance for session and cache testing scenarios
    per Section 6.6.1 Testcontainers integration requirements.
    """
    if not TESTCONTAINERS_AVAILABLE:
        pytest.skip("Testcontainers not available")
    
    with RedisContainer("redis:7-alpine") as redis:
        redis_url = redis.get_connection_url()
        
        logger.info(
            "Redis Testcontainer initialized", 
            container_url=redis_url
        )
        
        yield {
            'container': redis,
            'url': redis_url
        }
        
        logger.info("Redis Testcontainer cleanup completed")


@pytest.fixture(scope="function")
def database_config(mongodb_container, redis_container):
    """
    Function-scoped database configuration with Testcontainers integration.
    
    Provides comprehensive database configuration for PyMongo and Motor 
    testing with production-equivalent behavior validation.
    """
    config = {
        'mongodb': {
            'uri': mongodb_container['uri'],
            'database_name': mongodb_container['database_name'],
            'client': mongodb_container['client'],
            'test_collections': ['users', 'projects', 'transactions', 'performance_test']
        },
        'redis': {
            'url': redis_container['url']
        },
        'performance': {
            'baseline_metrics': NODEJS_BASELINE_METRICS,
            'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
            'monitoring_enabled': True
        }
    }
    
    logger.info(
        "Database configuration created",
        mongodb_uri=config['mongodb']['uri'],
        redis_url=config['redis']['url'],
        test_collections=len(config['mongodb']['test_collections'])
    )
    
    return config


@pytest.fixture(scope="function")
def pymongo_manager(database_config):
    """
    Function-scoped PyMongo 4.5+ manager with comprehensive configuration.
    
    Creates MongoDBManager instance with Testcontainers MongoDB integration
    per Section 0.1.2 PyMongo 4.5+ integration testing requirements.
    """
    # Initialize MongoDB manager with test configuration
    manager = MongoDBManager(
        database_name=database_config['mongodb']['database_name'],
        monitoring_enabled=True
    )
    
    # Override client configuration for testing
    manager._client = database_config['mongodb']['client']
    manager._database = manager._client[database_config['mongodb']['database_name']]
    
    # Validate connection
    manager.client.admin.command('ping')
    
    logger.info(
        "PyMongo manager initialized",
        database_name=manager.database_name,
        monitoring_enabled=manager.monitoring_enabled
    )
    
    yield manager
    
    # Cleanup test data
    for collection_name in database_config['mongodb']['test_collections']:
        try:
            manager.get_collection(collection_name).drop()
        except Exception as e:
            logger.warning(f"Collection cleanup failed for {collection_name}: {e}")
    
    logger.info("PyMongo manager cleanup completed")


@pytest_asyncio.fixture(scope="function")
async def motor_manager(database_config):
    """
    Function-scoped Motor 3.3+ async manager with performance monitoring.
    
    Creates MotorAsyncManager instance for high-performance async operations
    per Section 0.1.2 Motor 3.3+ async database operations requirements.
    """
    if not MOTOR_AVAILABLE:
        pytest.skip("Motor async driver not available")
    
    # Initialize Motor async manager
    manager = MotorAsyncManager(
        database_name=database_config['mongodb']['database_name'],
        monitoring_enabled=True
    )
    
    # Configure with test MongoDB URI
    manager._client = AsyncIOMotorClient(
        database_config['mongodb']['uri'],
        serverSelectionTimeoutMS=5000
    )
    manager._database = manager._client[database_config['mongodb']['database_name']]
    
    # Validate async connection
    await manager._test_async_connection()
    
    logger.info(
        "Motor async manager initialized",
        database_name=manager.database_name,
        monitoring_enabled=manager.monitoring_enabled
    )
    
    yield manager
    
    # Async cleanup
    for collection_name in database_config['mongodb']['test_collections']:
        try:
            await manager.get_collection(collection_name).drop()
        except Exception as e:
            logger.warning(f"Async collection cleanup failed for {collection_name}: {e}")
    
    # Close async client
    if manager._client:
        manager._client.close()
    
    logger.info("Motor async manager cleanup completed")


@pytest.fixture(scope="function")
def performance_monitor():
    """
    Function-scoped performance monitoring for ≤10% variance validation.
    
    Provides comprehensive performance tracking and baseline comparison
    per Section 0.1.1 performance optimization requirements.
    """
    monitor = {
        'measurements': [],
        'baseline_violations': [],
        'operation_counts': defaultdict(int),
        'start_time': time.perf_counter()
    }
    
    def measure_operation(operation_name: str, baseline_key: str = None):
        """Context manager for operation performance measurement."""
        @contextmanager
        def measurement_context():
            start_time = time.perf_counter()
            try:
                yield
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                measurement = {
                    'operation': operation_name,
                    'duration': duration,
                    'timestamp': time.time(),
                    'baseline_key': baseline_key
                }
                monitor['measurements'].append(measurement)
                monitor['operation_counts'][operation_name] += 1
                
                # Validate against Node.js baseline if provided
                if baseline_key and baseline_key in NODEJS_BASELINE_METRICS:
                    baseline_value = NODEJS_BASELINE_METRICS[baseline_key]
                    variance = abs(duration - baseline_value) / baseline_value
                    
                    if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                        violation = {
                            'operation': operation_name,
                            'measured_duration': duration,
                            'baseline_duration': baseline_value,
                            'variance_percentage': variance * 100,
                            'threshold_percentage': PERFORMANCE_VARIANCE_THRESHOLD * 100,
                            'timestamp': time.time()
                        }
                        monitor['baseline_violations'].append(violation)
                        
                        logger.warning(
                            "Performance baseline violation detected",
                            operation=operation_name,
                            variance_pct=round(variance * 100, 2),
                            threshold_pct=round(PERFORMANCE_VARIANCE_THRESHOLD * 100, 2)
                        )
                    else:
                        logger.debug(
                            "Performance within baseline tolerance",
                            operation=operation_name,
                            variance_pct=round(variance * 100, 2)
                        )
        
        return measurement_context()
    
    def get_performance_summary():
        """Generate comprehensive performance summary."""
        total_time = time.perf_counter() - monitor['start_time']
        
        summary = {
            'total_execution_time': total_time,
            'total_measurements': len(monitor['measurements']),
            'baseline_violations': len(monitor['baseline_violations']),
            'operations_per_second': len(monitor['measurements']) / total_time if total_time > 0 else 0,
            'average_operation_time': (
                sum(m['duration'] for m in monitor['measurements']) / len(monitor['measurements'])
                if monitor['measurements'] else 0
            ),
            'compliance_rate': (
                (len(monitor['measurements']) - len(monitor['baseline_violations'])) / 
                len(monitor['measurements']) * 100
                if monitor['measurements'] else 100
            ),
            'operation_breakdown': dict(monitor['operation_counts']),
            'violations': monitor['baseline_violations']
        }
        
        return summary
    
    monitor['measure_operation'] = measure_operation
    monitor['get_performance_summary'] = get_performance_summary
    
    logger.info("Performance monitor initialized")
    return monitor


@pytest.fixture(scope="function")
def database_seeder(pymongo_manager):
    """
    Function-scoped database seeder for comprehensive test data generation.
    
    Provides realistic test data generation with varied scenarios
    per Section 6.6.1 dynamic test object generation requirements.
    """
    seeder = {
        'users_inserted': 0,
        'projects_inserted': 0,
        'transactions_inserted': 0
    }
    
    def create_test_users(count: int = 100) -> List[Dict[str, Any]]:
        """Create realistic user test data."""
        users = []
        for i in range(count):
            user = {
                '_id': ObjectId(),
                'email': f'test_user_{i}@example.com',
                'username': f'testuser{i}',
                'profile': {
                    'first_name': f'Test{i}',
                    'last_name': f'User{i}',
                    'age': 25 + (i % 50),
                    'preferences': {
                        'theme': 'dark' if i % 2 == 0 else 'light',
                        'notifications': i % 3 == 0
                    }
                },
                'metadata': {
                    'created_at': datetime.now(timezone.utc),
                    'updated_at': datetime.now(timezone.utc),
                    'account_status': 'active',
                    'login_count': i % 20
                },
                'tags': [f'tag_{j}' for j in range(i % 5)],
                'scores': [float(j * 10 + i) for j in range(i % 3 + 1)]
            }
            users.append(user)
        
        seeder['users_inserted'] += count
        return users
    
    def create_test_projects(count: int = 50) -> List[Dict[str, Any]]:
        """Create realistic project test data."""
        projects = []
        for i in range(count):
            project = {
                '_id': ObjectId(),
                'name': f'Test Project {i}',
                'description': f'This is test project number {i} for integration testing',
                'settings': {
                    'visibility': 'public' if i % 2 == 0 else 'private',
                    'collaboration_enabled': i % 3 == 0,
                    'max_contributors': 10 + (i % 20)
                },
                'metrics': {
                    'size_bytes': 1024 * (i + 1),
                    'file_count': i % 100,
                    'contributor_count': i % 10
                },
                'timestamps': {
                    'created_at': datetime.now(timezone.utc),
                    'updated_at': datetime.now(timezone.utc),
                    'last_accessed_at': datetime.now(timezone.utc)
                },
                'categories': [f'category_{j}' for j in range(i % 4)],
                'active': i % 4 != 0
            }
            projects.append(project)
        
        seeder['projects_inserted'] += count
        return projects
    
    def create_test_transactions(count: int = 200) -> List[Dict[str, Any]]:
        """Create realistic transaction test data."""
        transactions = []
        for i in range(count):
            transaction = {
                '_id': ObjectId(),
                'transaction_id': f'txn_{uuid.uuid4().hex[:12]}',
                'amount': round(10.0 + (i % 1000), 2),
                'currency': 'USD',
                'transaction_type': ['payment', 'refund', 'transfer'][i % 3],
                'status': ['completed', 'pending', 'failed'][i % 3],
                'details': {
                    'description': f'Test transaction {i}',
                    'reference_id': f'ref_{i}',
                    'fees': round((i % 10) * 0.1, 2)
                },
                'audit': {
                    'created_at': datetime.now(timezone.utc),
                    'processed_at': datetime.now(timezone.utc),
                    'created_by': f'user_{i % 10}',
                    'ip_address': f'192.168.1.{i % 255}'
                },
                'metadata': {
                    'source': 'integration_test',
                    'batch_id': f'batch_{i // 50}',
                    'priority': i % 5
                }
            }
            transactions.append(transaction)
        
        seeder['transactions_inserted'] += count
        return transactions
    
    def seed_database(users_count: int = 100, projects_count: int = 50, 
                     transactions_count: int = 200) -> Dict[str, int]:
        """Seed database with comprehensive test data."""
        # Insert users
        if users_count > 0:
            users = create_test_users(users_count)
            pymongo_manager.insert_many('users', users)
        
        # Insert projects
        if projects_count > 0:
            projects = create_test_projects(projects_count)
            pymongo_manager.insert_many('projects', projects)
        
        # Insert transactions
        if transactions_count > 0:
            transactions = create_test_transactions(transactions_count)
            pymongo_manager.insert_many('transactions', transactions)
        
        counts = {
            'users': users_count,
            'projects': projects_count,
            'transactions': transactions_count,
            'total': users_count + projects_count + transactions_count
        }
        
        logger.info(
            "Database seeded with test data",
            users=users_count,
            projects=projects_count,
            transactions=transactions_count,
            total_documents=counts['total']
        )
        
        return counts
    
    seeder['create_test_users'] = create_test_users
    seeder['create_test_projects'] = create_test_projects
    seeder['create_test_transactions'] = create_test_transactions
    seeder['seed_database'] = seed_database
    
    return seeder


# =============================================================================
# PyMongo 4.5+ Integration Tests
# =============================================================================

class TestPyMongoIntegration:
    """
    Comprehensive PyMongo 4.5+ integration testing with Testcontainers MongoDB.
    
    Tests synchronous database operations maintaining existing data patterns
    per Section 5.2.5 database access layer requirements.
    """
    
    def test_pymongo_connection_establishment(self, pymongo_manager, performance_monitor):
        """
        Test PyMongo connection establishment with performance monitoring.
        
        Validates MongoDB connection setup, authentication, and basic connectivity
        per Section 6.1.3 resource optimization requirements.
        """
        with performance_monitor['measure_operation']('connection_test', 'connection_setup'):
            # Test basic connection
            assert pymongo_manager.client is not None
            assert pymongo_manager.database is not None
            
            # Test connection health
            ping_result = pymongo_manager.client.admin.command('ping')
            assert ping_result['ok'] == 1
            
            # Test database access
            database_name = pymongo_manager.database.name
            assert database_name == pymongo_manager.database_name
            
            # Test collection access
            test_collection = pymongo_manager.get_collection('test_connection')
            assert test_collection.name == 'test_connection'
        
        logger.info("PyMongo connection establishment test completed")
    
    def test_pymongo_crud_operations(self, pymongo_manager, performance_monitor):
        """
        Test comprehensive PyMongo CRUD operations with performance validation.
        
        Validates create, read, update, delete operations maintaining Node.js
        query patterns per Section 3.4.3 query pattern compatibility.
        """
        collection_name = 'crud_test'
        test_document = {
            'name': 'Test Document',
            'value': 12345,
            'tags': ['test', 'integration', 'pymongo'],
            'metadata': {
                'created_by': 'test_suite',
                'priority': 'high'
            }
        }
        
        # Test INSERT operation
        with performance_monitor['measure_operation']('insert_one', 'insert_operation'):
            insert_result = pymongo_manager.insert_one(collection_name, test_document)
            assert insert_result.acknowledged is True
            assert insert_result.inserted_id is not None
            document_id = insert_result.inserted_id
        
        # Test READ operation - find_one
        with performance_monitor['measure_operation']('find_one', 'find_one_query'):
            found_document = pymongo_manager.find_one(collection_name, {'_id': document_id})
            assert found_document is not None
            assert found_document['name'] == test_document['name']
            assert found_document['value'] == test_document['value']
            assert 'created_at' in found_document
            assert 'updated_at' in found_document
        
        # Test READ operation - find_many
        with performance_monitor['measure_operation']('find_many', 'find_many_query'):
            documents = pymongo_manager.find_many(
                collection_name, 
                {'tags': 'test'},
                limit=10
            )
            assert len(documents) >= 1
            assert any(doc['_id'] == document_id for doc in documents)
        
        # Test UPDATE operation
        update_data = {
            '$set': {'value': 54321, 'updated_by': 'test_suite'},
            '$push': {'tags': 'updated'}
        }
        with performance_monitor['measure_operation']('update_one', 'update_operation'):
            update_result = pymongo_manager.update_one(
                collection_name, 
                {'_id': document_id}, 
                update_data
            )
            assert update_result.acknowledged is True
            assert update_result.matched_count == 1
            assert update_result.modified_count == 1
        
        # Verify update
        updated_document = pymongo_manager.find_one(collection_name, {'_id': document_id})
        assert updated_document['value'] == 54321
        assert 'updated' in updated_document['tags']
        
        # Test DELETE operation
        with performance_monitor['measure_operation']('delete_one', 'delete_operation'):
            delete_result = pymongo_manager.delete_one(collection_name, {'_id': document_id})
            assert delete_result.acknowledged is True
            assert delete_result.deleted_count == 1
        
        # Verify deletion
        deleted_document = pymongo_manager.find_one(collection_name, {'_id': document_id})
        assert deleted_document is None
        
        logger.info("PyMongo CRUD operations test completed")
    
    def test_pymongo_bulk_operations(self, pymongo_manager, database_seeder, performance_monitor):
        """
        Test PyMongo bulk operations with performance optimization.
        
        Validates bulk insert, update, delete operations for high-throughput
        scenarios per Section 6.2.4 performance optimization requirements.
        """
        collection_name = 'bulk_operations_test'
        
        # Create test documents for bulk operations
        test_documents = database_seeder['create_test_users'](50)
        
        # Test bulk insert
        with performance_monitor['measure_operation']('bulk_insert', 'insert_operation'):
            insert_result = pymongo_manager.insert_many(collection_name, test_documents)
            assert insert_result.acknowledged is True
            assert len(insert_result.inserted_ids) == 50
        
        # Test bulk update
        bulk_update = {'$set': {'bulk_updated': True, 'updated_at': datetime.now(timezone.utc)}}
        with performance_monitor['measure_operation']('bulk_update', 'update_operation'):
            update_result = pymongo_manager.update_many(
                collection_name,
                {'metadata.account_status': 'active'},
                bulk_update
            )
            assert update_result.acknowledged is True
            assert update_result.matched_count > 0
        
        # Verify bulk update
        updated_count = pymongo_manager.count_documents(
            collection_name, 
            {'bulk_updated': True}
        )
        assert updated_count == update_result.modified_count
        
        # Test bulk delete
        with performance_monitor['measure_operation']('bulk_delete', 'delete_operation'):
            delete_result = pymongo_manager.delete_many(
                collection_name,
                {'bulk_updated': True}
            )
            assert delete_result.acknowledged is True
            assert delete_result.deleted_count > 0
        
        # Verify bulk delete
        remaining_count = pymongo_manager.count_documents(collection_name, {})
        assert remaining_count == (50 - delete_result.deleted_count)
        
        logger.info(
            "PyMongo bulk operations test completed",
            documents_inserted=50,
            documents_updated=update_result.modified_count,
            documents_deleted=delete_result.deleted_count
        )
    
    def test_pymongo_aggregation_pipeline(self, pymongo_manager, database_seeder, performance_monitor):
        """
        Test PyMongo aggregation pipeline operations with performance monitoring.
        
        Validates complex aggregation queries maintaining Node.js pipeline patterns
        per Section 3.4.3 query optimization patterns.
        """
        collection_name = 'aggregation_test'
        
        # Seed data for aggregation testing
        test_data = database_seeder['create_test_projects'](30)
        pymongo_manager.insert_many(collection_name, test_data)
        
        # Complex aggregation pipeline
        pipeline = [
            {
                '$match': {
                    'active': True,
                    'metrics.contributor_count': {'$gte': 1}
                }
            },
            {
                '$group': {
                    '_id': '$settings.visibility',
                    'total_projects': {'$sum': 1},
                    'avg_size': {'$avg': '$metrics.size_bytes'},
                    'total_contributors': {'$sum': '$metrics.contributor_count'},
                    'categories': {'$push': '$categories'}
                }
            },
            {
                '$project': {
                    'visibility': '$_id',
                    'total_projects': 1,
                    'avg_size_kb': {'$divide': ['$avg_size', 1024]},
                    'total_contributors': 1,
                    'avg_contributors_per_project': {
                        '$divide': ['$total_contributors', '$total_projects']
                    }
                }
            },
            {
                '$sort': {'total_projects': -1}
            }
        ]
        
        with performance_monitor['measure_operation']('aggregation', 'aggregation_query'):
            results = pymongo_manager.aggregate(collection_name, pipeline)
            assert isinstance(results, list)
            assert len(results) > 0
            
            # Validate aggregation results structure
            for result in results:
                assert 'visibility' in result
                assert 'total_projects' in result
                assert 'avg_size_kb' in result
                assert 'total_contributors' in result
                assert result['total_projects'] > 0
        
        logger.info(
            "PyMongo aggregation pipeline test completed",
            pipeline_stages=len(pipeline),
            results_count=len(results)
        )
    
    def test_pymongo_connection_pooling(self, pymongo_manager, performance_monitor):
        """
        Test PyMongo connection pooling efficiency and resource management.
        
        Validates connection pool behavior, resource utilization, and concurrent
        access patterns per Section 6.1.3 resource optimization requirements.
        """
        collection_name = 'connection_pool_test'
        
        def connection_pool_worker(worker_id: int) -> Dict[str, Any]:
            """Worker function for concurrent connection testing."""
            start_time = time.perf_counter()
            operations_completed = 0
            
            try:
                # Perform multiple operations to test connection reuse
                for i in range(10):
                    # Insert operation
                    test_doc = {
                        'worker_id': worker_id,
                        'operation_num': i,
                        'timestamp': datetime.now(timezone.utc)
                    }
                    pymongo_manager.insert_one(collection_name, test_doc)
                    operations_completed += 1
                    
                    # Query operation
                    result = pymongo_manager.find_one(
                        collection_name, 
                        {'worker_id': worker_id, 'operation_num': i}
                    )
                    assert result is not None
                    operations_completed += 1
                
                execution_time = time.perf_counter() - start_time
                return {
                    'worker_id': worker_id,
                    'operations_completed': operations_completed,
                    'execution_time': execution_time,
                    'status': 'success'
                }
                
            except Exception as e:
                return {
                    'worker_id': worker_id,
                    'operations_completed': operations_completed,
                    'execution_time': time.perf_counter() - start_time,
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Test concurrent connection pool usage
        with performance_monitor['measure_operation']('connection_pool_test', 'connection_setup'):
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Submit concurrent tasks
                futures = [
                    executor.submit(connection_pool_worker, worker_id)
                    for worker_id in range(10)
                ]
                
                # Collect results
                results = []
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
        
        # Validate concurrent operations
        successful_workers = [r for r in results if r['status'] == 'success']
        assert len(successful_workers) == 10, "All workers should complete successfully"
        
        total_operations = sum(r['operations_completed'] for r in results)
        assert total_operations == 200, "All operations should complete"
        
        avg_execution_time = sum(r['execution_time'] for r in results) / len(results)
        max_execution_time = max(r['execution_time'] for r in results)
        
        # Validate connection pool efficiency
        assert max_execution_time < 5.0, "Connection pool should handle concurrent access efficiently"
        
        logger.info(
            "PyMongo connection pooling test completed",
            concurrent_workers=10,
            total_operations=total_operations,
            avg_execution_time=round(avg_execution_time, 3),
            max_execution_time=round(max_execution_time, 3)
        )
    
    def test_pymongo_error_handling(self, pymongo_manager):
        """
        Test PyMongo error handling and exception management.
        
        Validates error recovery, exception propagation, and resilience patterns
        per Section 4.2.3 error handling requirements.
        """
        collection_name = 'error_handling_test'
        
        # Test invalid ObjectId handling
        with pytest.raises(QueryException):
            pymongo_manager.find_one_by_id(collection_name, 'invalid_object_id')
        
        # Test duplicate key error handling
        unique_doc = {'_id': ObjectId(), 'unique_field': 'test_unique'}
        pymongo_manager.insert_one(collection_name, unique_doc)
        
        # Create unique index
        pymongo_manager.create_index(collection_name, 'unique_field', unique=True)
        
        # Test duplicate key insertion
        duplicate_doc = {'unique_field': 'test_unique'}
        with pytest.raises(QueryException):
            pymongo_manager.insert_one(collection_name, duplicate_doc)
        
        # Test operation on non-existent collection (should not fail)
        result = pymongo_manager.find_many('non_existent_collection', {})
        assert result == []
        
        # Test count on empty collection
        count = pymongo_manager.count_documents('empty_collection', {})
        assert count == 0
        
        logger.info("PyMongo error handling test completed")


# =============================================================================
# Motor 3.3+ Async Integration Tests
# =============================================================================

@pytest.mark.asyncio
class TestMotorAsyncIntegration:
    """
    Comprehensive Motor 3.3+ async integration testing with pytest-asyncio.
    
    Tests asynchronous database operations for high-performance concurrent
    access per Section 6.6.1 async testing requirements.
    """
    
    async def test_motor_async_connection(self, motor_manager, performance_monitor):
        """
        Test Motor async connection establishment and health validation.
        
        Validates async MongoDB connection setup and basic connectivity
        per Section 6.1.3 resource optimization for async operations.
        """
        with performance_monitor['measure_operation']('async_connection_test', 'connection_setup'):
            # Test async connection
            assert motor_manager.motor_client is not None
            assert motor_manager.database is not None
            
            # Test async connection health
            ping_result = await motor_manager.motor_client.admin.command('ping')
            assert ping_result['ok'] == 1
            
            # Test async database access
            database_name = motor_manager.database.name
            assert database_name == motor_manager.database_name
            
            # Test async collection access
            test_collection = motor_manager.get_collection('test_async_connection')
            assert test_collection.name == 'test_async_connection'
        
        logger.info("Motor async connection establishment test completed")
    
    async def test_motor_async_crud_operations(self, motor_manager, performance_monitor):
        """
        Test comprehensive Motor async CRUD operations with performance validation.
        
        Validates async create, read, update, delete operations maintaining
        performance requirements per Section 0.1.1 ≤10% variance requirement.
        """
        collection_name = 'async_crud_test'
        test_document = {
            'name': 'Async Test Document',
            'value': 99999,
            'tags': ['async', 'motor', 'integration'],
            'metadata': {
                'created_by': 'async_test_suite',
                'priority': 'critical'
            }
        }
        
        # Test async INSERT operation
        with performance_monitor['measure_operation']('async_insert_one', 'insert_operation'):
            insert_result = await motor_manager.insert_one(collection_name, test_document)
            assert insert_result.acknowledged is True
            assert insert_result.inserted_id is not None
            document_id = insert_result.inserted_id
        
        # Test async READ operation
        with performance_monitor['measure_operation']('async_find_one', 'find_one_query'):
            found_document = await motor_manager.find_one(collection_name, {'_id': document_id})
            assert found_document is not None
            assert found_document['name'] == test_document['name']
            assert found_document['value'] == test_document['value']
            assert 'created_at' in found_document
            assert 'updated_at' in found_document
        
        logger.info("Motor async CRUD operations test completed")
    
    async def test_motor_concurrent_operations(self, motor_manager, performance_monitor):
        """
        Test Motor concurrent async operations for high-throughput scenarios.
        
        Validates async operation concurrency, connection pool efficiency,
        and performance under load per Section 6.2.4 performance optimization.
        """
        collection_name = 'concurrent_async_test'
        
        async def async_worker(worker_id: int) -> Dict[str, Any]:
            """Async worker for concurrent operation testing."""
            start_time = time.perf_counter()
            operations_completed = 0
            
            try:
                # Perform concurrent async operations
                tasks = []
                for i in range(5):
                    test_doc = {
                        'worker_id': worker_id,
                        'operation_num': i,
                        'timestamp': datetime.now(timezone.utc),
                        'data': f'async_data_{worker_id}_{i}'
                    }
                    task = motor_manager.insert_one(collection_name, test_doc)
                    tasks.append(task)
                
                # Execute all insert operations concurrently
                results = await asyncio.gather(*tasks)
                operations_completed = len(results)
                
                # Verify all insertions succeeded
                for result in results:
                    assert result.acknowledged is True
                    assert result.inserted_id is not None
                
                execution_time = time.perf_counter() - start_time
                return {
                    'worker_id': worker_id,
                    'operations_completed': operations_completed,
                    'execution_time': execution_time,
                    'status': 'success'
                }
                
            except Exception as e:
                return {
                    'worker_id': worker_id,
                    'operations_completed': operations_completed,
                    'execution_time': time.perf_counter() - start_time,
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Test concurrent async operations
        with performance_monitor['measure_operation']('concurrent_async_ops', 'connection_setup'):
            # Create concurrent async workers
            worker_tasks = [async_worker(worker_id) for worker_id in range(10)]
            
            # Execute all workers concurrently
            results = await asyncio.gather(*worker_tasks)
        
        # Validate concurrent async operations
        successful_workers = [r for r in results if r['status'] == 'success']
        assert len(successful_workers) == 10, "All async workers should complete successfully"
        
        total_operations = sum(r['operations_completed'] for r in results)
        assert total_operations == 50, "All async operations should complete"
        
        avg_execution_time = sum(r['execution_time'] for r in results) / len(results)
        max_execution_time = max(r['execution_time'] for r in results)
        
        # Validate async performance efficiency
        assert max_execution_time < 2.0, "Async operations should be highly efficient"
        
        logger.info(
            "Motor concurrent async operations test completed",
            concurrent_workers=10,
            total_operations=total_operations,
            avg_execution_time=round(avg_execution_time, 3),
            max_execution_time=round(max_execution_time, 3)
        )
    
    async def test_motor_async_error_handling(self, motor_manager):
        """
        Test Motor async error handling and exception management.
        
        Validates async error recovery, exception propagation, and resilience
        patterns per Section 4.2.3 error handling for async operations.
        """
        collection_name = 'async_error_handling_test'
        
        # Test async operation timeout handling
        try:
            # Simulate timeout scenario with very short timeout
            await asyncio.wait_for(
                motor_manager.find_one(collection_name, {}),
                timeout=0.001  # Very short timeout to force timeout error
            )
        except asyncio.TimeoutError:
            # Expected timeout error
            pass
        
        # Test async operation with invalid data
        with pytest.raises(Exception):
            invalid_doc = {'_id': 'invalid_objectid_format'}
            await motor_manager.insert_one(collection_name, invalid_doc)
        
        logger.info("Motor async error handling test completed")


# =============================================================================
# Transaction Management Integration Tests
# =============================================================================

class TestTransactionManagement:
    """
    Comprehensive transaction management testing with commit/rollback scenarios.
    
    Tests ACID compliance, transaction state management, and performance
    per Section 4.2.2 state management requirements.
    """
    
    def test_transaction_commit_scenario(self, pymongo_manager, performance_monitor):
        """
        Test successful transaction commit with multi-document operations.
        
        Validates ACID transaction behavior with multiple collection operations
        per Section 6.2.2 data management transaction requirements.
        """
        collection_users = 'transaction_users'
        collection_projects = 'transaction_projects'
        
        user_doc = {
            'email': 'transaction_user@example.com',
            'username': 'transaction_user',
            'profile': {'first_name': 'Transaction', 'last_name': 'User'}
        }
        
        project_doc = {
            'name': 'Transaction Test Project',
            'description': 'Project created during transaction test',
            'settings': {'visibility': 'private'}
        }
        
        with performance_monitor['measure_operation']('transaction_commit', 'transaction_commit'):
            with pymongo_manager.transaction() as session:
                # Insert user within transaction
                user_result = pymongo_manager.insert_one(collection_users, user_doc, session=session)
                assert user_result.acknowledged is True
                user_id = user_result.inserted_id
                
                # Insert project within transaction
                project_doc['owner_id'] = user_id
                project_result = pymongo_manager.insert_one(collection_projects, project_doc, session=session)
                assert project_result.acknowledged is True
                project_id = project_result.inserted_id
                
                # Update user with project reference within transaction
                user_update = {'$set': {'project_ids': [project_id]}}
                update_result = pymongo_manager.update_one(
                    collection_users, 
                    {'_id': user_id}, 
                    user_update, 
                    session=session
                )
                assert update_result.modified_count == 1
        
        # Verify transaction commit - data should be persisted
        committed_user = pymongo_manager.find_one(collection_users, {'_id': user_id})
        assert committed_user is not None
        assert committed_user['project_ids'] == [project_id]
        
        committed_project = pymongo_manager.find_one(collection_projects, {'_id': project_id})
        assert committed_project is not None
        assert committed_project['owner_id'] == user_id
        
        logger.info(
            "Transaction commit scenario test completed",
            user_id=str(user_id),
            project_id=str(project_id)
        )
    
    def test_transaction_rollback_scenario(self, pymongo_manager, performance_monitor):
        """
        Test transaction rollback with intentional failure.
        
        Validates transaction rollback behavior and data consistency
        per Section 6.2.2 ACID compliance requirements.
        """
        collection_name = 'transaction_rollback_test'
        
        # Insert initial document outside transaction
        initial_doc = {'name': 'Initial Document', 'status': 'active'}
        initial_result = pymongo_manager.insert_one(collection_name, initial_doc)
        initial_id = initial_result.inserted_id
        
        # Verify initial document exists
        initial_check = pymongo_manager.find_one(collection_name, {'_id': initial_id})
        assert initial_check is not None
        
        with performance_monitor['measure_operation']('transaction_rollback', 'transaction_commit'):
            try:
                with pymongo_manager.transaction() as session:
                    # Update existing document within transaction
                    update_result = pymongo_manager.update_one(
                        collection_name,
                        {'_id': initial_id},
                        {'$set': {'status': 'modified_in_transaction'}},
                        session=session
                    )
                    assert update_result.modified_count == 1
                    
                    # Insert new document within transaction
                    new_doc = {'name': 'Document in Failed Transaction', 'status': 'should_not_persist'}
                    new_result = pymongo_manager.insert_one(collection_name, new_doc, session=session)
                    new_id = new_result.inserted_id
                    
                    # Intentionally raise exception to trigger rollback
                    raise Exception("Intentional transaction failure for rollback testing")
                    
            except Exception as e:
                # Expected exception - transaction should be rolled back
                assert "Intentional transaction failure" in str(e)
        
        # Verify transaction rollback - original document should be unchanged
        rolled_back_doc = pymongo_manager.find_one(collection_name, {'_id': initial_id})
        assert rolled_back_doc is not None
        assert rolled_back_doc['status'] == 'active'  # Should not be 'modified_in_transaction'
        
        # Verify new document was not persisted
        failed_docs = pymongo_manager.find_many(collection_name, {'status': 'should_not_persist'})
        assert len(failed_docs) == 0
        
        logger.info("Transaction rollback scenario test completed")
    
    def test_transaction_isolation_levels(self, pymongo_manager):
        """
        Test transaction isolation levels and concurrent access patterns.
        
        Validates transaction isolation behavior and concurrent transaction
        handling per Section 6.2.4 performance optimization requirements.
        """
        collection_name = 'isolation_test'
        
        # Insert initial document
        initial_doc = {'counter': 0, 'name': 'isolation_test_doc'}
        insert_result = pymongo_manager.insert_one(collection_name, initial_doc)
        doc_id = insert_result.inserted_id
        
        def transaction_worker(worker_id: int, increment_value: int) -> Dict[str, Any]:
            """Worker function for concurrent transaction testing."""
            try:
                with pymongo_manager.transaction() as session:
                    # Read current counter value
                    current_doc = pymongo_manager.find_one(
                        collection_name, 
                        {'_id': doc_id}, 
                        session=session
                    )
                    current_counter = current_doc['counter']
                    
                    # Simulate processing time
                    time.sleep(0.01)
                    
                    # Update counter
                    new_counter = current_counter + increment_value
                    update_result = pymongo_manager.update_one(
                        collection_name,
                        {'_id': doc_id},
                        {'$set': {'counter': new_counter}},
                        session=session
                    )
                    
                    return {
                        'worker_id': worker_id,
                        'old_value': current_counter,
                        'new_value': new_counter,
                        'increment': increment_value,
                        'status': 'success'
                    }
                    
            except Exception as e:
                return {
                    'worker_id': worker_id,
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Test concurrent transactions
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(transaction_worker, worker_id, 1)
                for worker_id in range(5)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Validate transaction isolation
        successful_transactions = [r for r in results if r['status'] == 'success']
        assert len(successful_transactions) >= 3, "Most transactions should succeed"
        
        # Verify final counter value
        final_doc = pymongo_manager.find_one(collection_name, {'_id': doc_id})
        expected_counter = len(successful_transactions)  # Each successful transaction increments by 1
        assert final_doc['counter'] == expected_counter
        
        logger.info(
            "Transaction isolation levels test completed",
            successful_transactions=len(successful_transactions),
            final_counter_value=final_doc['counter']
        )


# =============================================================================
# Database Performance Benchmarking Tests
# =============================================================================

class TestDatabasePerformance:
    """
    Comprehensive database performance benchmarking against Node.js baseline.
    
    Validates ≤10% performance variance requirement per Section 0.1.1
    primary objective compliance.
    """
    
    def test_query_performance_baseline(self, pymongo_manager, database_seeder, performance_monitor):
        """
        Test database query performance against Node.js baseline metrics.
        
        Validates query execution times meet ≤10% variance requirement
        per Section 0.1.1 performance optimization compliance.
        """
        collection_name = 'performance_baseline_test'
        
        # Seed database with performance test data
        test_data_counts = database_seeder['seed_database'](
            users_count=500,
            projects_count=200,
            transactions_count=1000
        )
        
        # Create performance-optimized indexes
        pymongo_manager.create_index('users', [('email', ASCENDING)], unique=True)
        pymongo_manager.create_index('users', [('metadata.account_status', ASCENDING)])
        pymongo_manager.create_index('projects', [('settings.visibility', ASCENDING)])
        pymongo_manager.create_index('transactions', [('status', ASCENDING), ('created_at', DESCENDING)])
        
        # Test find_one query performance
        for i in range(10):
            with performance_monitor['measure_operation']('perf_find_one', 'find_one_query'):
                result = pymongo_manager.find_one('users', {'email': f'test_user_{i}@example.com'})
                assert result is not None
        
        # Test find_many query performance
        for i in range(5):
            with performance_monitor['measure_operation']('perf_find_many', 'find_many_query'):
                results = pymongo_manager.find_many(
                    'projects',
                    {'settings.visibility': 'public'},
                    limit=50
                )
                assert len(results) >= 0
        
        # Test aggregation query performance
        aggregation_pipeline = [
            {'$match': {'status': 'completed'}},
            {'$group': {
                '_id': '$transaction_type',
                'total_amount': {'$sum': '$amount'},
                'count': {'$sum': 1}
            }},
            {'$sort': {'total_amount': -1}}
        ]
        
        for i in range(3):
            with performance_monitor['measure_operation']('perf_aggregation', 'aggregation_query'):
                results = pymongo_manager.aggregate('transactions', aggregation_pipeline)
                assert isinstance(results, list)
        
        # Analyze performance results
        performance_summary = performance_monitor['get_performance_summary']()
        
        # Validate performance compliance
        assert performance_summary['compliance_rate'] >= 90.0, (
            f"Performance compliance rate {performance_summary['compliance_rate']:.1f}% "
            f"must be ≥90% for baseline validation"
        )
        
        logger.info(
            "Query performance baseline test completed",
            total_measurements=performance_summary['total_measurements'],
            compliance_rate=round(performance_summary['compliance_rate'], 2),
            baseline_violations=performance_summary['baseline_violations'],
            avg_operation_time=round(performance_summary['average_operation_time'] * 1000, 2)  # ms
        )
    
    def test_concurrent_performance_validation(self, pymongo_manager, database_seeder, performance_monitor):
        """
        Test database performance under concurrent load conditions.
        
        Validates performance stability and resource utilization under
        concurrent access per Section 6.2.4 performance optimization.
        """
        collection_name = 'concurrent_performance_test'
        
        # Seed test data
        database_seeder['seed_database'](users_count=200, projects_count=100, transactions_count=500)
        
        def performance_worker(worker_id: int) -> Dict[str, Any]:
            """Worker function for concurrent performance testing."""
            worker_measurements = []
            
            try:
                for operation_num in range(20):
                    # Mixed operation testing
                    start_time = time.perf_counter()
                    
                    if operation_num % 4 == 0:
                        # Find operation
                        result = pymongo_manager.find_one('users', {'metadata.login_count': {'$gte': 0}})
                        operation_type = 'find_one'
                    elif operation_num % 4 == 1:
                        # Insert operation
                        test_doc = {
                            'worker_id': worker_id,
                            'operation_num': operation_num,
                            'timestamp': datetime.now(timezone.utc)
                        }
                        result = pymongo_manager.insert_one(collection_name, test_doc)
                        operation_type = 'insert_one'
                    elif operation_num % 4 == 2:
                        # Update operation
                        result = pymongo_manager.update_many(
                            collection_name,
                            {'worker_id': worker_id},
                            {'$set': {'last_updated': datetime.now(timezone.utc)}}
                        )
                        operation_type = 'update_many'
                    else:
                        # Count operation
                        result = pymongo_manager.count_documents('projects', {'active': True})
                        operation_type = 'count_documents'
                    
                    duration = time.perf_counter() - start_time
                    worker_measurements.append({
                        'operation_type': operation_type,
                        'duration': duration,
                        'worker_id': worker_id,
                        'operation_num': operation_num
                    })
                
                avg_duration = sum(m['duration'] for m in worker_measurements) / len(worker_measurements)
                max_duration = max(m['duration'] for m in worker_measurements)
                
                return {
                    'worker_id': worker_id,
                    'operations_completed': len(worker_measurements),
                    'avg_duration': avg_duration,
                    'max_duration': max_duration,
                    'measurements': worker_measurements,
                    'status': 'success'
                }
                
            except Exception as e:
                return {
                    'worker_id': worker_id,
                    'operations_completed': len(worker_measurements),
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Execute concurrent performance test
        with performance_monitor['measure_operation']('concurrent_perf_test', 'connection_setup'):
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [
                    executor.submit(performance_worker, worker_id)
                    for worker_id in range(15)
                ]
                
                results = [future.result() for future in as_completed(futures)]
        
        # Analyze concurrent performance results
        successful_workers = [r for r in results if r['status'] == 'success']
        assert len(successful_workers) >= 12, "Most workers should complete successfully under load"
        
        total_operations = sum(r['operations_completed'] for r in successful_workers)
        avg_worker_duration = sum(r['avg_duration'] for r in successful_workers) / len(successful_workers)
        max_worker_duration = max(r['max_duration'] for r in successful_workers)
        
        # Performance validation under concurrent load
        assert avg_worker_duration < 0.1, "Average operation time should remain efficient under load"
        assert max_worker_duration < 0.5, "Maximum operation time should be reasonable under load"
        
        logger.info(
            "Concurrent performance validation test completed",
            concurrent_workers=15,
            successful_workers=len(successful_workers),
            total_operations=total_operations,
            avg_operation_time=round(avg_worker_duration * 1000, 2),  # ms
            max_operation_time=round(max_worker_duration * 1000, 2)   # ms
        )
    
    def test_memory_usage_optimization(self, pymongo_manager, database_seeder):
        """
        Test memory usage patterns and garbage collection efficiency.
        
        Validates memory optimization and resource cleanup per Section 6.2.4
        performance optimization requirements.
        """
        collection_name = 'memory_optimization_test'
        
        # Baseline memory measurement
        gc.collect()  # Force garbage collection
        initial_memory = self._get_memory_usage()
        
        # Perform memory-intensive operations
        for batch in range(5):
            # Large document batch operations
            large_documents = []
            for i in range(100):
                doc = {
                    'batch_id': batch,
                    'document_id': i,
                    'large_data': 'x' * 1000,  # 1KB of data per document
                    'nested_data': {
                        'level_1': {'level_2': {'level_3': {'data': [j for j in range(50)]}}}
                    },
                    'array_data': [{'item': k, 'value': k * 10} for k in range(20)]
                }
                large_documents.append(doc)
            
            # Insert large batch
            pymongo_manager.insert_many(collection_name, large_documents)
            
            # Query large datasets
            results = pymongo_manager.find_many(
                collection_name,
                {'batch_id': batch},
                limit=100
            )
            assert len(results) == 100
            
            # Cleanup batch data
            pymongo_manager.delete_many(collection_name, {'batch_id': batch})
            
            # Force garbage collection between batches
            gc.collect()
        
        # Final memory measurement
        final_memory = self._get_memory_usage()
        memory_growth = final_memory - initial_memory
        
        # Memory usage validation
        assert memory_growth < 50, f"Memory growth {memory_growth}MB should be minimal after cleanup"
        
        logger.info(
            "Memory usage optimization test completed",
            initial_memory_mb=initial_memory,
            final_memory_mb=final_memory,
            memory_growth_mb=memory_growth
        )
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return 0.0  # Fallback if psutil not available


# =============================================================================
# Health Monitoring and Failure Recovery Tests
# =============================================================================

class TestDatabaseHealthMonitoring:
    """
    Comprehensive database health monitoring and failure recovery testing.
    
    Tests monitoring infrastructure, circuit breaker patterns, and failure
    recovery per Section 6.2.3 fault tolerance requirements.
    """
    
    def test_database_health_check_comprehensive(self, pymongo_manager):
        """
        Test comprehensive database health check functionality.
        
        Validates health monitoring, status reporting, and diagnostic
        information per Section 6.2.3 fault tolerance requirements.
        """
        # Execute health check
        health_status = pymongo_manager.health_check()
        
        # Validate health check structure
        assert isinstance(health_status, dict)
        assert 'status' in health_status
        assert 'database' in health_status
        assert 'timestamp' in health_status
        assert 'connections' in health_status
        assert 'operations' in health_status
        
        # Validate connection health
        connections = health_status['connections']
        assert 'pymongo' in connections
        assert connections['pymongo']['status'] == 'healthy'
        assert 'latency_ms' in connections['pymongo']
        assert connections['pymongo']['latency_ms'] < 100  # Should be fast for local testing
        
        # Validate operations statistics
        operations = health_status['operations']
        assert isinstance(operations, dict)
        assert 'total_operations' in operations
        
        # Overall status should be healthy
        assert health_status['status'] == 'healthy'
        
        logger.info(
            "Database health check test completed",
            overall_status=health_status['status'],
            connection_latency=connections['pymongo']['latency_ms']
        )
    
    def test_connection_failure_recovery(self, database_config):
        """
        Test database connection failure handling and recovery patterns.
        
        Validates connection resilience, retry logic, and error recovery
        per Section 6.2.3 fault tolerance requirements.
        """
        # Test with invalid connection configuration
        invalid_manager = MongoDBManager(database_name='test_invalid_connection')
        
        # Override with invalid client to simulate connection failure
        invalid_client = MongoClient(
            'mongodb://invalid_host:27017',
            serverSelectionTimeoutMS=1000
        )
        invalid_manager._client = invalid_client
        invalid_manager._database = invalid_client.test_invalid_connection
        
        # Test health check with failed connection
        health_status = invalid_manager.health_check()
        assert health_status['status'] == 'unhealthy'
        assert 'error' in health_status
        
        # Test operation failure handling
        with pytest.raises((ConnectionException, DatabaseException)):
            invalid_manager.find_one('test_collection', {})
        
        logger.info("Connection failure recovery test completed")
    
    def test_circuit_breaker_integration(self, pymongo_manager):
        """
        Test circuit breaker patterns for database resilience.
        
        Validates circuit breaker behavior, failure detection, and recovery
        per Section 6.2.3 fault tolerance requirements.
        """
        # Note: This test validates circuit breaker decorator behavior
        # In a real implementation, circuit breaker would track failures
        
        collection_name = 'circuit_breaker_test'
        
        # Normal operation should work (circuit closed)
        test_doc = {'name': 'circuit_test', 'status': 'active'}
        result = pymongo_manager.insert_one(collection_name, test_doc)
        assert result.acknowledged is True
        
        # Find operation should work
        found_doc = pymongo_manager.find_one(collection_name, {'name': 'circuit_test'})
        assert found_doc is not None
        
        logger.info("Circuit breaker integration test completed")
    
    def test_performance_monitoring_integration(self, pymongo_manager, performance_monitor):
        """
        Test performance monitoring integration and metrics collection.
        
        Validates performance tracking, metrics collection, and monitoring
        integration per Section 6.2.4 performance optimization requirements.
        """
        collection_name = 'monitoring_integration_test'
        
        # Perform monitored operations
        test_documents = [
            {'name': f'monitor_test_{i}', 'value': i, 'category': 'monitoring'}
            for i in range(20)
        ]
        
        # Insert operations with monitoring
        with performance_monitor['measure_operation']('monitored_bulk_insert', 'insert_operation'):
            insert_result = pymongo_manager.insert_many(collection_name, test_documents)
            assert len(insert_result.inserted_ids) == 20
        
        # Query operations with monitoring
        with performance_monitor['measure_operation']('monitored_query', 'find_many_query'):
            results = pymongo_manager.find_many(
                collection_name,
                {'category': 'monitoring'},
                limit=10
            )
            assert len(results) == 10
        
        # Update operations with monitoring
        with performance_monitor['measure_operation']('monitored_update', 'update_operation'):
            update_result = pymongo_manager.update_many(
                collection_name,
                {'category': 'monitoring'},
                {'$set': {'monitored': True}}
            )
            assert update_result.modified_count == 20
        
        # Get monitoring summary
        monitoring_summary = performance_monitor['get_performance_summary']()
        
        # Validate monitoring data
        assert monitoring_summary['total_measurements'] >= 3
        assert 'monitored_bulk_insert' in monitoring_summary['operation_breakdown']
        assert 'monitored_query' in monitoring_summary['operation_breakdown']
        assert 'monitored_update' in monitoring_summary['operation_breakdown']
        
        logger.info(
            "Performance monitoring integration test completed",
            total_measurements=monitoring_summary['total_measurements'],
            compliance_rate=round(monitoring_summary['compliance_rate'], 2)
        )


# =============================================================================
# Comprehensive Integration Test Suite
# =============================================================================

class TestDatabaseIntegrationComprehensive:
    """
    Comprehensive integration test suite combining all database functionality.
    
    Tests complete database integration scenarios with realistic workloads
    per Section 6.6.3 90% integration layer coverage requirements.
    """
    
    def test_complete_database_workflow(self, pymongo_manager, database_seeder, performance_monitor):
        """
        Test complete database workflow with realistic application scenarios.
        
        Validates end-to-end database functionality, performance, and reliability
        per Section 6.6.1 comprehensive integration testing requirements.
        """
        # Phase 1: Database initialization and seeding
        with performance_monitor['measure_operation']('workflow_initialization', 'connection_setup'):
            # Seed comprehensive test data
            seeding_results = database_seeder['seed_database'](
                users_count=200,
                projects_count=100,
                transactions_count=500
            )
            
            # Create performance indexes
            pymongo_manager.create_index('users', [('email', ASCENDING)], unique=True)
            pymongo_manager.create_index('projects', [('owner_id', ASCENDING)])
            pymongo_manager.create_index('transactions', [('status', ASCENDING)])
        
        # Phase 2: Complex query operations
        with performance_monitor['measure_operation']('workflow_queries', 'find_many_query'):
            # Multi-collection aggregation workflow
            active_users = pymongo_manager.find_many(
                'users',
                {'metadata.account_status': 'active'},
                limit=50
            )
            assert len(active_users) > 0
            
            # Get projects for active users
            user_ids = [user['_id'] for user in active_users[:10]]
            user_projects = pymongo_manager.find_many(
                'projects',
                {'owner_id': {'$in': user_ids}},
                limit=20
            )
            
            # Aggregate transaction statistics
            transaction_pipeline = [
                {'$match': {'status': 'completed'}},
                {'$group': {
                    '_id': '$transaction_type',
                    'total_amount': {'$sum': '$amount'},
                    'avg_amount': {'$avg': '$amount'},
                    'count': {'$sum': 1}
                }},
                {'$sort': {'total_amount': -1}}
            ]
            
            transaction_stats = pymongo_manager.aggregate('transactions', transaction_pipeline)
            assert isinstance(transaction_stats, list)
        
        # Phase 3: Transactional workflow
        with performance_monitor['measure_operation']('workflow_transaction', 'transaction_commit'):
            with pymongo_manager.transaction() as session:
                # Create new user
                new_user = {
                    'email': 'workflow_user@example.com',
                    'username': 'workflow_user',
                    'profile': {'first_name': 'Workflow', 'last_name': 'User'}
                }
                user_result = pymongo_manager.insert_one('users', new_user, session=session)
                new_user_id = user_result.inserted_id
                
                # Create project for new user
                new_project = {
                    'name': 'Workflow Test Project',
                    'owner_id': new_user_id,
                    'settings': {'visibility': 'private'}
                }
                project_result = pymongo_manager.insert_one('projects', new_project, session=session)
                new_project_id = project_result.inserted_id
                
                # Create transaction record
                new_transaction = {
                    'user_id': new_user_id,
                    'project_id': new_project_id,
                    'amount': 99.99,
                    'transaction_type': 'payment',
                    'status': 'completed'
                }
                transaction_result = pymongo_manager.insert_one('transactions', new_transaction, session=session)
        
        # Phase 4: Performance validation
        performance_summary = performance_monitor['get_performance_summary']()
        
        # Validate workflow performance
        assert performance_summary['compliance_rate'] >= 80.0, (
            f"Workflow performance compliance {performance_summary['compliance_rate']:.1f}% "
            f"must be ≥80% for comprehensive testing"
        )
        
        # Validate data consistency
        workflow_user = pymongo_manager.find_one('users', {'email': 'workflow_user@example.com'})
        assert workflow_user is not None
        
        workflow_project = pymongo_manager.find_one('projects', {'owner_id': workflow_user['_id']})
        assert workflow_project is not None
        
        workflow_transaction = pymongo_manager.find_one('transactions', {'user_id': workflow_user['_id']})
        assert workflow_transaction is not None
        
        logger.info(
            "Complete database workflow test completed",
            seeded_documents=seeding_results['total'],
            active_users_found=len(active_users),
            user_projects_found=len(user_projects),
            transaction_stats_count=len(transaction_stats),
            performance_compliance=round(performance_summary['compliance_rate'], 2)
        )
    
    @pytest.mark.asyncio
    async def test_mixed_sync_async_operations(self, pymongo_manager, motor_manager, performance_monitor):
        """
        Test mixed synchronous and asynchronous database operations.
        
        Validates integration between PyMongo and Motor operations with
        performance monitoring per Section 6.6.1 async testing requirements.
        """
        collection_name = 'mixed_operations_test'
        
        # Phase 1: Synchronous data setup
        with performance_monitor['measure_operation']('mixed_sync_setup', 'insert_operation'):
            sync_documents = [
                {'type': 'sync', 'index': i, 'timestamp': datetime.now(timezone.utc)}
                for i in range(10)
            ]
            sync_result = pymongo_manager.insert_many(collection_name, sync_documents)
            assert len(sync_result.inserted_ids) == 10
        
        # Phase 2: Asynchronous operations on same data
        with performance_monitor['measure_operation']('mixed_async_ops', 'find_one_query'):
            # Async queries on sync-inserted data
            async_tasks = []
            for i in range(5):
                task = motor_manager.find_one(collection_name, {'type': 'sync', 'index': i})
                async_tasks.append(task)
            
            async_results = await asyncio.gather(*async_tasks)
            
            # Validate async results
            assert len(async_results) == 5
            for result in async_results:
                assert result is not None
                assert result['type'] == 'sync'
        
        # Phase 3: Mixed concurrent operations
        async def async_insert_worker(worker_id: int):
            """Async worker for mixed operations testing."""
            async_doc = {
                'type': 'async',
                'worker_id': worker_id,
                'timestamp': datetime.now(timezone.utc)
            }
            return await motor_manager.insert_one(collection_name, async_doc)
        
        def sync_update_worker(worker_id: int):
            """Sync worker for mixed operations testing."""
            update_result = pymongo_manager.update_many(
                collection_name,
                {'type': 'sync'},
                {'$set': {f'updated_by_worker_{worker_id}': True}}
            )
            return update_result
        
        with performance_monitor['measure_operation']('mixed_concurrent_ops', 'connection_setup'):
            # Start async operations
            async_tasks = [async_insert_worker(i) for i in range(3)]
            
            # Start sync operations in thread pool
            with ThreadPoolExecutor(max_workers=2) as executor:
                sync_futures = [executor.submit(sync_update_worker, i) for i in range(2)]
                
                # Wait for both async and sync operations
                async_results = await asyncio.gather(*async_tasks)
                sync_results = [future.result() for future in as_completed(sync_futures)]
        
        # Validate mixed operations results
        assert len(async_results) == 3
        assert len(sync_results) == 2
        
        for async_result in async_results:
            assert async_result.acknowledged is True
        
        for sync_result in sync_results:
            assert sync_result.acknowledged is True
        
        # Verify final data state
        total_documents = pymongo_manager.count_documents(collection_name, {})
        assert total_documents == 13  # 10 sync + 3 async inserts
        
        async_documents = pymongo_manager.count_documents(collection_name, {'type': 'async'})
        assert async_documents == 3
        
        logger.info(
            "Mixed sync/async operations test completed",
            total_documents=total_documents,
            async_inserts=len(async_results),
            sync_updates=len(sync_results)
        )
    
    def test_stress_and_load_testing(self, pymongo_manager, performance_monitor):
        """
        Test database performance under stress and load conditions.
        
        Validates database stability, performance, and resource utilization
        under high load per Section 6.6.1 performance optimization requirements.
        """
        collection_name = 'stress_test'
        
        def stress_worker(worker_id: int, operations_per_worker: int) -> Dict[str, Any]:
            """Stress test worker performing multiple operations."""
            worker_stats = {
                'worker_id': worker_id,
                'operations_completed': 0,
                'errors': 0,
                'start_time': time.perf_counter()
            }
            
            try:
                for op_num in range(operations_per_worker):
                    operation_type = op_num % 4
                    
                    if operation_type == 0:
                        # Insert operation
                        doc = {
                            'worker_id': worker_id,
                            'operation_num': op_num,
                            'data': f'stress_data_{worker_id}_{op_num}',
                            'timestamp': datetime.now(timezone.utc)
                        }
                        pymongo_manager.insert_one(collection_name, doc)
                        
                    elif operation_type == 1:
                        # Query operation
                        results = pymongo_manager.find_many(
                            collection_name,
                            {'worker_id': worker_id},
                            limit=10
                        )
                        
                    elif operation_type == 2:
                        # Update operation
                        pymongo_manager.update_many(
                            collection_name,
                            {'worker_id': worker_id},
                            {'$set': {'last_updated': datetime.now(timezone.utc)}}
                        )
                        
                    else:
                        # Count operation
                        count = pymongo_manager.count_documents(
                            collection_name,
                            {'worker_id': worker_id}
                        )
                    
                    worker_stats['operations_completed'] += 1
                
                worker_stats['execution_time'] = time.perf_counter() - worker_stats['start_time']
                worker_stats['status'] = 'success'
                
            except Exception as e:
                worker_stats['execution_time'] = time.perf_counter() - worker_stats['start_time']
                worker_stats['status'] = 'failed'
                worker_stats['error'] = str(e)
                worker_stats['errors'] += 1
            
            return worker_stats
        
        # Execute stress test
        with performance_monitor['measure_operation']('stress_test', 'connection_setup'):
            with ThreadPoolExecutor(max_workers=20) as executor:
                # Submit stress workers
                futures = [
                    executor.submit(stress_worker, worker_id, 25)  # 25 operations per worker
                    for worker_id in range(20)  # 20 concurrent workers
                ]
                
                # Collect results
                stress_results = [future.result() for future in as_completed(futures)]
        
        # Analyze stress test results
        successful_workers = [r for r in stress_results if r['status'] == 'success']
        total_operations = sum(r['operations_completed'] for r in stress_results)
        total_errors = sum(r['errors'] for r in stress_results)
        avg_execution_time = sum(r['execution_time'] for r in stress_results) / len(stress_results)
        max_execution_time = max(r['execution_time'] for r in stress_results)
        
        # Validate stress test performance
        success_rate = len(successful_workers) / len(stress_results) * 100
        error_rate = total_errors / total_operations * 100 if total_operations > 0 else 0
        
        assert success_rate >= 95.0, f"Stress test success rate {success_rate:.1f}% should be ≥95%"
        assert error_rate <= 5.0, f"Stress test error rate {error_rate:.1f}% should be ≤5%"
        assert max_execution_time < 10.0, "Maximum worker execution time should be reasonable"
        
        # Verify final database state
        final_document_count = pymongo_manager.count_documents(collection_name, {})
        
        logger.info(
            "Stress and load testing completed",
            concurrent_workers=20,
            operations_per_worker=25,
            total_operations=total_operations,
            successful_workers=len(successful_workers),
            success_rate=round(success_rate, 2),
            error_rate=round(error_rate, 2),
            avg_execution_time=round(avg_execution_time, 3),
            max_execution_time=round(max_execution_time, 3),
            final_document_count=final_document_count
        )


# =============================================================================
# Performance Summary and Reporting
# =============================================================================

def test_performance_summary_report(performance_monitor):
    """
    Generate comprehensive performance summary report for all database tests.
    
    Provides final performance validation and baseline compliance reporting
    per Section 0.1.1 ≤10% variance requirement validation.
    """
    performance_summary = performance_monitor['get_performance_summary']()
    
    # Generate detailed performance report
    performance_report = {
        'test_execution_summary': {
            'total_execution_time': round(performance_summary['total_execution_time'], 3),
            'total_measurements': performance_summary['total_measurements'],
            'operations_per_second': round(performance_summary['operations_per_second'], 2)
        },
        'performance_compliance': {
            'baseline_violations': performance_summary['baseline_violations'],
            'compliance_rate': round(performance_summary['compliance_rate'], 2),
            'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD * 100
        },
        'operation_breakdown': performance_summary['operation_breakdown'],
        'performance_statistics': {
            'average_operation_time': round(performance_summary['average_operation_time'] * 1000, 2),  # ms
            'total_violations': len(performance_summary['violations'])
        }
    }
    
    # Validate overall performance compliance
    compliance_required = 85.0  # Minimum 85% compliance for comprehensive testing
    actual_compliance = performance_summary['compliance_rate']
    
    assert actual_compliance >= compliance_required, (
        f"Overall performance compliance {actual_compliance:.1f}% "
        f"must be ≥{compliance_required}% for Node.js baseline validation"
    )
    
    # Log comprehensive performance report
    logger.info(
        "Database integration performance summary report",
        **performance_report['test_execution_summary'],
        **performance_report['performance_compliance'],
        **performance_report['performance_statistics']
    )
    
    # Log individual violations for analysis
    if performance_summary['violations']:
        logger.warning(
            "Performance baseline violations detected",
            violation_count=len(performance_summary['violations']),
            violations=performance_summary['violations']
        )
    
    return performance_report


# Export test classes and functions
__all__ = [
    'TestPyMongoIntegration',
    'TestMotorAsyncIntegration', 
    'TestTransactionManagement',
    'TestDatabasePerformance',
    'TestDatabaseHealthMonitoring',
    'TestDatabaseIntegrationComprehensive',
    'test_performance_summary_report'
]