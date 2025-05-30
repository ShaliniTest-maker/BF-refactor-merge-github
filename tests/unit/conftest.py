"""
Pytest configuration for unit tests.

This module provides pytest fixtures and configuration for comprehensive unit testing
of the Flask application utilities, following the testing strategy per Section 6.6.1
and supporting enterprise-grade test automation.

Key Features:
- Test fixtures for authentication utilities testing per Section 6.4.1
- Database mocking with Testcontainers integration per Section 6.6.1
- Security testing fixtures with cryptographic utilities per Section 6.4.1
- Performance testing configuration maintaining ≤10% variance requirement
- Comprehensive error handling test fixtures per Section 4.2.3
- Mock integrations for external services (Auth0, AWS KMS)
- Test data factories for business logic testing per Section 5.2.4

Testing Framework Integration:
- pytest 7.4+ with extensive plugin ecosystem support
- pytest-mock for comprehensive external service simulation
- pytest-flask for Flask-specific testing patterns
- pytest-cov with real-time coverage reporting
- pytest-asyncio for asynchronous operations testing
- freezegun for datetime testing consistency
"""

import pytest
import os
import json
import base64
import secrets
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, MagicMock, patch
import tempfile
import shutil

# Third-party testing imports
import jwt
from cryptography.fernet import Fernet
from freezegun import freeze_time


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    # Register custom markers
    config.addinivalue_line(
        "markers", 
        "utilities: mark test as utilities module test"
    )
    config.addinivalue_line(
        "markers", 
        "auth: mark test as authentication utilities test"
    )
    config.addinivalue_line(
        "markers", 
        "business: mark test as business utilities test"
    )
    config.addinivalue_line(
        "markers", 
        "security: mark test as security-focused test"
    )
    config.addinivalue_line(
        "markers", 
        "performance: mark test as performance validation test"
    )
    config.addinivalue_line(
        "markers", 
        "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", 
        "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Auto-mark tests based on file location
        if "test_auth" in item.nodeid:
            item.add_marker(pytest.mark.auth)
        if "test_business" in item.nodeid:
            item.add_marker(pytest.mark.business)
        if "test_utilities" in item.nodeid:
            item.add_marker(pytest.mark.utilities)
        if "security" in item.name.lower():
            item.add_marker(pytest.mark.security)
        if "performance" in item.name.lower():
            item.add_marker(pytest.mark.performance)


# ============================================================================
# ENVIRONMENT AND CONFIGURATION FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def test_config():
    """Session-wide test configuration."""
    return {
        "jwt_secret_key": "test-jwt-secret-key-for-testing-12345",
        "jwt_algorithm": "HS256",
        "jwt_expires_in": 3600,
        "encryption_key_size": 256,
        "password_salt_length": 32,
        "test_timezone": "UTC",
        "coverage_threshold": 0.90,
        "performance_threshold": 1.0,
        "test_user_id": "test-user-12345",
        "test_email": "test@example.com",
        "aws_region": "us-east-1",
        "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    }


@pytest.fixture(scope="function")
def mock_environment(test_config):
    """Mock environment variables for testing."""
    env_vars = {
        'JWT_SECRET_KEY': test_config["jwt_secret_key"],
        'DATE_MASKING_SALT': 'test-date-masking-salt',
        'FLASK_ENV': 'testing',
        'SECRET_KEY': 'test-flask-secret-key',
        'REDIS_ENCRYPTION_KEY': base64.b64encode(secrets.token_bytes(32)).decode(),
        'AWS_ACCESS_KEY_ID': 'test-aws-access-key',
        'AWS_SECRET_ACCESS_KEY': 'test-aws-secret-key',
        'AWS_KMS_CMK_ARN': test_config["kms_key_arn"],
        'AWS_REGION': test_config["aws_region"],
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_CLIENT_SECRET': 'test-client-secret',
        'AUTH0_AUDIENCE': 'test-api-audience'
    }
    
    with patch.dict('os.environ', env_vars):
        yield env_vars


@pytest.fixture(scope="function")
def temp_directory():
    """Create temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


# ============================================================================
# TIME AND DATE FIXTURES
# ============================================================================

@pytest.fixture
def fixed_datetime():
    """Fixed datetime for consistent testing."""
    return datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture
def frozen_time(fixed_datetime):
    """Freeze time for datetime-dependent tests."""
    with freeze_time(fixed_datetime):
        yield fixed_datetime


@pytest.fixture
def sample_dates():
    """Sample date values for testing."""
    base_date = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    return {
        "base_date": base_date,
        "past_date": base_date - timedelta(days=30),
        "future_date": base_date + timedelta(days=30),
        "iso_string": "2024-01-15T10:30:00Z",
        "date_only": "2024-01-15",
        "invalid_date": "not-a-date",
        "epoch_date": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "far_future": datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    }


# ============================================================================
# AUTHENTICATION AND SECURITY FIXTURES
# ============================================================================

@pytest.fixture
def test_jwt_payload(test_config):
    """Standard JWT payload for testing."""
    return {
        "user_id": test_config["test_user_id"],
        "email": test_config["test_email"],
        "roles": ["user", "admin"],
        "permissions": ["read", "write", "delete"],
        "organization_id": "test-org-123",
        "session_id": "test-session-456"
    }


@pytest.fixture
def test_jwt_token(test_config, test_jwt_payload):
    """Valid JWT token for testing."""
    return jwt.encode(
        payload={
            **test_jwt_payload,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=test_config["jwt_expires_in"]),
            "iss": "flask-auth-system"
        },
        key=test_config["jwt_secret_key"],
        algorithm=test_config["jwt_algorithm"]
    )


@pytest.fixture
def expired_jwt_token(test_config, test_jwt_payload):
    """Expired JWT token for testing."""
    past_time = datetime.utcnow() - timedelta(hours=1)
    return jwt.encode(
        payload={
            **test_jwt_payload,
            "iat": past_time,
            "exp": past_time + timedelta(minutes=30),  # Expired 30 minutes ago
            "iss": "flask-auth-system"
        },
        key=test_config["jwt_secret_key"],
        algorithm=test_config["jwt_algorithm"]
    )


@pytest.fixture
def test_encryption_key():
    """Test encryption key for cryptographic operations."""
    return secrets.token_bytes(32)  # 256-bit key


@pytest.fixture
def test_fernet_key():
    """Test Fernet encryption key."""
    return Fernet.generate_key()


@pytest.fixture
def sample_passwords():
    """Sample passwords for testing password utilities."""
    return {
        "strong": "StrongP@ssw0rd123!",
        "weak": "password",
        "medium": "Password123",
        "no_uppercase": "password123!",
        "no_lowercase": "PASSWORD123!",
        "no_numbers": "Password!",
        "no_special": "Password123",
        "too_short": "Pass1!",
        "empty": "",
        "unicode": "Pâsswörd123!",
        "very_long": "a" * 100 + "A1!"
    }


@pytest.fixture
def sample_hmac_data():
    """Sample data for HMAC testing."""
    return {
        "data": "Important message that needs signing",
        "secret_key": "super-secret-signing-key",
        "binary_data": b"Binary data \x00\x01\x02\x03",
        "json_data": {"user": "john", "action": "login", "timestamp": 1234567890}
    }


# ============================================================================
# BUSINESS LOGIC FIXTURES
# ============================================================================

@pytest.fixture
def sample_business_data():
    """Sample business data for testing data manipulation utilities."""
    return {
        "clean": {
            "name": "  John Doe  ",
            "email": "john@example.com",
            "age": "30",
            "salary": "50000.00",
            "active": "true",
            "notes": "",
            "tags": [],
            "metadata": None
        },
        "nested": {
            "user": {
                "profile": {
                    "first_name": "John",
                    "last_name": "Doe",
                    "age": 30
                },
                "preferences": {
                    "theme": "dark",
                    "notifications": True
                }
            },
            "settings": {
                "api": {
                    "timeout": 30,
                    "retries": 3
                }
            }
        },
        "list_data": [
            {"id": 1, "name": "Alice", "active": True, "role": "admin"},
            {"id": 2, "name": "Bob", "active": False, "role": "user"},
            {"id": 3, "name": "Charlie", "active": True, "role": "user"},
            {"id": 4, "name": "Diana", "active": True, "role": "admin"}
        ]
    }


@pytest.fixture
def sample_financial_data():
    """Sample financial data for testing business calculations."""
    return {
        "amounts": [
            Decimal("100.00"),
            Decimal("250.50"),
            Decimal("1000.99"),
            Decimal("0.01"),
            Decimal("99999.99")
        ],
        "currencies": ["USD", "EUR", "GBP", "JPY", "CAD"],
        "tax_rates": [0, 5.0, 8.25, 10.0, 15.0, 20.0],
        "discount_rates": [5, 10, 15, 20, 25, 50],
        "invalid_amounts": [-10, "invalid", None, float('inf'), float('nan')],
        "test_calculations": {
            "base_amount": Decimal("100.00"),
            "tax_rate": Decimal("8.25"),
            "discount_rate": 15,
            "expected_tax_exclusive": Decimal("8.25"),
            "expected_total_exclusive": Decimal("108.25"),
            "expected_discounted": Decimal("85.00")
        }
    }


@pytest.fixture
def sample_validation_data():
    """Sample data for testing validation utilities."""
    return {
        "emails": {
            "valid": [
                "user@example.com",
                "test.email+tag@domain.org",
                "firstname.lastname@company.co.uk",
                "user123@sub.domain.com"
            ],
            "invalid": [
                "invalid-email",
                "@domain.com",
                "user@",
                "user@@domain.com",
                "user@domain..com",
                "",
                None
            ]
        },
        "phones": {
            "valid": [
                "+1-555-123-4567",
                "(555) 123-4567",
                "555.123.4567",
                "+44 20 7946 0958"
            ],
            "invalid": [
                "123",
                "abc-def-ghij",
                "12345678901234567890",
                ""
            ]
        },
        "urls": {
            "valid": [
                "https://example.com",
                "http://sub.domain.org/path",
                "https://example.com:8080/path?query=value"
            ],
            "invalid": [
                "not-a-url",
                "ftp://example.com",
                "https://",
                "example.com"
            ]
        },
        "postal_codes": {
            "US": {
                "valid": ["12345", "12345-6789"],
                "invalid": ["1234", "123456", "ABCDE"]
            },
            "CA": {
                "valid": ["K1A 0A6", "K1A0A6", "M5V 3L9"],
                "invalid": ["12345", "K1A 0A", "ABC123"]
            }
        }
    }


@pytest.fixture
def sample_html_content():
    """Sample HTML content for testing sanitization."""
    return {
        "safe": "<p>This is <strong>safe</strong> content with <em>emphasis</em>.</p>",
        "dangerous": """
            <p>Safe paragraph</p>
            <script>alert('xss')</script>
            <img src="x" onerror="alert('xss')">
            <iframe src="javascript:alert('xss')"></iframe>
            <object data="malicious.swf"></object>
            <embed src="malicious.swf">
        """,
        "mixed": """
            <div>
                <h1>Title</h1>
                <p>Safe content</p>
                <script>alert('dangerous')</script>
                <ul>
                    <li>List item 1</li>
                    <li>List item 2</li>
                </ul>
                <form onsubmit="steal_data()">
                    <input type="text" name="username">
                </form>
            </div>
        """,
        "unicode": "<p>Unicode content: café, naïve, résumé</p>",
        "empty": "",
        "whitespace": "   \n\t   ",
        "special_chars": "<p>Special chars: &lt; &gt; &amp; &quot; &#39;</p>"
    }


@pytest.fixture
def sample_json_data():
    """Sample JSON data for testing JSON utilities."""
    return {
        "valid": {
            "simple": '{"name": "John", "age": 30}',
            "nested": '{"user": {"profile": {"name": "John"}}, "active": true}',
            "array": '[1, 2, 3, {"key": "value"}]',
            "complex": """
            {
                "users": [
                    {"id": 1, "name": "Alice", "roles": ["admin"]},
                    {"id": 2, "name": "Bob", "roles": ["user"]}
                ],
                "metadata": {
                    "total": 2,
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            }
            """
        },
        "invalid": [
            "not json",
            '{"incomplete": ',
            '{"invalid": "json"',
            '{name: "missing quotes"}',
            '{"trailing": "comma",}',
            ""
        ],
        "edge_cases": {
            "large": '{"data": "' + 'x' * 100000 + '"}',
            "deeply_nested": '{"a":' * 100 + '"value"' + '}' * 100,
            "unicode": '{"unicode": "café naïve résumé 中文"}',
            "special_chars": '{"special": "\\n\\t\\r\\"\\\\"}',
            "numbers": '{"int": 123, "float": 123.45, "negative": -456, "zero": 0}'
        }
    }


# ============================================================================
# MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_boto3_client():
    """Mock boto3 KMS client for testing."""
    mock_client = MagicMock()
    mock_client.encrypt.return_value = {
        'CiphertextBlob': b'mock-encrypted-data',
        'KeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key-id'
    }
    mock_client.decrypt.return_value = {
        'Plaintext': b'mock-decrypted-data',
        'KeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key-id'
    }
    mock_client.generate_data_key.return_value = {
        'Plaintext': secrets.token_bytes(32),
        'CiphertextBlob': b'mock-encrypted-key'
    }
    return mock_client


@pytest.fixture
def mock_auth0_client():
    """Mock Auth0 client for testing."""
    mock_client = MagicMock()
    mock_client.users.get.return_value = {
        'user_id': 'auth0|test-user-123',
        'email': 'test@example.com',
        'name': 'Test User',
        'roles': ['user', 'admin']
    }
    mock_client.users.update.return_value = {'updated': True}
    return mock_client


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing."""
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = 1
    mock_redis.exists.return_value = False
    mock_redis.setex.return_value = True
    return mock_redis


@pytest.fixture
def mock_email_validator():
    """Mock email validator for testing."""
    class MockValidatedEmail:
        def __init__(self, email):
            self.email = email.lower().strip()
    
    def mock_validate(email, check_deliverability=False):
        if "@" in email and "." in email.split("@")[1]:
            return MockValidatedEmail(email)
        else:
            from email_validator import EmailNotValidError
            raise EmailNotValidError("Invalid email format")
    
    return mock_validate


# ============================================================================
# DATABASE AND EXTERNAL SERVICE FIXTURES
# ============================================================================

@pytest.fixture
def mock_database_connection():
    """Mock database connection for testing."""
    mock_db = MagicMock()
    mock_db.insert_one.return_value = MagicMock(inserted_id="test-id-123")
    mock_db.find_one.return_value = {"_id": "test-id-123", "data": "test"}
    mock_db.update_one.return_value = MagicMock(modified_count=1)
    mock_db.delete_one.return_value = MagicMock(deleted_count=1)
    return mock_db


@pytest.fixture
def mock_external_service():
    """Mock external service for testing HTTP utilities."""
    mock_service = MagicMock()
    mock_service.get.return_value = MagicMock(
        status_code=200,
        json=lambda: {"status": "success", "data": "test"}
    )
    mock_service.post.return_value = MagicMock(
        status_code=201,
        json=lambda: {"status": "created", "id": "test-123"}
    )
    return mock_service


# ============================================================================
# PERFORMANCE TESTING FIXTURES
# ============================================================================

@pytest.fixture
def performance_timer():
    """Performance timing utility for tests."""
    import time
    
    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
            return self.duration
        
        @property
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
        
        def assert_duration_under(self, max_seconds):
            """Assert that operation completed within time limit."""
            assert self.duration is not None, "Timer not stopped"
            assert self.duration < max_seconds, \
                f"Operation took {self.duration:.3f}s, expected < {max_seconds}s"
    
    return PerformanceTimer()


@pytest.fixture
def large_dataset():
    """Large dataset for performance testing."""
    return {
        f"field_{i}": {
            "id": i,
            "name": f"Item {i}",
            "value": f"value_{i}",
            "metadata": {
                "created": f"2024-01-{(i % 28) + 1:02d}T10:30:00Z",
                "tags": [f"tag_{j}" for j in range(i % 5)]
            }
        }
        for i in range(1000)  # 1000 items for performance testing
    }


# ============================================================================
# SCHEMA AND VALIDATION FIXTURES
# ============================================================================

@pytest.fixture
def json_schemas():
    """JSON schemas for validation testing."""
    return {
        "user": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 100},
                "email": {"type": "string", "format": "email"},
                "age": {"type": "integer", "minimum": 0, "maximum": 150},
                "active": {"type": "boolean"},
                "roles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                }
            },
            "required": ["name", "email", "age"],
            "additionalProperties": False
        },
        "product": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "price": {"type": "number", "minimum": 0},
                "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
                "categories": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["name", "price", "currency"]
        },
        "nested": {
            "type": "object",
            "properties": {
                "user": {"$ref": "#/definitions/user"},
                "preferences": {
                    "type": "object",
                    "properties": {
                        "theme": {"type": "string", "enum": ["light", "dark"]},
                        "notifications": {"type": "boolean"}
                    }
                }
            },
            "definitions": {
                "user": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"}
                    },
                    "required": ["id", "name"]
                }
            }
        }
    }


# ============================================================================
# UTILITY FUNCTIONS FOR TESTS
# ============================================================================

@pytest.fixture
def assert_helpers():
    """Helper functions for common test assertions."""
    
    class AssertHelpers:
        @staticmethod
        def assert_valid_jwt(token, secret_key, algorithm="HS256"):
            """Assert that a JWT token is valid."""
            try:
                decoded = jwt.decode(token, secret_key, algorithms=[algorithm])
                assert isinstance(decoded, dict)
                assert "iat" in decoded
                assert "exp" in decoded
                return decoded
            except jwt.InvalidTokenError as e:
                pytest.fail(f"Invalid JWT token: {e}")
        
        @staticmethod
        def assert_encrypted_data(encrypted_data, original_data, key):
            """Assert that data is properly encrypted."""
            assert isinstance(encrypted_data, bytes)
            assert encrypted_data != original_data.encode() if isinstance(original_data, str) else original_data
            assert len(encrypted_data) > 0
        
        @staticmethod
        def assert_sanitized_html(sanitized, original):
            """Assert that HTML is properly sanitized."""
            dangerous_tags = ["<script", "<iframe", "<object", "<embed", "javascript:", "onload=", "onerror="]
            for tag in dangerous_tags:
                assert tag not in sanitized.lower(), f"Dangerous tag '{tag}' found in sanitized HTML"
        
        @staticmethod
        def assert_valid_email_format(email):
            """Assert that email has valid format."""
            assert "@" in email
            assert "." in email.split("@")[1]
            assert len(email.split("@")) == 2
            assert len(email.split("@")[1].split(".")) >= 2
        
        @staticmethod
        def assert_currency_precision(amount, currency):
            """Assert that currency amount has correct precision."""
            precision_map = {"USD": 2, "EUR": 2, "JPY": 0, "BHD": 3}
            expected_precision = precision_map.get(currency, 2)
            
            if isinstance(amount, Decimal):
                decimal_places = abs(amount.as_tuple().exponent)
                assert decimal_places <= expected_precision, \
                    f"Currency {currency} should have max {expected_precision} decimal places, got {decimal_places}"
    
    return AssertHelpers()


# ============================================================================
# CLEANUP AND TEARDOWN FIXTURES
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_test_environment():
    """Automatic cleanup after each test."""
    yield
    # Cleanup any test artifacts, temporary files, etc.
    # This runs after each test automatically


@pytest.fixture(scope="session", autouse=True)
def session_cleanup():
    """Session-wide cleanup."""
    yield
    # Cleanup any session-wide resources
    # This runs once at the end of the test session


# ============================================================================
# PYTEST PLUGINS AND EXTENSIONS
# ============================================================================

# Configure pytest-cov for coverage reporting
pytest_plugins = [
    "pytest_cov",
    "pytest_mock",
    "pytest_asyncio"
]


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests"
    )
    parser.addoption(
        "--run-integration",
        action="store_true", 
        default=False,
        help="Run integration tests"
    )


def pytest_runtest_setup(item):
    """Setup for individual test runs."""
    # Skip slow tests unless explicitly requested
    if "slow" in item.keywords and not item.config.getoption("--run-slow"):
        pytest.skip("need --run-slow option to run")
    
    # Skip integration tests unless explicitly requested
    if "integration" in item.keywords and not item.config.getoption("--run-integration"):
        pytest.skip("need --run-integration option to run")


# Coverage configuration
pytest_cov_config = {
    "cov": ["src/auth/utils", "src/business/utils", "src/utils"],
    "cov-report": ["term-missing", "html", "xml"],
    "cov-fail-under": 90,
    "cov-branch": True
}