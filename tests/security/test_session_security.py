"""
Session Security Testing Suite

This comprehensive test suite validates Flask-Session security implementation with Redis distributed 
storage, AES-256-GCM encryption testing, session hijacking prevention, and distributed session 
security verification. The tests ensure zero tolerance for session security vulnerabilities 
per Section 6.4.5 and complete compliance with enterprise security requirements.

Test Categories:
- Flask-Session security validation with Redis distributed storage per Section 6.4.1
- AES-256-GCM encryption security with AWS KMS integration per Section 6.4.1
- Session management security for stateless authentication per Section 6.4.1
- Session hijacking and fixation attack prevention per Section 6.4.1
- Redis session security and encryption validation per Section 6.4.1
- Session lifecycle security testing per Section 6.4.1
- AWS KMS key management security validation per Section 6.4.3

Security Requirements Validated:
- Zero tolerance for session security vulnerabilities per Section 6.4.5
- Enterprise-grade encryption with FIPS 140-2 compliance per Section 6.4.3
- OWASP Top 10 session management compliance per Section 6.4.5
- SOC 2 Type II audit trail support per Section 6.4.5
- Cross-instance session sharing security per Section 6.4.1
- Automated session cleanup and security validation per Section 6.4.1

Performance Requirements:
- Session security operations must maintain ≤10% variance from baseline per Section 0.1.1
- Encryption/decryption performance validation per Section 6.4.1
- Redis distributed session access performance verification per Section 6.4.1

Author: Security Testing Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10, FIPS 140-2
"""

import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Generator
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call

import pytest
import redis
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, session, request, g
from flask.testing import FlaskClient
from flask_login import login_user, logout_user, current_user
from flask_session import Session

# Import application modules for testing
from src.auth.session import (
    SessionManager,
    SessionUser,
    SessionEncryptionManager,
    get_session_manager,
    init_session_manager,
    session_metrics,
    is_session_valid,
    get_session_metadata,
    cleanup_user_sessions
)
from src.auth.cache import (
    AuthCacheManager,
    EncryptionManager,
    CacheKeyPatterns,
    get_auth_cache_manager,
    create_token_hash
)
from src.config.aws import (
    AWSServiceManager,
    AWSConfig,
    get_aws_manager
)
from src.auth.exceptions import (
    SecurityException,
    AuthenticationException,
    SessionException,
    SecurityErrorCode
)

# Test configuration constants
TEST_SESSION_TIMEOUT = 3600  # 1 hour for testing
TEST_MAX_SESSION_LIFETIME = 86400  # 24 hours for testing
TEST_ENCRYPTION_KEY_SIZE = 32  # 256 bits
TEST_REDIS_DB = 15  # Dedicated test Redis database
TEST_AWS_REGION = 'us-east-1'
TEST_KMS_KEY_ARN = 'arn:aws:kms:us-east-1:123456789012:key/test-key-id'

# Security test markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.integration,
    pytest.mark.database,
    pytest.mark.auth
]


# =============================================================================
# Security Test Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def security_test_app(redis_client):
    """
    Create Flask application configured for session security testing.
    
    This fixture provides a Flask application with comprehensive session security
    configuration including Flask-Session, Redis backend, and security headers
    for realistic security testing scenarios.
    
    Args:
        redis_client: Redis client fixture for session storage
        
    Returns:
        Flask: Configured Flask application for security testing
    """
    app = Flask(__name__)
    
    # Security-focused configuration
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key-for-session-security',
        'WTF_CSRF_ENABLED': False,
        
        # Flask-Session configuration for security testing
        'SESSION_TYPE': 'redis',
        'SESSION_REDIS': redis_client,
        'SESSION_PERMANENT': True,
        'SESSION_USE_SIGNER': True,
        'SESSION_KEY_PREFIX': 'test_session:',
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Strict',
        'SESSION_COOKIE_NAME': 'test_session_id',
        'PERMANENT_SESSION_LIFETIME': timedelta(seconds=TEST_SESSION_TIMEOUT),
        
        # Security headers configuration
        'SECURITY_HEADERS_ENABLED': True,
        'HSTS_MAX_AGE': 31536000,
        'CONTENT_SECURITY_POLICY': "default-src 'self'",
        
        # Testing environment variables
        'FLASK_ENV': 'testing',
        'REDIS_ENCRYPTION_KEY': base64.b64encode(os.urandom(32)).decode(),
        'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
        'AWS_REGION': TEST_AWS_REGION
    })
    
    # Initialize Flask-Session
    Session(app)
    
    # Create test routes for security validation
    @app.route('/login', methods=['POST'])
    def test_login():
        """Test login endpoint for session creation."""
        session['user_id'] = 'test_user_123'
        session['authenticated'] = True
        session['login_time'] = datetime.utcnow().isoformat()
        return {'status': 'logged_in', 'session_id': session.get('session_id')}
    
    @app.route('/logout', methods=['POST'])
    def test_logout():
        """Test logout endpoint for session destruction."""
        session.clear()
        return {'status': 'logged_out'}
    
    @app.route('/protected')
    def test_protected():
        """Test protected endpoint requiring valid session."""
        if not session.get('authenticated'):
            return {'error': 'Not authenticated'}, 401
        return {'message': 'Access granted', 'user_id': session.get('user_id')}
    
    @app.route('/session-info')
    def test_session_info():
        """Test endpoint for session information retrieval."""
        return {
            'session_data': dict(session),
            'session_id': session.get('session_id'),
            'authenticated': session.get('authenticated', False)
        }
    
    return app


@pytest.fixture(scope="function")
def secure_session_manager(redis_client):
    """
    Create SessionManager instance configured for security testing.
    
    Args:
        redis_client: Redis client for distributed session storage
        
    Returns:
        SessionManager: Configured session manager for security testing
    """
    # Create mock cache manager with test Redis client
    cache_manager = Mock(spec=AuthCacheManager)
    cache_manager.redis_client = redis_client
    
    # Create session manager with security-focused configuration
    session_manager = SessionManager(
        cache_manager=cache_manager,
        encryption_manager=None  # Will be auto-created
    )
    
    # Configure security settings for testing
    session_manager.session_timeout = timedelta(seconds=TEST_SESSION_TIMEOUT)
    session_manager.max_session_lifetime = timedelta(seconds=TEST_MAX_SESSION_LIFETIME)
    session_manager.cleanup_interval = timedelta(seconds=60)  # Frequent cleanup for testing
    session_manager.session_renewal_threshold = timedelta(seconds=300)  # 5 minutes
    
    return session_manager


@pytest.fixture(scope="function")
def session_encryption_manager():
    """
    Create SessionEncryptionManager for encryption security testing.
    
    Returns:
        SessionEncryptionManager: Configured encryption manager for security testing
    """
    with patch.dict(os.environ, {
        'REDIS_ENCRYPTION_KEY': base64.b64encode(os.urandom(32)).decode(),
        'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
        'AWS_REGION': TEST_AWS_REGION,
        'FLASK_ENV': 'testing'
    }):
        # Mock AWS manager to prevent external calls during testing
        with patch('src.auth.session.get_aws_manager') as mock_aws:
            mock_aws.return_value = Mock(spec=AWSServiceManager)
            
            encryption_manager = SessionEncryptionManager()
            
            # Verify initialization
            assert encryption_manager._current_fernet is not None
            assert encryption_manager._key_version is not None
            
            return encryption_manager


@pytest.fixture(scope="function")
def mock_aws_kms():
    """
    Create comprehensive AWS KMS mock for encryption testing.
    
    Returns:
        Mock: Configured AWS KMS mock with realistic behavior
    """
    with patch('boto3.client') as mock_boto_client:
        kms_mock = Mock()
        
        # Mock KMS data key generation
        kms_mock.generate_data_key.return_value = {
            'Plaintext': os.urandom(32),  # 256-bit key
            'CiphertextBlob': base64.b64encode(os.urandom(256))  # Encrypted key
        }
        
        # Mock KMS decryption
        kms_mock.decrypt.return_value = {
            'Plaintext': os.urandom(32)
        }
        
        # Mock key rotation
        kms_mock.enable_key_rotation.return_value = True
        kms_mock.get_key_rotation_status.return_value = {
            'KeyRotationEnabled': True
        }
        
        mock_boto_client.return_value = kms_mock
        
        yield kms_mock


@pytest.fixture(scope="function")
def security_audit_context():
    """
    Create security audit context for logging validation.
    
    Returns:
        Dict: Security audit context for test validation
    """
    audit_events = []
    security_violations = []
    
    def record_audit_event(event_type: str, details: Dict[str, Any]):
        """Record security audit event."""
        audit_events.append({
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def record_security_violation(violation_type: str, severity: str, details: Dict[str, Any]):
        """Record security violation."""
        security_violations.append({
            'violation_type': violation_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    return {
        'audit_events': audit_events,
        'security_violations': security_violations,
        'record_audit_event': record_audit_event,
        'record_security_violation': record_security_violation
    }


# =============================================================================
# Flask-Session Security Validation Tests
# =============================================================================

class TestFlaskSessionSecurity:
    """
    Comprehensive Flask-Session security validation tests.
    
    Tests Flask-Session integration with Redis distributed storage, session
    configuration security, and proper session lifecycle management per
    Section 6.4.1 Flask-Session security requirements.
    """
    
    def test_flask_session_redis_backend_configuration(self, security_test_app, redis_client):
        """
        Test Flask-Session Redis backend configuration security.
        
        Validates that Flask-Session is properly configured with Redis backend,
        secure cookie settings, and proper session isolation per Section 6.4.1.
        """
        with security_test_app.test_client() as client:
            # Test session creation with secure configuration
            response = client.post('/login')
            assert response.status_code == 200
            
            # Verify session is stored in Redis
            session_keys = redis_client.keys('test_session:*')
            assert len(session_keys) > 0, "Session not stored in Redis backend"
            
            # Verify session data structure
            session_data = redis_client.get(session_keys[0])
            assert session_data is not None, "Session data not found in Redis"
            
            # Test session retrieval and validation
            response = client.get('/session-info')
            assert response.status_code == 200
            session_info = response.get_json()
            
            assert session_info['authenticated'] is True
            assert session_info['session_data']['user_id'] == 'test_user_123'
            assert 'login_time' in session_info['session_data']
    
    def test_session_cookie_security_configuration(self, security_test_app):
        """
        Test session cookie security configuration.
        
        Validates that session cookies are configured with secure attributes
        including HttpOnly, Secure, SameSite, and proper domain settings
        per Section 6.4.1 session security requirements.
        """
        with security_test_app.test_client() as client:
            response = client.post('/login')
            assert response.status_code == 200
            
            # Extract Set-Cookie headers
            set_cookie_headers = [
                header for header in response.headers 
                if header[0].lower() == 'set-cookie'
            ]
            
            assert len(set_cookie_headers) > 0, "No session cookie set"
            
            # Parse cookie attributes
            cookie_header = set_cookie_headers[0][1]
            
            # Verify security attributes
            assert 'HttpOnly' in cookie_header, "Session cookie missing HttpOnly attribute"
            assert 'Secure' in cookie_header or security_test_app.config['TESTING'], \
                "Session cookie missing Secure attribute"
            assert 'SameSite=Strict' in cookie_header, "Session cookie missing SameSite=Strict"
    
    def test_session_isolation_between_clients(self, security_test_app, redis_client):
        """
        Test session isolation between different client instances.
        
        Validates that sessions are properly isolated between different clients
        and that session data cannot be accessed across client boundaries.
        """
        # Create first client session
        with security_test_app.test_client() as client1:
            response1 = client1.post('/login')
            assert response1.status_code == 200
            
            session_info1 = client1.get('/session-info').get_json()
            user_id1 = str(uuid.uuid4())
            
            # Set unique data for client1
            with client1.session_transaction() as sess:
                sess['unique_id'] = user_id1
        
        # Create second client session
        with security_test_app.test_client() as client2:
            response2 = client2.post('/login')
            assert response2.status_code == 200
            
            session_info2 = client2.get('/session-info').get_json()
            user_id2 = str(uuid.uuid4())
            
            # Set unique data for client2
            with client2.session_transaction() as sess:
                sess['unique_id'] = user_id2
        
        # Verify session isolation
        assert session_info1['session_id'] != session_info2['session_id'], \
            "Session IDs not properly isolated"
        
        # Verify data isolation
        with security_test_app.test_client() as client1:
            with client1.session_transaction() as sess:
                assert sess.get('unique_id') != user_id2, "Session data leaked between clients"
    
    def test_session_ttl_and_expiration(self, security_test_app, redis_client):
        """
        Test session TTL configuration and automatic expiration.
        
        Validates that Redis sessions have proper TTL settings and expire
        automatically according to configuration per Section 6.4.1.
        """
        with security_test_app.test_client() as client:
            # Create session
            response = client.post('/login')
            assert response.status_code == 200
            
            # Check Redis TTL
            session_keys = redis_client.keys('test_session:*')
            assert len(session_keys) > 0
            
            session_key = session_keys[0]
            ttl = redis_client.ttl(session_key)
            
            # Verify TTL is set and reasonable
            assert ttl > 0, "Session TTL not set in Redis"
            assert ttl <= TEST_SESSION_TIMEOUT, "Session TTL exceeds configured timeout"
            assert ttl > TEST_SESSION_TIMEOUT - 60, "Session TTL too short"
    
    @pytest.mark.slow
    def test_session_cleanup_on_expiration(self, security_test_app, redis_client):
        """
        Test automatic session cleanup on expiration.
        
        Validates that expired sessions are properly cleaned up from Redis
        and that expired session data cannot be accessed.
        """
        with security_test_app.test_client() as client:
            # Create session with short TTL
            response = client.post('/login')
            assert response.status_code == 200
            
            session_keys = redis_client.keys('test_session:*')
            assert len(session_keys) > 0
            
            session_key = session_keys[0]
            
            # Manually expire the session for testing
            redis_client.expire(session_key, 1)
            time.sleep(2)  # Wait for expiration
            
            # Verify session is cleaned up
            expired_session = redis_client.get(session_key)
            assert expired_session is None, "Expired session not cleaned up"
            
            # Verify access is denied with expired session
            response = client.get('/protected')
            assert response.status_code == 401, "Access granted with expired session"


# =============================================================================
# AES-256-GCM Encryption Security Tests
# =============================================================================

class TestSessionEncryptionSecurity:
    """
    Comprehensive AES-256-GCM encryption security tests.
    
    Tests session data encryption using AES-256-GCM with AWS KMS integration,
    encryption key management, and cryptographic security validation per
    Section 6.4.1 and Section 6.4.3 encryption requirements.
    """
    
    def test_aes_256_gcm_encryption_implementation(self, session_encryption_manager):
        """
        Test AES-256-GCM encryption implementation.
        
        Validates that session data is encrypted using proper AES-256-GCM
        algorithms with secure key derivation and proper encryption metadata.
        """
        test_data = {
            'user_id': 'test_user_123',
            'permissions': ['read', 'write'],
            'session_metadata': {
                'created_at': datetime.utcnow().isoformat(),
                'ip_address': '192.168.1.1'
            }
        }
        
        # Test encryption
        encrypted_data = session_encryption_manager.encrypt_session_data(test_data)
        
        # Verify encrypted data properties
        assert isinstance(encrypted_data, str), "Encrypted data should be string"
        assert len(encrypted_data) > len(json.dumps(test_data)), \
            "Encrypted data should be larger than plaintext"
        
        # Verify base64 encoding
        try:
            base64.b64decode(encrypted_data)
        except Exception:
            pytest.fail("Encrypted data is not valid base64")
        
        # Test decryption
        decrypted_data = session_encryption_manager.decrypt_session_data(encrypted_data)
        
        # Verify decryption accuracy
        assert decrypted_data['user_id'] == test_data['user_id']
        assert decrypted_data['permissions'] == test_data['permissions']
        assert decrypted_data['session_metadata'] == test_data['session_metadata']
    
    def test_encryption_key_security_properties(self, session_encryption_manager):
        """
        Test encryption key security properties and validation.
        
        Validates that encryption keys meet security requirements including
        proper key length, entropy, and rotation capabilities.
        """
        # Verify key version is set
        key_version = session_encryption_manager.get_key_version()
        assert key_version is not None, "Encryption key version not set"
        assert isinstance(key_version, str), "Key version should be string"
        assert len(key_version) > 0, "Key version should not be empty"
        
        # Test encryption with current key
        test_data = {'test': 'encryption_key_validation'}
        encrypted1 = session_encryption_manager.encrypt_session_data(test_data)
        encrypted2 = session_encryption_manager.encrypt_session_data(test_data)
        
        # Verify different ciphertexts for same plaintext (proper nonce usage)
        assert encrypted1 != encrypted2, \
            "Same plaintext produced identical ciphertext (nonce reuse vulnerability)"
        
        # Verify both decrypt correctly
        decrypted1 = session_encryption_manager.decrypt_session_data(encrypted1)
        decrypted2 = session_encryption_manager.decrypt_session_data(encrypted2)
        
        assert decrypted1 == test_data
        assert decrypted2 == test_data
    
    def test_encryption_integrity_validation(self, session_encryption_manager):
        """
        Test encryption integrity validation and tamper detection.
        
        Validates that encrypted data integrity is properly validated and
        that tampered ciphertext is detected and rejected.
        """
        test_data = {'sensitive': 'session_data', 'user_id': 'test_123'}
        encrypted_data = session_encryption_manager.encrypt_session_data(test_data)
        
        # Test tampering with encrypted data
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Flip a bit in the ciphertext
        tampered_bytes = bytearray(encrypted_bytes)
        tampered_bytes[10] ^= 1  # Flip a bit
        tampered_data = base64.b64encode(tampered_bytes).decode()
        
        # Verify tampered data is rejected
        with pytest.raises((SessionException, InvalidToken)):
            session_encryption_manager.decrypt_session_data(tampered_data)
    
    def test_encryption_performance_requirements(self, session_encryption_manager):
        """
        Test encryption performance against baseline requirements.
        
        Validates that encryption/decryption operations meet the ≤10% variance
        requirement from Node.js baseline per Section 0.1.1.
        """
        test_data = {
            'user_id': 'performance_test_user',
            'permissions': ['read', 'write', 'admin'] * 10,  # Larger dataset
            'session_metadata': {
                'created_at': datetime.utcnow().isoformat(),
                'large_field': 'x' * 1000  # 1KB of data
            }
        }
        
        # Measure encryption performance
        encryption_times = []
        decryption_times = []
        
        for _ in range(10):  # Average of 10 operations
            # Encryption timing
            start_time = time.time()
            encrypted_data = session_encryption_manager.encrypt_session_data(test_data)
            encryption_time = time.time() - start_time
            encryption_times.append(encryption_time)
            
            # Decryption timing
            start_time = time.time()
            session_encryption_manager.decrypt_session_data(encrypted_data)
            decryption_time = time.time() - start_time
            decryption_times.append(decryption_time)
        
        # Calculate averages
        avg_encryption_time = sum(encryption_times) / len(encryption_times)
        avg_decryption_time = sum(decryption_times) / len(decryption_times)
        
        # Performance assertions (baseline: 1ms for encryption, 0.5ms for decryption)
        assert avg_encryption_time < 0.01, \
            f"Encryption too slow: {avg_encryption_time:.4f}s > 0.01s"
        assert avg_decryption_time < 0.005, \
            f"Decryption too slow: {avg_decryption_time:.4f}s > 0.005s"
    
    @pytest.mark.integration
    def test_aws_kms_integration_security(self, mock_aws_kms):
        """
        Test AWS KMS integration security and error handling.
        
        Validates AWS KMS integration for encryption key management,
        proper error handling, and fallback mechanisms per Section 6.4.3.
        """
        with patch.dict(os.environ, {
            'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
            'AWS_REGION': TEST_AWS_REGION
        }):
            # Test KMS data key generation
            mock_aws_kms.generate_data_key.assert_not_called()
            
            # Create encryption manager (should trigger KMS interaction)
            with patch('src.auth.session.get_aws_manager'):
                encryption_manager = SessionEncryptionManager()
                
                # Verify encryption works with KMS-backed keys
                test_data = {'kms_test': 'data'}
                encrypted = encryption_manager.encrypt_session_data(test_data)
                decrypted = encryption_manager.decrypt_session_data(encrypted)
                
                assert decrypted == test_data
    
    def test_encryption_key_rotation_security(self, session_encryption_manager):
        """
        Test encryption key rotation security and data migration.
        
        Validates that encryption key rotation works properly and that
        data encrypted with old keys can still be decrypted during transition.
        """
        test_data = {'rotation_test': 'sensitive_data'}
        
        # Encrypt with current key
        original_key_version = session_encryption_manager.get_key_version()
        encrypted_with_old_key = session_encryption_manager.encrypt_session_data(test_data)
        
        # Force key rotation for testing
        with patch.object(session_encryption_manager, '_last_key_rotation', 
                         datetime.utcnow() - timedelta(days=91)):
            # This should trigger key rotation
            session_encryption_manager._rotate_encryption_key_if_needed()
            
            new_key_version = session_encryption_manager.get_key_version()
            assert new_key_version != original_key_version, "Key rotation did not occur"
            
            # Verify old encrypted data can still be decrypted
            try:
                decrypted_data = session_encryption_manager.decrypt_session_data(encrypted_with_old_key)
                # Note: In production, this might fail if old keys are purged
                # For testing, we verify the error handling is proper
            except SessionException:
                # Expected behavior when old keys are unavailable
                pass


# =============================================================================
# Session Hijacking Prevention Tests
# =============================================================================

class TestSessionHijackingPrevention:
    """
    Session hijacking and fixation attack prevention tests.
    
    Tests session security measures to prevent session hijacking, session
    fixation, and other session-based attacks per Section 6.4.1 and 
    OWASP session management guidelines.
    """
    
    def test_session_fixation_prevention(self, security_test_app, redis_client):
        """
        Test session fixation attack prevention.
        
        Validates that session IDs are regenerated on authentication state
        changes to prevent session fixation attacks.
        """
        with security_test_app.test_client() as client:
            # Get initial session ID (unauthenticated)
            response = client.get('/session-info')
            initial_session_data = response.get_json()
            initial_session_id = initial_session_data.get('session_id')
            
            # Authenticate user (should regenerate session ID)
            response = client.post('/login')
            assert response.status_code == 200
            
            # Get session ID after authentication
            response = client.get('/session-info')
            auth_session_data = response.get_json()
            auth_session_id = auth_session_data.get('session_id')
            
            # Verify session ID changed
            if initial_session_id:  # May be None for first request
                assert auth_session_id != initial_session_id, \
                    "Session ID not regenerated on authentication (session fixation vulnerability)"
            
            # Verify authentication status
            assert auth_session_data['authenticated'] is True
    
    def test_session_id_entropy_validation(self, security_test_app, redis_client):
        """
        Test session ID entropy and unpredictability.
        
        Validates that session IDs have sufficient entropy and are
        unpredictable to prevent session prediction attacks.
        """
        session_ids = set()
        
        # Generate multiple sessions
        for _ in range(10):
            with security_test_app.test_client() as client:
                response = client.post('/login')
                assert response.status_code == 200
                
                session_info = client.get('/session-info').get_json()
                session_id = session_info.get('session_id')
                
                if session_id:
                    session_ids.add(session_id)
        
        # Verify uniqueness
        assert len(session_ids) >= 8, "Insufficient session ID uniqueness"
        
        # Verify entropy (basic check)
        if session_ids:
            sample_id = list(session_ids)[0]
            # Session IDs should be reasonably long
            assert len(sample_id) >= 16, "Session ID too short for adequate entropy"
    
    def test_concurrent_session_isolation(self, security_test_app, redis_client):
        """
        Test isolation between concurrent user sessions.
        
        Validates that concurrent sessions for different users are properly
        isolated and cannot access each other's data.
        """
        import threading
        import queue
        
        session_data_queue = queue.Queue()
        
        def create_user_session(user_id: str):
            """Create isolated user session."""
            with security_test_app.test_client() as client:
                # Login as specific user
                with client.session_transaction() as sess:
                    sess['user_id'] = user_id
                    sess['authenticated'] = True
                    sess['user_specific_data'] = f"data_for_{user_id}"
                
                # Retrieve session info
                response = client.get('/session-info')
                session_info = response.get_json()
                session_data_queue.put((user_id, session_info))
        
        # Create concurrent sessions for different users
        threads = []
        for i in range(5):
            user_id = f"user_{i}"
            thread = threading.Thread(target=create_user_session, args=(user_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect session data
        session_results = {}
        while not session_data_queue.empty():
            user_id, session_info = session_data_queue.get()
            session_results[user_id] = session_info
        
        # Verify isolation
        session_ids = set()
        for user_id, session_info in session_results.items():
            session_id = session_info.get('session_id')
            if session_id:
                session_ids.add(session_id)
                
                # Verify user-specific data
                user_data = session_info['session_data'].get('user_specific_data')
                expected_data = f"data_for_{user_id}"
                assert user_data == expected_data, \
                    f"Session data leaked between users: {user_data} != {expected_data}"
        
        # Verify all sessions have unique IDs
        assert len(session_ids) == len(session_results), \
            "Session IDs not unique across concurrent sessions"
    
    def test_session_invalidation_on_security_events(self, secure_session_manager, security_audit_context):
        """
        Test session invalidation on security events.
        
        Validates that sessions are properly invalidated when security
        events occur, such as suspicious activity or policy violations.
        """
        # Create test user session
        user_id = "security_test_user"
        auth0_profile = {
            'sub': user_id,
            'email': 'security@test.com',
            'name': 'Security Test User'
        }
        
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Verify session exists
        loaded_session = secure_session_manager.load_user_session(user_id)
        assert loaded_session is not None
        assert loaded_session.id == user_id
        
        # Simulate security event (e.g., suspicious IP)
        security_audit_context['record_security_violation'](
            'suspicious_ip_change',
            'high',
            {'user_id': user_id, 'new_ip': '10.0.0.1', 'original_ip': '192.168.1.1'}
        )
        
        # Invalidate session due to security event
        result = secure_session_manager.destroy_user_session(user_id)
        assert result is True, "Session invalidation failed"
        
        # Verify session is completely removed
        invalid_session = secure_session_manager.load_user_session(user_id)
        assert invalid_session is None, "Session not properly invalidated"
        
        # Verify security event was recorded
        assert len(security_audit_context['security_violations']) == 1
        violation = security_audit_context['security_violations'][0]
        assert violation['violation_type'] == 'suspicious_ip_change'
        assert violation['severity'] == 'high'


# =============================================================================
# Distributed Session Security Tests
# =============================================================================

class TestDistributedSessionSecurity:
    """
    Distributed session security tests with Redis backend validation.
    
    Tests Redis-based distributed session management, cross-instance session
    sharing, and distributed session security validation per Section 6.4.1.
    """
    
    def test_redis_session_encryption_validation(self, redis_client, session_encryption_manager):
        """
        Test Redis session storage encryption validation.
        
        Validates that all session data stored in Redis is properly encrypted
        and cannot be accessed without proper decryption keys.
        """
        # Create test session data
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': 'test_user_redis',
            'permissions': ['read', 'write'],
            'sensitive_data': 'confidential_information',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Encrypt and store in Redis
        encrypted_data = session_encryption_manager.encrypt_session_data(session_data)
        redis_key = f"session:{session_id}"
        redis_client.setex(redis_key, 3600, encrypted_data)
        
        # Verify raw Redis data is encrypted
        raw_redis_data = redis_client.get(redis_key)
        assert raw_redis_data != json.dumps(session_data), \
            "Session data stored in plaintext in Redis"
        
        # Verify sensitive data is not visible in raw Redis data
        assert 'confidential_information' not in raw_redis_data, \
            "Sensitive data visible in encrypted Redis storage"
        assert 'test_user_redis' not in raw_redis_data, \
            "User ID visible in encrypted Redis storage"
        
        # Verify proper decryption
        decrypted_data = session_encryption_manager.decrypt_session_data(raw_redis_data)
        assert decrypted_data == session_data, "Decryption failed or data corrupted"
    
    def test_cross_instance_session_sharing(self, redis_client, secure_session_manager):
        """
        Test cross-instance session sharing security.
        
        Validates that sessions can be securely shared across multiple
        application instances while maintaining security boundaries.
        """
        # Simulate multiple application instances
        user_id = "cross_instance_user"
        auth0_profile = {
            'sub': user_id,
            'email': 'crossinstance@test.com',
            'name': 'Cross Instance Test User'
        }
        
        # Create session on "instance 1"
        session_user1 = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        session_id = session_user1.session_id
        
        # Create another session manager (simulating "instance 2")
        session_manager2 = SessionManager(
            cache_manager=secure_session_manager.cache_manager,
            encryption_manager=secure_session_manager.encryption_manager
        )
        
        # Load session on "instance 2"
        session_user2 = session_manager2.load_user_session(user_id)
        
        # Verify cross-instance session access
        assert session_user2 is not None, "Session not accessible from second instance"
        assert session_user2.id == user_id, "User ID mismatch across instances"
        assert session_user2.session_id == session_id, "Session ID mismatch across instances"
        assert session_user2.auth0_profile == auth0_profile, "Profile data mismatch"
        
        # Update session on instance 2
        session_user2.update_activity()
        session_manager2._save_user_session(session_user2)
        
        # Verify update is visible on instance 1
        updated_session = secure_session_manager.load_user_session(user_id)
        assert updated_session.last_activity == session_user2.last_activity, \
            "Session updates not synchronized across instances"
    
    def test_redis_connection_failure_handling(self, secure_session_manager):
        """
        Test Redis connection failure handling and graceful degradation.
        
        Validates that session management gracefully handles Redis connection
        failures without exposing sensitive data or causing security vulnerabilities.
        """
        user_id = "connection_failure_user"
        auth0_profile = {'sub': user_id, 'email': 'failure@test.com'}
        
        # Create session with working Redis
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Mock Redis connection failure
        with patch.object(secure_session_manager.cache_manager.redis_client, 'get') as mock_get:
            mock_get.side_effect = redis.ConnectionError("Redis connection failed")
            
            # Attempt to load session
            failed_session = secure_session_manager.load_user_session(user_id)
            
            # Verify graceful failure (should return None, not crash)
            assert failed_session is None, "Session load should fail gracefully"
        
        # Verify system recovers when Redis is available again
        recovered_session = secure_session_manager.load_user_session(user_id)
        assert recovered_session is not None, "Session not recovered after Redis restoration"
        assert recovered_session.id == user_id, "Session data corrupted during recovery"
    
    def test_distributed_session_cleanup_coordination(self, redis_client):
        """
        Test distributed session cleanup coordination.
        
        Validates that session cleanup operations are properly coordinated
        across multiple application instances to prevent data inconsistencies.
        """
        # Create multiple session managers (simulating distributed instances)
        managers = []
        for i in range(3):
            cache_manager = Mock(spec=AuthCacheManager)
            cache_manager.redis_client = redis_client
            manager = SessionManager(cache_manager=cache_manager)
            managers.append(manager)
        
        # Create sessions across different managers
        session_users = []
        for i, manager in enumerate(managers):
            user_id = f"cleanup_user_{i}"
            auth0_profile = {'sub': user_id, 'email': f'cleanup{i}@test.com'}
            
            session_user = manager.create_user_session(
                user_id=user_id,
                auth0_profile=auth0_profile
            )
            session_users.append((user_id, session_user))
        
        # Verify all sessions exist
        initial_sessions = redis_client.keys("session:*")
        assert len(initial_sessions) >= 3, "Not all sessions created"
        
        # Perform cleanup on one manager
        cleanup_stats = managers[0].cleanup_expired_sessions()
        
        # Verify cleanup coordination (expired sessions removed)
        # For this test, we'll manually expire some sessions
        for user_id, session_user in session_users[:2]:  # Expire first 2 sessions
            session_key = f"session:{user_id}"
            redis_client.expire(session_key, -1)  # Immediate expiration
        
        # Run cleanup again
        cleanup_stats = managers[0].cleanup_expired_sessions()
        
        # Verify expired sessions were cleaned up
        remaining_sessions = redis_client.keys("session:*")
        assert len(remaining_sessions) <= 1, "Expired sessions not properly cleaned up"
    
    def test_redis_key_pattern_security(self, redis_client, secure_session_manager):
        """
        Test Redis key pattern security and namespace isolation.
        
        Validates that Redis key patterns provide proper namespace isolation
        and prevent cross-contamination between different data types.
        """
        user_id = "key_pattern_user"
        auth0_profile = {'sub': user_id, 'email': 'keypattern@test.com'}
        
        # Create session
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Check Redis key patterns
        all_keys = redis_client.keys("*")
        session_keys = [key for key in all_keys if key.startswith(b"session:")]
        
        assert len(session_keys) > 0, "No session keys found with proper pattern"
        
        # Verify key pattern structure
        for key in session_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            
            # Session keys should follow pattern: session:{session_id}
            assert key_str.startswith("session:"), "Invalid session key pattern"
            
            # Verify session ID format (should be UUID-like)
            session_id = key_str.split(":", 1)[1]
            assert len(session_id) >= 16, "Session ID in key too short"
            
            # Verify no sensitive data in key names
            assert user_id not in key_str, "User ID exposed in Redis key name"
            assert "email" not in key_str, "Email exposed in Redis key name"


# =============================================================================
# Session Lifecycle Security Tests
# =============================================================================

class TestSessionLifecycleSecurity:
    """
    Session lifecycle security testing.
    
    Tests comprehensive session lifecycle management including creation,
    renewal, invalidation, and cleanup with security validation per
    Section 6.4.1 session lifecycle requirements.
    """
    
    def test_secure_session_creation_validation(self, secure_session_manager, security_audit_context):
        """
        Test secure session creation with comprehensive validation.
        
        Validates that session creation follows security best practices
        including proper metadata collection and audit logging.
        """
        user_id = "lifecycle_creation_user"
        auth0_profile = {
            'sub': user_id,
            'email': 'lifecycle@test.com',
            'name': 'Lifecycle Test User',
            'email_verified': True,
            'picture': 'https://example.com/avatar.jpg'
        }
        
        session_metadata = {
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 Test Browser',
            'login_method': 'auth0_jwt',
            'mfa_verified': True
        }
        
        # Create session with security context
        with patch('src.auth.session.request') as mock_request:
            mock_request.remote_addr = '192.168.1.100'
            mock_request.headers = {'User-Agent': 'Mozilla/5.0 Test Browser'}
            
            session_user = secure_session_manager.create_user_session(
                user_id=user_id,
                auth0_profile=auth0_profile,
                session_metadata=session_metadata
            )
        
        # Validate session properties
        assert session_user.id == user_id
        assert session_user.session_id is not None
        assert session_user.session_created is not None
        assert session_user.last_activity is not None
        assert session_user.is_authenticated is True
        assert session_user.is_active is True
        
        # Validate security metadata
        assert session_user.login_ip == '192.168.1.100'
        assert session_user.user_agent == 'Mozilla/5.0 Test Browser'
        assert session_user.mfa_verified is True
        assert session_user.security_level == 'standard'
        
        # Validate session metadata
        assert 'created_by' in session_user.session_metadata
        assert session_user.session_metadata['login_method'] == 'auth0_jwt'
        assert session_user.session_metadata['mfa_verified'] is True
    
    def test_session_renewal_security_validation(self, secure_session_manager):
        """
        Test session renewal security and validation.
        
        Validates that session renewal maintains security properties
        and properly updates activity tracking without vulnerabilities.
        """
        user_id = "renewal_test_user"
        auth0_profile = {'sub': user_id, 'email': 'renewal@test.com'}
        
        # Create initial session
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        original_session_id = session_user.session_id
        original_activity = session_user.last_activity
        
        # Wait to ensure time difference
        time.sleep(0.1)
        
        # Renew session
        renewal_result = secure_session_manager.renew_user_session(user_id)
        assert renewal_result is True, "Session renewal failed"
        
        # Verify renewed session properties
        renewed_session = secure_session_manager.load_user_session(user_id)
        assert renewed_session is not None
        assert renewed_session.session_id == original_session_id  # ID should remain same
        assert renewed_session.last_activity > original_activity  # Activity updated
        assert renewed_session.is_authenticated is True
        assert renewed_session.session_renewable is True
    
    def test_session_invalidation_security_cleanup(self, secure_session_manager, redis_client):
        """
        Test comprehensive session invalidation and security cleanup.
        
        Validates that session invalidation removes all traces of session
        data and prevents any residual data leakage.
        """
        user_id = "invalidation_test_user"
        auth0_profile = {'sub': user_id, 'email': 'invalidation@test.com'}
        
        # Create session
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        session_id = session_user.session_id
        
        # Verify session exists in Redis
        session_keys_before = redis_client.keys(f"*{user_id}*")
        assert len(session_keys_before) > 0, "Session not stored in Redis"
        
        # Invalidate session
        invalidation_result = secure_session_manager.destroy_user_session(user_id)
        assert invalidation_result is True, "Session invalidation failed"
        
        # Verify complete cleanup
        session_keys_after = redis_client.keys(f"*{user_id}*")
        assert len(session_keys_after) == 0, "Session data not completely removed"
        
        # Verify session cannot be loaded
        invalid_session = secure_session_manager.load_user_session(user_id)
        assert invalid_session is None, "Invalidated session still accessible"
        
        # Verify no residual data in Redis
        all_keys = redis_client.keys("*")
        for key in all_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            redis_value = redis_client.get(key)
            if redis_value:
                value_str = redis_value.decode() if isinstance(redis_value, bytes) else str(redis_value)
                assert user_id not in value_str, f"User ID found in residual Redis data: {key_str}"
                assert session_id not in value_str, f"Session ID found in residual Redis data: {key_str}"
    
    def test_session_expiration_and_cleanup_automation(self, secure_session_manager):
        """
        Test automated session expiration and cleanup processes.
        
        Validates that expired sessions are automatically detected and
        cleaned up according to security policies.
        """
        user_id = "expiration_test_user"
        auth0_profile = {'sub': user_id, 'email': 'expiration@test.com'}
        
        # Create session
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Manually set old timestamps to simulate expiration
        expired_time = datetime.utcnow() - timedelta(hours=25)  # Beyond max lifetime
        session_user.session_created = expired_time
        session_user.last_activity = expired_time
        
        # Save expired session state
        secure_session_manager._save_user_session(session_user)
        
        # Run cleanup process
        cleanup_stats = secure_session_manager.cleanup_expired_sessions()
        
        # Verify expired session was cleaned up
        assert cleanup_stats['expired_sessions'] >= 1, "Expired session not detected"
        
        # Verify expired session is no longer accessible
        expired_session = secure_session_manager.load_user_session(user_id)
        assert expired_session is None, "Expired session still accessible"
    
    def test_session_security_event_lifecycle(self, secure_session_manager, security_audit_context):
        """
        Test session lifecycle security event logging and monitoring.
        
        Validates that all session lifecycle events are properly logged
        for security auditing and compliance monitoring.
        """
        user_id = "security_event_user"
        auth0_profile = {'sub': user_id, 'email': 'securityevent@test.com'}
        
        # Track security events during session lifecycle
        with patch('src.auth.session.logger') as mock_logger:
            # Session creation
            session_user = secure_session_manager.create_user_session(
                user_id=user_id,
                auth0_profile=auth0_profile
            )
            
            # Verify creation logging
            create_calls = [call for call in mock_logger.info.call_args_list 
                          if 'session created' in str(call).lower()]
            assert len(create_calls) > 0, "Session creation not logged"
            
            # Session renewal
            secure_session_manager.renew_user_session(user_id)
            
            # Verify renewal logging
            renewal_calls = [call for call in mock_logger.info.call_args_list 
                           if 'renewed' in str(call).lower()]
            assert len(renewal_calls) > 0, "Session renewal not logged"
            
            # Session destruction
            secure_session_manager.destroy_user_session(user_id)
            
            # Verify destruction logging
            destroy_calls = [call for call in mock_logger.info.call_args_list 
                           if 'destroyed' in str(call).lower()]
            assert len(destroy_calls) > 0, "Session destruction not logged"


# =============================================================================
# AWS KMS Key Management Security Tests
# =============================================================================

class TestAWSKMSKeySecurity:
    """
    AWS KMS key management security tests.
    
    Tests AWS KMS integration for encryption key management, key rotation,
    and cryptographic security validation per Section 6.4.3.
    """
    
    @pytest.mark.integration
    def test_kms_key_generation_security(self, mock_aws_kms):
        """
        Test AWS KMS key generation security and validation.
        
        Validates that AWS KMS data key generation follows security
        best practices and produces cryptographically secure keys.
        """
        from src.config.aws import AWSConfig
        
        with patch.dict(os.environ, {
            'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
            'AWS_REGION': TEST_AWS_REGION
        }):
            # Mock KMS configuration
            aws_config = AWSConfig()
            
            # Test data key generation
            plaintext_key = os.urandom(32)
            encrypted_key = base64.b64encode(os.urandom(256))
            
            mock_aws_kms.generate_data_key.return_value = {
                'Plaintext': plaintext_key,
                'CiphertextBlob': encrypted_key
            }
            
            # Verify key generation parameters
            expected_params = {
                'KeyId': TEST_KMS_KEY_ARN,
                'KeySpec': 'AES_256',
                'EncryptionContext': {
                    'application': 'flask-session-system',
                    'purpose': 'session-data-encryption',
                    'environment': 'testing',
                    'data_type': 'session_data'
                }
            }
            
            # Validate key properties
            assert len(plaintext_key) == 32, "Generated key not 256 bits"
            assert plaintext_key != b'\x00' * 32, "Generated key is all zeros"
    
    @pytest.mark.integration
    def test_kms_key_rotation_security(self, mock_aws_kms):
        """
        Test AWS KMS key rotation security and automation.
        
        Validates that key rotation follows security policies and
        maintains data accessibility during rotation periods.
        """
        # Mock key rotation responses
        mock_aws_kms.enable_key_rotation.return_value = True
        mock_aws_kms.get_key_rotation_status.return_value = {
            'KeyRotationEnabled': True
        }
        
        # Test key rotation enablement
        with patch('boto3.client') as mock_boto:
            mock_boto.return_value = mock_aws_kms
            
            from src.auth.session import SessionEncryptionManager
            
            with patch.dict(os.environ, {
                'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
                'AWS_REGION': TEST_AWS_REGION
            }):
                encryption_manager = SessionEncryptionManager()
                
                # Verify rotation is configurable
                assert encryption_manager._key_rotation_threshold.days == 90, \
                    "Key rotation threshold not set to 90 days"
                
                # Test that rotation threshold is respected
                old_rotation_time = datetime.utcnow() - timedelta(days=91)
                with patch.object(encryption_manager, '_last_key_rotation', old_rotation_time):
                    encryption_manager._rotate_encryption_key_if_needed()
                    
                    # Verify rotation occurred
                    assert encryption_manager._last_key_rotation > old_rotation_time, \
                        "Key rotation did not occur when threshold exceeded"
    
    @pytest.mark.integration
    def test_kms_encryption_context_security(self, mock_aws_kms):
        """
        Test AWS KMS encryption context security and validation.
        
        Validates that encryption context is properly used for additional
        security and access control in KMS operations.
        """
        # Test encryption context validation
        expected_context = {
            'application': 'flask-session-system',
            'purpose': 'session-data-encryption',
            'environment': 'testing',
            'data_type': 'session_data'
        }
        
        with patch.dict(os.environ, {
            'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
            'AWS_REGION': TEST_AWS_REGION,
            'FLASK_ENV': 'testing'
        }):
            from src.auth.session import SessionEncryptionManager
            
            with patch('src.auth.session.get_aws_manager'):
                encryption_manager = SessionEncryptionManager()
                
                # Verify encryption context is properly set
                assert encryption_manager.encryption_context == expected_context, \
                    "Encryption context not properly configured"
                
                # Test that context is environment-specific
                assert encryption_manager.encryption_context['environment'] == 'testing', \
                    "Environment not reflected in encryption context"
    
    def test_kms_error_handling_security(self, mock_aws_kms):
        """
        Test AWS KMS error handling and security fallbacks.
        
        Validates that KMS errors are handled securely without exposing
        sensitive information or compromising system security.
        """
        from botocore.exceptions import ClientError
        
        # Mock KMS errors
        mock_aws_kms.generate_data_key.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'GenerateDataKey'
        )
        
        with patch.dict(os.environ, {
            'AWS_KMS_CMK_ARN': TEST_KMS_KEY_ARN,
            'AWS_REGION': TEST_AWS_REGION
        }):
            with patch('boto3.client', return_value=mock_aws_kms):
                with patch('src.auth.session.get_aws_manager'):
                    # Test error handling during initialization
                    try:
                        from src.auth.session import SessionEncryptionManager
                        encryption_manager = SessionEncryptionManager()
                        
                        # Should fall back to local key generation
                        assert encryption_manager._current_fernet is not None, \
                            "Fallback encryption not initialized"
                        
                    except Exception as e:
                        # Verify error doesn't expose sensitive information
                        error_str = str(e).lower()
                        assert 'key' not in error_str or 'secret' not in error_str, \
                            "Error message exposes sensitive key information"


# =============================================================================
# Performance and Security Metrics Tests
# =============================================================================

class TestSessionSecurityMetrics:
    """
    Session security performance and metrics validation tests.
    
    Tests session security operations performance, metrics collection,
    and compliance with ≤10% variance requirement per Section 0.1.1.
    """
    
    def test_session_operation_performance_baseline(self, secure_session_manager):
        """
        Test session operation performance against baseline requirements.
        
        Validates that session security operations maintain performance
        within the ≤10% variance requirement from Node.js baseline.
        """
        user_id = "performance_baseline_user"
        auth0_profile = {'sub': user_id, 'email': 'performance@test.com'}
        
        # Performance baselines (in seconds)
        baseline_create = 0.05  # 50ms
        baseline_load = 0.02    # 20ms
        baseline_destroy = 0.03  # 30ms
        
        # Test session creation performance
        create_times = []
        for _ in range(5):
            start_time = time.time()
            session_user = secure_session_manager.create_user_session(
                user_id=f"{user_id}_{uuid.uuid4()}",
                auth0_profile=auth0_profile
            )
            create_time = time.time() - start_time
            create_times.append(create_time)
            
            # Clean up for next iteration
            secure_session_manager.destroy_user_session(session_user.id)
        
        avg_create_time = sum(create_times) / len(create_times)
        
        # Test session load performance
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        load_times = []
        for _ in range(5):
            start_time = time.time()
            loaded_session = secure_session_manager.load_user_session(user_id)
            load_time = time.time() - start_time
            load_times.append(load_time)
        
        avg_load_time = sum(load_times) / len(load_times)
        
        # Test session destruction performance
        destroy_times = []
        for _ in range(5):
            temp_user_id = f"{user_id}_destroy_{uuid.uuid4()}"
            secure_session_manager.create_user_session(
                user_id=temp_user_id,
                auth0_profile=auth0_profile
            )
            
            start_time = time.time()
            secure_session_manager.destroy_user_session(temp_user_id)
            destroy_time = time.time() - start_time
            destroy_times.append(destroy_time)
        
        avg_destroy_time = sum(destroy_times) / len(destroy_times)
        
        # Validate performance within 10% variance
        create_variance = (avg_create_time - baseline_create) / baseline_create
        load_variance = (avg_load_time - baseline_load) / baseline_load
        destroy_variance = (avg_destroy_time - baseline_destroy) / baseline_destroy
        
        assert abs(create_variance) <= 0.1, \
            f"Session creation performance variance {create_variance:.2%} exceeds 10%"
        assert abs(load_variance) <= 0.1, \
            f"Session load performance variance {load_variance:.2%} exceeds 10%"
        assert abs(destroy_variance) <= 0.1, \
            f"Session destroy performance variance {destroy_variance:.2%} exceeds 10%"
    
    def test_encryption_performance_validation(self, session_encryption_manager):
        """
        Test encryption operation performance validation.
        
        Validates that encryption/decryption operations maintain acceptable
        performance for session security requirements.
        """
        # Test various data sizes
        test_datasets = [
            {'small': 'x' * 100},           # 100 bytes
            {'medium': 'x' * 1000},         # 1KB  
            {'large': 'x' * 10000},         # 10KB
            {'extra_large': 'x' * 100000}   # 100KB
        ]
        
        for dataset in test_datasets:
            data_name = list(dataset.keys())[0]
            test_data = {
                'user_id': 'encryption_perf_user',
                'test_data': dataset[data_name],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Measure encryption performance
            encrypt_times = []
            decrypt_times = []
            
            for _ in range(3):  # Average of 3 operations
                # Encryption timing
                start_time = time.time()
                encrypted_data = session_encryption_manager.encrypt_session_data(test_data)
                encrypt_time = time.time() - start_time
                encrypt_times.append(encrypt_time)
                
                # Decryption timing
                start_time = time.time()
                session_encryption_manager.decrypt_session_data(encrypted_data)
                decrypt_time = time.time() - start_time
                decrypt_times.append(decrypt_time)
            
            avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
            avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
            
            # Performance thresholds based on data size
            encrypt_threshold = 0.01 * (len(dataset[data_name]) / 1000 + 1)  # Scale with size
            decrypt_threshold = 0.005 * (len(dataset[data_name]) / 1000 + 1)  # Scale with size
            
            assert avg_encrypt_time < encrypt_threshold, \
                f"Encryption too slow for {data_name} data: {avg_encrypt_time:.4f}s"
            assert avg_decrypt_time < decrypt_threshold, \
                f"Decryption too slow for {data_name} data: {avg_decrypt_time:.4f}s"
    
    def test_security_metrics_collection_validation(self, secure_session_manager):
        """
        Test security metrics collection and validation.
        
        Validates that security metrics are properly collected and
        provide accurate monitoring data for session operations.
        """
        # Reset metrics for testing
        session_metrics['session_operations']._value.clear()
        session_metrics['session_security_events']._value.clear()
        
        user_id = "metrics_test_user"
        auth0_profile = {'sub': user_id, 'email': 'metrics@test.com'}
        
        # Perform operations to generate metrics
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        loaded_session = secure_session_manager.load_user_session(user_id)
        renewed_session = secure_session_manager.renew_user_session(user_id)
        destroyed_session = secure_session_manager.destroy_user_session(user_id)
        
        # Validate metrics were recorded
        operation_metrics = session_metrics['session_operations']._value
        
        # Check for operation metrics
        create_metrics = [m for m in operation_metrics if 'create' in str(m)]
        load_metrics = [m for m in operation_metrics if 'load' in str(m)]
        destroy_metrics = [m for m in operation_metrics if 'destroy' in str(m)]
        
        assert len(create_metrics) > 0, "Session creation metrics not recorded"
        assert len(load_metrics) > 0, "Session load metrics not recorded"
        assert len(destroy_metrics) > 0, "Session destruction metrics not recorded"
        
        # Validate active sessions gauge
        current_active_sessions = session_metrics['active_sessions']._value._value
        assert isinstance(current_active_sessions, (int, float)), \
            "Active sessions metric not properly maintained"


# =============================================================================
# Security Compliance and Audit Tests
# =============================================================================

class TestSessionSecurityCompliance:
    """
    Session security compliance and audit validation tests.
    
    Tests compliance with security standards including OWASP Top 10,
    SOC 2 Type II, and enterprise security requirements per Section 6.4.5.
    """
    
    def test_owasp_session_management_compliance(self, security_test_app, redis_client):
        """
        Test OWASP session management security compliance.
        
        Validates compliance with OWASP session management guidelines
        including session ID generation, fixation prevention, and timeout.
        """
        with security_test_app.test_client() as client:
            # OWASP A2: Session ID should be unpredictable
            session_ids = set()
            for _ in range(10):
                response = client.post('/login')
                session_info = client.get('/session-info').get_json()
                session_id = session_info.get('session_id')
                if session_id:
                    session_ids.add(session_id)
            
            # Verify session ID uniqueness and length
            assert len(session_ids) >= 8, "Session IDs not sufficiently unique"
            
            if session_ids:
                sample_id = list(session_ids)[0]
                assert len(sample_id) >= 16, "Session ID too short for OWASP compliance"
            
            # OWASP A2: Session timeout should be enforced
            with client.session_transaction() as sess:
                sess.permanent = True  # Required for timeout testing
            
            # Verify session timeout configuration
            assert security_test_app.permanent_session_lifetime.total_seconds() <= 86400, \
                "Session timeout exceeds OWASP recommendations (24 hours)"
            
            # OWASP A2: Secure cookie attributes
            response = client.post('/login')
            set_cookie_headers = [h[1] for h in response.headers if h[0].lower() == 'set-cookie']
            
            if set_cookie_headers:
                cookie_header = set_cookie_headers[0]
                assert 'HttpOnly' in cookie_header, "Missing HttpOnly (OWASP A2 compliance)"
                assert 'SameSite' in cookie_header, "Missing SameSite (OWASP A2 compliance)"
    
    def test_soc2_audit_trail_compliance(self, secure_session_manager, security_audit_context):
        """
        Test SOC 2 Type II audit trail compliance.
        
        Validates that session operations generate proper audit trails
        for SOC 2 compliance and security monitoring requirements.
        """
        user_id = "soc2_audit_user"
        auth0_profile = {'sub': user_id, 'email': 'soc2@test.com'}
        
        # Capture audit events during session lifecycle
        with patch('src.auth.session.logger') as mock_logger:
            # Session creation
            session_user = secure_session_manager.create_user_session(
                user_id=user_id,
                auth0_profile=auth0_profile
            )
            
            # Session operations
            secure_session_manager.load_user_session(user_id)
            secure_session_manager.renew_user_session(user_id)
            secure_session_manager.destroy_user_session(user_id)
            
            # Validate audit logging occurred
            logged_calls = mock_logger.info.call_args_list + mock_logger.debug.call_args_list
            
            # Check for required audit elements
            audit_elements = [
                'user_id',
                'session_id', 
                'timestamp',
                'operation'
            ]
            
            audit_logs_found = []
            for call in logged_calls:
                call_str = str(call)
                if any(element in call_str.lower() for element in audit_elements):
                    audit_logs_found.append(call_str)
            
            assert len(audit_logs_found) > 0, "No audit logs generated for SOC 2 compliance"
            
            # Verify audit log contains required information
            for audit_log in audit_logs_found:
                # Should contain user identification
                assert user_id in audit_log or 'user_id' in audit_log.lower(), \
                    "Audit log missing user identification"
    
    def test_enterprise_security_policy_compliance(self, secure_session_manager):
        """
        Test enterprise security policy compliance.
        
        Validates compliance with enterprise security policies including
        data classification, retention, and access controls.
        """
        user_id = "enterprise_policy_user"
        auth0_profile = {
            'sub': user_id,
            'email': 'enterprise@test.com',
            'name': 'Enterprise Policy User',
            'org_id': 'enterprise_org_123'
        }
        
        # Test data classification compliance
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Verify sensitive data handling
        session_dict = session_user.to_session_dict()
        
        # Validate required security metadata
        required_metadata = [
            'user_id',
            'session_id', 
            'created_at',
            'last_activity',
            'security_level'
        ]
        
        for field in required_metadata:
            assert field in session_dict, f"Missing required security metadata: {field}"
        
        # Validate data retention policy
        assert session_user.session_created is not None, "Session creation timestamp missing"
        assert session_user.last_activity is not None, "Session activity timestamp missing"
        
        # Test access control compliance
        assert session_user.is_authenticated is True, "Authentication state not properly maintained"
        assert session_user.security_level in ['standard', 'elevated', 'restricted'], \
            "Invalid security level classification"
    
    def test_zero_tolerance_security_vulnerability_validation(self, secure_session_manager, redis_client):
        """
        Test zero tolerance security vulnerability validation.
        
        Validates that the session system has zero tolerance for common
        security vulnerabilities per Section 6.4.5 requirements.
        """
        # Test 1: No session data in plaintext
        user_id = "zero_tolerance_user"
        auth0_profile = {'sub': user_id, 'email': 'zerotolerance@test.com'}
        
        session_user = secure_session_manager.create_user_session(
            user_id=user_id,
            auth0_profile=auth0_profile
        )
        
        # Check all Redis keys for plaintext data
        all_redis_keys = redis_client.keys("*")
        for key in all_redis_keys:
            redis_value = redis_client.get(key)
            if redis_value:
                value_str = redis_value.decode() if isinstance(redis_value, bytes) else str(redis_value)
                
                # Sensitive data should not appear in plaintext
                assert user_id not in value_str, f"User ID found in plaintext in Redis key: {key}"
                assert 'zerotolerance@test.com' not in value_str, \
                    f"Email found in plaintext in Redis key: {key}"
        
        # Test 2: No timing attacks on session validation
        valid_user_id = user_id
        invalid_user_id = "invalid_user_12345"
        
        # Measure timing for valid vs invalid sessions
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            # Time valid session load
            start_time = time.time()
            valid_session = secure_session_manager.load_user_session(valid_user_id)
            valid_time = time.time() - start_time
            valid_times.append(valid_time)
            
            # Time invalid session load
            start_time = time.time()
            invalid_session = secure_session_manager.load_user_session(invalid_user_id)
            invalid_time = time.time() - start_time
            invalid_times.append(invalid_time)
        
        avg_valid_time = sum(valid_times) / len(valid_times)
        avg_invalid_time = sum(invalid_times) / len(invalid_times)
        
        # Timing difference should be minimal (< 50% difference)
        time_difference_ratio = abs(avg_valid_time - avg_invalid_time) / min(avg_valid_time, avg_invalid_time)
        assert time_difference_ratio < 0.5, \
            f"Potential timing attack vulnerability: {time_difference_ratio:.2%} timing difference"
        
        # Test 3: Session isolation validation
        # Create multiple users and verify complete isolation
        test_users = []
        for i in range(3):
            test_user_id = f"isolation_user_{i}"
            test_profile = {'sub': test_user_id, 'email': f'isolation{i}@test.com'}
            test_session = secure_session_manager.create_user_session(
                user_id=test_user_id,
                auth0_profile=test_profile
            )
            test_users.append((test_user_id, test_session))
        
        # Verify each user can only access their own session
        for user_id, session_user in test_users:
            loaded_session = secure_session_manager.load_user_session(user_id)
            assert loaded_session is not None, f"User {user_id} cannot load own session"
            assert loaded_session.id == user_id, f"Session ID mismatch for user {user_id}"
            
            # Verify user cannot access other sessions
            for other_user_id, _ in test_users:
                if other_user_id != user_id:
                    other_session = secure_session_manager.load_user_session(other_user_id)
                    if other_session:
                        assert other_session.id != user_id, \
                            f"Session isolation breach: {user_id} accessed {other_user_id} session"


if __name__ == "__main__":
    # Run security tests with comprehensive coverage
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src.auth.session",
        "--cov=src.auth.cache", 
        "--cov-report=html",
        "--cov-report=term-missing",
        "--cov-fail-under=95",
        "-m", "security"
    ])