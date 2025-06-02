"""
Security Testing Configuration Management Module

This module provides comprehensive security testing configuration management for Flask application
security validation, implementing attack simulation parameters, penetration testing framework
settings, and enterprise security compliance configuration as specified in Section 6.6.1,
Section 6.4.5, and Section 6.4.6 of the technical specification.

Key Features:
- Security test configuration management for comprehensive validation per Section 6.6.1
- Attack simulation parameter configuration for penetration testing per Section 6.4.5
- Enterprise security compliance settings per Section 6.4.6
- Security tool integration and threshold configuration per Section 6.6.3
- OWASP security testing framework integration for comprehensive vulnerability assessment
- Automated security scanning configuration for CI/CD pipeline integration

Architecture Integration:
- Section 6.6.1: Security testing approach with pytest framework and security tool integration
- Section 6.4.5: Security Controls Matrix with vulnerability scanning and penetration testing
- Section 6.4.6: Compliance Requirements with automated security validation and audit trails
- Section 6.6.3: Quality Metrics with security scan enforcement and threshold management

Author: Flask Migration Team
Version: 1.0.0
Dependencies: pytest 7.4+, bandit 1.7+, safety 3.0+, owasp-zap-api 0.0.21+
"""

import os
import json
import logging
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# Security testing imports
import pytest
from unittest.mock import Mock, MagicMock

# Security scanning tool imports
import bandit
from safety.cli import check as safety_check
from zapv2 import ZAPv2

# Network and HTTP testing imports
import requests
import httpx
from tenacity import (
    retry, 
    stop_after_attempt, 
    wait_exponential_jitter,
    retry_if_exception_type
)

# Environment and validation imports
from marshmallow import Schema, fields, ValidationError
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import threading
import time

# Import test configuration base classes
from tests.test_config import TestBaseConfig

# Configure module logger
logger = logging.getLogger(__name__)


class SecurityTestLevel(Enum):
    """Security test execution levels for different testing scenarios."""
    
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    PENETRATION = "penetration"
    COMPLIANCE = "compliance"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels for security findings classification."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(Enum):
    """Attack simulation categories for penetration testing."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    SESSION_MANAGEMENT = "session_management"
    CONFIGURATION = "configuration"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "business_logic"
    API_SECURITY = "api_security"


@dataclass
class SecurityTestMetrics:
    """Security test execution metrics and results tracking."""
    
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    vulnerabilities_found: Dict[str, int] = field(default_factory=dict)
    compliance_score: float = 0.0
    coverage_percentage: float = 0.0
    
    @property
    def duration(self) -> timedelta:
        """Calculate test execution duration."""
        end = self.end_time or datetime.utcnow()
        return end - self.start_time
    
    @property
    def success_rate(self) -> float:
        """Calculate test success rate percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100


class SecurityTestConfig(TestBaseConfig):
    """
    Comprehensive security testing configuration providing security test parameters,
    attack simulation settings, penetration testing configuration, and enterprise
    security compliance settings for comprehensive security validation.
    
    This configuration implements the security testing requirements specified in
    Section 6.6.1, Section 6.4.5, and Section 6.4.6 of the technical specification,
    providing complete security validation capabilities for the Flask application.
    
    Features:
    - Security test configuration management per Section 6.6.1
    - Attack simulation parameter configuration per Section 6.4.5
    - Penetration testing framework settings per Section 6.4.5
    - Enterprise security compliance configuration per Section 6.4.6
    - Security threshold and enforcement settings per Section 6.6.3
    - Security tool integration parameters per Section 6.4.5
    """
    
    # Security Testing Configuration
    SECURITY_TESTING_ENABLED = True
    SECURITY_TEST_LEVEL = SecurityTestLevel.COMPREHENSIVE.value
    SECURITY_TEST_TIMEOUT = int(os.getenv('SECURITY_TEST_TIMEOUT', '3600'))  # 1 hour
    SECURITY_TEST_PARALLEL_WORKERS = int(os.getenv('SECURITY_TEST_WORKERS', '4'))
    
    # Security Scan Tool Configuration per Section 6.4.5
    BANDIT_CONFIG_ENABLED = True
    BANDIT_SEVERITY_THRESHOLD = VulnerabilitySeverity.MEDIUM.value
    BANDIT_CONFIDENCE_THRESHOLD = "HIGH"
    BANDIT_EXCLUDE_PATHS = [
        'tests/*',
        'venv/*',
        '.venv/*',
        'migrations/*'
    ]
    BANDIT_SKIP_TESTS = [
        'B101',  # Skip assert_used test in test files
        'B601'   # Skip shell injection for subprocess with shell=False
    ]
    
    # Safety Dependency Scanning Configuration per Section 6.4.5
    SAFETY_ENABLED = True
    SAFETY_SEVERITY_THRESHOLD = VulnerabilitySeverity.MEDIUM.value
    SAFETY_IGNORE_VULNERABILITIES = []  # List of CVE IDs to ignore
    SAFETY_REQUIREMENTS_FILE = 'requirements.txt'
    SAFETY_DATABASE_MIRROR = os.getenv('SAFETY_DB_MIRROR', 'https://osv-vulnerabilities.storage.googleapis.com')
    
    # OWASP ZAP Configuration per Section 6.4.5
    ZAP_ENABLED = True
    ZAP_PROXY_HOST = os.getenv('ZAP_PROXY_HOST', 'localhost')
    ZAP_PROXY_PORT = int(os.getenv('ZAP_PROXY_PORT', '8080'))
    ZAP_API_KEY = os.getenv('ZAP_API_KEY', 'test-api-key')
    ZAP_TARGET_URL = os.getenv('ZAP_TARGET_URL', 'http://localhost:5000')
    ZAP_SCAN_TIMEOUT = int(os.getenv('ZAP_SCAN_TIMEOUT', '1800'))  # 30 minutes
    ZAP_ALERT_THRESHOLD = VulnerabilitySeverity.MEDIUM.value
    
    # Container Security Scanning per Section 6.4.5
    TRIVY_ENABLED = True
    TRIVY_SEVERITY_THRESHOLD = VulnerabilitySeverity.HIGH.value
    TRIVY_IMAGE_NAME = os.getenv('TRIVY_IMAGE_NAME', 'flask-app:latest')
    TRIVY_OUTPUT_FORMAT = 'json'
    TRIVY_TIMEOUT = int(os.getenv('TRIVY_TIMEOUT', '900'))  # 15 minutes
    
    # Attack Simulation Configuration per Section 6.4.5
    ATTACK_SIMULATION_ENABLED = True
    ATTACK_SIMULATION_CATEGORIES = [
        AttackCategory.AUTHENTICATION.value,
        AttackCategory.AUTHORIZATION.value,
        AttackCategory.INPUT_VALIDATION.value,
        AttackCategory.SESSION_MANAGEMENT.value,
        AttackCategory.API_SECURITY.value
    ]
    
    # Penetration Testing Framework Configuration per Section 6.4.5
    PENETRATION_TESTING_ENABLED = True
    PENETRATION_TEST_SCENARIOS = {
        'authentication_bypass': {
            'enabled': True,
            'target_endpoints': ['/api/auth/login', '/api/auth/logout'],
            'attack_vectors': ['sql_injection', 'weak_passwords', 'session_fixation'],
            'timeout': 600
        },
        'authorization_escalation': {
            'enabled': True,
            'target_endpoints': ['/api/admin/*', '/api/users/*'],
            'attack_vectors': ['privilege_escalation', 'idor', 'path_traversal'],
            'timeout': 900
        },
        'input_validation_bypass': {
            'enabled': True,
            'target_endpoints': ['/api/*'],
            'attack_vectors': ['xss', 'sql_injection', 'command_injection', 'xxe'],
            'timeout': 1200
        },
        'session_attacks': {
            'enabled': True,
            'target_endpoints': ['/api/auth/*'],
            'attack_vectors': ['session_hijacking', 'csrf', 'session_fixation'],
            'timeout': 600
        },
        'api_security_tests': {
            'enabled': True,
            'target_endpoints': ['/api/*'],
            'attack_vectors': ['api_fuzzing', 'rate_limit_bypass', 'jwt_attacks'],
            'timeout': 1800
        }
    }
    
    # Enterprise Security Compliance Configuration per Section 6.4.6
    COMPLIANCE_VALIDATION_ENABLED = True
    COMPLIANCE_FRAMEWORKS = {
        'owasp_top_10': {
            'enabled': True,
            'version': '2021',
            'categories': [
                'A01_2021_Broken_Access_Control',
                'A02_2021_Cryptographic_Failures',
                'A03_2021_Injection',
                'A04_2021_Insecure_Design',
                'A05_2021_Security_Misconfiguration',
                'A06_2021_Vulnerable_Components',
                'A07_2021_Identification_Authentication_Failures',
                'A08_2021_Software_Data_Integrity_Failures',
                'A09_2021_Security_Logging_Monitoring_Failures',
                'A10_2021_Server_Side_Request_Forgery'
            ]
        },
        'sans_top_25': {
            'enabled': True,
            'version': '2023',
            'critical_weaknesses': [
                'CWE-79',   # Cross-site Scripting
                'CWE-89',   # SQL Injection
                'CWE-20',   # Improper Input Validation
                'CWE-125',  # Out-of-bounds Read
                'CWE-78',   # OS Command Injection
                'CWE-416',  # Use After Free
                'CWE-22',   # Path Traversal
                'CWE-352',  # Cross-Site Request Forgery
                'CWE-434',  # Unrestricted Upload of File
                'CWE-862'   # Missing Authorization
            ]
        },
        'pci_dss': {
            'enabled': False,  # Enable if handling payment data
            'version': '4.0',
            'requirements': [
                'secure_network_configuration',
                'protect_cardholder_data',
                'encryption_in_transit',
                'vulnerability_management',
                'access_control_measures',
                'network_monitoring'
            ]
        },
        'soc2_type2': {
            'enabled': True,
            'version': '2017',
            'trust_criteria': [
                'security',
                'availability',
                'processing_integrity',
                'confidentiality',
                'privacy'
            ]
        }
    }
    
    # Security Threshold and Enforcement Settings per Section 6.6.3
    SECURITY_THRESHOLDS = {
        'vulnerability_limits': {
            VulnerabilitySeverity.CRITICAL.value: 0,   # Zero tolerance
            VulnerabilitySeverity.HIGH.value: 0,       # Zero tolerance
            VulnerabilitySeverity.MEDIUM.value: 5,     # Maximum 5 medium severity
            VulnerabilitySeverity.LOW.value: 20,       # Maximum 20 low severity
            VulnerabilitySeverity.INFO.value: 50       # Maximum 50 informational
        },
        'compliance_score_minimum': 95.0,              # Minimum 95% compliance score
        'security_test_coverage_minimum': 90.0,        # Minimum 90% test coverage
        'penetration_test_pass_rate': 100.0,           # 100% penetration tests must pass
        'dependency_vulnerability_age_days': 30,       # Max 30 days for known vulnerabilities
        'security_scan_failure_threshold': 0           # Zero security scan failures allowed
    }
    
    # Security Tool Integration Parameters per Section 6.4.5
    SECURITY_TOOLS_INTEGRATION = {
        'ci_cd_integration': {
            'github_actions_enabled': True,
            'security_gate_required': True,
            'fail_fast_on_critical': True,
            'parallel_security_scans': True,
            'security_report_artifacts': True
        },
        'reporting_integration': {
            'json_reports_enabled': True,
            'xml_reports_enabled': True,
            'html_reports_enabled': True,
            'slack_notifications': os.getenv('SLACK_SECURITY_WEBHOOK'),
            'email_notifications': os.getenv('SECURITY_EMAIL_ALERTS')
        },
        'external_services': {
            'security_hub_integration': True,
            'cloudwatch_metrics': True,
            'prometheus_metrics': True,
            'siem_integration': True,
            'vulnerability_database_sync': True
        }
    }
    
    # Security Test Categories and Weights
    SECURITY_TEST_CATEGORIES = {
        'authentication_security': {
            'weight': 0.20,
            'tests': [
                'test_jwt_token_validation',
                'test_auth0_integration_security',
                'test_session_management_security',
                'test_password_policy_enforcement',
                'test_multi_factor_authentication'
            ]
        },
        'authorization_security': {
            'weight': 0.20,
            'tests': [
                'test_rbac_enforcement',
                'test_permission_validation',
                'test_privilege_escalation_prevention',
                'test_resource_access_control',
                'test_api_authorization'
            ]
        },
        'input_validation_security': {
            'weight': 0.15,
            'tests': [
                'test_xss_prevention',
                'test_sql_injection_prevention',
                'test_command_injection_prevention',
                'test_path_traversal_prevention',
                'test_xxe_prevention'
            ]
        },
        'cryptography_security': {
            'weight': 0.15,
            'tests': [
                'test_encryption_implementation',
                'test_key_management_security',
                'test_tls_configuration',
                'test_secure_random_generation',
                'test_certificate_validation'
            ]
        },
        'session_security': {
            'weight': 0.10,
            'tests': [
                'test_session_encryption',
                'test_session_timeout',
                'test_csrf_protection',
                'test_session_fixation_prevention',
                'test_cookie_security'
            ]
        },
        'configuration_security': {
            'weight': 0.10,
            'tests': [
                'test_security_headers',
                'test_cors_configuration',
                'test_environment_variable_security',
                'test_debug_mode_disabled',
                'test_error_handling_security'
            ]
        },
        'api_security': {
            'weight': 0.10,
            'tests': [
                'test_rate_limiting',
                'test_api_versioning_security',
                'test_swagger_security',
                'test_api_authentication',
                'test_api_input_validation'
            ]
        }
    }
    
    @classmethod
    def get_security_test_level(cls) -> SecurityTestLevel:
        """
        Get configured security test level.
        
        Returns:
            SecurityTestLevel: Configured test level enum value
        """
        return SecurityTestLevel(cls.SECURITY_TEST_LEVEL)
    
    @classmethod
    def get_enabled_attack_categories(cls) -> List[AttackCategory]:
        """
        Get list of enabled attack simulation categories.
        
        Returns:
            List[AttackCategory]: Enabled attack categories for simulation
        """
        return [AttackCategory(category) for category in cls.ATTACK_SIMULATION_CATEGORIES]
    
    @classmethod
    def get_vulnerability_threshold(cls, severity: VulnerabilitySeverity) -> int:
        """
        Get vulnerability threshold for specific severity level.
        
        Args:
            severity: Vulnerability severity level
            
        Returns:
            int: Maximum allowed vulnerabilities for severity level
        """
        return cls.SECURITY_THRESHOLDS['vulnerability_limits'].get(severity.value, 0)
    
    @classmethod
    def get_compliance_frameworks(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get enabled compliance frameworks configuration.
        
        Returns:
            Dict containing enabled compliance framework configurations
        """
        return {
            name: config for name, config in cls.COMPLIANCE_FRAMEWORKS.items()
            if config.get('enabled', False)
        }


class BanditSecurityScanner:
    """
    Bandit static analysis security scanner integration for Python code security validation.
    
    Implements comprehensive Python security pattern analysis per Section 6.4.5
    with configurable severity thresholds and enterprise security policy enforcement.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize Bandit security scanner with configuration.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.BanditScanner")
        self.scan_results: Dict[str, Any] = {}
    
    def run_security_scan(self, target_path: str = ".") -> Dict[str, Any]:
        """
        Execute Bandit security scan on target codebase.
        
        Args:
            target_path: Path to scan for security issues
            
        Returns:
            Dict containing scan results and vulnerability findings
        """
        try:
            # Prepare Bandit configuration
            bandit_config = self._create_bandit_config()
            
            # Execute Bandit scan using subprocess for better control
            scan_command = self._build_bandit_command(target_path, bandit_config)
            
            self.logger.info(f"Executing Bandit security scan: {scan_command}")
            
            result = subprocess.run(
                scan_command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.config.SECURITY_TEST_TIMEOUT
            )
            
            # Parse Bandit results
            scan_results = self._parse_bandit_results(result.stdout, result.stderr, result.returncode)
            
            # Validate against security thresholds
            validation_results = self._validate_security_thresholds(scan_results)
            
            self.scan_results = {
                **scan_results,
                'threshold_validation': validation_results,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'scan_duration': scan_results.get('scan_duration', 0)
            }
            
            self.logger.info(f"Bandit scan completed: {len(scan_results.get('issues', []))} issues found")
            
            return self.scan_results
            
        except subprocess.TimeoutExpired:
            error_msg = f"Bandit scan timed out after {self.config.SECURITY_TEST_TIMEOUT} seconds"
            self.logger.error(error_msg)
            return {'error': error_msg, 'scan_status': 'timeout'}
        except Exception as e:
            error_msg = f"Bandit scan failed: {str(e)}"
            self.logger.error(error_msg)
            return {'error': error_msg, 'scan_status': 'failed'}
    
    def _create_bandit_config(self) -> Dict[str, Any]:
        """Create Bandit configuration based on security test settings."""
        return {
            'severity': self.config.BANDIT_SEVERITY_THRESHOLD,
            'confidence': self.config.BANDIT_CONFIDENCE_THRESHOLD,
            'exclude_paths': self.config.BANDIT_EXCLUDE_PATHS,
            'skip_tests': self.config.BANDIT_SKIP_TESTS,
            'output_format': 'json'
        }
    
    def _build_bandit_command(self, target_path: str, bandit_config: Dict[str, Any]) -> List[str]:
        """Build Bandit command with security configuration."""
        command = [
            'bandit',
            '-r', target_path,
            '-f', bandit_config['output_format'],
            '-ll',  # Low severity, low confidence
            '--exit-zero'  # Don't exit with error code
        ]
        
        # Add exclude paths
        if bandit_config['exclude_paths']:
            exclude_pattern = ','.join(bandit_config['exclude_paths'])
            command.extend(['--exclude', exclude_pattern])
        
        # Add skip tests
        if bandit_config['skip_tests']:
            skip_pattern = ','.join(bandit_config['skip_tests'])
            command.extend(['--skip', skip_pattern])
        
        return command
    
    def _parse_bandit_results(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        """Parse Bandit scan results from JSON output."""
        try:
            if stdout:
                results = json.loads(stdout)
                
                # Extract vulnerability information
                issues = results.get('results', [])
                metrics = results.get('metrics', {})
                
                # Categorize issues by severity
                severity_counts = {severity.value: 0 for severity in VulnerabilitySeverity}
                
                for issue in issues:
                    severity = issue.get('issue_severity', 'info').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                return {
                    'scan_status': 'completed',
                    'issues': issues,
                    'total_issues': len(issues),
                    'severity_counts': severity_counts,
                    'metrics': metrics,
                    'return_code': return_code,
                    'stderr': stderr
                }
            else:
                return {
                    'scan_status': 'no_output',
                    'issues': [],
                    'total_issues': 0,
                    'severity_counts': {severity.value: 0 for severity in VulnerabilitySeverity},
                    'return_code': return_code,
                    'stderr': stderr
                }
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Bandit JSON output: {str(e)}")
            return {
                'scan_status': 'parse_error',
                'error': str(e),
                'raw_output': stdout,
                'stderr': stderr
            }
    
    def _validate_security_thresholds(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate scan results against configured security thresholds."""
        validation_results = {
            'passed': True,
            'violations': [],
            'compliance_score': 0.0
        }
        
        severity_counts = scan_results.get('severity_counts', {})
        
        # Check vulnerability thresholds
        for severity, count in severity_counts.items():
            threshold = self.config.get_vulnerability_threshold(VulnerabilitySeverity(severity))
            
            if count > threshold:
                validation_results['passed'] = False
                validation_results['violations'].append({
                    'type': 'vulnerability_threshold',
                    'severity': severity,
                    'count': count,
                    'threshold': threshold,
                    'message': f"Found {count} {severity} severity issues, threshold is {threshold}"
                })
        
        # Calculate compliance score
        total_issues = scan_results.get('total_issues', 0)
        if total_issues == 0:
            validation_results['compliance_score'] = 100.0
        else:
            # Weight issues by severity for compliance score
            weighted_score = 0
            severity_weights = {
                VulnerabilitySeverity.CRITICAL.value: 10,
                VulnerabilitySeverity.HIGH.value: 8,
                VulnerabilitySeverity.MEDIUM.value: 5,
                VulnerabilitySeverity.LOW.value: 2,
                VulnerabilitySeverity.INFO.value: 1
            }
            
            max_possible_score = 100
            penalty_score = 0
            
            for severity, count in severity_counts.items():
                penalty_score += count * severity_weights.get(severity, 1)
            
            validation_results['compliance_score'] = max(0, max_possible_score - penalty_score)
        
        return validation_results


class SafetyDependencyScanner:
    """
    Safety dependency vulnerability scanner for Python package security validation.
    
    Implements comprehensive dependency vulnerability assessment per Section 6.4.5
    with CVE database integration and automated security policy enforcement.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize Safety dependency scanner with configuration.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SafetyScanner")
        self.scan_results: Dict[str, Any] = {}
    
    def run_dependency_scan(self, requirements_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute Safety dependency vulnerability scan.
        
        Args:
            requirements_file: Path to requirements.txt file
            
        Returns:
            Dict containing dependency scan results and vulnerability findings
        """
        try:
            # Use configured requirements file or provided file
            req_file = requirements_file or self.config.SAFETY_REQUIREMENTS_FILE
            
            if not os.path.exists(req_file):
                return {
                    'scan_status': 'file_not_found',
                    'error': f"Requirements file not found: {req_file}"
                }
            
            # Build Safety scan command
            scan_command = self._build_safety_command(req_file)
            
            self.logger.info(f"Executing Safety dependency scan: {scan_command}")
            
            result = subprocess.run(
                scan_command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.config.SECURITY_TEST_TIMEOUT
            )
            
            # Parse Safety results
            scan_results = self._parse_safety_results(result.stdout, result.stderr, result.returncode)
            
            # Validate against security thresholds
            validation_results = self._validate_dependency_thresholds(scan_results)
            
            self.scan_results = {
                **scan_results,
                'threshold_validation': validation_results,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'requirements_file': req_file
            }
            
            self.logger.info(f"Safety scan completed: {len(scan_results.get('vulnerabilities', []))} vulnerabilities found")
            
            return self.scan_results
            
        except subprocess.TimeoutExpired:
            error_msg = f"Safety scan timed out after {self.config.SECURITY_TEST_TIMEOUT} seconds"
            self.logger.error(error_msg)
            return {'error': error_msg, 'scan_status': 'timeout'}
        except Exception as e:
            error_msg = f"Safety scan failed: {str(e)}"
            self.logger.error(error_msg)
            return {'error': error_msg, 'scan_status': 'failed'}
    
    def _build_safety_command(self, requirements_file: str) -> List[str]:
        """Build Safety command with dependency scanning configuration."""
        command = [
            'safety',
            'check',
            '--json',
            '--file', requirements_file
        ]
        
        # Add ignored vulnerabilities
        if self.config.SAFETY_IGNORE_VULNERABILITIES:
            for vuln_id in self.config.SAFETY_IGNORE_VULNERABILITIES:
                command.extend(['--ignore', vuln_id])
        
        return command
    
    def _parse_safety_results(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        """Parse Safety scan results from JSON output."""
        try:
            if stdout and stdout.strip():
                results = json.loads(stdout)
                
                # Safety returns list of vulnerabilities
                vulnerabilities = results if isinstance(results, list) else []
                
                # Categorize vulnerabilities by severity
                severity_counts = {severity.value: 0 for severity in VulnerabilitySeverity}
                
                for vuln in vulnerabilities:
                    # Map Safety vulnerability to severity levels
                    severity = self._map_safety_severity(vuln)
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                return {
                    'scan_status': 'completed',
                    'vulnerabilities': vulnerabilities,
                    'total_vulnerabilities': len(vulnerabilities),
                    'severity_counts': severity_counts,
                    'return_code': return_code,
                    'stderr': stderr
                }
            else:
                # No vulnerabilities found
                return {
                    'scan_status': 'completed',
                    'vulnerabilities': [],
                    'total_vulnerabilities': 0,
                    'severity_counts': {severity.value: 0 for severity in VulnerabilitySeverity},
                    'return_code': return_code,
                    'stderr': stderr
                }
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Safety JSON output: {str(e)}")
            return {
                'scan_status': 'parse_error',
                'error': str(e),
                'raw_output': stdout,
                'stderr': stderr
            }
    
    def _map_safety_severity(self, vulnerability: Dict[str, Any]) -> str:
        """Map Safety vulnerability data to severity levels."""
        # Safety doesn't provide direct severity mapping
        # Use heuristics based on vulnerability description and CVE data
        vuln_id = vulnerability.get('id', '').lower()
        description = vulnerability.get('advisory', '').lower()
        
        # Critical severity indicators
        critical_indicators = [
            'remote code execution',
            'arbitrary code execution',
            'privilege escalation',
            'authentication bypass',
            'sql injection'
        ]
        
        # High severity indicators
        high_indicators = [
            'cross-site scripting',
            'xss',
            'csrf',
            'path traversal',
            'directory traversal',
            'denial of service'
        ]
        
        # Check for critical vulnerabilities
        if any(indicator in description for indicator in critical_indicators):
            return VulnerabilitySeverity.CRITICAL.value
        
        # Check for high severity vulnerabilities
        if any(indicator in description for indicator in high_indicators):
            return VulnerabilitySeverity.HIGH.value
        
        # Default to medium severity
        return VulnerabilitySeverity.MEDIUM.value
    
    def _validate_dependency_thresholds(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate dependency scan results against security thresholds."""
        validation_results = {
            'passed': True,
            'violations': [],
            'compliance_score': 0.0
        }
        
        severity_counts = scan_results.get('severity_counts', {})
        
        # Check vulnerability thresholds
        for severity, count in severity_counts.items():
            threshold = self.config.get_vulnerability_threshold(VulnerabilitySeverity(severity))
            
            if count > threshold:
                validation_results['passed'] = False
                validation_results['violations'].append({
                    'type': 'dependency_vulnerability_threshold',
                    'severity': severity,
                    'count': count,
                    'threshold': threshold,
                    'message': f"Found {count} {severity} dependency vulnerabilities, threshold is {threshold}"
                })
        
        # Calculate compliance score based on vulnerabilities
        total_vulns = scan_results.get('total_vulnerabilities', 0)
        if total_vulns == 0:
            validation_results['compliance_score'] = 100.0
        else:
            # Penalty-based scoring for dependencies
            base_score = 100.0
            penalty_per_vuln = {
                VulnerabilitySeverity.CRITICAL.value: 25.0,
                VulnerabilitySeverity.HIGH.value: 15.0,
                VulnerabilitySeverity.MEDIUM.value: 8.0,
                VulnerabilitySeverity.LOW.value: 3.0,
                VulnerabilitySeverity.INFO.value: 1.0
            }
            
            total_penalty = 0
            for severity, count in severity_counts.items():
                total_penalty += count * penalty_per_vuln.get(severity, 1.0)
            
            validation_results['compliance_score'] = max(0.0, base_score - total_penalty)
        
        return validation_results


class OWASPZAPScanner:
    """
    OWASP ZAP dynamic application security testing (DAST) scanner integration.
    
    Implements comprehensive web application penetration testing per Section 6.4.5
    with automated vulnerability discovery and security validation capabilities.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize OWASP ZAP scanner with configuration.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.OWASPZAPScanner")
        self.zap_client: Optional[ZAPv2] = None
        self.scan_results: Dict[str, Any] = {}
    
    def initialize_zap_proxy(self) -> bool:
        """
        Initialize OWASP ZAP proxy client connection.
        
        Returns:
            bool: True if ZAP proxy connection successful
        """
        try:
            self.zap_client = ZAPv2(
                proxies={
                    'http': f"http://{self.config.ZAP_PROXY_HOST}:{self.config.ZAP_PROXY_PORT}",
                    'https': f"http://{self.config.ZAP_PROXY_HOST}:{self.config.ZAP_PROXY_PORT}"
                },
                apikey=self.config.ZAP_API_KEY
            )
            
            # Test ZAP connection
            version = self.zap_client.core.version
            self.logger.info(f"Connected to OWASP ZAP version: {version}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to OWASP ZAP: {str(e)}")
            return False
    
    def run_security_scan(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute OWASP ZAP security scan on target application.
        
        Args:
            target_url: Target URL for security scanning
            
        Returns:
            Dict containing ZAP scan results and vulnerability findings
        """
        if not self.initialize_zap_proxy():
            return {
                'scan_status': 'connection_failed',
                'error': 'Failed to connect to OWASP ZAP proxy'
            }
        
        target = target_url or self.config.ZAP_TARGET_URL
        
        try:
            self.logger.info(f"Starting OWASP ZAP security scan for: {target}")
            
            # Start ZAP scan phases
            scan_results = {}
            
            # Phase 1: Spider scan for discovery
            spider_results = self._run_spider_scan(target)
            scan_results['spider'] = spider_results
            
            # Phase 2: Active scan for vulnerabilities
            active_results = self._run_active_scan(target)
            scan_results['active'] = active_results
            
            # Phase 3: Get alerts and findings
            alerts_results = self._get_security_alerts()
            scan_results['alerts'] = alerts_results
            
            # Phase 4: Generate comprehensive report
            report_results = self._generate_scan_report()
            scan_results['report'] = report_results
            
            # Validate against security thresholds
            validation_results = self._validate_zap_thresholds(alerts_results)
            scan_results['threshold_validation'] = validation_results
            
            self.scan_results = {
                **scan_results,
                'scan_status': 'completed',
                'target_url': target,
                'scan_timestamp': datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"OWASP ZAP scan completed: {len(alerts_results.get('alerts', []))} alerts found")
            
            return self.scan_results
            
        except Exception as e:
            error_msg = f"OWASP ZAP scan failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'scan_status': 'failed',
                'error': error_msg,
                'target_url': target
            }
    
    def _run_spider_scan(self, target_url: str) -> Dict[str, Any]:
        """Run ZAP spider scan for application discovery."""
        try:
            self.logger.info(f"Starting ZAP spider scan for: {target_url}")
            
            # Start spider scan
            scan_id = self.zap_client.spider.scan(target_url)
            
            # Wait for spider to complete
            timeout = 300  # 5 minutes timeout for spider
            start_time = time.time()
            
            while int(self.zap_client.spider.status(scan_id)) < 100:
                if time.time() - start_time > timeout:
                    self.logger.warning("Spider scan timed out")
                    break
                time.sleep(5)
            
            # Get spider results
            urls_found = self.zap_client.spider.results(scan_id)
            
            return {
                'status': 'completed',
                'scan_id': scan_id,
                'urls_found': len(urls_found),
                'discovered_urls': urls_found[:50]  # Limit for logging
            }
            
        except Exception as e:
            self.logger.error(f"Spider scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _run_active_scan(self, target_url: str) -> Dict[str, Any]:
        """Run ZAP active scan for vulnerability detection."""
        try:
            self.logger.info(f"Starting ZAP active scan for: {target_url}")
            
            # Start active scan
            scan_id = self.zap_client.ascan.scan(target_url)
            
            # Wait for active scan to complete
            timeout = self.config.ZAP_SCAN_TIMEOUT
            start_time = time.time()
            
            while int(self.zap_client.ascan.status(scan_id)) < 100:
                if time.time() - start_time > timeout:
                    self.logger.warning(f"Active scan timed out after {timeout} seconds")
                    break
                
                progress = self.zap_client.ascan.status(scan_id)
                self.logger.debug(f"Active scan progress: {progress}%")
                time.sleep(10)
            
            return {
                'status': 'completed',
                'scan_id': scan_id,
                'final_progress': self.zap_client.ascan.status(scan_id)
            }
            
        except Exception as e:
            self.logger.error(f"Active scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _get_security_alerts(self) -> Dict[str, Any]:
        """Retrieve security alerts from ZAP scan."""
        try:
            # Get all alerts
            alerts = self.zap_client.core.alerts()
            
            # Categorize alerts by risk level
            risk_counts = {
                'high': 0,
                'medium': 0,
                'low': 0,
                'informational': 0
            }
            
            filtered_alerts = []
            
            for alert in alerts:
                risk_level = alert.get('risk', 'informational').lower()
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
                
                # Filter by configured alert threshold
                if self._meets_alert_threshold(risk_level):
                    filtered_alerts.append(alert)
            
            return {
                'total_alerts': len(alerts),
                'filtered_alerts': len(filtered_alerts),
                'alerts': filtered_alerts,
                'risk_counts': risk_counts
            }
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve ZAP alerts: {str(e)}")
            return {
                'error': str(e),
                'alerts': []
            }
    
    def _meets_alert_threshold(self, risk_level: str) -> bool:
        """Check if alert meets configured threshold."""
        threshold_map = {
            VulnerabilitySeverity.CRITICAL.value: ['high'],
            VulnerabilitySeverity.HIGH.value: ['high'],
            VulnerabilitySeverity.MEDIUM.value: ['high', 'medium'],
            VulnerabilitySeverity.LOW.value: ['high', 'medium', 'low']
        }
        
        allowed_levels = threshold_map.get(self.config.ZAP_ALERT_THRESHOLD, ['high', 'medium', 'low'])
        return risk_level in allowed_levels
    
    def _generate_scan_report(self) -> Dict[str, Any]:
        """Generate comprehensive ZAP scan report."""
        try:
            # Generate HTML report
            html_report = self.zap_client.core.htmlreport()
            
            # Generate XML report
            xml_report = self.zap_client.core.xmlreport()
            
            # Save reports to files
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            html_file = f"zap_report_{timestamp}.html"
            xml_file = f"zap_report_{timestamp}.xml"
            
            with open(html_file, 'w') as f:
                f.write(html_report)
            
            with open(xml_file, 'w') as f:
                f.write(xml_report)
            
            return {
                'html_report_file': html_file,
                'xml_report_file': xml_file,
                'report_size_html': len(html_report),
                'report_size_xml': len(xml_report)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate ZAP reports: {str(e)}")
            return {
                'error': str(e)
            }
    
    def _validate_zap_thresholds(self, alerts_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate ZAP scan results against security thresholds."""
        validation_results = {
            'passed': True,
            'violations': [],
            'compliance_score': 0.0
        }
        
        risk_counts = alerts_results.get('risk_counts', {})
        
        # Map ZAP risk levels to our severity levels
        severity_mapping = {
            'high': VulnerabilitySeverity.HIGH.value,
            'medium': VulnerabilitySeverity.MEDIUM.value,
            'low': VulnerabilitySeverity.LOW.value,
            'informational': VulnerabilitySeverity.INFO.value
        }
        
        # Check thresholds
        for zap_risk, count in risk_counts.items():
            if zap_risk in severity_mapping:
                severity = severity_mapping[zap_risk]
                threshold = self.config.get_vulnerability_threshold(VulnerabilitySeverity(severity))
                
                if count > threshold:
                    validation_results['passed'] = False
                    validation_results['violations'].append({
                        'type': 'zap_alert_threshold',
                        'risk_level': zap_risk,
                        'count': count,
                        'threshold': threshold,
                        'message': f"Found {count} {zap_risk} risk alerts, threshold is {threshold}"
                    })
        
        # Calculate compliance score
        total_alerts = sum(risk_counts.values())
        if total_alerts == 0:
            validation_results['compliance_score'] = 100.0
        else:
            # Weight alerts by risk level
            risk_weights = {
                'high': 20,
                'medium': 10,
                'low': 5,
                'informational': 1
            }
            
            penalty_score = sum(count * risk_weights.get(risk, 1) for risk, count in risk_counts.items())
            validation_results['compliance_score'] = max(0.0, 100.0 - penalty_score)
        
        return validation_results


class PenetrationTestRunner:
    """
    Comprehensive penetration testing framework for security validation.
    
    Implements attack simulation scenarios per Section 6.4.5 with configurable
    attack vectors and comprehensive security validation capabilities.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize penetration testing framework.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PenetrationTestRunner")
        self.test_results: Dict[str, Any] = {}
        self.attack_scenarios: Dict[str, Dict[str, Any]] = {}
    
    def run_penetration_tests(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute comprehensive penetration testing scenarios.
        
        Args:
            target_url: Target URL for penetration testing
            
        Returns:
            Dict containing penetration test results and findings
        """
        target = target_url or self.config.ZAP_TARGET_URL
        
        try:
            self.logger.info(f"Starting penetration tests for: {target}")
            
            # Initialize test scenarios
            self._initialize_attack_scenarios(target)
            
            # Execute test scenarios in parallel
            test_results = {}
            
            with ThreadPoolExecutor(max_workers=self.config.SECURITY_TEST_PARALLEL_WORKERS) as executor:
                # Submit all enabled test scenarios
                future_to_scenario = {}
                
                for scenario_name, scenario_config in self.config.PENETRATION_TEST_SCENARIOS.items():
                    if scenario_config.get('enabled', True):
                        future = executor.submit(self._execute_test_scenario, scenario_name, scenario_config, target)
                        future_to_scenario[future] = scenario_name
                
                # Collect results
                for future in future_to_scenario:
                    scenario_name = future_to_scenario[future]
                    try:
                        scenario_result = future.result(timeout=scenario_config.get('timeout', 600))
                        test_results[scenario_name] = scenario_result
                    except TimeoutError:
                        test_results[scenario_name] = {
                            'status': 'timeout',
                            'error': f"Test scenario {scenario_name} timed out"
                        }
                    except Exception as e:
                        test_results[scenario_name] = {
                            'status': 'failed',
                            'error': str(e)
                        }
            
            # Generate comprehensive report
            summary = self._generate_penetration_test_summary(test_results)
            
            self.test_results = {
                'test_status': 'completed',
                'target_url': target,
                'scenarios': test_results,
                'summary': summary,
                'test_timestamp': datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Penetration tests completed: {summary['total_scenarios']} scenarios executed")
            
            return self.test_results
            
        except Exception as e:
            error_msg = f"Penetration testing failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'test_status': 'failed',
                'error': error_msg,
                'target_url': target
            }
    
    def _initialize_attack_scenarios(self, target_url: str) -> None:
        """Initialize attack scenarios with target-specific configuration."""
        self.attack_scenarios = {
            'authentication_bypass': {
                'attacks': [
                    self._test_sql_injection_auth,
                    self._test_weak_password_policy,
                    self._test_session_fixation,
                    self._test_brute_force_protection
                ]
            },
            'authorization_escalation': {
                'attacks': [
                    self._test_privilege_escalation,
                    self._test_idor_vulnerabilities,
                    self._test_path_traversal,
                    self._test_horizontal_privilege_escalation
                ]
            },
            'input_validation_bypass': {
                'attacks': [
                    self._test_xss_vulnerabilities,
                    self._test_sql_injection,
                    self._test_command_injection,
                    self._test_xxe_vulnerabilities
                ]
            },
            'session_attacks': {
                'attacks': [
                    self._test_session_hijacking,
                    self._test_csrf_protection,
                    self._test_session_timeout,
                    self._test_cookie_security
                ]
            },
            'api_security_tests': {
                'attacks': [
                    self._test_api_fuzzing,
                    self._test_rate_limit_bypass,
                    self._test_jwt_attacks,
                    self._test_api_versioning_security
                ]
            }
        }
    
    def _execute_test_scenario(self, scenario_name: str, scenario_config: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """Execute individual penetration test scenario."""
        try:
            self.logger.info(f"Executing penetration test scenario: {scenario_name}")
            
            scenario_results = {
                'scenario_name': scenario_name,
                'status': 'running',
                'attacks': {},
                'vulnerabilities_found': [],
                'start_time': datetime.utcnow().isoformat()
            }
            
            # Get attack functions for this scenario
            attack_functions = self.attack_scenarios.get(scenario_name, {}).get('attacks', [])
            
            # Execute each attack in the scenario
            for attack_func in attack_functions:
                attack_name = attack_func.__name__
                
                try:
                    attack_result = attack_func(target_url, scenario_config)
                    scenario_results['attacks'][attack_name] = attack_result
                    
                    # Collect vulnerabilities
                    if attack_result.get('vulnerabilities'):
                        scenario_results['vulnerabilities_found'].extend(attack_result['vulnerabilities'])
                        
                except Exception as e:
                    scenario_results['attacks'][attack_name] = {
                        'status': 'failed',
                        'error': str(e)
                    }
            
            scenario_results['status'] = 'completed'
            scenario_results['end_time'] = datetime.utcnow().isoformat()
            scenario_results['total_vulnerabilities'] = len(scenario_results['vulnerabilities_found'])
            
            return scenario_results
            
        except Exception as e:
            return {
                'scenario_name': scenario_name,
                'status': 'failed',
                'error': str(e)
            }
    
    # Authentication Attack Methods
    def _test_sql_injection_auth(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities in authentication endpoints."""
        vulnerabilities = []
        
        try:
            # Test common SQL injection payloads
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT 1,2,3 --",
                "admin'--",
                "' OR 1=1#"
            ]
            
            auth_endpoints = config.get('target_endpoints', ['/api/auth/login'])
            
            for endpoint in auth_endpoints:
                endpoint_url = f"{target_url.rstrip('/')}{endpoint}"
                
                for payload in sql_payloads:
                    test_data = {
                        'username': payload,
                        'password': 'test123'
                    }
                    
                    try:
                        response = requests.post(
                            endpoint_url,
                            json=test_data,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for SQL injection indicators
                        if self._check_sql_injection_response(response):
                            vulnerabilities.append({
                                'type': 'sql_injection',
                                'severity': VulnerabilitySeverity.CRITICAL.value,
                                'endpoint': endpoint,
                                'payload': payload,
                                'description': f"SQL injection vulnerability detected in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'sql_injection_auth',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(sql_payloads) * len(auth_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'sql_injection_auth',
                'error': str(e)
            }
    
    def _test_weak_password_policy(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test password policy enforcement."""
        vulnerabilities = []
        
        try:
            weak_passwords = [
                'password',
                '123456',
                'admin',
                'test',
                '1234',
                'password123'
            ]
            
            # Test password registration/change endpoints
            for password in weak_passwords:
                # Simulate user registration with weak password
                test_data = {
                    'username': 'testuser',
                    'password': password,
                    'email': 'test@example.com'
                }
                
                try:
                    response = requests.post(
                        f"{target_url}/api/auth/register",
                        json=test_data,
                        timeout=10,
                        verify=False
                    )
                    
                    # Check if weak password was accepted
                    if response.status_code == 201 or response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'weak_password_policy',
                            'severity': VulnerabilitySeverity.MEDIUM.value,
                            'password': password,
                            'description': f"Weak password '{password}' was accepted"
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'weak_password_policy',
                'vulnerabilities': vulnerabilities,
                'passwords_tested': len(weak_passwords)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'weak_password_policy',
                'error': str(e)
            }
    
    def _test_session_fixation(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for session fixation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test session fixation by attempting to preserve session ID after login
            session = requests.Session()
            
            # Get initial session
            response1 = session.get(f"{target_url}/api/auth/profile", verify=False)
            initial_session_id = session.cookies.get('session', None)
            
            if initial_session_id:
                # Attempt login with fixed session
                login_data = {
                    'username': 'admin',
                    'password': 'admin123'
                }
                
                response2 = session.post(
                    f"{target_url}/api/auth/login",
                    json=login_data,
                    verify=False
                )
                
                post_login_session_id = session.cookies.get('session', None)
                
                # Check if session ID remained the same (vulnerability)
                if initial_session_id == post_login_session_id and response2.status_code == 200:
                    vulnerabilities.append({
                        'type': 'session_fixation',
                        'severity': VulnerabilitySeverity.HIGH.value,
                        'description': "Session ID not regenerated after authentication"
                    })
            
            return {
                'status': 'completed',
                'attack_type': 'session_fixation',
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'session_fixation',
                'error': str(e)
            }
    
    def _test_brute_force_protection(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test brute force protection mechanisms."""
        vulnerabilities = []
        
        try:
            # Attempt multiple failed logins
            failed_attempts = 0
            max_attempts = 20
            
            for attempt in range(max_attempts):
                login_data = {
                    'username': 'admin',
                    'password': f'wrongpassword{attempt}'
                }
                
                try:
                    response = requests.post(
                        f"{target_url}/api/auth/login",
                        json=login_data,
                        timeout=5,
                        verify=False
                    )
                    
                    if response.status_code == 401:
                        failed_attempts += 1
                    elif response.status_code == 429:  # Rate limited
                        break
                    
                except requests.RequestException:
                    continue
            
            # Check if rate limiting kicked in
            if failed_attempts >= 10:  # Allow up to 10 attempts before expecting rate limiting
                vulnerabilities.append({
                    'type': 'insufficient_brute_force_protection',
                    'severity': VulnerabilitySeverity.MEDIUM.value,
                    'failed_attempts': failed_attempts,
                    'description': f"No rate limiting after {failed_attempts} failed login attempts"
                })
            
            return {
                'status': 'completed',
                'attack_type': 'brute_force_protection',
                'vulnerabilities': vulnerabilities,
                'attempts_made': failed_attempts
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'brute_force_protection',
                'error': str(e)
            }
    
    # Authorization Attack Methods
    def _test_privilege_escalation(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test horizontal privilege escalation by accessing other users' data
            test_endpoints = [
                '/api/users/1',
                '/api/users/profile',
                '/api/admin/users',
                '/api/admin/settings'
            ]
            
            # Test with user-level token (if available)
            headers = {'Authorization': 'Bearer user-token-here'}
            
            for endpoint in test_endpoints:
                try:
                    response = requests.get(
                        f"{target_url}{endpoint}",
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Check for successful access to privileged endpoints
                    if response.status_code == 200 and 'admin' in endpoint:
                        vulnerabilities.append({
                            'type': 'privilege_escalation',
                            'severity': VulnerabilitySeverity.HIGH.value,
                            'endpoint': endpoint,
                            'description': f"User-level access granted to admin endpoint: {endpoint}"
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'privilege_escalation',
                'vulnerabilities': vulnerabilities,
                'endpoints_tested': len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'privilege_escalation',
                'error': str(e)
            }
    
    def _test_idor_vulnerabilities(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for Insecure Direct Object Reference (IDOR) vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test IDOR by accessing different user IDs
            user_ids = range(1, 11)  # Test user IDs 1-10
            
            for user_id in user_ids:
                endpoint = f"/api/users/{user_id}"
                
                try:
                    response = requests.get(
                        f"{target_url}{endpoint}",
                        timeout=10,
                        verify=False
                    )
                    
                    # Check for successful access without authorization
                    if response.status_code == 200:
                        response_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                        
                        # Check if sensitive user data is exposed
                        if any(field in str(response_data).lower() for field in ['email', 'phone', 'ssn', 'password']):
                            vulnerabilities.append({
                                'type': 'idor',
                                'severity': VulnerabilitySeverity.HIGH.value,
                                'endpoint': endpoint,
                                'user_id': user_id,
                                'description': f"IDOR vulnerability allows access to user {user_id} data"
                            })
                            
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'idor_vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'user_ids_tested': len(user_ids)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'idor_vulnerabilities',
                'error': str(e)
            }
    
    def _test_path_traversal(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for path traversal vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Path traversal payloads
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '../../../app.py',
                '../../../requirements.txt',
                '....//....//....//etc/passwd'
            ]
            
            # Test endpoints that might handle file paths
            test_endpoints = [
                '/api/files/',
                '/api/download/',
                '/api/static/',
                '/api/export/'
            ]
            
            for endpoint in test_endpoints:
                for payload in traversal_payloads:
                    test_url = f"{target_url}{endpoint}{payload}"
                    
                    try:
                        response = requests.get(
                            test_url,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for path traversal indicators
                        if self._check_path_traversal_response(response):
                            vulnerabilities.append({
                                'type': 'path_traversal',
                                'severity': VulnerabilitySeverity.HIGH.value,
                                'endpoint': endpoint,
                                'payload': payload,
                                'description': f"Path traversal vulnerability in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'path_traversal',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(traversal_payloads) * len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'path_traversal',
                'error': str(e)
            }
    
    def _test_horizontal_privilege_escalation(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for horizontal privilege escalation."""
        vulnerabilities = []
        
        try:
            # Simulate two different users
            users = [
                {'id': 1, 'token': 'user1-token'},
                {'id': 2, 'token': 'user2-token'}
            ]
            
            # Test cross-user access
            for user in users:
                other_user_id = 2 if user['id'] == 1 else 1
                
                # Try to access other user's data
                endpoint = f"/api/users/{other_user_id}/profile"
                headers = {'Authorization': f"Bearer {user['token']}"}
                
                try:
                    response = requests.get(
                        f"{target_url}{endpoint}",
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Check if user can access other user's data
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'horizontal_privilege_escalation',
                            'severity': VulnerabilitySeverity.HIGH.value,
                            'user_id': user['id'],
                            'accessed_user_id': other_user_id,
                            'endpoint': endpoint,
                            'description': f"User {user['id']} can access user {other_user_id}'s data"
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'horizontal_privilege_escalation',
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'horizontal_privilege_escalation',
                'error': str(e)
            }
    
    # Input Validation Attack Methods
    def _test_xss_vulnerabilities(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        vulnerabilities = []
        
        try:
            # XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>'
            ]
            
            # Test endpoints that might reflect user input
            test_endpoints = [
                '/api/search?q=',
                '/api/comments',
                '/api/profile'
            ]
            
            for endpoint in test_endpoints:
                for payload in xss_payloads:
                    try:
                        if '?q=' in endpoint:
                            # GET request for search
                            response = requests.get(
                                f"{target_url}{endpoint}{payload}",
                                timeout=10,
                                verify=False
                            )
                        else:
                            # POST request
                            response = requests.post(
                                f"{target_url}{endpoint}",
                                json={'content': payload},
                                timeout=10,
                                verify=False
                            )
                        
                        # Check for XSS vulnerability
                        if self._check_xss_response(response, payload):
                            vulnerabilities.append({
                                'type': 'xss',
                                'severity': VulnerabilitySeverity.MEDIUM.value,
                                'endpoint': endpoint,
                                'payload': payload,
                                'description': f"XSS vulnerability in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'xss_vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(xss_payloads) * len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'xss_vulnerabilities',
                'error': str(e)
            }
    
    def _test_sql_injection(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities in general endpoints."""
        vulnerabilities = []
        
        try:
            # SQL injection payloads
            sql_payloads = [
                "' OR 1=1--",
                "'; SELECT * FROM users--",
                "' UNION SELECT NULL--",
                "1' ORDER BY 1--",
                "' AND 1=1--"
            ]
            
            # Test various endpoints
            test_endpoints = [
                '/api/search',
                '/api/users',
                '/api/products'
            ]
            
            for endpoint in test_endpoints:
                for payload in sql_payloads:
                    test_data = {'query': payload}
                    
                    try:
                        response = requests.post(
                            f"{target_url}{endpoint}",
                            json=test_data,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for SQL injection indicators
                        if self._check_sql_injection_response(response):
                            vulnerabilities.append({
                                'type': 'sql_injection',
                                'severity': VulnerabilitySeverity.CRITICAL.value,
                                'endpoint': endpoint,
                                'payload': payload,
                                'description': f"SQL injection vulnerability in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'sql_injection',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(sql_payloads) * len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'sql_injection',
                'error': str(e)
            }
    
    def _test_command_injection(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for command injection vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Command injection payloads
            command_payloads = [
                '; ls -la',
                '&& cat /etc/passwd',
                '| whoami',
                '; ping -c 1 127.0.0.1',
                '`id`'
            ]
            
            # Test endpoints that might execute system commands
            test_endpoints = [
                '/api/system/ping',
                '/api/tools/convert',
                '/api/admin/backup'
            ]
            
            for endpoint in test_endpoints:
                for payload in command_payloads:
                    test_data = {'command': f"test{payload}"}
                    
                    try:
                        response = requests.post(
                            f"{target_url}{endpoint}",
                            json=test_data,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for command injection indicators
                        if self._check_command_injection_response(response):
                            vulnerabilities.append({
                                'type': 'command_injection',
                                'severity': VulnerabilitySeverity.CRITICAL.value,
                                'endpoint': endpoint,
                                'payload': payload,
                                'description': f"Command injection vulnerability in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'command_injection',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(command_payloads) * len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'command_injection',
                'error': str(e)
            }
    
    def _test_xxe_vulnerabilities(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for XML External Entity (XXE) vulnerabilities."""
        vulnerabilities = []
        
        try:
            # XXE payloads
            xxe_payloads = [
                '''<?xml version="1.0" encoding="ISO-8859-1"?>
                <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <data>&xxe;</data>''',
                '''<?xml version="1.0" encoding="ISO-8859-1"?>
                <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/test">]>
                <data>&xxe;</data>'''
            ]
            
            # Test endpoints that might accept XML
            test_endpoints = [
                '/api/upload/xml',
                '/api/import/data',
                '/api/config/update'
            ]
            
            for endpoint in test_endpoints:
                for payload in xxe_payloads:
                    headers = {'Content-Type': 'application/xml'}
                    
                    try:
                        response = requests.post(
                            f"{target_url}{endpoint}",
                            data=payload,
                            headers=headers,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for XXE vulnerability indicators
                        if self._check_xxe_response(response):
                            vulnerabilities.append({
                                'type': 'xxe',
                                'severity': VulnerabilitySeverity.HIGH.value,
                                'endpoint': endpoint,
                                'description': f"XXE vulnerability in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'xxe_vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(xxe_payloads) * len(test_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'xxe_vulnerabilities',
                'error': str(e)
            }
    
    # Session Attack Methods
    def _test_session_hijacking(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for session hijacking vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test session security
            session = requests.Session()
            
            # Get session cookie
            response = session.get(f"{target_url}/api/auth/profile", verify=False)
            session_cookie = session.cookies.get('session')
            
            if session_cookie:
                # Test session cookie security attributes
                cookie_security = self._check_cookie_security(session.cookies)
                
                if not cookie_security['secure']:
                    vulnerabilities.append({
                        'type': 'insecure_session_cookie',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'description': "Session cookie missing Secure flag"
                    })
                
                if not cookie_security['httponly']:
                    vulnerabilities.append({
                        'type': 'session_cookie_xss',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'description': "Session cookie missing HttpOnly flag"
                    })
                
                if not cookie_security['samesite']:
                    vulnerabilities.append({
                        'type': 'session_cookie_csrf',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'description': "Session cookie missing SameSite attribute"
                    })
            
            return {
                'status': 'completed',
                'attack_type': 'session_hijacking',
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'session_hijacking',
                'error': str(e)
            }
    
    def _test_csrf_protection(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test for Cross-Site Request Forgery (CSRF) protection."""
        vulnerabilities = []
        
        try:
            # Test state-changing operations without CSRF tokens
            test_operations = [
                {'method': 'POST', 'endpoint': '/api/users/profile', 'data': {'name': 'test'}},
                {'method': 'DELETE', 'endpoint': '/api/users/1', 'data': {}},
                {'method': 'PUT', 'endpoint': '/api/settings', 'data': {'setting': 'value'}}
            ]
            
            for operation in test_operations:
                try:
                    # Make request without CSRF token
                    if operation['method'] == 'POST':
                        response = requests.post(
                            f"{target_url}{operation['endpoint']}",
                            json=operation['data'],
                            timeout=10,
                            verify=False
                        )
                    elif operation['method'] == 'DELETE':
                        response = requests.delete(
                            f"{target_url}{operation['endpoint']}",
                            timeout=10,
                            verify=False
                        )
                    elif operation['method'] == 'PUT':
                        response = requests.put(
                            f"{target_url}{operation['endpoint']}",
                            json=operation['data'],
                            timeout=10,
                            verify=False
                        )
                    
                    # Check if operation succeeded without CSRF protection
                    if response.status_code in [200, 201, 204]:
                        vulnerabilities.append({
                            'type': 'csrf',
                            'severity': VulnerabilitySeverity.MEDIUM.value,
                            'endpoint': operation['endpoint'],
                            'method': operation['method'],
                            'description': f"CSRF protection missing for {operation['method']} {operation['endpoint']}"
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'csrf_protection',
                'vulnerabilities': vulnerabilities,
                'operations_tested': len(test_operations)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'csrf_protection',
                'error': str(e)
            }
    
    def _test_session_timeout(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test session timeout mechanisms."""
        vulnerabilities = []
        
        try:
            # Test session timeout by checking if old sessions remain valid
            session = requests.Session()
            
            # Authenticate to get valid session
            login_data = {'username': 'admin', 'password': 'admin123'}
            login_response = session.post(
                f"{target_url}/api/auth/login",
                json=login_data,
                verify=False
            )
            
            if login_response.status_code == 200:
                # Wait for potential session timeout (simplified test)
                time.sleep(2)  # In real scenario, would wait longer
                
                # Check if session is still valid
                profile_response = session.get(
                    f"{target_url}/api/auth/profile",
                    verify=False
                )
                
                # Note: This is a simplified test - real timeout testing would require longer waits
                if profile_response.status_code == 200:
                    # Check for session timeout configuration
                    # This would typically require checking session metadata
                    pass
            
            return {
                'status': 'completed',
                'attack_type': 'session_timeout',
                'vulnerabilities': vulnerabilities,
                'note': 'Session timeout testing requires longer observation periods'
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'session_timeout',
                'error': str(e)
            }
    
    def _test_cookie_security(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test cookie security attributes."""
        vulnerabilities = []
        
        try:
            # Get cookies from the application
            response = requests.get(f"{target_url}/", verify=False)
            
            for cookie in response.cookies:
                cookie_security = self._analyze_cookie_security(cookie)
                
                if not cookie_security['secure']:
                    vulnerabilities.append({
                        'type': 'insecure_cookie',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'cookie_name': cookie.name,
                        'description': f"Cookie '{cookie.name}' missing Secure flag"
                    })
                
                if not cookie_security['httponly']:
                    vulnerabilities.append({
                        'type': 'cookie_xss_risk',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'cookie_name': cookie.name,
                        'description': f"Cookie '{cookie.name}' missing HttpOnly flag"
                    })
            
            return {
                'status': 'completed',
                'attack_type': 'cookie_security',
                'vulnerabilities': vulnerabilities,
                'cookies_analyzed': len(response.cookies)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'cookie_security',
                'error': str(e)
            }
    
    # API Security Attack Methods
    def _test_api_fuzzing(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test API endpoints with fuzzing techniques."""
        vulnerabilities = []
        
        try:
            # Common API endpoints to fuzz
            api_endpoints = [
                '/api/users',
                '/api/auth/login',
                '/api/products',
                '/api/orders'
            ]
            
            # Fuzzing payloads
            fuzz_payloads = [
                {'type': 'oversized', 'data': 'A' * 10000},
                {'type': 'null_bytes', 'data': 'test\x00data'},
                {'type': 'unicode', 'data': '测试数据'},
                {'type': 'special_chars', 'data': '!@#$%^&*()'},
                {'type': 'negative_numbers', 'data': -9999999}
            ]
            
            for endpoint in api_endpoints:
                for payload in fuzz_payloads:
                    test_data = {'test_field': payload['data']}
                    
                    try:
                        response = requests.post(
                            f"{target_url}{endpoint}",
                            json=test_data,
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for error disclosure or unexpected behavior
                        if self._check_fuzzing_response(response, payload):
                            vulnerabilities.append({
                                'type': 'api_fuzzing_error',
                                'severity': VulnerabilitySeverity.LOW.value,
                                'endpoint': endpoint,
                                'payload_type': payload['type'],
                                'description': f"API fuzzing revealed error in {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'api_fuzzing',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(fuzz_payloads) * len(api_endpoints)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'api_fuzzing',
                'error': str(e)
            }
    
    def _test_rate_limit_bypass(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test rate limiting bypass techniques."""
        vulnerabilities = []
        
        try:
            # Test rate limiting bypass methods
            bypass_methods = [
                {'type': 'user_agent_rotation', 'headers': {'User-Agent': 'TestAgent1'}},
                {'type': 'x_forwarded_for', 'headers': {'X-Forwarded-For': '192.168.1.1'}},
                {'type': 'x_real_ip', 'headers': {'X-Real-IP': '10.0.0.1'}},
                {'type': 'origin_header', 'headers': {'Origin': 'https://trusted-domain.com'}}
            ]
            
            test_endpoint = '/api/auth/login'
            
            for method in bypass_methods:
                # Attempt multiple requests with bypass headers
                successful_requests = 0
                
                for i in range(20):  # Try 20 requests
                    test_data = {'username': 'test', 'password': f'pass{i}'}
                    
                    try:
                        response = requests.post(
                            f"{target_url}{test_endpoint}",
                            json=test_data,
                            headers=method['headers'],
                            timeout=5,
                            verify=False
                        )
                        
                        if response.status_code != 429:  # Not rate limited
                            successful_requests += 1
                        else:
                            break
                            
                    except requests.RequestException:
                        continue
                
                # Check if rate limiting was bypassed
                if successful_requests > 10:
                    vulnerabilities.append({
                        'type': 'rate_limit_bypass',
                        'severity': VulnerabilitySeverity.MEDIUM.value,
                        'bypass_method': method['type'],
                        'successful_requests': successful_requests,
                        'description': f"Rate limiting bypassed using {method['type']}"
                    })
            
            return {
                'status': 'completed',
                'attack_type': 'rate_limit_bypass',
                'vulnerabilities': vulnerabilities,
                'bypass_methods_tested': len(bypass_methods)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'rate_limit_bypass',
                'error': str(e)
            }
    
    def _test_jwt_attacks(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test JWT token security vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test JWT attacks
            jwt_attacks = [
                {
                    'type': 'none_algorithm',
                    'token': 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
                },
                {
                    'type': 'weak_secret',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
                }
            ]
            
            for attack in jwt_attacks:
                headers = {'Authorization': f'Bearer {attack["token"]}'}
                
                try:
                    response = requests.get(
                        f"{target_url}/api/auth/profile",
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Check if malicious JWT was accepted
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': f'jwt_{attack["type"]}',
                            'severity': VulnerabilitySeverity.HIGH.value,
                            'attack_type': attack['type'],
                            'description': f"JWT {attack['type']} attack successful"
                        })
                        
                except requests.RequestException:
                    continue
            
            return {
                'status': 'completed',
                'attack_type': 'jwt_attacks',
                'vulnerabilities': vulnerabilities,
                'attacks_tested': len(jwt_attacks)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'jwt_attacks',
                'error': str(e)
            }
    
    def _test_api_versioning_security(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test API versioning security issues."""
        vulnerabilities = []
        
        try:
            # Test different API versions
            api_versions = ['v1', 'v2', 'v3', 'beta', 'alpha', 'test']
            base_endpoint = '/api/users'
            
            for version in api_versions:
                version_endpoints = [
                    f"/api/{version}/users",
                    f"/{version}/api/users",
                    f"/api/users?version={version}"
                ]
                
                for endpoint in version_endpoints:
                    try:
                        response = requests.get(
                            f"{target_url}{endpoint}",
                            timeout=10,
                            verify=False
                        )
                        
                        # Check for unauthorized access to API versions
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'api_version_exposure',
                                'severity': VulnerabilitySeverity.LOW.value,
                                'version': version,
                                'endpoint': endpoint,
                                'description': f"Exposed API version {version} at {endpoint}"
                            })
                            
                    except requests.RequestException:
                        continue
            
            return {
                'status': 'completed',
                'attack_type': 'api_versioning_security',
                'vulnerabilities': vulnerabilities,
                'versions_tested': len(api_versions)
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'attack_type': 'api_versioning_security',
                'error': str(e)
            }
    
    # Helper Methods for Response Analysis
    def _check_sql_injection_response(self, response: requests.Response) -> bool:
        """Check response for SQL injection indicators."""
        try:
            content = response.text.lower()
            sql_error_indicators = [
                'sql syntax',
                'mysql_fetch',
                'ora-01756',
                'microsoft jet database',
                'odbc sql server driver',
                'sqlite_prepare',
                'postgre sql error'
            ]
            
            return any(indicator in content for indicator in sql_error_indicators)
        except:
            return False
    
    def _check_xss_response(self, response: requests.Response, payload: str) -> bool:
        """Check response for XSS vulnerability indicators."""
        try:
            content = response.text
            # Check if payload is reflected without encoding
            return payload in content and response.headers.get('content-type', '').startswith('text/html')
        except:
            return False
    
    def _check_path_traversal_response(self, response: requests.Response) -> bool:
        """Check response for path traversal indicators."""
        try:
            content = response.text.lower()
            traversal_indicators = [
                'root:x:',
                '[system process]',
                'boot.ini',
                'etc/passwd',
                'system32'
            ]
            
            return any(indicator in content for indicator in traversal_indicators)
        except:
            return False
    
    def _check_command_injection_response(self, response: requests.Response) -> bool:
        """Check response for command injection indicators."""
        try:
            content = response.text.lower()
            command_indicators = [
                'uid=',
                'gid=',
                'root@',
                'administrator',
                'command not found',
                'permission denied'
            ]
            
            return any(indicator in content for indicator in command_indicators)
        except:
            return False
    
    def _check_xxe_response(self, response: requests.Response) -> bool:
        """Check response for XXE vulnerability indicators."""
        try:
            content = response.text.lower()
            xxe_indicators = [
                'root:x:',
                'etc/passwd',
                'internal server error',
                'xml parsing error'
            ]
            
            return any(indicator in content for indicator in xxe_indicators)
        except:
            return False
    
    def _check_cookie_security(self, cookies) -> Dict[str, bool]:
        """Analyze cookie security attributes."""
        security_attrs = {
            'secure': False,
            'httponly': False,
            'samesite': False
        }
        
        for cookie in cookies:
            if hasattr(cookie, 'secure') and cookie.secure:
                security_attrs['secure'] = True
            if hasattr(cookie, 'get_nonstandard_attr'):
                if cookie.get_nonstandard_attr('HttpOnly'):
                    security_attrs['httponly'] = True
                if cookie.get_nonstandard_attr('SameSite'):
                    security_attrs['samesite'] = True
        
        return security_attrs
    
    def _analyze_cookie_security(self, cookie) -> Dict[str, bool]:
        """Analyze individual cookie security."""
        return {
            'secure': hasattr(cookie, 'secure') and cookie.secure,
            'httponly': hasattr(cookie, 'get_nonstandard_attr') and cookie.get_nonstandard_attr('HttpOnly'),
            'samesite': hasattr(cookie, 'get_nonstandard_attr') and cookie.get_nonstandard_attr('SameSite')
        }
    
    def _check_fuzzing_response(self, response: requests.Response, payload: Dict[str, Any]) -> bool:
        """Check response for fuzzing vulnerability indicators."""
        try:
            # Check for error disclosure
            if response.status_code == 500:
                content = response.text.lower()
                error_indicators = [
                    'traceback',
                    'stack trace',
                    'internal server error',
                    'database error',
                    'file not found'
                ]
                return any(indicator in content for indicator in error_indicators)
            
            return False
        except:
            return False
    
    def _generate_penetration_test_summary(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive penetration test summary."""
        summary = {
            'total_scenarios': len(test_results),
            'successful_scenarios': 0,
            'failed_scenarios': 0,
            'total_vulnerabilities': 0,
            'vulnerabilities_by_severity': {severity.value: 0 for severity in VulnerabilitySeverity},
            'attack_categories_tested': [],
            'compliance_score': 0.0
        }
        
        for scenario_name, scenario_result in test_results.items():
            if scenario_result.get('status') == 'completed':
                summary['successful_scenarios'] += 1
                
                vulnerabilities = scenario_result.get('vulnerabilities_found', [])
                summary['total_vulnerabilities'] += len(vulnerabilities)
                
                # Count vulnerabilities by severity
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', VulnerabilitySeverity.INFO.value)
                    if severity in summary['vulnerabilities_by_severity']:
                        summary['vulnerabilities_by_severity'][severity] += 1
                
                # Track attack categories
                for attack_category in AttackCategory:
                    if attack_category.value in scenario_name:
                        if attack_category.value not in summary['attack_categories_tested']:
                            summary['attack_categories_tested'].append(attack_category.value)
            else:
                summary['failed_scenarios'] += 1
        
        # Calculate compliance score
        if summary['total_vulnerabilities'] == 0:
            summary['compliance_score'] = 100.0
        else:
            # Penalty-based scoring
            severity_penalties = {
                VulnerabilitySeverity.CRITICAL.value: 30.0,
                VulnerabilitySeverity.HIGH.value: 20.0,
                VulnerabilitySeverity.MEDIUM.value: 10.0,
                VulnerabilitySeverity.LOW.value: 5.0,
                VulnerabilitySeverity.INFO.value: 1.0
            }
            
            total_penalty = sum(
                count * severity_penalties.get(severity, 1.0)
                for severity, count in summary['vulnerabilities_by_severity'].items()
            )
            
            summary['compliance_score'] = max(0.0, 100.0 - total_penalty)
        
        return summary


class ComplianceValidator:
    """
    Enterprise security compliance validation framework.
    
    Implements comprehensive compliance checking per Section 6.4.6 with support
    for multiple compliance frameworks and automated validation capabilities.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize compliance validator with configuration.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ComplianceValidator")
        self.validation_results: Dict[str, Any] = {}
    
    def validate_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive compliance validation across all enabled frameworks.
        
        Args:
            scan_results: Aggregated security scan results
            
        Returns:
            Dict containing compliance validation results and scores
        """
        try:
            self.logger.info("Starting compliance validation")
            
            compliance_results = {
                'validation_status': 'running',
                'frameworks': {},
                'overall_compliance_score': 0.0,
                'validation_timestamp': datetime.utcnow().isoformat()
            }
            
            enabled_frameworks = self.config.get_compliance_frameworks()
            
            # Validate each enabled framework
            for framework_name, framework_config in enabled_frameworks.items():
                framework_result = self._validate_framework_compliance(
                    framework_name, 
                    framework_config, 
                    scan_results
                )
                compliance_results['frameworks'][framework_name] = framework_result
            
            # Calculate overall compliance score
            if compliance_results['frameworks']:
                total_score = sum(
                    framework_result.get('compliance_score', 0.0)
                    for framework_result in compliance_results['frameworks'].values()
                )
                compliance_results['overall_compliance_score'] = total_score / len(compliance_results['frameworks'])
            
            compliance_results['validation_status'] = 'completed'
            
            # Check against minimum compliance requirements
            compliance_results['meets_minimum_requirements'] = (
                compliance_results['overall_compliance_score'] >= 
                self.config.SECURITY_THRESHOLDS['compliance_score_minimum']
            )
            
            self.validation_results = compliance_results
            
            self.logger.info(f"Compliance validation completed: {compliance_results['overall_compliance_score']:.2f}% overall score")
            
            return self.validation_results
            
        except Exception as e:
            error_msg = f"Compliance validation failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'validation_status': 'failed',
                'error': error_msg
            }
    
    def _validate_framework_compliance(
        self, 
        framework_name: str, 
        framework_config: Dict[str, Any], 
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate compliance for specific framework."""
        if framework_name == 'owasp_top_10':
            return self._validate_owasp_top_10(framework_config, scan_results)
        elif framework_name == 'sans_top_25':
            return self._validate_sans_top_25(framework_config, scan_results)
        elif framework_name == 'pci_dss':
            return self._validate_pci_dss(framework_config, scan_results)
        elif framework_name == 'soc2_type2':
            return self._validate_soc2_type2(framework_config, scan_results)
        else:
            return {
                'framework': framework_name,
                'compliance_score': 0.0,
                'status': 'unsupported',
                'error': f"Framework {framework_name} not supported"
            }
    
    def _validate_owasp_top_10(self, config: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate OWASP Top 10 compliance."""
        owasp_categories = config.get('categories', [])
        category_scores = {}
        
        # Map vulnerabilities to OWASP categories
        owasp_mapping = {
            'A01_2021_Broken_Access_Control': ['privilege_escalation', 'idor', 'authorization'],
            'A02_2021_Cryptographic_Failures': ['weak_encryption', 'insecure_crypto'],
            'A03_2021_Injection': ['sql_injection', 'command_injection', 'xss'],
            'A04_2021_Insecure_Design': ['insecure_design_patterns'],
            'A05_2021_Security_Misconfiguration': ['security_headers', 'default_credentials'],
            'A06_2021_Vulnerable_Components': ['dependency_vulnerabilities'],
            'A07_2021_Identification_Authentication_Failures': ['weak_passwords', 'session_fixation'],
            'A08_2021_Software_Data_Integrity_Failures': ['integrity_failures'],
            'A09_2021_Security_Logging_Monitoring_Failures': ['insufficient_logging'],
            'A10_2021_Server_Side_Request_Forgery': ['ssrf']
        }
        
        # Evaluate each OWASP category
        for category in owasp_categories:
            category_vulns = owasp_mapping.get(category, [])
            category_score = self._calculate_category_score(category_vulns, scan_results)
            category_scores[category] = category_score
        
        # Calculate overall OWASP compliance score
        overall_score = sum(category_scores.values()) / len(category_scores) if category_scores else 0.0
        
        return {
            'framework': 'owasp_top_10',
            'version': config.get('version', '2021'),
            'compliance_score': overall_score,
            'category_scores': category_scores,
            'status': 'completed'
        }
    
    def _validate_sans_top_25(self, config: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SANS Top 25 compliance."""
        critical_weaknesses = config.get('critical_weaknesses', [])
        weakness_scores = {}
        
        # Map CWE IDs to vulnerability types
        cwe_mapping = {
            'CWE-79': ['xss'],
            'CWE-89': ['sql_injection'],
            'CWE-20': ['input_validation'],
            'CWE-125': ['buffer_overflow'],
            'CWE-78': ['command_injection'],
            'CWE-416': ['use_after_free'],
            'CWE-22': ['path_traversal'],
            'CWE-352': ['csrf'],
            'CWE-434': ['file_upload'],
            'CWE-862': ['authorization']
        }
        
        # Evaluate each CWE
        for cwe_id in critical_weaknesses:
            cwe_vulns = cwe_mapping.get(cwe_id, [])
            weakness_score = self._calculate_category_score(cwe_vulns, scan_results)
            weakness_scores[cwe_id] = weakness_score
        
        # Calculate overall SANS compliance score
        overall_score = sum(weakness_scores.values()) / len(weakness_scores) if weakness_scores else 0.0
        
        return {
            'framework': 'sans_top_25',
            'version': config.get('version', '2023'),
            'compliance_score': overall_score,
            'weakness_scores': weakness_scores,
            'status': 'completed'
        }
    
    def _validate_pci_dss(self, config: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate PCI DSS compliance."""
        requirements = config.get('requirements', [])
        requirement_scores = {}
        
        # Map PCI requirements to security controls
        pci_mapping = {
            'secure_network_configuration': ['security_headers', 'tls_configuration'],
            'protect_cardholder_data': ['encryption', 'data_protection'],
            'encryption_in_transit': ['tls_configuration', 'secure_communication'],
            'vulnerability_management': ['dependency_vulnerabilities', 'security_patches'],
            'access_control_measures': ['authentication', 'authorization'],
            'network_monitoring': ['logging', 'monitoring']
        }
        
        # Evaluate each PCI requirement
        for requirement in requirements:
            req_controls = pci_mapping.get(requirement, [])
            requirement_score = self._calculate_category_score(req_controls, scan_results)
            requirement_scores[requirement] = requirement_score
        
        # Calculate overall PCI compliance score
        overall_score = sum(requirement_scores.values()) / len(requirement_scores) if requirement_scores else 0.0
        
        return {
            'framework': 'pci_dss',
            'version': config.get('version', '4.0'),
            'compliance_score': overall_score,
            'requirement_scores': requirement_scores,
            'status': 'completed'
        }
    
    def _validate_soc2_type2(self, config: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SOC 2 Type II compliance."""
        trust_criteria = config.get('trust_criteria', [])
        criteria_scores = {}
        
        # Map SOC 2 criteria to security controls
        soc2_mapping = {
            'security': ['authentication', 'authorization', 'encryption'],
            'availability': ['monitoring', 'redundancy', 'disaster_recovery'],
            'processing_integrity': ['data_validation', 'integrity_checks'],
            'confidentiality': ['encryption', 'access_control', 'data_protection'],
            'privacy': ['data_minimization', 'consent_management', 'data_retention']
        }
        
        # Evaluate each trust criterion
        for criterion in trust_criteria:
            criterion_controls = soc2_mapping.get(criterion, [])
            criterion_score = self._calculate_category_score(criterion_controls, scan_results)
            criteria_scores[criterion] = criterion_score
        
        # Calculate overall SOC 2 compliance score
        overall_score = sum(criteria_scores.values()) / len(criteria_scores) if criteria_scores else 0.0
        
        return {
            'framework': 'soc2_type2',
            'version': config.get('version', '2017'),
            'compliance_score': overall_score,
            'criteria_scores': criteria_scores,
            'status': 'completed'
        }
    
    def _calculate_category_score(self, category_vulns: List[str], scan_results: Dict[str, Any]) -> float:
        """Calculate compliance score for a category based on vulnerabilities found."""
        base_score = 100.0
        
        # Check all scan results for relevant vulnerabilities
        all_vulnerabilities = []
        
        # Aggregate vulnerabilities from all scan types
        for scan_type, results in scan_results.items():
            if isinstance(results, dict):
                # From individual scanners
                if 'vulnerabilities' in results:
                    all_vulnerabilities.extend(results['vulnerabilities'])
                elif 'issues' in results:
                    all_vulnerabilities.extend(results['issues'])
                elif 'alerts' in results:
                    alerts = results['alerts']
                    if isinstance(alerts, dict) and 'alerts' in alerts:
                        all_vulnerabilities.extend(alerts['alerts'])
                
                # From penetration testing
                if 'scenarios' in results:
                    for scenario_result in results['scenarios'].values():
                        if 'vulnerabilities_found' in scenario_result:
                            all_vulnerabilities.extend(scenario_result['vulnerabilities_found'])
        
        # Count relevant vulnerabilities
        relevant_vulns = 0
        for vuln in all_vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            if any(category_vuln in vuln_type for category_vuln in category_vulns):
                relevant_vulns += 1
                
                # Apply penalty based on severity
                severity = vuln.get('severity', VulnerabilitySeverity.INFO.value)
                if severity == VulnerabilitySeverity.CRITICAL.value:
                    base_score -= 25.0
                elif severity == VulnerabilitySeverity.HIGH.value:
                    base_score -= 15.0
                elif severity == VulnerabilitySeverity.MEDIUM.value:
                    base_score -= 8.0
                elif severity == VulnerabilitySeverity.LOW.value:
                    base_score -= 3.0
                else:
                    base_score -= 1.0
        
        return max(0.0, base_score)


class SecurityTestOrchestrator:
    """
    Security test orchestration and coordination manager.
    
    Coordinates execution of all security testing components and generates
    comprehensive security validation reports per Section 6.6.1 and Section 6.6.3.
    """
    
    def __init__(self, config: Optional[SecurityTestConfig] = None):
        """
        Initialize security test orchestrator.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config or SecurityTestConfig()
        self.logger = logging.getLogger(f"{__name__}.SecurityTestOrchestrator")
        self.test_metrics = SecurityTestMetrics()
        
        # Initialize security scanners
        self.bandit_scanner = BanditSecurityScanner(self.config)
        self.safety_scanner = SafetyDependencyScanner(self.config)
        self.zap_scanner = OWASPZAPScanner(self.config)
        self.penetration_tester = PenetrationTestRunner(self.config)
        self.compliance_validator = ComplianceValidator(self.config)
    
    def run_comprehensive_security_tests(
        self, 
        target_url: Optional[str] = None,
        test_level: Optional[SecurityTestLevel] = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive security testing suite.
        
        Args:
            target_url: Target URL for dynamic security testing
            test_level: Security test execution level
            
        Returns:
            Dict containing comprehensive security test results
        """
        try:
            test_level = test_level or self.config.get_security_test_level()
            target_url = target_url or self.config.ZAP_TARGET_URL
            
            self.logger.info(f"Starting comprehensive security tests - Level: {test_level.value}")
            self.test_metrics.start_time = datetime.utcnow()
            
            # Initialize test results
            test_results = {
                'test_execution': {
                    'status': 'running',
                    'test_level': test_level.value,
                    'target_url': target_url,
                    'start_time': self.test_metrics.start_time.isoformat()
                },
                'security_scans': {},
                'compliance_validation': {},
                'summary': {},
                'recommendations': []
            }
            
            # Execute security scans based on test level
            if test_level in [SecurityTestLevel.BASIC, SecurityTestLevel.STANDARD, 
                             SecurityTestLevel.COMPREHENSIVE, SecurityTestLevel.COMPLIANCE]:
                
                # Static Analysis Security Testing (SAST)
                self.logger.info("Running Bandit static analysis security scan")
                bandit_results = self.bandit_scanner.run_security_scan()
                test_results['security_scans']['bandit'] = bandit_results
                self._update_metrics_from_scan(bandit_results, 'bandit')
                
                # Dependency Vulnerability Scanning
                self.logger.info("Running Safety dependency vulnerability scan")
                safety_results = self.safety_scanner.run_dependency_scan()
                test_results['security_scans']['safety'] = safety_results
                self._update_metrics_from_scan(safety_results, 'safety')
            
            if test_level in [SecurityTestLevel.STANDARD, SecurityTestLevel.COMPREHENSIVE, 
                             SecurityTestLevel.PENETRATION]:
                
                # Dynamic Application Security Testing (DAST)
                if self.config.ZAP_ENABLED:
                    self.logger.info("Running OWASP ZAP dynamic security scan")
                    zap_results = self.zap_scanner.run_security_scan(target_url)
                    test_results['security_scans']['zap'] = zap_results
                    self._update_metrics_from_scan(zap_results, 'zap')
            
            if test_level in [SecurityTestLevel.COMPREHENSIVE, SecurityTestLevel.PENETRATION]:
                
                # Penetration Testing
                if self.config.PENETRATION_TESTING_ENABLED:
                    self.logger.info("Running penetration testing scenarios")
                    pentest_results = self.penetration_tester.run_penetration_tests(target_url)
                    test_results['security_scans']['penetration_testing'] = pentest_results
                    self._update_metrics_from_scan(pentest_results, 'penetration_testing')
            
            # Compliance Validation
            if test_level in [SecurityTestLevel.COMPLIANCE, SecurityTestLevel.COMPREHENSIVE]:
                if self.config.COMPLIANCE_VALIDATION_ENABLED:
                    self.logger.info("Running compliance validation")
                    compliance_results = self.compliance_validator.validate_compliance(
                        test_results['security_scans']
                    )
                    test_results['compliance_validation'] = compliance_results
            
            # Generate comprehensive summary
            self.test_metrics.end_time = datetime.utcnow()
            test_summary = self._generate_test_summary(test_results)
            test_results['summary'] = test_summary
            
            # Generate security recommendations
            recommendations = self._generate_security_recommendations(test_results)
            test_results['recommendations'] = recommendations
            
            # Validate against security thresholds
            threshold_validation = self._validate_security_thresholds(test_results)
            test_results['threshold_validation'] = threshold_validation
            
            test_results['test_execution']['status'] = 'completed'
            test_results['test_execution']['end_time'] = self.test_metrics.end_time.isoformat()
            test_results['test_execution']['duration'] = str(self.test_metrics.duration)
            
            self.logger.info(f"Security tests completed - Duration: {self.test_metrics.duration}")
            
            return test_results
            
        except Exception as e:
            error_msg = f"Comprehensive security testing failed: {str(e)}"
            self.logger.error(error_msg)
            self.test_metrics.end_time = datetime.utcnow()
            
            return {
                'test_execution': {
                    'status': 'failed',
                    'error': error_msg,
                    'end_time': self.test_metrics.end_time.isoformat()
                }
            }
    
    def _update_metrics_from_scan(self, scan_results: Dict[str, Any], scan_type: str) -> None:
        """Update test metrics from individual scan results."""
        self.test_metrics.total_tests += 1
        
        if scan_results.get('scan_status') == 'completed' or scan_results.get('status') == 'completed':
            self.test_metrics.passed_tests += 1
        else:
            self.test_metrics.failed_tests += 1
        
        # Count vulnerabilities by type
        if scan_type == 'bandit':
            severity_counts = scan_results.get('severity_counts', {})
            for severity, count in severity_counts.items():
                self.test_metrics.vulnerabilities_found[severity] = (
                    self.test_metrics.vulnerabilities_found.get(severity, 0) + count
                )
        elif scan_type == 'safety':
            severity_counts = scan_results.get('severity_counts', {})
            for severity, count in severity_counts.items():
                self.test_metrics.vulnerabilities_found[severity] = (
                    self.test_metrics.vulnerabilities_found.get(severity, 0) + count
                )
        elif scan_type == 'zap':
            alerts = scan_results.get('alerts', {})
            risk_counts = alerts.get('risk_counts', {})
            # Map ZAP risk levels to our severity levels
            zap_mapping = {
                'high': VulnerabilitySeverity.HIGH.value,
                'medium': VulnerabilitySeverity.MEDIUM.value,
                'low': VulnerabilitySeverity.LOW.value,
                'informational': VulnerabilitySeverity.INFO.value
            }
            for risk, count in risk_counts.items():
                severity = zap_mapping.get(risk, VulnerabilitySeverity.INFO.value)
                self.test_metrics.vulnerabilities_found[severity] = (
                    self.test_metrics.vulnerabilities_found.get(severity, 0) + count
                )
        elif scan_type == 'penetration_testing':
            summary = scan_results.get('summary', {})
            vuln_by_severity = summary.get('vulnerabilities_by_severity', {})
            for severity, count in vuln_by_severity.items():
                self.test_metrics.vulnerabilities_found[severity] = (
                    self.test_metrics.vulnerabilities_found.get(severity, 0) + count
                )
    
    def _generate_test_summary(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive test execution summary."""
        summary = {
            'execution_metrics': {
                'total_tests': self.test_metrics.total_tests,
                'passed_tests': self.test_metrics.passed_tests,
                'failed_tests': self.test_metrics.failed_tests,
                'success_rate': self.test_metrics.success_rate,
                'duration': str(self.test_metrics.duration)
            },
            'vulnerability_summary': {
                'total_vulnerabilities': sum(self.test_metrics.vulnerabilities_found.values()),
                'vulnerabilities_by_severity': dict(self.test_metrics.vulnerabilities_found)
            },
            'scan_results_summary': {},
            'compliance_summary': {}
        }
        
        # Summarize individual scan results
        security_scans = test_results.get('security_scans', {})
        for scan_type, scan_result in security_scans.items():
            if scan_type == 'bandit':
                summary['scan_results_summary']['bandit'] = {
                    'total_issues': scan_result.get('total_issues', 0),
                    'severity_distribution': scan_result.get('severity_counts', {}),
                    'scan_status': scan_result.get('scan_status', 'unknown')
                }
            elif scan_type == 'safety':
                summary['scan_results_summary']['safety'] = {
                    'total_vulnerabilities': scan_result.get('total_vulnerabilities', 0),
                    'severity_distribution': scan_result.get('severity_counts', {}),
                    'scan_status': scan_result.get('scan_status', 'unknown')
                }
            elif scan_type == 'zap':
                alerts = scan_result.get('alerts', {})
                summary['scan_results_summary']['zap'] = {
                    'total_alerts': alerts.get('total_alerts', 0),
                    'filtered_alerts': alerts.get('filtered_alerts', 0),
                    'risk_distribution': alerts.get('risk_counts', {}),
                    'scan_status': scan_result.get('scan_status', 'unknown')
                }
            elif scan_type == 'penetration_testing':
                pen_summary = scan_result.get('summary', {})
                summary['scan_results_summary']['penetration_testing'] = {
                    'total_scenarios': pen_summary.get('total_scenarios', 0),
                    'successful_scenarios': pen_summary.get('successful_scenarios', 0),
                    'total_vulnerabilities': pen_summary.get('total_vulnerabilities', 0),
                    'compliance_score': pen_summary.get('compliance_score', 0.0)
                }
        
        # Summarize compliance results
        compliance_validation = test_results.get('compliance_validation', {})
        if compliance_validation:
            summary['compliance_summary'] = {
                'overall_compliance_score': compliance_validation.get('overall_compliance_score', 0.0),
                'meets_minimum_requirements': compliance_validation.get('meets_minimum_requirements', False),
                'frameworks_validated': list(compliance_validation.get('frameworks', {}).keys())
            }
        
        # Calculate overall security score
        security_score = self._calculate_overall_security_score(summary)
        summary['overall_security_score'] = security_score
        
        return summary
    
    def _calculate_overall_security_score(self, summary: Dict[str, Any]) -> float:
        """Calculate overall security score based on all test results."""
        base_score = 100.0
        
        # Apply penalties for vulnerabilities
        vuln_summary = summary['vulnerability_summary']
        severity_penalties = {
            VulnerabilitySeverity.CRITICAL.value: 30.0,
            VulnerabilitySeverity.HIGH.value: 20.0,
            VulnerabilitySeverity.MEDIUM.value: 10.0,
            VulnerabilitySeverity.LOW.value: 5.0,
            VulnerabilitySeverity.INFO.value: 1.0
        }
        
        for severity, count in vuln_summary['vulnerabilities_by_severity'].items():
            penalty = severity_penalties.get(severity, 1.0)
            base_score -= (count * penalty)
        
        # Factor in compliance score if available
        compliance_summary = summary.get('compliance_summary', {})
        if compliance_summary:
            compliance_score = compliance_summary.get('overall_compliance_score', 100.0)
            # Weight compliance score at 30% of total
            base_score = (base_score * 0.7) + (compliance_score * 0.3)
        
        return max(0.0, min(100.0, base_score))
    
    def _generate_security_recommendations(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable security recommendations based on test results."""
        recommendations = []
        
        # Analyze security scan results for recommendations
        security_scans = test_results.get('security_scans', {})
        
        # Bandit recommendations
        bandit_results = security_scans.get('bandit', {})
        if bandit_results.get('total_issues', 0) > 0:
            severity_counts = bandit_results.get('severity_counts', {})
            
            if severity_counts.get(VulnerabilitySeverity.CRITICAL.value, 0) > 0:
                recommendations.append({
                    'category': 'static_analysis',
                    'priority': 'critical',
                    'title': 'Critical Security Issues in Code',
                    'description': 'Bandit identified critical security issues in the codebase that require immediate attention.',
                    'remediation': 'Review and fix all critical security issues identified by Bandit static analysis.',
                    'impact': 'High - Critical security vulnerabilities could lead to system compromise.'
                })
            
            if severity_counts.get(VulnerabilitySeverity.HIGH.value, 0) > 0:
                recommendations.append({
                    'category': 'static_analysis',
                    'priority': 'high',
                    'title': 'High-Severity Security Issues',
                    'description': 'Multiple high-severity security issues detected in source code.',
                    'remediation': 'Address high-severity security findings through code review and remediation.',
                    'impact': 'Medium - High-severity issues increase attack surface.'
                })
        
        # Safety recommendations
        safety_results = security_scans.get('safety', {})
        if safety_results.get('total_vulnerabilities', 0) > 0:
            recommendations.append({
                'category': 'dependency_management',
                'priority': 'high',
                'title': 'Vulnerable Dependencies Detected',
                'description': 'Safety scan identified vulnerable Python packages in dependencies.',
                'remediation': 'Update vulnerable packages to secure versions. Review dependency management practices.',
                'impact': 'Medium to High - Vulnerable dependencies can be exploited by attackers.'
            })
        
        # ZAP recommendations
        zap_results = security_scans.get('zap', {})
        zap_alerts = zap_results.get('alerts', {})
        if zap_alerts.get('total_alerts', 0) > 0:
            risk_counts = zap_alerts.get('risk_counts', {})
            
            if risk_counts.get('high', 0) > 0:
                recommendations.append({
                    'category': 'web_application_security',
                    'priority': 'critical',
                    'title': 'High-Risk Web Application Vulnerabilities',
                    'description': 'OWASP ZAP identified high-risk vulnerabilities in web application.',
                    'remediation': 'Address all high-risk findings from DAST scan. Implement security controls.',
                    'impact': 'High - Web application vulnerabilities can lead to data breaches.'
                })
        
        # Penetration testing recommendations
        pentest_results = security_scans.get('penetration_testing', {})
        pentest_summary = pentest_results.get('summary', {})
        if pentest_summary.get('total_vulnerabilities', 0) > 0:
            recommendations.append({
                'category': 'penetration_testing',
                'priority': 'high',
                'title': 'Penetration Testing Vulnerabilities',
                'description': 'Penetration testing identified exploitable vulnerabilities in the application.',
                'remediation': 'Address all vulnerabilities found during penetration testing. Implement defense-in-depth.',
                'impact': 'High - Exploitable vulnerabilities pose immediate security risk.'
            })
        
        # Compliance recommendations
        compliance_results = test_results.get('compliance_validation', {})
        if compliance_results.get('overall_compliance_score', 100.0) < self.config.SECURITY_THRESHOLDS['compliance_score_minimum']:
            recommendations.append({
                'category': 'compliance',
                'priority': 'medium',
                'title': 'Compliance Score Below Threshold',
                'description': f"Overall compliance score is below required threshold of {self.config.SECURITY_THRESHOLDS['compliance_score_minimum']}%.",
                'remediation': 'Address compliance gaps identified in framework validation. Implement required controls.',
                'impact': 'Medium - Compliance failures may result in regulatory issues.'
            })
        
        # General security recommendations
        if not recommendations:
            recommendations.append({
                'category': 'general',
                'priority': 'low',
                'title': 'Continue Security Monitoring',
                'description': 'No critical security issues detected. Maintain current security posture.',
                'remediation': 'Continue regular security testing and monitoring. Review security controls periodically.',
                'impact': 'Low - Proactive security maintenance.'
            })
        
        return recommendations
    
    def _validate_security_thresholds(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate test results against configured security thresholds."""
        threshold_validation = {
            'passed': True,
            'violations': [],
            'threshold_checks': {}
        }
        
        # Check vulnerability thresholds
        total_vulns_by_severity = {}
        
        # Aggregate vulnerabilities from all scans
        security_scans = test_results.get('security_scans', {})
        
        for scan_type, scan_results in security_scans.items():
            if scan_type == 'bandit':
                severity_counts = scan_results.get('severity_counts', {})
                for severity, count in severity_counts.items():
                    total_vulns_by_severity[severity] = (
                        total_vulns_by_severity.get(severity, 0) + count
                    )
            elif scan_type == 'safety':
                severity_counts = scan_results.get('severity_counts', {})
                for severity, count in severity_counts.items():
                    total_vulns_by_severity[severity] = (
                        total_vulns_by_severity.get(severity, 0) + count
                    )
            elif scan_type == 'zap':
                alerts = scan_results.get('alerts', {})
                risk_counts = alerts.get('risk_counts', {})
                # Map ZAP risk levels
                zap_mapping = {
                    'high': VulnerabilitySeverity.HIGH.value,
                    'medium': VulnerabilitySeverity.MEDIUM.value,
                    'low': VulnerabilitySeverity.LOW.value,
                    'informational': VulnerabilitySeverity.INFO.value
                }
                for risk, count in risk_counts.items():
                    severity = zap_mapping.get(risk, VulnerabilitySeverity.INFO.value)
                    total_vulns_by_severity[severity] = (
                        total_vulns_by_severity.get(severity, 0) + count
                    )
        
        # Check against thresholds
        vulnerability_limits = self.config.SECURITY_THRESHOLDS['vulnerability_limits']
        
        for severity, count in total_vulns_by_severity.items():
            threshold = vulnerability_limits.get(severity, 0)
            threshold_validation['threshold_checks'][f'vulnerability_{severity}'] = {
                'count': count,
                'threshold': threshold,
                'passed': count <= threshold
            }
            
            if count > threshold:
                threshold_validation['passed'] = False
                threshold_validation['violations'].append({
                    'type': 'vulnerability_threshold',
                    'severity': severity,
                    'count': count,
                    'threshold': threshold,
                    'message': f"Found {count} {severity} vulnerabilities, threshold is {threshold}"
                })
        
        # Check compliance score threshold
        compliance_results = test_results.get('compliance_validation', {})
        if compliance_results:
            compliance_score = compliance_results.get('overall_compliance_score', 0.0)
            compliance_threshold = self.config.SECURITY_THRESHOLDS['compliance_score_minimum']
            
            threshold_validation['threshold_checks']['compliance_score'] = {
                'score': compliance_score,
                'threshold': compliance_threshold,
                'passed': compliance_score >= compliance_threshold
            }
            
            if compliance_score < compliance_threshold:
                threshold_validation['passed'] = False
                threshold_validation['violations'].append({
                    'type': 'compliance_threshold',
                    'score': compliance_score,
                    'threshold': compliance_threshold,
                    'message': f"Compliance score {compliance_score:.2f}% below threshold {compliance_threshold}%"
                })
        
        return threshold_validation


# Export security configuration and testing classes
__all__ = [
    # Enums
    'SecurityTestLevel',
    'VulnerabilitySeverity',
    'AttackCategory',
    
    # Data classes
    'SecurityTestMetrics',
    
    # Main configuration class
    'SecurityTestConfig',
    
    # Scanner classes
    'BanditSecurityScanner',
    'SafetyDependencyScanner',
    'OWASPZAPScanner',
    'PenetrationTestRunner',
    'ComplianceValidator',
    
    # Orchestration class
    'SecurityTestOrchestrator'
]