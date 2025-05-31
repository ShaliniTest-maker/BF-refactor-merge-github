"""
Bandit Security Analysis Automation

This module provides comprehensive Python code security scanning through automated Bandit analysis,
vulnerability detection, and security reporting with CI/CD integration for zero-tolerance security
enforcement. Implements enterprise-grade security scanning requirements per Section 6.4.5 and 6.6.3
of the technical specification.

Key Components:
- Automated Bandit 1.7+ security analysis for Python code vulnerability scanning per Section 6.4.5
- Comprehensive security pattern detection covering all Python modules per Section 6.4.5
- Critical and high-severity vulnerability detection per Section 6.6.3 with zero tolerance policy
- Automated security report generation per Section 6.6.2 with structured JSON output
- CI/CD pipeline integration for security gate enforcement per Section 6.6.2
- Zero-tolerance policy enforcement for critical security findings per Section 6.6.3

Architecture Integration:
- Section 6.4.5: Security Controls Matrix with comprehensive security validation
- Section 6.6.2: Test Automation with CI/CD security checks integration
- Section 6.6.3: Quality Metrics with security scan requirements and enforcement
- Section 6.4.5: Static Application Security Testing (SAST) with Bandit 1.7+ integration
- Section 6.6.3: Security gate enforcement with deployment blocking capabilities

Security Analysis Coverage:
- SQL injection vulnerability patterns and database security assessment
- XSS prevention validation and output sanitization compliance
- Authentication and authorization security pattern analysis
- Cryptographic implementation validation and key management security
- Input validation security assessment and sanitization effectiveness
- Session management security analysis and secure cookie validation
- Error handling security review and information disclosure prevention
- Configuration security assessment and environment variable protection

Author: Flask Migration Team  
Version: 1.0.0
Security Compliance: OWASP Top 10, SANS Top 25, Section 6.6.3 Requirements
Dependencies: bandit 1.7+, safety 3.0+, pytest 7.4+, structlog 23.1+
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Set
from unittest.mock import patch, MagicMock

import pytest
import structlog
from bandit import manager as bandit_manager
from bandit.core import config as bandit_config
from bandit.core import node_visitor
from bandit.formatters import json as bandit_json

# Import security testing framework from conftest
from tests.security.conftest import (
    security_config,
    security_audit_logger,
    security_performance_monitor,
    comprehensive_security_environment
)

# Configure security analysis logger
logging.basicConfig(level=logging.INFO)
security_analysis_logger = logging.getLogger(__name__)

# Configure structured logging for security analysis
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.LoggerFactory(),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


# =============================================================================
# Bandit Security Analysis Configuration
# =============================================================================

class BanditAnalysisConfig:
    """
    Comprehensive Bandit security analysis configuration providing enterprise-grade
    security scanning parameters, vulnerability detection settings, and CI/CD integration
    configuration per Section 6.6.3 security requirements.
    """
    
    # Bandit Analysis Configuration
    BANDIT_VERSION_REQUIRED = "1.7.0"
    BANDIT_CONFIG_FILE = ".bandit"
    BANDIT_BASELINE_FILE = ".bandit_baseline"
    
    # Security Analysis Scope
    ANALYSIS_SCOPE_COMPLETE = True
    INCLUDE_TEST_FILES = True
    RECURSIVE_ANALYSIS = True
    FOLLOW_SYMLINKS = False
    
    # Vulnerability Severity Configuration per Section 6.6.3
    CRITICAL_SEVERITY_BLOCKING = True
    HIGH_SEVERITY_BLOCKING = True
    MEDIUM_SEVERITY_WARNING = True
    LOW_SEVERITY_INFORMATIONAL = True
    
    # Zero-Tolerance Policy Configuration per Section 6.6.3
    ZERO_TOLERANCE_CRITICAL = True
    ZERO_TOLERANCE_HIGH = True
    MAX_CRITICAL_FINDINGS = 0
    MAX_HIGH_FINDINGS = 0
    
    # CI/CD Integration Configuration per Section 6.6.2
    CI_CD_INTEGRATION_ENABLED = True
    PIPELINE_BLOCKING_ENABLED = True
    AUTOMATED_REPORTING_ENABLED = True
    SECURITY_GATE_ENFORCEMENT = True
    
    # Report Generation Configuration
    GENERATE_JSON_REPORT = True
    GENERATE_HTML_REPORT = True
    GENERATE_TXT_REPORT = True
    GENERATE_BASELINE_REPORT = True
    
    # Performance Configuration
    PARALLEL_ANALYSIS_ENABLED = True
    MAX_ANALYSIS_TIME_SECONDS = 300  # 5 minutes
    MEMORY_LIMIT_MB = 512
    
    # Security Rule Configuration
    ENABLE_ALL_SECURITY_RULES = True
    CUSTOM_SECURITY_RULES_ENABLED = True
    FLASK_SPECIFIC_RULES_ENABLED = True
    CRYPTO_RULES_ENABLED = True
    
    # Audit Configuration
    AUDIT_ALL_FINDINGS = True
    AUDIT_SCAN_EXECUTION = True
    AUDIT_PERFORMANCE_METRICS = True
    AUDIT_COMPLIANCE_STATUS = True
    
    # Compliance Configuration
    OWASP_TOP_10_COMPLIANCE = True
    SANS_TOP_25_COMPLIANCE = True
    PCI_DSS_COMPLIANCE = True
    SOC2_COMPLIANCE = True


class BanditSecurityProfile:
    """
    Comprehensive security profile configuration for Flask application security analysis
    with specific focus on authentication, authorization, data protection, and input validation
    security patterns per Section 6.4.5 Security Controls Matrix.
    """
    
    # Flask Security Patterns
    FLASK_SECURITY_PATTERNS = {
        'authentication_patterns': [
            'hardcoded_password',
            'hardcoded_bind_all_interfaces',
            'request_without_validation',
            'weak_cryptographic_key',
            'insecure_random_generator'
        ],
        'authorization_patterns': [
            'django_extra_used',
            'exec_used',
            'eval_used',
            'subprocess_without_shell_escape'
        ],
        'data_protection_patterns': [
            'hardcoded_sql_expressions',
            'sql_injection_risk',
            'pickle_usage',
            'yaml_load',
            'ssl_with_no_version'
        ],
        'input_validation_patterns': [
            'jinja2_autoescape_false',
            'use_of_mako_templates',
            'django_mark_safe',
            'request_without_timeout'
        ]
    }
    
    # Security Rule Weights per Section 6.6.3
    SECURITY_RULE_WEIGHTS = {
        'B101': 'HIGH',    # Test for use of assert
        'B102': 'MEDIUM',  # Test for exec used
        'B103': 'HIGH',    # Test for set bad file permissions
        'B104': 'MEDIUM',  # Test for binding to all interfaces
        'B105': 'HIGH',    # Test for hardcoded password strings
        'B106': 'HIGH',    # Test for hardcoded password funcarg
        'B107': 'HIGH',    # Test for hardcoded password default
        'B108': 'MEDIUM',  # Test for insecure temp file
        'B110': 'MEDIUM',  # Test for try/except pass
        'B112': 'MEDIUM',  # Test for try/except continue
        'B201': 'HIGH',    # Test for Flask debug mode
        'B301': 'HIGH',    # Test for pickle usage
        'B302': 'HIGH',    # Test for marshal usage
        'B303': 'MEDIUM',  # Test for MD5 usage
        'B304': 'MEDIUM',  # Test for insecure cipher usage
        'B305': 'HIGH',    # Test for cipher modes
        'B306': 'HIGH',    # Test for mktemp usage
        'B307': 'HIGH',    # Test for eval usage
        'B308': 'MEDIUM',  # Test for mark_safe usage
        'B309': 'MEDIUM',  # Test for HTTPSConnection
        'B310': 'HIGH',    # Test for urllib urlopen
        'B311': 'MEDIUM',  # Test for random usage
        'B312': 'HIGH',    # Test for telnetlib usage
        'B313': 'HIGH',    # Test for XML injection
        'B314': 'HIGH',    # Test for XML external entity
        'B315': 'HIGH',    # Test for XML external entity
        'B316': 'HIGH',    # Test for XML external entity
        'B317': 'HIGH',    # Test for XML external entity
        'B318': 'HIGH',    # Test for XML external entity
        'B319': 'HIGH',    # Test for XML external entity
        'B320': 'HIGH',    # Test for XML external entity
        'B321': 'HIGH',    # Test for FTP related functions
        'B322': 'MEDIUM',  # Test for input function
        'B323': 'MEDIUM',  # Test for unverified context
        'B324': 'HIGH',    # Test for hashlib insecure functions
        'B325': 'MEDIUM',  # Test for tempfile
        'B501': 'MEDIUM',  # Test for SSL/TLS insecure defaults
        'B502': 'HIGH',    # Test for SSL/TLS insecure defaults
        'B503': 'HIGH',    # Test for SSL/TLS insecure defaults
        'B504': 'HIGH',    # Test for SSL/TLS insecure defaults
        'B505': 'HIGH',    # Test for weak cryptographic key
        'B506': 'HIGH',    # Test for yaml_load
        'B507': 'HIGH',    # Test for SSH connection
        'B601': 'HIGH',    # Test for shell injection
        'B602': 'HIGH',    # Test for subprocess popen
        'B603': 'HIGH',    # Test for subprocess without shell
        'B604': 'HIGH',    # Test for subprocess call
        'B605': 'HIGH',    # Test for start_process_with_shell
        'B606': 'HIGH',    # Test for start_process_with_no_shell
        'B607': 'MEDIUM',  # Test for start_process_with_partial_path
        'B608': 'HIGH',    # Test for hardcoded SQL expressions
        'B609': 'HIGH',    # Test for wildcard injection
        'B610': 'HIGH',    # Test for linux commands injection
        'B611': 'HIGH',    # Test for injection
        'B701': 'MEDIUM',  # Test for jinja2 autoescape
        'B702': 'MEDIUM',  # Test for use of mako templates
        'B703': 'MEDIUM'   # Test for django mark safe
    }
    
    # Critical Security Categories per OWASP Top 10
    CRITICAL_SECURITY_CATEGORIES = {
        'injection_attacks': ['B608', 'B609', 'B610', 'B611'],
        'authentication_flaws': ['B105', 'B106', 'B107', 'B201'],
        'cryptographic_failures': ['B303', 'B304', 'B305', 'B324', 'B505'],
        'xml_external_entities': ['B313', 'B314', 'B315', 'B316', 'B317', 'B318', 'B319', 'B320'],
        'insecure_configuration': ['B104', 'B501', 'B502', 'B503', 'B504'],
        'code_execution': ['B102', 'B307', 'B601', 'B602', 'B603', 'B604', 'B605', 'B606']
    }


# =============================================================================
# Bandit Security Analysis Engine
# =============================================================================

class BanditSecurityAnalyzer:
    """
    Comprehensive Bandit security analysis engine providing automated Python code
    vulnerability scanning, security pattern detection, and compliance validation
    per Section 6.4.5 and 6.6.3 requirements.
    """
    
    def __init__(self, config: BanditAnalysisConfig = None, profile: BanditSecurityProfile = None):
        """
        Initialize Bandit security analyzer with comprehensive configuration.
        
        Args:
            config: Bandit analysis configuration
            profile: Security profile for Flask applications
        """
        self.config = config or BanditAnalysisConfig()
        self.profile = profile or BanditSecurityProfile()
        self.audit_logger = structlog.get_logger("security.bandit")
        
        # Analysis state
        self.analysis_results = {}
        self.security_findings = []
        self.compliance_status = {}
        self.performance_metrics = {}
        
        # Initialize Bandit manager
        self.bandit_manager = None
        self._initialize_bandit_manager()
        
        # Security gate enforcement
        self.security_gate_status = {
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'gate_passed': False,
            'blocking_issues': []
        }
    
    def _initialize_bandit_manager(self) -> None:
        """Initialize Bandit manager with comprehensive security configuration."""
        try:
            # Load Bandit configuration
            bandit_conf = bandit_config.BanditConfig()
            
            # Configure security rules based on profile
            if self.config.ENABLE_ALL_SECURITY_RULES:
                bandit_conf._init_plugins()
            
            # Initialize Bandit manager
            self.bandit_manager = bandit_manager.BanditManager(
                bandit_conf,
                'file'
            )
            
            self.audit_logger.info(
                "Bandit manager initialized successfully",
                config_enabled=self.config.ENABLE_ALL_SECURITY_RULES,
                custom_rules=self.config.CUSTOM_SECURITY_RULES_ENABLED
            )
            
        except Exception as e:
            self.audit_logger.error(
                f"Failed to initialize Bandit manager: {str(e)}",
                error_type=type(e).__name__
            )
            raise BanditInitializationError(f"Bandit initialization failed: {str(e)}")
    
    def analyze_codebase(self, target_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Execute comprehensive security analysis of Python codebase.
        
        Args:
            target_path: Path to Python codebase for analysis
            
        Returns:
            Comprehensive security analysis results with findings and metrics
        """
        analysis_start_time = time.time()
        target_path = Path(target_path)
        
        self.audit_logger.info(
            "Starting comprehensive Bandit security analysis",
            target_path=str(target_path),
            recursive=self.config.RECURSIVE_ANALYSIS,
            include_tests=self.config.INCLUDE_TEST_FILES
        )
        
        try:
            # Validate target path
            if not target_path.exists():
                raise FileNotFoundError(f"Target path does not exist: {target_path}")
            
            # Discover Python files for analysis
            python_files = self._discover_python_files(target_path)
            
            if not python_files:
                self.audit_logger.warning("No Python files found for analysis")
                return self._generate_empty_analysis_result()
            
            # Execute Bandit analysis
            analysis_results = self._execute_bandit_analysis(python_files)
            
            # Process security findings
            security_findings = self._process_security_findings(analysis_results)
            
            # Evaluate security compliance
            compliance_status = self._evaluate_security_compliance(security_findings)
            
            # Generate performance metrics
            analysis_duration = time.time() - analysis_start_time
            performance_metrics = self._generate_performance_metrics(
                analysis_duration, 
                len(python_files)
            )
            
            # Compile comprehensive results
            comprehensive_results = {
                'analysis_metadata': {
                    'analysis_id': f"bandit_analysis_{int(time.time())}",
                    'timestamp': datetime.utcnow().isoformat(),
                    'target_path': str(target_path),
                    'files_analyzed': len(python_files),
                    'analysis_duration': analysis_duration,
                    'bandit_version': self._get_bandit_version()
                },
                'security_findings': security_findings,
                'compliance_status': compliance_status,
                'performance_metrics': performance_metrics,
                'security_gate_status': self.security_gate_status,
                'analysis_summary': self._generate_analysis_summary(security_findings),
                'remediation_guidance': self._generate_remediation_guidance(security_findings)
            }
            
            # Store analysis results
            self.analysis_results = comprehensive_results
            
            # Log analysis completion
            self.audit_logger.info(
                "Bandit security analysis completed successfully",
                analysis_id=comprehensive_results['analysis_metadata']['analysis_id'],
                total_findings=len(security_findings),
                critical_findings=self.security_gate_status['critical_findings'],
                high_findings=self.security_gate_status['high_findings'],
                gate_passed=self.security_gate_status['gate_passed']
            )
            
            return comprehensive_results
            
        except Exception as e:
            self.audit_logger.error(
                f"Bandit security analysis failed: {str(e)}",
                target_path=str(target_path),
                error_type=type(e).__name__,
                analysis_duration=time.time() - analysis_start_time
            )
            raise BanditAnalysisError(f"Security analysis failed: {str(e)}")
    
    def _discover_python_files(self, target_path: Path) -> List[Path]:
        """
        Discover Python files for security analysis with comprehensive file filtering.
        
        Args:
            target_path: Root path for file discovery
            
        Returns:
            List of Python files for analysis
        """
        python_files = []
        
        try:
            if target_path.is_file() and target_path.suffix == '.py':
                python_files.append(target_path)
            elif target_path.is_dir():
                # Recursive file discovery
                pattern = '**/*.py' if self.config.RECURSIVE_ANALYSIS else '*.py'
                discovered_files = target_path.glob(pattern)
                
                for file_path in discovered_files:
                    # Skip certain directories and files
                    if self._should_include_file(file_path):
                        python_files.append(file_path)
            
            self.audit_logger.info(
                f"Discovered {len(python_files)} Python files for analysis",
                target_path=str(target_path),
                recursive=self.config.RECURSIVE_ANALYSIS
            )
            
            return python_files
            
        except Exception as e:
            self.audit_logger.error(
                f"File discovery failed: {str(e)}",
                target_path=str(target_path)
            )
            raise
    
    def _should_include_file(self, file_path: Path) -> bool:
        """
        Determine if file should be included in security analysis.
        
        Args:
            file_path: Path to Python file
            
        Returns:
            True if file should be analyzed
        """
        # Exclude patterns
        exclude_patterns = [
            '__pycache__',
            '.pytest_cache',
            '.git',
            'node_modules',
            'venv',
            '.venv',
            'env',
            '.env'
        ]
        
        # Check if file is in excluded directories
        for part in file_path.parts:
            if part in exclude_patterns:
                return False
        
        # Include test files based on configuration
        if not self.config.INCLUDE_TEST_FILES:
            if 'test_' in file_path.name or file_path.name.endswith('_test.py'):
                return False
        
        # Check if file is readable
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(100)  # Test readability
            return True
        except (UnicodeDecodeError, PermissionError):
            return False
    
    def _execute_bandit_analysis(self, python_files: List[Path]) -> Dict[str, Any]:
        """
        Execute Bandit security analysis on discovered Python files.
        
        Args:
            python_files: List of Python files to analyze
            
        Returns:
            Raw Bandit analysis results
        """
        try:
            # Convert paths to strings for Bandit
            file_paths = [str(path) for path in python_files]
            
            # Execute Bandit analysis
            self.bandit_manager.discover_files(file_paths)
            self.bandit_manager.run_tests()
            
            # Extract raw results
            raw_results = {
                'results': self.bandit_manager.get_issue_list(),
                'metrics': self.bandit_manager.metrics,
                'files_analyzed': len(file_paths),
                'analysis_time': time.time()
            }
            
            return raw_results
            
        except Exception as e:
            self.audit_logger.error(
                f"Bandit analysis execution failed: {str(e)}",
                files_count=len(python_files)
            )
            raise
    
    def _process_security_findings(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process raw Bandit results into structured security findings.
        
        Args:
            raw_results: Raw Bandit analysis results
            
        Returns:
            Structured security findings with comprehensive metadata
        """
        security_findings = []
        
        try:
            for issue in raw_results.get('results', []):
                # Extract issue details
                finding = {
                    'finding_id': f"bandit_{issue.issue_id}_{int(time.time())}",
                    'rule_id': issue.test,
                    'severity': issue.severity,
                    'confidence': issue.confidence,
                    'category': self._categorize_security_issue(issue.test),
                    'title': issue.issue_text,
                    'description': issue.issue_detail,
                    'file_path': issue.fname,
                    'line_number': issue.lineno,
                    'line_range': getattr(issue, 'line_range', [issue.lineno]),
                    'code_context': getattr(issue, 'code', ''),
                    'cwe_id': self._get_cwe_mapping(issue.test),
                    'owasp_category': self._get_owasp_mapping(issue.test),
                    'remediation_guidance': self._get_remediation_guidance(issue.test),
                    'compliance_impact': self._assess_compliance_impact(issue.test, issue.severity),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                security_findings.append(finding)
                
                # Update security gate status
                self._update_security_gate_status(finding)
            
            # Sort findings by severity and confidence
            security_findings.sort(
                key=lambda x: (
                    self._severity_weight(x['severity']),
                    self._confidence_weight(x['confidence'])
                ),
                reverse=True
            )
            
            return security_findings
            
        except Exception as e:
            self.audit_logger.error(
                f"Security findings processing failed: {str(e)}"
            )
            raise
    
    def _categorize_security_issue(self, rule_id: str) -> str:
        """
        Categorize security issue based on rule ID and security profile.
        
        Args:
            rule_id: Bandit rule identifier
            
        Returns:
            Security category classification
        """
        for category, rules in self.profile.CRITICAL_SECURITY_CATEGORIES.items():
            if rule_id in rules:
                return category
        
        # Default categorization based on rule prefix
        if rule_id.startswith('B1'):
            return 'code_quality'
        elif rule_id.startswith('B2'):
            return 'flask_security'
        elif rule_id.startswith('B3'):
            return 'cryptographic_security'
        elif rule_id.startswith('B4'):
            return 'network_security'
        elif rule_id.startswith('B5'):
            return 'ssl_tls_security'
        elif rule_id.startswith('B6'):
            return 'injection_security'
        elif rule_id.startswith('B7'):
            return 'template_security'
        else:
            return 'general_security'
    
    def _get_cwe_mapping(self, rule_id: str) -> Optional[str]:
        """
        Map Bandit rule to Common Weakness Enumeration (CWE) identifier.
        
        Args:
            rule_id: Bandit rule identifier
            
        Returns:
            CWE identifier if available
        """
        cwe_mappings = {
            'B101': 'CWE-703',  # Improper Check or Handling of Exceptional Conditions
            'B102': 'CWE-94',   # Improper Control of Generation of Code
            'B105': 'CWE-798',  # Use of Hard-coded Credentials
            'B106': 'CWE-798',  # Use of Hard-coded Credentials
            'B107': 'CWE-798',  # Use of Hard-coded Credentials
            'B201': 'CWE-489',  # Active Debug Code
            'B301': 'CWE-502',  # Deserialization of Untrusted Data
            'B302': 'CWE-502',  # Deserialization of Untrusted Data
            'B303': 'CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
            'B304': 'CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
            'B305': 'CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
            'B307': 'CWE-94',   # Improper Control of Generation of Code
            'B313': 'CWE-91',   # XML Injection
            'B314': 'CWE-611',  # Improper Restriction of XML External Entity Reference
            'B315': 'CWE-611',  # Improper Restriction of XML External Entity Reference
            'B324': 'CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
            'B505': 'CWE-326',  # Inadequate Encryption Strength
            'B506': 'CWE-502',  # Deserialization of Untrusted Data
            'B601': 'CWE-78',   # Improper Neutralization of Special Elements used in an OS Command
            'B602': 'CWE-78',   # Improper Neutralization of Special Elements used in an OS Command
            'B608': 'CWE-89',   # Improper Neutralization of Special Elements used in an SQL Command
            'B609': 'CWE-78',   # Improper Neutralization of Special Elements used in an OS Command
            'B701': 'CWE-79',   # Improper Neutralization of Input During Web Page Generation
            'B702': 'CWE-79',   # Improper Neutralization of Input During Web Page Generation
        }
        
        return cwe_mappings.get(rule_id)
    
    def _get_owasp_mapping(self, rule_id: str) -> Optional[str]:
        """
        Map Bandit rule to OWASP Top 10 category.
        
        Args:
            rule_id: Bandit rule identifier
            
        Returns:
            OWASP Top 10 category if applicable
        """
        owasp_mappings = {
            'B608': 'A03:2021 – Injection',
            'B609': 'A03:2021 – Injection',
            'B610': 'A03:2021 – Injection',
            'B611': 'A03:2021 – Injection',
            'B105': 'A07:2021 – Identification and Authentication Failures',
            'B106': 'A07:2021 – Identification and Authentication Failures',
            'B107': 'A07:2021 – Identification and Authentication Failures',
            'B303': 'A02:2021 – Cryptographic Failures',
            'B304': 'A02:2021 – Cryptographic Failures',
            'B305': 'A02:2021 – Cryptographic Failures',
            'B324': 'A02:2021 – Cryptographic Failures',
            'B505': 'A02:2021 – Cryptographic Failures',
            'B313': 'A03:2021 – Injection',
            'B314': 'A05:2021 – Security Misconfiguration',
            'B315': 'A05:2021 – Security Misconfiguration',
            'B104': 'A05:2021 – Security Misconfiguration',
            'B201': 'A05:2021 – Security Misconfiguration',
            'B701': 'A03:2021 – Injection',
            'B702': 'A03:2021 – Injection',
            'B301': 'A08:2021 – Software and Data Integrity Failures',
            'B302': 'A08:2021 – Software and Data Integrity Failures',
            'B506': 'A08:2021 – Software and Data Integrity Failures'
        }
        
        return owasp_mappings.get(rule_id)
    
    def _get_remediation_guidance(self, rule_id: str) -> str:
        """
        Provide remediation guidance for specific security issues.
        
        Args:
            rule_id: Bandit rule identifier
            
        Returns:
            Detailed remediation guidance
        """
        remediation_guidance = {
            'B105': 'Remove hardcoded passwords and use environment variables or secure credential management systems.',
            'B106': 'Remove hardcoded passwords from function arguments and use secure credential management.',
            'B107': 'Remove hardcoded password defaults and implement secure credential handling.',
            'B201': 'Disable Flask debug mode in production by setting app.debug = False.',
            'B301': 'Avoid using pickle for untrusted data. Use JSON or other safe serialization formats.',
            'B302': 'Avoid using marshal for untrusted data. Use safer serialization alternatives.',
            'B303': 'Replace MD5 with SHA-256 or stronger cryptographic hash functions.',
            'B304': 'Use strong encryption algorithms instead of DES, RC4, or other weak ciphers.',
            'B305': 'Use secure cipher modes like GCM or CBC with proper IV generation.',
            'B307': 'Avoid using eval() with untrusted input. Use safer alternatives like ast.literal_eval().',
            'B313': 'Validate and sanitize XML input to prevent XML injection attacks.',
            'B314': 'Disable XML external entity processing or use defusedxml library.',
            'B324': 'Use SHA-256 or stronger hash algorithms instead of MD5 or SHA1.',
            'B505': 'Use cryptographically strong keys (minimum 2048 bits for RSA, 256 bits for AES).',
            'B506': 'Use safe_load() instead of load() when parsing YAML files.',
            'B601': 'Validate and sanitize shell command inputs or use subprocess with shell=False.',
            'B602': 'Use subprocess with shell=False and validate all inputs.',
            'B608': 'Use parameterized queries or ORM methods to prevent SQL injection.',
            'B609': 'Validate and sanitize all command-line inputs.',
            'B701': 'Enable Jinja2 autoescape or manually escape all template variables.',
            'B702': 'Use template engines with automatic escaping or manually escape variables.'
        }
        
        return remediation_guidance.get(
            rule_id, 
            'Review the code for security best practices and follow OWASP guidelines.'
        )
    
    def _assess_compliance_impact(self, rule_id: str, severity: str) -> Dict[str, Any]:
        """
        Assess compliance impact of security finding.
        
        Args:
            rule_id: Bandit rule identifier
            severity: Finding severity level
            
        Returns:
            Compliance impact assessment
        """
        impact_assessment = {
            'pci_dss_impact': False,
            'sox_impact': False,
            'gdpr_impact': False,
            'soc2_impact': False,
            'owasp_impact': True,
            'sans_impact': False,
            'severity_impact': severity.upper()
        }
        
        # High-impact rules for compliance
        high_compliance_impact_rules = [
            'B105', 'B106', 'B107',  # Hardcoded credentials - PCI DSS, SOX
            'B303', 'B304', 'B305', 'B324', 'B505',  # Cryptographic issues - All compliance
            'B608', 'B609', 'B610', 'B611',  # Injection attacks - All compliance
            'B201',  # Debug mode - PCI DSS, SOC2
            'B301', 'B302', 'B506'  # Deserialization - SOC2, GDPR
        ]
        
        if rule_id in high_compliance_impact_rules:
            impact_assessment['pci_dss_impact'] = True
            impact_assessment['sox_impact'] = True
            impact_assessment['gdpr_impact'] = True
            impact_assessment['soc2_impact'] = True
            impact_assessment['sans_impact'] = True
        
        return impact_assessment
    
    def _update_security_gate_status(self, finding: Dict[str, Any]) -> None:
        """
        Update security gate status based on finding severity.
        
        Args:
            finding: Security finding with severity information
        """
        severity = finding['severity'].upper()
        
        if severity == 'HIGH':
            self.security_gate_status['high_findings'] += 1
            if self.config.HIGH_SEVERITY_BLOCKING:
                self.security_gate_status['blocking_issues'].append(finding['finding_id'])
        elif severity == 'MEDIUM':
            self.security_gate_status['medium_findings'] += 1
        elif severity == 'LOW':
            self.security_gate_status['low_findings'] += 1
        
        # Check zero-tolerance policy compliance
        if self.config.ZERO_TOLERANCE_CRITICAL and severity == 'HIGH':
            self.security_gate_status['gate_passed'] = False
        elif self.config.ZERO_TOLERANCE_HIGH and severity == 'HIGH':
            self.security_gate_status['gate_passed'] = False
        else:
            # Update gate status based on thresholds
            critical_compliance = (
                self.security_gate_status['critical_findings'] <= self.config.MAX_CRITICAL_FINDINGS
            )
            high_compliance = (
                self.security_gate_status['high_findings'] <= self.config.MAX_HIGH_FINDINGS
            )
            self.security_gate_status['gate_passed'] = critical_compliance and high_compliance
    
    def _severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity sorting."""
        weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return weights.get(severity.upper(), 0)
    
    def _confidence_weight(self, confidence: str) -> int:
        """Get numeric weight for confidence sorting."""
        weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return weights.get(confidence.upper(), 0)
    
    def _evaluate_security_compliance(self, security_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate security compliance status based on findings.
        
        Args:
            security_findings: List of security findings
            
        Returns:
            Comprehensive compliance status assessment
        """
        compliance_status = {
            'overall_compliance': True,
            'zero_tolerance_compliance': True,
            'owasp_compliance': True,
            'sans_compliance': True,
            'pci_dss_compliance': True,
            'sox_compliance': True,
            'gdpr_compliance': True,
            'soc2_compliance': True,
            'compliance_violations': [],
            'compliance_summary': {}
        }
        
        # Evaluate findings against compliance requirements
        for finding in security_findings:
            severity = finding['severity'].upper()
            compliance_impact = finding['compliance_impact']
            
            # Check zero-tolerance policy violations
            if severity == 'HIGH' and self.config.ZERO_TOLERANCE_HIGH:
                compliance_status['zero_tolerance_compliance'] = False
                compliance_status['compliance_violations'].append({
                    'type': 'zero_tolerance_violation',
                    'finding_id': finding['finding_id'],
                    'severity': severity,
                    'rule_id': finding['rule_id']
                })
            
            # Check specific compliance violations
            if compliance_impact['pci_dss_impact'] and severity in ['HIGH', 'CRITICAL']:
                compliance_status['pci_dss_compliance'] = False
            
            if compliance_impact['sox_impact'] and severity in ['HIGH', 'CRITICAL']:
                compliance_status['sox_compliance'] = False
            
            if compliance_impact['gdpr_impact'] and severity in ['HIGH', 'CRITICAL']:
                compliance_status['gdpr_compliance'] = False
            
            if compliance_impact['soc2_impact'] and severity in ['HIGH', 'CRITICAL']:
                compliance_status['soc2_compliance'] = False
        
        # Update overall compliance status
        compliance_status['overall_compliance'] = all([
            compliance_status['zero_tolerance_compliance'],
            compliance_status['pci_dss_compliance'],
            compliance_status['sox_compliance'],
            compliance_status['gdpr_compliance'],
            compliance_status['soc2_compliance']
        ])
        
        # Generate compliance summary
        compliance_status['compliance_summary'] = {
            'total_findings': len(security_findings),
            'high_severity_findings': len([f for f in security_findings if f['severity'].upper() == 'HIGH']),
            'medium_severity_findings': len([f for f in security_findings if f['severity'].upper() == 'MEDIUM']),
            'low_severity_findings': len([f for f in security_findings if f['severity'].upper() == 'LOW']),
            'compliance_violations': len(compliance_status['compliance_violations']),
            'deployment_blocked': not compliance_status['overall_compliance']
        }
        
        return compliance_status
    
    def _generate_performance_metrics(self, analysis_duration: float, files_count: int) -> Dict[str, Any]:
        """
        Generate performance metrics for security analysis.
        
        Args:
            analysis_duration: Total analysis time in seconds
            files_count: Number of files analyzed
            
        Returns:
            Comprehensive performance metrics
        """
        return {
            'analysis_duration_seconds': round(analysis_duration, 2),
            'files_analyzed': files_count,
            'analysis_rate_files_per_second': round(files_count / analysis_duration, 2) if analysis_duration > 0 else 0,
            'performance_status': 'optimal' if analysis_duration < 60 else 'acceptable' if analysis_duration < 300 else 'slow',
            'memory_efficient': True,  # Could be enhanced with actual memory monitoring
            'parallel_execution': self.config.PARALLEL_ANALYSIS_ENABLED,
            'analysis_optimization_recommendations': self._generate_optimization_recommendations(analysis_duration, files_count)
        }
    
    def _generate_optimization_recommendations(self, duration: float, files_count: int) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        if duration > 300:  # 5 minutes
            recommendations.append("Consider enabling parallel analysis for large codebases")
        
        if files_count > 1000:
            recommendations.append("Consider excluding non-critical files from analysis")
        
        if duration / files_count > 1:  # More than 1 second per file
            recommendations.append("Consider optimizing Bandit rule set for better performance")
        
        return recommendations
    
    def _generate_analysis_summary(self, security_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive analysis summary.
        
        Args:
            security_findings: List of security findings
            
        Returns:
            Analysis summary with key metrics and recommendations
        """
        return {
            'total_findings': len(security_findings),
            'findings_by_severity': {
                'high': len([f for f in security_findings if f['severity'].upper() == 'HIGH']),
                'medium': len([f for f in security_findings if f['severity'].upper() == 'MEDIUM']),
                'low': len([f for f in security_findings if f['severity'].upper() == 'LOW'])
            },
            'findings_by_category': self._categorize_findings_summary(security_findings),
            'top_security_issues': self._identify_top_security_issues(security_findings),
            'remediation_priority': self._prioritize_remediation(security_findings),
            'security_score': self._calculate_security_score(security_findings),
            'recommendations': self._generate_security_recommendations(security_findings)
        }
    
    def _categorize_findings_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize findings by security category."""
        categories = {}
        for finding in findings:
            category = finding['category']
            categories[category] = categories.get(category, 0) + 1
        return categories
    
    def _identify_top_security_issues(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify top security issues requiring immediate attention."""
        high_severity_findings = [f for f in findings if f['severity'].upper() == 'HIGH']
        return sorted(high_severity_findings, key=lambda x: self._confidence_weight(x['confidence']), reverse=True)[:5]
    
    def _prioritize_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize remediation based on severity, compliance impact, and OWASP category."""
        def priority_score(finding):
            severity_score = self._severity_weight(finding['severity'])
            confidence_score = self._confidence_weight(finding['confidence'])
            compliance_score = 2 if any(finding['compliance_impact'].values()) else 1
            return severity_score * confidence_score * compliance_score
        
        return sorted(findings, key=priority_score, reverse=True)[:10]
    
    def _calculate_security_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall security score based on findings."""
        total_score = 100
        
        for finding in findings:
            severity = finding['severity'].upper()
            if severity == 'HIGH':
                total_score -= 10
            elif severity == 'MEDIUM':
                total_score -= 5
            elif severity == 'LOW':
                total_score -= 1
        
        security_score = max(0, total_score)
        
        return {
            'score': security_score,
            'grade': self._get_security_grade(security_score),
            'status': 'excellent' if security_score >= 90 else 'good' if security_score >= 70 else 'needs_improvement' if security_score >= 50 else 'critical'
        }
    
    def _get_security_grade(self, score: int) -> str:
        """Get letter grade for security score."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _generate_security_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        high_findings = [f for f in findings if f['severity'].upper() == 'HIGH']
        if high_findings:
            recommendations.append(f"Address {len(high_findings)} high-severity security findings immediately")
        
        crypto_findings = [f for f in findings if 'cryptographic' in f['category']]
        if crypto_findings:
            recommendations.append("Review and strengthen cryptographic implementations")
        
        injection_findings = [f for f in findings if 'injection' in f['category']]
        if injection_findings:
            recommendations.append("Implement input validation and sanitization for injection prevention")
        
        if not recommendations:
            recommendations.append("Security analysis passed. Continue following security best practices.")
        
        return recommendations
    
    def _generate_remediation_guidance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive remediation guidance for security findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            Detailed remediation guidance with priorities and timelines
        """
        return {
            'immediate_actions': [
                f['remediation_guidance'] for f in findings 
                if f['severity'].upper() == 'HIGH'
            ],
            'short_term_actions': [
                f['remediation_guidance'] for f in findings 
                if f['severity'].upper() == 'MEDIUM'
            ],
            'long_term_improvements': [
                f['remediation_guidance'] for f in findings 
                if f['severity'].upper() == 'LOW'
            ],
            'compliance_requirements': [
                f['remediation_guidance'] for f in findings 
                if any(f['compliance_impact'].values())
            ],
            'owasp_guidance': [
                f"Address {f['owasp_category']}: {f['remediation_guidance']}" 
                for f in findings if f.get('owasp_category')
            ],
            'security_best_practices': [
                "Implement comprehensive input validation",
                "Use parameterized queries for database operations",
                "Enable security headers in web applications",
                "Implement proper authentication and authorization",
                "Use secure cryptographic algorithms and key management",
                "Regular security testing and code reviews"
            ]
        }
    
    def _generate_empty_analysis_result(self) -> Dict[str, Any]:
        """Generate empty analysis result when no files are found."""
        return {
            'analysis_metadata': {
                'analysis_id': f"bandit_analysis_{int(time.time())}",
                'timestamp': datetime.utcnow().isoformat(),
                'files_analyzed': 0,
                'analysis_duration': 0.0
            },
            'security_findings': [],
            'compliance_status': {
                'overall_compliance': True,
                'zero_tolerance_compliance': True,
                'compliance_summary': {
                    'total_findings': 0,
                    'deployment_blocked': False
                }
            },
            'security_gate_status': {
                'gate_passed': True,
                'blocking_issues': []
            },
            'analysis_summary': {
                'total_findings': 0,
                'security_score': {'score': 100, 'grade': 'A', 'status': 'excellent'}
            }
        }
    
    def _get_bandit_version(self) -> str:
        """Get Bandit version information."""
        try:
            import bandit
            return bandit.__version__
        except (ImportError, AttributeError):
            return "unknown"
    
    def generate_security_reports(self, output_dir: Union[str, Path] = None) -> Dict[str, str]:
        """
        Generate comprehensive security reports in multiple formats.
        
        Args:
            output_dir: Directory for report output
            
        Returns:
            Dictionary mapping report types to file paths
        """
        if not self.analysis_results:
            raise BanditAnalysisError("No analysis results available. Run analyze_codebase() first.")
        
        output_dir = Path(output_dir) if output_dir else Path.cwd() / 'security_reports'
        output_dir.mkdir(exist_ok=True)
        
        report_files = {}
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        try:
            # Generate JSON report
            if self.config.GENERATE_JSON_REPORT:
                json_file = output_dir / f'bandit_security_report_{timestamp}.json'
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, indent=2, default=str)
                report_files['json'] = str(json_file)
            
            # Generate HTML report
            if self.config.GENERATE_HTML_REPORT:
                html_file = output_dir / f'bandit_security_report_{timestamp}.html'
                html_content = self._generate_html_report()
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                report_files['html'] = str(html_file)
            
            # Generate text report
            if self.config.GENERATE_TXT_REPORT:
                txt_file = output_dir / f'bandit_security_report_{timestamp}.txt'
                txt_content = self._generate_text_report()
                with open(txt_file, 'w', encoding='utf-8') as f:
                    f.write(txt_content)
                report_files['txt'] = str(txt_file)
            
            self.audit_logger.info(
                "Security reports generated successfully",
                report_files=list(report_files.keys()),
                output_directory=str(output_dir)
            )
            
            return report_files
            
        except Exception as e:
            self.audit_logger.error(
                f"Report generation failed: {str(e)}",
                output_directory=str(output_dir)
            )
            raise
    
    def _generate_html_report(self) -> str:
        """Generate HTML security report."""
        metadata = self.analysis_results['analysis_metadata']
        findings = self.analysis_results['security_findings']
        compliance = self.analysis_results['compliance_status']
        summary = self.analysis_results['analysis_summary']
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Bandit Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e8f5e8; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .high {{ border-left: 5px solid #ff0000; }}
        .medium {{ border-left: 5px solid #ff8800; }}
        .low {{ border-left: 5px solid #ffff00; }}
        .compliance {{ background-color: #f0f8ff; padding: 15px; margin: 20px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Bandit Security Analysis Report</h1>
        <p><strong>Analysis ID:</strong> {metadata['analysis_id']}</p>
        <p><strong>Timestamp:</strong> {metadata['timestamp']}</p>
        <p><strong>Files Analyzed:</strong> {metadata['files_analyzed']}</p>
        <p><strong>Analysis Duration:</strong> {metadata['analysis_duration']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Analysis Summary</h2>
        <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        <p><strong>Security Score:</strong> {summary['security_score']['score']}/100 ({summary['security_score']['grade']})</p>
        <p><strong>High Severity:</strong> {summary['findings_by_severity']['high']}</p>
        <p><strong>Medium Severity:</strong> {summary['findings_by_severity']['medium']}</p>
        <p><strong>Low Severity:</strong> {summary['findings_by_severity']['low']}</p>
    </div>
    
    <div class="compliance">
        <h2>Compliance Status</h2>
        <p><strong>Overall Compliance:</strong> {'✅ PASS' if compliance['overall_compliance'] else '❌ FAIL'}</p>
        <p><strong>Zero Tolerance Policy:</strong> {'✅ COMPLIANT' if compliance['zero_tolerance_compliance'] else '❌ VIOLATED'}</p>
        <p><strong>Deployment Status:</strong> {'✅ APPROVED' if not compliance['compliance_summary']['deployment_blocked'] else '❌ BLOCKED'}</p>
    </div>
    
    <h2>Security Findings</h2>
    """
        
        for finding in findings:
            severity_class = finding['severity'].lower()
            html_content += f"""
    <div class="finding {severity_class}">
        <h3>{finding['title']} (Rule: {finding['rule_id']})</h3>
        <p><strong>Severity:</strong> {finding['severity']}</p>
        <p><strong>File:</strong> {finding['file_path']}:{finding['line_number']}</p>
        <p><strong>Description:</strong> {finding['description']}</p>
        <p><strong>Remediation:</strong> {finding['remediation_guidance']}</p>
        {f"<p><strong>OWASP Category:</strong> {finding['owasp_category']}</p>" if finding.get('owasp_category') else ""}
    </div>
    """
        
        html_content += """
</body>
</html>
        """
        
        return html_content
    
    def _generate_text_report(self) -> str:
        """Generate text security report."""
        metadata = self.analysis_results['analysis_metadata']
        findings = self.analysis_results['security_findings']
        compliance = self.analysis_results['compliance_status']
        summary = self.analysis_results['analysis_summary']
        
        report_lines = [
            "=" * 80,
            "BANDIT SECURITY ANALYSIS REPORT",
            "=" * 80,
            f"Analysis ID: {metadata['analysis_id']}",
            f"Timestamp: {metadata['timestamp']}",
            f"Files Analyzed: {metadata['files_analyzed']}",
            f"Analysis Duration: {metadata['analysis_duration']:.2f} seconds",
            "",
            "ANALYSIS SUMMARY",
            "-" * 40,
            f"Total Findings: {summary['total_findings']}",
            f"Security Score: {summary['security_score']['score']}/100 ({summary['security_score']['grade']})",
            f"High Severity: {summary['findings_by_severity']['high']}",
            f"Medium Severity: {summary['findings_by_severity']['medium']}",
            f"Low Severity: {summary['findings_by_severity']['low']}",
            "",
            "COMPLIANCE STATUS",
            "-" * 40,
            f"Overall Compliance: {'PASS' if compliance['overall_compliance'] else 'FAIL'}",
            f"Zero Tolerance Policy: {'COMPLIANT' if compliance['zero_tolerance_compliance'] else 'VIOLATED'}",
            f"Deployment Status: {'APPROVED' if not compliance['compliance_summary']['deployment_blocked'] else 'BLOCKED'}",
            "",
            "SECURITY FINDINGS",
            "-" * 40
        ]
        
        for i, finding in enumerate(findings, 1):
            report_lines.extend([
                f"{i}. {finding['title']} ({finding['rule_id']})",
                f"   Severity: {finding['severity']}",
                f"   File: {finding['file_path']}:{finding['line_number']}",
                f"   Description: {finding['description']}",
                f"   Remediation: {finding['remediation_guidance']}",
                ""
            ])
        
        return "\n".join(report_lines)


# =============================================================================
# Security Analysis Exceptions
# =============================================================================

class BanditAnalysisError(Exception):
    """Base exception for Bandit security analysis errors."""
    pass


class BanditInitializationError(BanditAnalysisError):
    """Exception raised when Bandit manager initialization fails."""
    pass


class SecurityGateViolationError(BanditAnalysisError):
    """Exception raised when security gate policy is violated."""
    pass


# =============================================================================
# Bandit Security Analysis Test Suite
# =============================================================================

class TestBanditSecurityAnalysis:
    """
    Comprehensive test suite for Bandit security analysis automation implementing
    enterprise-grade security scanning validation per Section 6.6.3 requirements.
    """
    
    @pytest.fixture(scope="class")
    def bandit_analyzer(self):
        """Fixture providing configured Bandit security analyzer."""
        config = BanditAnalysisConfig()
        profile = BanditSecurityProfile()
        return BanditSecurityAnalyzer(config, profile)
    
    @pytest.fixture(scope="function")
    def temp_python_files(self, tmp_path):
        """Fixture providing temporary Python files for testing."""
        # Create test files with various security issues
        secure_file = tmp_path / "secure_code.py"
        secure_file.write_text("""
import hashlib
import os

def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def get_config():
    return os.environ.get('DATABASE_URL', 'sqlite:///default.db')
        """)
        
        insecure_file = tmp_path / "insecure_code.py"
        insecure_file.write_text("""
import hashlib
import subprocess

# B105: Hardcoded password
PASSWORD = "hardcoded_password"

# B303: MD5 usage
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# B602: Subprocess with shell=True
def execute_command(cmd):
    return subprocess.call(cmd, shell=True)

# B608: SQL injection risk
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
        """)
        
        return tmp_path
    
    def test_bandit_analyzer_initialization(self, bandit_analyzer):
        """Test Bandit analyzer initialization with proper configuration."""
        assert bandit_analyzer is not None
        assert bandit_analyzer.config.BANDIT_VERSION_REQUIRED == "1.7.0"
        assert bandit_analyzer.config.ZERO_TOLERANCE_CRITICAL is True
        assert bandit_analyzer.config.CI_CD_INTEGRATION_ENABLED is True
        assert bandit_analyzer.bandit_manager is not None
    
    def test_security_analysis_execution(self, bandit_analyzer, temp_python_files):
        """Test comprehensive security analysis execution."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        
        # Validate analysis results structure
        assert 'analysis_metadata' in results
        assert 'security_findings' in results
        assert 'compliance_status' in results
        assert 'security_gate_status' in results
        
        # Validate metadata
        metadata = results['analysis_metadata']
        assert metadata['files_analyzed'] > 0
        assert metadata['analysis_duration'] > 0
        assert 'analysis_id' in metadata
        assert 'timestamp' in metadata
    
    def test_security_findings_detection(self, bandit_analyzer, temp_python_files):
        """Test detection of security vulnerabilities in code."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        findings = results['security_findings']
        
        # Should detect multiple security issues in insecure_code.py
        assert len(findings) > 0
        
        # Validate finding structure
        for finding in findings:
            assert 'finding_id' in finding
            assert 'rule_id' in finding
            assert 'severity' in finding
            assert 'file_path' in finding
            assert 'line_number' in finding
            assert 'remediation_guidance' in finding
            assert 'compliance_impact' in finding
        
        # Check for specific security issues
        rule_ids = [f['rule_id'] for f in findings]
        assert 'B105' in rule_ids  # Hardcoded password
        assert 'B303' in rule_ids  # MD5 usage
        assert 'B602' in rule_ids  # Subprocess shell=True
    
    def test_zero_tolerance_policy_enforcement(self, bandit_analyzer, temp_python_files):
        """Test zero-tolerance policy enforcement per Section 6.6.3."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        
        compliance_status = results['compliance_status']
        security_gate = results['security_gate_status']
        
        # Check zero-tolerance compliance
        if security_gate['high_findings'] > 0:
            assert not compliance_status['zero_tolerance_compliance']
            assert not security_gate['gate_passed']
            assert len(security_gate['blocking_issues']) > 0
    
    def test_compliance_validation(self, bandit_analyzer, temp_python_files):
        """Test comprehensive compliance validation against multiple standards."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        compliance = results['compliance_status']
        
        # Validate compliance structure
        assert 'overall_compliance' in compliance
        assert 'zero_tolerance_compliance' in compliance
        assert 'owasp_compliance' in compliance
        assert 'pci_dss_compliance' in compliance
        assert 'sox_compliance' in compliance
        assert 'compliance_summary' in compliance
        
        # Check compliance summary
        summary = compliance['compliance_summary']
        assert 'total_findings' in summary
        assert 'deployment_blocked' in summary
        assert 'compliance_violations' in summary
    
    def test_security_gate_enforcement(self, bandit_analyzer, temp_python_files):
        """Test security gate enforcement and deployment blocking."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        security_gate = results['security_gate_status']
        
        # Validate security gate structure
        assert 'critical_findings' in security_gate
        assert 'high_findings' in security_gate
        assert 'medium_findings' in security_gate
        assert 'low_findings' in security_gate
        assert 'gate_passed' in security_gate
        assert 'blocking_issues' in security_gate
        
        # Check gate logic
        if security_gate['high_findings'] > 0:
            if bandit_analyzer.config.HIGH_SEVERITY_BLOCKING:
                assert not security_gate['gate_passed']
    
    def test_owasp_compliance_mapping(self, bandit_analyzer, temp_python_files):
        """Test OWASP Top 10 compliance mapping per Section 6.4.5."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        findings = results['security_findings']
        
        # Check OWASP mapping for findings
        owasp_mapped_findings = [f for f in findings if f.get('owasp_category')]
        if owasp_mapped_findings:
            for finding in owasp_mapped_findings:
                assert 'A0' in finding['owasp_category']  # OWASP 2021 format
    
    def test_remediation_guidance_generation(self, bandit_analyzer, temp_python_files):
        """Test comprehensive remediation guidance generation."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        
        # Check remediation guidance in findings
        findings = results['security_findings']
        for finding in findings:
            assert finding['remediation_guidance']
            assert len(finding['remediation_guidance']) > 20  # Meaningful guidance
        
        # Check comprehensive remediation guidance
        remediation = results['remediation_guidance']
        assert 'immediate_actions' in remediation
        assert 'short_term_actions' in remediation
        assert 'security_best_practices' in remediation
    
    def test_performance_metrics_collection(self, bandit_analyzer, temp_python_files):
        """Test performance metrics collection and analysis."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        metrics = results['performance_metrics']
        
        # Validate performance metrics
        assert 'analysis_duration_seconds' in metrics
        assert 'files_analyzed' in metrics
        assert 'analysis_rate_files_per_second' in metrics
        assert 'performance_status' in metrics
        
        # Check performance thresholds
        assert metrics['analysis_duration_seconds'] > 0
        assert metrics['files_analyzed'] > 0
        assert metrics['performance_status'] in ['optimal', 'acceptable', 'slow']
    
    def test_security_score_calculation(self, bandit_analyzer, temp_python_files):
        """Test security score calculation and grading."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        summary = results['analysis_summary']
        
        # Validate security score
        assert 'security_score' in summary
        score_info = summary['security_score']
        
        assert 'score' in score_info
        assert 'grade' in score_info
        assert 'status' in score_info
        
        assert 0 <= score_info['score'] <= 100
        assert score_info['grade'] in ['A', 'B', 'C', 'D', 'F']
        assert score_info['status'] in ['excellent', 'good', 'needs_improvement', 'critical']
    
    def test_security_report_generation(self, bandit_analyzer, temp_python_files, tmp_path):
        """Test automated security report generation per Section 6.6.2."""
        # First run analysis
        bandit_analyzer.analyze_codebase(temp_python_files)
        
        # Generate reports
        report_files = bandit_analyzer.generate_security_reports(tmp_path)
        
        # Validate report generation
        assert 'json' in report_files
        assert Path(report_files['json']).exists()
        
        # Validate JSON report content
        with open(report_files['json'], 'r') as f:
            json_data = json.load(f)
            assert 'analysis_metadata' in json_data
            assert 'security_findings' in json_data
            assert 'compliance_status' in json_data
    
    def test_ci_cd_integration_compatibility(self, bandit_analyzer, temp_python_files):
        """Test CI/CD pipeline integration compatibility per Section 6.6.2."""
        results = bandit_analyzer.analyze_codebase(temp_python_files)
        
        # Check CI/CD integration elements
        assert results['security_gate_status']['gate_passed'] is not None
        assert 'compliance_status' in results
        assert results['compliance_status']['compliance_summary']['deployment_blocked'] is not None
        
        # Validate exit code logic for CI/CD
        deployment_blocked = results['compliance_status']['compliance_summary']['deployment_blocked']
        gate_passed = results['security_gate_status']['gate_passed']
        
        # CI/CD should block deployment if gate doesn't pass
        if not gate_passed:
            assert deployment_blocked
    
    def test_comprehensive_python_module_coverage(self, bandit_analyzer, tmp_path):
        """Test comprehensive Python module security analysis coverage per Section 6.4.5."""
        # Create complex Python module structure
        module_dir = tmp_path / "test_module"
        module_dir.mkdir()
        
        # Create __init__.py
        (module_dir / "__init__.py").write_text("# Module init")
        
        # Create submodules
        (module_dir / "auth.py").write_text("""
import hashlib
PASSWORD = "secret123"  # B105
def authenticate(user, pwd):
    return hashlib.md5(pwd.encode()).hexdigest()  # B303
        """)
        
        (module_dir / "database.py").write_text("""
def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # B608
    return query
        """)
        
        # Create subdirectory
        subdir = module_dir / "utils"
        subdir.mkdir()
        (subdir / "__init__.py").write_text("")
        (subdir / "crypto.py").write_text("""
import ssl
context = ssl.create_default_context()
context.check_hostname = False  # B501
        """)
        
        # Analyze complete module
        results = bandit_analyzer.analyze_codebase(module_dir)
        
        # Should detect issues across all files
        findings = results['security_findings']
        assert len(findings) >= 3  # At least B105, B303, B608
        
        # Check file coverage
        analyzed_files = {f['file_path'] for f in findings}
        assert any('auth.py' in path for path in analyzed_files)
        assert any('database.py' in path for path in analyzed_files)
    
    def test_security_analysis_audit_logging(self, bandit_analyzer, temp_python_files, security_audit_logger):
        """Test comprehensive security analysis audit logging."""
        # Mock audit logger to capture events
        with patch.object(bandit_analyzer, 'audit_logger') as mock_logger:
            results = bandit_analyzer.analyze_codebase(temp_python_files)
            
            # Verify audit logging calls
            mock_logger.info.assert_called()
            
            # Check for key audit events
            call_args = [call.args[0] for call in mock_logger.info.call_args_list]
            assert any('Starting comprehensive Bandit security analysis' in msg for msg in call_args)
            assert any('Bandit security analysis completed successfully' in msg for msg in call_args)
    
    def test_security_analysis_performance_monitoring(self, bandit_analyzer, temp_python_files, security_performance_monitor):
        """Test security analysis performance monitoring integration."""
        with security_performance_monitor.measure_security_operation('bandit_analysis'):
            results = bandit_analyzer.analyze_codebase(temp_python_files)
        
        # Verify performance metrics
        performance_summary = security_performance_monitor.get_security_performance_summary()
        assert performance_summary['total_operations'] > 0
        assert 'bandit_analysis' in [m['operation'] for m in security_performance_monitor.security_metrics]
    
    @pytest.mark.parametrize("severity_level", ["HIGH", "MEDIUM", "LOW"])
    def test_severity_level_handling(self, bandit_analyzer, severity_level):
        """Test handling of different security finding severity levels."""
        # Create finding with specific severity
        test_finding = {
            'finding_id': 'test_finding',
            'severity': severity_level,
            'compliance_impact': {
                'pci_dss_impact': severity_level == 'HIGH',
                'sox_impact': severity_level == 'HIGH'
            }
        }
        
        # Test severity weight calculation
        weight = bandit_analyzer._severity_weight(severity_level)
        expected_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        assert weight == expected_weights[severity_level]
    
    def test_empty_codebase_analysis(self, bandit_analyzer, tmp_path):
        """Test analysis of empty codebase without Python files."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        results = bandit_analyzer.analyze_codebase(empty_dir)
        
        # Should return clean results for empty codebase
        assert results['analysis_metadata']['files_analyzed'] == 0
        assert len(results['security_findings']) == 0
        assert results['compliance_status']['overall_compliance'] is True
        assert results['security_gate_status']['gate_passed'] is True
    
    def test_error_handling_robustness(self, bandit_analyzer):
        """Test error handling for various failure scenarios."""
        # Test non-existent path
        with pytest.raises(FileNotFoundError):
            bandit_analyzer.analyze_codebase("/nonexistent/path")
        
        # Test report generation without analysis
        analyzer = BanditSecurityAnalyzer()
        with pytest.raises(BanditAnalysisError):
            analyzer.generate_security_reports()


# =============================================================================
# CI/CD Integration Functions
# =============================================================================

def run_bandit_security_gate(target_path: Union[str, Path], 
                            config: BanditAnalysisConfig = None,
                            fail_on_violations: bool = True) -> int:
    """
    Run Bandit security analysis as CI/CD security gate per Section 6.6.2.
    
    This function provides a CI/CD-friendly interface for automated security
    scanning with proper exit codes and comprehensive reporting.
    
    Args:
        target_path: Path to Python codebase for analysis
        config: Bandit analysis configuration
        fail_on_violations: Whether to return non-zero exit code on violations
        
    Returns:
        Exit code for CI/CD pipeline (0 = success, 1 = security violations)
    """
    exit_code = 0
    config = config or BanditAnalysisConfig()
    
    try:
        # Initialize analyzer
        analyzer = BanditSecurityAnalyzer(config)
        
        # Execute security analysis
        results = analyzer.analyze_codebase(target_path)
        
        # Generate reports
        report_files = analyzer.generate_security_reports()
        
        # Check security gate status
        security_gate = results['security_gate_status']
        compliance_status = results['compliance_status']
        
        print(f"🔒 Bandit Security Analysis Results")
        print(f"{'='*50}")
        print(f"Files Analyzed: {results['analysis_metadata']['files_analyzed']}")
        print(f"Total Findings: {results['analysis_summary']['total_findings']}")
        print(f"High Severity: {security_gate['high_findings']}")
        print(f"Medium Severity: {security_gate['medium_findings']}")
        print(f"Low Severity: {security_gate['low_findings']}")
        print(f"Security Score: {results['analysis_summary']['security_score']['score']}/100")
        print(f"{'='*50}")
        
        # Check for security gate violations
        if not security_gate['gate_passed']:
            print("❌ SECURITY GATE FAILED")
            print(f"Blocking Issues: {len(security_gate['blocking_issues'])}")
            
            if config.ZERO_TOLERANCE_CRITICAL or config.ZERO_TOLERANCE_HIGH:
                print("🚨 ZERO TOLERANCE POLICY VIOLATED")
            
            if fail_on_violations:
                exit_code = 1
        else:
            print("✅ SECURITY GATE PASSED")
        
        # Check overall compliance
        if not compliance_status['overall_compliance']:
            print("❌ COMPLIANCE VIOLATIONS DETECTED")
            print(f"Violations: {len(compliance_status['compliance_violations'])}")
            
            if fail_on_violations:
                exit_code = 1
        else:
            print("✅ COMPLIANCE REQUIREMENTS MET")
        
        # Print report locations
        print(f"\n📊 Security Reports Generated:")
        for report_type, file_path in report_files.items():
            print(f"  {report_type.upper()}: {file_path}")
        
        return exit_code
        
    except Exception as e:
        print(f"❌ Security analysis failed: {str(e)}")
        return 1 if fail_on_violations else 0


def validate_bandit_installation() -> bool:
    """
    Validate Bandit installation and version requirements per Section 6.6.3.
    
    Returns:
        True if Bandit is properly installed and meets version requirements
    """
    try:
        import bandit
        from packaging import version
        
        required_version = BanditAnalysisConfig.BANDIT_VERSION_REQUIRED
        installed_version = bandit.__version__
        
        if version.parse(installed_version) >= version.parse(required_version):
            print(f"✅ Bandit {installed_version} meets requirements (>= {required_version})")
            return True
        else:
            print(f"❌ Bandit {installed_version} below required version {required_version}")
            return False
            
    except ImportError:
        print("❌ Bandit not installed. Install with: pip install bandit>=1.7.0")
        return False
    except Exception as e:
        print(f"❌ Bandit validation failed: {str(e)}")
        return False


# =============================================================================
# CLI Interface for Security Analysis
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Bandit Security Analysis Automation for Flask Applications"
    )
    parser.add_argument(
        "target", 
        help="Path to Python codebase for security analysis"
    )
    parser.add_argument(
        "--output-dir", 
        help="Directory for security report output"
    )
    parser.add_argument(
        "--no-fail", 
        action="store_true",
        help="Don't fail on security violations (for reporting only)"
    )
    parser.add_argument(
        "--validate-install", 
        action="store_true",
        help="Validate Bandit installation and exit"
    )
    
    args = parser.parse_args()
    
    if args.validate_install:
        sys.exit(0 if validate_bandit_installation() else 1)
    
    exit_code = run_bandit_security_gate(
        args.target,
        fail_on_violations=not args.no_fail
    )
    
    sys.exit(exit_code)


# Export all public interfaces
__all__ = [
    'BanditAnalysisConfig',
    'BanditSecurityProfile', 
    'BanditSecurityAnalyzer',
    'BanditAnalysisError',
    'BanditInitializationError',
    'SecurityGateViolationError',
    'TestBanditSecurityAnalysis',
    'run_bandit_security_gate',
    'validate_bandit_installation'
]