"""
Bandit Security Analysis Automation

Comprehensive Python code security scanning using bandit 1.7+ for vulnerability detection,
automated security reporting, and CI/CD integration with zero-tolerance security enforcement.

This module implements enterprise-grade security analysis automation including:
- Bandit 1.7+ integration for comprehensive Python security pattern scanning per Section 6.4.5
- Critical and high-severity vulnerability detection with zero-tolerance enforcement per Section 6.6.3
- Automated security report generation and metrics collection per Section 6.6.2
- CI/CD pipeline integration for security gate enforcement per Section 6.6.2
- Comprehensive security analysis covering all Python modules per Section 6.4.5
- Security posture monitoring and trend analysis per Section 6.4.6

Integration with Security Infrastructure:
- Builds on security testing fixtures from tests/security/conftest.py per Section 6.6.1
- Integrates with enterprise security monitoring and SIEM systems per Section 6.4.5
- Supports automated security incident response and remediation workflows per Section 6.4.6
- Provides comprehensive security metrics for compliance reporting per Section 6.4.6

Dependencies:
- bandit 1.7+ for comprehensive Python security analysis and vulnerability detection
- subprocess for bandit execution and result collection with secure parameter handling
- json for security finding parsing and structured data management
- pathlib for secure file system operations and path validation
- typing for comprehensive type safety and runtime validation
- logging for structured security event logging and audit trail generation
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import secrets

# Import security testing infrastructure
from tests.security.conftest import (
    SecurityTestConfig,
    SecurityMonitor,
    SecurityMetricsCollector
)

# Configure structured logging for security analysis
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security.bandit_analysis')


class SecuritySeverity(Enum):
    """Security finding severity levels with enforcement policies."""
    
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    @property
    def enforcement_level(self) -> str:
        """Get enforcement level for severity."""
        enforcement_map = {
            self.LOW: "warning",
            self.MEDIUM: "warning",
            self.HIGH: "blocking",
            self.CRITICAL: "blocking"
        }
        return enforcement_map[self]
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for severity comparison."""
        severity_values = {
            self.LOW: 1,
            self.MEDIUM: 2,
            self.HIGH: 3,
            self.CRITICAL: 4
        }
        return severity_values[self]


class SecurityRuleCategory(Enum):
    """Security rule categories for comprehensive analysis."""
    
    HARDCODED_PASSWORD = "hardcoded_password_default_argument"
    SQL_INJECTION = "hardcoded_sql_expressions"
    SHELL_INJECTION = "subprocess_popen_with_shell_equals_true"
    CRYPTO_WEAK = "weak_cryptographic_key"
    RANDOM_WEAK = "standard_pseudorandom_generators"
    INPUT_VALIDATION = "try_except_pass"
    INSECURE_TRANSPORT = "request_without_timeout"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "pickle_load"
    EXEC_INJECTION = "exec_used"
    EVAL_INJECTION = "use_of_eval"
    YAML_LOAD = "yaml_load"
    XML_VULNERABILITY = "xml_bad_tree"
    LDAP_INJECTION = "ldap_injection"
    HTTP_INSECURE = "request_with_no_cert_validation"
    
    @property
    def default_severity(self) -> SecuritySeverity:
        """Get default severity for rule category."""
        high_severity_rules = {
            self.HARDCODED_PASSWORD,
            self.SQL_INJECTION,
            self.SHELL_INJECTION,
            self.EXEC_INJECTION,
            self.EVAL_INJECTION,
            self.DESERIALIZATION
        }
        
        critical_severity_rules = {
            self.CRYPTO_WEAK,
            self.PATH_TRAVERSAL,
            self.XML_VULNERABILITY
        }
        
        if self in critical_severity_rules:
            return SecuritySeverity.CRITICAL
        elif self in high_severity_rules:
            return SecuritySeverity.HIGH
        else:
            return SecuritySeverity.MEDIUM


@dataclass
class SecurityFinding:
    """
    Comprehensive security finding data structure for vulnerability tracking.
    
    Represents individual security vulnerabilities identified by bandit analysis
    with complete metadata for remediation, reporting, and compliance tracking.
    """
    
    # Core finding identification
    finding_id: str
    rule_id: str
    test_name: str
    category: SecurityRuleCategory
    
    # Severity and risk assessment
    severity: SecuritySeverity
    confidence: str
    risk_score: float
    
    # Location and context information
    file_path: str
    line_number: int
    column_number: int
    code_snippet: str
    
    # Vulnerability details
    issue_text: str
    issue_description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Remediation and guidance
    remediation_guidance: Optional[str] = None
    mitigation_priority: str = "medium"
    estimated_fix_time: Optional[str] = None
    
    # Metadata and tracking
    scan_timestamp: str
    analyzer_version: str
    baseline_status: str = "new"
    suppression_status: str = "active"
    false_positive: bool = False
    
    # Compliance and reporting
    compliance_impact: List[str] = None
    reporting_tags: List[str] = None
    
    def __post_init__(self):
        """Post-initialization processing for security finding."""
        if self.compliance_impact is None:
            self.compliance_impact = []
        if self.reporting_tags is None:
            self.reporting_tags = []
            
        # Generate unique finding ID if not provided
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()
            
        # Set mitigation priority based on severity
        self.mitigation_priority = self._calculate_mitigation_priority()
        
        # Add OWASP categorization
        self.owasp_category = self._map_to_owasp_category()
        
        # Add compliance impact assessment
        self.compliance_impact = self._assess_compliance_impact()
    
    def _generate_finding_id(self) -> str:
        """Generate unique finding identifier."""
        content = f"{self.rule_id}:{self.file_path}:{self.line_number}:{self.test_name}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _calculate_mitigation_priority(self) -> str:
        """Calculate mitigation priority based on severity and confidence."""
        if self.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
            if self.confidence in ["HIGH", "MEDIUM"]:
                return "critical"
            else:
                return "high"
        elif self.severity == SecuritySeverity.MEDIUM:
            return "medium"
        else:
            return "low"
    
    def _map_to_owasp_category(self) -> str:
        """Map security finding to OWASP Top 10 category."""
        owasp_mapping = {
            SecurityRuleCategory.SQL_INJECTION: "A03:2021 – Injection",
            SecurityRuleCategory.SHELL_INJECTION: "A03:2021 – Injection",
            SecurityRuleCategory.EXEC_INJECTION: "A03:2021 – Injection",
            SecurityRuleCategory.EVAL_INJECTION: "A03:2021 – Injection",
            SecurityRuleCategory.LDAP_INJECTION: "A03:2021 – Injection",
            SecurityRuleCategory.HARDCODED_PASSWORD: "A07:2021 – Identification and Authentication Failures",
            SecurityRuleCategory.CRYPTO_WEAK: "A02:2021 – Cryptographic Failures",
            SecurityRuleCategory.INSECURE_TRANSPORT: "A02:2021 – Cryptographic Failures",
            SecurityRuleCategory.HTTP_INSECURE: "A02:2021 – Cryptographic Failures",
            SecurityRuleCategory.INPUT_VALIDATION: "A03:2021 – Injection",
            SecurityRuleCategory.PATH_TRAVERSAL: "A01:2021 – Broken Access Control",
            SecurityRuleCategory.DESERIALIZATION: "A08:2021 – Software and Data Integrity Failures",
            SecurityRuleCategory.XML_VULNERABILITY: "A05:2021 – Security Misconfiguration",
            SecurityRuleCategory.YAML_LOAD: "A08:2021 – Software and Data Integrity Failures"
        }
        return owasp_mapping.get(self.category, "A10:2021 – Server-Side Request Forgery")
    
    def _assess_compliance_impact(self) -> List[str]:
        """Assess compliance framework impact."""
        impact = []
        
        # Critical and High severity findings impact multiple frameworks
        if self.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
            impact.extend(["SOC 2", "ISO 27001", "PCI DSS"])
            
        # Specific rule category impacts
        if self.category in [SecurityRuleCategory.HARDCODED_PASSWORD, SecurityRuleCategory.CRYPTO_WEAK]:
            impact.extend(["FIPS 140-2", "GDPR"])
            
        if self.category in [SecurityRuleCategory.SQL_INJECTION, SecurityRuleCategory.INPUT_VALIDATION]:
            impact.extend(["OWASP Top 10", "SANS Top 25"])
            
        return list(set(impact))  # Remove duplicates
    
    def is_blocking(self) -> bool:
        """Determine if finding should block deployment."""
        return (
            self.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH] and
            not self.false_positive and
            self.suppression_status == "active"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return asdict(self)


@dataclass
class BanditScanResult:
    """
    Comprehensive bandit scan result with metrics and analysis.
    
    Aggregates security findings from bandit analysis with comprehensive
    metrics, compliance assessment, and remediation guidance for enterprise
    security reporting and decision making.
    """
    
    # Scan metadata
    scan_id: str
    scan_timestamp: str
    scan_duration: float
    analyzer_version: str
    
    # Scan configuration
    target_paths: List[str]
    excluded_paths: List[str]
    rules_used: List[str]
    confidence_levels: List[str]
    
    # Scan results
    findings: List[SecurityFinding]
    total_files_scanned: int
    total_lines_scanned: int
    
    # Security metrics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Quality metrics
    false_positive_rate: float = 0.0
    suppressed_count: int = 0
    new_findings_count: int = 0
    
    # Compliance assessment
    compliance_status: str = "unknown"
    blocking_findings: List[SecurityFinding] = None
    compliance_violations: List[str] = None
    
    # Remediation metrics
    estimated_remediation_time: str = "unknown"
    priority_findings: List[SecurityFinding] = None
    
    def __post_init__(self):
        """Post-initialization processing for scan result."""
        if self.blocking_findings is None:
            self.blocking_findings = []
        if self.compliance_violations is None:
            self.compliance_violations = []
        if self.priority_findings is None:
            self.priority_findings = []
            
        # Calculate severity counts
        self._calculate_severity_counts()
        
        # Assess compliance status
        self.compliance_status = self._assess_compliance_status()
        
        # Identify blocking findings
        self.blocking_findings = [f for f in self.findings if f.is_blocking()]
        
        # Calculate priority findings
        self.priority_findings = self._identify_priority_findings()
        
        # Estimate remediation time
        self.estimated_remediation_time = self._estimate_remediation_time()
        
        # Assess compliance violations
        self.compliance_violations = self._assess_compliance_violations()
    
    def _calculate_severity_counts(self):
        """Calculate count of findings by severity level."""
        severity_counts = {
            SecuritySeverity.CRITICAL: 0,
            SecuritySeverity.HIGH: 0,
            SecuritySeverity.MEDIUM: 0,
            SecuritySeverity.LOW: 0
        }
        
        for finding in self.findings:
            if not finding.false_positive and finding.suppression_status == "active":
                severity_counts[finding.severity] += 1
        
        self.critical_count = severity_counts[SecuritySeverity.CRITICAL]
        self.high_count = severity_counts[SecuritySeverity.HIGH]
        self.medium_count = severity_counts[SecuritySeverity.MEDIUM]
        self.low_count = severity_counts[SecuritySeverity.LOW]
    
    def _assess_compliance_status(self) -> str:
        """Assess overall compliance status based on findings."""
        if self.critical_count > 0:
            return "critical_non_compliant"
        elif self.high_count > 0:
            return "non_compliant"
        elif self.medium_count > 0:
            return "conditional_compliant"
        else:
            return "compliant"
    
    def _identify_priority_findings(self) -> List[SecurityFinding]:
        """Identify high-priority findings requiring immediate attention."""
        priority_findings = []
        
        for finding in self.findings:
            if (finding.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH] and
                not finding.false_positive and
                finding.confidence in ["HIGH", "MEDIUM"]):
                priority_findings.append(finding)
        
        # Sort by severity and confidence
        priority_findings.sort(
            key=lambda f: (f.severity.numeric_value, f.confidence == "HIGH"),
            reverse=True
        )
        
        return priority_findings
    
    def _estimate_remediation_time(self) -> str:
        """Estimate total remediation time based on findings."""
        total_hours = 0
        
        time_estimates = {
            SecuritySeverity.CRITICAL: 8,  # 8 hours per critical finding
            SecuritySeverity.HIGH: 4,      # 4 hours per high finding
            SecuritySeverity.MEDIUM: 2,    # 2 hours per medium finding
            SecuritySeverity.LOW: 1        # 1 hour per low finding
        }
        
        for finding in self.findings:
            if not finding.false_positive and finding.suppression_status == "active":
                total_hours += time_estimates.get(finding.severity, 1)
        
        if total_hours == 0:
            return "0 hours"
        elif total_hours < 8:
            return f"{total_hours} hours"
        elif total_hours < 40:
            return f"{total_hours // 8} days"
        else:
            return f"{total_hours // 40} weeks"
    
    def _assess_compliance_violations(self) -> List[str]:
        """Assess compliance framework violations."""
        violations = set()
        
        for finding in self.findings:
            if finding.is_blocking():
                violations.update(finding.compliance_impact)
        
        return list(violations)
    
    def is_deployment_ready(self) -> bool:
        """Determine if scan results allow deployment."""
        return len(self.blocking_findings) == 0
    
    def get_security_score(self) -> float:
        """Calculate overall security score (0-100)."""
        if not self.findings:
            return 100.0
        
        # Weight findings by severity
        severity_weights = {
            SecuritySeverity.CRITICAL: 25,
            SecuritySeverity.HIGH: 10,
            SecuritySeverity.MEDIUM: 5,
            SecuritySeverity.LOW: 1
        }
        
        total_penalty = sum(
            severity_weights[f.severity] for f in self.findings
            if not f.false_positive and f.suppression_status == "active"
        )
        
        # Calculate score based on penalty
        max_penalty = len(self.findings) * severity_weights[SecuritySeverity.CRITICAL]
        if max_penalty == 0:
            return 100.0
        
        score = max(0, 100 - (total_penalty / max_penalty * 100))
        return round(score, 2)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary for serialization."""
        result_dict = asdict(self)
        # Convert SecurityFinding objects to dictionaries
        result_dict['findings'] = [f.to_dict() for f in self.findings]
        result_dict['blocking_findings'] = [f.to_dict() for f in self.blocking_findings]
        result_dict['priority_findings'] = [f.to_dict() for f in self.priority_findings]
        return result_dict


class BanditSecurityAnalyzer:
    """
    Comprehensive bandit security analysis automation with enterprise integration.
    
    Implements automated Python code security scanning using bandit 1.7+ with
    comprehensive vulnerability detection, reporting, and CI/CD integration for
    zero-tolerance security enforcement per Section 6.6.3.
    """
    
    def __init__(
        self,
        project_root: Union[str, Path],
        config_path: Optional[Union[str, Path]] = None,
        security_monitor: Optional[SecurityMonitor] = None,
        metrics_collector: Optional[SecurityMetricsCollector] = None
    ):
        """
        Initialize bandit security analyzer with comprehensive configuration.
        
        Args:
            project_root: Root directory of project for security scanning
            config_path: Optional path to bandit configuration file
            security_monitor: Security event monitoring integration
            metrics_collector: Security metrics collection integration
        """
        self.project_root = Path(project_root).resolve()
        self.config_path = Path(config_path) if config_path else None
        self.security_monitor = security_monitor
        self.metrics_collector = metrics_collector
        
        # Validate project root exists and is accessible
        if not self.project_root.exists():
            raise FileNotFoundError(f"Project root not found: {self.project_root}")
        
        # Initialize bandit configuration
        self.bandit_config = self._initialize_bandit_config()
        
        # Security analysis configuration
        self.excluded_paths = self._get_excluded_paths()
        self.included_rules = self._get_included_rules()
        self.confidence_levels = ["HIGH", "MEDIUM", "LOW"]
        
        # Initialize scan tracking
        self.scan_history: List[BanditScanResult] = []
        self.baseline_findings: Set[str] = set()
        
        # Configure logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Validate bandit installation
        self._validate_bandit_installation()
    
    def _initialize_bandit_config(self) -> Dict[str, Any]:
        """Initialize bandit configuration with security-focused settings."""
        default_config = {
            "tests": [
                "B101", "B102", "B103", "B104", "B105", "B106", "B107",  # Assert and test issues
                "B108", "B110", "B112",  # Hardcoded password checks
                "B201", "B301", "B302", "B303", "B304", "B305", "B306",  # Flask/Django security
                "B307", "B308", "B309", "B310", "B311", "B312", "B313",  # Crypto and random
                "B314", "B315", "B316", "B317", "B318", "B319", "B320",  # XML and misc
                "B321", "B322", "B323", "B324", "B325", "B501", "B502",  # Request/urllib issues
                "B503", "B504", "B505", "B506", "B507", "B601", "B602",  # Shell injection
                "B603", "B604", "B605", "B606", "B607", "B608", "B609",  # Process/subprocess
                "B610", "B611", "B701", "B702", "B703"                   # Django/Jinja specific
            ],
            "skips": [],  # No tests skipped for comprehensive scanning
            "exclude_dirs": [
                "/.venv/", "/venv/", "/.tox/", "/node_modules/",
                "/.git/", "/migrations/", "/__pycache__/"
            ],
            "severity": ["LOW", "MEDIUM", "HIGH"],
            "confidence": ["LOW", "MEDIUM", "HIGH"],
            "format": "json",
            "output": None,  # Will be set per scan
            "verbose": True,
            "debug": False,
            "quiet": False,
            "ignore_nosec": False,  # Don't ignore # nosec comments
            "baseline": None,       # Will be set if baseline exists
            "ini_path": None       # Will be set if config file exists
        }
        
        # Load custom configuration if provided
        if self.config_path and self.config_path.exists():
            try:
                import configparser
                config_parser = configparser.ConfigParser()
                config_parser.read(self.config_path)
                
                if 'bandit' in config_parser:
                    bandit_section = config_parser['bandit']
                    
                    # Update configuration from file
                    if 'tests' in bandit_section:
                        default_config['tests'] = bandit_section['tests'].split(',')
                    if 'skips' in bandit_section:
                        default_config['skips'] = bandit_section['skips'].split(',')
                    if 'exclude_dirs' in bandit_section:
                        default_config['exclude_dirs'].extend(
                            bandit_section['exclude_dirs'].split(',')
                        )
                        
            except Exception as e:
                self.logger.warning(f"Failed to load bandit config from {self.config_path}: {e}")
        
        return default_config
    
    def _get_excluded_paths(self) -> List[str]:
        """Get list of paths to exclude from security scanning."""
        excluded_patterns = [
            # Standard exclusions
            "__pycache__", "*.pyc", "*.pyo", "*.pyd",
            ".git", ".svn", ".hg", ".bzr",
            ".tox", ".coverage", "htmlcov",
            "node_modules", "bower_components",
            
            # Virtual environments
            "venv", ".venv", "env", ".env",
            "virtualenv", ".virtualenv",
            
            # IDE and editor files
            ".idea", ".vscode", "*.swp", "*.swo",
            ".DS_Store", "Thumbs.db",
            
            # Build and distribution
            "build", "dist", "*.egg-info",
            ".pytest_cache", ".mypy_cache",
            
            # Database and temporary files
            "*.db", "*.sqlite", "*.sqlite3",
            "tmp", "temp", "*.tmp", "*.temp",
            
            # Documentation
            "docs/_build", "site",
            
            # Test fixtures that may contain intentionally vulnerable code
            "test_fixtures", "mock_data"
        ]
        
        return excluded_patterns
    
    def _get_included_rules(self) -> List[str]:
        """Get comprehensive list of bandit rules for security scanning."""
        # Comprehensive rule set covering OWASP Top 10 and enterprise security
        return [
            # Hardcoded password and secret detection
            "B105", "B106", "B107", "B108",
            
            # SQL injection and command injection
            "B608", "B609", "B602", "B603", "B604", "B605", "B606", "B607",
            
            # Cryptographic issues
            "B311", "B313", "B320", "B321", "B322", "B323", "B324", "B325",
            
            # Insecure randomness
            "B311", "B506",
            
            # XML vulnerabilities
            "B314", "B315", "B316", "B317", "B318", "B319",
            
            # Request/HTTP security
            "B501", "B502", "B503", "B504", "B505", "B507",
            
            # Input validation and sanitization
            "B301", "B302", "B303", "B304", "B305", "B306", "B307", "B308", "B309",
            
            # Deserialization vulnerabilities
            "B301", "B302", "B pickle_load",
            
            # Shell injection
            "B602", "B603", "B604", "B605", "B606", "B607", "B608", "B609", "B610",
            
            # Assert usage
            "B101", "B112",
            
            # Flask/Django specific security
            "B201", "B701", "B702", "B703",
            
            # General security issues
            "B102", "B103", "B104", "B110", "B611"
        ]
    
    def _validate_bandit_installation(self):
        """Validate bandit installation and version requirements."""
        try:
            # Check bandit installation
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError("Bandit not properly installed")
            
            # Parse version
            version_output = result.stdout.strip()
            self.logger.info(f"Bandit version detected: {version_output}")
            
            # Check minimum version requirement (1.7+)
            import re
            version_match = re.search(r'bandit\s+(\d+\.\d+\.\d+)', version_output)
            if version_match:
                version_str = version_match.group(1)
                version_parts = [int(x) for x in version_str.split('.')]
                
                # Check if version is 1.7.0 or higher
                if version_parts[0] < 1 or (version_parts[0] == 1 and version_parts[1] < 7):
                    raise RuntimeError(f"Bandit version {version_str} is below required 1.7.0")
                
                self.logger.info(f"Bandit version {version_str} meets requirements")
            else:
                self.logger.warning("Could not parse bandit version, proceeding with scan")
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"Bandit installation validation failed: {e}")
    
    def scan_project(
        self,
        target_paths: Optional[List[Union[str, Path]]] = None,
        baseline_path: Optional[Union[str, Path]] = None,
        output_format: str = "json",
        include_nosec: bool = False
    ) -> BanditScanResult:
        """
        Execute comprehensive security scan of project using bandit.
        
        Args:
            target_paths: Specific paths to scan (defaults to project root)
            baseline_path: Path to baseline file for comparison
            output_format: Output format for bandit results
            include_nosec: Whether to include findings marked with # nosec
            
        Returns:
            BanditScanResult: Comprehensive scan results with findings and metrics
            
        Raises:
            SecurityScanError: When scan execution fails
            SecurityAnalysisError: When scan results cannot be processed
        """
        scan_start_time = time.time()
        scan_id = f"bandit_scan_{int(scan_start_time)}_{secrets.token_hex(4)}"
        
        self.logger.info(f"Starting bandit security scan: {scan_id}")
        
        # Log security event
        if self.security_monitor:
            self.security_monitor.log_security_event(
                "security_scan_started",
                {
                    "scan_id": scan_id,
                    "scanner": "bandit",
                    "target_paths": [str(p) for p in (target_paths or [self.project_root])]
                }
            )
        
        try:
            # Prepare scan parameters
            scan_targets = target_paths or [self.project_root]
            scan_paths = [Path(p).resolve() for p in scan_targets]
            
            # Validate target paths
            for path in scan_paths:
                if not path.exists():
                    raise FileNotFoundError(f"Scan target not found: {path}")
            
            # Execute bandit scan
            scan_output = self._execute_bandit_scan(
                scan_paths=scan_paths,
                baseline_path=baseline_path,
                output_format=output_format,
                include_nosec=include_nosec
            )
            
            # Process scan results
            findings = self._process_scan_results(scan_output, scan_id)
            
            # Calculate scan metrics
            scan_duration = time.time() - scan_start_time
            scan_metrics = self._calculate_scan_metrics(scan_paths)
            
            # Create comprehensive scan result
            scan_result = BanditScanResult(
                scan_id=scan_id,
                scan_timestamp=datetime.now(timezone.utc).isoformat(),
                scan_duration=scan_duration,
                analyzer_version=self._get_bandit_version(),
                target_paths=[str(p) for p in scan_paths],
                excluded_paths=self.excluded_paths,
                rules_used=self.included_rules,
                confidence_levels=self.confidence_levels,
                findings=findings,
                total_files_scanned=scan_metrics['files_scanned'],
                total_lines_scanned=scan_metrics['lines_scanned']
            )
            
            # Record scan in history
            self.scan_history.append(scan_result)
            
            # Log scan completion
            self.logger.info(
                f"Bandit scan completed: {scan_id} - "
                f"Found {len(findings)} findings in {scan_duration:.2f}s"
            )
            
            # Log security event
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    "security_scan_completed",
                    {
                        "scan_id": scan_id,
                        "findings_count": len(findings),
                        "critical_count": scan_result.critical_count,
                        "high_count": scan_result.high_count,
                        "scan_duration": scan_duration,
                        "deployment_ready": scan_result.is_deployment_ready()
                    }
                )
            
            # Record metrics
            if self.metrics_collector:
                self.metrics_collector.record_security_response_time(
                    "bandit_scan", scan_duration * 1000
                )
                for finding in findings:
                    self.metrics_collector.record_attack_detection(
                        f"static_analysis_{finding.category.value}",
                        True,  # bandit detects by definition
                        0  # Static analysis has no detection time
                    )
            
            return scan_result
            
        except Exception as e:
            scan_duration = time.time() - scan_start_time
            self.logger.error(f"Bandit scan failed: {scan_id} - {str(e)}")
            
            # Log security event
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    "security_scan_failed",
                    {
                        "scan_id": scan_id,
                        "error": str(e),
                        "scan_duration": scan_duration
                    }
                )
            
            raise SecurityScanError(f"Bandit security scan failed: {str(e)}") from e
    
    def _execute_bandit_scan(
        self,
        scan_paths: List[Path],
        baseline_path: Optional[Path] = None,
        output_format: str = "json",
        include_nosec: bool = False
    ) -> str:
        """
        Execute bandit scan with comprehensive configuration.
        
        Args:
            scan_paths: Paths to scan for security issues
            baseline_path: Optional baseline file for comparison
            output_format: Output format for results
            include_nosec: Whether to include nosec findings
            
        Returns:
            Raw bandit output as string
            
        Raises:
            SecurityScanError: When bandit execution fails
        """
        # Prepare bandit command
        bandit_cmd = ["bandit"]
        
        # Add format specification
        bandit_cmd.extend(["-f", output_format])
        
        # Add verbosity
        bandit_cmd.append("-v")
        
        # Add confidence levels
        bandit_cmd.extend(["-i", ",".join(self.confidence_levels)])
        
        # Add severity levels
        bandit_cmd.extend(["-ll"])  # Include low level findings
        
        # Add baseline if provided
        if baseline_path and baseline_path.exists():
            bandit_cmd.extend(["-b", str(baseline_path)])
        
        # Add excluded paths
        for exclude_pattern in self.bandit_config["exclude_dirs"]:
            bandit_cmd.extend(["-x", exclude_pattern])
        
        # Add specific tests if configured
        if self.bandit_config["tests"]:
            tests_str = ",".join(self.bandit_config["tests"])
            bandit_cmd.extend(["-t", tests_str])
        
        # Add skip tests if configured
        if self.bandit_config["skips"]:
            skips_str = ",".join(self.bandit_config["skips"])
            bandit_cmd.extend(["-s", skips_str])
        
        # Handle nosec comments
        if not include_nosec:
            # Default: respect # nosec comments
            pass
        else:
            # Force scan even with # nosec comments
            bandit_cmd.append("--ignore-nosec")
        
        # Add target paths
        for path in scan_paths:
            if path.is_file():
                bandit_cmd.append(str(path))
            else:
                bandit_cmd.extend(["-r", str(path)])
        
        self.logger.debug(f"Executing bandit command: {' '.join(bandit_cmd)}")
        
        try:
            # Execute bandit with timeout protection
            result = subprocess.run(
                bandit_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=self.project_root
            )
            
            # Bandit returns exit code 1 when findings are present
            # Exit code 0 = no findings, 1 = findings found, >1 = error
            if result.returncode > 1:
                error_msg = f"Bandit execution error (exit code {result.returncode}): {result.stderr}"
                raise SecurityScanError(error_msg)
            
            if not result.stdout:
                # No output typically means no findings
                return '{"results": [], "metrics": {}}'
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise SecurityScanError("Bandit scan timed out after 5 minutes")
        except FileNotFoundError:
            raise SecurityScanError("Bandit executable not found in PATH")
        except Exception as e:
            raise SecurityScanError(f"Bandit execution failed: {str(e)}") from e
    
    def _process_scan_results(self, scan_output: str, scan_id: str) -> List[SecurityFinding]:
        """
        Process bandit scan output into structured security findings.
        
        Args:
            scan_output: Raw bandit JSON output
            scan_id: Unique scan identifier
            
        Returns:
            List of processed security findings
            
        Raises:
            SecurityAnalysisError: When results cannot be parsed
        """
        try:
            # Parse JSON output
            scan_data = json.loads(scan_output)
            
            findings = []
            results = scan_data.get("results", [])
            
            for result in results:
                try:
                    # Extract finding data
                    finding = self._create_security_finding(result, scan_id)
                    findings.append(finding)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to process finding: {e}")
                    continue
            
            self.logger.info(f"Processed {len(findings)} security findings from scan")
            return findings
            
        except json.JSONDecodeError as e:
            raise SecurityAnalysisError(f"Failed to parse bandit output as JSON: {e}")
        except Exception as e:
            raise SecurityAnalysisError(f"Failed to process scan results: {e}")
    
    def _create_security_finding(self, result_data: Dict[str, Any], scan_id: str) -> SecurityFinding:
        """
        Create SecurityFinding object from bandit result data.
        
        Args:
            result_data: Individual bandit finding data
            scan_id: Associated scan identifier
            
        Returns:
            Structured SecurityFinding object
        """
        # Extract basic information
        test_name = result_data.get("test_name", "unknown")
        test_id = result_data.get("test_id", "B000")
        
        # Map bandit severity to our severity enum
        bandit_severity = result_data.get("issue_severity", "MEDIUM").upper()
        severity_mapping = {
            "LOW": SecuritySeverity.LOW,
            "MEDIUM": SecuritySeverity.MEDIUM,
            "HIGH": SecuritySeverity.HIGH,
            "CRITICAL": SecuritySeverity.CRITICAL
        }
        severity = severity_mapping.get(bandit_severity, SecuritySeverity.MEDIUM)
        
        # Extract confidence level
        confidence = result_data.get("issue_confidence", "MEDIUM").upper()
        
        # Extract location information
        filename = result_data.get("filename", "unknown")
        line_number = result_data.get("line_number", 0)
        column_number = result_data.get("col_offset", 0)
        
        # Extract code snippet
        code_snippet = result_data.get("code", "").strip()
        
        # Extract vulnerability details
        issue_text = result_data.get("issue_text", "")
        
        # Map test name to security rule category
        category = self._map_test_to_category(test_name, test_id)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity, confidence)
        
        # Generate remediation guidance
        remediation_guidance = self._generate_remediation_guidance(category, test_name)
        
        # Create security finding
        finding = SecurityFinding(
            finding_id="",  # Will be generated in __post_init__
            rule_id=test_id,
            test_name=test_name,
            category=category,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            file_path=filename,
            line_number=line_number,
            column_number=column_number,
            code_snippet=code_snippet,
            issue_text=issue_text,
            issue_description=issue_text,
            remediation_guidance=remediation_guidance,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            analyzer_version=self._get_bandit_version(),
            reporting_tags=[scan_id, "bandit", "static_analysis"]
        )
        
        return finding
    
    def _map_test_to_category(self, test_name: str, test_id: str) -> SecurityRuleCategory:
        """Map bandit test name/ID to security rule category."""
        # Mapping based on test names and IDs
        category_mapping = {
            # Hardcoded passwords and secrets
            "hardcoded_password_string": SecurityRuleCategory.HARDCODED_PASSWORD,
            "hardcoded_password_funcarg": SecurityRuleCategory.HARDCODED_PASSWORD,
            "hardcoded_password_default": SecurityRuleCategory.HARDCODED_PASSWORD,
            "hardcoded_bind_all_interfaces": SecurityRuleCategory.HARDCODED_PASSWORD,
            
            # SQL injection
            "hardcoded_sql_expressions": SecurityRuleCategory.SQL_INJECTION,
            
            # Shell injection
            "subprocess_popen_with_shell_equals_true": SecurityRuleCategory.SHELL_INJECTION,
            "subprocess_without_shell_equals_false": SecurityRuleCategory.SHELL_INJECTION,
            "start_process_with_a_shell": SecurityRuleCategory.SHELL_INJECTION,
            "start_process_with_no_shell": SecurityRuleCategory.SHELL_INJECTION,
            "start_process_with_partial_path": SecurityRuleCategory.SHELL_INJECTION,
            
            # Cryptographic issues
            "weak_cryptographic_key": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_insecure_md2_hash": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_insecure_md4_hash": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_insecure_md5_hash": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_weak_cryptographic_key": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_insecure_cipher": SecurityRuleCategory.CRYPTO_WEAK,
            "use_of_insecure_cipher_mode": SecurityRuleCategory.CRYPTO_WEAK,
            
            # Random number generation
            "standard_pseudorandom_generators": SecurityRuleCategory.RANDOM_WEAK,
            "use_of_insecure_pseudo_random_generator": SecurityRuleCategory.RANDOM_WEAK,
            
            # Input validation
            "try_except_pass": SecurityRuleCategory.INPUT_VALIDATION,
            "try_except_continue": SecurityRuleCategory.INPUT_VALIDATION,
            
            # Insecure transport
            "request_without_timeout": SecurityRuleCategory.INSECURE_TRANSPORT,
            "request_with_no_cert_validation": SecurityRuleCategory.HTTP_INSECURE,
            "use_of_http_instead_of_https": SecurityRuleCategory.INSECURE_TRANSPORT,
            
            # Path traversal
            "path_traversal": SecurityRuleCategory.PATH_TRAVERSAL,
            
            # Deserialization
            "pickle_load": SecurityRuleCategory.DESERIALIZATION,
            "use_of_insecure_deserializer": SecurityRuleCategory.DESERIALIZATION,
            
            # Code execution
            "exec_used": SecurityRuleCategory.EXEC_INJECTION,
            "use_of_eval": SecurityRuleCategory.EVAL_INJECTION,
            
            # YAML/XML vulnerabilities
            "yaml_load": SecurityRuleCategory.YAML_LOAD,
            "xml_bad_tree": SecurityRuleCategory.XML_VULNERABILITY,
            "xml_bad_etree": SecurityRuleCategory.XML_VULNERABILITY,
            "xml_bad_expatreader": SecurityRuleCategory.XML_VULNERABILITY,
            "xml_bad_minidom": SecurityRuleCategory.XML_VULNERABILITY,
            
            # LDAP injection
            "ldap_injection": SecurityRuleCategory.LDAP_INJECTION
        }
        
        # Try to match by test name first
        category = category_mapping.get(test_name.lower())
        if category:
            return category
        
        # Try to match by test ID patterns
        if test_id.startswith("B1"):
            # B1xx series - assert and password issues
            if test_id in ["B105", "B106", "B107", "B108"]:
                return SecurityRuleCategory.HARDCODED_PASSWORD
            else:
                return SecurityRuleCategory.INPUT_VALIDATION
        elif test_id.startswith("B2"):
            # B2xx series - application security
            return SecurityRuleCategory.INPUT_VALIDATION
        elif test_id.startswith("B3"):
            # B3xx series - crypto and security
            return SecurityRuleCategory.CRYPTO_WEAK
        elif test_id.startswith("B4"):
            # B4xx series - misc security
            return SecurityRuleCategory.INPUT_VALIDATION
        elif test_id.startswith("B5"):
            # B5xx series - web security
            return SecurityRuleCategory.INSECURE_TRANSPORT
        elif test_id.startswith("B6"):
            # B6xx series - injection
            return SecurityRuleCategory.SHELL_INJECTION
        elif test_id.startswith("B7"):
            # B7xx series - framework specific
            return SecurityRuleCategory.INPUT_VALIDATION
        
        # Default category
        return SecurityRuleCategory.INPUT_VALIDATION
    
    def _calculate_risk_score(self, severity: SecuritySeverity, confidence: str) -> float:
        """Calculate numerical risk score for finding prioritization."""
        severity_scores = {
            SecuritySeverity.LOW: 1.0,
            SecuritySeverity.MEDIUM: 4.0,
            SecuritySeverity.HIGH: 7.0,
            SecuritySeverity.CRITICAL: 10.0
        }
        
        confidence_multipliers = {
            "LOW": 0.3,
            "MEDIUM": 0.7,
            "HIGH": 1.0
        }
        
        base_score = severity_scores[severity]
        confidence_multiplier = confidence_multipliers.get(confidence, 0.5)
        
        return round(base_score * confidence_multiplier, 2)
    
    def _generate_remediation_guidance(self, category: SecurityRuleCategory, test_name: str) -> str:
        """Generate specific remediation guidance for security finding."""
        remediation_map = {
            SecurityRuleCategory.HARDCODED_PASSWORD: (
                "Remove hardcoded passwords and secrets. Use environment variables, "
                "configuration files, or secure secret management systems like AWS Secrets Manager."
            ),
            SecurityRuleCategory.SQL_INJECTION: (
                "Use parameterized queries or prepared statements instead of string concatenation. "
                "Validate and sanitize all user input before database operations."
            ),
            SecurityRuleCategory.SHELL_INJECTION: (
                "Avoid shell=True in subprocess calls. Use subprocess with argument lists "
                "instead of shell commands. Validate and sanitize command arguments."
            ),
            SecurityRuleCategory.CRYPTO_WEAK: (
                "Replace weak cryptographic algorithms with strong alternatives. "
                "Use AES-256 for encryption, SHA-256 or higher for hashing, and secure key generation."
            ),
            SecurityRuleCategory.RANDOM_WEAK: (
                "Replace standard random generators with cryptographically secure alternatives "
                "using secrets module for security-sensitive operations."
            ),
            SecurityRuleCategory.INPUT_VALIDATION: (
                "Implement comprehensive input validation and error handling. "
                "Use try-except blocks with specific exception handling instead of bare except."
            ),
            SecurityRuleCategory.INSECURE_TRANSPORT: (
                "Use HTTPS for all network communications. Set appropriate timeouts "
                "and enable certificate verification for requests."
            ),
            SecurityRuleCategory.PATH_TRAVERSAL: (
                "Validate file paths and prevent directory traversal attacks. "
                "Use os.path.normpath() and restrict file access to allowed directories."
            ),
            SecurityRuleCategory.DESERIALIZATION: (
                "Avoid deserializing untrusted data. Use safe serialization formats "
                "like JSON instead of pickle for external data."
            ),
            SecurityRuleCategory.EXEC_INJECTION: (
                "Remove use of exec() and eval() functions. Implement alternative approaches "
                "using safe parsing and controlled execution environments."
            ),
            SecurityRuleCategory.EVAL_INJECTION: (
                "Replace eval() with safe alternatives like ast.literal_eval() for data parsing "
                "or implement custom parsers for specific use cases."
            ),
            SecurityRuleCategory.YAML_LOAD: (
                "Use yaml.safe_load() instead of yaml.load() to prevent code execution "
                "during YAML parsing. Validate YAML structure before processing."
            ),
            SecurityRuleCategory.XML_VULNERABILITY: (
                "Use secure XML parsers with disabled external entity processing. "
                "Configure XML parsers to prevent XXE attacks and validate XML input."
            ),
            SecurityRuleCategory.LDAP_INJECTION: (
                "Sanitize LDAP queries and use parameterized LDAP operations. "
                "Validate and escape special characters in LDAP search filters."
            ),
            SecurityRuleCategory.HTTP_INSECURE: (
                "Enable SSL certificate verification for HTTP requests. "
                "Use trusted certificate authorities and validate server certificates."
            )
        }
        
        return remediation_map.get(
            category,
            "Review security finding details and implement appropriate security controls "
            "based on the specific vulnerability type and context."
        )
    
    def _calculate_scan_metrics(self, scan_paths: List[Path]) -> Dict[str, int]:
        """Calculate scan coverage metrics."""
        files_scanned = 0
        lines_scanned = 0
        
        for path in scan_paths:
            if path.is_file() and path.suffix == '.py':
                files_scanned += 1
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        lines_scanned += sum(1 for _ in f)
                except Exception:
                    pass  # Skip files that can't be read
            elif path.is_dir():
                for py_file in path.rglob('*.py'):
                    # Skip excluded directories
                    if any(exclude in str(py_file) for exclude in self.excluded_paths):
                        continue
                    
                    files_scanned += 1
                    try:
                        with open(py_file, 'r', encoding='utf-8') as f:
                            lines_scanned += sum(1 for _ in f)
                    except Exception:
                        pass  # Skip files that can't be read
        
        return {
            'files_scanned': files_scanned,
            'lines_scanned': lines_scanned
        }
    
    def _get_bandit_version(self) -> str:
        """Get bandit version string."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "unknown"
        except Exception:
            return "unknown"
    
    def create_baseline(self, output_path: Union[str, Path]) -> bool:
        """
        Create security baseline file for future comparisons.
        
        Args:
            output_path: Path where baseline file should be saved
            
        Returns:
            Success status of baseline creation
        """
        try:
            baseline_path = Path(output_path)
            
            # Execute scan to create baseline
            scan_result = self.scan_project()
            
            # Create baseline data
            baseline_data = {
                "creation_date": datetime.now(timezone.utc).isoformat(),
                "bandit_version": self._get_bandit_version(),
                "project_root": str(self.project_root),
                "findings": [finding.to_dict() for finding in scan_result.findings],
                "metrics": {
                    "total_files": scan_result.total_files_scanned,
                    "total_lines": scan_result.total_lines_scanned,
                    "finding_counts": {
                        "critical": scan_result.critical_count,
                        "high": scan_result.high_count,
                        "medium": scan_result.medium_count,
                        "low": scan_result.low_count
                    }
                }
            }
            
            # Save baseline to file
            with open(baseline_path, 'w', encoding='utf-8') as f:
                json.dump(baseline_data, f, indent=2, sort_keys=True)
            
            # Update baseline findings tracking
            self.baseline_findings = {f.finding_id for f in scan_result.findings}
            
            self.logger.info(f"Security baseline created: {baseline_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create security baseline: {e}")
            return False
    
    def compare_with_baseline(
        self,
        baseline_path: Union[str, Path],
        current_scan: Optional[BanditScanResult] = None
    ) -> Dict[str, Any]:
        """
        Compare current scan results with security baseline.
        
        Args:
            baseline_path: Path to baseline file
            current_scan: Current scan results (will scan if not provided)
            
        Returns:
            Comprehensive comparison results
        """
        try:
            baseline_file = Path(baseline_path)
            if not baseline_file.exists():
                raise FileNotFoundError(f"Baseline file not found: {baseline_file}")
            
            # Load baseline data
            with open(baseline_file, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
            
            # Get current scan results
            if current_scan is None:
                current_scan = self.scan_project()
            
            # Extract baseline findings
            baseline_findings = {
                finding_data['finding_id']: finding_data
                for finding_data in baseline_data.get('findings', [])
            }
            
            # Extract current findings
            current_findings = {
                finding.finding_id: finding.to_dict()
                for finding in current_scan.findings
            }
            
            # Perform comparison analysis
            comparison_result = {
                "baseline_info": {
                    "creation_date": baseline_data.get('creation_date'),
                    "bandit_version": baseline_data.get('bandit_version'),
                    "total_findings": len(baseline_findings)
                },
                "current_scan_info": {
                    "scan_date": current_scan.scan_timestamp,
                    "bandit_version": current_scan.analyzer_version,
                    "total_findings": len(current_findings)
                },
                "comparison_analysis": {
                    "new_findings": [],
                    "resolved_findings": [],
                    "unchanged_findings": [],
                    "modified_findings": []
                },
                "trend_analysis": {
                    "security_improvement": False,
                    "net_change": 0,
                    "severity_changes": {}
                }
            }
            
            # Identify finding changes
            baseline_ids = set(baseline_findings.keys())
            current_ids = set(current_findings.keys())
            
            # New findings (in current but not in baseline)
            new_finding_ids = current_ids - baseline_ids
            comparison_result["comparison_analysis"]["new_findings"] = [
                current_findings[fid] for fid in new_finding_ids
            ]
            
            # Resolved findings (in baseline but not in current)
            resolved_finding_ids = baseline_ids - current_ids
            comparison_result["comparison_analysis"]["resolved_findings"] = [
                baseline_findings[fid] for fid in resolved_finding_ids
            ]
            
            # Unchanged findings (in both with same severity)
            unchanged_ids = baseline_ids & current_ids
            unchanged_findings = []
            modified_findings = []
            
            for fid in unchanged_ids:
                baseline_finding = baseline_findings[fid]
                current_finding = current_findings[fid]
                
                if baseline_finding['severity'] == current_finding['severity']:
                    unchanged_findings.append(current_finding)
                else:
                    modified_findings.append({
                        'finding_id': fid,
                        'baseline_severity': baseline_finding['severity'],
                        'current_severity': current_finding['severity'],
                        'finding_details': current_finding
                    })
            
            comparison_result["comparison_analysis"]["unchanged_findings"] = unchanged_findings
            comparison_result["comparison_analysis"]["modified_findings"] = modified_findings
            
            # Calculate trend analysis
            net_change = len(new_finding_ids) - len(resolved_finding_ids)
            comparison_result["trend_analysis"]["net_change"] = net_change
            comparison_result["trend_analysis"]["security_improvement"] = net_change <= 0
            
            # Calculate severity changes
            baseline_metrics = baseline_data.get('metrics', {}).get('finding_counts', {})
            current_metrics = {
                'critical': current_scan.critical_count,
                'high': current_scan.high_count,
                'medium': current_scan.medium_count,
                'low': current_scan.low_count
            }
            
            severity_changes = {}
            for severity, current_count in current_metrics.items():
                baseline_count = baseline_metrics.get(severity, 0)
                severity_changes[severity] = {
                    'baseline': baseline_count,
                    'current': current_count,
                    'change': current_count - baseline_count
                }
            
            comparison_result["trend_analysis"]["severity_changes"] = severity_changes
            
            self.logger.info(
                f"Baseline comparison completed: {len(new_finding_ids)} new, "
                f"{len(resolved_finding_ids)} resolved, {len(unchanged_ids)} unchanged"
            )
            
            return comparison_result
            
        except Exception as e:
            self.logger.error(f"Baseline comparison failed: {e}")
            raise SecurityAnalysisError(f"Failed to compare with baseline: {e}")
    
    def generate_security_report(
        self,
        scan_result: BanditScanResult,
        output_path: Union[str, Path],
        report_format: str = "json",
        include_remediation: bool = True
    ) -> bool:
        """
        Generate comprehensive security report from scan results.
        
        Args:
            scan_result: Scan results to generate report from
            output_path: Path where report should be saved
            report_format: Report format (json, html, markdown)
            include_remediation: Whether to include remediation guidance
            
        Returns:
            Success status of report generation
        """
        try:
            report_path = Path(output_path)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            
            if report_format.lower() == "json":
                report_data = self._generate_json_report(scan_result, include_remediation)
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, sort_keys=True)
                    
            elif report_format.lower() == "html":
                report_html = self._generate_html_report(scan_result, include_remediation)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report_html)
                    
            elif report_format.lower() == "markdown":
                report_md = self._generate_markdown_report(scan_result, include_remediation)
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report_md)
                    
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
            
            self.logger.info(f"Security report generated: {report_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate security report: {e}")
            return False
    
    def _generate_json_report(self, scan_result: BanditScanResult, include_remediation: bool) -> Dict[str, Any]:
        """Generate comprehensive JSON security report."""
        report_data = {
            "report_metadata": {
                "generation_time": datetime.now(timezone.utc).isoformat(),
                "report_version": "1.0",
                "scanner": "bandit",
                "analyzer_version": scan_result.analyzer_version
            },
            "scan_summary": {
                "scan_id": scan_result.scan_id,
                "scan_timestamp": scan_result.scan_timestamp,
                "scan_duration": scan_result.scan_duration,
                "security_score": scan_result.get_security_score(),
                "deployment_ready": scan_result.is_deployment_ready(),
                "compliance_status": scan_result.compliance_status
            },
            "coverage_metrics": {
                "files_scanned": scan_result.total_files_scanned,
                "lines_scanned": scan_result.total_lines_scanned,
                "target_paths": scan_result.target_paths,
                "excluded_paths": scan_result.excluded_paths
            },
            "security_findings": {
                "total_findings": len(scan_result.findings),
                "severity_breakdown": {
                    "critical": scan_result.critical_count,
                    "high": scan_result.high_count,
                    "medium": scan_result.medium_count,
                    "low": scan_result.low_count
                },
                "blocking_findings": len(scan_result.blocking_findings),
                "priority_findings": len(scan_result.priority_findings)
            },
            "compliance_assessment": {
                "compliance_violations": scan_result.compliance_violations,
                "estimated_remediation_time": scan_result.estimated_remediation_time,
                "affected_frameworks": list(set(
                    impact for finding in scan_result.findings
                    for impact in finding.compliance_impact
                ))
            },
            "detailed_findings": [
                finding.to_dict() for finding in scan_result.findings
            ]
        }
        
        if include_remediation:
            report_data["remediation_guidance"] = {
                "priority_actions": [
                    {
                        "finding_id": f.finding_id,
                        "severity": f.severity.value,
                        "category": f.category.value,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "remediation": f.remediation_guidance,
                        "estimated_time": f.estimated_fix_time or "2-4 hours"
                    }
                    for f in scan_result.priority_findings
                ],
                "remediation_summary": {
                    "immediate_actions": len([
                        f for f in scan_result.findings
                        if f.severity == SecuritySeverity.CRITICAL
                    ]),
                    "short_term_actions": len([
                        f for f in scan_result.findings
                        if f.severity == SecuritySeverity.HIGH
                    ]),
                    "medium_term_actions": len([
                        f for f in scan_result.findings
                        if f.severity == SecuritySeverity.MEDIUM
                    ])
                }
            }
        
        return report_data
    
    def _generate_html_report(self, scan_result: BanditScanResult, include_remediation: bool) -> str:
        """Generate HTML security report."""
        # Basic HTML report template
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bandit Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; font-weight: bold; }}
        .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #dee2e6; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Bandit Security Analysis Report</h1>
        <p><strong>Scan ID:</strong> {scan_result.scan_id}</p>
        <p><strong>Scan Date:</strong> {scan_result.scan_timestamp}</p>
        <p><strong>Security Score:</strong> {scan_result.get_security_score()}/100</p>
        <p><strong>Deployment Ready:</strong> {"✅ Yes" if scan_result.is_deployment_ready() else "❌ No"}</p>
    </div>
    
    <div class="summary">
        <h2>Security Summary</h2>
        <p><span class="critical">Critical: {scan_result.critical_count}</span> | 
           <span class="high">High: {scan_result.high_count}</span> | 
           <span class="medium">Medium: {scan_result.medium_count}</span> | 
           <span class="low">Low: {scan_result.low_count}</span></p>
        <p><strong>Total Findings:</strong> {len(scan_result.findings)}</p>
        <p><strong>Files Scanned:</strong> {scan_result.total_files_scanned}</p>
        <p><strong>Blocking Findings:</strong> {len(scan_result.blocking_findings)}</p>
    </div>
"""
        
        # Add findings details
        if scan_result.findings:
            html_template += "<h2>Security Findings</h2>"
            for finding in scan_result.findings:
                severity_class = finding.severity.value.lower()
                html_template += f"""
    <div class="finding {severity_class}">
        <h3>{finding.test_name} ({finding.severity.value})</h3>
        <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
        <p><strong>Issue:</strong> {finding.issue_text}</p>
        <p><strong>Rule ID:</strong> {finding.rule_id}</p>
        <p><strong>Confidence:</strong> {finding.confidence}</p>
"""
                if include_remediation and finding.remediation_guidance:
                    html_template += f"<p><strong>Remediation:</strong> {finding.remediation_guidance}</p>"
                
                html_template += "</div>"
        
        html_template += """
</body>
</html>
"""
        return html_template
    
    def _generate_markdown_report(self, scan_result: BanditScanResult, include_remediation: bool) -> str:
        """Generate Markdown security report."""
        report_md = f"""# Bandit Security Analysis Report

## Scan Summary

- **Scan ID:** {scan_result.scan_id}
- **Scan Date:** {scan_result.scan_timestamp}
- **Scanner Version:** {scan_result.analyzer_version}
- **Security Score:** {scan_result.get_security_score()}/100
- **Deployment Ready:** {"✅ Yes" if scan_result.is_deployment_ready() else "❌ No"}

## Security Findings Overview

| Severity | Count |
|----------|-------|
| Critical | {scan_result.critical_count} |
| High     | {scan_result.high_count} |
| Medium   | {scan_result.medium_count} |
| Low      | {scan_result.low_count} |
| **Total** | **{len(scan_result.findings)}** |

## Scan Coverage

- **Files Scanned:** {scan_result.total_files_scanned}
- **Lines Scanned:** {scan_result.total_lines_scanned}
- **Blocking Findings:** {len(scan_result.blocking_findings)}
- **Priority Findings:** {len(scan_result.priority_findings)}

"""
        
        # Add detailed findings
        if scan_result.findings:
            report_md += "## Detailed Findings\n\n"
            
            for i, finding in enumerate(scan_result.findings, 1):
                severity_emoji = {
                    SecuritySeverity.CRITICAL: "🔴",
                    SecuritySeverity.HIGH: "🟠", 
                    SecuritySeverity.MEDIUM: "🟡",
                    SecuritySeverity.LOW: "🟢"
                }
                
                report_md += f"""### {i}. {finding.test_name} {severity_emoji[finding.severity]}

- **Severity:** {finding.severity.value}
- **Confidence:** {finding.confidence}
- **File:** `{finding.file_path}:{finding.line_number}`
- **Rule ID:** {finding.rule_id}
- **Issue:** {finding.issue_text}

"""
                if include_remediation and finding.remediation_guidance:
                    report_md += f"**Remediation:** {finding.remediation_guidance}\n\n"
                
                report_md += "---\n\n"
        
        return report_md
    
    def is_deployment_ready(self, scan_result: Optional[BanditScanResult] = None) -> Tuple[bool, List[str]]:
        """
        Determine if codebase is ready for deployment based on security scan.
        
        Args:
            scan_result: Scan results to evaluate (will scan if not provided)
            
        Returns:
            Tuple of (deployment_ready, blocking_reasons)
        """
        if scan_result is None:
            scan_result = self.scan_project()
        
        blocking_reasons = []
        
        # Check for critical findings
        if scan_result.critical_count > 0:
            blocking_reasons.append(
                f"{scan_result.critical_count} critical security vulnerabilities found"
            )
        
        # Check for high severity findings
        if scan_result.high_count > 0:
            blocking_reasons.append(
                f"{scan_result.high_count} high severity security vulnerabilities found"
            )
        
        # Check compliance violations
        if scan_result.compliance_violations:
            blocking_reasons.append(
                f"Compliance violations: {', '.join(scan_result.compliance_violations)}"
            )
        
        # Check for specific blocking rule violations
        blocking_rules = [
            SecurityRuleCategory.HARDCODED_PASSWORD,
            SecurityRuleCategory.SQL_INJECTION,
            SecurityRuleCategory.SHELL_INJECTION,
            SecurityRuleCategory.EXEC_INJECTION,
            SecurityRuleCategory.EVAL_INJECTION,
            SecurityRuleCategory.CRYPTO_WEAK
        ]
        
        for finding in scan_result.findings:
            if (finding.category in blocking_rules and 
                finding.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH] and
                not finding.false_positive):
                blocking_reasons.append(
                    f"Blocking security rule violation: {finding.category.value} in {finding.file_path}"
                )
        
        deployment_ready = len(blocking_reasons) == 0
        
        # Log deployment readiness assessment
        if self.security_monitor:
            self.security_monitor.log_security_event(
                "deployment_readiness_assessment",
                {
                    "scan_id": scan_result.scan_id,
                    "deployment_ready": deployment_ready,
                    "blocking_reasons": blocking_reasons,
                    "security_score": scan_result.get_security_score()
                }
            )
        
        return deployment_ready, blocking_reasons


# Custom exception classes
class SecurityScanError(Exception):
    """Exception raised when security scan execution fails."""
    pass


class SecurityAnalysisError(Exception):
    """Exception raised when security analysis processing fails."""
    pass


# Utility functions for CI/CD integration
def run_security_gate(
    project_root: Union[str, Path],
    fail_on_high: bool = True,
    fail_on_medium: bool = False,
    output_report: Optional[Union[str, Path]] = None
) -> bool:
    """
    Execute security gate for CI/CD pipeline integration.
    
    Args:
        project_root: Project root directory to scan
        fail_on_high: Whether to fail on high severity findings
        fail_on_medium: Whether to fail on medium severity findings
        output_report: Optional path to save detailed report
        
    Returns:
        Success status (True = pass, False = fail)
    """
    try:
        # Initialize analyzer
        analyzer = BanditSecurityAnalyzer(project_root)
        
        # Execute scan
        scan_result = analyzer.scan_project()
        
        # Assess deployment readiness
        deployment_ready, blocking_reasons = analyzer.is_deployment_ready(scan_result)
        
        # Apply additional failure criteria
        if fail_on_high and scan_result.high_count > 0:
            deployment_ready = False
            blocking_reasons.append(f"High severity findings not allowed: {scan_result.high_count} found")
        
        if fail_on_medium and scan_result.medium_count > 0:
            deployment_ready = False
            blocking_reasons.append(f"Medium severity findings not allowed: {scan_result.medium_count} found")
        
        # Generate report if requested
        if output_report:
            analyzer.generate_security_report(scan_result, output_report, "json", True)
        
        # Log results
        logger.info(f"Security gate assessment: {'PASS' if deployment_ready else 'FAIL'}")
        if blocking_reasons:
            logger.warning(f"Blocking reasons: {'; '.join(blocking_reasons)}")
        
        return deployment_ready
        
    except Exception as e:
        logger.error(f"Security gate execution failed: {e}")
        return False


def main():
    """
    Main entry point for command-line execution.
    
    Provides command-line interface for bandit security analysis with
    comprehensive reporting and CI/CD integration capabilities.
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Bandit Security Analysis Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bandit_analysis.py /path/to/project
  python bandit_analysis.py /path/to/project --report security_report.json
  python bandit_analysis.py /path/to/project --fail-on-high --fail-on-medium
  python bandit_analysis.py /path/to/project --baseline baseline.json --compare
        """
    )
    
    parser.add_argument(
        "project_root",
        help="Root directory of project to scan"
    )
    
    parser.add_argument(
        "--config",
        help="Path to bandit configuration file"
    )
    
    parser.add_argument(
        "--report",
        help="Path to save security report"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown"],
        default="json",
        help="Report format (default: json)"
    )
    
    parser.add_argument(
        "--baseline",
        help="Path to baseline file for comparison"
    )
    
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="Create new baseline file"
    )
    
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare results with baseline"
    )
    
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Fail if high severity findings are found"
    )
    
    parser.add_argument(
        "--fail-on-medium",
        action="store_true",
        help="Fail if medium severity findings are found"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize analyzer
        analyzer = BanditSecurityAnalyzer(
            project_root=args.project_root,
            config_path=args.config
        )
        
        if args.create_baseline:
            # Create baseline
            if not args.baseline:
                print("Error: --baseline path required when creating baseline")
                sys.exit(1)
            
            success = analyzer.create_baseline(args.baseline)
            if success:
                print(f"Baseline created: {args.baseline}")
                sys.exit(0)
            else:
                print("Failed to create baseline")
                sys.exit(1)
        
        # Execute scan
        scan_result = analyzer.scan_project()
        
        # Compare with baseline if requested
        if args.compare and args.baseline:
            comparison = analyzer.compare_with_baseline(args.baseline, scan_result)
            print(f"Baseline comparison: {comparison['trend_analysis']['net_change']} net change")
        
        # Generate report if requested
        if args.report:
            success = analyzer.generate_security_report(
                scan_result, args.report, args.format, True
            )
            if success:
                print(f"Security report saved: {args.report}")
        
        # Assess deployment readiness
        deployment_ready, blocking_reasons = analyzer.is_deployment_ready(scan_result)
        
        # Apply command-line failure criteria
        if args.fail_on_high and scan_result.high_count > 0:
            deployment_ready = False
            blocking_reasons.append(f"High severity findings: {scan_result.high_count}")
        
        if args.fail_on_medium and scan_result.medium_count > 0:
            deployment_ready = False
            blocking_reasons.append(f"Medium severity findings: {scan_result.medium_count}")
        
        # Display results
        print(f"Security Scan Results:")
        print(f"  Critical: {scan_result.critical_count}")
        print(f"  High: {scan_result.high_count}")
        print(f"  Medium: {scan_result.medium_count}")
        print(f"  Low: {scan_result.low_count}")
        print(f"  Security Score: {scan_result.get_security_score()}/100")
        print(f"  Deployment Ready: {'Yes' if deployment_ready else 'No'}")
        
        if blocking_reasons:
            print(f"Blocking Issues:")
            for reason in blocking_reasons:
                print(f"  - {reason}")
        
        # Exit with appropriate code
        sys.exit(0 if deployment_ready else 1)
        
    except Exception as e:
        print(f"Security analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()