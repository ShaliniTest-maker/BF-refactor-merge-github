"""
Security Report Generator implementing comprehensive security findings consolidation, compliance reporting,
and executive dashboard integration with detailed security metrics collection and trend analysis.

This module implements enterprise-grade security reporting automation per Section 6.6.2 and Section 6.4.6,
providing consolidated security findings from all security testing tools, compliance dashboard visualization,
and comprehensive security posture tracking for executive-level security oversight.

Key Features:
- Consolidated security findings reporting from bandit, safety, vulnerability scanners per Section 6.6.2
- Compliance reporting with dashboard visualization per Section 6.4.6
- Security metrics collection and trend analysis per Section 6.6.3
- Executive security posture visualization per Section 6.4.6
- Integration with Prometheus metrics and structlog audit logging per Section 6.5
- Automated security report generation for CI/CD pipeline integration
- Historical trend tracking and security posture improvement monitoring
- Enterprise security operations center (SOC) integration capabilities

Dependencies Integration:
- Integrates with bandit_analysis.py for static application security testing (SAST) results
- Processes safety_scan.py dependency vulnerability findings
- Consolidates vulnerability_scanner.py dynamic security test results
- Utilizes conftest.py security testing infrastructure for comprehensive analysis
- Integrates with Flask-Talisman security header enforcement validation
- Processes Auth0 security integration test results and JWT validation findings

Architecture:
- Multi-layered security data collection from testing tools and monitoring systems
- Structured report generation with JSON formatting and enterprise integration
- Real-time security metrics collection with Prometheus integration
- Executive dashboard data preparation with visualization-ready formats
- Compliance framework mapping with automated compliance status tracking
- Trend analysis engine with historical data correlation and predictive insights
"""

import asyncio
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set
import logging
import hashlib
import base64

# Third-party imports for enterprise integration
import requests
import redis
from prometheus_client import Counter as PrometheusCounter, Gauge, Histogram, generate_latest
import structlog

# Flask and testing framework imports
from flask import Flask, current_app
from flask.testing import FlaskClient

# Security testing infrastructure imports
try:
    from tests.security.conftest import (
        SecurityMonitor, AttackSimulator, PenetrationTestSuite,
        SecurityMetricsCollector, SecurityTestConfig, TalismanValidator
    )
except ImportError:
    # Graceful fallback for missing dependencies
    SecurityMonitor = SecurityMetricsCollector = None
    SecurityTestConfig = PenetrationTestSuite = None

# Configure structured logging for security reporting
logger = structlog.get_logger("security.reporting")

# Prometheus metrics for security reporting
SECURITY_FINDINGS_TOTAL = PrometheusCounter(
    'security_findings_total',
    'Total security findings by tool and severity',
    ['tool', 'severity', 'category']
)

COMPLIANCE_SCORE_GAUGE = Gauge(
    'security_compliance_score',
    'Security compliance score by framework',
    ['framework', 'component']
)

SECURITY_SCAN_DURATION = Histogram(
    'security_scan_duration_seconds',
    'Duration of security scans by tool',
    ['tool', 'scan_type']
)

VULNERABILITY_AGE_DAYS = Histogram(
    'security_vulnerability_age_days',
    'Age of open vulnerabilities in days',
    ['severity', 'category', 'tool']
)

SECURITY_POSTURE_SCORE = Gauge(
    'security_posture_score',
    'Overall security posture score',
    ['component', 'assessment_type']
)

class SecuritySeverity:
    """Security severity classification constants aligned with enterprise standards."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    ALL_SEVERITIES = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
    
    @classmethod
    def get_numeric_score(cls, severity: str) -> int:
        """Convert severity to numeric score for calculations."""
        severity_scores = {
            cls.CRITICAL: 100,
            cls.HIGH: 75,
            cls.MEDIUM: 50,
            cls.LOW: 25,
            cls.INFO: 5
        }
        return severity_scores.get(severity.lower(), 0)


class SecurityComplianceFramework:
    """Security compliance framework constants and mapping."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    OWASP_TOP10 = "owasp_top10"
    NIST_CSF = "nist_csf"
    
    ALL_FRAMEWORKS = [SOC2, ISO27001, PCI_DSS, GDPR, OWASP_TOP10, NIST_CSF]
    
    @classmethod
    def get_framework_requirements(cls, framework: str) -> Dict[str, Any]:
        """Get compliance requirements for specific framework."""
        requirements = {
            cls.SOC2: {
                "controls": ["access_control", "data_protection", "audit_logging"],
                "threshold": 95,
                "critical_controls": ["authentication", "authorization", "data_encryption"]
            },
            cls.ISO27001: {
                "controls": ["risk_management", "security_policies", "incident_response"],
                "threshold": 90,
                "critical_controls": ["information_security", "access_management"]
            },
            cls.OWASP_TOP10: {
                "controls": ["injection", "broken_auth", "sensitive_data", "xss", "broken_access"],
                "threshold": 100,
                "critical_controls": ["sql_injection", "xss", "broken_authentication"]
            },
            cls.PCI_DSS: {
                "controls": ["network_security", "data_protection", "access_control"],
                "threshold": 100,
                "critical_controls": ["encryption", "access_control", "monitoring"]
            }
        }
        return requirements.get(framework, {})


class SecurityReportFormat:
    """Security report format constants and utilities."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    PROMETHEUS = "prometheus"
    
    @classmethod
    def get_content_type(cls, format_type: str) -> str:
        """Get content type for report format."""
        content_types = {
            cls.JSON: "application/json",
            cls.HTML: "text/html",
            cls.PDF: "application/pdf",
            cls.CSV: "text/csv",
            cls.PROMETHEUS: "text/plain"
        }
        return content_types.get(format_type, "application/octet-stream")


class SecurityFinding:
    """Represents a single security finding with enterprise metadata."""
    
    def __init__(
        self,
        finding_id: str,
        tool: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        location: str,
        recommendation: str,
        cve_ids: Optional[List[str]] = None,
        compliance_frameworks: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        additional_metadata: Optional[Dict[str, Any]] = None
    ):
        self.finding_id = finding_id
        self.tool = tool
        self.severity = severity.lower()
        self.category = category
        self.title = title
        self.description = description
        self.location = location
        self.recommendation = recommendation
        self.cve_ids = cve_ids or []
        self.compliance_frameworks = compliance_frameworks or []
        self.first_seen = first_seen or datetime.now(timezone.utc)
        self.last_seen = last_seen or datetime.now(timezone.utc)
        self.additional_metadata = additional_metadata or {}
        
        # Calculate age and risk score
        self.age_days = (datetime.now(timezone.utc) - self.first_seen).days
        self.risk_score = self._calculate_risk_score()
    
    def _calculate_risk_score(self) -> float:
        """Calculate risk score based on severity, age, and CVE presence."""
        base_score = SecuritySeverity.get_numeric_score(self.severity)
        
        # Age factor (older vulnerabilities increase risk)
        age_factor = min(1.5, 1.0 + (self.age_days / 100))
        
        # CVE factor (presence of CVE IDs increases risk)
        cve_factor = 1.2 if self.cve_ids else 1.0
        
        # Compliance factor (affects compliance frameworks)
        compliance_factor = 1.3 if self.compliance_frameworks else 1.0
        
        return round(base_score * age_factor * cve_factor * compliance_factor, 2)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "tool": self.tool,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "recommendation": self.recommendation,
            "cve_ids": self.cve_ids,
            "compliance_frameworks": self.compliance_frameworks,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "age_days": self.age_days,
            "risk_score": self.risk_score,
            "additional_metadata": self.additional_metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create SecurityFinding from dictionary."""
        return cls(
            finding_id=data["finding_id"],
            tool=data["tool"],
            severity=data["severity"],
            category=data["category"],
            title=data["title"],
            description=data["description"],
            location=data["location"],
            recommendation=data["recommendation"],
            cve_ids=data.get("cve_ids", []),
            compliance_frameworks=data.get("compliance_frameworks", []),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            additional_metadata=data.get("additional_metadata", {})
        )


class SecurityTrendData:
    """Security trend analysis data structure for historical tracking."""
    
    def __init__(self):
        self.timestamp = datetime.now(timezone.utc)
        self.findings_by_severity = defaultdict(int)
        self.findings_by_tool = defaultdict(int)
        self.findings_by_category = defaultdict(int)
        self.compliance_scores = {}
        self.security_posture_score = 0.0
        self.vulnerability_count = 0
        self.remediation_rate = 0.0
        self.mean_time_to_remediation = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert trend data to dictionary for storage."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_tool": dict(self.findings_by_tool),
            "findings_by_category": dict(self.findings_by_category),
            "compliance_scores": self.compliance_scores,
            "security_posture_score": self.security_posture_score,
            "vulnerability_count": self.vulnerability_count,
            "remediation_rate": self.remediation_rate,
            "mean_time_to_remediation": self.mean_time_to_remediation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityTrendData':
        """Create SecurityTrendData from dictionary."""
        trend = cls()
        trend.timestamp = datetime.fromisoformat(data["timestamp"])
        trend.findings_by_severity = defaultdict(int, data["findings_by_severity"])
        trend.findings_by_tool = defaultdict(int, data["findings_by_tool"])
        trend.findings_by_category = defaultdict(int, data["findings_by_category"])
        trend.compliance_scores = data["compliance_scores"]
        trend.security_posture_score = data["security_posture_score"]
        trend.vulnerability_count = data["vulnerability_count"]
        trend.remediation_rate = data["remediation_rate"]
        trend.mean_time_to_remediation = data["mean_time_to_remediation"]
        return trend


class SecurityToolAdapter:
    """Base adapter for integrating with security tools."""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.logger = structlog.get_logger(f"security.adapter.{tool_name}")
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect security findings from the tool. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement collect_findings")
    
    def _generate_finding_id(self, content: str) -> str:
        """Generate unique finding ID based on content."""
        return hashlib.sha256(f"{self.tool_name}:{content}".encode()).hexdigest()[:16]


class BanditAdapter(SecurityToolAdapter):
    """Adapter for integrating with Bandit SAST tool per Section 6.4.5."""
    
    def __init__(self):
        super().__init__("bandit")
        self.bandit_command = ["bandit", "-r", ".", "-f", "json"]
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect Bandit SAST findings."""
        try:
            # Run bandit security analysis
            result = subprocess.run(
                self.bandit_command,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path.cwd()
            )
            
            if result.returncode not in [0, 1]:  # 1 = findings found
                self.logger.error(f"Bandit execution failed: {result.stderr}")
                return []
            
            # Parse bandit JSON output
            try:
                bandit_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                self.logger.error("Failed to parse Bandit JSON output")
                return []
            
            findings = []
            for issue in bandit_data.get("results", []):
                finding = SecurityFinding(
                    finding_id=self._generate_finding_id(
                        f"{issue['filename']}:{issue['line_number']}:{issue['test_id']}"
                    ),
                    tool=self.tool_name,
                    severity=issue["issue_severity"].lower(),
                    category="sast",
                    title=f"Bandit {issue['test_id']}: {issue['issue_text']}",
                    description=issue["issue_text"],
                    location=f"{issue['filename']}:{issue['line_number']}",
                    recommendation=self._get_bandit_recommendation(issue["test_id"]),
                    compliance_frameworks=["owasp_top10", "soc2"],
                    additional_metadata={
                        "test_id": issue["test_id"],
                        "confidence": issue["issue_confidence"],
                        "line_range": issue.get("line_range", []),
                        "code": issue.get("code", "")
                    }
                )
                findings.append(finding)
            
            self.logger.info(f"Collected {len(findings)} findings from Bandit")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error("Bandit execution timed out")
            return []
        except Exception as e:
            self.logger.error(f"Error collecting Bandit findings: {str(e)}")
            return []
    
    def _get_bandit_recommendation(self, test_id: str) -> str:
        """Get remediation recommendation for Bandit test ID."""
        recommendations = {
            "B101": "Remove or replace assert statements in production code",
            "B102": "Use subprocess with shell=False or validate input thoroughly",
            "B103": "Set file permissions explicitly using os.chmod",
            "B104": "Bind to specific interfaces instead of 0.0.0.0",
            "B105": "Use secrets.token_hex() for cryptographic tokens",
            "B106": "Use secrets.token_hex() for passwords and tokens",
            "B107": "Use subprocess with shell=False or validate input",
            "B108": "Add exception handling for temporary files",
            "B110": "Handle all exception types explicitly",
            "B112": "Add rate limiting or timeout to prevent DoS",
            "B201": "Use parameterized queries to prevent SQL injection",
            "B301": "Use pickle.loads() only with trusted data",
            "B302": "Use safer marshalling alternatives",
            "B303": "Use hashlib with explicit algorithms",
            "B304": "Use cryptographically secure ciphers",
            "B305": "Use cryptographically secure ciphers",
            "B306": "Use os.path.join() for file paths",
            "B307": "Use subprocess with shell=False",
            "B308": "Replace MD5 with SHA-256 or stronger",
            "B309": "Use HTTPSConnection for secure communications",
            "B310": "Use urllib.parse.quote() for URL encoding",
            "B311": "Use secrets module for random values",
            "B312": "Use secrets.token_hex() for random strings",
            "B313": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B314": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B315": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B316": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B317": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B318": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B319": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B320": "Use xml.etree.ElementTree.XMLParser with secure settings",
            "B321": "Use ftplib with explicit TLS",
            "B322": "Validate input before passing to system commands",
            "B323": "Set secure umask before creating temporary files",
            "B324": "Use hashlib with explicit algorithms",
            "B325": "Use os.urandom() for random bytes",
            "B401": "Import telnetlib only when necessary",
            "B402": "Replace ftplib with secure alternatives",
            "B403": "Import pickle only when necessary and with trusted data",
            "B404": "Import subprocess carefully",
            "B405": "Import xml modules with secure configurations",
            "B406": "Import mktemp only when necessary",
            "B407": "Import xml.sax with secure configurations",
            "B408": "Import xml.dom.minidom with secure configurations",
            "B409": "Import xml.etree with secure configurations",
            "B410": "Import lxml with secure configurations",
            "B411": "Import xmlrpclib with secure configurations",
            "B412": "Import httpoxy with secure configurations",
            "B413": "Import pycrypto only when necessary",
            "B501": "Use ssl.create_default_context()",
            "B502": "Use ssl.create_default_context()",
            "B503": "Use ssl.create_default_context()",
            "B504": "Use ssl.create_default_context()",
            "B505": "Use cryptographically secure ciphers",
            "B506": "Use parameterized YAML loading",
            "B507": "Use parameterized YAML loading",
            "B601": "Replace shell=True with shell=False",
            "B602": "Replace shell=True with shell=False",
            "B603": "Validate subprocess arguments",
            "B604": "Validate subprocess arguments",
            "B605": "Replace os.system() with subprocess",
            "B606": "Replace os.popen() with subprocess",
            "B607": "Validate partial paths in subprocess calls",
            "B608": "Use parameterized SQL queries",
            "B609": "Use secure wildcard matching",
            "B610": "Use parameterized Django queries",
            "B611": "Use parameterized Django queries",
            "B701": "Use jinja2.select_autoescape()",
            "B702": "Use secure test framework configuration",
            "B703": "Use secure Django settings"
        }
        return recommendations.get(test_id, "Follow security best practices for this issue")


class SafetyAdapter(SecurityToolAdapter):
    """Adapter for integrating with Safety dependency vulnerability scanner."""
    
    def __init__(self):
        super().__init__("safety")
        self.safety_command = ["safety", "check", "--json"]
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect Safety dependency vulnerability findings."""
        try:
            # Run safety vulnerability check
            result = subprocess.run(
                self.safety_command,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=Path.cwd()
            )
            
            if result.returncode not in [0, 64]:  # 64 = vulnerabilities found
                self.logger.error(f"Safety execution failed: {result.stderr}")
                return []
            
            # Parse safety JSON output
            try:
                safety_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                self.logger.error("Failed to parse Safety JSON output")
                return []
            
            findings = []
            for vuln in safety_data:
                finding = SecurityFinding(
                    finding_id=self._generate_finding_id(
                        f"{vuln['package']}:{vuln['id']}"
                    ),
                    tool=self.tool_name,
                    severity=self._map_safety_severity(vuln.get("severity", "medium")),
                    category="dependency_vulnerability",
                    title=f"Vulnerable dependency: {vuln['package']} {vuln['installed_version']}",
                    description=vuln["vulnerability"],
                    location=f"Package: {vuln['package']} {vuln['installed_version']}",
                    recommendation=f"Upgrade to {vuln['package']} >= {vuln.get('safe_version', 'latest')}",
                    cve_ids=[vuln.get("cve", "").replace("CVE-", "CVE-")] if vuln.get("cve") else [],
                    compliance_frameworks=["soc2", "iso27001"],
                    additional_metadata={
                        "package": vuln["package"],
                        "installed_version": vuln["installed_version"],
                        "safe_version": vuln.get("safe_version"),
                        "vulnerability_id": vuln["id"],
                        "more_info_url": vuln.get("more_info_url")
                    }
                )
                findings.append(finding)
            
            self.logger.info(f"Collected {len(findings)} findings from Safety")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error("Safety execution timed out")
            return []
        except Exception as e:
            self.logger.error(f"Error collecting Safety findings: {str(e)}")
            return []
    
    def _map_safety_severity(self, safety_severity: str) -> str:
        """Map Safety severity to standard severity levels."""
        severity_mapping = {
            "critical": SecuritySeverity.CRITICAL,
            "high": SecuritySeverity.HIGH,
            "medium": SecuritySeverity.MEDIUM,
            "low": SecuritySeverity.LOW
        }
        return severity_mapping.get(safety_severity.lower(), SecuritySeverity.MEDIUM)


class VulnerabilityAdapter(SecurityToolAdapter):
    """Adapter for integrating with custom vulnerability scanner."""
    
    def __init__(self):
        super().__init__("vulnerability_scanner")
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect custom vulnerability scanner findings."""
        try:
            # Import and run vulnerability scanner if available
            try:
                from tests.security.vulnerability_scanner import VulnerabilityScanner
                scanner = VulnerabilityScanner()
                scan_results = await scanner.run_comprehensive_scan()
            except ImportError:
                self.logger.warning("Vulnerability scanner module not available")
                return []
            
            findings = []
            for result in scan_results.get("vulnerabilities", []):
                finding = SecurityFinding(
                    finding_id=self._generate_finding_id(
                        f"{result['type']}:{result.get('endpoint', 'unknown')}"
                    ),
                    tool=self.tool_name,
                    severity=result.get("severity", "medium").lower(),
                    category=result.get("category", "web_vulnerability"),
                    title=result["title"],
                    description=result["description"],
                    location=result.get("endpoint", "Application"),
                    recommendation=result.get("recommendation", "Review and remediate vulnerability"),
                    cve_ids=result.get("cve_ids", []),
                    compliance_frameworks=result.get("compliance_frameworks", ["owasp_top10"]),
                    additional_metadata=result.get("metadata", {})
                )
                findings.append(finding)
            
            self.logger.info(f"Collected {len(findings)} findings from vulnerability scanner")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error collecting vulnerability scanner findings: {str(e)}")
            return []


class TalismanSecurityAdapter(SecurityToolAdapter):
    """Adapter for Flask-Talisman security header validation per Section 6.4.1."""
    
    def __init__(self, app: Flask = None):
        super().__init__("flask_talisman")
        self.app = app
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect Flask-Talisman security header findings."""
        try:
            if not self.app:
                self.logger.warning("Flask app not available for Talisman validation")
                return []
            
            # Use TalismanValidator from conftest if available
            if TalismanValidator:
                validator = TalismanValidator(self.app)
                
                # Test security headers on key endpoints
                endpoints_to_test = [
                    "/", "/api/health", "/api/login", "/api/users"
                ]
                
                findings = []
                with self.app.test_client() as client:
                    for endpoint in endpoints_to_test:
                        try:
                            response = client.get(endpoint)
                            validation_results = validator.validate_security_headers(response)
                            
                            # Check for missing or non-compliant headers
                            for header, result in validation_results["headers_validated"].items():
                                if not result["present"]:
                                    finding = SecurityFinding(
                                        finding_id=self._generate_finding_id(f"missing_header:{endpoint}:{header}"),
                                        tool=self.tool_name,
                                        severity=SecuritySeverity.MEDIUM,
                                        category="security_headers",
                                        title=f"Missing security header: {header}",
                                        description=f"Security header {header} is missing from response on {endpoint}",
                                        location=f"Endpoint: {endpoint}",
                                        recommendation=f"Configure Flask-Talisman to include {header} header",
                                        compliance_frameworks=["owasp_top10", "soc2"],
                                        additional_metadata={
                                            "endpoint": endpoint,
                                            "header": header,
                                            "compliance_score": validation_results.get("compliance_score", 0)
                                        }
                                    )
                                    findings.append(finding)
                                elif not result["compliant"]:
                                    finding = SecurityFinding(
                                        finding_id=self._generate_finding_id(f"invalid_header:{endpoint}:{header}"),
                                        tool=self.tool_name,
                                        severity=SecuritySeverity.LOW,
                                        category="security_headers",
                                        title=f"Non-compliant security header: {header}",
                                        description=f"Security header {header} value is not compliant: {result['value']}",
                                        location=f"Endpoint: {endpoint}",
                                        recommendation=f"Update Flask-Talisman configuration for {header} header",
                                        compliance_frameworks=["owasp_top10", "soc2"],
                                        additional_metadata={
                                            "endpoint": endpoint,
                                            "header": header,
                                            "current_value": result["value"],
                                            "compliance_score": validation_results.get("compliance_score", 0)
                                        }
                                    )
                                    findings.append(finding)
                        except Exception as e:
                            self.logger.warning(f"Error testing endpoint {endpoint}: {str(e)}")
                            continue
                
                self.logger.info(f"Collected {len(findings)} Talisman security header findings")
                return findings
            else:
                self.logger.warning("TalismanValidator not available")
                return []
                
        except Exception as e:
            self.logger.error(f"Error collecting Talisman findings: {str(e)}")
            return []


class PenetrationTestAdapter(SecurityToolAdapter):
    """Adapter for integrating with penetration testing suite per Section 6.4.5."""
    
    def __init__(self, app: Flask = None):
        super().__init__("penetration_testing")
        self.app = app
    
    async def collect_findings(self) -> List[SecurityFinding]:
        """Collect penetration testing findings."""
        try:
            if not self.app or not PenetrationTestSuite:
                self.logger.warning("Penetration testing infrastructure not available")
                return []
            
            # Initialize penetration testing components
            security_environment = {
                'app': self.app,
                'test_session_id': f"pentest_{secrets.token_hex(8)}"
            }
            
            # Mock required dependencies for testing
            owasp_payloads = type('MockOWASPPayloads', (), {
                'create_attack_payloads_dataset': lambda: {
                    'xss': ['<script>alert("xss")</script>'],
                    'sql_injection': ["'; DROP TABLE users; --"],
                    'command_injection': ['; cat /etc/passwd']
                }
            })()
            
            metrics_collector = type('MockMetricsCollector', (), {
                'record_security_response_time': lambda *args: None,
                'record_attack_detection': lambda *args: None
            })()
            
            pentest_suite = PenetrationTestSuite(
                security_environment,
                owasp_payloads,
                metrics_collector
            )
            
            findings = []
            
            # Run comprehensive security scan if app test client available
            with self.app.test_client() as client:
                scan_results = await pentest_suite.run_comprehensive_security_scan(client)
                
                # Process OWASP Top 10 results
                owasp_results = scan_results.get("test_categories", {}).get("owasp_top10", {})
                for vulnerability in owasp_results.get("critical_findings", []):
                    finding = SecurityFinding(
                        finding_id=self._generate_finding_id(
                            f"pentest:{vulnerability['vulnerability_type']}:{vulnerability['endpoint']}"
                        ),
                        tool=self.tool_name,
                        severity=SecuritySeverity.HIGH,
                        category="penetration_testing",
                        title=f"OWASP {vulnerability['vulnerability_type'].upper()} vulnerability",
                        description=f"Penetration test identified {vulnerability['vulnerability_type']} vulnerability",
                        location=vulnerability["endpoint"],
                        recommendation="Implement input validation and output encoding",
                        compliance_frameworks=["owasp_top10", "soc2"],
                        additional_metadata={
                            "payload": vulnerability.get("payload", ""),
                            "vulnerability_type": vulnerability["vulnerability_type"],
                            "pentest_session": security_environment["test_session_id"]
                        }
                    )
                    findings.append(finding)
                
                # Process authentication test results
                auth_results = scan_results.get("test_categories", {}).get("authentication", {})
                for vuln in auth_results.get("jwt_security", {}).get("vulnerabilities_found", []):
                    finding = SecurityFinding(
                        finding_id=self._generate_finding_id(f"pentest:auth:{vuln['vulnerability']}"),
                        tool=self.tool_name,
                        severity=SecuritySeverity.CRITICAL,
                        category="authentication",
                        title=f"Authentication vulnerability: {vuln['vulnerability']}",
                        description="Penetration test identified authentication bypass vulnerability",
                        location=vuln.get("endpoint", "/api/protected"),
                        recommendation="Review JWT token validation and authentication flows",
                        compliance_frameworks=["soc2", "iso27001"],
                        additional_metadata={
                            "vulnerability": vuln["vulnerability"],
                            "token": vuln.get("token", ""),
                            "pentest_session": security_environment["test_session_id"]
                        }
                    )
                    findings.append(finding)
            
            self.logger.info(f"Collected {len(findings)} penetration testing findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error collecting penetration testing findings: {str(e)}")
            return []


class SecurityReportGenerator:
    """
    Comprehensive security report generator implementing consolidated security findings,
    compliance reporting, and executive dashboard integration per Section 6.6.2 and 6.4.6.
    """
    
    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        prometheus_registry=None,
        app: Optional[Flask] = None
    ):
        self.redis_client = redis_client
        self.prometheus_registry = prometheus_registry
        self.app = app
        self.logger = structlog.get_logger("security.report_generator")
        
        # Initialize security tool adapters
        self.adapters = {
            "bandit": BanditAdapter(),
            "safety": SafetyAdapter(),
            "vulnerability_scanner": VulnerabilityAdapter(),
            "flask_talisman": TalismanSecurityAdapter(app),
            "penetration_testing": PenetrationTestAdapter(app)
        }
        
        # Redis keys for caching and trend storage
        self.cache_key_prefix = "security_reports"
        self.trends_key = f"{self.cache_key_prefix}:trends"
        self.findings_key = f"{self.cache_key_prefix}:findings"
        
        # Initialize trend tracking
        self.trend_data = []
    
    async def generate_consolidated_report(
        self,
        report_format: str = SecurityReportFormat.JSON,
        include_trends: bool = True,
        include_executive_summary: bool = True
    ) -> Dict[str, Any]:
        """
        Generate consolidated security report from all security tools per Section 6.6.2.
        
        Args:
            report_format: Output format for the report
            include_trends: Whether to include trend analysis
            include_executive_summary: Whether to include executive summary
            
        Returns:
            Comprehensive security report dictionary
        """
        try:
            report_start_time = time.time()
            report_id = f"security_report_{int(report_start_time)}"
            
            self.logger.info(f"Starting consolidated security report generation: {report_id}")
            
            # Collect findings from all security tools
            all_findings = await self._collect_all_findings()
            
            # Generate compliance analysis
            compliance_results = await self._analyze_compliance(all_findings)
            
            # Calculate security metrics
            security_metrics = await self._calculate_security_metrics(all_findings)
            
            # Generate trend analysis if requested
            trend_analysis = {}
            if include_trends:
                trend_analysis = await self._generate_trend_analysis(all_findings)
            
            # Generate executive summary if requested
            executive_summary = {}
            if include_executive_summary:
                executive_summary = await self._generate_executive_summary(
                    all_findings, compliance_results, security_metrics
                )
            
            # Compile consolidated report
            consolidated_report = {
                "report_metadata": {
                    "report_id": report_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "generation_duration_seconds": time.time() - report_start_time,
                    "report_format": report_format,
                    "total_findings": len(all_findings),
                    "tools_analyzed": list(self.adapters.keys()),
                    "compliance_frameworks": SecurityComplianceFramework.ALL_FRAMEWORKS
                },
                "executive_summary": executive_summary,
                "security_findings": [finding.to_dict() for finding in all_findings],
                "compliance_analysis": compliance_results,
                "security_metrics": security_metrics,
                "trend_analysis": trend_analysis,
                "recommendations": await self._generate_recommendations(all_findings),
                "next_actions": await self._generate_next_actions(all_findings, compliance_results)
            }
            
            # Update Prometheus metrics
            await self._update_prometheus_metrics(all_findings, security_metrics)
            
            # Cache report for future reference
            await self._cache_report(report_id, consolidated_report)
            
            # Store trend data
            await self._store_trend_data(all_findings, security_metrics)
            
            self.logger.info(
                f"Consolidated security report generated successfully",
                report_id=report_id,
                findings_count=len(all_findings),
                duration=time.time() - report_start_time
            )
            
            return consolidated_report
            
        except Exception as e:
            self.logger.error(f"Error generating consolidated security report: {str(e)}")
            raise
    
    async def _collect_all_findings(self) -> List[SecurityFinding]:
        """Collect findings from all security tool adapters."""
        all_findings = []
        
        for tool_name, adapter in self.adapters.items():
            try:
                tool_start_time = time.time()
                findings = await adapter.collect_findings()
                tool_duration = time.time() - tool_start_time
                
                all_findings.extend(findings)
                
                # Record scan duration metric
                SECURITY_SCAN_DURATION.labels(
                    tool=tool_name,
                    scan_type="automated"
                ).observe(tool_duration)
                
                self.logger.info(
                    f"Collected findings from {tool_name}",
                    tool=tool_name,
                    findings_count=len(findings),
                    duration=tool_duration
                )
                
            except Exception as e:
                self.logger.error(f"Error collecting findings from {tool_name}: {str(e)}")
                continue
        
        # Remove duplicate findings
        unique_findings = self._deduplicate_findings(all_findings)
        
        self.logger.info(
            f"Collected total findings",
            total_findings=len(all_findings),
            unique_findings=len(unique_findings),
            duplicates_removed=len(all_findings) - len(unique_findings)
        )
        
        return unique_findings
    
    def _deduplicate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings based on content similarity."""
        unique_findings = {}
        
        for finding in findings:
            # Create deduplication key based on tool, location, and description
            dedup_key = hashlib.sha256(
                f"{finding.tool}:{finding.location}:{finding.description}".encode()
            ).hexdigest()
            
            if dedup_key not in unique_findings:
                unique_findings[dedup_key] = finding
            else:
                # Keep finding with higher severity
                existing = unique_findings[dedup_key]
                if SecuritySeverity.get_numeric_score(finding.severity) > \
                   SecuritySeverity.get_numeric_score(existing.severity):
                    unique_findings[dedup_key] = finding
        
        return list(unique_findings.values())
    
    async def _analyze_compliance(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze compliance status across all frameworks per Section 6.4.6."""
        compliance_analysis = {}
        
        for framework in SecurityComplianceFramework.ALL_FRAMEWORKS:
            framework_requirements = SecurityComplianceFramework.get_framework_requirements(framework)
            
            # Filter findings relevant to this framework
            framework_findings = [
                f for f in findings if framework in f.compliance_frameworks
            ]
            
            # Calculate compliance metrics
            critical_findings = [
                f for f in framework_findings 
                if f.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]
            ]
            
            total_findings = len(framework_findings)
            critical_count = len(critical_findings)
            
            # Calculate compliance score
            if total_findings == 0:
                compliance_score = 100.0
            else:
                # Deduct points based on findings severity
                penalty = sum(
                    SecuritySeverity.get_numeric_score(f.severity) / 100
                    for f in framework_findings
                )
                compliance_score = max(0, 100 - penalty)
            
            # Determine compliance status
            threshold = framework_requirements.get("threshold", 90)
            compliance_status = "compliant" if compliance_score >= threshold else "non_compliant"
            
            compliance_analysis[framework] = {
                "compliance_score": round(compliance_score, 2),
                "compliance_status": compliance_status,
                "threshold": threshold,
                "total_findings": total_findings,
                "critical_findings": critical_count,
                "findings_by_severity": self._group_findings_by_severity(framework_findings),
                "required_controls": framework_requirements.get("controls", []),
                "critical_controls": framework_requirements.get("critical_controls", []),
                "recommendations": self._get_compliance_recommendations(framework, critical_findings)
            }
            
            # Update Prometheus compliance metric
            COMPLIANCE_SCORE_GAUGE.labels(
                framework=framework,
                component="overall"
            ).set(compliance_score)
        
        return compliance_analysis
    
    def _group_findings_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Group findings by severity level."""
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity] += 1
        return dict(severity_counts)
    
    def _get_compliance_recommendations(
        self,
        framework: str,
        critical_findings: List[SecurityFinding]
    ) -> List[str]:
        """Generate compliance-specific recommendations."""
        recommendations = []
        
        if not critical_findings:
            recommendations.append(f"Maintain current {framework.upper()} compliance status")
            return recommendations
        
        # Group critical findings by category
        findings_by_category = defaultdict(list)
        for finding in critical_findings:
            findings_by_category[finding.category].append(finding)
        
        for category, category_findings in findings_by_category.items():
            count = len(category_findings)
            recommendations.append(
                f"Address {count} critical {category} finding(s) for {framework.upper()} compliance"
            )
        
        # Add framework-specific recommendations
        framework_specific = {
            SecurityComplianceFramework.SOC2: [
                "Implement comprehensive audit logging",
                "Review access control mechanisms",
                "Enhance data protection measures"
            ],
            SecurityComplianceFramework.OWASP_TOP10: [
                "Implement input validation across all endpoints",
                "Review authentication and session management",
                "Enhance output encoding and XSS protection"
            ],
            SecurityComplianceFramework.PCI_DSS: [
                "Implement strong encryption for sensitive data",
                "Review network security controls",
                "Enhance access control and monitoring"
            ]
        }
        
        recommendations.extend(framework_specific.get(framework, []))
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    async def _calculate_security_metrics(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate comprehensive security metrics per Section 6.6.3."""
        metrics = {
            "total_findings": len(findings),
            "findings_by_severity": self._group_findings_by_severity(findings),
            "findings_by_tool": defaultdict(int),
            "findings_by_category": defaultdict(int),
            "risk_score_distribution": {},
            "age_analysis": {},
            "remediation_metrics": {}
        }
        
        # Calculate findings by tool and category
        for finding in findings:
            metrics["findings_by_tool"][finding.tool] += 1
            metrics["findings_by_category"][finding.category] += 1
        
        # Convert defaultdicts to regular dicts
        metrics["findings_by_tool"] = dict(metrics["findings_by_tool"])
        metrics["findings_by_category"] = dict(metrics["findings_by_category"])
        
        # Calculate risk score distribution
        risk_scores = [f.risk_score for f in findings]
        if risk_scores:
            metrics["risk_score_distribution"] = {
                "mean": round(sum(risk_scores) / len(risk_scores), 2),
                "max": max(risk_scores),
                "min": min(risk_scores),
                "high_risk_count": len([s for s in risk_scores if s >= 75])
            }
        
        # Calculate age analysis
        ages = [f.age_days for f in findings]
        if ages:
            metrics["age_analysis"] = {
                "average_age_days": round(sum(ages) / len(ages), 2),
                "oldest_finding_days": max(ages),
                "stale_findings_count": len([a for a in ages if a > 30])
            }
        
        # Calculate overall security posture score
        if findings:
            # Weighted scoring based on severity and age
            severity_weights = {
                SecuritySeverity.CRITICAL: 4,
                SecuritySeverity.HIGH: 3,
                SecuritySeverity.MEDIUM: 2,
                SecuritySeverity.LOW: 1,
                SecuritySeverity.INFO: 0.5
            }
            
            total_weight = sum(
                severity_weights.get(f.severity, 1) * (1 + f.age_days / 100)
                for f in findings
            )
            
            # Calculate score (0-100, where 100 is perfect security)
            max_possible_weight = len(findings) * 4  # All critical, age 0
            security_posture_score = max(0, 100 - (total_weight / max_possible_weight * 100))
        else:
            security_posture_score = 100
        
        metrics["security_posture_score"] = round(security_posture_score, 2)
        
        # Update Prometheus metrics
        SECURITY_POSTURE_SCORE.labels(
            component="overall",
            assessment_type="automated"
        ).set(security_posture_score)
        
        # Record vulnerability age metrics
        for finding in findings:
            VULNERABILITY_AGE_DAYS.labels(
                severity=finding.severity,
                category=finding.category,
                tool=finding.tool
            ).observe(finding.age_days)
        
        return metrics
    
    async def _generate_trend_analysis(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate security trend analysis per Section 6.6.3."""
        try:
            # Get historical trend data
            historical_trends = await self._get_historical_trends()
            
            # Calculate current trend data
            current_trend = SecurityTrendData()
            current_trend.findings_by_severity = self._group_findings_by_severity(findings)
            current_trend.findings_by_tool = {
                tool: len([f for f in findings if f.tool == tool])
                for tool in self.adapters.keys()
            }
            current_trend.findings_by_category = {
                category: len([f for f in findings if f.category == category])
                for category in set(f.category for f in findings)
            }
            current_trend.vulnerability_count = len(findings)
            current_trend.security_posture_score = (
                await self._calculate_security_metrics(findings)
            )["security_posture_score"]
            
            # Calculate trends if historical data exists
            trends = {
                "current_period": current_trend.to_dict(),
                "historical_data": [trend.to_dict() for trend in historical_trends[-30:]],  # Last 30 periods
                "trend_analysis": {}
            }
            
            if len(historical_trends) >= 2:
                # Compare with previous period
                previous_trend = historical_trends[-1]
                
                trends["trend_analysis"] = {
                    "vulnerability_count_change": {
                        "current": current_trend.vulnerability_count,
                        "previous": previous_trend.vulnerability_count,
                        "change": current_trend.vulnerability_count - previous_trend.vulnerability_count,
                        "percentage_change": self._calculate_percentage_change(
                            previous_trend.vulnerability_count,
                            current_trend.vulnerability_count
                        )
                    },
                    "security_posture_change": {
                        "current": current_trend.security_posture_score,
                        "previous": previous_trend.security_posture_score,
                        "change": current_trend.security_posture_score - previous_trend.security_posture_score,
                        "percentage_change": self._calculate_percentage_change(
                            previous_trend.security_posture_score,
                            current_trend.security_posture_score
                        )
                    },
                    "severity_trends": self._analyze_severity_trends(historical_trends[-7:], current_trend),
                    "tool_performance": self._analyze_tool_performance(historical_trends[-7:], current_trend)
                }
            
            return trends
            
        except Exception as e:
            self.logger.error(f"Error generating trend analysis: {str(e)}")
            return {"error": "Trend analysis unavailable"}
    
    def _calculate_percentage_change(self, old_value: float, new_value: float) -> float:
        """Calculate percentage change between two values."""
        if old_value == 0:
            return 100.0 if new_value > 0 else 0.0
        return round(((new_value - old_value) / old_value) * 100, 2)
    
    def _analyze_severity_trends(
        self,
        historical_trends: List[SecurityTrendData],
        current_trend: SecurityTrendData
    ) -> Dict[str, Any]:
        """Analyze trends in security findings by severity."""
        severity_analysis = {}
        
        for severity in SecuritySeverity.ALL_SEVERITIES:
            current_count = current_trend.findings_by_severity.get(severity, 0)
            
            if historical_trends:
                historical_counts = [
                    trend.findings_by_severity.get(severity, 0)
                    for trend in historical_trends
                ]
                avg_historical = sum(historical_counts) / len(historical_counts)
                
                severity_analysis[severity] = {
                    "current": current_count,
                    "historical_average": round(avg_historical, 2),
                    "trend": "increasing" if current_count > avg_historical else "decreasing",
                    "change_from_average": round(current_count - avg_historical, 2)
                }
            else:
                severity_analysis[severity] = {
                    "current": current_count,
                    "historical_average": 0,
                    "trend": "new",
                    "change_from_average": current_count
                }
        
        return severity_analysis
    
    def _analyze_tool_performance(
        self,
        historical_trends: List[SecurityTrendData],
        current_trend: SecurityTrendData
    ) -> Dict[str, Any]:
        """Analyze security tool performance trends."""
        tool_analysis = {}
        
        for tool in self.adapters.keys():
            current_findings = current_trend.findings_by_tool.get(tool, 0)
            
            if historical_trends:
                historical_findings = [
                    trend.findings_by_tool.get(tool, 0)
                    for trend in historical_trends
                ]
                avg_historical = sum(historical_findings) / len(historical_findings)
                
                tool_analysis[tool] = {
                    "current_findings": current_findings,
                    "historical_average": round(avg_historical, 2),
                    "effectiveness_trend": "improving" if current_findings > avg_historical else "stable",
                    "findings_change": round(current_findings - avg_historical, 2)
                }
            else:
                tool_analysis[tool] = {
                    "current_findings": current_findings,
                    "historical_average": 0,
                    "effectiveness_trend": "new",
                    "findings_change": current_findings
                }
        
        return tool_analysis
    
    async def _generate_executive_summary(
        self,
        findings: List[SecurityFinding],
        compliance_results: Dict[str, Any],
        security_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary per Section 6.4.6."""
        # Calculate key executive metrics
        critical_high_count = len([
            f for f in findings 
            if f.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]
        ])
        
        compliance_scores = [
            result["compliance_score"]
            for result in compliance_results.values()
        ]
        avg_compliance_score = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 100
        
        # Determine overall security status
        if critical_high_count == 0 and avg_compliance_score >= 95:
            security_status = "excellent"
            status_color = "green"
        elif critical_high_count <= 2 and avg_compliance_score >= 85:
            security_status = "good"
            status_color = "yellow"
        elif critical_high_count <= 5 and avg_compliance_score >= 70:
            security_status = "needs_attention"
            status_color = "orange"
        else:
            security_status = "critical_attention_required"
            status_color = "red"
        
        # Generate key insights
        insights = []
        
        if critical_high_count > 0:
            insights.append(f"{critical_high_count} critical/high severity vulnerabilities require immediate attention")
        
        # Compliance insights
        non_compliant_frameworks = [
            framework for framework, result in compliance_results.items()
            if result["compliance_status"] == "non_compliant"
        ]
        
        if non_compliant_frameworks:
            insights.append(f"Non-compliance detected in: {', '.join(non_compliant_frameworks)}")
        
        # Tool insights
        tool_findings = security_metrics["findings_by_tool"]
        most_findings_tool = max(tool_findings, key=tool_findings.get) if tool_findings else None
        if most_findings_tool:
            insights.append(f"{most_findings_tool} identified the most security issues ({tool_findings[most_findings_tool]} findings)")
        
        # Age insights
        age_analysis = security_metrics.get("age_analysis", {})
        stale_count = age_analysis.get("stale_findings_count", 0)
        if stale_count > 0:
            insights.append(f"{stale_count} findings are over 30 days old and require prioritized remediation")
        
        executive_summary = {
            "security_status": {
                "overall_status": security_status,
                "status_color": status_color,
                "security_posture_score": security_metrics["security_posture_score"],
                "last_assessment": datetime.now(timezone.utc).isoformat()
            },
            "key_metrics": {
                "total_findings": len(findings),
                "critical_high_findings": critical_high_count,
                "average_compliance_score": round(avg_compliance_score, 2),
                "security_tools_active": len(self.adapters),
                "oldest_finding_age_days": age_analysis.get("oldest_finding_days", 0)
            },
            "compliance_overview": {
                "frameworks_assessed": len(compliance_results),
                "compliant_frameworks": len([
                    r for r in compliance_results.values()
                    if r["compliance_status"] == "compliant"
                ]),
                "non_compliant_frameworks": non_compliant_frameworks,
                "average_score": round(avg_compliance_score, 2)
            },
            "top_priorities": self._generate_top_priorities(findings),
            "key_insights": insights[:5],  # Limit to top 5 insights
            "recommended_actions": self._generate_executive_actions(findings, compliance_results)
        }
        
        return executive_summary
    
    def _generate_top_priorities(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate top priority findings for executive attention."""
        # Sort findings by risk score and select top priorities
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        top_priorities = []
        
        for finding in sorted_findings[:5]:  # Top 5 priorities
            priority = {
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "category": finding.category,
                "age_days": finding.age_days,
                "recommendation": finding.recommendation,
                "compliance_impact": finding.compliance_frameworks
            }
            top_priorities.append(priority)
        
        return top_priorities
    
    def _generate_executive_actions(
        self,
        findings: List[SecurityFinding],
        compliance_results: Dict[str, Any]
    ) -> List[str]:
        """Generate recommended executive actions."""
        actions = []
        
        # Critical findings action
        critical_count = len([f for f in findings if f.severity == SecuritySeverity.CRITICAL])
        if critical_count > 0:
            actions.append(f"Immediate remediation required for {critical_count} critical security vulnerabilities")
        
        # Compliance actions
        non_compliant = [
            framework for framework, result in compliance_results.items()
            if result["compliance_status"] == "non_compliant"
        ]
        if non_compliant:
            actions.append(f"Initiate compliance remediation for {', '.join(non_compliant)} frameworks")
        
        # Resource allocation
        high_count = len([f for f in findings if f.severity == SecuritySeverity.HIGH])
        if high_count > 10:
            actions.append("Consider additional security engineering resources for vulnerability remediation")
        
        # Tool optimization
        tool_findings = defaultdict(int)
        for finding in findings:
            tool_findings[finding.tool] += 1
        
        if len(tool_findings) < 3:
            actions.append("Consider expanding security testing tool coverage")
        
        # Age-based actions
        old_findings = [f for f in findings if f.age_days > 60]
        if old_findings:
            actions.append(f"Establish remediation timeline for {len(old_findings)} long-standing vulnerabilities")
        
        return actions[:5]  # Limit to top 5 actions
    
    async def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate comprehensive security recommendations."""
        recommendations = []
        
        # Group findings by category for targeted recommendations
        findings_by_category = defaultdict(list)
        for finding in findings:
            findings_by_category[finding.category].append(finding)
        
        for category, category_findings in findings_by_category.items():
            if not category_findings:
                continue
            
            critical_count = len([f for f in category_findings if f.severity == SecuritySeverity.CRITICAL])
            high_count = len([f for f in category_findings if f.severity == SecuritySeverity.HIGH])
            
            if critical_count > 0 or high_count > 0:
                recommendation = {
                    "category": category,
                    "priority": "high" if critical_count > 0 else "medium",
                    "finding_count": len(category_findings),
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "recommendation": self._get_category_recommendation(category),
                    "timeline": "immediate" if critical_count > 0 else "within_30_days"
                }
                recommendations.append(recommendation)
        
        # Sort by priority and finding count
        recommendations.sort(key=lambda r: (r["priority"] == "high", r["critical_count"]), reverse=True)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_category_recommendation(self, category: str) -> str:
        """Get recommendation for specific finding category."""
        category_recommendations = {
            "sast": "Review and remediate static analysis findings through code review and secure coding practices",
            "dependency_vulnerability": "Update vulnerable dependencies and implement automated dependency scanning",
            "security_headers": "Configure Flask-Talisman security headers and review web application security policies",
            "authentication": "Review authentication mechanisms and implement additional security controls",
            "authorization": "Audit access controls and implement principle of least privilege",
            "penetration_testing": "Address penetration testing findings and enhance security testing coverage",
            "web_vulnerability": "Implement input validation, output encoding, and secure development practices",
            "configuration": "Review security configuration and implement security hardening guidelines"
        }
        return category_recommendations.get(category, "Review and remediate security findings in this category")
    
    async def _generate_next_actions(
        self,
        findings: List[SecurityFinding],
        compliance_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate specific next actions with timelines."""
        next_actions = []
        
        # Immediate actions for critical findings
        critical_findings = [f for f in findings if f.severity == SecuritySeverity.CRITICAL]
        if critical_findings:
            next_actions.append({
                "action": "Critical Vulnerability Remediation",
                "description": f"Address {len(critical_findings)} critical security vulnerabilities",
                "timeline": "immediate",
                "priority": "critical",
                "owner": "Security Team",
                "resources_required": ["security_engineer", "development_team"]
            })
        
        # Compliance actions
        for framework, result in compliance_results.items():
            if result["compliance_status"] == "non_compliant":
                next_actions.append({
                    "action": f"{framework.upper()} Compliance Remediation",
                    "description": f"Address compliance gaps for {framework} framework",
                    "timeline": "within_30_days",
                    "priority": "high",
                    "owner": "Compliance Team",
                    "resources_required": ["compliance_officer", "security_team"]
                })
        
        # Tool enhancement actions
        tool_coverage = len(self.adapters)
        if tool_coverage < 5:
            next_actions.append({
                "action": "Security Tool Coverage Enhancement",
                "description": "Implement additional security testing tools and processes",
                "timeline": "within_60_days",
                "priority": "medium",
                "owner": "Security Engineering",
                "resources_required": ["security_engineer", "devops_team"]
            })
        
        # Process improvement actions
        old_findings = [f for f in findings if f.age_days > 30]
        if len(old_findings) > 5:
            next_actions.append({
                "action": "Vulnerability Management Process Improvement",
                "description": "Establish SLAs and processes for timely vulnerability remediation",
                "timeline": "within_30_days",
                "priority": "medium",
                "owner": "Security Management",
                "resources_required": ["security_manager", "process_improvement"]
            })
        
        return next_actions[:8]  # Limit to top 8 actions
    
    async def _update_prometheus_metrics(
        self,
        findings: List[SecurityFinding],
        security_metrics: Dict[str, Any]
    ) -> None:
        """Update Prometheus metrics with current security data."""
        try:
            # Update security findings metrics
            for finding in findings:
                SECURITY_FINDINGS_TOTAL.labels(
                    tool=finding.tool,
                    severity=finding.severity,
                    category=finding.category
                ).inc()
            
            # Update security posture score
            SECURITY_POSTURE_SCORE.labels(
                component="overall",
                assessment_type="comprehensive"
            ).set(security_metrics["security_posture_score"])
            
            self.logger.info("Updated Prometheus security metrics")
            
        except Exception as e:
            self.logger.error(f"Error updating Prometheus metrics: {str(e)}")
    
    async def _cache_report(self, report_id: str, report_data: Dict[str, Any]) -> None:
        """Cache security report in Redis for future reference."""
        try:
            if self.redis_client:
                cache_key = f"{self.cache_key_prefix}:report:{report_id}"
                
                # Cache report with 7-day expiration
                self.redis_client.setex(
                    cache_key,
                    timedelta(days=7),
                    json.dumps(report_data, default=str)
                )
                
                # Add to reports index
                reports_index_key = f"{self.cache_key_prefix}:reports_index"
                self.redis_client.zadd(
                    reports_index_key,
                    {report_id: time.time()}
                )
                
                self.logger.info(f"Cached security report: {report_id}")
            
        except Exception as e:
            self.logger.error(f"Error caching security report: {str(e)}")
    
    async def _store_trend_data(
        self,
        findings: List[SecurityFinding],
        security_metrics: Dict[str, Any]
    ) -> None:
        """Store current security data for trend analysis."""
        try:
            if self.redis_client:
                # Create trend data point
                trend_data = SecurityTrendData()
                trend_data.findings_by_severity = security_metrics["findings_by_severity"]
                trend_data.findings_by_tool = security_metrics["findings_by_tool"]
                trend_data.findings_by_category = security_metrics["findings_by_category"]
                trend_data.vulnerability_count = len(findings)
                trend_data.security_posture_score = security_metrics["security_posture_score"]
                
                # Store in Redis sorted set with timestamp as score
                self.redis_client.zadd(
                    self.trends_key,
                    {json.dumps(trend_data.to_dict(), default=str): time.time()}
                )
                
                # Keep only last 90 days of trend data
                cutoff_time = time.time() - (90 * 24 * 60 * 60)
                self.redis_client.zremrangebyscore(self.trends_key, 0, cutoff_time)
                
                self.logger.info("Stored security trend data")
            
        except Exception as e:
            self.logger.error(f"Error storing trend data: {str(e)}")
    
    async def _get_historical_trends(self) -> List[SecurityTrendData]:
        """Retrieve historical trend data from Redis."""
        try:
            if not self.redis_client:
                return []
            
            # Get trend data from Redis
            trend_data = self.redis_client.zrange(self.trends_key, 0, -1)
            
            trends = []
            for data in trend_data:
                try:
                    trend_dict = json.loads(data)
                    trend = SecurityTrendData.from_dict(trend_dict)
                    trends.append(trend)
                except (json.JSONDecodeError, KeyError):
                    continue
            
            return trends
            
        except Exception as e:
            self.logger.error(f"Error retrieving historical trends: {str(e)}")
            return []
    
    async def generate_compliance_dashboard_data(
        self,
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate compliance dashboard data per Section 6.4.6.
        
        Args:
            frameworks: List of compliance frameworks to include (default: all)
            
        Returns:
            Dashboard-ready compliance data
        """
        try:
            # Collect current findings
            all_findings = await self._collect_all_findings()
            
            # Analyze compliance for requested frameworks
            target_frameworks = frameworks or SecurityComplianceFramework.ALL_FRAMEWORKS
            compliance_results = {}
            
            for framework in target_frameworks:
                framework_analysis = await self._analyze_framework_compliance(framework, all_findings)
                compliance_results[framework] = framework_analysis
            
            # Generate dashboard widgets
            dashboard_data = {
                "compliance_overview": {
                    "total_frameworks": len(target_frameworks),
                    "compliant_count": len([
                        r for r in compliance_results.values()
                        if r["status"] == "compliant"
                    ]),
                    "overall_score": sum(
                        r["score"] for r in compliance_results.values()
                    ) / len(compliance_results) if compliance_results else 100
                },
                "framework_details": compliance_results,
                "compliance_trends": await self._get_compliance_trends(target_frameworks),
                "priority_actions": await self._get_compliance_priority_actions(compliance_results),
                "dashboard_widgets": await self._generate_dashboard_widgets(compliance_results),
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Error generating compliance dashboard data: {str(e)}")
            raise
    
    async def _analyze_framework_compliance(
        self,
        framework: str,
        findings: List[SecurityFinding]
    ) -> Dict[str, Any]:
        """Analyze compliance for a specific framework."""
        framework_requirements = SecurityComplianceFramework.get_framework_requirements(framework)
        
        # Filter findings relevant to framework
        framework_findings = [
            f for f in findings if framework in f.compliance_frameworks
        ]
        
        # Calculate compliance score
        if not framework_findings:
            compliance_score = 100.0
            status = "compliant"
        else:
            # Weighted scoring based on severity
            severity_weights = {
                SecuritySeverity.CRITICAL: 10,
                SecuritySeverity.HIGH: 5,
                SecuritySeverity.MEDIUM: 2,
                SecuritySeverity.LOW: 1,
                SecuritySeverity.INFO: 0.5
            }
            
            total_weight = sum(
                severity_weights.get(f.severity, 1) for f in framework_findings
            )
            
            # Deduct from 100 based on weighted findings
            compliance_score = max(0, 100 - total_weight)
            
            threshold = framework_requirements.get("threshold", 90)
            status = "compliant" if compliance_score >= threshold else "non_compliant"
        
        return {
            "framework": framework,
            "score": round(compliance_score, 2),
            "status": status,
            "threshold": framework_requirements.get("threshold", 90),
            "findings_count": len(framework_findings),
            "critical_findings": len([f for f in framework_findings if f.severity == SecuritySeverity.CRITICAL]),
            "high_findings": len([f for f in framework_findings if f.severity == SecuritySeverity.HIGH]),
            "required_controls": framework_requirements.get("controls", []),
            "critical_controls": framework_requirements.get("critical_controls", []),
            "last_assessment": datetime.now(timezone.utc).isoformat()
        }
    
    async def _get_compliance_trends(self, frameworks: List[str]) -> Dict[str, Any]:
        """Get compliance trends for dashboard visualization."""
        try:
            historical_trends = await self._get_historical_trends()
            
            if len(historical_trends) < 2:
                return {"message": "Insufficient historical data for trend analysis"}
            
            # Analyze trends for each framework
            framework_trends = {}
            
            for framework in frameworks:
                scores = []
                timestamps = []
                
                for trend in historical_trends[-30:]:  # Last 30 data points
                    framework_score = trend.compliance_scores.get(framework, 100)
                    scores.append(framework_score)
                    timestamps.append(trend.timestamp.isoformat())
                
                if scores:
                    framework_trends[framework] = {
                        "current_score": scores[-1] if scores else 100,
                        "previous_score": scores[-2] if len(scores) > 1 else scores[0],
                        "trend_direction": "improving" if len(scores) > 1 and scores[-1] > scores[-2] else "stable",
                        "historical_scores": scores,
                        "timestamps": timestamps
                    }
            
            return framework_trends
            
        except Exception as e:
            self.logger.error(f"Error getting compliance trends: {str(e)}")
            return {}
    
    async def _get_compliance_priority_actions(
        self,
        compliance_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Get priority actions for compliance dashboard."""
        priority_actions = []
        
        # Sort frameworks by compliance score (lowest first)
        sorted_frameworks = sorted(
            compliance_results.items(),
            key=lambda x: x[1]["score"]
        )
        
        for framework, result in sorted_frameworks:
            if result["status"] == "non_compliant":
                priority_actions.append({
                    "framework": framework,
                    "action": f"Address {framework.upper()} compliance gaps",
                    "priority": "high" if result["critical_findings"] > 0 else "medium",
                    "score": result["score"],
                    "findings": result["findings_count"],
                    "timeline": "immediate" if result["critical_findings"] > 0 else "30_days"
                })
        
        # Add improvement actions for frameworks with low scores
        for framework, result in sorted_frameworks:
            if result["status"] == "compliant" but result["score"] < 95:
                priority_actions.append({
                    "framework": framework,
                    "action": f"Improve {framework.upper()} compliance score",
                    "priority": "low",
                    "score": result["score"],
                    "findings": result["findings_count"],
                    "timeline": "60_days"
                })
        
        return priority_actions[:5]  # Top 5 priority actions
    
    async def _generate_dashboard_widgets(
        self,
        compliance_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate dashboard widgets for compliance visualization."""
        widgets = []
        
        # Compliance score gauge widget
        overall_score = sum(r["score"] for r in compliance_results.values()) / len(compliance_results) if compliance_results else 100
        
        widgets.append({
            "type": "gauge",
            "title": "Overall Compliance Score",
            "value": round(overall_score, 1),
            "max_value": 100,
            "thresholds": [
                {"value": 95, "color": "green", "label": "Excellent"},
                {"value": 85, "color": "yellow", "label": "Good"},
                {"value": 70, "color": "orange", "label": "Needs Attention"},
                {"value": 0, "color": "red", "label": "Critical"}
            ]
        })
        
        # Framework status widget
        widgets.append({
            "type": "status_grid",
            "title": "Framework Compliance Status",
            "data": [
                {
                    "framework": framework,
                    "score": result["score"],
                    "status": result["status"],
                    "color": "green" if result["status"] == "compliant" else "red"
                }
                for framework, result in compliance_results.items()
            ]
        })
        
        # Findings distribution widget
        total_findings = sum(r["findings_count"] for r in compliance_results.values())
        critical_findings = sum(r["critical_findings"] for r in compliance_results.values())
        high_findings = sum(r["high_findings"] for r in compliance_results.values())
        
        widgets.append({
            "type": "donut_chart",
            "title": "Security Findings by Severity",
            "data": [
                {"label": "Critical", "value": critical_findings, "color": "red"},
                {"label": "High", "value": high_findings, "color": "orange"},
                {"label": "Other", "value": total_findings - critical_findings - high_findings, "color": "yellow"}
            ]
        })
        
        # Compliance timeline widget
        widgets.append({
            "type": "timeline",
            "title": "Compliance Improvement Timeline",
            "data": [
                {
                    "date": datetime.now(timezone.utc).isoformat(),
                    "event": "Current Assessment",
                    "score": overall_score,
                    "type": "assessment"
                }
            ]
        })
        
        return widgets
    
    async def export_prometheus_metrics(self) -> str:
        """Export current security metrics in Prometheus format."""
        try:
            # Collect current findings to update metrics
            all_findings = await self._collect_all_findings()
            
            # Update metrics
            await self._update_prometheus_metrics(all_findings, await self._calculate_security_metrics(all_findings))
            
            # Generate Prometheus metrics output
            return generate_latest(self.prometheus_registry).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error exporting Prometheus metrics: {str(e)}")
            return f"# Error generating metrics: {str(e)}\n"
    
    async def get_security_posture_summary(self) -> Dict[str, Any]:
        """Get executive security posture summary per Section 6.4.6."""
        try:
            # Generate comprehensive report
            report = await self.generate_consolidated_report(
                include_trends=True,
                include_executive_summary=True
            )
            
            # Extract executive summary
            executive_summary = report.get("executive_summary", {})
            security_metrics = report.get("security_metrics", {})
            compliance_analysis = report.get("compliance_analysis", {})
            
            # Create executive-focused summary
            posture_summary = {
                "security_status": executive_summary.get("security_status", {}),
                "key_metrics": executive_summary.get("key_metrics", {}),
                "compliance_overview": executive_summary.get("compliance_overview", {}),
                "top_priorities": executive_summary.get("top_priorities", [])[:3],
                "recommended_actions": executive_summary.get("recommended_actions", [])[:3],
                "risk_indicators": {
                    "critical_vulnerabilities": len([
                        f for f in report.get("security_findings", [])
                        if f.get("severity") == "critical"
                    ]),
                    "compliance_gaps": len([
                        f for f in compliance_analysis.values()
                        if f.get("compliance_status") == "non_compliant"
                    ]),
                    "security_posture_score": security_metrics.get("security_posture_score", 100),
                    "trend_direction": "stable"  # Would be calculated from historical data
                },
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
            return posture_summary
            
        except Exception as e:
            self.logger.error(f"Error generating security posture summary: {str(e)}")
            raise


# Utility functions for report generation
def create_security_report_generator(
    redis_url: Optional[str] = None,
    app: Optional[Flask] = None
) -> SecurityReportGenerator:
    """
    Factory function to create SecurityReportGenerator with proper configuration.
    
    Args:
        redis_url: Redis connection URL for caching and trend storage
        app: Flask application instance for security testing
        
    Returns:
        Configured SecurityReportGenerator instance
    """
    redis_client = None
    if redis_url:
        try:
            redis_client = redis.from_url(redis_url)
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {str(e)}")
    
    return SecurityReportGenerator(
        redis_client=redis_client,
        app=app
    )


async def generate_security_report_cli(
    output_file: Optional[str] = None,
    report_format: str = SecurityReportFormat.JSON,
    include_trends: bool = True
) -> None:
    """
    CLI function for generating security reports.
    
    Args:
        output_file: Output file path (default: stdout)
        report_format: Report format (json, html, csv)
        include_trends: Whether to include trend analysis
    """
    try:
        # Create report generator
        generator = create_security_report_generator()
        
        # Generate report
        report = await generator.generate_consolidated_report(
            report_format=report_format,
            include_trends=include_trends
        )
        
        # Output report
        if report_format == SecurityReportFormat.JSON:
            output = json.dumps(report, indent=2)
        else:
            output = str(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"Security report written to {output_file}")
        else:
            print(output)
            
    except Exception as e:
        print(f"Error generating security report: {str(e)}")
        raise


# Export key classes and functions
__all__ = [
    'SecurityReportGenerator',
    'SecurityFinding',
    'SecuritySeverity',
    'SecurityComplianceFramework',
    'SecurityReportFormat',
    'create_security_report_generator',
    'generate_security_report_cli'
]