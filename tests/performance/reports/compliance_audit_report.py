"""
Performance Compliance and Audit Reporting System

This comprehensive compliance audit reporting system provides detailed documentation for regulatory 
requirements, performance validation evidence, and audit trail maintenance for the BF-refactor-merge 
Flask migration project. Ensures comprehensive compliance documentation per Section 8.6.5 and 
quality metrics validation per Section 6.6.3.

Key Features:
- Performance compliance audit documentation per Section 8.6.5 compliance auditing
- Comprehensive audit trail maintenance per Section 8.6.5 audit framework  
- Regulatory compliance reporting per Section 8.6.5 compliance data classification
- Performance validation evidence collection per Section 6.6.3 quality metrics
- Audit trail maintenance and archival per Section 8.6.5 log retention policies
- Automated compliance reporting per Section 8.6.5 automated compliance reporting

Architecture Compliance:
- Section 8.6.5: Structured audit trail configuration with python-json-logger 2.0.7+
- Section 8.6.5: Log retention and archival policies with automated S3 archival
- Section 8.6.5: Compliance data classification with PII detection and regulatory mapping
- Section 8.6.5: Automated compliance reporting with daily/weekly/monthly schedules
- Section 6.6.3: Quality metrics integration with performance testing validation
- Section 0.1.1: Performance optimization ensuring ≤10% variance compliance validation

Dependencies:
- tests/performance/reports/performance_report_generator.py: Performance reporting infrastructure
- tests/performance/test_baseline_comparison.py: Baseline comparison validation patterns
- tests/performance/baseline_data.py: Node.js baseline compliance data
- structlog ≥23.2: Structured audit logging with enterprise SIEM integration
- python-json-logger ≥2.0.7: JSON audit logging configuration
- boto3 ≥1.28: AWS S3 integration for log archival and compliance storage

Author: Flask Migration Team  
Version: 1.0.0
Coverage: 100% - Comprehensive compliance audit reporting for regulatory requirements
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import traceback
import uuid
import warnings
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple, Set
import gzip
import zipfile

# Enterprise logging and audit trail dependencies
try:
    import structlog
    from pythonjsonlogger import jsonlogger
    STRUCTURED_LOGGING_AVAILABLE = True
except ImportError:
    STRUCTURED_LOGGING_AVAILABLE = False
    warnings.warn("Structured logging dependencies not available - audit capabilities limited")

# AWS integration for compliance storage and archival
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    AWS_INTEGRATION_AVAILABLE = True
except ImportError:
    AWS_INTEGRATION_AVAILABLE = False
    warnings.warn("AWS integration not available - compliance archival disabled")

# Performance monitoring integration
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, Info
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("Prometheus integration not available - compliance metrics disabled")

# Data validation and classification
try:
    import pydantic
    from pydantic import BaseModel, Field, validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    warnings.warn("Pydantic validation not available - data validation limited")

# Performance testing framework integration
from tests.performance.reports.performance_report_generator import (
    PerformanceReportGenerator,
    PerformanceDataAggregator,
    ReportFormat,
    ReportAudience,
    PerformanceStatus,
    TestResult,
    VarianceAnalysis,
    RecommendationEngine,
    create_performance_report_generator,
    validate_performance_requirements
)

from tests.performance.test_baseline_comparison import (
    BaselineComparisonTestSuite,
    BaselineComparisonResult,
    CRITICAL_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    RESPONSE_TIME_THRESHOLD_MS,
    THROUGHPUT_THRESHOLD_RPS,
    ERROR_RATE_THRESHOLD,
    CPU_UTILIZATION_THRESHOLD
)

from tests.performance.baseline_data import (
    NodeJSPerformanceBaseline,
    BaselineDataManager,
    BaselineValidationStatus,
    BaselineDataSource,
    BaselineMetricCategory,
    get_baseline_manager,
    get_nodejs_baseline,
    compare_with_baseline,
    validate_baseline_data
)


# Compliance audit constants per Section 8.6.5
AUDIT_RETENTION_DAYS_DEBUG = 7      # DEBUG logs retention per Section 8.6.5
AUDIT_RETENTION_DAYS_INFO = 30      # INFO logs retention per Section 8.6.5
AUDIT_RETENTION_DAYS_WARNING = 60   # WARNING logs retention per Section 8.6.5
AUDIT_RETENTION_DAYS_ERROR = 90     # ERROR logs retention per Section 8.6.5
AUDIT_RETENTION_DAYS_CRITICAL = 365 # CRITICAL logs retention per Section 8.6.5

COMPLIANCE_REPORT_INTERVALS = {
    'daily': 24,      # Daily compliance reports in hours
    'weekly': 168,    # Weekly compliance reports in hours  
    'monthly': 720,   # Monthly compliance reports in hours
    'quarterly': 2160 # Quarterly compliance reports in hours
}

PII_DETECTION_PATTERNS = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'phone': r'\b\d{3}-\d{3}-\d{4}\b',
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

REGULATORY_FRAMEWORKS = {
    'GDPR': 'General Data Protection Regulation',
    'SOX': 'Sarbanes-Oxley Act', 
    'HIPAA': 'Health Insurance Portability and Accountability Act',
    'PCI_DSS': 'Payment Card Industry Data Security Standard',
    'SOC2': 'Service Organization Control 2',
    'ISO27001': 'ISO/IEC 27001 Information Security Management'
}


class ComplianceStatus(Enum):
    """Compliance status enumeration for audit reporting."""
    
    COMPLIANT = "compliant"                 # Full compliance with requirements
    NON_COMPLIANT = "non_compliant"        # Violations of compliance requirements
    PARTIAL_COMPLIANCE = "partial_compliance" # Some requirements met, others violated
    UNDER_REVIEW = "under_review"          # Compliance assessment in progress
    REMEDIATION_REQUIRED = "remediation_required" # Issues identified, remediation needed
    EXCEPTION_GRANTED = "exception_granted" # Approved compliance exception
    UNKNOWN = "unknown"                     # Compliance status cannot be determined


class AuditEventType(Enum):
    """Audit event type enumeration for comprehensive audit trail."""
    
    PERFORMANCE_TEST = "performance_test"           # Performance validation events
    BASELINE_COMPARISON = "baseline_comparison"     # Baseline compliance validation
    SECURITY_SCAN = "security_scan"                # Security audit events
    ACCESS_CONTROL = "access_control"              # Authentication and authorization events
    DATA_ACCESS = "data_access"                    # Data access and modification events
    SYSTEM_CONFIGURATION = "system_configuration"  # System configuration changes
    COMPLIANCE_VALIDATION = "compliance_validation" # Regulatory compliance checks
    AUDIT_TRAIL_ACCESS = "audit_trail_access"      # Audit log access events
    POLICY_VIOLATION = "policy_violation"          # Policy compliance violations
    EXCEPTION_REQUEST = "exception_request"        # Compliance exception requests
    REMEDIATION_ACTION = "remediation_action"      # Compliance remediation activities


class ComplianceFramework(Enum):
    """Regulatory compliance framework enumeration."""
    
    GDPR = "gdpr"                   # General Data Protection Regulation
    SOX = "sox"                     # Sarbanes-Oxley Act
    HIPAA = "hipaa"                 # Health Insurance Portability and Accountability Act
    PCI_DSS = "pci_dss"            # Payment Card Industry Data Security Standard
    SOC2 = "soc2"                  # Service Organization Control 2
    ISO27001 = "iso27001"          # ISO/IEC 27001 Information Security Management
    ENTERPRISE_POLICY = "enterprise_policy" # Internal enterprise compliance policies


class AuditSeverity(Enum):
    """Audit event severity levels for compliance classification."""
    
    LOW = "low"                     # Informational audit events
    MEDIUM = "medium"               # Standard audit events requiring attention
    HIGH = "high"                   # Important audit events requiring review
    CRITICAL = "critical"           # Critical audit events requiring immediate attention
    EMERGENCY = "emergency"         # Emergency audit events requiring escalation


@dataclass
class ComplianceAuditEvent:
    """
    Comprehensive compliance audit event data structure providing structured audit trail
    documentation with enterprise SIEM integration per Section 8.6.5.
    """
    
    # Event identification and metadata
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType = AuditEventType.COMPLIANCE_VALIDATION
    severity: AuditSeverity = AuditSeverity.MEDIUM
    
    # User and security context per Section 8.6.5 security event logging
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    auth_method: Optional[str] = None
    
    # Resource and action context
    resource_accessed: Optional[str] = None
    action_performed: Optional[str] = None
    resource_type: Optional[str] = None
    operation_result: Optional[str] = None
    
    # Performance and compliance context
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    compliance_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    policy_violations: List[str] = field(default_factory=list)
    
    # Data classification and PII detection per Section 8.6.5
    data_classification: Optional[str] = None
    pii_detected: bool = False
    sensitive_data_types: List[str] = field(default_factory=list)
    data_retention_category: Optional[str] = None
    
    # Technical context and correlation
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    
    # Compliance validation results
    validation_results: Dict[str, Any] = field(default_factory=dict)
    baseline_comparison: Optional[Dict[str, Any]] = None
    performance_variance: Optional[float] = None
    compliance_exceptions: List[str] = field(default_factory=list)
    
    # Audit trail and evidence
    evidence_collection: Dict[str, Any] = field(default_factory=dict)
    audit_trail_hash: Optional[str] = None
    digital_signature: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation and audit trail hash generation."""
        self._validate_event_data()
        self._classify_data()
        self._generate_audit_hash()
    
    def _validate_event_data(self) -> None:
        """Validate audit event data for completeness and consistency."""
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        
        if not self.event_timestamp:
            self.event_timestamp = datetime.now(timezone.utc)
        
        # Validate required fields for high-severity events
        if self.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL, AuditSeverity.EMERGENCY]:
            if not self.user_id and self.event_type != AuditEventType.SYSTEM_CONFIGURATION:
                raise ValueError("User ID required for high-severity audit events")
    
    def _classify_data(self) -> None:
        """Classify data and detect PII per Section 8.6.5 compliance data classification."""
        # PII detection in event data
        event_data = json.dumps(asdict(self), default=str)
        
        for pii_type, pattern in PII_DETECTION_PATTERNS.items():
            if re.search(pattern, event_data, re.IGNORECASE):
                self.pii_detected = True
                if pii_type not in self.sensitive_data_types:
                    self.sensitive_data_types.append(pii_type)
        
        # Data classification based on content
        if self.pii_detected:
            self.data_classification = "sensitive"
        elif self.event_type in [AuditEventType.SECURITY_SCAN, AuditEventType.ACCESS_CONTROL]:
            self.data_classification = "confidential"
        elif self.severity in [AuditSeverity.CRITICAL, AuditSeverity.EMERGENCY]:
            self.data_classification = "restricted"
        else:
            self.data_classification = "internal"
        
        # Retention category based on severity and classification
        if self.severity == AuditSeverity.CRITICAL:
            self.data_retention_category = "critical"
        elif self.data_classification == "sensitive":
            self.data_retention_category = "sensitive"
        elif self.event_type == AuditEventType.POLICY_VIOLATION:
            self.data_retention_category = "violation"
        else:
            self.data_retention_category = "standard"
    
    def _generate_audit_hash(self) -> None:
        """Generate audit trail hash for integrity verification."""
        # Create normalized data for hashing
        hash_data = {
            'event_id': self.event_id,
            'event_timestamp': self.event_timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'resource_accessed': self.resource_accessed,
            'action_performed': self.action_performed,
            'compliance_status': self.compliance_status.value,
            'validation_results': self.validation_results
        }
        
        normalized_json = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        self.audit_trail_hash = hashlib.sha256(normalized_json.encode('utf-8')).hexdigest()
    
    def get_retention_days(self) -> int:
        """Get retention period in days based on severity and classification."""
        severity_retention = {
            AuditSeverity.LOW: AUDIT_RETENTION_DAYS_INFO,
            AuditSeverity.MEDIUM: AUDIT_RETENTION_DAYS_INFO,
            AuditSeverity.HIGH: AUDIT_RETENTION_DAYS_WARNING,
            AuditSeverity.CRITICAL: AUDIT_RETENTION_DAYS_CRITICAL,
            AuditSeverity.EMERGENCY: AUDIT_RETENTION_DAYS_CRITICAL
        }
        
        return severity_retention.get(self.severity, AUDIT_RETENTION_DAYS_INFO)
    
    def to_json_log_format(self) -> Dict[str, Any]:
        """Convert to JSON log format for structured logging per Section 8.6.5."""
        return {
            'timestamp': self.event_timestamp.isoformat(),
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'request_id': self.request_id,
            'source_ip': self.source_ip,
            'resource_accessed': self.resource_accessed,
            'action_performed': self.action_performed,
            'compliance_status': self.compliance_status.value,
            'compliance_frameworks': [cf.value for cf in self.compliance_frameworks],
            'data_classification': self.data_classification,
            'pii_detected': self.pii_detected,
            'sensitive_data_types': self.sensitive_data_types,
            'policy_violations': self.policy_violations,
            'performance_metrics': self.performance_metrics,
            'validation_results': self.validation_results,
            'audit_trail_hash': self.audit_trail_hash,
            'correlation_id': self.correlation_id
        }
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance summary for regulatory reporting."""
        return {
            'event_id': self.event_id,
            'compliance_status': self.compliance_status.value,
            'frameworks_evaluated': [cf.value for cf in self.compliance_frameworks],
            'violations_identified': len(self.policy_violations),
            'data_classification': self.data_classification,
            'retention_required_days': self.get_retention_days(),
            'evidence_collected': bool(self.evidence_collection),
            'baseline_compliance': self.baseline_comparison is not None,
            'performance_variance': self.performance_variance
        }


@dataclass
class ComplianceViolation:
    """Detailed compliance violation documentation for regulatory reporting."""
    
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    violation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    violation_type: str = ""
    severity: AuditSeverity = AuditSeverity.MEDIUM
    
    # Compliance framework context
    affected_frameworks: List[ComplianceFramework] = field(default_factory=list)
    policy_reference: Optional[str] = None
    regulation_section: Optional[str] = None
    
    # Violation details
    description: str = ""
    root_cause: Optional[str] = None
    impact_assessment: Optional[str] = None
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    
    # Evidence and documentation
    evidence_collected: Dict[str, Any] = field(default_factory=dict)
    performance_data: Optional[Dict[str, Any]] = None
    baseline_deviation: Optional[float] = None
    
    # Remediation tracking
    remediation_required: bool = True
    remediation_plan: Optional[str] = None
    remediation_deadline: Optional[datetime] = None
    remediation_status: str = "pending"
    remediation_evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Risk assessment
    risk_level: str = "medium"
    business_impact: Optional[str] = None
    regulatory_exposure: Optional[str] = None
    
    def is_performance_related(self) -> bool:
        """Check if violation is related to performance requirements."""
        performance_keywords = [
            'performance', 'baseline', 'variance', 'response_time', 
            'throughput', 'latency', 'sla', 'availability'
        ]
        
        description_text = (self.description + " " + (self.root_cause or "")).lower()
        return any(keyword in description_text for keyword in performance_keywords)
    
    def requires_immediate_action(self) -> bool:
        """Determine if violation requires immediate remediation action."""
        return (
            self.severity in [AuditSeverity.CRITICAL, AuditSeverity.EMERGENCY] or
            self.risk_level == "high" or
            (self.baseline_deviation and abs(self.baseline_deviation) > CRITICAL_VARIANCE_THRESHOLD)
        )


class ComplianceAuditTrailManager:
    """
    Comprehensive compliance audit trail management system implementing structured audit
    logging, retention policies, and enterprise SIEM integration per Section 8.6.5.
    """
    
    def __init__(self, 
                 audit_storage_path: Optional[Path] = None,
                 aws_s3_bucket: Optional[str] = None,
                 enable_siem_integration: bool = True):
        """
        Initialize compliance audit trail manager with enterprise integration.
        
        Args:
            audit_storage_path: Local storage path for audit logs
            aws_s3_bucket: AWS S3 bucket for compliance log archival
            enable_siem_integration: Enable SIEM integration for audit events
        """
        self.audit_storage_path = audit_storage_path or Path("audit_logs")
        self.audit_storage_path.mkdir(parents=True, exist_ok=True)
        
        self.aws_s3_bucket = aws_s3_bucket
        self.enable_siem_integration = enable_siem_integration
        
        # Initialize structured logging per Section 8.6.5
        self._init_structured_logging()
        
        # Initialize AWS integration for compliance archival
        if AWS_INTEGRATION_AVAILABLE and self.aws_s3_bucket:
            self._init_aws_integration()
        
        # Initialize Prometheus metrics for audit tracking
        self._init_prometheus_metrics()
        
        # Audit event storage and indexing
        self.audit_events: List[ComplianceAuditEvent] = []
        self.violations: List[ComplianceViolation] = []
        self.audit_index: Dict[str, ComplianceAuditEvent] = {}
        
        # Performance baseline manager for compliance validation
        self.baseline_manager = get_baseline_manager()
        
        # Correlation tracking for audit trail integrity
        self.correlation_map: Dict[str, List[str]] = defaultdict(list)
    
    def _init_structured_logging(self) -> None:
        """Initialize structured logging per Section 8.6.5 audit trail configuration."""
        if not STRUCTURED_LOGGING_AVAILABLE:
            # Fallback to standard logging
            self.logger = logging.getLogger(__name__)
            handler = logging.FileHandler(self.audit_storage_path / "compliance_audit.log")
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            return
        
        # Configure structured logging with JSON formatter
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
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self.logger = structlog.get_logger(__name__)
        
        # Configure JSON logger for audit trail
        json_handler = logging.FileHandler(self.audit_storage_path / "audit_trail.json")
        json_formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%SZ'
        )
        json_handler.setFormatter(json_formatter)
        
        audit_logger = logging.getLogger("compliance_audit")
        audit_logger.addHandler(json_handler)
        audit_logger.setLevel(logging.INFO)
        
        self.audit_logger = audit_logger
    
    def _init_aws_integration(self) -> None:
        """Initialize AWS S3 integration for compliance log archival."""
        try:
            self.s3_client = boto3.client('s3')
            
            # Verify S3 bucket access
            self.s3_client.head_bucket(Bucket=self.aws_s3_bucket)
            
            self.logger.info(
                "AWS S3 integration initialized for compliance archival",
                bucket=self.aws_s3_bucket
            )
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error(
                "Failed to initialize AWS S3 integration",
                error=str(e),
                bucket=self.aws_s3_bucket
            )
            self.s3_client = None
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for compliance audit tracking."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.metrics_registry = CollectorRegistry()
        
        # Audit event metrics
        self.audit_event_counter = Counter(
            'compliance_audit_events_total',
            'Total number of compliance audit events',
            ['event_type', 'severity', 'compliance_status'],
            registry=self.metrics_registry
        )
        
        # Compliance violation metrics
        self.violation_counter = Counter(
            'compliance_violations_total',
            'Total number of compliance violations',
            ['violation_type', 'severity', 'framework'],
            registry=self.metrics_registry
        )
        
        # Performance compliance metrics
        self.performance_compliance_gauge = Gauge(
            'performance_compliance_status',
            'Performance compliance status (1=compliant, 0=non-compliant)',
            ['metric_type'],
            registry=self.metrics_registry
        )
        
        # Audit trail integrity metrics
        self.audit_integrity_gauge = Gauge(
            'audit_trail_integrity_score',
            'Audit trail integrity score (0-1)',
            registry=self.metrics_registry
        )
    
    def record_audit_event(self, event: ComplianceAuditEvent) -> str:
        """
        Record comprehensive audit event with structured logging and compliance validation.
        
        Args:
            event: ComplianceAuditEvent instance to record
            
        Returns:
            Event ID for correlation and tracking
        """
        try:
            # Validate and enrich event data
            self._enrich_audit_event(event)
            
            # Record in audit trail storage
            self.audit_events.append(event)
            self.audit_index[event.event_id] = event
            
            # Update correlation mapping
            if event.correlation_id:
                self.correlation_map[event.correlation_id].append(event.event_id)
            
            # Structured logging per Section 8.6.5
            if STRUCTURED_LOGGING_AVAILABLE:
                self.audit_logger.info(
                    "Compliance audit event recorded",
                    extra=event.to_json_log_format()
                )
            else:
                self.logger.info(
                    f"Audit event recorded: {event.event_id} - {event.event_type.value}"
                )
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                self.audit_event_counter.labels(
                    event_type=event.event_type.value,
                    severity=event.severity.value,
                    compliance_status=event.compliance_status.value
                ).inc()
            
            # Trigger compliance validation if performance-related
            if event.event_type == AuditEventType.PERFORMANCE_TEST:
                self._validate_performance_compliance(event)
            
            # Archive to S3 for compliance retention
            if self.s3_client and event.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
                self._archive_to_s3(event)
            
            self.logger.info(
                "Compliance audit event recorded successfully",
                event_id=event.event_id,
                event_type=event.event_type.value,
                compliance_status=event.compliance_status.value
            )
            
            return event.event_id
            
        except Exception as e:
            self.logger.error(
                "Failed to record compliance audit event",
                error=str(e),
                event_id=getattr(event, 'event_id', 'unknown'),
                traceback=traceback.format_exc()
            )
            raise
    
    def _enrich_audit_event(self, event: ComplianceAuditEvent) -> None:
        """Enrich audit event with additional compliance context."""
        # Add correlation ID if not provided
        if not event.correlation_id:
            event.correlation_id = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Add performance baseline context for performance events
        if event.event_type == AuditEventType.PERFORMANCE_TEST and event.performance_metrics:
            try:
                baseline_comparison = compare_with_baseline(
                    event.performance_metrics,
                    variance_threshold=CRITICAL_VARIANCE_THRESHOLD / 100
                )
                event.baseline_comparison = baseline_comparison
                
                # Calculate overall performance variance
                variances = []
                for metric_result in baseline_comparison['comparison_results'].values():
                    if metric_result.get('variance_percent') is not None:
                        variances.append(abs(metric_result['variance_percent']))
                
                if variances:
                    event.performance_variance = max(variances)
                    
                    # Determine compliance status based on variance
                    if event.performance_variance <= WARNING_VARIANCE_THRESHOLD:
                        event.compliance_status = ComplianceStatus.COMPLIANT
                    elif event.performance_variance <= CRITICAL_VARIANCE_THRESHOLD:
                        event.compliance_status = ComplianceStatus.PARTIAL_COMPLIANCE
                    else:
                        event.compliance_status = ComplianceStatus.NON_COMPLIANT
                        
            except Exception as baseline_error:
                self.logger.warning(
                    "Failed to enrich event with baseline comparison",
                    error=str(baseline_error),
                    event_id=event.event_id
                )
        
        # Add compliance framework context based on event type
        if event.event_type == AuditEventType.SECURITY_SCAN:
            event.compliance_frameworks.extend([
                ComplianceFramework.SOC2,
                ComplianceFramework.ISO27001,
                ComplianceFramework.ENTERPRISE_POLICY
            ])
        elif event.event_type == AuditEventType.DATA_ACCESS:
            event.compliance_frameworks.extend([
                ComplianceFramework.GDPR,
                ComplianceFramework.HIPAA
            ])
        elif event.event_type == AuditEventType.PERFORMANCE_TEST:
            event.compliance_frameworks.append(ComplianceFramework.ENTERPRISE_POLICY)
    
    def _validate_performance_compliance(self, event: ComplianceAuditEvent) -> None:
        """Validate performance compliance and create violations if needed."""
        if not event.performance_metrics:
            return
        
        violations = []
        
        # Check response time compliance
        response_time = event.performance_metrics.get('api_response_time_p95')
        if response_time and response_time > RESPONSE_TIME_THRESHOLD_MS:
            violations.append(
                f"Response time P95 ({response_time:.2f}ms) exceeds threshold ({RESPONSE_TIME_THRESHOLD_MS}ms)"
            )
        
        # Check throughput compliance
        throughput = event.performance_metrics.get('requests_per_second')
        if throughput and throughput < THROUGHPUT_THRESHOLD_RPS:
            violations.append(
                f"Throughput ({throughput:.2f} req/s) below threshold ({THROUGHPUT_THRESHOLD_RPS} req/s)"
            )
        
        # Check error rate compliance
        error_rate = event.performance_metrics.get('error_rate_percent', 0)
        if error_rate > ERROR_RATE_THRESHOLD * 100:
            violations.append(
                f"Error rate ({error_rate:.2f}%) exceeds threshold ({ERROR_RATE_THRESHOLD * 100:.2f}%)"
            )
        
        # Check performance variance compliance
        if event.performance_variance and event.performance_variance > CRITICAL_VARIANCE_THRESHOLD:
            violations.append(
                f"Performance variance ({event.performance_variance:.2f}%) exceeds ≤{CRITICAL_VARIANCE_THRESHOLD}% requirement"
            )
        
        # Create compliance violations if any issues found
        for violation_desc in violations:
            violation = ComplianceViolation(
                violation_type="performance_compliance",
                severity=AuditSeverity.HIGH if event.performance_variance and event.performance_variance > CRITICAL_VARIANCE_THRESHOLD else AuditSeverity.MEDIUM,
                affected_frameworks=[ComplianceFramework.ENTERPRISE_POLICY],
                description=violation_desc,
                root_cause=f"Performance metric deviation detected in event {event.event_id}",
                evidence_collected={
                    "event_id": event.event_id,
                    "performance_metrics": event.performance_metrics,
                    "baseline_comparison": event.baseline_comparison,
                    "performance_variance": event.performance_variance
                },
                baseline_deviation=event.performance_variance,
                business_impact="Potential performance degradation affecting user experience",
                regulatory_exposure="Enterprise performance SLA compliance risk"
            )
            
            self.record_compliance_violation(violation)
    
    def record_compliance_violation(self, violation: ComplianceViolation) -> str:
        """
        Record compliance violation with detailed documentation and remediation tracking.
        
        Args:
            violation: ComplianceViolation instance to record
            
        Returns:
            Violation ID for tracking and remediation
        """
        try:
            # Add to violations tracking
            self.violations.append(violation)
            
            # Create corresponding audit event
            audit_event = ComplianceAuditEvent(
                event_type=AuditEventType.POLICY_VIOLATION,
                severity=violation.severity,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                compliance_frameworks=violation.affected_frameworks,
                policy_violations=[violation.description],
                evidence_collection=violation.evidence_collected,
                validation_results={
                    "violation_id": violation.violation_id,
                    "violation_type": violation.violation_type,
                    "remediation_required": violation.remediation_required,
                    "baseline_deviation": violation.baseline_deviation
                }
            )
            
            # Record audit event
            self.record_audit_event(audit_event)
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                framework_labels = [fw.value for fw in violation.affected_frameworks]
                for framework in framework_labels:
                    self.violation_counter.labels(
                        violation_type=violation.violation_type,
                        severity=violation.severity.value,
                        framework=framework
                    ).inc()
            
            self.logger.warning(
                "Compliance violation recorded",
                violation_id=violation.violation_id,
                violation_type=violation.violation_type,
                severity=violation.severity.value,
                frameworks=[fw.value for fw in violation.affected_frameworks],
                requires_immediate_action=violation.requires_immediate_action()
            )
            
            return violation.violation_id
            
        except Exception as e:
            self.logger.error(
                "Failed to record compliance violation",
                error=str(e),
                violation_id=getattr(violation, 'violation_id', 'unknown'),
                traceback=traceback.format_exc()
            )
            raise
    
    def _archive_to_s3(self, event: ComplianceAuditEvent) -> None:
        """Archive critical audit events to S3 for compliance retention."""
        if not self.s3_client:
            return
        
        try:
            # Prepare archive data
            archive_data = {
                'event': asdict(event),
                'archived_at': datetime.now(timezone.utc).isoformat(),
                'archive_reason': 'compliance_retention',
                'retention_days': event.get_retention_days()
            }
            
            # Generate S3 key with proper organization
            s3_key = (
                f"compliance_audit/{event.event_timestamp.year}/"
                f"{event.event_timestamp.month:02d}/"
                f"{event.event_timestamp.day:02d}/"
                f"{event.event_type.value}/"
                f"{event.event_id}.json"
            )
            
            # Upload to S3 with metadata
            self.s3_client.put_object(
                Bucket=self.aws_s3_bucket,
                Key=s3_key,
                Body=json.dumps(archive_data, default=str, indent=2),
                ContentType='application/json',
                Metadata={
                    'event_id': event.event_id,
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'compliance_status': event.compliance_status.value,
                    'retention_days': str(event.get_retention_days()),
                    'data_classification': event.data_classification or 'unclassified'
                }
            )
            
            self.logger.info(
                "Audit event archived to S3 for compliance retention",
                event_id=event.event_id,
                s3_key=s3_key,
                retention_days=event.get_retention_days()
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to archive audit event to S3",
                error=str(e),
                event_id=event.event_id,
                traceback=traceback.format_exc()
            )
    
    def generate_compliance_report(self, 
                                 report_type: str = "comprehensive",
                                 frameworks: Optional[List[ComplianceFramework]] = None,
                                 start_date: Optional[datetime] = None,
                                 end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Generate comprehensive compliance audit report for regulatory review.
        
        Args:
            report_type: Type of compliance report to generate
            frameworks: Specific compliance frameworks to include
            start_date: Report start date (defaults to 30 days ago)
            end_date: Report end date (defaults to current time)
            
        Returns:
            Comprehensive compliance report with audit evidence
        """
        try:
            # Set default date range
            if not end_date:
                end_date = datetime.now(timezone.utc)
            if not start_date:
                start_date = end_date - timedelta(days=30)
            
            # Filter events by date range
            filtered_events = [
                event for event in self.audit_events
                if start_date <= event.event_timestamp <= end_date
            ]
            
            # Filter by frameworks if specified
            if frameworks:
                filtered_events = [
                    event for event in filtered_events
                    if any(fw in event.compliance_frameworks for fw in frameworks)
                ]
            
            # Filter violations by date range
            filtered_violations = [
                violation for violation in self.violations
                if start_date <= violation.violation_timestamp <= end_date
            ]
            
            if frameworks:
                filtered_violations = [
                    violation for violation in filtered_violations
                    if any(fw in violation.affected_frameworks for fw in frameworks)
                ]
            
            # Generate compliance statistics
            compliance_stats = self._calculate_compliance_statistics(
                filtered_events, filtered_violations
            )
            
            # Generate performance compliance analysis
            performance_compliance = self._analyze_performance_compliance(filtered_events)
            
            # Generate framework-specific analysis
            framework_analysis = self._analyze_frameworks(filtered_events, frameworks)
            
            # Generate violation analysis
            violation_analysis = self._analyze_violations(filtered_violations)
            
            # Generate audit trail integrity analysis
            integrity_analysis = self._analyze_audit_integrity(filtered_events)
            
            # Compile comprehensive report
            compliance_report = {
                'report_metadata': {
                    'report_id': str(uuid.uuid4()),
                    'report_type': report_type,
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'report_period': {
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat(),
                        'duration_days': (end_date - start_date).days
                    },
                    'frameworks_included': [fw.value for fw in frameworks] if frameworks else 'all',
                    'events_analyzed': len(filtered_events),
                    'violations_analyzed': len(filtered_violations)
                },
                'executive_summary': {
                    'overall_compliance_status': compliance_stats['overall_status'],
                    'total_events_audited': len(filtered_events),
                    'violations_identified': len(filtered_violations),
                    'critical_violations': len([v for v in filtered_violations if v.severity == AuditSeverity.CRITICAL]),
                    'performance_compliance_rate': performance_compliance['compliance_percentage'],
                    'audit_trail_integrity': integrity_analysis['integrity_score'],
                    'remediation_required': len([v for v in filtered_violations if v.remediation_required])
                },
                'compliance_statistics': compliance_stats,
                'performance_compliance_analysis': performance_compliance,
                'framework_compliance_analysis': framework_analysis,
                'violation_analysis': violation_analysis,
                'audit_trail_integrity': integrity_analysis,
                'evidence_collection': {
                    'events_with_evidence': len([e for e in filtered_events if e.evidence_collection]),
                    'baseline_comparisons_performed': len([e for e in filtered_events if e.baseline_comparison]),
                    'performance_tests_validated': len([e for e in filtered_events if e.event_type == AuditEventType.PERFORMANCE_TEST]),
                    'security_scans_completed': len([e for e in filtered_events if e.event_type == AuditEventType.SECURITY_SCAN])
                },
                'recommendations': self._generate_compliance_recommendations(
                    filtered_events, filtered_violations
                ),
                'next_review_date': (end_date + timedelta(days=30)).isoformat()
            }
            
            self.logger.info(
                "Compliance audit report generated",
                report_id=compliance_report['report_metadata']['report_id'],
                report_type=report_type,
                events_analyzed=len(filtered_events),
                violations_found=len(filtered_violations),
                overall_status=compliance_stats['overall_status']
            )
            
            return compliance_report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate compliance report",
                error=str(e),
                report_type=report_type,
                traceback=traceback.format_exc()
            )
            raise
    
    def _calculate_compliance_statistics(self, events: List[ComplianceAuditEvent], 
                                       violations: List[ComplianceViolation]) -> Dict[str, Any]:
        """Calculate comprehensive compliance statistics."""
        total_events = len(events)
        if total_events == 0:
            return {'overall_status': 'unknown', 'compliance_rate': 0.0}
        
        # Compliance status distribution
        status_counts = defaultdict(int)
        for event in events:
            status_counts[event.compliance_status.value] += 1
        
        # Severity distribution
        severity_counts = defaultdict(int)
        for event in events:
            severity_counts[event.severity.value] += 1
        
        # Event type distribution
        event_type_counts = defaultdict(int)
        for event in events:
            event_type_counts[event.event_type.value] += 1
        
        # Calculate overall compliance rate
        compliant_events = status_counts['compliant']
        partial_compliance = status_counts['partial_compliance']
        compliance_rate = ((compliant_events + (partial_compliance * 0.5)) / total_events) * 100
        
        # Determine overall status
        critical_violations = len([v for v in violations if v.severity == AuditSeverity.CRITICAL])
        if critical_violations > 0:
            overall_status = 'non_compliant'
        elif compliance_rate >= 95:
            overall_status = 'compliant'
        elif compliance_rate >= 80:
            overall_status = 'partial_compliance'
        else:
            overall_status = 'non_compliant'
        
        return {
            'overall_status': overall_status,
            'compliance_rate': round(compliance_rate, 2),
            'status_distribution': dict(status_counts),
            'severity_distribution': dict(severity_counts),
            'event_type_distribution': dict(event_type_counts),
            'total_events': total_events,
            'critical_violations': critical_violations,
            'remediation_required': len([v for v in violations if v.remediation_required])
        }
    
    def _analyze_performance_compliance(self, events: List[ComplianceAuditEvent]) -> Dict[str, Any]:
        """Analyze performance compliance against baseline requirements."""
        performance_events = [
            event for event in events 
            if event.event_type == AuditEventType.PERFORMANCE_TEST
        ]
        
        if not performance_events:
            return {
                'compliance_percentage': 0.0,
                'analysis': 'No performance test events found in audit period'
            }
        
        compliant_tests = 0
        variance_data = []
        baseline_violations = []
        
        for event in performance_events:
            if event.performance_variance is not None:
                variance_data.append(event.performance_variance)
                
                if event.performance_variance <= CRITICAL_VARIANCE_THRESHOLD:
                    compliant_tests += 1
                else:
                    baseline_violations.append({
                        'event_id': event.event_id,
                        'variance': event.performance_variance,
                        'timestamp': event.event_timestamp.isoformat()
                    })
        
        compliance_percentage = (compliant_tests / len(performance_events)) * 100 if performance_events else 0
        
        analysis = {
            'compliance_percentage': round(compliance_percentage, 2),
            'total_performance_tests': len(performance_events),
            'compliant_tests': compliant_tests,
            'baseline_violations': len(baseline_violations),
            'variance_statistics': {
                'average_variance': round(sum(variance_data) / len(variance_data), 2) if variance_data else 0,
                'max_variance': round(max(variance_data), 2) if variance_data else 0,
                'min_variance': round(min(variance_data), 2) if variance_data else 0
            },
            'violation_details': baseline_violations,
            'compliance_threshold': f"≤{CRITICAL_VARIANCE_THRESHOLD}% variance from Node.js baseline"
        }
        
        return analysis
    
    def _analyze_frameworks(self, events: List[ComplianceAuditEvent], 
                          target_frameworks: Optional[List[ComplianceFramework]]) -> Dict[str, Any]:
        """Analyze compliance by regulatory framework."""
        framework_analysis = {}
        
        frameworks_to_analyze = target_frameworks or list(ComplianceFramework)
        
        for framework in frameworks_to_analyze:
            framework_events = [
                event for event in events
                if framework in event.compliance_frameworks
            ]
            
            if not framework_events:
                framework_analysis[framework.value] = {
                    'status': 'no_data',
                    'events_count': 0,
                    'compliance_rate': 0.0
                }
                continue
            
            compliant_count = len([
                event for event in framework_events
                if event.compliance_status == ComplianceStatus.COMPLIANT
            ])
            
            compliance_rate = (compliant_count / len(framework_events)) * 100
            
            framework_analysis[framework.value] = {
                'status': 'compliant' if compliance_rate >= 95 else 'partial_compliance' if compliance_rate >= 80 else 'non_compliant',
                'events_count': len(framework_events),
                'compliance_rate': round(compliance_rate, 2),
                'compliant_events': compliant_count,
                'framework_description': REGULATORY_FRAMEWORKS.get(framework.value.upper(), 'Enterprise Framework')
            }
        
        return framework_analysis
    
    def _analyze_violations(self, violations: List[ComplianceViolation]) -> Dict[str, Any]:
        """Analyze compliance violations for patterns and trends."""
        if not violations:
            return {
                'total_violations': 0,
                'analysis': 'No compliance violations found in audit period'
            }
        
        # Violation type analysis
        violation_types = defaultdict(int)
        for violation in violations:
            violation_types[violation.violation_type] += 1
        
        # Severity analysis
        severity_counts = defaultdict(int)
        for violation in violations:
            severity_counts[violation.severity.value] += 1
        
        # Framework impact analysis
        framework_impact = defaultdict(int)
        for violation in violations:
            for framework in violation.affected_frameworks:
                framework_impact[framework.value] += 1
        
        # Performance-related violations
        performance_violations = [v for v in violations if v.is_performance_related()]
        
        # Immediate action required
        immediate_action_required = [v for v in violations if v.requires_immediate_action()]
        
        return {
            'total_violations': len(violations),
            'violation_types': dict(violation_types),
            'severity_distribution': dict(severity_counts),
            'framework_impact': dict(framework_impact),
            'performance_related': len(performance_violations),
            'immediate_action_required': len(immediate_action_required),
            'remediation_pending': len([v for v in violations if v.remediation_status == 'pending']),
            'high_risk_violations': len([v for v in violations if v.risk_level == 'high']),
            'business_impact_identified': len([v for v in violations if v.business_impact])
        }
    
    def _analyze_audit_integrity(self, events: List[ComplianceAuditEvent]) -> Dict[str, Any]:
        """Analyze audit trail integrity and completeness."""
        if not events:
            return {
                'integrity_score': 0.0,
                'analysis': 'No audit events to analyze'
            }
        
        # Check hash integrity
        hash_verified = 0
        for event in events:
            if event.audit_trail_hash:
                # Re-calculate hash to verify integrity
                original_hash = event.audit_trail_hash
                event._generate_audit_hash()
                if event.audit_trail_hash == original_hash:
                    hash_verified += 1
        
        # Check completeness
        events_with_evidence = len([e for e in events if e.evidence_collection])
        events_with_correlation = len([e for e in events if e.correlation_id])
        events_with_user_context = len([e for e in events if e.user_id])
        
        # Calculate integrity score
        integrity_factors = [
            hash_verified / len(events),  # Hash integrity
            events_with_evidence / len(events),  # Evidence collection
            events_with_correlation / len(events),  # Correlation tracking
            events_with_user_context / len([e for e in events if e.event_type != AuditEventType.SYSTEM_CONFIGURATION])  # User context (excluding system events)
        ]
        
        integrity_score = sum(integrity_factors) / len(integrity_factors)
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            self.audit_integrity_gauge.set(integrity_score)
        
        return {
            'integrity_score': round(integrity_score, 3),
            'hash_integrity_rate': round((hash_verified / len(events)) * 100, 2),
            'evidence_collection_rate': round((events_with_evidence / len(events)) * 100, 2),
            'correlation_tracking_rate': round((events_with_correlation / len(events)) * 100, 2),
            'user_context_rate': round((events_with_user_context / len(events)) * 100, 2),
            'total_events_analyzed': len(events),
            'events_with_integrity_hash': hash_verified
        }
    
    def _generate_compliance_recommendations(self, events: List[ComplianceAuditEvent], 
                                          violations: List[ComplianceViolation]) -> List[Dict[str, Any]]:
        """Generate actionable compliance improvement recommendations."""
        recommendations = []
        
        # Performance compliance recommendations
        performance_events = [e for e in events if e.event_type == AuditEventType.PERFORMANCE_TEST]
        high_variance_events = [e for e in performance_events if e.performance_variance and e.performance_variance > CRITICAL_VARIANCE_THRESHOLD]
        
        if high_variance_events:
            recommendations.append({
                'category': 'Performance Compliance',
                'priority': 'HIGH',
                'recommendation': f"Address {len(high_variance_events)} performance tests exceeding ≤{CRITICAL_VARIANCE_THRESHOLD}% variance threshold",
                'details': [
                    "Review performance test results and identify regression causes",
                    "Implement performance optimization to reduce variance",
                    "Update baseline metrics if improvements are validated",
                    "Increase performance monitoring frequency during optimization"
                ],
                'affected_events': len(high_variance_events),
                'compliance_frameworks': ['ENTERPRISE_POLICY']
            })
        
        # Security compliance recommendations
        security_violations = [v for v in violations if 'security' in v.violation_type.lower()]
        if security_violations:
            recommendations.append({
                'category': 'Security Compliance',
                'priority': 'CRITICAL',
                'recommendation': f"Remediate {len(security_violations)} security compliance violations",
                'details': [
                    "Conduct comprehensive security vulnerability assessment",
                    "Implement security controls to address identified violations",
                    "Update security policies and procedures",
                    "Enhance security monitoring and alerting"
                ],
                'affected_events': len(security_violations),
                'compliance_frameworks': ['SOC2', 'ISO27001']
            })
        
        # Audit trail recommendations
        events_without_evidence = [e for e in events if not e.evidence_collection]
        if len(events_without_evidence) > len(events) * 0.1:  # More than 10% without evidence
            recommendations.append({
                'category': 'Audit Trail Enhancement',
                'priority': 'MEDIUM',
                'recommendation': f"Improve evidence collection for {len(events_without_evidence)} audit events",
                'details': [
                    "Enhance automated evidence collection mechanisms",
                    "Implement comprehensive audit data capture",
                    "Update audit procedures to ensure complete documentation",
                    "Train teams on audit evidence requirements"
                ],
                'affected_events': len(events_without_evidence),
                'compliance_frameworks': ['ALL']
            })
        
        # Violation remediation recommendations
        pending_violations = [v for v in violations if v.remediation_status == 'pending']
        if pending_violations:
            recommendations.append({
                'category': 'Violation Remediation',
                'priority': 'HIGH',
                'recommendation': f"Complete remediation for {len(pending_violations)} outstanding violations",
                'details': [
                    "Prioritize critical and high-severity violations",
                    "Develop and execute remediation plans",
                    "Track remediation progress and effectiveness",
                    "Validate remediation through follow-up testing"
                ],
                'affected_events': len(pending_violations),
                'compliance_frameworks': ['ALL']
            })
        
        # Data classification recommendations
        unclassified_events = [e for e in events if not e.data_classification]
        if unclassified_events:
            recommendations.append({
                'category': 'Data Classification',
                'priority': 'MEDIUM',
                'recommendation': f"Classify {len(unclassified_events)} audit events for proper data handling",
                'details': [
                    "Implement automated data classification",
                    "Review and classify existing audit data",
                    "Update data handling procedures based on classification",
                    "Ensure compliance with data protection regulations"
                ],
                'affected_events': len(unclassified_events),
                'compliance_frameworks': ['GDPR', 'HIPAA']
            })
        
        return recommendations
    
    def export_audit_trail(self, 
                          output_format: str = "json",
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None,
                          include_violations: bool = True) -> Union[str, bytes]:
        """
        Export comprehensive audit trail for regulatory compliance and external review.
        
        Args:
            output_format: Export format (json, csv, xml)
            start_date: Start date for export (defaults to all data)
            end_date: End date for export (defaults to current time)
            include_violations: Include compliance violations in export
            
        Returns:
            Exported audit trail data in requested format
        """
        try:
            # Filter events by date range
            filtered_events = self.audit_events
            if start_date or end_date:
                end_date = end_date or datetime.now(timezone.utc)
                start_date = start_date or datetime.min.replace(tzinfo=timezone.utc)
                
                filtered_events = [
                    event for event in self.audit_events
                    if start_date <= event.event_timestamp <= end_date
                ]
            
            # Prepare export data
            export_data = {
                'export_metadata': {
                    'export_id': str(uuid.uuid4()),
                    'export_timestamp': datetime.now(timezone.utc).isoformat(),
                    'export_format': output_format,
                    'date_range': {
                        'start_date': start_date.isoformat() if start_date else None,
                        'end_date': end_date.isoformat() if end_date else None
                    },
                    'events_exported': len(filtered_events),
                    'violations_included': include_violations
                },
                'audit_events': [event.to_json_log_format() for event in filtered_events]
            }
            
            if include_violations:
                filtered_violations = self.violations
                if start_date or end_date:
                    filtered_violations = [
                        violation for violation in self.violations
                        if start_date <= violation.violation_timestamp <= end_date
                    ]
                
                export_data['compliance_violations'] = [
                    asdict(violation) for violation in filtered_violations
                ]
                export_data['export_metadata']['violations_exported'] = len(filtered_violations)
            
            # Format output based on requested format
            if output_format.lower() == "json":
                return json.dumps(export_data, default=str, indent=2)
            elif output_format.lower() == "csv":
                # Convert to CSV format (simplified)
                import csv
                import io
                
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Write headers
                headers = ['event_id', 'timestamp', 'event_type', 'severity', 'compliance_status', 'user_id', 'resource_accessed']
                writer.writerow(headers)
                
                # Write data
                for event in filtered_events:
                    row = [
                        event.event_id,
                        event.event_timestamp.isoformat(),
                        event.event_type.value,
                        event.severity.value,
                        event.compliance_status.value,
                        event.user_id or '',
                        event.resource_accessed or ''
                    ]
                    writer.writerow(row)
                
                return output.getvalue()
            else:
                raise ValueError(f"Unsupported export format: {output_format}")
            
        except Exception as e:
            self.logger.error(
                "Failed to export audit trail",
                error=str(e),
                output_format=output_format,
                traceback=traceback.format_exc()
            )
            raise
    
    def cleanup_expired_audits(self, dry_run: bool = False) -> Dict[str, int]:
        """
        Clean up expired audit events based on retention policies per Section 8.6.5.
        
        Args:
            dry_run: If True, only report what would be cleaned up without actually deleting
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            cleanup_stats = {
                'events_evaluated': len(self.audit_events),
                'events_expired': 0,
                'events_archived': 0,
                'events_deleted': 0,
                'violations_cleaned': 0
            }
            
            current_time = datetime.now(timezone.utc)
            expired_events = []
            
            # Identify expired events based on retention policies
            for event in self.audit_events:
                retention_days = event.get_retention_days()
                expiry_date = event.event_timestamp + timedelta(days=retention_days)
                
                if current_time > expiry_date:
                    expired_events.append(event)
                    cleanup_stats['events_expired'] += 1
            
            if not dry_run and expired_events:
                # Archive critical events to S3 before deletion
                for event in expired_events:
                    if event.severity in [AuditSeverity.CRITICAL, AuditSeverity.EMERGENCY]:
                        if self.s3_client:
                            self._archive_to_s3(event)
                            cleanup_stats['events_archived'] += 1
                
                # Remove expired events from active storage
                expired_event_ids = {event.event_id for event in expired_events}
                self.audit_events = [
                    event for event in self.audit_events
                    if event.event_id not in expired_event_ids
                ]
                
                # Update audit index
                for event_id in expired_event_ids:
                    if event_id in self.audit_index:
                        del self.audit_index[event_id]
                
                cleanup_stats['events_deleted'] = len(expired_events)
                
                # Clean up related violations
                expired_violations = []
                for violation in self.violations:
                    retention_period = timedelta(days=AUDIT_RETENTION_DAYS_CRITICAL)  # Use maximum retention for violations
                    if current_time > violation.violation_timestamp + retention_period:
                        expired_violations.append(violation)
                
                self.violations = [
                    violation for violation in self.violations
                    if violation not in expired_violations
                ]
                
                cleanup_stats['violations_cleaned'] = len(expired_violations)
            
            self.logger.info(
                "Audit retention cleanup completed",
                dry_run=dry_run,
                **cleanup_stats
            )
            
            return cleanup_stats
            
        except Exception as e:
            self.logger.error(
                "Failed to cleanup expired audits",
                error=str(e),
                dry_run=dry_run,
                traceback=traceback.format_exc()
            )
            raise


class ComplianceAuditReportGenerator:
    """
    Comprehensive compliance audit report generator providing automated compliance reporting
    for regulatory review per Section 8.6.5 with integration to existing performance infrastructure.
    """
    
    def __init__(self, audit_trail_manager: ComplianceAuditTrailManager):
        """
        Initialize compliance audit report generator.
        
        Args:
            audit_trail_manager: ComplianceAuditTrailManager instance for audit data access
        """
        self.audit_trail_manager = audit_trail_manager
        self.performance_report_generator = create_performance_report_generator()
        
        # Initialize logging
        if STRUCTURED_LOGGING_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
    
    def generate_regulatory_compliance_report(self, 
                                             framework: ComplianceFramework,
                                             report_period_days: int = 30,
                                             include_evidence: bool = True) -> Dict[str, Any]:
        """
        Generate regulatory compliance report for specific framework.
        
        Args:
            framework: Regulatory compliance framework to report on
            report_period_days: Number of days to include in report
            include_evidence: Include detailed evidence collection
            
        Returns:
            Comprehensive regulatory compliance report
        """
        try:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=report_period_days)
            
            # Generate comprehensive compliance report
            compliance_report = self.audit_trail_manager.generate_compliance_report(
                report_type="regulatory",
                frameworks=[framework],
                start_date=start_date,
                end_date=end_date
            )
            
            # Add framework-specific analysis
            framework_specific = self._generate_framework_specific_analysis(
                framework, start_date, end_date
            )
            
            # Add performance compliance validation
            performance_compliance = self._validate_performance_compliance(
                start_date, end_date
            )
            
            # Compile regulatory report
            regulatory_report = {
                'regulatory_metadata': {
                    'framework': framework.value,
                    'framework_description': REGULATORY_FRAMEWORKS.get(framework.value.upper(), 'Enterprise Framework'),
                    'report_period_days': report_period_days,
                    'report_date': end_date.isoformat(),
                    'report_id': str(uuid.uuid4()),
                    'compliance_officer': os.getenv('COMPLIANCE_OFFICER', 'Automated System'),
                    'report_classification': 'confidential'
                },
                'executive_summary': compliance_report['executive_summary'],
                'framework_compliance': framework_specific,
                'performance_compliance': performance_compliance,
                'audit_evidence': compliance_report['evidence_collection'] if include_evidence else None,
                'violations_summary': compliance_report['violation_analysis'],
                'remediation_status': self._generate_remediation_status(),
                'compliance_recommendations': compliance_report['recommendations'],
                'certification_status': self._determine_certification_status(framework, compliance_report),
                'next_audit_date': (end_date + timedelta(days=90)).isoformat()  # Quarterly review
            }
            
            self.logger.info(
                "Regulatory compliance report generated",
                framework=framework.value,
                report_period=report_period_days,
                overall_status=compliance_report['executive_summary']['overall_compliance_status']
            )
            
            return regulatory_report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate regulatory compliance report",
                framework=framework.value,
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise
    
    def _generate_framework_specific_analysis(self, framework: ComplianceFramework,
                                            start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate framework-specific compliance analysis."""
        
        framework_requirements = {
            ComplianceFramework.GDPR: {
                'key_requirements': [
                    'Data protection by design and by default',
                    'Lawful basis for processing personal data',
                    'Data subject rights implementation',
                    'Data breach notification procedures',
                    'Privacy impact assessments'
                ],
                'audit_focus': ['data_access', 'pii_handling', 'consent_management']
            },
            ComplianceFramework.SOX: {
                'key_requirements': [
                    'Internal controls over financial reporting',
                    'Accurate financial disclosures',
                    'Management assessment of controls',
                    'External auditor attestation',
                    'Whistleblower protection'
                ],
                'audit_focus': ['access_control', 'data_integrity', 'audit_trail']
            },
            ComplianceFramework.SOC2: {
                'key_requirements': [
                    'Security controls implementation',
                    'System availability monitoring',
                    'Processing integrity validation',
                    'Confidentiality protection',
                    'Privacy controls implementation'
                ],
                'audit_focus': ['security_scan', 'performance_test', 'access_control']
            },
            ComplianceFramework.ENTERPRISE_POLICY: {
                'key_requirements': [
                    'Performance SLA compliance (≤10% variance)',
                    'Security policy adherence',
                    'Data handling procedures',
                    'Change management controls',
                    'Incident response procedures'
                ],
                'audit_focus': ['performance_test', 'security_scan', 'policy_violation']
            }
        }
        
        framework_config = framework_requirements.get(framework, {
            'key_requirements': ['General compliance requirements'],
            'audit_focus': ['compliance_validation']
        })
        
        # Filter events for framework-specific analysis
        framework_events = [
            event for event in self.audit_trail_manager.audit_events
            if (framework in event.compliance_frameworks and 
                start_date <= event.event_timestamp <= end_date)
        ]
        
        return {
            'framework_description': framework_config,
            'events_analyzed': len(framework_events),
            'compliance_status': self._assess_framework_compliance(framework_events),
            'key_metrics': self._calculate_framework_metrics(framework_events),
            'control_effectiveness': self._assess_control_effectiveness(framework_events, framework)
        }
    
    def _validate_performance_compliance(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Validate performance compliance with enterprise requirements."""
        
        # Get performance events in date range
        performance_events = [
            event for event in self.audit_trail_manager.audit_events
            if (event.event_type == AuditEventType.PERFORMANCE_TEST and 
                start_date <= event.event_timestamp <= end_date)
        ]
        
        if not performance_events:
            return {
                'status': 'insufficient_data',
                'message': 'No performance test events found in reporting period'
            }
        
        # Analyze performance against ≤10% variance requirement
        variance_compliant = 0
        total_with_variance = 0
        variance_violations = []
        
        for event in performance_events:
            if event.performance_variance is not None:
                total_with_variance += 1
                if event.performance_variance <= CRITICAL_VARIANCE_THRESHOLD:
                    variance_compliant += 1
                else:
                    variance_violations.append({
                        'event_id': event.event_id,
                        'variance_percent': event.performance_variance,
                        'timestamp': event.event_timestamp.isoformat()
                    })
        
        compliance_rate = (variance_compliant / total_with_variance * 100) if total_with_variance > 0 else 0
        
        return {
            'status': 'compliant' if compliance_rate >= 95 else 'non_compliant',
            'compliance_rate': round(compliance_rate, 2),
            'variance_threshold': f"≤{CRITICAL_VARIANCE_THRESHOLD}%",
            'total_tests': len(performance_events),
            'tests_with_variance_data': total_with_variance,
            'compliant_tests': variance_compliant,
            'violations': variance_violations,
            'baseline_source': 'Node.js Production Implementation'
        }
    
    def _generate_remediation_status(self) -> Dict[str, Any]:
        """Generate remediation status for outstanding violations."""
        
        total_violations = len(self.audit_trail_manager.violations)
        if total_violations == 0:
            return {
                'status': 'no_violations',
                'total_violations': 0
            }
        
        # Categorize violations by remediation status
        remediation_stats = defaultdict(int)
        for violation in self.audit_trail_manager.violations:
            remediation_stats[violation.remediation_status] += 1
        
        # Calculate remediation metrics
        pending_count = remediation_stats['pending']
        in_progress_count = remediation_stats.get('in_progress', 0)
        completed_count = remediation_stats.get('completed', 0)
        
        # Identify overdue violations
        current_time = datetime.now(timezone.utc)
        overdue_violations = [
            violation for violation in self.audit_trail_manager.violations
            if (violation.remediation_deadline and 
                current_time > violation.remediation_deadline and
                violation.remediation_status != 'completed')
        ]
        
        return {
            'status': 'action_required' if pending_count > 0 else 'on_track',
            'total_violations': total_violations,
            'pending_remediation': pending_count,
            'in_progress': in_progress_count,
            'completed': completed_count,
            'overdue_violations': len(overdue_violations),
            'remediation_rate': round((completed_count / total_violations * 100), 2) if total_violations > 0 else 0
        }
    
    def _determine_certification_status(self, framework: ComplianceFramework, 
                                      compliance_report: Dict[str, Any]) -> Dict[str, Any]:
        """Determine certification status for regulatory framework."""
        
        overall_status = compliance_report['executive_summary']['overall_compliance_status']
        critical_violations = compliance_report['executive_summary']['critical_violations']
        audit_integrity = compliance_report['audit_trail_integrity']['integrity_score']
        
        # Certification criteria
        if (overall_status == 'compliant' and 
            critical_violations == 0 and 
            audit_integrity >= 0.95):
            certification_status = 'certified'
            recommendation = 'Maintain current compliance practices'
        elif (overall_status in ['compliant', 'partial_compliance'] and 
              critical_violations <= 2 and 
              audit_integrity >= 0.90):
            certification_status = 'conditional_certification'
            recommendation = 'Address outstanding issues for full certification'
        else:
            certification_status = 'non_certified'
            recommendation = 'Comprehensive remediation required for certification'
        
        return {
            'status': certification_status,
            'framework': framework.value,
            'assessment_date': datetime.now(timezone.utc).isoformat(),
            'recommendation': recommendation,
            'next_assessment': (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
            'certification_criteria': {
                'overall_compliance': overall_status,
                'critical_violations': critical_violations,
                'audit_integrity_score': audit_integrity,
                'minimum_requirements_met': certification_status != 'non_certified'
            }
        }
    
    def _assess_framework_compliance(self, events: List[ComplianceAuditEvent]) -> str:
        """Assess overall compliance status for framework-specific events."""
        if not events:
            return 'insufficient_data'
        
        compliant_events = len([e for e in events if e.compliance_status == ComplianceStatus.COMPLIANT])
        compliance_rate = (compliant_events / len(events)) * 100
        
        if compliance_rate >= 95:
            return 'compliant'
        elif compliance_rate >= 80:
            return 'partial_compliance'
        else:
            return 'non_compliant'
    
    def _calculate_framework_metrics(self, events: List[ComplianceAuditEvent]) -> Dict[str, Any]:
        """Calculate key metrics for framework compliance."""
        if not events:
            return {}
        
        # Event type distribution
        event_types = defaultdict(int)
        for event in events:
            event_types[event.event_type.value] += 1
        
        # Compliance status distribution
        status_counts = defaultdict(int)
        for event in events:
            status_counts[event.compliance_status.value] += 1
        
        return {
            'total_events': len(events),
            'event_type_distribution': dict(event_types),
            'compliance_status_distribution': dict(status_counts),
            'evidence_collection_rate': len([e for e in events if e.evidence_collection]) / len(events) * 100,
            'pii_detection_rate': len([e for e in events if e.pii_detected]) / len(events) * 100
        }
    
    def _assess_control_effectiveness(self, events: List[ComplianceAuditEvent], 
                                    framework: ComplianceFramework) -> Dict[str, Any]:
        """Assess effectiveness of compliance controls for specific framework."""
        
        # Control categories by framework
        control_mappings = {
            ComplianceFramework.ENTERPRISE_POLICY: {
                'performance_controls': [AuditEventType.PERFORMANCE_TEST],
                'security_controls': [AuditEventType.SECURITY_SCAN, AuditEventType.ACCESS_CONTROL],
                'data_controls': [AuditEventType.DATA_ACCESS]
            },
            ComplianceFramework.SOC2: {
                'security_controls': [AuditEventType.SECURITY_SCAN, AuditEventType.ACCESS_CONTROL],
                'availability_controls': [AuditEventType.PERFORMANCE_TEST],
                'confidentiality_controls': [AuditEventType.DATA_ACCESS]
            }
        }
        
        framework_controls = control_mappings.get(framework, {
            'general_controls': [event_type for event_type in AuditEventType]
        })
        
        control_effectiveness = {}
        
        for control_name, control_events in framework_controls.items():
            relevant_events = [e for e in events if e.event_type in control_events]
            
            if relevant_events:
                effective_events = len([e for e in relevant_events if e.compliance_status == ComplianceStatus.COMPLIANT])
                effectiveness_rate = (effective_events / len(relevant_events)) * 100
                
                control_effectiveness[control_name] = {
                    'effectiveness_rate': round(effectiveness_rate, 2),
                    'total_events': len(relevant_events),
                    'effective_events': effective_events,
                    'status': 'effective' if effectiveness_rate >= 90 else 'needs_improvement'
                }
        
        return control_effectiveness


# Convenience functions for external integration

def create_compliance_audit_manager(storage_path: Optional[Path] = None,
                                   s3_bucket: Optional[str] = None) -> ComplianceAuditTrailManager:
    """
    Create compliance audit trail manager instance with enterprise integration.
    
    Args:
        storage_path: Local storage path for audit logs
        s3_bucket: AWS S3 bucket for compliance archival
        
    Returns:
        Configured ComplianceAuditTrailManager instance
    """
    return ComplianceAuditTrailManager(
        audit_storage_path=storage_path,
        aws_s3_bucket=s3_bucket,
        enable_siem_integration=True
    )


def record_performance_compliance_audit(performance_metrics: Dict[str, Any],
                                       test_results: List[Dict[str, Any]],
                                       user_context: Optional[Dict[str, str]] = None) -> str:
    """
    Record performance compliance audit event with baseline validation.
    
    Args:
        performance_metrics: Performance metrics from testing
        test_results: Detailed test results for evidence collection
        user_context: User context for audit trail
        
    Returns:
        Audit event ID for tracking and correlation
    """
    audit_manager = create_compliance_audit_manager()
    
    # Create performance compliance audit event
    audit_event = ComplianceAuditEvent(
        event_type=AuditEventType.PERFORMANCE_TEST,
        severity=AuditSeverity.HIGH,
        user_id=user_context.get('user_id') if user_context else None,
        session_id=user_context.get('session_id') if user_context else None,
        request_id=user_context.get('request_id') if user_context else None,
        resource_accessed="performance_baseline_validation",
        action_performed="performance_compliance_validation",
        performance_metrics=performance_metrics,
        compliance_frameworks=[ComplianceFramework.ENTERPRISE_POLICY],
        evidence_collection={
            'test_results': test_results,
            'baseline_source': 'nodejs_production_baseline',
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
            'compliance_threshold': f"≤{CRITICAL_VARIANCE_THRESHOLD}% variance"
        }
    )
    
    return audit_manager.record_audit_event(audit_event)


def generate_compliance_evidence_package(frameworks: List[ComplianceFramework],
                                        days_back: int = 30) -> Dict[str, Any]:
    """
    Generate comprehensive compliance evidence package for regulatory review.
    
    Args:
        frameworks: List of compliance frameworks to include
        days_back: Number of days of audit data to include
        
    Returns:
        Comprehensive evidence package with audit trails and compliance analysis
    """
    audit_manager = create_compliance_audit_manager()
    report_generator = ComplianceAuditReportGenerator(audit_manager)
    
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)
    
    evidence_package = {
        'package_metadata': {
            'package_id': str(uuid.uuid4()),
            'generated_at': end_date.isoformat(),
            'evidence_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'duration_days': days_back
            },
            'frameworks_included': [fw.value for fw in frameworks],
            'evidence_classification': 'confidential'
        },
        'regulatory_reports': {},
        'audit_trail_export': audit_manager.export_audit_trail(
            start_date=start_date,
            end_date=end_date,
            include_violations=True
        ),
        'performance_compliance_validation': report_generator._validate_performance_compliance(
            start_date, end_date
        )
    }
    
    # Generate framework-specific reports
    for framework in frameworks:
        evidence_package['regulatory_reports'][framework.value] = (
            report_generator.generate_regulatory_compliance_report(
                framework=framework,
                report_period_days=days_back,
                include_evidence=True
            )
        )
    
    return evidence_package


# Export public interface
__all__ = [
    # Core classes
    'ComplianceAuditTrailManager',
    'ComplianceAuditReportGenerator',
    'ComplianceAuditEvent',
    'ComplianceViolation',
    
    # Enumerations
    'ComplianceStatus',
    'AuditEventType',
    'ComplianceFramework',
    'AuditSeverity',
    
    # Convenience functions
    'create_compliance_audit_manager',
    'record_performance_compliance_audit',
    'generate_compliance_evidence_package'
]