"""
Performance Reports Package Initialization

This module provides comprehensive performance report generation capabilities for the Flask 
migration project, implementing ≤10% variance threshold compliance reporting, baseline 
comparison analysis, and enterprise-grade performance documentation per technical 
specification requirements.

Key Features:
- Performance reporting framework initialization per Section 0.3.4 documentation requirements
- Report format and output configurations supporting JSON, Markdown, HTML, and CSV formats
- Common reporting utilities and constants per Section 6.6.3 quality metrics documentation
- Report versioning and metadata standards per Section 6.6.3 documentation requirements
- Report output directory management per Section 8.6.5 compliance auditing requirements
- ≤10% variance requirement validation and reporting per Section 0.1.1 primary objective
- Enterprise integration with Prometheus metrics and structured logging per Section 8.6.2

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.4: Documentation requirements for performance tuning and troubleshooting
- Section 6.6.3: Quality metrics documentation with historical trend analysis
- Section 8.6.2: Performance metrics collection and enterprise monitoring integration
- Section 8.6.5: Compliance auditing with structured logging and retention policies

Author: Flask Migration Team
Version: 1.0.0
Dependencies: structlog ≥23.1+, prometheus-client ≥0.17+, python-dateutil ≥2.8+
"""

import os
import sys
import time
import json
import csv
import hashlib
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, NamedTuple, Callable, TextIO
from dataclasses import dataclass, field, asdict
from enum import Enum
import warnings
import uuid
from collections import defaultdict

# Performance testing framework imports
try:
    from tests.performance import (
        PERFORMANCE_VARIANCE_THRESHOLD,
        NodeJSBaseline,
        PerformanceValidator,
        performance_framework
    )
    PERFORMANCE_FRAMEWORK_AVAILABLE = True
except ImportError:
    PERFORMANCE_FRAMEWORK_AVAILABLE = False
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10
    
    # Fallback NodeJS baseline placeholder
    class NodeJSBaseline:
        API_RESPONSE_TIMES = {'health_check': 50, 'api_get_users': 150}
        MEMORY_USAGE = {'average_mb': 256}
        CPU_UTILIZATION = {'baseline_percent': 15}

try:
    from tests.performance.performance_config import (
        PerformanceConfigFactory,
        BaselineMetrics,
        PerformanceThreshold,
        PerformanceTestType,
        generate_performance_report
    )
    PERFORMANCE_CONFIG_AVAILABLE = True
except ImportError:
    PERFORMANCE_CONFIG_AVAILABLE = False

# Structured logging import
try:
    import structlog
    logger = structlog.get_logger(__name__)
    STRUCTLOG_AVAILABLE = True
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    STRUCTLOG_AVAILABLE = False

# Date/time handling
try:
    from dateutil import tz, parser as date_parser
    from dateutil.relativedelta import relativedelta
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False
    import datetime as dt

# Prometheus metrics integration
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


# =============================================================================
# CORE REPORTING CONSTANTS - Section 0.3.4 Documentation Requirements
# =============================================================================

# Performance reporting configuration per Section 0.3.4
PERFORMANCE_REPORTS_VERSION = "1.0.0"
"""Performance reports package version per Section 6.6.3 versioning standards."""

PERFORMANCE_VARIANCE_THRESHOLD_PERCENT = PERFORMANCE_VARIANCE_THRESHOLD * 100
"""Performance variance threshold expressed as percentage for reporting (10%)."""

# Report format configurations per Section 0.3.4
SUPPORTED_REPORT_FORMATS = ['json', 'markdown', 'html', 'csv', 'xml']
"""Supported report output formats per Section 0.3.4 documentation requirements."""

DEFAULT_REPORT_FORMAT = 'json'
"""Default report format for automated systems integration."""

# Report output directory management per Section 8.6.5
DEFAULT_REPORTS_DIRECTORY = "tests/performance/reports/output"
"""Default directory for performance report output per Section 8.6.5 compliance."""

REPORTS_RETENTION_DAYS = 90
"""Report retention period per Section 8.6.5 compliance auditing (90 days)."""

ARCHIVE_REPORTS_AFTER_DAYS = 30
"""Archive reports to long-term storage after 30 days per Section 8.6.5."""

# Report versioning and metadata standards per Section 6.6.3
REPORT_SCHEMA_VERSION = "2.0"
"""Report schema version for compatibility validation."""

REPORT_METADATA_REQUIRED_FIELDS = [
    'report_id', 'generated_at', 'schema_version', 'environment',
    'performance_config', 'baseline_comparison', 'test_results'
]
"""Required metadata fields per Section 6.6.3 documentation requirements."""

# Performance thresholds for reporting per Section 0.1.1
VARIANCE_THRESHOLD_WARNING = 0.05  # 5% warning threshold
VARIANCE_THRESHOLD_CRITICAL = 0.08  # 8% critical threshold
VARIANCE_THRESHOLD_FAILURE = PERFORMANCE_VARIANCE_THRESHOLD  # 10% failure threshold

# Quality gates thresholds per Section 6.6.3
COVERAGE_THRESHOLD_MINIMUM = 0.90  # 90% minimum coverage
COVERAGE_THRESHOLD_CRITICAL = 0.95  # 95% critical requirement
TEST_SUCCESS_RATE_MINIMUM = 0.99  # 99% minimum success rate


# =============================================================================
# REPORT FORMAT ENUMERATIONS
# =============================================================================

class ReportFormat(Enum):
    """Report output format enumeration per Section 0.3.4."""
    
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    XML = "xml"
    PDF = "pdf"  # Future enhancement


class ReportType(Enum):
    """Performance report type enumeration for categorization."""
    
    BASELINE_COMPARISON = "baseline_comparison"
    PERFORMANCE_SUMMARY = "performance_summary"
    VARIANCE_ANALYSIS = "variance_analysis"
    TREND_ANALYSIS = "trend_analysis"
    QUALITY_METRICS = "quality_metrics"
    COMPLIANCE_REPORT = "compliance_report"
    EXECUTIVE_SUMMARY = "executive_summary"


class ReportStatus(Enum):
    """Report generation status enumeration."""
    
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    ERROR = "error"
    IN_PROGRESS = "in_progress"


class ComplianceLevel(Enum):
    """Performance compliance level enumeration per Section 0.1.1."""
    
    COMPLIANT = "compliant"          # ≤5% variance - excellent
    WARNING = "warning"              # 5-8% variance - concerning
    CRITICAL = "critical"            # 8-10% variance - critical
    NON_COMPLIANT = "non_compliant"  # >10% variance - failure


# =============================================================================
# REPORT CONFIGURATION CLASSES
# =============================================================================

@dataclass
class ReportConfiguration:
    """
    Report generation configuration per Section 0.3.4 documentation requirements.
    
    Provides comprehensive configuration for performance report generation including
    format specifications, output destinations, metadata requirements, and compliance
    validation parameters.
    """
    
    # Core report settings
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_type: ReportType = ReportType.PERFORMANCE_SUMMARY
    output_format: ReportFormat = ReportFormat.JSON
    output_directory: str = DEFAULT_REPORTS_DIRECTORY
    filename_template: str = "performance_report_{timestamp}_{report_type}.{format}"
    
    # Metadata configuration per Section 6.6.3
    include_metadata: bool = True
    include_baseline_comparison: bool = True
    include_trend_analysis: bool = True
    include_recommendations: bool = True
    
    # Report content configuration
    include_raw_data: bool = False
    include_charts: bool = True
    include_executive_summary: bool = True
    detailed_variance_analysis: bool = True
    
    # Compliance reporting per Section 8.6.5
    compliance_reporting: bool = True
    audit_trail_inclusion: bool = True
    retention_metadata: bool = True
    
    # Performance thresholds
    variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD
    warning_threshold: float = VARIANCE_THRESHOLD_WARNING
    critical_threshold: float = VARIANCE_THRESHOLD_CRITICAL
    
    # Output customization
    timestamp_format: str = "%Y%m%d_%H%M%S"
    timezone: str = "UTC"
    compression_enabled: bool = False
    encryption_enabled: bool = False
    
    def generate_filename(self, timestamp: Optional[datetime] = None) -> str:
        """
        Generate report filename based on configuration template.
        
        Args:
            timestamp: Custom timestamp for filename (defaults to current time)
            
        Returns:
            Formatted filename string
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
            
        formatted_timestamp = timestamp.strftime(self.timestamp_format)
        
        return self.filename_template.format(
            timestamp=formatted_timestamp,
            report_type=self.report_type.value,
            format=self.output_format.value,
            report_id=self.report_id[:8]  # Short ID for filename
        )
    
    def get_output_path(self, filename: Optional[str] = None) -> Path:
        """
        Get complete output path for report file.
        
        Args:
            filename: Custom filename (defaults to auto-generated)
            
        Returns:
            Complete Path object for report output
        """
        if filename is None:
            filename = self.generate_filename()
            
        output_dir = Path(self.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        return output_dir / filename


@dataclass
class ReportMetadata:
    """
    Report metadata structure per Section 6.6.3 documentation requirements.
    
    Provides comprehensive metadata tracking for performance reports including
    generation context, performance configuration, and compliance validation.
    """
    
    # Core identification
    report_id: str
    schema_version: str = REPORT_SCHEMA_VERSION
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str = "Flask Migration Performance Testing Framework"
    
    # Environment context
    environment: str = "unknown"
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    system_platform: str = sys.platform
    
    # Performance configuration
    performance_variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD
    baseline_comparison_enabled: bool = True
    performance_monitoring_enabled: bool = True
    
    # Test execution context
    test_execution_id: Optional[str] = None
    test_start_time: Optional[datetime] = None
    test_end_time: Optional[datetime] = None
    test_duration_seconds: Optional[float] = None
    
    # Data source information
    data_sources: List[str] = field(default_factory=list)
    baseline_source: str = "Node.js Baseline Implementation"
    metrics_collection_interval: int = 1  # seconds
    
    # Compliance and audit per Section 8.6.5
    compliance_framework: str = "≤10% Performance Variance Requirement"
    audit_trail_id: Optional[str] = None
    retention_policy: str = f"{REPORTS_RETENTION_DAYS} days active, archived after {ARCHIVE_REPORTS_AFTER_DAYS} days"
    
    # Quality metrics per Section 6.6.3
    report_quality_score: Optional[float] = None
    data_completeness_percent: Optional[float] = None
    baseline_coverage_percent: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary format for serialization."""
        data = asdict(self)
        
        # Convert datetime objects to ISO format strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        
        return data
    
    def calculate_duration(self) -> None:
        """Calculate test duration if start and end times are available."""
        if self.test_start_time and self.test_end_time:
            duration = self.test_end_time - self.test_start_time
            self.test_duration_seconds = duration.total_seconds()


# =============================================================================
# PERFORMANCE REPORT DATA STRUCTURES
# =============================================================================

@dataclass
class PerformanceMetric:
    """Individual performance metric data structure for reporting."""
    
    metric_name: str
    current_value: float
    baseline_value: Optional[float] = None
    unit: str = "ms"
    variance_percent: Optional[float] = None
    compliance_status: ComplianceLevel = ComplianceLevel.COMPLIANT
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Additional context
    measurement_context: Dict[str, Any] = field(default_factory=dict)
    quality_score: Optional[float] = None
    confidence_interval: Optional[tuple] = None
    
    def calculate_variance(self) -> Optional[float]:
        """Calculate variance percentage from baseline if available."""
        if self.baseline_value is None or self.baseline_value == 0:
            return None
            
        variance = ((self.current_value - self.baseline_value) / self.baseline_value) * 100
        self.variance_percent = round(variance, 2)
        return self.variance_percent
    
    def determine_compliance_status(self, 
                                  variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD) -> ComplianceLevel:
        """Determine compliance status based on variance thresholds."""
        if self.variance_percent is None:
            return ComplianceLevel.COMPLIANT
            
        abs_variance = abs(self.variance_percent) / 100.0
        
        if abs_variance <= VARIANCE_THRESHOLD_WARNING:
            self.compliance_status = ComplianceLevel.COMPLIANT
        elif abs_variance <= VARIANCE_THRESHOLD_CRITICAL:
            self.compliance_status = ComplianceLevel.WARNING
        elif abs_variance <= variance_threshold:
            self.compliance_status = ComplianceLevel.CRITICAL
        else:
            self.compliance_status = ComplianceLevel.NON_COMPLIANT
            
        return self.compliance_status


@dataclass
class BaselineComparisonResult:
    """Baseline comparison analysis result per Section 0.1.1 requirements."""
    
    metric_name: str
    current_value: float
    baseline_value: float
    variance_percent: float
    compliance_status: ComplianceLevel
    
    # Detailed analysis
    trend_analysis: Optional[str] = None
    historical_variance: List[float] = field(default_factory=list)
    recommendation: Optional[str] = None
    
    # Statistical analysis
    confidence_level: float = 0.95
    statistical_significance: bool = False
    sample_size: int = 1
    
    def is_within_threshold(self, threshold: float = PERFORMANCE_VARIANCE_THRESHOLD) -> bool:
        """Check if variance is within acceptable threshold."""
        return abs(self.variance_percent) / 100.0 <= threshold
    
    def get_trend_direction(self) -> str:
        """Determine performance trend direction."""
        if not self.historical_variance:
            return "insufficient_data"
            
        if len(self.historical_variance) < 2:
            return "single_measurement"
            
        recent_avg = sum(self.historical_variance[-3:]) / min(3, len(self.historical_variance))
        overall_avg = sum(self.historical_variance) / len(self.historical_variance)
        
        if recent_avg < overall_avg - 1:  # Improving by >1%
            return "improving"
        elif recent_avg > overall_avg + 1:  # Degrading by >1%
            return "degrading"
        else:
            return "stable"


@dataclass
class PerformanceReportData:
    """
    Comprehensive performance report data structure per Section 6.6.3.
    
    Contains all performance metrics, baseline comparisons, compliance analysis,
    and quality metrics for comprehensive performance reporting.
    """
    
    # Core report identification
    metadata: ReportMetadata
    
    # Performance metrics
    performance_metrics: List[PerformanceMetric] = field(default_factory=list)
    baseline_comparisons: List[BaselineComparisonResult] = field(default_factory=list)
    
    # Summary statistics
    overall_compliance_status: ComplianceLevel = ComplianceLevel.COMPLIANT
    total_metrics_count: int = 0
    compliant_metrics_count: int = 0
    non_compliant_metrics_count: int = 0
    
    # Quality metrics per Section 6.6.3
    test_coverage_percent: Optional[float] = None
    test_success_rate: Optional[float] = None
    performance_score: Optional[float] = None
    
    # Executive summary
    executive_summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    action_items: List[str] = field(default_factory=list)
    
    # Raw data (optional)
    raw_test_data: Optional[Dict[str, Any]] = None
    prometheus_metrics: Optional[Dict[str, Any]] = None
    
    def calculate_summary_statistics(self) -> None:
        """Calculate summary statistics from performance metrics."""
        self.total_metrics_count = len(self.performance_metrics)
        
        if self.total_metrics_count == 0:
            return
            
        compliant_count = sum(
            1 for metric in self.performance_metrics 
            if metric.compliance_status == ComplianceLevel.COMPLIANT
        )
        
        self.compliant_metrics_count = compliant_count
        self.non_compliant_metrics_count = self.total_metrics_count - compliant_count
        
        # Determine overall compliance status
        compliance_rate = compliant_count / self.total_metrics_count
        
        if compliance_rate >= 0.95:  # 95%+ compliant
            self.overall_compliance_status = ComplianceLevel.COMPLIANT
        elif compliance_rate >= 0.90:  # 90-95% compliant
            self.overall_compliance_status = ComplianceLevel.WARNING
        elif compliance_rate >= 0.80:  # 80-90% compliant
            self.overall_compliance_status = ComplianceLevel.CRITICAL
        else:  # <80% compliant
            self.overall_compliance_status = ComplianceLevel.NON_COMPLIANT
    
    def calculate_performance_score(self) -> float:
        """
        Calculate overall performance score (0-100) based on compliance and variance.
        
        Returns:
            Performance score from 0 (worst) to 100 (best)
        """
        if not self.performance_metrics:
            return 0.0
            
        total_score = 0.0
        scored_metrics = 0
        
        for metric in self.performance_metrics:
            if metric.variance_percent is not None:
                # Score based on variance (lower variance = higher score)
                abs_variance = abs(metric.variance_percent) / 100.0
                
                if abs_variance <= VARIANCE_THRESHOLD_WARNING:
                    score = 100.0  # Excellent performance
                elif abs_variance <= VARIANCE_THRESHOLD_CRITICAL:
                    score = 80.0   # Good performance
                elif abs_variance <= PERFORMANCE_VARIANCE_THRESHOLD:
                    score = 60.0   # Acceptable performance
                else:
                    score = 0.0    # Poor performance
                    
                total_score += score
                scored_metrics += 1
        
        self.performance_score = total_score / scored_metrics if scored_metrics > 0 else 0.0
        return self.performance_score
    
    def generate_recommendations(self) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        # Check for performance issues
        non_compliant_metrics = [
            metric for metric in self.performance_metrics 
            if metric.compliance_status in [ComplianceLevel.CRITICAL, ComplianceLevel.NON_COMPLIANT]
        ]
        
        if non_compliant_metrics:
            recommendations.append(
                f"Critical: {len(non_compliant_metrics)} metrics exceed performance variance threshold. "
                "Immediate optimization required."
            )
            
            # Specific recommendations for different metric types
            response_time_issues = [m for m in non_compliant_metrics if 'response' in m.metric_name.lower()]
            memory_issues = [m for m in non_compliant_metrics if 'memory' in m.metric_name.lower()]
            cpu_issues = [m for m in non_compliant_metrics if 'cpu' in m.metric_name.lower()]
            
            if response_time_issues:
                recommendations.append(
                    "Optimize API response times through caching, query optimization, "
                    "and connection pooling improvements."
                )
                
            if memory_issues:
                recommendations.append(
                    "Investigate memory usage patterns and implement memory optimization "
                    "strategies including garbage collection tuning."
                )
                
            if cpu_issues:
                recommendations.append(
                    "Optimize CPU-intensive operations and consider horizontal scaling "
                    "or performance profiling for bottleneck identification."
                )
        
        # Test coverage recommendations
        if self.test_coverage_percent and self.test_coverage_percent < COVERAGE_THRESHOLD_MINIMUM * 100:
            recommendations.append(
                f"Increase test coverage from {self.test_coverage_percent:.1f}% to minimum {COVERAGE_THRESHOLD_MINIMUM * 100}% "
                "to ensure comprehensive performance validation."
            )
        
        # Success rate recommendations
        if self.test_success_rate and self.test_success_rate < TEST_SUCCESS_RATE_MINIMUM:
            recommendations.append(
                f"Improve test success rate from {self.test_success_rate * 100:.1f}% to minimum {TEST_SUCCESS_RATE_MINIMUM * 100}% "
                "through test stabilization and infrastructure improvements."
            )
        
        self.recommendations = recommendations
        return recommendations


# =============================================================================
# REPORT GENERATION ENGINE
# =============================================================================

class PerformanceReportGenerator:
    """
    Performance report generation engine per Section 0.3.4 and Section 6.6.3.
    
    Provides comprehensive report generation capabilities with multiple output formats,
    baseline comparison analysis, compliance validation, and enterprise integration.
    """
    
    def __init__(self, config: Optional[ReportConfiguration] = None):
        """
        Initialize performance report generator.
        
        Args:
            config: Report configuration (uses default if not provided)
        """
        self.config = config or ReportConfiguration()
        self.logger = logger.bind(component="PerformanceReportGenerator")
        
        # Initialize Prometheus metrics if available
        if PROMETHEUS_AVAILABLE:
            self._setup_prometheus_metrics()
        
        # Ensure output directory exists
        Path(self.config.output_directory).mkdir(parents=True, exist_ok=True)
    
    def _setup_prometheus_metrics(self) -> None:
        """Setup Prometheus metrics for report generation monitoring."""
        self.reports_generated = Counter(
            'performance_reports_generated_total',
            'Total number of performance reports generated',
            ['report_type', 'format', 'status']
        )
        
        self.report_generation_duration = Histogram(
            'performance_report_generation_duration_seconds',
            'Time spent generating performance reports',
            ['report_type', 'format']
        )
        
        self.report_size_bytes = Histogram(
            'performance_report_size_bytes',
            'Size of generated performance reports',
            ['report_type', 'format']
        )
    
    def generate_report(self, 
                       test_results: Dict[str, Any],
                       baseline_data: Optional[Dict[str, Any]] = None,
                       custom_metadata: Optional[Dict[str, Any]] = None) -> PerformanceReportData:
        """
        Generate comprehensive performance report from test results.
        
        Args:
            test_results: Performance test execution results
            baseline_data: Node.js baseline comparison data
            custom_metadata: Additional metadata for the report
            
        Returns:
            Complete PerformanceReportData structure
        """
        start_time = time.perf_counter()
        
        try:
            # Create report metadata
            metadata = self._create_report_metadata(custom_metadata)
            
            # Initialize report data structure
            report_data = PerformanceReportData(metadata=metadata)
            
            # Process performance metrics
            self._process_performance_metrics(report_data, test_results)
            
            # Perform baseline comparison if data available
            if baseline_data or PERFORMANCE_FRAMEWORK_AVAILABLE:
                self._perform_baseline_comparison(report_data, baseline_data)
            
            # Calculate summary statistics and scores
            report_data.calculate_summary_statistics()
            report_data.calculate_performance_score()
            
            # Generate recommendations
            report_data.generate_recommendations()
            
            # Create executive summary
            self._create_executive_summary(report_data)
            
            # Record metrics
            if PROMETHEUS_AVAILABLE:
                generation_time = time.perf_counter() - start_time
                self.report_generation_duration.labels(
                    report_type=self.config.report_type.value,
                    format=self.config.output_format.value
                ).observe(generation_time)
                
                self.reports_generated.labels(
                    report_type=self.config.report_type.value,
                    format=self.config.output_format.value,
                    status="success"
                ).inc()
            
            self.logger.info(
                "Performance report generated successfully",
                report_id=report_data.metadata.report_id,
                metrics_count=report_data.total_metrics_count,
                compliance_status=report_data.overall_compliance_status.value,
                generation_time_seconds=time.perf_counter() - start_time
            )
            
            return report_data
            
        except Exception as e:
            if PROMETHEUS_AVAILABLE:
                self.reports_generated.labels(
                    report_type=self.config.report_type.value,
                    format=self.config.output_format.value,
                    status="error"
                ).inc()
            
            self.logger.error(
                "Failed to generate performance report",
                error=str(e),
                generation_time_seconds=time.perf_counter() - start_time
            )
            raise
    
    def _create_report_metadata(self, custom_metadata: Optional[Dict[str, Any]] = None) -> ReportMetadata:
        """Create comprehensive report metadata."""
        metadata = ReportMetadata(
            report_id=self.config.report_id,
            environment=os.getenv('PERFORMANCE_ENV', 'development'),
            performance_variance_threshold=self.config.variance_threshold
        )
        
        # Add custom metadata if provided
        if custom_metadata:
            for key, value in custom_metadata.items():
                if hasattr(metadata, key):
                    setattr(metadata, key, value)
        
        # Add data sources
        metadata.data_sources = [
            "Flask Application Performance Tests",
            "Node.js Baseline Comparison Data"
        ]
        
        if PERFORMANCE_FRAMEWORK_AVAILABLE:
            metadata.data_sources.append("Performance Testing Framework")
        
        if PROMETHEUS_AVAILABLE:
            metadata.data_sources.append("Prometheus Metrics Collection")
        
        return metadata
    
    def _process_performance_metrics(self, 
                                   report_data: PerformanceReportData, 
                                   test_results: Dict[str, Any]) -> None:
        """Process performance metrics from test results."""
        for metric_name, metric_data in test_results.items():
            if isinstance(metric_data, dict) and 'value' in metric_data:
                # Extract metric value and metadata
                current_value = float(metric_data['value'])
                unit = metric_data.get('unit', 'ms')
                measurement_context = metric_data.get('context', {})
                
                # Get baseline value if available
                baseline_value = self._get_baseline_value(metric_name)
                
                # Create performance metric
                metric = PerformanceMetric(
                    metric_name=metric_name,
                    current_value=current_value,
                    baseline_value=baseline_value,
                    unit=unit,
                    measurement_context=measurement_context
                )
                
                # Calculate variance and compliance status
                metric.calculate_variance()
                metric.determine_compliance_status(self.config.variance_threshold)
                
                report_data.performance_metrics.append(metric)
            
            elif isinstance(metric_data, (int, float)):
                # Simple numeric value
                baseline_value = self._get_baseline_value(metric_name)
                
                metric = PerformanceMetric(
                    metric_name=metric_name,
                    current_value=float(metric_data),
                    baseline_value=baseline_value
                )
                
                metric.calculate_variance()
                metric.determine_compliance_status(self.config.variance_threshold)
                
                report_data.performance_metrics.append(metric)
    
    def _get_baseline_value(self, metric_name: str) -> Optional[float]:
        """Get baseline value for metric from Node.js baseline data."""
        if not PERFORMANCE_FRAMEWORK_AVAILABLE:
            return None
            
        # Check API response times
        if metric_name in NodeJSBaseline.API_RESPONSE_TIMES:
            return float(NodeJSBaseline.API_RESPONSE_TIMES[metric_name])
        
        # Check database operations
        if hasattr(NodeJSBaseline, 'DATABASE_OPERATIONS') and metric_name in NodeJSBaseline.DATABASE_OPERATIONS:
            return float(NodeJSBaseline.DATABASE_OPERATIONS[metric_name])
        
        # Check memory usage
        if 'memory' in metric_name.lower():
            return float(NodeJSBaseline.MEMORY_USAGE.get('average_mb', 256))
        
        # Check CPU utilization
        if 'cpu' in metric_name.lower():
            return float(NodeJSBaseline.CPU_UTILIZATION.get('baseline_percent', 15))
        
        return None
    
    def _perform_baseline_comparison(self, 
                                   report_data: PerformanceReportData,
                                   baseline_data: Optional[Dict[str, Any]] = None) -> None:
        """Perform detailed baseline comparison analysis."""
        for metric in report_data.performance_metrics:
            if metric.baseline_value is not None and metric.variance_percent is not None:
                comparison = BaselineComparisonResult(
                    metric_name=metric.metric_name,
                    current_value=metric.current_value,
                    baseline_value=metric.baseline_value,
                    variance_percent=metric.variance_percent,
                    compliance_status=metric.compliance_status
                )
                
                # Add trend analysis if historical data available
                if baseline_data and metric.metric_name in baseline_data:
                    historical_data = baseline_data[metric.metric_name]
                    if isinstance(historical_data, list):
                        comparison.historical_variance = historical_data
                        comparison.trend_analysis = comparison.get_trend_direction()
                
                # Generate recommendation
                comparison.recommendation = self._generate_metric_recommendation(comparison)
                
                report_data.baseline_comparisons.append(comparison)
    
    def _generate_metric_recommendation(self, comparison: BaselineComparisonResult) -> str:
        """Generate specific recommendation for a metric comparison."""
        if comparison.compliance_status == ComplianceLevel.COMPLIANT:
            return "Performance is within acceptable limits. Continue monitoring."
        
        variance_abs = abs(comparison.variance_percent)
        
        if comparison.compliance_status == ComplianceLevel.WARNING:
            return (f"Performance variance ({variance_abs:.1f}%) approaching threshold. "
                   "Monitor closely and consider optimization.")
        
        elif comparison.compliance_status == ComplianceLevel.CRITICAL:
            return (f"Performance variance ({variance_abs:.1f}%) is critical. "
                   "Immediate investigation and optimization required.")
        
        else:  # NON_COMPLIANT
            return (f"Performance variance ({variance_abs:.1f}%) exceeds ≤10% threshold. "
                   "Critical performance regression requiring immediate attention.")
    
    def _create_executive_summary(self, report_data: PerformanceReportData) -> None:
        """Create executive summary for the performance report."""
        summary = {
            'overall_status': report_data.overall_compliance_status.value,
            'performance_score': report_data.performance_score,
            'total_metrics': report_data.total_metrics_count,
            'compliant_metrics': report_data.compliant_metrics_count,
            'non_compliant_metrics': report_data.non_compliant_metrics_count,
            'compliance_rate_percent': (
                (report_data.compliant_metrics_count / report_data.total_metrics_count * 100)
                if report_data.total_metrics_count > 0 else 0
            )
        }
        
        # Add key findings
        key_findings = []
        
        if report_data.overall_compliance_status == ComplianceLevel.COMPLIANT:
            key_findings.append("✓ All performance metrics meet ≤10% variance requirement")
        else:
            non_compliant_count = report_data.non_compliant_metrics_count
            key_findings.append(f"⚠ {non_compliant_count} metrics exceed performance variance threshold")
        
        if report_data.performance_score:
            if report_data.performance_score >= 90:
                key_findings.append("✓ Excellent overall performance score")
            elif report_data.performance_score >= 70:
                key_findings.append("⚠ Good performance with room for improvement")
            else:
                key_findings.append("❌ Poor performance requiring immediate attention")
        
        summary['key_findings'] = key_findings
        summary['recommendations_count'] = len(report_data.recommendations)
        
        report_data.executive_summary = summary
    
    def export_report(self, 
                     report_data: PerformanceReportData,
                     output_format: Optional[ReportFormat] = None,
                     output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Export performance report to specified format and location.
        
        Args:
            report_data: Complete report data structure
            output_format: Target output format (uses config default if not specified)
            output_path: Custom output path (uses config default if not specified)
            
        Returns:
            Path to generated report file
        """
        format_type = output_format or self.config.output_format
        
        if output_path:
            file_path = Path(output_path)
        else:
            filename = self.config.generate_filename()
            file_path = self.config.get_output_path(filename)
        
        # Generate report content based on format
        if format_type == ReportFormat.JSON:
            content = self._generate_json_report(report_data)
        elif format_type == ReportFormat.MARKDOWN:
            content = self._generate_markdown_report(report_data)
        elif format_type == ReportFormat.HTML:
            content = self._generate_html_report(report_data)
        elif format_type == ReportFormat.CSV:
            content = self._generate_csv_report(report_data)
        elif format_type == ReportFormat.XML:
            content = self._generate_xml_report(report_data)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
        
        # Write report to file
        if format_type == ReportFormat.CSV:
            # CSV requires special handling for binary mode
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                f.write(content)
        else:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        # Record file size metrics
        if PROMETHEUS_AVAILABLE:
            file_size = file_path.stat().st_size
            self.report_size_bytes.labels(
                report_type=self.config.report_type.value,
                format=format_type.value
            ).observe(file_size)
        
        self.logger.info(
            "Performance report exported successfully",
            report_id=report_data.metadata.report_id,
            format=format_type.value,
            file_path=str(file_path),
            file_size_bytes=file_path.stat().st_size
        )
        
        return file_path
    
    def _generate_json_report(self, report_data: PerformanceReportData) -> str:
        """Generate JSON format performance report."""
        # Convert dataclasses to dictionaries
        report_dict = {
            'metadata': report_data.metadata.to_dict(),
            'executive_summary': report_data.executive_summary,
            'performance_metrics': [asdict(metric) for metric in report_data.performance_metrics],
            'baseline_comparisons': [asdict(comparison) for comparison in report_data.baseline_comparisons],
            'summary_statistics': {
                'overall_compliance_status': report_data.overall_compliance_status.value,
                'total_metrics_count': report_data.total_metrics_count,
                'compliant_metrics_count': report_data.compliant_metrics_count,
                'non_compliant_metrics_count': report_data.non_compliant_metrics_count,
                'performance_score': report_data.performance_score,
                'test_coverage_percent': report_data.test_coverage_percent,
                'test_success_rate': report_data.test_success_rate
            },
            'recommendations': report_data.recommendations,
            'action_items': report_data.action_items
        }
        
        # Include raw data if configured
        if self.config.include_raw_data and report_data.raw_test_data:
            report_dict['raw_test_data'] = report_data.raw_test_data
        
        # Include Prometheus metrics if available
        if self.config.include_raw_data and report_data.prometheus_metrics:
            report_dict['prometheus_metrics'] = report_data.prometheus_metrics
        
        return json.dumps(report_dict, indent=2, default=str)
    
    def _generate_markdown_report(self, report_data: PerformanceReportData) -> str:
        """Generate Markdown format performance report."""
        lines = [
            f"# Performance Test Report",
            f"",
            f"**Report ID:** {report_data.metadata.report_id}",
            f"**Generated:** {report_data.metadata.generated_at.isoformat()}",
            f"**Environment:** {report_data.metadata.environment}",
            f"**Schema Version:** {report_data.metadata.schema_version}",
            f"",
            f"## Executive Summary",
            f"",
            f"**Overall Status:** {report_data.overall_compliance_status.value.title()}",
            f"**Performance Score:** {report_data.performance_score:.1f}/100",
            f"**Compliance Rate:** {(report_data.compliant_metrics_count / report_data.total_metrics_count * 100):.1f}%",
            f"",
            f"### Key Findings",
            f""
        ]
        
        for finding in report_data.executive_summary.get('key_findings', []):
            lines.append(f"- {finding}")
        
        lines.extend([
            f"",
            f"## Performance Metrics Summary",
            f"",
            f"| Metric | Current Value | Baseline | Variance | Status |",
            f"|--------|---------------|----------|----------|--------|"
        ])
        
        for metric in report_data.performance_metrics:
            baseline_str = f"{metric.baseline_value:.1f} {metric.unit}" if metric.baseline_value else "N/A"
            variance_str = f"{metric.variance_percent:.1f}%" if metric.variance_percent else "N/A"
            status_emoji = {
                ComplianceLevel.COMPLIANT: "✅",
                ComplianceLevel.WARNING: "⚠️",
                ComplianceLevel.CRITICAL: "🔴",
                ComplianceLevel.NON_COMPLIANT: "❌"
            }.get(metric.compliance_status, "❓")
            
            lines.append(
                f"| {metric.metric_name} | {metric.current_value:.1f} {metric.unit} | "
                f"{baseline_str} | {variance_str} | {status_emoji} {metric.compliance_status.value} |"
            )
        
        if report_data.recommendations:
            lines.extend([
                f"",
                f"## Recommendations",
                f""
            ])
            
            for i, recommendation in enumerate(report_data.recommendations, 1):
                lines.append(f"{i}. {recommendation}")
        
        lines.extend([
            f"",
            f"## Compliance Information",
            f"",
            f"This report validates Flask application performance against the ≤10% variance requirement ",
            f"from the original Node.js implementation per Section 0.1.1 primary objective.",
            f"",
            f"**Performance Variance Threshold:** {report_data.metadata.performance_variance_threshold * 100:.1f}%",
            f"**Baseline Source:** {report_data.metadata.baseline_source}",
            f"**Compliance Framework:** {report_data.metadata.compliance_framework}",
        ])
        
        return "\n".join(lines)
    
    def _generate_html_report(self, report_data: PerformanceReportData) -> str:
        """Generate HTML format performance report."""
        status_colors = {
            ComplianceLevel.COMPLIANT: "#28a745",
            ComplianceLevel.WARNING: "#ffc107",
            ComplianceLevel.CRITICAL: "#fd7e14",
            ComplianceLevel.NON_COMPLIANT: "#dc3545"
        }
        
        overall_color = status_colors.get(report_data.overall_compliance_status, "#6c757d")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - {report_data.metadata.report_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #dee2e6; padding-bottom: 20px; }}
        .status-badge {{ display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; text-transform: uppercase; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #495057; }}
        .metric-label {{ color: #6c757d; text-transform: uppercase; font-size: 0.8em; margin-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #e9ecef; font-weight: 600; }}
        .compliance-good {{ color: #28a745; font-weight: bold; }}
        .compliance-warning {{ color: #ffc107; font-weight: bold; }}
        .compliance-critical {{ color: #fd7e14; font-weight: bold; }}
        .compliance-bad {{ color: #dc3545; font-weight: bold; }}
        .recommendations {{ background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Performance Test Report</h1>
            <p><strong>Report ID:</strong> {report_data.metadata.report_id}</p>
            <p><strong>Generated:</strong> {report_data.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Environment:</strong> {report_data.metadata.environment}</p>
            <div class="status-badge" style="background-color: {overall_color};">
                {report_data.overall_compliance_status.value.replace('_', ' ').title()}
            </div>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Performance Score</div>
                <div class="metric-value">{report_data.performance_score:.1f}/100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Metrics</div>
                <div class="metric-value">{report_data.total_metrics_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Compliant Metrics</div>
                <div class="metric-value">{report_data.compliant_metrics_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Compliance Rate</div>
                <div class="metric-value">{(report_data.compliant_metrics_count / report_data.total_metrics_count * 100):.1f}%</div>
            </div>
        </div>
        
        <h2>Performance Metrics Detail</h2>
        <table>
            <thead>
                <tr>
                    <th>Metric Name</th>
                    <th>Current Value</th>
                    <th>Baseline</th>
                    <th>Variance</th>
                    <th>Compliance Status</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for metric in report_data.performance_metrics:
            baseline_str = f"{metric.baseline_value:.1f} {metric.unit}" if metric.baseline_value else "N/A"
            variance_str = f"{metric.variance_percent:.1f}%" if metric.variance_percent else "N/A"
            
            compliance_class = {
                ComplianceLevel.COMPLIANT: "compliance-good",
                ComplianceLevel.WARNING: "compliance-warning",
                ComplianceLevel.CRITICAL: "compliance-critical",
                ComplianceLevel.NON_COMPLIANT: "compliance-bad"
            }.get(metric.compliance_status, "")
            
            html_content += f"""
                <tr>
                    <td>{metric.metric_name}</td>
                    <td>{metric.current_value:.1f} {metric.unit}</td>
                    <td>{baseline_str}</td>
                    <td>{variance_str}</td>
                    <td class="{compliance_class}">{metric.compliance_status.value.replace('_', ' ').title()}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
"""
        
        if report_data.recommendations:
            html_content += """
        <div class="recommendations">
            <h3>🔍 Recommendations</h3>
            <ul>
"""
            for recommendation in report_data.recommendations:
                html_content += f"                <li>{recommendation}</li>\n"
            
            html_content += """
            </ul>
        </div>
"""
        
        html_content += f"""
        <div class="footer">
            <p>Generated by Flask Migration Performance Testing Framework</p>
            <p>Compliance Framework: {report_data.metadata.compliance_framework}</p>
            <p>Performance Variance Threshold: ≤{report_data.metadata.performance_variance_threshold * 100:.1f}%</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def _generate_csv_report(self, report_data: PerformanceReportData) -> str:
        """Generate CSV format performance report."""
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header information
        writer.writerow(['Performance Test Report'])
        writer.writerow(['Report ID', report_data.metadata.report_id])
        writer.writerow(['Generated', report_data.metadata.generated_at.isoformat()])
        writer.writerow(['Environment', report_data.metadata.environment])
        writer.writerow(['Overall Status', report_data.overall_compliance_status.value])
        writer.writerow(['Performance Score', report_data.performance_score or 'N/A'])
        writer.writerow([])  # Empty row
        
        # Write metrics data
        writer.writerow(['Metric Name', 'Current Value', 'Unit', 'Baseline Value', 'Variance %', 'Compliance Status'])
        
        for metric in report_data.performance_metrics:
            writer.writerow([
                metric.metric_name,
                metric.current_value,
                metric.unit,
                metric.baseline_value or 'N/A',
                metric.variance_percent or 'N/A',
                metric.compliance_status.value
            ])
        
        # Write recommendations
        if report_data.recommendations:
            writer.writerow([])  # Empty row
            writer.writerow(['Recommendations'])
            for i, recommendation in enumerate(report_data.recommendations, 1):
                writer.writerow([f"Recommendation {i}", recommendation])
        
        return output.getvalue()
    
    def _generate_xml_report(self, report_data: PerformanceReportData) -> str:
        """Generate XML format performance report."""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<performance_report>',
            '  <metadata>',
            f'    <report_id>{report_data.metadata.report_id}</report_id>',
            f'    <generated_at>{report_data.metadata.generated_at.isoformat()}</generated_at>',
            f'    <environment>{report_data.metadata.environment}</environment>',
            f'    <schema_version>{report_data.metadata.schema_version}</schema_version>',
            '  </metadata>',
            '  <summary>',
            f'    <overall_status>{report_data.overall_compliance_status.value}</overall_status>',
            f'    <performance_score>{report_data.performance_score or 0}</performance_score>',
            f'    <total_metrics>{report_data.total_metrics_count}</total_metrics>',
            f'    <compliant_metrics>{report_data.compliant_metrics_count}</compliant_metrics>',
            '  </summary>',
            '  <metrics>'
        ]
        
        for metric in report_data.performance_metrics:
            xml_lines.extend([
                '    <metric>',
                f'      <name>{metric.metric_name}</name>',
                f'      <current_value>{metric.current_value}</current_value>',
                f'      <unit>{metric.unit}</unit>',
                f'      <baseline_value>{metric.baseline_value or "N/A"}</baseline_value>',
                f'      <variance_percent>{metric.variance_percent or "N/A"}</variance_percent>',
                f'      <compliance_status>{metric.compliance_status.value}</compliance_status>',
                '    </metric>'
            ])
        
        xml_lines.append('  </metrics>')
        
        if report_data.recommendations:
            xml_lines.append('  <recommendations>')
            for recommendation in report_data.recommendations:
                xml_lines.append(f'    <recommendation>{recommendation}</recommendation>')
            xml_lines.append('  </recommendations>')
        
        xml_lines.append('</performance_report>')
        
        return '\n'.join(xml_lines)


# =============================================================================
# REPORT MANAGEMENT UTILITIES
# =============================================================================

class ReportManager:
    """
    Performance report management utilities per Section 8.6.5 compliance auditing.
    
    Provides report lifecycle management including creation, storage, retention,
    archival, and cleanup operations with compliance auditing support.
    """
    
    def __init__(self, reports_directory: str = DEFAULT_REPORTS_DIRECTORY):
        """
        Initialize report manager.
        
        Args:
            reports_directory: Base directory for report storage
        """
        self.reports_directory = Path(reports_directory)
        self.reports_directory.mkdir(parents=True, exist_ok=True)
        
        self.archive_directory = self.reports_directory / "archive"
        self.archive_directory.mkdir(parents=True, exist_ok=True)
        
        self.logger = logger.bind(component="ReportManager")
    
    def list_reports(self, 
                    report_type: Optional[ReportType] = None,
                    days_back: int = 30) -> List[Dict[str, Any]]:
        """
        List available performance reports with metadata.
        
        Args:
            report_type: Filter by specific report type
            days_back: Number of days back to search
            
        Returns:
            List of report metadata dictionaries
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        reports = []
        
        for report_file in self.reports_directory.glob("performance_report_*.json"):
            try:
                # Check file modification time
                file_mtime = datetime.fromtimestamp(report_file.stat().st_mtime, timezone.utc)
                if file_mtime < cutoff_date:
                    continue
                
                # Load report metadata
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                metadata = report_data.get('metadata', {})
                
                # Filter by report type if specified
                if report_type and metadata.get('report_type') != report_type.value:
                    continue
                
                reports.append({
                    'file_path': str(report_file),
                    'file_size': report_file.stat().st_size,
                    'created_at': file_mtime.isoformat(),
                    'report_id': metadata.get('report_id'),
                    'environment': metadata.get('environment'),
                    'compliance_status': report_data.get('summary_statistics', {}).get('overall_compliance_status')
                })
                
            except Exception as e:
                self.logger.warning(
                    "Failed to process report file",
                    file_path=str(report_file),
                    error=str(e)
                )
                continue
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x['created_at'], reverse=True)
        
        return reports
    
    def cleanup_old_reports(self, retention_days: int = REPORTS_RETENTION_DAYS) -> Dict[str, int]:
        """
        Clean up old performance reports per Section 8.6.5 retention policies.
        
        Args:
            retention_days: Number of days to retain reports
            
        Returns:
            Dictionary with cleanup statistics
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        deleted_count = 0
        archived_count = 0
        total_size_deleted = 0
        
        for report_file in self.reports_directory.glob("performance_report_*"):
            try:
                file_mtime = datetime.fromtimestamp(report_file.stat().st_mtime, timezone.utc)
                
                if file_mtime < cutoff_date:
                    file_size = report_file.stat().st_size
                    
                    # Archive before deletion if within archive threshold
                    archive_cutoff = datetime.now(timezone.utc) - timedelta(days=ARCHIVE_REPORTS_AFTER_DAYS)
                    
                    if file_mtime > archive_cutoff:
                        # Archive the file
                        archive_path = self.archive_directory / report_file.name
                        shutil.move(str(report_file), str(archive_path))
                        archived_count += 1
                        
                        self.logger.info(
                            "Report archived",
                            original_path=str(report_file),
                            archive_path=str(archive_path),
                            file_age_days=(datetime.now(timezone.utc) - file_mtime).days
                        )
                    else:
                        # Delete the file
                        report_file.unlink()
                        deleted_count += 1
                        total_size_deleted += file_size
                        
                        self.logger.info(
                            "Report deleted",
                            file_path=str(report_file),
                            file_size_bytes=file_size,
                            file_age_days=(datetime.now(timezone.utc) - file_mtime).days
                        )
                        
            except Exception as e:
                self.logger.error(
                    "Failed to cleanup report file",
                    file_path=str(report_file),
                    error=str(e)
                )
                continue
        
        cleanup_stats = {
            'deleted_count': deleted_count,
            'archived_count': archived_count,
            'total_size_deleted_bytes': total_size_deleted,
            'retention_days': retention_days
        }
        
        self.logger.info(
            "Report cleanup completed",
            **cleanup_stats
        )
        
        return cleanup_stats
    
    def get_report_trends(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Analyze performance report trends per Section 6.6.3 historical analysis.
        
        Args:
            days_back: Number of days back to analyze
            
        Returns:
            Dictionary with trend analysis data
        """
        reports = self.list_reports(days_back=days_back)
        
        if not reports:
            return {'error': 'No reports found for trend analysis'}
        
        # Load full report data for analysis
        trend_data = {
            'total_reports': len(reports),
            'compliance_trend': [],
            'performance_score_trend': [],
            'environments': defaultdict(int),
            'compliance_distribution': defaultdict(int)
        }
        
        for report_info in reports:
            try:
                with open(report_info['file_path'], 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                # Extract trend metrics
                summary = report_data.get('summary_statistics', {})
                metadata = report_data.get('metadata', {})
                
                trend_point = {
                    'date': report_info['created_at'][:10],  # Date only
                    'compliance_status': summary.get('overall_compliance_status'),
                    'performance_score': summary.get('performance_score'),
                    'environment': metadata.get('environment')
                }
                
                if trend_point['compliance_status']:
                    trend_data['compliance_trend'].append(trend_point)
                    trend_data['compliance_distribution'][trend_point['compliance_status']] += 1
                
                if trend_point['environment']:
                    trend_data['environments'][trend_point['environment']] += 1
                
            except Exception as e:
                self.logger.warning(
                    "Failed to process report for trend analysis",
                    file_path=report_info['file_path'],
                    error=str(e)
                )
                continue
        
        # Calculate trend statistics
        if trend_data['compliance_trend']:
            compliant_reports = sum(
                1 for t in trend_data['compliance_trend'] 
                if t['compliance_status'] == 'compliant'
            )
            trend_data['compliance_rate'] = compliant_reports / len(trend_data['compliance_trend'])
            
            # Performance score statistics
            scores = [
                t['performance_score'] for t in trend_data['compliance_trend']
                if t['performance_score'] is not None
            ]
            
            if scores:
                trend_data['average_performance_score'] = sum(scores) / len(scores)
                trend_data['min_performance_score'] = min(scores)
                trend_data['max_performance_score'] = max(scores)
        
        return trend_data


# =============================================================================
# MODULE INITIALIZATION AND EXPORTS
# =============================================================================

# Initialize default report generator
default_report_config = ReportConfiguration()
default_report_generator = PerformanceReportGenerator(default_report_config)
default_report_manager = ReportManager()

# Setup module-level logging
if STRUCTLOG_AVAILABLE:
    logger.info(
        "Performance reports package initialized",
        version=PERFORMANCE_REPORTS_VERSION,
        variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD,
        supported_formats=SUPPORTED_REPORT_FORMATS,
        default_directory=DEFAULT_REPORTS_DIRECTORY,
        framework_available=PERFORMANCE_FRAMEWORK_AVAILABLE,
        config_available=PERFORMANCE_CONFIG_AVAILABLE
    )

# Export public interface
__all__ = [
    # Core constants
    'PERFORMANCE_REPORTS_VERSION',
    'PERFORMANCE_VARIANCE_THRESHOLD_PERCENT',
    'SUPPORTED_REPORT_FORMATS',
    'DEFAULT_REPORT_FORMAT',
    'DEFAULT_REPORTS_DIRECTORY',
    'REPORTS_RETENTION_DAYS',
    'REPORT_SCHEMA_VERSION',
    
    # Threshold constants
    'VARIANCE_THRESHOLD_WARNING',
    'VARIANCE_THRESHOLD_CRITICAL',
    'VARIANCE_THRESHOLD_FAILURE',
    'COVERAGE_THRESHOLD_MINIMUM',
    'COVERAGE_THRESHOLD_CRITICAL',
    'TEST_SUCCESS_RATE_MINIMUM',
    
    # Enumerations
    'ReportFormat',
    'ReportType',
    'ReportStatus',
    'ComplianceLevel',
    
    # Configuration classes
    'ReportConfiguration',
    'ReportMetadata',
    
    # Data structures
    'PerformanceMetric',
    'BaselineComparisonResult',
    'PerformanceReportData',
    
    # Core functionality
    'PerformanceReportGenerator',
    'ReportManager',
    
    # Default instances
    'default_report_config',
    'default_report_generator',
    'default_report_manager',
]

# Module version and metadata
__version__ = PERFORMANCE_REPORTS_VERSION
__author__ = "Flask Migration Team"
__description__ = "Performance reporting framework for Flask migration compliance validation"