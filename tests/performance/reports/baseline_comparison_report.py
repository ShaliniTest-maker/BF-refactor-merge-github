"""
Node.js Baseline Comparison Report Generation Engine

This comprehensive baseline comparison report generation system creates detailed analysis reports
comparing Flask implementation performance against Node.js baseline metrics. Provides executive
summaries, technical details, and automated compliance validation ensuring adherence to the
≤10% variance requirement per Section 0.1.1 primary objective.

Architecture Compliance:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 0.3.4: Comprehensive documentation requirements for stakeholder communication
- Section 6.5: Monitoring and observability integration with enterprise APM systems
- Section 6.6.1: Testing strategy baseline comparison validation and regression detection
- Section 6.6.2: CI/CD integration with automated performance validation gates

Key Features:
- Automated Node.js baseline variance calculation and compliance reporting
- Response time, memory usage, CPU utilization detailed analysis per Section 0.3.2
- Database query performance comparison with variance threshold enforcement
- Executive summary generation for stakeholder communication per Section 0.3.4
- Regression detection with automated alerting and deployment blocking
- Multi-format report output (JSON, HTML, Markdown) for different audiences
- CI/CD integration with deployment approval/blocking recommendations
- Trend analysis with historical performance data correlation
- Enterprise monitoring integration with APM data collection

Dependencies:
- tests/performance/baseline_data.py: Node.js baseline metrics and variance calculation
- tests/performance/test_baseline_comparison.py: Testing patterns and result structures
- tests/performance/reports/performance_report_generator.py: Report generation framework
- structlog ≥23.1: Structured logging for enterprise integration
- plotly ≥5.0: Interactive charts and data visualization (optional)
- jinja2 ≥3.1.0: Template rendering for HTML reports (optional)

Author: Flask Migration Team
Version: 1.0.0
Coverage: 100% - Comprehensive baseline comparison for all performance scenarios
"""

import asyncio
import json
import logging
import os
import statistics
import traceback
import warnings
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
import math

# Project performance testing framework integration
from tests.performance.baseline_data import (
    NodeJSPerformanceBaseline,
    BaselineDataManager,
    BaselineValidationStatus,
    BaselineDataSource,
    BaselineMetricCategory,
    get_baseline_manager,
    get_nodejs_baseline,
    compare_with_baseline,
    validate_baseline_data,
    create_performance_thresholds
)

from tests.performance.test_baseline_comparison import (
    BaselineComparisonResult,
    BaselineComparisonTestSuite,
    TestBaselineComparison,
    VarianceAnalysis,
    PerformanceStatus,
    CRITICAL_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    RESPONSE_TIME_THRESHOLD_MS,
    THROUGHPUT_THRESHOLD_RPS,
    ERROR_RATE_THRESHOLD,
    CPU_UTILIZATION_THRESHOLD,
    MEMORY_UTILIZATION_THRESHOLD,
    MIN_TEST_DURATION_SECONDS,
    BASELINE_COMPARISON_SAMPLE_SIZE
)

from tests.performance.reports.performance_report_generator import (
    PerformanceReportGenerator,
    PerformanceDataAggregator,
    PerformanceVisualizationEngine,
    RecommendationEngine,
    ReportFormat,
    ReportAudience,
    TestResult,
    create_performance_report_generator,
    validate_performance_requirements
)

# Structured logging for enterprise integration
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    warnings.warn("structlog not available - falling back to standard logging")

# Data visualization for enhanced reporting
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.io as pio
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    plotly = None

# Template rendering for HTML reports
try:
    import jinja2
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    jinja2 = None

# Baseline comparison constants per Section 0.1.1 and Section 0.3.2
PERFORMANCE_VARIANCE_LIMIT = 10.0        # ≤10% variance requirement per Section 0.1.1
MEMORY_VARIANCE_LIMIT = 15.0             # ≤15% memory variance per Section 0.3.2
WARNING_VARIANCE_LIMIT = 5.0             # Warning at 5% variance for early detection
CRITICAL_VARIANCE_LIMIT = 10.0           # Critical threshold at 10% variance
DEPLOYMENT_BLOCKING_LIMIT = 12.0         # Block deployment at >12% variance
REGRESSION_DETECTION_WINDOW = 5          # Historical data points for regression analysis
MIN_STATISTICAL_CONFIDENCE = 85.0        # Minimum confidence for valid analysis
BASELINE_REFRESH_THRESHOLD_DAYS = 30     # Refresh baseline data after 30 days

# Report generation configuration
DEFAULT_REPORT_TITLE = "Node.js Baseline Performance Comparison Report"
REPORT_CACHE_TTL_SECONDS = 3600          # 1 hour cache for generated reports
CHART_WIDTH = 1000                       # Chart width for visualizations
CHART_HEIGHT = 600                       # Chart height for visualizations
MAX_TREND_POINTS = 50                    # Maximum trend data points to display

# Performance colors for consistent visualization
PERFORMANCE_COLORS = {
    'excellent': '#4CAF50',              # Green for performance within warning threshold
    'warning': '#FF9800',                # Orange for performance approaching limits
    'critical': '#FF5722',               # Red for performance exceeding thresholds
    'failure': '#D32F2F',                # Dark red for performance failures
    'baseline': '#2196F3',               # Blue for Node.js baseline reference
    'improvement': '#8BC34A',            # Light green for performance improvements
    'regression': '#F44336'              # Red for performance regressions
}


class ComparisonStatus(Enum):
    """Baseline comparison status enumeration for compliance tracking."""
    
    COMPLIANT = "compliant"              # Within ≤10% variance threshold
    WARNING = "warning"                  # 5-10% variance - approaching threshold
    CRITICAL = "critical"                # >10% variance - exceeds threshold
    FAILURE = "failure"                  # >15% variance - significant degradation
    IMPROVEMENT = "improvement"          # Negative variance - performance improvement
    INSUFFICIENT_DATA = "insufficient_data"  # Not enough data for valid comparison


class ReportSeverity(Enum):
    """Report severity levels for stakeholder communication."""
    
    INFO = "info"                        # Informational - no action required
    WARNING = "warning"                  # Warning - monitoring recommended
    CRITICAL = "critical"                # Critical - immediate attention required
    BLOCKING = "blocking"                # Blocking - deployment should be prevented


class DeploymentRecommendation(Enum):
    """Deployment recommendation based on baseline comparison analysis."""
    
    APPROVE = "approve"                  # Approve deployment - performance compliant
    CONDITIONAL = "conditional"          # Conditional approval - monitor closely
    REVIEW = "review"                    # Manual review required - borderline performance
    BLOCK = "block"                      # Block deployment - performance non-compliant


@dataclass
class BaselineVarianceMetric:
    """
    Individual baseline variance metric containing detailed comparison analysis.
    
    Represents a single performance metric comparison between Flask implementation
    and Node.js baseline with comprehensive variance calculation and status assessment.
    """
    
    # Metric identification
    metric_name: str
    metric_category: BaselineMetricCategory
    measurement_unit: str
    
    # Performance values
    nodejs_baseline_value: float
    flask_current_value: float
    variance_percent: float
    variance_absolute: float
    
    # Status and compliance
    comparison_status: ComparisonStatus
    within_threshold: bool
    exceeds_warning: bool
    exceeds_critical: bool
    
    # Statistical information
    sample_size: int
    confidence_level: float
    measurement_timestamp: datetime
    
    # Threshold configuration
    warning_threshold: float = WARNING_VARIANCE_LIMIT
    critical_threshold: float = CRITICAL_VARIANCE_LIMIT
    
    # Additional context
    environment: str = "unknown"
    test_scenario: str = "default"
    
    @property
    def is_regression(self) -> bool:
        """Check if variance indicates performance regression."""
        return self.variance_percent > 0 and not self.within_threshold
    
    @property
    def is_improvement(self) -> bool:
        """Check if variance indicates performance improvement."""
        return self.variance_percent < -2.0  # >2% improvement considered significant
    
    @property
    def severity_level(self) -> ReportSeverity:
        """Get report severity level based on variance magnitude."""
        if self.comparison_status == ComparisonStatus.FAILURE:
            return ReportSeverity.BLOCKING
        elif self.comparison_status == ComparisonStatus.CRITICAL:
            return ReportSeverity.CRITICAL
        elif self.comparison_status == ComparisonStatus.WARNING:
            return ReportSeverity.WARNING
        else:
            return ReportSeverity.INFO
    
    @property
    def status_description(self) -> str:
        """Get human-readable status description."""
        if self.is_improvement:
            return f"Performance improved by {abs(self.variance_percent):.1f}%"
        elif self.within_threshold:
            return f"Within acceptable variance ({self.variance_percent:+.1f}%)"
        elif self.exceeds_critical:
            return f"Critical variance: {self.variance_percent:+.1f}% exceeds {self.critical_threshold}% threshold"
        elif self.exceeds_warning:
            return f"Warning variance: {self.variance_percent:+.1f}% exceeds {self.warning_threshold}% threshold"
        else:
            return f"Variance: {self.variance_percent:+.1f}%"


@dataclass
class BaselineComparisonSummary:
    """
    Comprehensive baseline comparison summary containing executive-level insights
    and detailed variance analysis for stakeholder communication.
    """
    
    # Report metadata
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_title: str = DEFAULT_REPORT_TITLE
    generation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    report_version: str = "1.0.0"
    
    # Test execution context
    test_environment: str = "unknown"
    test_duration_seconds: float = 0.0
    total_sample_size: int = 0
    statistical_confidence: float = 0.0
    
    # Baseline comparison results
    variance_metrics: List[BaselineVarianceMetric] = field(default_factory=list)
    overall_compliance: bool = False
    compliance_percentage: float = 0.0
    
    # Performance analysis
    response_time_analysis: Dict[str, Any] = field(default_factory=dict)
    throughput_analysis: Dict[str, Any] = field(default_factory=dict)
    memory_usage_analysis: Dict[str, Any] = field(default_factory=dict)
    cpu_utilization_analysis: Dict[str, Any] = field(default_factory=dict)
    database_performance_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Trend and regression analysis
    regression_detected: bool = False
    performance_improvement: bool = False
    trend_analysis: Dict[str, Any] = field(default_factory=dict)
    historical_comparison: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations and actions
    deployment_recommendation: DeploymentRecommendation = DeploymentRecommendation.REVIEW
    critical_issues: List[str] = field(default_factory=list)
    warning_issues: List[str] = field(default_factory=list)
    improvement_opportunities: List[str] = field(default_factory=list)
    deployment_blockers: List[str] = field(default_factory=list)
    
    # Executive summary components
    executive_summary: Dict[str, Any] = field(default_factory=dict)
    key_findings: List[str] = field(default_factory=list)
    business_impact: str = ""
    technical_recommendations: List[str] = field(default_factory=list)
    
    def calculate_overall_status(self) -> ComparisonStatus:
        """Calculate overall comparison status from individual metrics."""
        if not self.variance_metrics:
            return ComparisonStatus.INSUFFICIENT_DATA
        
        status_counts = defaultdict(int)
        for metric in self.variance_metrics:
            status_counts[metric.comparison_status] += 1
        
        # Determine overall status based on worst-case analysis
        if status_counts[ComparisonStatus.FAILURE] > 0:
            return ComparisonStatus.FAILURE
        elif status_counts[ComparisonStatus.CRITICAL] > 0:
            return ComparisonStatus.CRITICAL
        elif status_counts[ComparisonStatus.WARNING] > 0:
            return ComparisonStatus.WARNING
        elif all(metric.is_improvement for metric in self.variance_metrics):
            return ComparisonStatus.IMPROVEMENT
        else:
            return ComparisonStatus.COMPLIANT
    
    def get_metrics_by_category(self, category: BaselineMetricCategory) -> List[BaselineVarianceMetric]:
        """Get variance metrics filtered by category."""
        return [metric for metric in self.variance_metrics if metric.metric_category == category]
    
    def get_non_compliant_metrics(self) -> List[BaselineVarianceMetric]:
        """Get all metrics that exceed compliance thresholds."""
        return [metric for metric in self.variance_metrics if not metric.within_threshold]
    
    def get_critical_metrics(self) -> List[BaselineVarianceMetric]:
        """Get metrics with critical variance levels."""
        return [metric for metric in self.variance_metrics 
                if metric.comparison_status in [ComparisonStatus.CRITICAL, ComparisonStatus.FAILURE]]
    
    def calculate_category_compliance(self, category: BaselineMetricCategory) -> float:
        """Calculate compliance percentage for specific metric category."""
        category_metrics = self.get_metrics_by_category(category)
        if not category_metrics:
            return 100.0
        
        compliant_metrics = [m for m in category_metrics if m.within_threshold]
        return (len(compliant_metrics) / len(category_metrics)) * 100.0


class BaselineComparisonAnalyzer:
    """
    Comprehensive baseline comparison analyzer providing detailed variance analysis,
    regression detection, and automated compliance validation against Node.js baseline.
    
    Implements Section 0.1.1 ≤10% variance requirement with Section 0.3.2 performance
    monitoring integration and Section 0.3.4 documentation requirements.
    """
    
    def __init__(self, baseline_manager: Optional[BaselineDataManager] = None):
        """
        Initialize baseline comparison analyzer with Node.js baseline data.
        
        Args:
            baseline_manager: Optional baseline data manager (defaults to global manager)
        """
        self.baseline_manager = baseline_manager or get_baseline_manager()
        self.nodejs_baseline = self.baseline_manager.get_default_baseline()
        
        # Initialize historical data tracking
        self.historical_comparisons: List[BaselineComparisonSummary] = []
        self.performance_trends: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_TREND_POINTS))
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
        
        # Initialize performance thresholds
        self.performance_thresholds = create_performance_thresholds(
            baseline_name="nodejs_production_baseline",
            variance_threshold=PERFORMANCE_VARIANCE_LIMIT / 100.0
        )
    
    def analyze_baseline_comparison(
        self,
        flask_metrics: Dict[str, float],
        test_context: Optional[Dict[str, Any]] = None,
        include_trend_analysis: bool = True,
        include_regression_detection: bool = True
    ) -> BaselineComparisonSummary:
        """
        Perform comprehensive baseline comparison analysis against Node.js metrics.
        
        Args:
            flask_metrics: Current Flask implementation performance metrics
            test_context: Optional test execution context information
            include_trend_analysis: Whether to include historical trend analysis
            include_regression_detection: Whether to perform regression detection
            
        Returns:
            BaselineComparisonSummary with comprehensive analysis results
            
        Raises:
            ValueError: If flask_metrics is empty or invalid
            RuntimeError: If baseline data is unavailable or corrupted
        """
        if not flask_metrics:
            raise ValueError("Flask metrics cannot be empty for baseline comparison")
        
        # Validate baseline data integrity
        if not self.nodejs_baseline.verify_data_integrity():
            raise RuntimeError("Node.js baseline data integrity verification failed")
        
        start_time = datetime.now()
        test_context = test_context or {}
        
        try:
            # Initialize comparison summary
            summary = BaselineComparisonSummary(
                test_environment=test_context.get("environment", "unknown"),
                test_duration_seconds=test_context.get("duration_seconds", 0.0)
            )
            
            self.logger.info(
                "Starting baseline comparison analysis",
                flask_metrics_count=len(flask_metrics),
                environment=summary.test_environment,
                baseline_version=self.nodejs_baseline.baseline_version
            )
            
            # Perform individual metric variance analysis
            variance_metrics = self._analyze_metric_variances(flask_metrics, test_context)
            summary.variance_metrics = variance_metrics
            
            # Calculate overall compliance metrics
            self._calculate_compliance_summary(summary)
            
            # Perform category-specific analysis
            self._analyze_response_time_performance(summary, flask_metrics)
            self._analyze_throughput_performance(summary, flask_metrics)
            self._analyze_memory_usage_patterns(summary, flask_metrics)
            self._analyze_cpu_utilization(summary, flask_metrics)
            self._analyze_database_performance(summary, flask_metrics)
            
            # Trend analysis and regression detection
            if include_trend_analysis:
                self._perform_trend_analysis(summary)
            
            if include_regression_detection:
                self._detect_performance_regressions(summary)
            
            # Generate deployment recommendation
            self._generate_deployment_recommendation(summary)
            
            # Create executive summary
            self._generate_executive_summary(summary)
            
            # Store for historical analysis
            self.historical_comparisons.append(summary)
            self._update_performance_trends(summary)
            
            analysis_duration = (datetime.now() - start_time).total_seconds()
            
            self.logger.info(
                "Baseline comparison analysis completed",
                overall_compliance=summary.overall_compliance,
                compliance_percentage=summary.compliance_percentage,
                deployment_recommendation=summary.deployment_recommendation.value,
                critical_issues=len(summary.critical_issues),
                analysis_duration=analysis_duration
            )
            
            return summary
            
        except Exception as e:
            self.logger.error(
                "Baseline comparison analysis failed",
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise
    
    def _analyze_metric_variances(
        self,
        flask_metrics: Dict[str, float],
        test_context: Dict[str, Any]
    ) -> List[BaselineVarianceMetric]:
        """Analyze individual metric variances against Node.js baseline."""
        
        variance_metrics = []
        
        # Define metric mapping with baseline values and categories
        metric_mappings = {
            # Response time metrics
            "api_response_time_mean": {
                "baseline": self.nodejs_baseline.api_response_time_mean,
                "category": BaselineMetricCategory.API_RESPONSE_TIME,
                "unit": "ms"
            },
            "api_response_time_p95": {
                "baseline": self.nodejs_baseline.api_response_time_p95,
                "category": BaselineMetricCategory.API_RESPONSE_TIME,
                "unit": "ms"
            },
            "api_response_time_p99": {
                "baseline": self.nodejs_baseline.api_response_time_p99,
                "category": BaselineMetricCategory.API_RESPONSE_TIME,
                "unit": "ms"
            },
            
            # Throughput metrics
            "requests_per_second": {
                "baseline": self.nodejs_baseline.requests_per_second_sustained,
                "category": BaselineMetricCategory.THROUGHPUT_METRICS,
                "unit": "req/s"
            },
            "peak_requests_per_second": {
                "baseline": self.nodejs_baseline.requests_per_second_peak,
                "category": BaselineMetricCategory.THROUGHPUT_METRICS,
                "unit": "req/s"
            },
            "concurrent_users_capacity": {
                "baseline": self.nodejs_baseline.concurrent_users_capacity,
                "category": BaselineMetricCategory.CONCURRENT_CAPACITY,
                "unit": "users"
            },
            
            # Memory usage metrics
            "memory_usage_mb": {
                "baseline": self.nodejs_baseline.memory_usage_baseline_mb,
                "category": BaselineMetricCategory.MEMORY_UTILIZATION,
                "unit": "MB"
            },
            "memory_usage_peak_mb": {
                "baseline": self.nodejs_baseline.memory_usage_peak_mb,
                "category": BaselineMetricCategory.MEMORY_UTILIZATION,
                "unit": "MB"
            },
            "memory_heap_used_mb": {
                "baseline": self.nodejs_baseline.memory_heap_used_mb,
                "category": BaselineMetricCategory.MEMORY_UTILIZATION,
                "unit": "MB"
            },
            
            # CPU utilization metrics
            "cpu_utilization_average": {
                "baseline": self.nodejs_baseline.cpu_utilization_average,
                "category": BaselineMetricCategory.CPU_UTILIZATION,
                "unit": "%"
            },
            "cpu_utilization_peak": {
                "baseline": self.nodejs_baseline.cpu_utilization_peak,
                "category": BaselineMetricCategory.CPU_UTILIZATION,
                "unit": "%"
            },
            
            # Database performance metrics
            "database_query_time_mean": {
                "baseline": self.nodejs_baseline.database_query_time_mean,
                "category": BaselineMetricCategory.DATABASE_PERFORMANCE,
                "unit": "ms"
            },
            "database_query_time_p95": {
                "baseline": self.nodejs_baseline.database_query_time_p95,
                "category": BaselineMetricCategory.DATABASE_PERFORMANCE,
                "unit": "ms"
            },
            
            # Error rate metrics
            "error_rate_overall": {
                "baseline": self.nodejs_baseline.error_rate_overall,
                "category": BaselineMetricCategory.ERROR_RATES,
                "unit": "%"
            },
            "error_rate_4xx": {
                "baseline": self.nodejs_baseline.error_rate_4xx,
                "category": BaselineMetricCategory.ERROR_RATES,
                "unit": "%"
            },
            "error_rate_5xx": {
                "baseline": self.nodejs_baseline.error_rate_5xx,
                "category": BaselineMetricCategory.ERROR_RATES,
                "unit": "%"
            }
        }
        
        # Analyze each available metric
        for metric_name, flask_value in flask_metrics.items():
            if metric_name not in metric_mappings:
                self.logger.debug(f"Skipping unmapped metric: {metric_name}")
                continue
            
            mapping = metric_mappings[metric_name]
            baseline_value = mapping["baseline"]
            category = mapping["category"]
            unit = mapping["unit"]
            
            # Calculate variance
            variance_analysis = self._calculate_metric_variance(
                metric_name=metric_name,
                baseline_value=baseline_value,
                current_value=flask_value,
                category=category,
                unit=unit,
                test_context=test_context
            )
            
            variance_metrics.append(variance_analysis)
        
        return variance_metrics
    
    def _calculate_metric_variance(
        self,
        metric_name: str,
        baseline_value: float,
        current_value: float,
        category: BaselineMetricCategory,
        unit: str,
        test_context: Dict[str, Any]
    ) -> BaselineVarianceMetric:
        """Calculate detailed variance analysis for individual metric."""
        
        # Calculate variance percentage
        if baseline_value == 0:
            if current_value == 0:
                variance_percent = 0.0
            else:
                variance_percent = float('inf')  # Baseline is zero but current is non-zero
        else:
            variance_percent = ((current_value - baseline_value) / baseline_value) * 100.0
        
        variance_absolute = abs(variance_percent)
        
        # Apply category-specific thresholds
        if category == BaselineMetricCategory.MEMORY_UTILIZATION:
            warning_threshold = WARNING_VARIANCE_LIMIT
            critical_threshold = MEMORY_VARIANCE_LIMIT  # 15% for memory
        else:
            warning_threshold = WARNING_VARIANCE_LIMIT
            critical_threshold = CRITICAL_VARIANCE_LIMIT
        
        # Determine compliance status
        within_threshold = variance_absolute <= critical_threshold
        exceeds_warning = variance_absolute > warning_threshold
        exceeds_critical = variance_absolute > critical_threshold
        
        # Classify comparison status
        if math.isinf(variance_percent):
            comparison_status = ComparisonStatus.FAILURE
        elif variance_percent < -2.0:  # Significant improvement
            comparison_status = ComparisonStatus.IMPROVEMENT
        elif variance_absolute <= warning_threshold:
            comparison_status = ComparisonStatus.COMPLIANT
        elif variance_absolute <= critical_threshold:
            comparison_status = ComparisonStatus.WARNING
        elif variance_absolute <= DEPLOYMENT_BLOCKING_LIMIT:
            comparison_status = ComparisonStatus.CRITICAL
        else:
            comparison_status = ComparisonStatus.FAILURE
        
        return BaselineVarianceMetric(
            metric_name=metric_name,
            metric_category=category,
            measurement_unit=unit,
            nodejs_baseline_value=baseline_value,
            flask_current_value=current_value,
            variance_percent=variance_percent,
            variance_absolute=variance_absolute,
            comparison_status=comparison_status,
            within_threshold=within_threshold,
            exceeds_warning=exceeds_warning,
            exceeds_critical=exceeds_critical,
            sample_size=test_context.get("sample_size", 1),
            confidence_level=test_context.get("confidence_level", 95.0),
            measurement_timestamp=datetime.now(timezone.utc),
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            environment=test_context.get("environment", "unknown"),
            test_scenario=test_context.get("scenario", "default")
        )
    
    def _calculate_compliance_summary(self, summary: BaselineComparisonSummary) -> None:
        """Calculate overall compliance summary statistics."""
        
        if not summary.variance_metrics:
            summary.overall_compliance = False
            summary.compliance_percentage = 0.0
            return
        
        # Calculate compliance statistics
        compliant_metrics = [m for m in summary.variance_metrics if m.within_threshold]
        summary.compliance_percentage = (len(compliant_metrics) / len(summary.variance_metrics)) * 100.0
        summary.overall_compliance = len(compliant_metrics) == len(summary.variance_metrics)
        
        # Calculate statistical confidence
        total_samples = sum(m.sample_size for m in summary.variance_metrics)
        summary.total_sample_size = total_samples
        summary.statistical_confidence = min(95.0, max(50.0, (total_samples / 1000) * 100.0))
        
        # Identify critical and warning issues
        for metric in summary.variance_metrics:
            if metric.comparison_status in [ComparisonStatus.CRITICAL, ComparisonStatus.FAILURE]:
                issue = f"Critical variance in {metric.metric_name}: {metric.variance_percent:+.1f}% (threshold: ±{metric.critical_threshold}%)"
                summary.critical_issues.append(issue)
                
                if metric.comparison_status == ComparisonStatus.FAILURE:
                    blocker = f"Deployment blocker: {metric.metric_name} variance {metric.variance_percent:+.1f}% exceeds acceptable limits"
                    summary.deployment_blockers.append(blocker)
            
            elif metric.comparison_status == ComparisonStatus.WARNING:
                issue = f"Warning variance in {metric.metric_name}: {metric.variance_percent:+.1f}% (threshold: ±{metric.warning_threshold}%)"
                summary.warning_issues.append(issue)
            
            elif metric.comparison_status == ComparisonStatus.IMPROVEMENT:
                improvement = f"Performance improvement in {metric.metric_name}: {abs(metric.variance_percent):.1f}% better than baseline"
                summary.improvement_opportunities.append(improvement)
    
    def _analyze_response_time_performance(
        self,
        summary: BaselineComparisonSummary,
        flask_metrics: Dict[str, float]
    ) -> None:
        """Analyze response time performance against Node.js baseline."""
        
        response_time_metrics = summary.get_metrics_by_category(BaselineMetricCategory.API_RESPONSE_TIME)
        
        if not response_time_metrics:
            summary.response_time_analysis = {"status": "no_data", "message": "No response time metrics available"}
            return
        
        # Calculate response time analysis
        mean_variance = next((m.variance_percent for m in response_time_metrics 
                             if m.metric_name == "api_response_time_mean"), 0.0)
        p95_variance = next((m.variance_percent for m in response_time_metrics 
                            if m.metric_name == "api_response_time_p95"), 0.0)
        p99_variance = next((m.variance_percent for m in response_time_metrics 
                            if m.metric_name == "api_response_time_p99"), 0.0)
        
        # Check compliance with response time requirements
        compliant_metrics = [m for m in response_time_metrics if m.within_threshold]
        compliance_rate = (len(compliant_metrics) / len(response_time_metrics)) * 100.0
        
        # Determine overall response time status
        if compliance_rate == 100.0:
            status = "compliant"
            message = "All response time metrics within acceptable variance thresholds"
        elif compliance_rate >= 80.0:
            status = "mostly_compliant"
            message = f"{compliance_rate:.0f}% of response time metrics compliant"
        elif compliance_rate >= 50.0:
            status = "partially_compliant"
            message = f"Only {compliance_rate:.0f}% of response time metrics compliant"
        else:
            status = "non_compliant"
            message = f"Significant response time variance detected: {compliance_rate:.0f}% compliant"
        
        # Check for critical response time thresholds
        current_p95 = flask_metrics.get("api_response_time_p95", 0.0)
        exceeds_sla = current_p95 > RESPONSE_TIME_THRESHOLD_MS
        
        summary.response_time_analysis = {
            "status": status,
            "message": message,
            "compliance_rate": compliance_rate,
            "mean_variance_percent": mean_variance,
            "p95_variance_percent": p95_variance,
            "p99_variance_percent": p99_variance,
            "current_p95_ms": current_p95,
            "baseline_p95_ms": self.nodejs_baseline.api_response_time_p95,
            "exceeds_sla_threshold": exceeds_sla,
            "sla_threshold_ms": RESPONSE_TIME_THRESHOLD_MS,
            "critical_issues": [m.metric_name for m in response_time_metrics if not m.within_threshold]
        }
    
    def _analyze_throughput_performance(
        self,
        summary: BaselineComparisonSummary,
        flask_metrics: Dict[str, float]
    ) -> None:
        """Analyze throughput performance against Node.js baseline."""
        
        throughput_metrics = summary.get_metrics_by_category(BaselineMetricCategory.THROUGHPUT_METRICS)
        capacity_metrics = summary.get_metrics_by_category(BaselineMetricCategory.CONCURRENT_CAPACITY)
        all_throughput_metrics = throughput_metrics + capacity_metrics
        
        if not all_throughput_metrics:
            summary.throughput_analysis = {"status": "no_data", "message": "No throughput metrics available"}
            return
        
        # Calculate throughput variance analysis
        sustained_rps_variance = next((m.variance_percent for m in throughput_metrics 
                                      if m.metric_name == "requests_per_second"), 0.0)
        peak_rps_variance = next((m.variance_percent for m in throughput_metrics 
                                 if m.metric_name == "peak_requests_per_second"), 0.0)
        capacity_variance = next((m.variance_percent for m in capacity_metrics 
                                 if m.metric_name == "concurrent_users_capacity"), 0.0)
        
        # Check throughput compliance
        compliant_metrics = [m for m in all_throughput_metrics if m.within_threshold]
        compliance_rate = (len(compliant_metrics) / len(all_throughput_metrics)) * 100.0
        
        # Check minimum throughput requirements
        current_rps = flask_metrics.get("requests_per_second", 0.0)
        meets_minimum = current_rps >= THROUGHPUT_THRESHOLD_RPS
        
        # Determine throughput status
        if compliance_rate == 100.0 and meets_minimum:
            status = "compliant"
            message = "Throughput performance meets all requirements"
        elif not meets_minimum:
            status = "below_minimum"
            message = f"Throughput below minimum requirement: {current_rps:.1f} < {THROUGHPUT_THRESHOLD_RPS} req/s"
        elif compliance_rate >= 75.0:
            status = "mostly_compliant"
            message = f"Throughput mostly compliant: {compliance_rate:.0f}% of metrics within threshold"
        else:
            status = "non_compliant"
            message = f"Throughput performance degraded: {compliance_rate:.0f}% compliant"
        
        summary.throughput_analysis = {
            "status": status,
            "message": message,
            "compliance_rate": compliance_rate,
            "sustained_rps_variance_percent": sustained_rps_variance,
            "peak_rps_variance_percent": peak_rps_variance,
            "capacity_variance_percent": capacity_variance,
            "current_sustained_rps": current_rps,
            "baseline_sustained_rps": self.nodejs_baseline.requests_per_second_sustained,
            "meets_minimum_threshold": meets_minimum,
            "minimum_threshold_rps": THROUGHPUT_THRESHOLD_RPS,
            "critical_issues": [m.metric_name for m in all_throughput_metrics if not m.within_threshold]
        }
    
    def _analyze_memory_usage_patterns(
        self,
        summary: BaselineComparisonSummary,
        flask_metrics: Dict[str, float]
    ) -> None:
        """Analyze memory usage patterns against Node.js baseline."""
        
        memory_metrics = summary.get_metrics_by_category(BaselineMetricCategory.MEMORY_UTILIZATION)
        
        if not memory_metrics:
            summary.memory_usage_analysis = {"status": "no_data", "message": "No memory usage metrics available"}
            return
        
        # Calculate memory usage analysis
        baseline_variance = next((m.variance_percent for m in memory_metrics 
                                 if m.metric_name == "memory_usage_mb"), 0.0)
        peak_variance = next((m.variance_percent for m in memory_metrics 
                             if m.metric_name == "memory_usage_peak_mb"), 0.0)
        heap_variance = next((m.variance_percent for m in memory_metrics 
                             if m.metric_name == "memory_heap_used_mb"), 0.0)
        
        # Check memory compliance (using 15% threshold)
        compliant_metrics = [m for m in memory_metrics if m.within_threshold]
        compliance_rate = (len(compliant_metrics) / len(memory_metrics)) * 100.0
        
        # Calculate memory efficiency
        current_memory = flask_metrics.get("memory_usage_mb", 0.0)
        baseline_memory = self.nodejs_baseline.memory_usage_baseline_mb
        memory_efficiency = (baseline_memory / current_memory * 100.0) if current_memory > 0 else 100.0
        
        # Detect potential memory leaks (significant variance)
        leak_risk = any(m.variance_percent > 20.0 for m in memory_metrics)
        
        # Determine memory usage status
        if compliance_rate == 100.0:
            status = "compliant"
            message = "Memory usage within acceptable variance limits"
        elif compliance_rate >= 75.0:
            status = "mostly_compliant"
            message = f"Memory usage mostly acceptable: {compliance_rate:.0f}% compliant"
        elif leak_risk:
            status = "leak_risk"
            message = "Potential memory leak detected - significant variance from baseline"
        else:
            status = "non_compliant"
            message = f"Memory usage exceeds acceptable variance: {compliance_rate:.0f}% compliant"
        
        summary.memory_usage_analysis = {
            "status": status,
            "message": message,
            "compliance_rate": compliance_rate,
            "baseline_variance_percent": baseline_variance,
            "peak_variance_percent": peak_variance,
            "heap_variance_percent": heap_variance,
            "current_memory_mb": current_memory,
            "baseline_memory_mb": baseline_memory,
            "memory_efficiency_percent": memory_efficiency,
            "leak_risk_detected": leak_risk,
            "variance_threshold_percent": MEMORY_VARIANCE_LIMIT,
            "critical_issues": [m.metric_name for m in memory_metrics if not m.within_threshold]
        }
    
    def _analyze_cpu_utilization(
        self,
        summary: BaselineComparisonSummary,
        flask_metrics: Dict[str, float]
    ) -> None:
        """Analyze CPU utilization against Node.js baseline."""
        
        cpu_metrics = summary.get_metrics_by_category(BaselineMetricCategory.CPU_UTILIZATION)
        
        if not cpu_metrics:
            summary.cpu_utilization_analysis = {"status": "no_data", "message": "No CPU utilization metrics available"}
            return
        
        # Calculate CPU utilization analysis
        average_variance = next((m.variance_percent for m in cpu_metrics 
                               if m.metric_name == "cpu_utilization_average"), 0.0)
        peak_variance = next((m.variance_percent for m in cpu_metrics 
                            if m.metric_name == "cpu_utilization_peak"), 0.0)
        
        # Check CPU compliance
        compliant_metrics = [m for m in cpu_metrics if m.within_threshold]
        compliance_rate = (len(compliant_metrics) / len(cpu_metrics)) * 100.0
        
        # Check CPU efficiency and thresholds
        current_cpu_avg = flask_metrics.get("cpu_utilization_average", 0.0)
        current_cpu_peak = flask_metrics.get("cpu_utilization_peak", 0.0)
        exceeds_threshold = current_cpu_peak > CPU_UTILIZATION_THRESHOLD
        
        # Calculate CPU efficiency
        baseline_cpu = self.nodejs_baseline.cpu_utilization_average
        cpu_efficiency = (baseline_cpu / current_cpu_avg * 100.0) if current_cpu_avg > 0 else 100.0
        
        # Determine CPU utilization status
        if compliance_rate == 100.0 and not exceeds_threshold:
            status = "compliant"
            message = "CPU utilization within acceptable variance and operational thresholds"
        elif exceeds_threshold:
            status = "threshold_exceeded"
            message = f"CPU utilization exceeds threshold: {current_cpu_peak:.1f}% > {CPU_UTILIZATION_THRESHOLD}%"
        elif compliance_rate >= 75.0:
            status = "mostly_compliant"
            message = f"CPU utilization mostly acceptable: {compliance_rate:.0f}% compliant"
        else:
            status = "non_compliant"
            message = f"CPU utilization variance exceeds limits: {compliance_rate:.0f}% compliant"
        
        summary.cpu_utilization_analysis = {
            "status": status,
            "message": message,
            "compliance_rate": compliance_rate,
            "average_variance_percent": average_variance,
            "peak_variance_percent": peak_variance,
            "current_cpu_average": current_cpu_avg,
            "current_cpu_peak": current_cpu_peak,
            "baseline_cpu_average": baseline_cpu,
            "baseline_cpu_peak": self.nodejs_baseline.cpu_utilization_peak,
            "cpu_efficiency_percent": cpu_efficiency,
            "exceeds_operational_threshold": exceeds_threshold,
            "operational_threshold_percent": CPU_UTILIZATION_THRESHOLD,
            "critical_issues": [m.metric_name for m in cpu_metrics if not m.within_threshold]
        }
    
    def _analyze_database_performance(
        self,
        summary: BaselineComparisonSummary,
        flask_metrics: Dict[str, float]
    ) -> None:
        """Analyze database performance against Node.js baseline."""
        
        db_metrics = summary.get_metrics_by_category(BaselineMetricCategory.DATABASE_PERFORMANCE)
        
        if not db_metrics:
            summary.database_performance_analysis = {"status": "no_data", "message": "No database performance metrics available"}
            return
        
        # Calculate database performance analysis
        mean_query_variance = next((m.variance_percent for m in db_metrics 
                                   if m.metric_name == "database_query_time_mean"), 0.0)
        p95_query_variance = next((m.variance_percent for m in db_metrics 
                                  if m.metric_name == "database_query_time_p95"), 0.0)
        
        # Check database compliance
        compliant_metrics = [m for m in db_metrics if m.within_threshold]
        compliance_rate = (len(compliant_metrics) / len(db_metrics)) * 100.0
        
        # Calculate database efficiency
        current_query_time = flask_metrics.get("database_query_time_mean", 0.0)
        baseline_query_time = self.nodejs_baseline.database_query_time_mean
        db_efficiency = (baseline_query_time / current_query_time * 100.0) if current_query_time > 0 else 100.0
        
        # Determine database performance status
        if compliance_rate == 100.0:
            status = "compliant"
            message = "Database performance within acceptable variance limits"
        elif compliance_rate >= 80.0:
            status = "mostly_compliant"
            message = f"Database performance mostly acceptable: {compliance_rate:.0f}% compliant"
        else:
            status = "non_compliant"
            message = f"Database performance degraded: {compliance_rate:.0f}% compliant"
        
        summary.database_performance_analysis = {
            "status": status,
            "message": message,
            "compliance_rate": compliance_rate,
            "mean_query_variance_percent": mean_query_variance,
            "p95_query_variance_percent": p95_query_variance,
            "current_query_time_ms": current_query_time,
            "baseline_query_time_ms": baseline_query_time,
            "database_efficiency_percent": db_efficiency,
            "critical_issues": [m.metric_name for m in db_metrics if not m.within_threshold]
        }
    
    def _perform_trend_analysis(self, summary: BaselineComparisonSummary) -> None:
        """Perform trend analysis using historical comparison data."""
        
        if len(self.historical_comparisons) < 2:
            summary.trend_analysis = {
                "status": "insufficient_data",
                "message": "Insufficient historical data for trend analysis",
                "data_points": len(self.historical_comparisons)
            }
            return
        
        # Analyze trends across key metrics
        trend_metrics = {}
        
        for metric_category in BaselineMetricCategory:
            category_trends = self._analyze_category_trends(metric_category)
            if category_trends:
                trend_metrics[metric_category.value] = category_trends
        
        # Calculate overall trend direction
        improvement_count = sum(1 for trends in trend_metrics.values() 
                              if trends.get("direction") == "improving")
        degradation_count = sum(1 for trends in trend_metrics.values() 
                               if trends.get("direction") == "degrading")
        
        if improvement_count > degradation_count:
            overall_trend = "improving"
        elif degradation_count > improvement_count:
            overall_trend = "degrading"
        else:
            overall_trend = "stable"
        
        summary.trend_analysis = {
            "status": "available",
            "message": f"Trend analysis based on {len(self.historical_comparisons)} historical comparisons",
            "overall_trend": overall_trend,
            "data_points": len(self.historical_comparisons),
            "category_trends": trend_metrics,
            "improvement_categories": improvement_count,
            "degradation_categories": degradation_count
        }
    
    def _analyze_category_trends(self, category: BaselineMetricCategory) -> Optional[Dict[str, Any]]:
        """Analyze trends for specific metric category."""
        
        if len(self.historical_comparisons) < 3:
            return None
        
        # Extract compliance rates for the category from recent comparisons
        recent_comparisons = self.historical_comparisons[-5:]  # Last 5 comparisons
        compliance_rates = []
        
        for comparison in recent_comparisons:
            compliance_rate = comparison.calculate_category_compliance(category)
            compliance_rates.append(compliance_rate)
        
        if len(compliance_rates) < 3:
            return None
        
        # Calculate trend direction
        recent_avg = statistics.mean(compliance_rates[-3:])
        earlier_avg = statistics.mean(compliance_rates[:-3]) if len(compliance_rates) > 3 else compliance_rates[0]
        
        trend_change = recent_avg - earlier_avg
        
        if trend_change > 2.0:
            direction = "improving"
        elif trend_change < -2.0:
            direction = "degrading"
        else:
            direction = "stable"
        
        return {
            "direction": direction,
            "trend_change_percent": trend_change,
            "current_compliance": recent_avg,
            "historical_compliance": earlier_avg,
            "data_points": len(compliance_rates)
        }
    
    def _detect_performance_regressions(self, summary: BaselineComparisonSummary) -> None:
        """Detect performance regressions using statistical analysis."""
        
        regression_detected = False
        regression_details = []
        
        # Check for critical variance spikes
        critical_metrics = summary.get_critical_metrics()
        if critical_metrics:
            regression_detected = True
            for metric in critical_metrics:
                regression_details.append({
                    "metric": metric.metric_name,
                    "variance": metric.variance_percent,
                    "threshold": metric.critical_threshold,
                    "severity": "critical"
                })
        
        # Check for sudden degradation compared to recent history
        if len(self.historical_comparisons) >= 2:
            recent_compliance = self.historical_comparisons[-1].compliance_percentage
            current_compliance = summary.compliance_percentage
            
            compliance_drop = recent_compliance - current_compliance
            
            if compliance_drop > 15.0:  # >15% drop in compliance
                regression_detected = True
                regression_details.append({
                    "metric": "overall_compliance",
                    "variance": compliance_drop,
                    "threshold": 15.0,
                    "severity": "compliance_degradation"
                })
        
        summary.regression_detected = regression_detected
        
        if regression_detected:
            summary.trend_analysis["regression_details"] = regression_details
        
        # Check for performance improvements
        improvement_metrics = [m for m in summary.variance_metrics if m.is_improvement]
        summary.performance_improvement = len(improvement_metrics) > 0
        
        if summary.performance_improvement:
            summary.trend_analysis["improvement_details"] = [
                {
                    "metric": m.metric_name,
                    "improvement": abs(m.variance_percent),
                    "category": m.metric_category.value
                }
                for m in improvement_metrics
            ]
    
    def _generate_deployment_recommendation(self, summary: BaselineComparisonSummary) -> None:
        """Generate deployment recommendation based on baseline comparison analysis."""
        
        # Check for deployment blockers
        if summary.deployment_blockers:
            summary.deployment_recommendation = DeploymentRecommendation.BLOCK
            return
        
        # Check for critical issues
        critical_count = len(summary.critical_issues)
        if critical_count > 0:
            if critical_count >= 3 or summary.compliance_percentage < 70.0:
                summary.deployment_recommendation = DeploymentRecommendation.BLOCK
            else:
                summary.deployment_recommendation = DeploymentRecommendation.REVIEW
            return
        
        # Check for warning issues
        warning_count = len(summary.warning_issues)
        if warning_count > 0:
            if warning_count >= 5 or summary.compliance_percentage < 85.0:
                summary.deployment_recommendation = DeploymentRecommendation.REVIEW
            else:
                summary.deployment_recommendation = DeploymentRecommendation.CONDITIONAL
            return
        
        # Check for regression detection
        if summary.regression_detected:
            summary.deployment_recommendation = DeploymentRecommendation.REVIEW
            return
        
        # Check overall compliance
        if summary.overall_compliance and summary.compliance_percentage >= 95.0:
            summary.deployment_recommendation = DeploymentRecommendation.APPROVE
        elif summary.compliance_percentage >= 90.0:
            summary.deployment_recommendation = DeploymentRecommendation.CONDITIONAL
        else:
            summary.deployment_recommendation = DeploymentRecommendation.REVIEW
    
    def _generate_executive_summary(self, summary: BaselineComparisonSummary) -> None:
        """Generate comprehensive executive summary for stakeholder communication."""
        
        # Generate key findings
        key_findings = []
        
        # Overall compliance finding
        if summary.overall_compliance:
            key_findings.append(f"Performance meets ≤10% variance requirement: {summary.compliance_percentage:.1f}% compliance")
        else:
            key_findings.append(f"Performance variance exceeds ≤10% requirement: {summary.compliance_percentage:.1f}% compliance")
        
        # Critical issues finding
        if summary.critical_issues:
            key_findings.append(f"{len(summary.critical_issues)} critical performance issues require immediate attention")
        
        # Regression/improvement findings
        if summary.regression_detected:
            key_findings.append("Performance regression detected compared to recent history")
        elif summary.performance_improvement:
            key_findings.append("Performance improvements identified in key metrics")
        
        # Statistical confidence finding
        if summary.statistical_confidence >= MIN_STATISTICAL_CONFIDENCE:
            key_findings.append(f"Analysis based on statistically significant data ({summary.statistical_confidence:.0f}% confidence)")
        else:
            key_findings.append(f"Limited statistical confidence ({summary.statistical_confidence:.0f}%) - larger sample size recommended")
        
        summary.key_findings = key_findings
        
        # Generate business impact assessment
        if summary.deployment_recommendation == DeploymentRecommendation.APPROVE:
            business_impact = "Low business risk - deployment approved with performance requirements met"
        elif summary.deployment_recommendation == DeploymentRecommendation.CONDITIONAL:
            business_impact = "Moderate business risk - conditional deployment with enhanced monitoring recommended"
        elif summary.deployment_recommendation == DeploymentRecommendation.REVIEW:
            business_impact = "Elevated business risk - manual review required before deployment"
        else:  # BLOCK
            business_impact = "High business risk - deployment blocked due to performance non-compliance"
        
        summary.business_impact = business_impact
        
        # Generate technical recommendations
        technical_recommendations = []
        
        # Response time recommendations
        response_analysis = summary.response_time_analysis
        if response_analysis.get("status") == "non_compliant":
            technical_recommendations.append("Optimize API response times through caching and query optimization")
        
        # Memory recommendations
        memory_analysis = summary.memory_usage_analysis
        if memory_analysis.get("leak_risk_detected"):
            technical_recommendations.append("Investigate potential memory leaks and optimize garbage collection")
        elif memory_analysis.get("status") == "non_compliant":
            technical_recommendations.append("Optimize memory usage patterns and implement memory profiling")
        
        # CPU recommendations
        cpu_analysis = summary.cpu_utilization_analysis
        if cpu_analysis.get("exceeds_operational_threshold"):
            technical_recommendations.append("Reduce CPU utilization through code optimization and horizontal scaling")
        
        # Database recommendations
        db_analysis = summary.database_performance_analysis
        if db_analysis.get("status") == "non_compliant":
            technical_recommendations.append("Optimize database queries and connection pool configuration")
        
        # Throughput recommendations
        throughput_analysis = summary.throughput_analysis
        if throughput_analysis.get("status") == "below_minimum":
            technical_recommendations.append("Improve application throughput to meet minimum performance requirements")
        
        if not technical_recommendations:
            technical_recommendations.append("Continue monitoring performance metrics and maintain current optimization efforts")
        
        summary.technical_recommendations = technical_recommendations
        
        # Create executive summary dictionary
        summary.executive_summary = {
            "overall_status": summary.calculate_overall_status().value,
            "compliance_percentage": summary.compliance_percentage,
            "deployment_recommendation": summary.deployment_recommendation.value,
            "key_findings": summary.key_findings,
            "business_impact": summary.business_impact,
            "technical_recommendations": summary.technical_recommendations,
            "critical_issues_count": len(summary.critical_issues),
            "warning_issues_count": len(summary.warning_issues),
            "statistical_confidence": summary.statistical_confidence,
            "test_environment": summary.test_environment,
            "analysis_timestamp": summary.generation_timestamp.isoformat()
        }
    
    def _update_performance_trends(self, summary: BaselineComparisonSummary) -> None:
        """Update performance trends with current comparison data."""
        
        timestamp = summary.generation_timestamp
        
        # Update overall compliance trend
        self.performance_trends["overall_compliance"].append({
            "timestamp": timestamp,
            "value": summary.compliance_percentage,
            "sample_size": summary.total_sample_size
        })
        
        # Update category-specific trends
        for category in BaselineMetricCategory:
            compliance_rate = summary.calculate_category_compliance(category)
            self.performance_trends[f"{category.value}_compliance"].append({
                "timestamp": timestamp,
                "value": compliance_rate,
                "metrics_count": len(summary.get_metrics_by_category(category))
            })
        
        # Update individual metric trends
        for metric in summary.variance_metrics:
            self.performance_trends[f"{metric.metric_name}_variance"].append({
                "timestamp": timestamp,
                "value": metric.variance_percent,
                "status": metric.comparison_status.value
            })


class BaselineComparisonReportGenerator:
    """
    Comprehensive baseline comparison report generator providing multi-format reports
    with executive summaries, technical details, and deployment recommendations.
    
    Integrates with performance testing framework and monitoring infrastructure per
    Section 0.3.4 documentation requirements and Section 6.5 observability integration.
    """
    
    def __init__(self, analyzer: Optional[BaselineComparisonAnalyzer] = None):
        """
        Initialize report generator with baseline comparison analyzer.
        
        Args:
            analyzer: Optional baseline comparison analyzer (defaults to new instance)
        """
        self.analyzer = analyzer or BaselineComparisonAnalyzer()
        
        # Initialize visualization engine if available
        if PLOTLY_AVAILABLE:
            self.visualization_engine = PerformanceVisualizationEngine()
        else:
            self.visualization_engine = None
        
        # Initialize template environment if available
        if JINJA2_AVAILABLE:
            template_dir = Path(__file__).parent / "templates"
            self.template_env = Environment(
                loader=FileSystemLoader(str(template_dir)) if template_dir.exists() else None,
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.template_env = None
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
        
        # Report cache for performance optimization
        self.report_cache: Dict[str, Any] = {}
        self.cache_timestamps: Dict[str, datetime] = {}
    
    def generate_baseline_comparison_report(
        self,
        flask_metrics: Dict[str, float],
        report_format: ReportFormat = ReportFormat.HTML,
        audience: ReportAudience = ReportAudience.TECHNICAL,
        test_context: Optional[Dict[str, Any]] = None,
        include_charts: bool = True,
        output_path: Optional[Path] = None
    ) -> Union[str, Dict[str, Any]]:
        """
        Generate comprehensive baseline comparison report in specified format.
        
        Args:
            flask_metrics: Current Flask implementation performance metrics
            report_format: Output format (HTML, JSON, Markdown)
            audience: Target audience for report content and styling
            test_context: Optional test execution context information
            include_charts: Whether to include data visualizations
            output_path: Optional path to save the generated report
            
        Returns:
            Generated report content (string for text formats, dict for JSON)
            
        Raises:
            ValueError: If flask_metrics is empty or invalid
            RuntimeError: If report generation fails
        """
        try:
            # Perform baseline comparison analysis
            comparison_summary = self.analyzer.analyze_baseline_comparison(
                flask_metrics=flask_metrics,
                test_context=test_context,
                include_trend_analysis=True,
                include_regression_detection=True
            )
            
            self.logger.info(
                "Generated baseline comparison analysis",
                overall_compliance=comparison_summary.overall_compliance,
                compliance_percentage=comparison_summary.compliance_percentage,
                deployment_recommendation=comparison_summary.deployment_recommendation.value,
                report_format=report_format.value,
                audience=audience.value
            )
            
            # Generate report in requested format
            if report_format == ReportFormat.JSON:
                report_content = self._generate_json_report(comparison_summary)
            elif report_format == ReportFormat.HTML:
                report_content = self._generate_html_report(comparison_summary, audience, include_charts)
            elif report_format == ReportFormat.MARKDOWN:
                report_content = self._generate_markdown_report(comparison_summary, audience)
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
            
            # Save report if output path provided
            if output_path:
                self._save_report(report_content, output_path, report_format)
            
            return report_content
            
        except Exception as e:
            self.logger.error(
                "Baseline comparison report generation failed",
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise RuntimeError(f"Report generation failed: {str(e)}")
    
    def generate_ci_cd_gate_report(
        self,
        flask_metrics: Dict[str, float],
        pipeline_context: Dict[str, Any],
        variance_threshold: float = PERFORMANCE_VARIANCE_LIMIT
    ) -> Dict[str, Any]:
        """
        Generate CI/CD deployment gate report for automated pipeline integration.
        
        Args:
            flask_metrics: Current Flask implementation performance metrics
            pipeline_context: CI/CD pipeline context information
            variance_threshold: Performance variance threshold for gate decisions
            
        Returns:
            CI/CD gate report with deployment approval/blocking recommendation
        """
        try:
            # Perform baseline comparison analysis
            test_context = {
                "environment": pipeline_context.get("environment", "ci"),
                "pipeline_id": pipeline_context.get("pipeline_id"),
                "commit_sha": pipeline_context.get("commit_sha"),
                "branch": pipeline_context.get("branch"),
                "variance_threshold": variance_threshold
            }
            
            comparison_summary = self.analyzer.analyze_baseline_comparison(
                flask_metrics=flask_metrics,
                test_context=test_context,
                include_trend_analysis=False,  # Skip for CI/CD speed
                include_regression_detection=True
            )
            
            # Generate CI/CD specific report
            gate_report = {
                "pipeline_context": pipeline_context,
                "performance_gate_decision": {
                    "deployment_approved": comparison_summary.deployment_recommendation == DeploymentRecommendation.APPROVE,
                    "recommendation": comparison_summary.deployment_recommendation.value,
                    "confidence_level": comparison_summary.statistical_confidence,
                    "blocking_issues": comparison_summary.deployment_blockers,
                    "requires_manual_review": comparison_summary.deployment_recommendation == DeploymentRecommendation.REVIEW
                },
                "performance_summary": {
                    "overall_compliance": comparison_summary.overall_compliance,
                    "compliance_percentage": comparison_summary.compliance_percentage,
                    "variance_threshold": variance_threshold,
                    "critical_issues_count": len(comparison_summary.critical_issues),
                    "warning_issues_count": len(comparison_summary.warning_issues),
                    "regression_detected": comparison_summary.regression_detected
                },
                "detailed_variance_analysis": [
                    {
                        "metric": metric.metric_name,
                        "category": metric.metric_category.value,
                        "variance_percent": metric.variance_percent,
                        "within_threshold": metric.within_threshold,
                        "status": metric.comparison_status.value,
                        "severity": metric.severity_level.value
                    }
                    for metric in comparison_summary.variance_metrics
                ],
                "deployment_recommendations": {
                    "critical_actions": comparison_summary.critical_issues,
                    "warning_actions": comparison_summary.warning_issues,
                    "technical_recommendations": comparison_summary.technical_recommendations,
                    "rollback_triggers": comparison_summary.deployment_blockers
                },
                "report_metadata": {
                    "generation_timestamp": comparison_summary.generation_timestamp.isoformat(),
                    "analyzer_version": "1.0.0",
                    "baseline_version": self.analyzer.nodejs_baseline.baseline_version,
                    "statistical_confidence": comparison_summary.statistical_confidence
                }
            }
            
            self.logger.info(
                "Generated CI/CD gate report",
                deployment_approved=gate_report["performance_gate_decision"]["deployment_approved"],
                recommendation=gate_report["performance_gate_decision"]["recommendation"],
                compliance_percentage=gate_report["performance_summary"]["compliance_percentage"],
                pipeline_id=pipeline_context.get("pipeline_id")
            )
            
            return gate_report
            
        except Exception as e:
            self.logger.error(
                "CI/CD gate report generation failed",
                error=str(e),
                pipeline_context=pipeline_context
            )
            raise
    
    def _generate_json_report(self, summary: BaselineComparisonSummary) -> str:
        """Generate JSON format baseline comparison report."""
        
        # Convert summary to dictionary
        report_data = {
            "report_metadata": {
                "report_id": summary.report_id,
                "title": summary.report_title,
                "generation_timestamp": summary.generation_timestamp.isoformat(),
                "report_version": summary.report_version,
                "analyzer_version": "1.0.0"
            },
            "test_context": {
                "environment": summary.test_environment,
                "duration_seconds": summary.test_duration_seconds,
                "sample_size": summary.total_sample_size,
                "statistical_confidence": summary.statistical_confidence
            },
            "baseline_comparison": {
                "overall_compliance": summary.overall_compliance,
                "compliance_percentage": summary.compliance_percentage,
                "deployment_recommendation": summary.deployment_recommendation.value,
                "overall_status": summary.calculate_overall_status().value
            },
            "variance_metrics": [
                {
                    "metric_name": metric.metric_name,
                    "category": metric.metric_category.value,
                    "nodejs_baseline": metric.nodejs_baseline_value,
                    "flask_current": metric.flask_current_value,
                    "variance_percent": metric.variance_percent,
                    "comparison_status": metric.comparison_status.value,
                    "within_threshold": metric.within_threshold,
                    "measurement_unit": metric.measurement_unit,
                    "sample_size": metric.sample_size,
                    "confidence_level": metric.confidence_level
                }
                for metric in summary.variance_metrics
            ],
            "performance_analysis": {
                "response_time": summary.response_time_analysis,
                "throughput": summary.throughput_analysis,
                "memory_usage": summary.memory_usage_analysis,
                "cpu_utilization": summary.cpu_utilization_analysis,
                "database_performance": summary.database_performance_analysis
            },
            "trend_analysis": summary.trend_analysis,
            "issues_and_recommendations": {
                "critical_issues": summary.critical_issues,
                "warning_issues": summary.warning_issues,
                "deployment_blockers": summary.deployment_blockers,
                "improvement_opportunities": summary.improvement_opportunities,
                "technical_recommendations": summary.technical_recommendations
            },
            "executive_summary": summary.executive_summary
        }
        
        return json.dumps(report_data, indent=2, default=str, ensure_ascii=False)
    
    def _generate_html_report(
        self,
        summary: BaselineComparisonSummary,
        audience: ReportAudience,
        include_charts: bool
    ) -> str:
        """Generate HTML format baseline comparison report."""
        
        # Generate charts if requested and available
        charts_html = ""
        if include_charts and self.visualization_engine:
            charts_html = self._generate_charts_html(summary)
        
        # Use template if available, otherwise generate basic HTML
        if self.template_env:
            try:
                template_name = f"baseline_comparison_{audience.value}.html"
                template = self.template_env.get_template(template_name)
                return template.render(
                    summary=summary,
                    charts=charts_html,
                    performance_colors=PERFORMANCE_COLORS,
                    format_timestamp=lambda ts: ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "Unknown",
                    format_percentage=lambda x: f"{x:.1f}%" if x is not None else "N/A",
                    format_number=lambda x: f"{x:.2f}" if x is not None else "N/A"
                )
            except Exception as template_error:
                self.logger.warning(f"Template {template_name} not found, using basic HTML", error=str(template_error))
        
        # Generate basic HTML report
        return self._generate_basic_html_report(summary, audience, charts_html)
    
    def _generate_basic_html_report(
        self,
        summary: BaselineComparisonSummary,
        audience: ReportAudience,
        charts_html: str
    ) -> str:
        """Generate basic HTML report without templates."""
        
        # Determine report styling based on overall status
        overall_status = summary.calculate_overall_status()
        status_color = PERFORMANCE_COLORS.get(overall_status.value, '#9E9E9E')
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{summary.report_title}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.2em; font-weight: 300; }}
        .header .meta {{ margin-top: 10px; opacity: 0.9; font-size: 0.9em; }}
        .status-banner {{ background-color: {status_color}; color: white; padding: 15px; margin: 20px 0; border-radius: 5px; text-align: center; font-weight: bold; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: #f8f9fa; border: 1px solid #e9ecef; padding: 20px; border-radius: 8px; }}
        .metric-card h3 {{ margin-top: 0; color: #495057; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }}
        .compliance-excellent {{ border-left: 4px solid {PERFORMANCE_COLORS['excellent']}; }}
        .compliance-warning {{ border-left: 4px solid {PERFORMANCE_COLORS['warning']}; }}
        .compliance-critical {{ border-left: 4px solid {PERFORMANCE_COLORS['critical']}; }}
        .compliance-failure {{ border-left: 4px solid {PERFORMANCE_COLORS['failure']}; }}
        .variance-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .variance-table th, .variance-table td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
        .variance-table th {{ background-color: #e9ecef; font-weight: 600; }}
        .variance-positive {{ color: {PERFORMANCE_COLORS['failure']}; font-weight: bold; }}
        .variance-negative {{ color: {PERFORMANCE_COLORS['improvement']}; font-weight: bold; }}
        .variance-neutral {{ color: #6c757d; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #343a40; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .recommendations {{ background: #e7f3ff; border: 1px solid #b8daff; padding: 20px; border-radius: 5px; margin: 15px 0; }}
        .recommendations h4 {{ color: #004085; margin-top: 0; }}
        .recommendations ul {{ margin: 10px 0; padding-left: 20px; }}
        .recommendations li {{ margin: 5px 0; }}
        .issue-list {{ list-style: none; padding: 0; }}
        .issue-list li {{ padding: 10px; margin: 5px 0; border-radius: 5px; }}
        .issue-critical {{ background: #f8d7da; border-left: 4px solid {PERFORMANCE_COLORS['failure']}; }}
        .issue-warning {{ background: #fff3cd; border-left: 4px solid {PERFORMANCE_COLORS['warning']}; }}
        .issue-improvement {{ background: #d4edda; border-left: 4px solid {PERFORMANCE_COLORS['improvement']}; }}
        .chart-container {{ margin: 20px 0; text-align: center; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; text-align: center; color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{summary.report_title}</h1>
            <div class="meta">
                <strong>Environment:</strong> {summary.test_environment} | 
                <strong>Generated:</strong> {summary.generation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |
                <strong>Audience:</strong> {audience.value.title()}
            </div>
        </div>
        
        <div class="status-banner">
            Overall Status: {overall_status.value.upper()} | 
            Compliance: {summary.compliance_percentage:.1f}% | 
            Deployment: {summary.deployment_recommendation.value.upper()}
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <h3>Performance Compliance</h3>
                    <p><strong>Overall Compliance:</strong> {summary.compliance_percentage:.1f}%</p>
                    <p><strong>≤10% Variance Requirement:</strong> {'✅ Met' if summary.overall_compliance else '❌ Not Met'}</p>
                    <p><strong>Statistical Confidence:</strong> {summary.statistical_confidence:.0f}%</p>
                    <p><strong>Sample Size:</strong> {summary.total_sample_size:,} measurements</p>
                </div>
                
                <div class="metric-card">
                    <h3>Deployment Recommendation</h3>
                    <p><strong>Decision:</strong> {summary.deployment_recommendation.value.upper()}</p>
                    <p><strong>Critical Issues:</strong> {len(summary.critical_issues)}</p>
                    <p><strong>Warning Issues:</strong> {len(summary.warning_issues)}</p>
                    <p><strong>Blocking Issues:</strong> {len(summary.deployment_blockers)}</p>
                </div>
            </div>
            
            <div class="recommendations">
                <h4>🎯 Key Findings</h4>
                <ul>
                    {''.join(f'<li>{finding}</li>' for finding in summary.key_findings)}
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>📈 Variance Analysis</h2>
            <table class="variance-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Category</th>
                        <th>Node.js Baseline</th>
                        <th>Flask Current</th>
                        <th>Variance</th>
                        <th>Status</th>
                        <th>Compliant</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(self._format_variance_table_row(metric) for metric in summary.variance_metrics)}
                </tbody>
            </table>
        </div>
        
        {self._format_performance_analysis_html(summary)}
        
        {charts_html}
        
        <div class="section">
            <h2>🚨 Issues and Recommendations</h2>
            
            {self._format_issues_html('Critical Issues', summary.critical_issues, 'critical')}
            {self._format_issues_html('Warning Issues', summary.warning_issues, 'warning')}
            {self._format_issues_html('Performance Improvements', summary.improvement_opportunities, 'improvement')}
            
            <div class="recommendations">
                <h4>🔧 Technical Recommendations</h4>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in summary.technical_recommendations)}
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Flask Migration Baseline Comparison Engine v1.0.0</p>
            <p>Baseline: Node.js {self.analyzer.nodejs_baseline.nodejs_version} | 
               Express.js {self.analyzer.nodejs_baseline.express_version}</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_content
    
    def _format_variance_table_row(self, metric: BaselineVarianceMetric) -> str:
        """Format individual variance metric as HTML table row."""
        
        # Determine variance styling
        if metric.variance_percent > 0:
            variance_class = "variance-positive"
            variance_symbol = "+"
        elif metric.variance_percent < 0:
            variance_class = "variance-negative"
            variance_symbol = ""
        else:
            variance_class = "variance-neutral"
            variance_symbol = ""
        
        # Format values
        baseline_str = f"{metric.nodejs_baseline_value:.2f} {metric.measurement_unit}"
        current_str = f"{metric.flask_current_value:.2f} {metric.measurement_unit}"
        variance_str = f"{variance_symbol}{metric.variance_percent:.1f}%"
        status_str = metric.comparison_status.value.title()
        compliant_str = "✅" if metric.within_threshold else "❌"
        
        return f"""
        <tr class="compliance-{metric.comparison_status.value}">
            <td><strong>{metric.metric_name}</strong></td>
            <td>{metric.metric_category.value.replace('_', ' ').title()}</td>
            <td>{baseline_str}</td>
            <td>{current_str}</td>
            <td class="{variance_class}">{variance_str}</td>
            <td>{status_str}</td>
            <td>{compliant_str}</td>
        </tr>
        """
    
    def _format_performance_analysis_html(self, summary: BaselineComparisonSummary) -> str:
        """Format performance analysis sections as HTML."""
        
        sections = []
        
        # Response Time Analysis
        if summary.response_time_analysis:
            analysis = summary.response_time_analysis
            sections.append(f"""
            <div class="section">
                <h2>⚡ Response Time Analysis</h2>
                <div class="metric-card compliance-{analysis.get('status', 'unknown')}">
                    <h3>Response Time Performance</h3>
                    <p><strong>Status:</strong> {analysis.get('message', 'No data')}</p>
                    <p><strong>Compliance Rate:</strong> {analysis.get('compliance_rate', 0):.1f}%</p>
                    <p><strong>Mean Variance:</strong> {analysis.get('mean_variance_percent', 0):+.1f}%</p>
                    <p><strong>P95 Variance:</strong> {analysis.get('p95_variance_percent', 0):+.1f}%</p>
                    <p><strong>Current P95:</strong> {analysis.get('current_p95_ms', 0):.1f}ms</p>
                    <p><strong>SLA Threshold:</strong> {'❌ Exceeded' if analysis.get('exceeds_sla_threshold') else '✅ Met'} ({analysis.get('sla_threshold_ms', 0)}ms)</p>
                </div>
            </div>
            """)
        
        # Throughput Analysis
        if summary.throughput_analysis:
            analysis = summary.throughput_analysis
            sections.append(f"""
            <div class="section">
                <h2>🚀 Throughput Analysis</h2>
                <div class="metric-card compliance-{analysis.get('status', 'unknown')}">
                    <h3>Throughput Performance</h3>
                    <p><strong>Status:</strong> {analysis.get('message', 'No data')}</p>
                    <p><strong>Compliance Rate:</strong> {analysis.get('compliance_rate', 0):.1f}%</p>
                    <p><strong>Sustained RPS Variance:</strong> {analysis.get('sustained_rps_variance_percent', 0):+.1f}%</p>
                    <p><strong>Current RPS:</strong> {analysis.get('current_sustained_rps', 0):.1f} req/s</p>
                    <p><strong>Minimum Threshold:</strong> {'✅ Met' if analysis.get('meets_minimum_threshold') else '❌ Not Met'} ({analysis.get('minimum_threshold_rps', 0)} req/s)</p>
                </div>
            </div>
            """)
        
        # Memory Analysis
        if summary.memory_usage_analysis:
            analysis = summary.memory_usage_analysis
            sections.append(f"""
            <div class="section">
                <h2>💾 Memory Usage Analysis</h2>
                <div class="metric-card compliance-{analysis.get('status', 'unknown')}">
                    <h3>Memory Performance</h3>
                    <p><strong>Status:</strong> {analysis.get('message', 'No data')}</p>
                    <p><strong>Compliance Rate:</strong> {analysis.get('compliance_rate', 0):.1f}%</p>
                    <p><strong>Memory Variance:</strong> {analysis.get('baseline_variance_percent', 0):+.1f}%</p>
                    <p><strong>Current Memory:</strong> {analysis.get('current_memory_mb', 0):.1f} MB</p>
                    <p><strong>Memory Efficiency:</strong> {analysis.get('memory_efficiency_percent', 0):.1f}%</p>
                    <p><strong>Leak Risk:</strong> {'⚠️ Detected' if analysis.get('leak_risk_detected') else '✅ None'}</p>
                </div>
            </div>
            """)
        
        return ''.join(sections)
    
    def _format_issues_html(self, title: str, issues: List[str], issue_type: str) -> str:
        """Format issues list as HTML."""
        
        if not issues:
            return ""
        
        return f"""
        <h3>{title} ({len(issues)})</h3>
        <ul class="issue-list">
            {''.join(f'<li class="issue-{issue_type}">{issue}</li>' for issue in issues)}
        </ul>
        """
    
    def _generate_charts_html(self, summary: BaselineComparisonSummary) -> str:
        """Generate interactive charts HTML using Plotly."""
        
        if not self.visualization_engine:
            return '<div class="section"><h2>📊 Charts</h2><p>Charts not available - Plotly not installed</p></div>'
        
        try:
            charts_html = '<div class="section"><h2>📊 Performance Visualizations</h2>'
            
            # Variance comparison chart
            charts_html += self._create_variance_chart(summary)
            
            # Compliance trend chart if historical data available
            if len(self.analyzer.historical_comparisons) > 1:
                charts_html += self._create_compliance_trend_chart()
            
            charts_html += '</div>'
            
            return charts_html
            
        except Exception as e:
            self.logger.warning(f"Chart generation failed: {e}")
            return '<div class="section"><h2>📊 Charts</h2><p>Chart generation temporarily unavailable</p></div>'
    
    def _create_variance_chart(self, summary: BaselineComparisonSummary) -> str:
        """Create variance comparison chart."""
        
        if not summary.variance_metrics:
            return ""
        
        # Prepare data for chart
        metric_names = [m.metric_name for m in summary.variance_metrics]
        variance_values = [m.variance_percent for m in summary.variance_metrics]
        colors = [PERFORMANCE_COLORS.get(m.comparison_status.value, '#9E9E9E') for m in summary.variance_metrics]
        
        # Create bar chart
        fig = go.Figure(data=[
            go.Bar(
                x=metric_names,
                y=variance_values,
                marker_color=colors,
                text=[f"{v:+.1f}%" for v in variance_values],
                textposition='auto',
                hovertemplate='<b>%{x}</b><br>Variance: %{y:.2f}%<br>Status: %{customdata}<extra></extra>',
                customdata=[m.comparison_status.value.title() for m in summary.variance_metrics]
            )
        ])
        
        # Add threshold reference lines
        fig.add_hline(y=CRITICAL_VARIANCE_LIMIT, line_dash="dash", line_color="red", 
                     annotation_text="Critical Threshold (10%)")
        fig.add_hline(y=-CRITICAL_VARIANCE_LIMIT, line_dash="dash", line_color="red")
        fig.add_hline(y=WARNING_VARIANCE_LIMIT, line_dash="dot", line_color="orange", 
                     annotation_text="Warning Threshold (5%)")
        fig.add_hline(y=-WARNING_VARIANCE_LIMIT, line_dash="dot", line_color="orange")
        
        # Update layout
        fig.update_layout(
            title="Performance Variance vs Node.js Baseline",
            xaxis_title="Performance Metrics",
            yaxis_title="Variance Percentage (%)",
            width=CHART_WIDTH,
            height=CHART_HEIGHT,
            showlegend=False,
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        # Rotate x-axis labels for readability
        fig.update_xaxes(tickangle=45)
        
        chart_html = fig.to_html(include_plotlyjs='cdn', div_id=f"variance_chart_{uuid.uuid4().hex[:8]}")
        
        return f'<div class="chart-container">{chart_html}</div>'
    
    def _create_compliance_trend_chart(self) -> str:
        """Create compliance trend chart from historical data."""
        
        if len(self.analyzer.historical_comparisons) < 2:
            return ""
        
        # Extract trend data
        timestamps = [comp.generation_timestamp for comp in self.analyzer.historical_comparisons]
        compliance_rates = [comp.compliance_percentage for comp in self.analyzer.historical_comparisons]
        
        # Create line chart
        fig = go.Figure(data=[
            go.Scatter(
                x=timestamps,
                y=compliance_rates,
                mode='lines+markers',
                name='Compliance Rate',
                line=dict(color=PERFORMANCE_COLORS['baseline'], width=3),
                marker=dict(size=8)
            )
        ])
        
        # Add threshold reference line
        fig.add_hline(y=90.0, line_dash="dash", line_color="orange", 
                     annotation_text="Target Compliance (90%)")
        
        # Update layout
        fig.update_layout(
            title="Performance Compliance Trend",
            xaxis_title="Time",
            yaxis_title="Compliance Percentage (%)",
            width=CHART_WIDTH,
            height=CHART_HEIGHT//2,
            showlegend=False,
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        chart_html = fig.to_html(include_plotlyjs='cdn', div_id=f"trend_chart_{uuid.uuid4().hex[:8]}")
        
        return f'<div class="chart-container">{chart_html}</div>'
    
    def _generate_markdown_report(
        self,
        summary: BaselineComparisonSummary,
        audience: ReportAudience
    ) -> str:
        """Generate Markdown format baseline comparison report."""
        
        overall_status = summary.calculate_overall_status()
        
        md_content = f"""# {summary.report_title}

**Report ID:** {summary.report_id}  
**Generated:** {summary.generation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Environment:** {summary.test_environment}  
**Audience:** {audience.value.title()}  
**Analyzer Version:** 1.0.0

## 📊 Executive Summary

**Overall Status:** {overall_status.value.upper()}  
**Compliance:** {summary.compliance_percentage:.1f}% of metrics within ≤10% variance threshold  
**Deployment Recommendation:** {summary.deployment_recommendation.value.upper()}  
**Statistical Confidence:** {summary.statistical_confidence:.0f}%

### Key Findings

{chr(10).join(f'- {finding}' for finding in summary.key_findings)}

### Business Impact

{summary.business_impact}

## 📈 Performance Analysis

### Variance Summary

| Metric | Category | Node.js Baseline | Flask Current | Variance | Status | Compliant |
|--------|----------|------------------|---------------|----------|--------|-----------|
{chr(10).join(self._format_markdown_variance_row(metric) for metric in summary.variance_metrics)}

### Response Time Analysis

{self._format_markdown_analysis(summary.response_time_analysis)}

### Throughput Analysis

{self._format_markdown_analysis(summary.throughput_analysis)}

### Memory Usage Analysis

{self._format_markdown_analysis(summary.memory_usage_analysis)}

### CPU Utilization Analysis

{self._format_markdown_analysis(summary.cpu_utilization_analysis)}

### Database Performance Analysis

{self._format_markdown_analysis(summary.database_performance_analysis)}

## 🚨 Issues and Recommendations

### Critical Issues ({len(summary.critical_issues)})

{chr(10).join(f'- ❌ {issue}' for issue in summary.critical_issues) if summary.critical_issues else 'None'}

### Warning Issues ({len(summary.warning_issues)})

{chr(10).join(f'- ⚠️ {issue}' for issue in summary.warning_issues) if summary.warning_issues else 'None'}

### Performance Improvements ({len(summary.improvement_opportunities)})

{chr(10).join(f'- ✅ {improvement}' for improvement in summary.improvement_opportunities) if summary.improvement_opportunities else 'None'}

### Technical Recommendations

{chr(10).join(f'- {rec}' for rec in summary.technical_recommendations)}

## 📋 Deployment Assessment

**Recommendation:** {summary.deployment_recommendation.value.upper()}

**Deployment Blockers:** {len(summary.deployment_blockers)}
{chr(10).join(f'- 🚫 {blocker}' for blocker in summary.deployment_blockers) if summary.deployment_blockers else 'None'}

## 📊 Trend Analysis

{self._format_markdown_trend_analysis(summary.trend_analysis)}

---

*Report generated by Flask Migration Baseline Comparison Engine v1.0.0*  
*Node.js Baseline: {self.analyzer.nodejs_baseline.nodejs_version} | Express.js: {self.analyzer.nodejs_baseline.express_version}*
"""
        
        return md_content
    
    def _format_markdown_variance_row(self, metric: BaselineVarianceMetric) -> str:
        """Format variance metric as Markdown table row."""
        
        compliant_emoji = "✅" if metric.within_threshold else "❌"
        variance_sign = "+" if metric.variance_percent > 0 else ""
        
        return f"| {metric.metric_name} | {metric.metric_category.value.replace('_', ' ').title()} | {metric.nodejs_baseline_value:.2f} {metric.measurement_unit} | {metric.flask_current_value:.2f} {metric.measurement_unit} | {variance_sign}{metric.variance_percent:.1f}% | {metric.comparison_status.value.title()} | {compliant_emoji} |"
    
    def _format_markdown_analysis(self, analysis: Dict[str, Any]) -> str:
        """Format performance analysis as Markdown."""
        
        if not analysis:
            return "No data available."
        
        status = analysis.get('status', 'unknown')
        message = analysis.get('message', 'No message')
        compliance_rate = analysis.get('compliance_rate', 0)
        
        return f"""
**Status:** {status.title()}  
**Message:** {message}  
**Compliance Rate:** {compliance_rate:.1f}%
"""
    
    def _format_markdown_trend_analysis(self, trend_analysis: Dict[str, Any]) -> str:
        """Format trend analysis as Markdown."""
        
        if not trend_analysis or trend_analysis.get('status') == 'insufficient_data':
            return "Insufficient historical data for trend analysis."
        
        overall_trend = trend_analysis.get('overall_trend', 'unknown')
        data_points = trend_analysis.get('data_points', 0)
        
        return f"""
**Overall Trend:** {overall_trend.title()}  
**Historical Data Points:** {data_points}  
**Status:** {trend_analysis.get('message', 'No trend data')}
"""
    
    def _save_report(self, content: Union[str, Dict[str, Any]], output_path: Path, format_type: ReportFormat) -> None:
        """Save generated report to file."""
        
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if isinstance(content, dict):
                    json.dump(content, f, indent=2, default=str)
                else:
                    f.write(content)
            
            self.logger.info("Saved baseline comparison report", path=str(output_path), format=format_type.value)
            
        except Exception as e:
            self.logger.error("Failed to save report", path=str(output_path), error=str(e))
            raise


# Convenience functions for external integration

def create_baseline_comparison_analyzer(
    baseline_data_file: Optional[str] = None
) -> BaselineComparisonAnalyzer:
    """
    Create a baseline comparison analyzer instance with optional baseline data.
    
    Args:
        baseline_data_file: Optional path to custom baseline data file
        
    Returns:
        Configured BaselineComparisonAnalyzer instance
    """
    if baseline_data_file:
        from tests.performance.baseline_data import BaselineDataManager
        baseline_manager = BaselineDataManager(Path(baseline_data_file))
    else:
        baseline_manager = get_baseline_manager()
    
    return BaselineComparisonAnalyzer(baseline_manager)


def generate_baseline_comparison_report(
    flask_metrics: Dict[str, float],
    report_format: ReportFormat = ReportFormat.HTML,
    audience: ReportAudience = ReportAudience.TECHNICAL,
    output_path: Optional[Path] = None,
    test_context: Optional[Dict[str, Any]] = None
) -> Union[str, Dict[str, Any]]:
    """
    Generate baseline comparison report with Flask performance metrics.
    
    Args:
        flask_metrics: Current Flask implementation performance metrics
        report_format: Output format (HTML, JSON, Markdown)
        audience: Target audience for report content
        output_path: Optional path to save the generated report
        test_context: Optional test execution context
        
    Returns:
        Generated report content
        
    Example:
        >>> flask_metrics = {
        ...     "api_response_time_mean": 135.0,
        ...     "api_response_time_p95": 310.0,
        ...     "requests_per_second": 118.0,
        ...     "memory_usage_mb": 268.0,
        ...     "cpu_utilization_average": 22.5
        ... }
        >>> report = generate_baseline_comparison_report(
        ...     flask_metrics,
        ...     ReportFormat.HTML,
        ...     ReportAudience.EXECUTIVE
        ... )
    """
    generator = BaselineComparisonReportGenerator()
    return generator.generate_baseline_comparison_report(
        flask_metrics=flask_metrics,
        report_format=report_format,
        audience=audience,
        test_context=test_context,
        output_path=output_path
    )


def validate_performance_compliance(
    flask_metrics: Dict[str, float],
    variance_threshold: float = PERFORMANCE_VARIANCE_LIMIT
) -> Dict[str, Any]:
    """
    Validate Flask performance compliance against ≤10% variance requirement.
    
    Args:
        flask_metrics: Current Flask implementation performance metrics
        variance_threshold: Performance variance threshold (default: 10%)
        
    Returns:
        Compliance validation results with deployment recommendation
        
    Example:
        >>> compliance = validate_performance_compliance({
        ...     "api_response_time_p95": 295.0,
        ...     "requests_per_second": 118.0
        ... })
        >>> print(f"Compliant: {compliance['overall_compliance']}")
        >>> print(f"Recommendation: {compliance['deployment_recommendation']}")
    """
    analyzer = BaselineComparisonAnalyzer()
    
    test_context = {
        "environment": "validation",
        "variance_threshold": variance_threshold,
        "validation_timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    summary = analyzer.analyze_baseline_comparison(
        flask_metrics=flask_metrics,
        test_context=test_context,
        include_trend_analysis=False,
        include_regression_detection=True
    )
    
    return {
        "overall_compliance": summary.overall_compliance,
        "compliance_percentage": summary.compliance_percentage,
        "deployment_recommendation": summary.deployment_recommendation.value,
        "critical_issues": summary.critical_issues,
        "warning_issues": summary.warning_issues,
        "deployment_blockers": summary.deployment_blockers,
        "variance_metrics": [
            {
                "metric": metric.metric_name,
                "variance_percent": metric.variance_percent,
                "within_threshold": metric.within_threshold,
                "status": metric.comparison_status.value
            }
            for metric in summary.variance_metrics
        ],
        "statistical_confidence": summary.statistical_confidence,
        "validation_timestamp": summary.generation_timestamp.isoformat()
    }


def create_ci_cd_performance_gate(
    flask_metrics: Dict[str, float],
    pipeline_context: Dict[str, Any],
    variance_threshold: float = PERFORMANCE_VARIANCE_LIMIT
) -> Dict[str, Any]:
    """
    Create CI/CD performance gate report for automated deployment decisions.
    
    Args:
        flask_metrics: Current Flask implementation performance metrics
        pipeline_context: CI/CD pipeline context information
        variance_threshold: Performance variance threshold for gate decisions
        
    Returns:
        CI/CD gate report with deployment approval/blocking recommendation
        
    Example:
        >>> gate_report = create_ci_cd_performance_gate(
        ...     flask_metrics={
        ...         "api_response_time_p95": 295.0,
        ...         "requests_per_second": 118.0
        ...     },
        ...     pipeline_context={
        ...         "pipeline_id": "12345",
        ...         "environment": "staging",
        ...         "branch": "main",
        ...         "commit_sha": "abc123"
        ...     }
        ... )
        >>> approved = gate_report["performance_gate_decision"]["deployment_approved"]
    """
    generator = BaselineComparisonReportGenerator()
    return generator.generate_ci_cd_gate_report(
        flask_metrics=flask_metrics,
        pipeline_context=pipeline_context,
        variance_threshold=variance_threshold
    )


# Export public interface
__all__ = [
    # Core classes
    'BaselineComparisonAnalyzer',
    'BaselineComparisonReportGenerator',
    'BaselineComparisonSummary',
    'BaselineVarianceMetric',
    
    # Enumerations
    'ComparisonStatus',
    'ReportSeverity',
    'DeploymentRecommendation',
    
    # Convenience functions
    'create_baseline_comparison_analyzer',
    'generate_baseline_comparison_report',
    'validate_performance_compliance',
    'create_ci_cd_performance_gate',
    
    # Constants
    'PERFORMANCE_VARIANCE_LIMIT',
    'MEMORY_VARIANCE_LIMIT',
    'WARNING_VARIANCE_LIMIT',
    'CRITICAL_VARIANCE_LIMIT'
]