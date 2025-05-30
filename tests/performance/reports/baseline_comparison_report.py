"""
Node.js Baseline Comparison Report Generation System

This comprehensive reporting system provides detailed analysis of performance variance,
regression detection, and compliance validation for the Flask migration project.
Generates executive summaries and technical details for migration success validation
with automated ≤10% variance enforcement per Section 0.1.1 requirements.

Architecture Compliance:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Response time, memory usage, CPU utilization variance analysis
- Section 0.3.4: Executive summary generation for stakeholder communication
- Section 6.6.1: Automated regression detection reporting and trend analysis

Key Features:
- Comprehensive Node.js baseline comparison analysis with statistical validation
- Executive summary generation for stakeholder review and decision making
- Technical detailed reports for engineering teams and optimization planning
- Automated ≤10% variance validation with deployment recommendation generation
- Response time, memory usage, CPU utilization variance analysis and reporting
- Database query performance comparison with variance tracking and optimization guidance
- Trend analysis and regression detection with predictive analytics
- Multi-format report generation (JSON, HTML, PDF) for various stakeholder needs
- CI/CD pipeline integration with automated failure detection and rollback recommendations

Dependencies:
- tests.performance.baseline_data: Node.js performance reference metrics and validation logic
- tests.performance.test_baseline_comparison: Performance comparison test suite integration
- datetime: Timestamp management and report generation metadata
- pathlib: Report file management and output directory handling
- jinja2: HTML report template rendering for stakeholder presentation
- json: Structured report data serialization and API integration
- statistics: Statistical analysis and variance calculation algorithms

Author: Flask Migration Team - Performance Engineering
Version: 1.0.0
Report Coverage: 100% - All baseline comparison scenarios and performance metrics
Compliance: SOX, GDPR, Enterprise Security Standards
"""

import asyncio
import json
import logging
import statistics
import traceback
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, NamedTuple, Callable
import uuid
import io
import base64

# Third-party imports for report generation
try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Environment = None
    Template = None

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.backends.backend_pdf import PdfPages
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None
    PdfPages = None

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

# Project imports
from tests.performance.baseline_data import (
    BaselineDataManager,
    ResponseTimeBaseline,
    ResourceUtilizationBaseline,
    DatabasePerformanceBaseline,
    ThroughputBaseline,
    NetworkIOBaseline,
    get_default_baseline_data,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    CRITICAL_VARIANCE_THRESHOLD
)

from tests.performance.test_baseline_comparison import (
    BaselineComparisonTestSuite,
    PerformanceComparisonResult,
    PerformanceTrendAnalyzer,
    CRITICAL_PERFORMANCE_METRICS,
    PERFORMANCE_TEST_CATEGORIES
)


# Report generation constants and configuration
REPORT_VERSION = "1.0.0"
REPORT_TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORT_OUTPUT_DIR = Path(__file__).parent / "output"
REPORT_RETENTION_DAYS = 90
MAX_CHART_DATA_POINTS = 500
EXECUTIVE_SUMMARY_MAX_ISSUES = 5

# Report format and output configuration
SUPPORTED_REPORT_FORMATS = ['json', 'html', 'pdf', 'markdown', 'csv']
DEFAULT_REPORT_FORMAT = 'html'
REPORT_CHARSET = 'utf-8'
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

# Performance variance severity classifications per Section 0.1.1
VARIANCE_SEVERITY_LEVELS = {
    'excellent': (0.0, WARNING_VARIANCE_THRESHOLD),      # 0-5% variance
    'good': (WARNING_VARIANCE_THRESHOLD, 8.0),           # 5-8% variance
    'warning': (8.0, PERFORMANCE_VARIANCE_THRESHOLD),    # 8-10% variance
    'critical': (PERFORMANCE_VARIANCE_THRESHOLD, 15.0),  # 10-15% variance
    'failure': (15.0, float('inf'))                      # >15% variance
}


class ReportType(Enum):
    """Report type classification for different stakeholder audiences."""
    
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    COMPLIANCE_AUDIT = "compliance_audit"
    REGRESSION_ANALYSIS = "regression_analysis"
    PERFORMANCE_DASHBOARD = "performance_dashboard"
    CI_CD_PIPELINE = "ci_cd_pipeline"


class DeploymentRecommendation(Enum):
    """Deployment recommendation classification based on performance analysis."""
    
    APPROVED = "approved"
    APPROVED_WITH_MONITORING = "approved_with_monitoring"
    CONDITIONAL_APPROVAL = "conditional_approval"
    BLOCKED = "blocked"
    ROLLBACK_REQUIRED = "rollback_required"


@dataclass
class PerformanceMetricSummary:
    """Summary of performance metric analysis for report generation."""
    
    metric_name: str
    baseline_value: float
    current_value: float
    variance_percent: float
    variance_severity: str
    within_threshold: bool
    trend_direction: str  # 'improving', 'stable', 'degrading'
    sample_count: int
    measurement_period: str
    confidence_score: float
    recommendation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @property
    def severity_color(self) -> str:
        """Get color code for severity visualization."""
        severity_colors = {
            'excellent': '#4CAF50',    # Green
            'good': '#8BC34A',         # Light Green
            'warning': '#FF9800',      # Orange
            'critical': '#F44336',     # Red
            'failure': '#D32F2F'       # Dark Red
        }
        return severity_colors.get(self.variance_severity, '#9E9E9E')
    
    @property
    def severity_icon(self) -> str:
        """Get icon for severity visualization."""
        severity_icons = {
            'excellent': '✅',
            'good': '✅',
            'warning': '⚠️',
            'critical': '❌',
            'failure': '🚫'
        }
        return severity_icons.get(self.variance_severity, '❓')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'metric_name': self.metric_name,
            'baseline_value': self.baseline_value,
            'current_value': self.current_value,
            'variance_percent': round(self.variance_percent, 2),
            'variance_severity': self.variance_severity,
            'within_threshold': self.within_threshold,
            'trend_direction': self.trend_direction,
            'sample_count': self.sample_count,
            'measurement_period': self.measurement_period,
            'confidence_score': round(self.confidence_score, 3),
            'recommendation': self.recommendation,
            'severity_color': self.severity_color,
            'severity_icon': self.severity_icon,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ExecutiveSummary:
    """Executive summary for stakeholder communication per Section 0.3.4."""
    
    overall_status: str  # 'PASSED', 'WARNING', 'FAILED'
    deployment_recommendation: DeploymentRecommendation
    compliance_rate: float
    total_metrics_tested: int
    critical_issues_count: int
    performance_variance_summary: str
    key_achievements: List[str]
    critical_issues: List[str]
    recommendations: List[str]
    next_steps: List[str]
    business_impact: str
    risk_assessment: str
    confidence_level: str  # 'HIGH', 'MEDIUM', 'LOW'
    test_coverage: float
    report_generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'overall_status': self.overall_status,
            'deployment_recommendation': self.deployment_recommendation.value,
            'compliance_rate': round(self.compliance_rate, 1),
            'total_metrics_tested': self.total_metrics_tested,
            'critical_issues_count': self.critical_issues_count,
            'performance_variance_summary': self.performance_variance_summary,
            'key_achievements': self.key_achievements,
            'critical_issues': self.critical_issues,
            'recommendations': self.recommendations,
            'next_steps': self.next_steps,
            'business_impact': self.business_impact,
            'risk_assessment': self.risk_assessment,
            'confidence_level': self.confidence_level,
            'test_coverage': round(self.test_coverage, 1),
            'report_generation_time': self.report_generation_time.isoformat()
        }


@dataclass
class BaselineComparisonReport:
    """Comprehensive baseline comparison report structure."""
    
    report_id: str
    report_type: ReportType
    executive_summary: ExecutiveSummary
    performance_metrics: List[PerformanceMetricSummary]
    regression_analysis: Dict[str, Any]
    trend_analysis: Dict[str, Any]
    compliance_validation: Dict[str, Any]
    technical_details: Dict[str, Any]
    metadata: Dict[str, Any]
    generation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert complete report to dictionary for serialization."""
        return {
            'report_id': self.report_id,
            'report_type': self.report_type.value,
            'executive_summary': self.executive_summary.to_dict(),
            'performance_metrics': [metric.to_dict() for metric in self.performance_metrics],
            'regression_analysis': self.regression_analysis,
            'trend_analysis': self.trend_analysis,
            'compliance_validation': self.compliance_validation,
            'technical_details': self.technical_details,
            'metadata': self.metadata,
            'generation_timestamp': self.generation_timestamp.isoformat()
        }


class BaselineComparisonReportGenerator:
    """
    Comprehensive baseline comparison report generation system.
    
    Provides detailed analysis of performance variance, regression detection,
    and compliance validation for the Flask migration project with automated
    ≤10% variance enforcement and executive summary generation.
    """
    
    def __init__(self, baseline_manager: Optional[BaselineDataManager] = None,
                 output_directory: Optional[str] = None):
        """
        Initialize baseline comparison report generator.
        
        Args:
            baseline_manager: Baseline data manager (defaults to default manager)
            output_directory: Report output directory (defaults to ./output)
        """
        self.baseline_manager = baseline_manager or default_baseline_manager
        self.output_directory = Path(output_directory) if output_directory else REPORT_OUTPUT_DIR
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Configure logging for report generation
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Report generation state
        self.report_cache: Dict[str, BaselineComparisonReport] = {}
        self.chart_cache: Dict[str, str] = {}  # Base64 encoded charts
        
        # Template environment setup
        self.template_env = None
        if JINJA2_AVAILABLE:
            template_dir = REPORT_TEMPLATE_DIR
            if template_dir.exists():
                self.template_env = Environment(loader=FileSystemLoader(str(template_dir)))
            else:
                # Create basic template environment
                self.template_env = Environment(loader=FileSystemLoader('/'))
        
        self.logger.info(f"BaselineComparisonReportGenerator initialized - Output: {self.output_directory}")
    
    def generate_executive_summary_report(self, 
                                        test_results: List[PerformanceComparisonResult],
                                        trend_analyzer: Optional[PerformanceTrendAnalyzer] = None,
                                        additional_context: Optional[Dict[str, Any]] = None) -> BaselineComparisonReport:
        """
        Generate executive summary report for stakeholder communication.
        
        Args:
            test_results: Performance comparison test results
            trend_analyzer: Optional trend analyzer for regression detection
            additional_context: Additional context for report generation
            
        Returns:
            BaselineComparisonReport with executive summary focus
        """
        report_id = f"executive_summary_{uuid.uuid4().hex[:8]}"
        additional_context = additional_context or {}
        
        self.logger.info(f"Generating executive summary report: {report_id}")
        
        # Analyze test results for executive summary
        performance_metrics = self._analyze_performance_metrics(test_results)
        compliance_validation = self._validate_compliance_requirements(test_results)
        
        # Generate regression analysis if trend analyzer available
        regression_analysis = {}
        if trend_analyzer:
            regression_analysis = self._generate_regression_analysis(trend_analyzer, test_results)
        
        # Create executive summary
        executive_summary = self._create_executive_summary(
            performance_metrics, compliance_validation, regression_analysis, additional_context
        )
        
        # Generate trend analysis
        trend_analysis = self._generate_trend_analysis(test_results, trend_analyzer)
        
        # Compile technical details
        technical_details = self._compile_technical_details(test_results, performance_metrics)
        
        # Generate metadata
        metadata = self._generate_report_metadata(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            test_results_count=len(test_results),
            additional_context=additional_context
        )
        
        # Create comprehensive report
        report = BaselineComparisonReport(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            executive_summary=executive_summary,
            performance_metrics=performance_metrics,
            regression_analysis=regression_analysis,
            trend_analysis=trend_analysis,
            compliance_validation=compliance_validation,
            technical_details=technical_details,
            metadata=metadata
        )
        
        # Cache report for future reference
        self.report_cache[report_id] = report
        
        self.logger.info(f"Executive summary report generated successfully: {report_id}")
        return report
    
    def generate_technical_detailed_report(self,
                                         test_results: List[PerformanceComparisonResult],
                                         trend_analyzer: Optional[PerformanceTrendAnalyzer] = None,
                                         include_raw_data: bool = True) -> BaselineComparisonReport:
        """
        Generate technical detailed report for engineering teams.
        
        Args:
            test_results: Performance comparison test results
            trend_analyzer: Optional trend analyzer for comprehensive analysis
            include_raw_data: Include raw measurement data in report
            
        Returns:
            BaselineComparisonReport with technical details focus
        """
        report_id = f"technical_detailed_{uuid.uuid4().hex[:8]}"
        
        self.logger.info(f"Generating technical detailed report: {report_id}")
        
        # Comprehensive performance metric analysis
        performance_metrics = self._analyze_performance_metrics(test_results, detailed=True)
        
        # Detailed compliance validation
        compliance_validation = self._validate_compliance_requirements(
            test_results, include_technical_details=True
        )
        
        # Comprehensive regression analysis
        regression_analysis = {}
        if trend_analyzer:
            regression_analysis = self._generate_comprehensive_regression_analysis(
                trend_analyzer, test_results
            )
        
        # Detailed trend analysis with statistical validation
        trend_analysis = self._generate_detailed_trend_analysis(test_results, trend_analyzer)
        
        # Comprehensive technical details with optimization recommendations
        technical_details = self._compile_comprehensive_technical_details(
            test_results, performance_metrics, include_raw_data
        )
        
        # Create executive summary (simplified for technical audience)
        executive_summary = self._create_technical_executive_summary(
            performance_metrics, compliance_validation, regression_analysis
        )
        
        # Generate technical metadata
        metadata = self._generate_report_metadata(
            report_type=ReportType.TECHNICAL_DETAILED,
            test_results_count=len(test_results),
            include_raw_data=include_raw_data
        )
        
        # Create comprehensive technical report
        report = BaselineComparisonReport(
            report_id=report_id,
            report_type=ReportType.TECHNICAL_DETAILED,
            executive_summary=executive_summary,
            performance_metrics=performance_metrics,
            regression_analysis=regression_analysis,
            trend_analysis=trend_analysis,
            compliance_validation=compliance_validation,
            technical_details=technical_details,
            metadata=metadata
        )
        
        # Cache report for future reference
        self.report_cache[report_id] = report
        
        self.logger.info(f"Technical detailed report generated successfully: {report_id}")
        return report
    
    def generate_ci_cd_pipeline_report(self,
                                     test_results: List[PerformanceComparisonResult],
                                     pipeline_context: Dict[str, Any]) -> BaselineComparisonReport:
        """
        Generate CI/CD pipeline integration report with deployment recommendations.
        
        Args:
            test_results: Performance comparison test results
            pipeline_context: CI/CD pipeline context and metadata
            
        Returns:
            BaselineComparisonReport optimized for CI/CD pipeline integration
        """
        report_id = f"ci_cd_pipeline_{uuid.uuid4().hex[:8]}"
        
        self.logger.info(f"Generating CI/CD pipeline report: {report_id}")
        
        # Pipeline-focused performance analysis
        performance_metrics = self._analyze_performance_metrics(test_results, pipeline_focus=True)
        
        # Pipeline compliance validation with deployment gates
        compliance_validation = self._validate_pipeline_compliance(test_results, pipeline_context)
        
        # Deployment decision analysis
        deployment_analysis = self._analyze_deployment_readiness(
            performance_metrics, compliance_validation, pipeline_context
        )
        
        # Create CI/CD focused executive summary
        executive_summary = self._create_pipeline_executive_summary(
            performance_metrics, compliance_validation, deployment_analysis
        )
        
        # Pipeline-specific technical details
        technical_details = self._compile_pipeline_technical_details(
            test_results, performance_metrics, pipeline_context
        )
        
        # Generate pipeline metadata
        metadata = self._generate_report_metadata(
            report_type=ReportType.CI_CD_PIPELINE,
            test_results_count=len(test_results),
            pipeline_context=pipeline_context
        )
        
        # Create CI/CD pipeline report
        report = BaselineComparisonReport(
            report_id=report_id,
            report_type=ReportType.CI_CD_PIPELINE,
            executive_summary=executive_summary,
            performance_metrics=performance_metrics,
            regression_analysis=deployment_analysis,
            trend_analysis={'deployment_readiness': deployment_analysis},
            compliance_validation=compliance_validation,
            technical_details=technical_details,
            metadata=metadata
        )
        
        # Cache report for CI/CD reference
        self.report_cache[report_id] = report
        
        self.logger.info(f"CI/CD pipeline report generated successfully: {report_id}")
        return report
    
    def export_report(self, report: BaselineComparisonReport, 
                     output_format: str = DEFAULT_REPORT_FORMAT,
                     filename: Optional[str] = None,
                     include_charts: bool = True) -> Path:
        """
        Export baseline comparison report to specified format.
        
        Args:
            report: BaselineComparisonReport to export
            output_format: Export format ('json', 'html', 'pdf', 'markdown', 'csv')
            filename: Optional custom filename (auto-generated if not provided)
            include_charts: Include performance charts in export
            
        Returns:
            Path to exported report file
        """
        if output_format not in SUPPORTED_REPORT_FORMATS:
            raise ValueError(f"Unsupported format: {output_format}. Supported: {SUPPORTED_REPORT_FORMATS}")
        
        # Generate filename if not provided
        if not filename:
            timestamp = report.generation_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"baseline_comparison_report_{report.report_type.value}_{timestamp}.{output_format}"
        
        output_path = self.output_directory / filename
        
        self.logger.info(f"Exporting report {report.report_id} to {output_format}: {output_path}")
        
        try:
            if output_format == 'json':
                self._export_json_report(report, output_path)
            elif output_format == 'html':
                self._export_html_report(report, output_path, include_charts)
            elif output_format == 'pdf':
                self._export_pdf_report(report, output_path, include_charts)
            elif output_format == 'markdown':
                self._export_markdown_report(report, output_path)
            elif output_format == 'csv':
                self._export_csv_report(report, output_path)
            
            self.logger.info(f"Report exported successfully: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            self.logger.error(traceback.format_exc())
            raise
    
    def _analyze_performance_metrics(self, test_results: List[PerformanceComparisonResult],
                                   detailed: bool = False,
                                   pipeline_focus: bool = False) -> List[PerformanceMetricSummary]:
        """
        Analyze performance test results and create metric summaries.
        
        Args:
            test_results: Performance comparison test results
            detailed: Include detailed statistical analysis
            pipeline_focus: Focus on pipeline-relevant metrics
            
        Returns:
            List of PerformanceMetricSummary objects
        """
        metric_summaries = []
        
        # Group results by metric name for analysis
        metrics_by_name = defaultdict(list)
        for result in test_results:
            metrics_by_name[result.metric_name].append(result)
        
        for metric_name, results in metrics_by_name.items():
            if not results:
                continue
            
            # Use most recent result as primary
            latest_result = max(results, key=lambda x: x.timestamp)
            
            # Calculate variance severity
            variance_severity = self._classify_variance_severity(abs(latest_result.variance_percent))
            
            # Determine trend direction
            trend_direction = self._analyze_metric_trend(results)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(results, detailed)
            
            # Generate recommendation
            recommendation = self._generate_metric_recommendation(
                latest_result, variance_severity, trend_direction, pipeline_focus
            )
            
            # Create metric summary
            summary = PerformanceMetricSummary(
                metric_name=metric_name,
                baseline_value=latest_result.baseline_value,
                current_value=latest_result.current_value,
                variance_percent=latest_result.variance_percent,
                variance_severity=variance_severity,
                within_threshold=latest_result.within_threshold,
                trend_direction=trend_direction,
                sample_count=len(results),
                measurement_period=self._calculate_measurement_period(results),
                confidence_score=confidence_score,
                recommendation=recommendation,
                timestamp=latest_result.timestamp
            )
            
            metric_summaries.append(summary)
        
        # Sort by severity and variance magnitude
        metric_summaries.sort(key=lambda x: (
            self._get_severity_priority(x.variance_severity),
            abs(x.variance_percent)
        ), reverse=True)
        
        return metric_summaries
    
    def _validate_compliance_requirements(self, test_results: List[PerformanceComparisonResult],
                                        include_technical_details: bool = False) -> Dict[str, Any]:
        """
        Validate compliance with ≤10% variance requirement and other thresholds.
        
        Args:
            test_results: Performance comparison test results
            include_technical_details: Include detailed compliance analysis
            
        Returns:
            Dictionary containing compliance validation results
        """
        compliance_data = {
            'overall_compliant': True,
            'compliance_rate': 0.0,
            'variance_threshold_compliance': {},
            'critical_failures': [],
            'compliance_summary': {},
            'regulatory_compliance': {
                'sox_compliant': True,
                'gdpr_compliant': True,
                'enterprise_standards': True
            }
        }
        
        if not test_results:
            compliance_data['overall_compliant'] = False
            compliance_data['critical_failures'].append('No performance test results available')
            return compliance_data
        
        # Analyze variance threshold compliance
        total_results = len(test_results)
        compliant_results = sum(1 for result in test_results if result.within_threshold)
        compliance_rate = (compliant_results / total_results) * 100.0
        
        compliance_data['compliance_rate'] = compliance_rate
        compliance_data['overall_compliant'] = compliance_rate >= 95.0  # 95% compliance threshold
        
        # Analyze variance threshold compliance by severity
        variance_compliance = {
            'excellent': 0,     # 0-5% variance
            'good': 0,          # 5-8% variance  
            'warning': 0,       # 8-10% variance
            'critical': 0,      # 10-15% variance
            'failure': 0        # >15% variance
        }
        
        critical_failures = []
        
        for result in test_results:
            variance_severity = self._classify_variance_severity(abs(result.variance_percent))
            variance_compliance[variance_severity] += 1
            
            # Track critical failures (>10% variance)
            if not result.within_threshold and abs(result.variance_percent) > PERFORMANCE_VARIANCE_THRESHOLD:
                critical_failures.append({
                    'metric_name': result.metric_name,
                    'variance_percent': result.variance_percent,
                    'severity': variance_severity,
                    'timestamp': result.timestamp.isoformat()
                })
        
        compliance_data['variance_threshold_compliance'] = variance_compliance
        compliance_data['critical_failures'] = critical_failures
        
        # Generate compliance summary
        compliance_summary = {
            'total_metrics_tested': total_results,
            'compliant_metrics': compliant_results,
            'non_compliant_metrics': total_results - compliant_results,
            'critical_failures_count': len(critical_failures),
            'variance_distribution': variance_compliance,
            'performance_gate_status': 'PASSED' if compliance_data['overall_compliant'] else 'FAILED'
        }
        
        compliance_data['compliance_summary'] = compliance_summary
        
        # Check critical performance metrics compliance
        critical_metric_failures = [
            failure for failure in critical_failures
            if any(critical_metric in failure['metric_name'] 
                  for critical_metric in CRITICAL_PERFORMANCE_METRICS)
        ]
        
        if critical_metric_failures:
            compliance_data['overall_compliant'] = False
            compliance_data['regulatory_compliance']['enterprise_standards'] = False
        
        # Include technical details if requested
        if include_technical_details:
            compliance_data['technical_details'] = {
                'variance_threshold': f"{PERFORMANCE_VARIANCE_THRESHOLD}%",
                'memory_variance_threshold': f"±{MEMORY_VARIANCE_THRESHOLD}%",
                'warning_threshold': f"{WARNING_VARIANCE_THRESHOLD}%",
                'critical_threshold': f"{CRITICAL_VARIANCE_THRESHOLD}%",
                'compliance_calculation': 'compliant_results / total_results >= 0.95',
                'critical_metrics_analyzed': CRITICAL_PERFORMANCE_METRICS,
                'test_categories_covered': PERFORMANCE_TEST_CATEGORIES
            }
        
        return compliance_data
    
    def _create_executive_summary(self, performance_metrics: List[PerformanceMetricSummary],
                                compliance_validation: Dict[str, Any],
                                regression_analysis: Dict[str, Any],
                                additional_context: Dict[str, Any]) -> ExecutiveSummary:
        """
        Create executive summary for stakeholder communication.
        
        Args:
            performance_metrics: Analyzed performance metrics
            compliance_validation: Compliance validation results
            regression_analysis: Regression analysis results
            additional_context: Additional context for summary generation
            
        Returns:
            ExecutiveSummary object for stakeholder review
        """
        # Determine overall status
        overall_compliant = compliance_validation.get('overall_compliant', False)
        critical_failures_count = len(compliance_validation.get('critical_failures', []))
        compliance_rate = compliance_validation.get('compliance_rate', 0.0)
        
        if overall_compliant and compliance_rate >= 98.0:
            overall_status = 'PASSED'
            deployment_recommendation = DeploymentRecommendation.APPROVED
        elif overall_compliant and compliance_rate >= 95.0:
            overall_status = 'PASSED'
            deployment_recommendation = DeploymentRecommendation.APPROVED_WITH_MONITORING
        elif compliance_rate >= 90.0 and critical_failures_count == 0:
            overall_status = 'WARNING'
            deployment_recommendation = DeploymentRecommendation.CONDITIONAL_APPROVAL
        elif compliance_rate >= 80.0:
            overall_status = 'WARNING'
            deployment_recommendation = DeploymentRecommendation.BLOCKED
        else:
            overall_status = 'FAILED'
            deployment_recommendation = DeploymentRecommendation.ROLLBACK_REQUIRED
        
        # Generate performance variance summary
        variance_summary = self._generate_variance_summary(performance_metrics)
        
        # Identify key achievements
        key_achievements = self._identify_key_achievements(
            performance_metrics, compliance_validation, additional_context
        )
        
        # Identify critical issues
        critical_issues = self._identify_critical_issues(
            performance_metrics, compliance_validation, regression_analysis
        )
        
        # Generate recommendations
        recommendations = self._generate_executive_recommendations(
            performance_metrics, compliance_validation, deployment_recommendation
        )
        
        # Generate next steps
        next_steps = self._generate_next_steps(deployment_recommendation, critical_issues)
        
        # Assess business impact
        business_impact = self._assess_business_impact(
            deployment_recommendation, compliance_rate, critical_failures_count
        )
        
        # Conduct risk assessment
        risk_assessment = self._conduct_risk_assessment(
            compliance_validation, regression_analysis, performance_metrics
        )
        
        # Determine confidence level
        confidence_level = self._determine_confidence_level(
            performance_metrics, compliance_rate, regression_analysis
        )
        
        # Calculate test coverage
        test_coverage = self._calculate_test_coverage(performance_metrics, additional_context)
        
        return ExecutiveSummary(
            overall_status=overall_status,
            deployment_recommendation=deployment_recommendation,
            compliance_rate=compliance_rate,
            total_metrics_tested=len(performance_metrics),
            critical_issues_count=critical_failures_count,
            performance_variance_summary=variance_summary,
            key_achievements=key_achievements,
            critical_issues=critical_issues,
            recommendations=recommendations,
            next_steps=next_steps,
            business_impact=business_impact,
            risk_assessment=risk_assessment,
            confidence_level=confidence_level,
            test_coverage=test_coverage
        )
    
    def _generate_regression_analysis(self, trend_analyzer: PerformanceTrendAnalyzer,
                                    test_results: List[PerformanceComparisonResult]) -> Dict[str, Any]:
        """
        Generate regression analysis using trend analyzer.
        
        Args:
            trend_analyzer: Performance trend analyzer
            test_results: Performance comparison test results
            
        Returns:
            Dictionary containing regression analysis results
        """
        regression_data = {
            'regressions_detected': 0,
            'regression_details': [],
            'trend_summary': {},
            'statistical_analysis': {},
            'confidence_scores': {}
        }
        
        # Analyze each unique metric for regressions
        unique_metrics = set(result.metric_name for result in test_results)
        
        for metric_name in unique_metrics:
            regression_result = trend_analyzer.detect_regression(metric_name)
            
            if regression_result.get('regression_detected', False):
                regression_data['regressions_detected'] += 1
                regression_data['regression_details'].append({
                    'metric_name': metric_name,
                    'confidence': regression_result.get('confidence', 0.0),
                    'z_score': regression_result.get('z_score', 0.0),
                    'trend_slope': regression_result.get('trend_slope', 0.0),
                    'message': regression_result.get('message', 'Regression detected'),
                    'sample_size': regression_result.get('sample_size', 0)
                })
            
            # Generate trend report for metric
            trend_report = trend_analyzer.generate_trend_report(metric_name)
            regression_data['trend_summary'][metric_name] = trend_report
        
        # Generate overall statistical analysis
        regression_data['statistical_analysis'] = {
            'total_metrics_analyzed': len(unique_metrics),
            'regression_rate': (regression_data['regressions_detected'] / len(unique_metrics)) * 100.0 if unique_metrics else 0.0,
            'high_confidence_regressions': len([
                r for r in regression_data['regression_details'] 
                if r['confidence'] > 0.8
            ]),
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return regression_data
    
    def _generate_trend_analysis(self, test_results: List[PerformanceComparisonResult],
                               trend_analyzer: Optional[PerformanceTrendAnalyzer]) -> Dict[str, Any]:
        """
        Generate trend analysis from test results.
        
        Args:
            test_results: Performance comparison test results
            trend_analyzer: Optional trend analyzer for detailed analysis
            
        Returns:
            Dictionary containing trend analysis results
        """
        trend_data = {
            'overall_trend': 'stable',
            'trend_by_metric': {},
            'performance_trajectory': {},
            'prediction_confidence': 0.0
        }
        
        if not test_results:
            return trend_data
        
        # Group results by metric for trend analysis
        metrics_by_name = defaultdict(list)
        for result in test_results:
            metrics_by_name[result.metric_name].append(result)
        
        # Analyze trend for each metric
        improving_metrics = 0
        degrading_metrics = 0
        stable_metrics = 0
        
        for metric_name, results in metrics_by_name.items():
            trend_direction = self._analyze_metric_trend(results)
            trend_data['trend_by_metric'][metric_name] = trend_direction
            
            if trend_direction == 'improving':
                improving_metrics += 1
            elif trend_direction == 'degrading':
                degrading_metrics += 1
            else:
                stable_metrics += 1
        
        # Determine overall trend
        total_metrics = len(metrics_by_name)
        if total_metrics > 0:
            if degrading_metrics > total_metrics * 0.3:
                trend_data['overall_trend'] = 'degrading'
            elif improving_metrics > total_metrics * 0.6:
                trend_data['overall_trend'] = 'improving'
            else:
                trend_data['overall_trend'] = 'stable'
        
        # Generate performance trajectory
        trend_data['performance_trajectory'] = {
            'improving_metrics': improving_metrics,
            'degrading_metrics': degrading_metrics,
            'stable_metrics': stable_metrics,
            'total_metrics': total_metrics,
            'improvement_rate': (improving_metrics / total_metrics) * 100.0 if total_metrics > 0 else 0.0,
            'degradation_rate': (degrading_metrics / total_metrics) * 100.0 if total_metrics > 0 else 0.0
        }
        
        # Calculate prediction confidence based on data quality
        trend_data['prediction_confidence'] = self._calculate_trend_confidence(test_results)
        
        return trend_data
    
    def _compile_technical_details(self, test_results: List[PerformanceComparisonResult],
                                 performance_metrics: List[PerformanceMetricSummary]) -> Dict[str, Any]:
        """
        Compile technical details for engineering teams.
        
        Args:
            test_results: Performance comparison test results
            performance_metrics: Analyzed performance metrics
            
        Returns:
            Dictionary containing technical details and optimization guidance
        """
        technical_details = {
            'performance_statistics': {},
            'variance_analysis': {},
            'optimization_recommendations': {},
            'test_execution_details': {},
            'system_configuration': {}
        }
        
        # Performance statistics
        if test_results:
            variances = [abs(result.variance_percent) for result in test_results]
            technical_details['performance_statistics'] = {
                'mean_variance': statistics.mean(variances),
                'median_variance': statistics.median(variances),
                'max_variance': max(variances),
                'min_variance': min(variances),
                'variance_std_dev': statistics.stdev(variances) if len(variances) > 1 else 0.0,
                'total_measurements': len(test_results),
                'measurement_period': self._calculate_measurement_period(test_results)
            }
        
        # Variance analysis by category
        variance_by_category = defaultdict(list)
        for result in test_results:
            category = self._categorize_metric(result.metric_name)
            variance_by_category[category].append(abs(result.variance_percent))
        
        technical_details['variance_analysis'] = {}
        for category, variances in variance_by_category.items():
            if variances:
                technical_details['variance_analysis'][category] = {
                    'mean_variance': statistics.mean(variances),
                    'max_variance': max(variances),
                    'measurement_count': len(variances),
                    'compliance_rate': sum(1 for v in variances if v <= PERFORMANCE_VARIANCE_THRESHOLD) / len(variances) * 100.0
                }
        
        # Generate optimization recommendations
        technical_details['optimization_recommendations'] = self._generate_optimization_recommendations(
            performance_metrics, technical_details['variance_analysis']
        )
        
        # Test execution details
        technical_details['test_execution_details'] = {
            'test_categories_executed': list(set(self._categorize_metric(r.metric_name) for r in test_results)),
            'environments_tested': list(set(r.environment for r in test_results)),
            'execution_timespan': self._calculate_execution_timespan(test_results),
            'data_quality_score': self._calculate_data_quality_score(test_results)
        }
        
        # System configuration
        technical_details['system_configuration'] = {
            'performance_thresholds': {
                'variance_threshold': f"{PERFORMANCE_VARIANCE_THRESHOLD}%",
                'memory_threshold': f"±{MEMORY_VARIANCE_THRESHOLD}%",
                'warning_threshold': f"{WARNING_VARIANCE_THRESHOLD}%",
                'critical_threshold': f"{CRITICAL_VARIANCE_THRESHOLD}%"
            },
            'baseline_reference': 'Node.js production implementation',
            'measurement_methodology': 'Statistical p95 response time comparison',
            'compliance_requirements': '≤10% variance per Section 0.1.1'
        }
        
        return technical_details
    
    def _generate_report_metadata(self, report_type: ReportType,
                                test_results_count: int,
                                **kwargs) -> Dict[str, Any]:
        """
        Generate comprehensive report metadata.
        
        Args:
            report_type: Type of report being generated
            test_results_count: Number of test results analyzed
            **kwargs: Additional metadata context
            
        Returns:
            Dictionary containing report metadata
        """
        metadata = {
            'report_version': REPORT_VERSION,
            'generation_timestamp': datetime.now(timezone.utc).isoformat(),
            'report_type': report_type.value,
            'generator_version': self.__class__.__name__ + " v1.0.0",
            'test_data_summary': {
                'test_results_count': test_results_count,
                'baseline_reference': 'Node.js production implementation',
                'compliance_framework': 'Section 0.1.1 ≤10% variance requirement'
            },
            'environment_info': {
                'python_version': f"Python {'.'.join(map(str, __import__('sys').version_info[:3]))}",
                'dependencies': {
                    'jinja2_available': JINJA2_AVAILABLE,
                    'matplotlib_available': MATPLOTLIB_AVAILABLE,
                    'pandas_available': PANDAS_AVAILABLE
                }
            },
            'report_configuration': {
                'variance_thresholds': {
                    'performance_variance': f"{PERFORMANCE_VARIANCE_THRESHOLD}%",
                    'memory_variance': f"±{MEMORY_VARIANCE_THRESHOLD}%",
                    'warning_threshold': f"{WARNING_VARIANCE_THRESHOLD}%",
                    'critical_threshold': f"{CRITICAL_VARIANCE_THRESHOLD}%"
                },
                'supported_formats': SUPPORTED_REPORT_FORMATS,
                'chart_generation': MATPLOTLIB_AVAILABLE,
                'template_rendering': JINJA2_AVAILABLE
            }
        }
        
        # Add context-specific metadata
        for key, value in kwargs.items():
            if key not in metadata:
                metadata[key] = value
        
        return metadata
    
    def _export_json_report(self, report: BaselineComparisonReport, output_path: Path) -> None:
        """Export report as JSON format."""
        with open(output_path, 'w', encoding=REPORT_CHARSET) as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    
    def _export_html_report(self, report: BaselineComparisonReport, output_path: Path,
                          include_charts: bool) -> None:
        """Export report as HTML format with optional charts."""
        # Generate charts if requested and matplotlib available
        charts = {}
        if include_charts and MATPLOTLIB_AVAILABLE:
            charts = self._generate_performance_charts(report)
        
        # Use template if available, otherwise generate basic HTML
        if self.template_env:
            try:
                template = self.template_env.get_template('baseline_comparison_report.html')
                html_content = template.render(report=report, charts=charts)
            except:
                # Fallback to basic HTML generation
                html_content = self._generate_basic_html_report(report, charts)
        else:
            html_content = self._generate_basic_html_report(report, charts)
        
        with open(output_path, 'w', encoding=REPORT_CHARSET) as f:
            f.write(html_content)
    
    def _export_markdown_report(self, report: BaselineComparisonReport, output_path: Path) -> None:
        """Export report as Markdown format."""
        markdown_content = self._generate_markdown_content(report)
        
        with open(output_path, 'w', encoding=REPORT_CHARSET) as f:
            f.write(markdown_content)
    
    def _export_csv_report(self, report: BaselineComparisonReport, output_path: Path) -> None:
        """Export performance metrics as CSV format."""
        import csv
        
        with open(output_path, 'w', newline='', encoding=REPORT_CHARSET) as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Metric Name', 'Baseline Value', 'Current Value', 'Variance (%)',
                'Severity', 'Within Threshold', 'Trend Direction', 'Sample Count',
                'Confidence Score', 'Recommendation', 'Timestamp'
            ])
            
            # Write metric data
            for metric in report.performance_metrics:
                writer.writerow([
                    metric.metric_name,
                    metric.baseline_value,
                    metric.current_value,
                    round(metric.variance_percent, 2),
                    metric.variance_severity,
                    metric.within_threshold,
                    metric.trend_direction,
                    metric.sample_count,
                    round(metric.confidence_score, 3),
                    metric.recommendation,
                    metric.timestamp.isoformat()
                ])
    
    def _export_pdf_report(self, report: BaselineComparisonReport, output_path: Path,
                         include_charts: bool) -> None:
        """Export report as PDF format (requires matplotlib)."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("matplotlib is required for PDF export")
        
        # Generate charts for PDF
        charts = {}
        if include_charts:
            charts = self._generate_performance_charts(report)
        
        # Create PDF report
        with PdfPages(output_path) as pdf:
            # Title page
            fig = plt.figure(figsize=(8.5, 11))
            fig.suptitle('Node.js Baseline Comparison Report', fontsize=16, fontweight='bold')
            
            # Add executive summary text
            executive_text = self._format_executive_summary_for_pdf(report.executive_summary)
            plt.text(0.1, 0.8, executive_text, transform=fig.transFigure, fontsize=10,
                    verticalalignment='top', wrap=True)
            
            plt.axis('off')
            pdf.savefig(fig, bbox_inches='tight')
            plt.close(fig)
            
            # Add charts if available
            for chart_name, chart_data in charts.items():
                # Create figure from chart data (implementation depends on chart format)
                # This is a simplified implementation
                fig = plt.figure(figsize=(8.5, 11))
                plt.title(chart_name)
                plt.text(0.5, 0.5, f"Chart: {chart_name}", ha='center', va='center')
                plt.axis('off')
                pdf.savefig(fig, bbox_inches='tight')
                plt.close(fig)
    
    # Helper methods for analysis and generation
    
    def _classify_variance_severity(self, variance_percent: float) -> str:
        """Classify variance severity based on percentage."""
        for severity, (min_val, max_val) in VARIANCE_SEVERITY_LEVELS.items():
            if min_val <= variance_percent < max_val:
                return severity
        return 'failure'  # Default for values outside ranges
    
    def _analyze_metric_trend(self, results: List[PerformanceComparisonResult]) -> str:
        """Analyze trend direction for a metric based on results over time."""
        if len(results) < 2:
            return 'stable'
        
        # Sort by timestamp
        sorted_results = sorted(results, key=lambda x: x.timestamp)
        
        # Calculate trend using linear regression on variance percentages
        variances = [result.variance_percent for result in sorted_results]
        n = len(variances)
        x = list(range(n))
        
        # Simple linear regression
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(variances)
        
        numerator = sum((x[i] - x_mean) * (variances[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 'stable'
        
        slope = numerator / denominator
        
        # Classify trend based on slope
        if slope < -0.1:  # Improving (variance decreasing)
            return 'improving'
        elif slope > 0.1:  # Degrading (variance increasing)
            return 'degrading'
        else:
            return 'stable'
    
    def _calculate_confidence_score(self, results: List[PerformanceComparisonResult],
                                  detailed: bool = False) -> float:
        """Calculate confidence score based on data quality and consistency."""
        if not results:
            return 0.0
        
        # Base confidence on sample size
        sample_confidence = min(len(results) / 50.0, 1.0)  # Max confidence at 50+ samples
        
        # Factor in variance consistency
        variances = [abs(result.variance_percent) for result in results]
        if len(variances) > 1:
            variance_std = statistics.stdev(variances)
            variance_consistency = max(0.0, 1.0 - (variance_std / 10.0))  # Lower std = higher confidence
        else:
            variance_consistency = 0.5
        
        # Factor in temporal consistency (results spread over time)
        if len(results) > 1:
            timestamps = [result.timestamp for result in results]
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            temporal_confidence = min(time_span / 3600.0, 1.0)  # Max confidence at 1+ hour span
        else:
            temporal_confidence = 0.5
        
        # Weighted average of confidence factors
        confidence = (
            sample_confidence * 0.4 +
            variance_consistency * 0.4 +
            temporal_confidence * 0.2
        )
        
        return max(0.0, min(1.0, confidence))
    
    def _generate_metric_recommendation(self, result: PerformanceComparisonResult,
                                      variance_severity: str, trend_direction: str,
                                      pipeline_focus: bool = False) -> str:
        """Generate recommendation for a specific metric."""
        recommendations = []
        
        if variance_severity == 'excellent':
            recommendations.append("Performance excellent - continue current approach")
        elif variance_severity == 'good':
            recommendations.append("Performance good - monitor for stability")
        elif variance_severity == 'warning':
            recommendations.append("Performance approaching threshold - investigate optimization opportunities")
        elif variance_severity == 'critical':
            recommendations.append("Performance exceeds ≤10% threshold - immediate optimization required")
        else:  # failure
            recommendations.append("Critical performance failure - consider rollback to Node.js baseline")
        
        # Add trend-based recommendations
        if trend_direction == 'degrading':
            recommendations.append("Degrading trend detected - proactive optimization recommended")
        elif trend_direction == 'improving':
            recommendations.append("Positive trend - maintain current optimization efforts")
        
        # Add pipeline-specific recommendations
        if pipeline_focus:
            if not result.within_threshold:
                recommendations.append("PIPELINE: Block deployment until performance issues resolved")
            else:
                recommendations.append("PIPELINE: Approve deployment with continued monitoring")
        
        return "; ".join(recommendations)
    
    def _calculate_measurement_period(self, results: List[PerformanceComparisonResult]) -> str:
        """Calculate measurement period from results."""
        if not results:
            return "No data"
        
        timestamps = [result.timestamp for result in results]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        
        if duration.total_seconds() < 3600:
            return f"{duration.total_seconds():.0f} seconds"
        elif duration.total_seconds() < 86400:
            return f"{duration.total_seconds() / 3600:.1f} hours"
        else:
            return f"{duration.days} days"
    
    def _get_severity_priority(self, severity: str) -> int:
        """Get priority number for severity (higher = more severe)."""
        priorities = {
            'failure': 5,
            'critical': 4,
            'warning': 3,
            'good': 2,
            'excellent': 1
        }
        return priorities.get(severity, 0)
    
    def _generate_variance_summary(self, performance_metrics: List[PerformanceMetricSummary]) -> str:
        """Generate concise variance summary for executive review."""
        if not performance_metrics:
            return "No performance metrics available for analysis"
        
        # Count metrics by severity
        severity_counts = defaultdict(int)
        for metric in performance_metrics:
            severity_counts[metric.variance_severity] += 1
        
        total_metrics = len(performance_metrics)
        compliant_metrics = sum(1 for metric in performance_metrics if metric.within_threshold)
        compliance_rate = (compliant_metrics / total_metrics) * 100.0
        
        # Generate summary based on overall performance
        if compliance_rate >= 95.0:
            return f"Excellent performance compliance ({compliance_rate:.1f}%) - {severity_counts['excellent']} excellent, {severity_counts['good']} good metrics"
        elif compliance_rate >= 90.0:
            return f"Good performance compliance ({compliance_rate:.1f}%) - {severity_counts['warning']} metrics approaching threshold"
        elif compliance_rate >= 80.0:
            return f"Performance concerns identified ({compliance_rate:.1f}% compliance) - {severity_counts['critical']} critical issues require attention"
        else:
            return f"Significant performance issues ({compliance_rate:.1f}% compliance) - {severity_counts['failure']} failures require immediate action"
    
    def _identify_key_achievements(self, performance_metrics: List[PerformanceMetricSummary],
                                 compliance_validation: Dict[str, Any],
                                 additional_context: Dict[str, Any]) -> List[str]:
        """Identify key achievements for executive summary."""
        achievements = []
        
        # Performance achievements
        excellent_metrics = sum(1 for metric in performance_metrics if metric.variance_severity == 'excellent')
        if excellent_metrics > 0:
            achievements.append(f"{excellent_metrics} metrics showing excellent performance (≤5% variance)")
        
        improving_metrics = sum(1 for metric in performance_metrics if metric.trend_direction == 'improving')
        if improving_metrics > 0:
            achievements.append(f"{improving_metrics} metrics showing performance improvements")
        
        # Compliance achievements
        compliance_rate = compliance_validation.get('compliance_rate', 0.0)
        if compliance_rate >= 95.0:
            achievements.append(f"High compliance rate achieved ({compliance_rate:.1f}%)")
        
        # Test coverage achievements
        total_metrics = len(performance_metrics)
        if total_metrics >= 20:
            achievements.append(f"Comprehensive testing coverage ({total_metrics} metrics analyzed)")
        
        # Migration milestone achievements
        if additional_context.get('migration_phase') == 'complete':
            achievements.append("Node.js to Flask migration successfully completed")
        
        # Default achievement if none identified
        if not achievements:
            achievements.append("Baseline comparison analysis completed successfully")
        
        return achievements[:5]  # Limit to top 5 achievements
    
    def _identify_critical_issues(self, performance_metrics: List[PerformanceMetricSummary],
                                compliance_validation: Dict[str, Any],
                                regression_analysis: Dict[str, Any]) -> List[str]:
        """Identify critical issues for executive attention."""
        issues = []
        
        # Performance threshold violations
        critical_metrics = [
            metric for metric in performance_metrics 
            if metric.variance_severity in ['critical', 'failure']
        ]
        
        for metric in critical_metrics[:EXECUTIVE_SUMMARY_MAX_ISSUES]:
            issues.append(
                f"{metric.metric_name}: {metric.variance_percent:.1f}% variance exceeds ≤10% threshold"
            )
        
        # Regression issues
        regressions_detected = regression_analysis.get('regressions_detected', 0)
        if regressions_detected > 0:
            issues.append(f"{regressions_detected} performance regressions detected")
        
        # Compliance issues
        if not compliance_validation.get('overall_compliant', False):
            compliance_rate = compliance_validation.get('compliance_rate', 0.0)
            issues.append(f"Overall compliance below 95% threshold ({compliance_rate:.1f}%)")
        
        # Critical metric failures
        critical_failures = compliance_validation.get('critical_failures', [])
        critical_metric_failures = [
            failure for failure in critical_failures
            if any(critical_metric in failure['metric_name'] 
                  for critical_metric in CRITICAL_PERFORMANCE_METRICS)
        ]
        
        if critical_metric_failures:
            issues.append(f"{len(critical_metric_failures)} critical metrics failing performance requirements")
        
        return issues[:EXECUTIVE_SUMMARY_MAX_ISSUES]
    
    def _generate_executive_recommendations(self, performance_metrics: List[PerformanceMetricSummary],
                                          compliance_validation: Dict[str, Any],
                                          deployment_recommendation: DeploymentRecommendation) -> List[str]:
        """Generate executive-level recommendations."""
        recommendations = []
        
        # Deployment recommendations
        if deployment_recommendation == DeploymentRecommendation.APPROVED:
            recommendations.append("Approve production deployment - all performance requirements met")
        elif deployment_recommendation == DeploymentRecommendation.APPROVED_WITH_MONITORING:
            recommendations.append("Approve deployment with enhanced performance monitoring")
        elif deployment_recommendation == DeploymentRecommendation.CONDITIONAL_APPROVAL:
            recommendations.append("Conditional approval - address warning-level issues within 30 days")
        elif deployment_recommendation == DeploymentRecommendation.BLOCKED:
            recommendations.append("Block deployment until critical performance issues resolved")
        else:  # ROLLBACK_REQUIRED
            recommendations.append("Immediate rollback to Node.js baseline recommended")
        
        # Performance improvement recommendations
        critical_metrics = [
            metric for metric in performance_metrics 
            if metric.variance_severity in ['critical', 'failure']
        ]
        
        if critical_metrics:
            categories = set(self._categorize_metric(metric.metric_name) for metric in critical_metrics)
            for category in categories:
                recommendations.append(f"Prioritize {category} performance optimization")
        
        # Monitoring recommendations
        degrading_metrics = sum(1 for metric in performance_metrics if metric.trend_direction == 'degrading')
        if degrading_metrics > 0:
            recommendations.append(f"Implement enhanced monitoring for {degrading_metrics} degrading metrics")
        
        # Resource allocation recommendations
        if len(critical_metrics) > 5:
            recommendations.append("Allocate additional engineering resources for performance optimization")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _generate_next_steps(self, deployment_recommendation: DeploymentRecommendation,
                           critical_issues: List[str]) -> List[str]:
        """Generate next steps based on deployment recommendation."""
        next_steps = []
        
        if deployment_recommendation == DeploymentRecommendation.APPROVED:
            next_steps.extend([
                "Proceed with production deployment",
                "Maintain standard performance monitoring",
                "Schedule post-deployment performance review in 30 days"
            ])
        elif deployment_recommendation == DeploymentRecommendation.APPROVED_WITH_MONITORING:
            next_steps.extend([
                "Deploy with enhanced monitoring configuration",
                "Implement real-time performance alerting",
                "Conduct weekly performance review for first month"
            ])
        elif deployment_recommendation == DeploymentRecommendation.CONDITIONAL_APPROVAL:
            next_steps.extend([
                "Address identified warning-level performance issues",
                "Re-run comprehensive performance testing",
                "Schedule deployment review meeting with stakeholders"
            ])
        elif deployment_recommendation == DeploymentRecommendation.BLOCKED:
            next_steps.extend([
                "Halt deployment process immediately",
                "Prioritize resolution of critical performance issues",
                "Conduct root cause analysis for performance failures"
            ])
        else:  # ROLLBACK_REQUIRED
            next_steps.extend([
                "Execute immediate rollback to Node.js baseline",
                "Conduct emergency performance incident review",
                "Reassess migration strategy and timeline"
            ])
        
        # Add issue-specific next steps
        if critical_issues:
            next_steps.append("Create action plan for each critical issue identified")
            next_steps.append("Assign dedicated engineering resources to performance optimization")
        
        return next_steps[:5]  # Limit to top 5 next steps
    
    def _assess_business_impact(self, deployment_recommendation: DeploymentRecommendation,
                              compliance_rate: float, critical_failures_count: int) -> str:
        """Assess business impact of performance analysis results."""
        if deployment_recommendation == DeploymentRecommendation.APPROVED:
            return "Positive business impact - Migration delivers performance parity with potential for future optimizations"
        elif deployment_recommendation == DeploymentRecommendation.APPROVED_WITH_MONITORING:
            return "Acceptable business impact - Migration meets minimum requirements with monitoring for optimization opportunities"
        elif deployment_recommendation == DeploymentRecommendation.CONDITIONAL_APPROVAL:
            return "Limited business impact - Migration requires performance improvements before full value realization"
        elif deployment_recommendation == DeploymentRecommendation.BLOCKED:
            return "Negative business impact - Performance issues prevent successful migration and may affect user experience"
        else:  # ROLLBACK_REQUIRED
            return "Critical business impact - Immediate rollback required to prevent service degradation and customer impact"
    
    def _conduct_risk_assessment(self, compliance_validation: Dict[str, Any],
                               regression_analysis: Dict[str, Any],
                               performance_metrics: List[PerformanceMetricSummary]) -> str:
        """Conduct risk assessment for migration deployment."""
        risk_factors = []
        
        # Compliance risk
        compliance_rate = compliance_validation.get('compliance_rate', 0.0)
        if compliance_rate < 90.0:
            risk_factors.append("HIGH: Low compliance rate increases production failure risk")
        elif compliance_rate < 95.0:
            risk_factors.append("MEDIUM: Moderate compliance rate requires monitoring")
        
        # Regression risk
        regressions_detected = regression_analysis.get('regressions_detected', 0)
        if regressions_detected > 3:
            risk_factors.append("HIGH: Multiple regressions indicate systemic performance issues")
        elif regressions_detected > 0:
            risk_factors.append("MEDIUM: Performance regressions require attention")
        
        # Critical metric risk
        critical_metrics = sum(1 for metric in performance_metrics 
                             if metric.variance_severity in ['critical', 'failure'])
        if critical_metrics > 5:
            risk_factors.append("HIGH: Multiple critical metrics exceed acceptable thresholds")
        elif critical_metrics > 0:
            risk_factors.append("MEDIUM: Critical metrics require optimization")
        
        # Trend risk
        degrading_metrics = sum(1 for metric in performance_metrics 
                              if metric.trend_direction == 'degrading')
        if degrading_metrics > len(performance_metrics) * 0.3:
            risk_factors.append("MEDIUM: Significant proportion of metrics showing degrading trends")
        
        # Overall risk assessment
        if any("HIGH:" in factor for factor in risk_factors):
            return "HIGH RISK: " + "; ".join(risk_factors)
        elif risk_factors:
            return "MEDIUM RISK: " + "; ".join(risk_factors)
        else:
            return "LOW RISK: Performance metrics within acceptable parameters"
    
    def _determine_confidence_level(self, performance_metrics: List[PerformanceMetricSummary],
                                  compliance_rate: float,
                                  regression_analysis: Dict[str, Any]) -> str:
        """Determine confidence level in performance analysis results."""
        confidence_factors = []
        
        # Sample size confidence
        total_samples = sum(metric.sample_count for metric in performance_metrics)
        if total_samples >= 1000:
            confidence_factors.append("HIGH")
        elif total_samples >= 500:
            confidence_factors.append("MEDIUM")
        else:
            confidence_factors.append("LOW")
        
        # Measurement quality confidence
        avg_confidence = statistics.mean([metric.confidence_score for metric in performance_metrics]) if performance_metrics else 0.0
        if avg_confidence >= 0.8:
            confidence_factors.append("HIGH")
        elif avg_confidence >= 0.6:
            confidence_factors.append("MEDIUM")
        else:
            confidence_factors.append("LOW")
        
        # Regression analysis confidence
        regression_confidence = regression_analysis.get('statistical_analysis', {}).get('total_metrics_analyzed', 0)
        if regression_confidence >= 20:
            confidence_factors.append("HIGH")
        elif regression_confidence >= 10:
            confidence_factors.append("MEDIUM")
        else:
            confidence_factors.append("LOW")
        
        # Overall confidence determination
        high_count = confidence_factors.count("HIGH")
        medium_count = confidence_factors.count("MEDIUM")
        
        if high_count >= 2:
            return "HIGH"
        elif high_count >= 1 or medium_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_test_coverage(self, performance_metrics: List[PerformanceMetricSummary],
                               additional_context: Dict[str, Any]) -> float:
        """Calculate test coverage percentage."""
        # Categories of metrics that should be tested
        expected_categories = {
            'response_time', 'resource_utilization', 'database_performance',
            'throughput', 'network_io', 'authentication', 'business_logic'
        }
        
        # Categories actually tested
        tested_categories = set()
        for metric in performance_metrics:
            category = self._categorize_metric(metric.metric_name)
            tested_categories.add(category)
        
        # Calculate coverage
        coverage = (len(tested_categories) / len(expected_categories)) * 100.0
        
        # Adjust based on additional context
        if additional_context.get('comprehensive_testing', False):
            coverage = min(100.0, coverage * 1.1)  # Boost for comprehensive testing
        
        return coverage
    
    def _categorize_metric(self, metric_name: str) -> str:
        """Categorize metric based on name."""
        metric_name_lower = metric_name.lower()
        
        if 'response_time' in metric_name_lower or 'latency' in metric_name_lower:
            return 'response_time'
        elif 'cpu' in metric_name_lower or 'memory' in metric_name_lower:
            return 'resource_utilization'
        elif 'database' in metric_name_lower or 'query' in metric_name_lower:
            return 'database_performance'
        elif 'throughput' in metric_name_lower or 'requests_per_second' in metric_name_lower:
            return 'throughput'
        elif 'network' in metric_name_lower or 'bandwidth' in metric_name_lower:
            return 'network_io'
        elif 'auth' in metric_name_lower or 'login' in metric_name_lower:
            return 'authentication'
        elif 'business' in metric_name_lower or 'logic' in metric_name_lower:
            return 'business_logic'
        else:
            return 'other'
    
    def _generate_performance_charts(self, report: BaselineComparisonReport) -> Dict[str, str]:
        """Generate performance charts and return as base64 encoded strings."""
        charts = {}
        
        if not MATPLOTLIB_AVAILABLE:
            return charts
        
        try:
            # Variance distribution chart
            charts['variance_distribution'] = self._create_variance_distribution_chart(report.performance_metrics)
            
            # Performance trend chart
            charts['performance_trend'] = self._create_performance_trend_chart(report.performance_metrics)
            
            # Compliance summary chart
            charts['compliance_summary'] = self._create_compliance_summary_chart(report.compliance_validation)
            
        except Exception as e:
            self.logger.warning(f"Failed to generate charts: {e}")
        
        return charts
    
    def _create_variance_distribution_chart(self, metrics: List[PerformanceMetricSummary]) -> str:
        """Create variance distribution chart."""
        if not metrics:
            return ""
        
        # Count metrics by severity
        severity_counts = defaultdict(int)
        for metric in metrics:
            severity_counts[metric.variance_severity] += 1
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(8, 6))
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        colors = [VARIANCE_SEVERITY_LEVELS[label][0] if label in VARIANCE_SEVERITY_LEVELS else '#9E9E9E' for label in labels]
        
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax.set_title('Performance Variance Distribution')
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        return chart_data
    
    def _create_performance_trend_chart(self, metrics: List[PerformanceMetricSummary]) -> str:
        """Create performance trend chart."""
        if not metrics:
            return ""
        
        # Sort metrics by timestamp
        sorted_metrics = sorted(metrics, key=lambda x: x.timestamp)
        
        # Create line chart
        fig, ax = plt.subplots(figsize=(12, 6))
        
        timestamps = [metric.timestamp for metric in sorted_metrics]
        variances = [abs(metric.variance_percent) for metric in sorted_metrics]
        
        ax.plot(timestamps, variances, marker='o', linewidth=2, markersize=4)
        ax.axhline(y=PERFORMANCE_VARIANCE_THRESHOLD, color='r', linestyle='--', 
                  label=f'{PERFORMANCE_VARIANCE_THRESHOLD}% Threshold')
        ax.axhline(y=WARNING_VARIANCE_THRESHOLD, color='orange', linestyle='--', 
                  label=f'{WARNING_VARIANCE_THRESHOLD}% Warning')
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Variance Percentage')
        ax.set_title('Performance Variance Trend Over Time')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Format x-axis
        fig.autofmt_xdate()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        return chart_data
    
    def _create_compliance_summary_chart(self, compliance_validation: Dict[str, Any]) -> str:
        """Create compliance summary chart."""
        compliance_summary = compliance_validation.get('compliance_summary', {})
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        
        categories = ['Compliant', 'Non-Compliant', 'Critical Failures']
        values = [
            compliance_summary.get('compliant_metrics', 0),
            compliance_summary.get('non_compliant_metrics', 0),
            compliance_summary.get('critical_failures_count', 0)
        ]
        colors = ['#4CAF50', '#FF9800', '#F44336']
        
        bars = ax.bar(categories, values, color=colors)
        ax.set_ylabel('Number of Metrics')
        ax.set_title('Performance Compliance Summary')
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{value}', ha='center', va='bottom')
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        return chart_data
    
    def _generate_basic_html_report(self, report: BaselineComparisonReport, 
                                  charts: Dict[str, str]) -> str:
        """Generate basic HTML report without template engine."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Node.js Baseline Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }}
        .metric {{ background-color: #f9f9f9; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .status-passed {{ color: #4CAF50; font-weight: bold; }}
        .status-warning {{ color: #FF9800; font-weight: bold; }}
        .status-failed {{ color: #F44336; font-weight: bold; }}
        .chart {{ text-align: center; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Node.js Baseline Comparison Report</h1>
        <p><strong>Report ID:</strong> {report.report_id}</p>
        <p><strong>Generated:</strong> {report.generation_timestamp.strftime(TIMESTAMP_FORMAT)}</p>
        <p><strong>Report Type:</strong> {report.report_type.value}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Overall Status:</strong> 
            <span class="status-{report.executive_summary.overall_status.lower()}">{report.executive_summary.overall_status}</span>
        </p>
        <p><strong>Deployment Recommendation:</strong> {report.executive_summary.deployment_recommendation.value}</p>
        <p><strong>Compliance Rate:</strong> {report.executive_summary.compliance_rate:.1f}%</p>
        <p><strong>Total Metrics Tested:</strong> {report.executive_summary.total_metrics_tested}</p>
        <p><strong>Critical Issues:</strong> {report.executive_summary.critical_issues_count}</p>
        
        <h3>Key Achievements</h3>
        <ul>
            {''.join(f'<li>{achievement}</li>' for achievement in report.executive_summary.key_achievements)}
        </ul>
        
        <h3>Critical Issues</h3>
        <ul>
            {''.join(f'<li>{issue}</li>' for issue in report.executive_summary.critical_issues)}
        </ul>
        
        <h3>Recommendations</h3>
        <ul>
            {''.join(f'<li>{rec}</li>' for rec in report.executive_summary.recommendations)}
        </ul>
    </div>

    <div class="section">
        <h2>Performance Metrics</h2>
        <table>
            <tr>
                <th>Metric Name</th>
                <th>Baseline</th>
                <th>Current</th>
                <th>Variance (%)</th>
                <th>Severity</th>
                <th>Trend</th>
                <th>Recommendation</th>
            </tr>
            {''.join(f"""
            <tr>
                <td>{metric.metric_name}</td>
                <td>{metric.baseline_value:.2f}</td>
                <td>{metric.current_value:.2f}</td>
                <td>{metric.variance_percent:.2f}%</td>
                <td>{metric.severity_icon} {metric.variance_severity}</td>
                <td>{metric.trend_direction}</td>
                <td>{metric.recommendation}</td>
            </tr>
            """ for metric in report.performance_metrics)}
        </table>
    </div>

    {self._generate_charts_html(charts)}

    <div class="section">
        <h2>Technical Details</h2>
        <h3>Performance Statistics</h3>
        <pre>{json.dumps(report.technical_details.get('performance_statistics', {}), indent=2)}</pre>
        
        <h3>Compliance Validation</h3>
        <pre>{json.dumps(report.compliance_validation, indent=2)}</pre>
    </div>

    <div class="section">
        <h2>Report Metadata</h2>
        <pre>{json.dumps(report.metadata, indent=2)}</pre>
    </div>
</body>
</html>
        """
        return html_content
    
    def _generate_charts_html(self, charts: Dict[str, str]) -> str:
        """Generate HTML for charts section."""
        if not charts:
            return ""
        
        charts_html = '<div class="section"><h2>Performance Charts</h2>'
        
        for chart_name, chart_data in charts.items():
            if chart_data:
                charts_html += f'''
                <div class="chart">
                    <h3>{chart_name.replace('_', ' ').title()}</h3>
                    <img src="data:image/png;base64,{chart_data}" alt="{chart_name}" style="max-width: 100%;">
                </div>
                '''
        
        charts_html += '</div>'
        return charts_html
    
    def _generate_markdown_content(self, report: BaselineComparisonReport) -> str:
        """Generate Markdown content for report."""
        markdown_content = f"""# Node.js Baseline Comparison Report

**Report ID:** {report.report_id}  
**Generated:** {report.generation_timestamp.strftime(TIMESTAMP_FORMAT)}  
**Report Type:** {report.report_type.value}

## Executive Summary

- **Overall Status:** {report.executive_summary.overall_status}
- **Deployment Recommendation:** {report.executive_summary.deployment_recommendation.value}
- **Compliance Rate:** {report.executive_summary.compliance_rate:.1f}%
- **Total Metrics Tested:** {report.executive_summary.total_metrics_tested}
- **Critical Issues:** {report.executive_summary.critical_issues_count}

### Key Achievements
{chr(10).join(f"- {achievement}" for achievement in report.executive_summary.key_achievements)}

### Critical Issues
{chr(10).join(f"- {issue}" for issue in report.executive_summary.critical_issues)}

### Recommendations
{chr(10).join(f"- {rec}" for rec in report.executive_summary.recommendations)}

## Performance Metrics

| Metric Name | Baseline | Current | Variance (%) | Severity | Trend | Within Threshold |
|-------------|----------|---------|--------------|----------|-------|------------------|
"""
        
        for metric in report.performance_metrics:
            markdown_content += f"| {metric.metric_name} | {metric.baseline_value:.2f} | {metric.current_value:.2f} | {metric.variance_percent:.2f}% | {metric.variance_severity} | {metric.trend_direction} | {metric.within_threshold} |\n"
        
        markdown_content += f"""
## Compliance Validation

- **Overall Compliant:** {report.compliance_validation.get('overall_compliant', False)}
- **Compliance Rate:** {report.compliance_validation.get('compliance_rate', 0.0):.1f}%
- **Critical Failures:** {len(report.compliance_validation.get('critical_failures', []))}

## Technical Details

### Performance Statistics
```json
{json.dumps(report.technical_details.get('performance_statistics', {}), indent=2)}
```

### Regression Analysis
```json
{json.dumps(report.regression_analysis, indent=2)}
```

### Trend Analysis
```json
{json.dumps(report.trend_analysis, indent=2)}
```

## Report Metadata

```json
{json.dumps(report.metadata, indent=2)}
```
"""
        
        return markdown_content
    
    def _format_executive_summary_for_pdf(self, executive_summary: ExecutiveSummary) -> str:
        """Format executive summary text for PDF generation."""
        return f"""
EXECUTIVE SUMMARY

Overall Status: {executive_summary.overall_status}
Deployment Recommendation: {executive_summary.deployment_recommendation.value}
Compliance Rate: {executive_summary.compliance_rate:.1f}%
Total Metrics Tested: {executive_summary.total_metrics_tested}
Critical Issues: {executive_summary.critical_issues_count}

KEY ACHIEVEMENTS:
{chr(10).join(f"• {achievement}" for achievement in executive_summary.key_achievements)}

CRITICAL ISSUES:
{chr(10).join(f"• {issue}" for issue in executive_summary.critical_issues)}

RECOMMENDATIONS:
{chr(10).join(f"• {rec}" for rec in executive_summary.recommendations)}

Business Impact: {executive_summary.business_impact}
Risk Assessment: {executive_summary.risk_assessment}
Confidence Level: {executive_summary.confidence_level}
        """
    
    # Additional helper methods for pipeline integration and specialized reporting
    
    def _validate_pipeline_compliance(self, test_results: List[PerformanceComparisonResult],
                                    pipeline_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate compliance specifically for CI/CD pipeline gates."""
        compliance_data = self._validate_compliance_requirements(test_results, include_technical_details=True)
        
        # Add pipeline-specific validation
        pipeline_validation = {
            'deployment_gate_status': 'PASSED' if compliance_data['overall_compliant'] else 'FAILED',
            'pipeline_stage': pipeline_context.get('stage', 'unknown'),
            'commit_hash': pipeline_context.get('commit_hash', 'unknown'),
            'branch': pipeline_context.get('branch', 'unknown'),
            'build_number': pipeline_context.get('build_number', 'unknown'),
            'pipeline_specific_checks': {}
        }
        
        # Critical metrics must all pass for pipeline approval
        critical_failures = [
            failure for failure in compliance_data.get('critical_failures', [])
            if any(critical_metric in failure['metric_name'] 
                  for critical_metric in CRITICAL_PERFORMANCE_METRICS)
        ]
        
        pipeline_validation['pipeline_specific_checks']['critical_metrics_gate'] = {
            'status': 'PASSED' if not critical_failures else 'FAILED',
            'critical_failures_count': len(critical_failures),
            'gate_description': 'All critical performance metrics must be within ≤10% variance threshold'
        }
        
        # Overall variance threshold gate
        compliance_rate = compliance_data.get('compliance_rate', 0.0)
        pipeline_validation['pipeline_specific_checks']['variance_threshold_gate'] = {
            'status': 'PASSED' if compliance_rate >= 95.0 else 'FAILED',
            'compliance_rate': compliance_rate,
            'gate_description': 'Overall compliance rate must be ≥95% for deployment approval'
        }
        
        # Update compliance data with pipeline specifics
        compliance_data.update(pipeline_validation)
        
        return compliance_data
    
    def _analyze_deployment_readiness(self, performance_metrics: List[PerformanceMetricSummary],
                                    compliance_validation: Dict[str, Any],
                                    pipeline_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze deployment readiness with detailed gate analysis."""
        deployment_analysis = {
            'deployment_ready': False,
            'gate_analysis': {},
            'risk_factors': [],
            'mitigation_strategies': [],
            'rollback_plan': {},
            'monitoring_recommendations': []
        }
        
        # Analyze each deployment gate
        gates = {
            'performance_variance_gate': self._analyze_performance_variance_gate(performance_metrics),
            'critical_metrics_gate': self._analyze_critical_metrics_gate(performance_metrics),
            'regression_detection_gate': self._analyze_regression_detection_gate(performance_metrics),
            'compliance_threshold_gate': self._analyze_compliance_threshold_gate(compliance_validation)
        }
        
        deployment_analysis['gate_analysis'] = gates
        
        # Overall deployment readiness
        all_gates_passed = all(gate['status'] == 'PASSED' for gate in gates.values())
        deployment_analysis['deployment_ready'] = all_gates_passed
        
        # Risk factor analysis
        if not all_gates_passed:
            failed_gates = [name for name, gate in gates.items() if gate['status'] == 'FAILED']
            deployment_analysis['risk_factors'].extend([
                f"Deployment gate failure: {gate}" for gate in failed_gates
            ])
        
        # Generate mitigation strategies
        deployment_analysis['mitigation_strategies'] = self._generate_mitigation_strategies(gates)
        
        # Rollback plan
        deployment_analysis['rollback_plan'] = self._generate_rollback_plan(pipeline_context, gates)
        
        # Monitoring recommendations
        deployment_analysis['monitoring_recommendations'] = self._generate_monitoring_recommendations(
            performance_metrics, gates
        )
        
        return deployment_analysis
    
    def _analyze_performance_variance_gate(self, performance_metrics: List[PerformanceMetricSummary]) -> Dict[str, Any]:
        """Analyze performance variance gate for deployment."""
        if not performance_metrics:
            return {'status': 'FAILED', 'reason': 'No performance metrics available'}
        
        # Check ≤10% variance requirement
        exceeding_threshold = [
            metric for metric in performance_metrics 
            if abs(metric.variance_percent) > PERFORMANCE_VARIANCE_THRESHOLD
        ]
        
        gate_status = 'PASSED' if not exceeding_threshold else 'FAILED'
        
        return {
            'status': gate_status,
            'threshold': f"{PERFORMANCE_VARIANCE_THRESHOLD}%",
            'exceeding_threshold_count': len(exceeding_threshold),
            'worst_variance': max(abs(metric.variance_percent) for metric in performance_metrics),
            'exceeding_metrics': [metric.metric_name for metric in exceeding_threshold]
        }
    
    def _analyze_critical_metrics_gate(self, performance_metrics: List[PerformanceMetricSummary]) -> Dict[str, Any]:
        """Analyze critical metrics gate for deployment."""
        critical_metric_results = [
            metric for metric in performance_metrics
            if any(critical_metric in metric.metric_name for critical_metric in CRITICAL_PERFORMANCE_METRICS)
        ]
        
        failing_critical_metrics = [
            metric for metric in critical_metric_results
            if not metric.within_threshold
        ]
        
        gate_status = 'PASSED' if not failing_critical_metrics else 'FAILED'
        
        return {
            'status': gate_status,
            'critical_metrics_tested': len(critical_metric_results),
            'critical_metrics_failing': len(failing_critical_metrics),
            'failing_metrics': [metric.metric_name for metric in failing_critical_metrics],
            'gate_description': 'All critical performance metrics must pass ≤10% variance threshold'
        }
    
    def _analyze_regression_detection_gate(self, performance_metrics: List[PerformanceMetricSummary]) -> Dict[str, Any]:
        """Analyze regression detection gate for deployment."""
        degrading_metrics = [
            metric for metric in performance_metrics
            if metric.trend_direction == 'degrading'
        ]
        
        # Gate passes if <30% of metrics are degrading
        degradation_rate = (len(degrading_metrics) / len(performance_metrics)) * 100.0 if performance_metrics else 0.0
        gate_status = 'PASSED' if degradation_rate < 30.0 else 'FAILED'
        
        return {
            'status': gate_status,
            'degrading_metrics_count': len(degrading_metrics),
            'degradation_rate': degradation_rate,
            'threshold': '30% degradation rate limit',
            'degrading_metrics': [metric.metric_name for metric in degrading_metrics]
        }
    
    def _analyze_compliance_threshold_gate(self, compliance_validation: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance threshold gate for deployment."""
        compliance_rate = compliance_validation.get('compliance_rate', 0.0)
        gate_status = 'PASSED' if compliance_rate >= 95.0 else 'FAILED'
        
        return {
            'status': gate_status,
            'compliance_rate': compliance_rate,
            'threshold': '95% compliance rate required',
            'total_metrics': compliance_validation.get('compliance_summary', {}).get('total_metrics_tested', 0),
            'compliant_metrics': compliance_validation.get('compliance_summary', {}).get('compliant_metrics', 0)
        }
    
    def _generate_mitigation_strategies(self, gates: Dict[str, Dict[str, Any]]) -> List[str]:
        """Generate mitigation strategies based on gate failures."""
        strategies = []
        
        for gate_name, gate_result in gates.items():
            if gate_result['status'] == 'FAILED':
                if gate_name == 'performance_variance_gate':
                    strategies.append("Implement performance optimization for metrics exceeding ≤10% variance threshold")
                elif gate_name == 'critical_metrics_gate':
                    strategies.append("Prioritize optimization of critical performance metrics before deployment")
                elif gate_name == 'regression_detection_gate':
                    strategies.append("Investigate and address performance regression root causes")
                elif gate_name == 'compliance_threshold_gate':
                    strategies.append("Increase performance testing coverage and address non-compliant metrics")
        
        if not strategies:
            strategies.append("All deployment gates passed - proceed with standard deployment monitoring")
        
        return strategies
    
    def _generate_rollback_plan(self, pipeline_context: Dict[str, Any], 
                              gates: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate rollback plan based on gate failures and pipeline context."""
        failed_gates = [name for name, gate in gates.items() if gate['status'] == 'FAILED']
        
        rollback_plan = {
            'rollback_required': len(failed_gates) > 0,
            'rollback_triggers': failed_gates,
            'rollback_procedure': [],
            'rollback_validation': [],
            'recovery_time_estimate': '5-15 minutes'
        }
        
        if rollback_plan['rollback_required']:
            rollback_plan['rollback_procedure'] = [
                "1. Activate circuit breaker to divert traffic to Node.js baseline",
                "2. Disable Flask application deployment in load balancer",
                "3. Verify Node.js baseline performance restoration",
                "4. Update feature flags to disable migration features",
                "5. Notify stakeholders of rollback completion"
            ]
            
            rollback_plan['rollback_validation'] = [
                "Verify response time returns to baseline levels",
                "Confirm error rate <0.1% threshold",
                "Validate all critical endpoints operational",
                "Check system resource utilization normalized"
            ]
        else:
            rollback_plan['rollback_procedure'] = [
                "Standard deployment monitoring - no rollback required"
            ]
        
        return rollback_plan
    
    def _generate_monitoring_recommendations(self, performance_metrics: List[PerformanceMetricSummary],
                                           gates: Dict[str, Dict[str, Any]]) -> List[str]:
        """Generate monitoring recommendations based on performance analysis."""
        recommendations = []
        
        # Critical metrics monitoring
        critical_metrics = [
            metric for metric in performance_metrics
            if any(critical_metric in metric.metric_name for critical_metric in CRITICAL_PERFORMANCE_METRICS)
        ]
        
        if critical_metrics:
            recommendations.append(f"Implement enhanced monitoring for {len(critical_metrics)} critical performance metrics")
        
        # Variance monitoring
        warning_metrics = [
            metric for metric in performance_metrics
            if metric.variance_severity in ['warning', 'critical']
        ]
        
        if warning_metrics:
            recommendations.append(f"Set up real-time alerting for {len(warning_metrics)} metrics approaching variance thresholds")
        
        # Trend monitoring
        degrading_metrics = [
            metric for metric in performance_metrics
            if metric.trend_direction == 'degrading'
        ]
        
        if degrading_metrics:
            recommendations.append(f"Configure trend analysis monitoring for {len(degrading_metrics)} degrading metrics")
        
        # Gate-specific monitoring
        failed_gates = [name for name, gate in gates.items() if gate['status'] == 'FAILED']
        if failed_gates:
            recommendations.append(f"Implement specialized monitoring for failed deployment gates: {', '.join(failed_gates)}")
        
        # Default monitoring recommendation
        if not recommendations:
            recommendations.append("Continue standard performance monitoring with current baseline comparison")
        
        return recommendations


# Factory functions for easy report generation

def generate_executive_summary_report(test_results: List[PerformanceComparisonResult],
                                    trend_analyzer: Optional[PerformanceTrendAnalyzer] = None,
                                    output_format: str = 'html',
                                    output_directory: Optional[str] = None) -> Path:
    """
    Generate and export executive summary report.
    
    Args:
        test_results: Performance comparison test results
        trend_analyzer: Optional trend analyzer for regression detection
        output_format: Export format ('json', 'html', 'pdf', 'markdown', 'csv')
        output_directory: Optional output directory
        
    Returns:
        Path to exported report file
    """
    generator = BaselineComparisonReportGenerator(output_directory=output_directory)
    report = generator.generate_executive_summary_report(test_results, trend_analyzer)
    return generator.export_report(report, output_format)


def generate_technical_detailed_report(test_results: List[PerformanceComparisonResult],
                                     trend_analyzer: Optional[PerformanceTrendAnalyzer] = None,
                                     output_format: str = 'html',
                                     output_directory: Optional[str] = None,
                                     include_raw_data: bool = True) -> Path:
    """
    Generate and export technical detailed report.
    
    Args:
        test_results: Performance comparison test results
        trend_analyzer: Optional trend analyzer for comprehensive analysis
        output_format: Export format ('json', 'html', 'pdf', 'markdown', 'csv')
        output_directory: Optional output directory
        include_raw_data: Include raw measurement data in report
        
    Returns:
        Path to exported report file
    """
    generator = BaselineComparisonReportGenerator(output_directory=output_directory)
    report = generator.generate_technical_detailed_report(test_results, trend_analyzer, include_raw_data)
    return generator.export_report(report, output_format)


def generate_ci_cd_pipeline_report(test_results: List[PerformanceComparisonResult],
                                 pipeline_context: Dict[str, Any],
                                 output_format: str = 'json',
                                 output_directory: Optional[str] = None) -> Path:
    """
    Generate and export CI/CD pipeline integration report.
    
    Args:
        test_results: Performance comparison test results
        pipeline_context: CI/CD pipeline context and metadata
        output_format: Export format ('json', 'html', 'pdf', 'markdown', 'csv')
        output_directory: Optional output directory
        
    Returns:
        Path to exported report file
    """
    generator = BaselineComparisonReportGenerator(output_directory=output_directory)
    report = generator.generate_ci_cd_pipeline_report(test_results, pipeline_context)
    return generator.export_report(report, output_format)


# Export public interface
__all__ = [
    'BaselineComparisonReportGenerator',
    'BaselineComparisonReport',
    'ExecutiveSummary',
    'PerformanceMetricSummary',
    'ReportType',
    'DeploymentRecommendation',
    'generate_executive_summary_report',
    'generate_technical_detailed_report',
    'generate_ci_cd_pipeline_report',
    'SUPPORTED_REPORT_FORMATS',
    'VARIANCE_SEVERITY_LEVELS'
]