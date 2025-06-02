"""
Automated Performance Report Generation Engine

This module provides comprehensive performance report generation with trend analysis for the
Flask migration project, creating detailed reports from test results, baseline comparisons,
and variance analysis. Generates HTML, PDF, and JSON reports for different stakeholder
audiences with automated recommendations and enterprise monitoring integration.

Key Features:
- Comprehensive performance report generation with trend analysis per Section 0.3.4
- ≤10% variance validation and reporting per Section 0.1.1 primary objective
- Multi-format output for different stakeholder needs per Section 0.3.4
- Enterprise monitoring integration for data sourcing per Section 6.5.1
- Automated recommendation engine for performance optimization per Section 6.6.1

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 6.5.1: Metrics collection and enterprise APM integration for report data sourcing
- Section 6.6.1: Performance testing tools integration with Locust and Apache Bench
- Section 0.3.4: Documentation requirements with comprehensive reporting

Author: Flask Migration Team
Version: 1.0.0
Dependencies: baseline_data.py, performance_config.py, test_baseline_comparison.py
"""

import asyncio
import csv
import json
import logging
import math
import os
import statistics
import time
import warnings
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, NamedTuple, TextIO
from dataclasses import dataclass, field, asdict
from enum import Enum
from uuid import uuid4

# Performance testing framework integration
from tests.performance.baseline_data import (
    NodeJSPerformanceBaseline,
    BaselineDataManager,
    BaselineValidationStatus,
    compare_with_baseline,
    get_nodejs_baseline,
    get_baseline_manager
)

from tests.performance.performance_config import (
    PerformanceTestConfig,
    LoadTestScenario,
    LoadTestConfiguration,
    PerformanceMetricType,
    create_performance_config,
    get_baseline_metrics,
    validate_performance_results
)

from tests.performance.test_baseline_comparison import (
    BaselineComparisonResult,
    BaselineComparisonTestSuite,
    CRITICAL_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    RESPONSE_TIME_THRESHOLD_MS,
    THROUGHPUT_THRESHOLD_RPS
)

# Structured logging for comprehensive report generation
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    STRUCTLOG_AVAILABLE = False
    logger = logging.getLogger(__name__)
    warnings.warn("structlog not available - falling back to standard logging")

# HTML templating for report generation
try:
    from jinja2 import Environment, DictLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    warnings.warn("Jinja2 not available - HTML reporting disabled")

# PDF generation for stakeholder reports
try:
    import weasyprint
    PDF_GENERATION_AVAILABLE = True
except ImportError:
    PDF_GENERATION_AVAILABLE = False
    warnings.warn("WeasyPrint not available - PDF generation disabled")

# Charts and visualization for performance reports
try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import seaborn as sns
    VISUALIZATION_AVAILABLE = True
    
    # Configure matplotlib for server environments
    plt.switch_backend('Agg')
    sns.set_style("whitegrid")
    plt.style.use('seaborn-v0_8')
except ImportError:
    VISUALIZATION_AVAILABLE = False
    warnings.warn("matplotlib/seaborn not available - chart generation disabled")

# Prometheus metrics integration for enterprise monitoring
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("prometheus_client not available - metrics integration disabled")


class ReportFormat(Enum):
    """Report output format enumeration for multi-format support."""
    
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class StakeholderType(Enum):
    """Stakeholder type enumeration for audience-specific reporting."""
    
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    OPERATIONS = "operations"
    PERFORMANCE_ENGINEERING = "performance_engineering"
    QA_TESTING = "qa_testing"
    DEVELOPMENT = "development"


class ReportSeverity(Enum):
    """Report severity levels for performance issue classification."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PerformanceIssueType(Enum):
    """Performance issue type enumeration for categorization."""
    
    RESPONSE_TIME_DEGRADATION = "response_time_degradation"
    THROUGHPUT_REDUCTION = "throughput_reduction"
    MEMORY_USAGE_INCREASE = "memory_usage_increase"
    CPU_UTILIZATION_HIGH = "cpu_utilization_high"
    DATABASE_PERFORMANCE = "database_performance"
    EXTERNAL_SERVICE_LATENCY = "external_service_latency"
    ERROR_RATE_INCREASE = "error_rate_increase"
    REGRESSION_DETECTION = "regression_detection"


@dataclass
class PerformanceIssue:
    """
    Performance issue data structure for automated issue detection and reporting.
    """
    
    issue_id: str = field(default_factory=lambda: str(uuid4()))
    issue_type: PerformanceIssueType = PerformanceIssueType.RESPONSE_TIME_DEGRADATION
    severity: ReportSeverity = ReportSeverity.MEDIUM
    title: str = ""
    description: str = ""
    affected_endpoints: List[str] = field(default_factory=list)
    current_value: float = 0.0
    baseline_value: float = 0.0
    variance_percent: float = 0.0
    impact_assessment: str = ""
    recommendation: str = ""
    detected_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert performance issue to dictionary format."""
        return {
            "issue_id": self.issue_id,
            "issue_type": self.issue_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_endpoints": self.affected_endpoints,
            "current_value": self.current_value,
            "baseline_value": self.baseline_value,
            "variance_percent": self.variance_percent,
            "impact_assessment": self.impact_assessment,
            "recommendation": self.recommendation,
            "detected_timestamp": self.detected_timestamp.isoformat()
        }


@dataclass
class TestResultSummary:
    """
    Comprehensive test result summary for report generation.
    """
    
    # Test execution metadata
    test_id: str = field(default_factory=lambda: str(uuid4()))
    test_name: str = ""
    test_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_duration_seconds: float = 0.0
    test_environment: str = "unknown"
    
    # Performance metrics
    response_time_metrics: Dict[str, Dict[str, float]] = field(default_factory=dict)
    throughput_metrics: Dict[str, float] = field(default_factory=dict)
    resource_utilization: Dict[str, float] = field(default_factory=dict)
    error_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Baseline comparison results
    baseline_comparison: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    variance_analysis: Dict[str, float] = field(default_factory=dict)
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    
    # Quality assessment
    overall_compliance: bool = False
    performance_grade: str = "F"
    issues_detected: List[PerformanceIssue] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Statistical analysis
    sample_size: int = 0
    statistical_confidence: float = 0.0
    test_reliability_score: float = 0.0


@dataclass
class ReportConfiguration:
    """
    Report configuration parameters for customizable report generation.
    """
    
    # Report metadata
    report_title: str = "Performance Analysis Report"
    report_description: str = "Comprehensive performance analysis and baseline comparison"
    generated_by: str = "Flask Migration Performance System"
    
    # Stakeholder configuration
    target_audience: StakeholderType = StakeholderType.TECHNICAL
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_recommendations: bool = True
    
    # Content configuration
    include_charts: bool = True
    include_trend_analysis: bool = True
    include_baseline_comparison: bool = True
    include_issue_analysis: bool = True
    
    # Formatting configuration
    chart_style: str = "professional"
    color_scheme: str = "blue"
    logo_path: Optional[str] = None
    custom_css: Optional[str] = None
    
    # Threshold configuration
    variance_threshold: float = CRITICAL_VARIANCE_THRESHOLD
    warning_threshold: float = WARNING_VARIANCE_THRESHOLD
    memory_threshold: float = MEMORY_VARIANCE_THRESHOLD


class PerformanceReportGenerator:
    """
    Comprehensive performance report generation engine creating detailed reports from
    test results, baseline comparisons, and trend analysis with multi-format output
    and stakeholder-specific templates.
    
    Implements automated report generation per Section 6.6.1 and Section 0.3.4
    documentation requirements with enterprise monitoring integration.
    """
    
    def __init__(
        self,
        baseline_manager: Optional[BaselineDataManager] = None,
        performance_config: Optional[PerformanceTestConfig] = None,
        output_directory: Optional[Path] = None
    ):
        """
        Initialize performance report generator with configuration and dependencies.
        
        Args:
            baseline_manager: Baseline data manager for Node.js comparisons
            performance_config: Performance configuration and thresholds
            output_directory: Directory for report output files
        """
        self.baseline_manager = baseline_manager or get_baseline_manager()
        self.performance_config = performance_config or create_performance_config()
        self.output_directory = output_directory or Path(__file__).parent / "output"
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize report generation state
        self.report_cache: Dict[str, Any] = {}
        self.chart_cache: Dict[str, str] = {}
        self.template_cache: Dict[str, str] = {}
        
        # Performance metrics tracking
        if PROMETHEUS_AVAILABLE:
            self.metrics_registry = CollectorRegistry()
            self._init_prometheus_metrics()
        
        # Initialize template engine
        if JINJA2_AVAILABLE:
            self._init_template_engine()
        
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for report generation tracking."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # Report generation metrics
        self.report_generation_counter = Counter(
            'performance_reports_generated_total',
            'Total number of performance reports generated',
            ['format', 'stakeholder_type'],
            registry=self.metrics_registry
        )
        
        # Report generation duration
        self.report_generation_histogram = Histogram(
            'performance_report_generation_duration_seconds',
            'Time spent generating performance reports',
            ['format'],
            registry=self.metrics_registry
        )
        
        # Performance issues detected
        self.issues_detected_gauge = Gauge(
            'performance_issues_detected',
            'Number of performance issues detected in reports',
            ['severity', 'issue_type'],
            registry=self.metrics_registry
        )
        
        # Variance tracking
        self.variance_distribution_histogram = Histogram(
            'performance_variance_distribution',
            'Distribution of performance variance percentages',
            buckets=[1.0, 2.5, 5.0, 7.5, 10.0, 15.0, 20.0, 30.0],
            registry=self.metrics_registry
        )
    
    def _init_template_engine(self) -> None:
        """Initialize Jinja2 template engine with report templates."""
        if not JINJA2_AVAILABLE:
            return
        
        # Define HTML report templates
        html_templates = {
            'base_report.html': self._get_base_html_template(),
            'executive_summary.html': self._get_executive_summary_template(),
            'technical_details.html': self._get_technical_details_template(),
            'performance_charts.html': self._get_performance_charts_template(),
            'issue_analysis.html': self._get_issue_analysis_template(),
            'recommendations.html': self._get_recommendations_template()
        }
        
        self.template_env = Environment(
            loader=DictLoader(html_templates),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate_comprehensive_report(
        self,
        test_results: List[TestResultSummary],
        report_config: Optional[ReportConfiguration] = None,
        output_formats: Optional[List[ReportFormat]] = None
    ) -> Dict[str, str]:
        """
        Generate comprehensive performance report with multiple output formats.
        
        Args:
            test_results: List of test result summaries to analyze
            report_config: Report configuration parameters
            output_formats: List of desired output formats
            
        Returns:
            Dictionary mapping output format to generated file path
            
        Raises:
            ValueError: If test results are invalid or insufficient
            RuntimeError: If report generation fails
        """
        start_time = time.time()
        
        if not test_results:
            raise ValueError("Test results are required for report generation")
        
        # Use default configuration if not provided
        config = report_config or ReportConfiguration()
        formats = output_formats or [ReportFormat.HTML, ReportFormat.JSON]
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info(
                "Starting comprehensive performance report generation",
                test_count=len(test_results),
                output_formats=[fmt.value for fmt in formats],
                target_audience=config.target_audience.value
            )
        
        generated_files = {}
        
        try:
            # Validate and process test results
            processed_results = self._process_test_results(test_results)
            
            # Generate performance analysis
            analysis_results = self._analyze_performance_data(processed_results, config)
            
            # Detect performance issues
            detected_issues = self._detect_performance_issues(analysis_results, config)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analysis_results, detected_issues, config)
            
            # Create comprehensive report data
            report_data = self._create_report_data(
                processed_results,
                analysis_results,
                detected_issues,
                recommendations,
                config
            )
            
            # Generate reports in requested formats
            for output_format in formats:
                try:
                    file_path = self._generate_format_specific_report(
                        report_data,
                        output_format,
                        config
                    )
                    generated_files[output_format.value] = str(file_path)
                    
                    # Update metrics
                    if PROMETHEUS_AVAILABLE:
                        self.report_generation_counter.labels(
                            format=output_format.value,
                            stakeholder_type=config.target_audience.value
                        ).inc()
                        
                except Exception as format_error:
                    if STRUCTLOG_AVAILABLE:
                        self.logger.error(
                            "Failed to generate report in specific format",
                            format=output_format.value,
                            error=str(format_error)
                        )
                    # Continue with other formats
                    continue
            
            # Update performance metrics
            generation_duration = time.time() - start_time
            
            if PROMETHEUS_AVAILABLE:
                for output_format in formats:
                    self.report_generation_histogram.labels(
                        format=output_format.value
                    ).observe(generation_duration)
                
                # Update issue detection metrics
                for issue in detected_issues:
                    self.issues_detected_gauge.labels(
                        severity=issue.severity.value,
                        issue_type=issue.issue_type.value
                    ).inc()
                
                # Update variance distribution
                for result in processed_results:
                    for variance in result.variance_analysis.values():
                        if isinstance(variance, (int, float)) and not math.isinf(variance):
                            self.variance_distribution_histogram.observe(abs(variance))
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Comprehensive performance report generation completed",
                    generated_formats=list(generated_files.keys()),
                    issues_detected=len(detected_issues),
                    generation_duration=generation_duration,
                    output_directory=str(self.output_directory)
                )
            
            return generated_files
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Comprehensive performance report generation failed",
                    error=str(e),
                    test_count=len(test_results)
                )
            raise RuntimeError(f"Report generation failed: {str(e)}")
    
    def parse_locust_results(self, locust_results_path: Path) -> TestResultSummary:
        """
        Parse Locust load testing results into standardized test result format.
        
        Args:
            locust_results_path: Path to Locust CSV results file
            
        Returns:
            TestResultSummary with parsed Locust results
            
        Raises:
            FileNotFoundError: If Locust results file is not found
            ValueError: If Locust results format is invalid
        """
        if not locust_results_path.exists():
            raise FileNotFoundError(f"Locust results file not found: {locust_results_path}")
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info(
                "Parsing Locust load testing results",
                results_path=str(locust_results_path)
            )
        
        test_summary = TestResultSummary(
            test_name="locust_load_test",
            test_timestamp=datetime.now(timezone.utc),
            test_environment="load_testing"
        )
        
        try:
            # Parse Locust CSV results
            response_time_data = {}
            throughput_data = {}
            error_data = {}
            
            with open(locust_results_path, 'r', encoding='utf-8') as f:
                csv_reader = csv.DictReader(f)
                
                for row in csv_reader:
                    endpoint = row.get('Name', 'unknown')
                    method = row.get('Method', 'GET')
                    endpoint_key = f"{method} {endpoint}"
                    
                    # Parse response time metrics
                    response_time_data[endpoint_key] = {
                        'min_ms': float(row.get('Min Response Time', 0)),
                        'max_ms': float(row.get('Max Response Time', 0)),
                        'avg_ms': float(row.get('Average Response Time', 0)),
                        'median_ms': float(row.get('Median Response Time', 0)),
                        'p95_ms': float(row.get('95%ile', 0)),
                        'p99_ms': float(row.get('99%ile', 0))
                    }
                    
                    # Parse throughput metrics
                    request_count = int(row.get('Request Count', 0))
                    failure_count = int(row.get('Failure Count', 0))
                    
                    throughput_data[endpoint_key] = {
                        'total_requests': request_count,
                        'successful_requests': request_count - failure_count,
                        'failed_requests': failure_count,
                        'requests_per_second': float(row.get('Requests/s', 0)),
                        'failures_per_second': float(row.get('Failures/s', 0))
                    }
                    
                    # Parse error metrics
                    error_rate = (failure_count / request_count * 100) if request_count > 0 else 0
                    error_data[endpoint_key] = {
                        'error_rate_percent': error_rate,
                        'total_failures': failure_count
                    }
            
            # Update test summary with parsed data
            test_summary.response_time_metrics = response_time_data
            test_summary.throughput_metrics = self._flatten_throughput_data(throughput_data)
            test_summary.error_metrics = self._flatten_error_data(error_data)
            
            # Calculate overall metrics
            all_requests = sum(data['total_requests'] for data in throughput_data.values())
            all_failures = sum(data['failed_requests'] for data in throughput_data.values())
            
            test_summary.sample_size = all_requests
            test_summary.error_metrics['overall_error_rate'] = (
                all_failures / all_requests * 100 if all_requests > 0 else 0
            )
            
            # Perform baseline comparison
            test_summary.baseline_comparison = self._compare_with_baseline(test_summary)
            test_summary.variance_analysis = self._calculate_variance_analysis(test_summary)
            test_summary.compliance_status = self._assess_compliance_status(test_summary)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Locust results parsing completed",
                    endpoints_analyzed=len(response_time_data),
                    total_requests=all_requests,
                    overall_error_rate=test_summary.error_metrics['overall_error_rate']
                )
            
            return test_summary
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Failed to parse Locust results",
                    results_path=str(locust_results_path),
                    error=str(e)
                )
            raise ValueError(f"Invalid Locust results format: {str(e)}")
    
    def parse_apache_bench_results(self, ab_results_path: Path) -> TestResultSummary:
        """
        Parse Apache Bench performance testing results into standardized format.
        
        Args:
            ab_results_path: Path to Apache Bench results file
            
        Returns:
            TestResultSummary with parsed Apache Bench results
            
        Raises:
            FileNotFoundError: If Apache Bench results file is not found
            ValueError: If results format is invalid
        """
        if not ab_results_path.exists():
            raise FileNotFoundError(f"Apache Bench results file not found: {ab_results_path}")
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info(
                "Parsing Apache Bench performance results",
                results_path=str(ab_results_path)
            )
        
        test_summary = TestResultSummary(
            test_name="apache_bench_performance_test",
            test_timestamp=datetime.now(timezone.utc),
            test_environment="benchmark_testing"
        )
        
        try:
            # Parse Apache Bench text output
            with open(ab_results_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract key metrics using regex patterns
            import re
            
            # Extract basic test information
            requests_match = re.search(r'Complete requests:\s+(\d+)', content)
            failed_match = re.search(r'Failed requests:\s+(\d+)', content)
            total_time_match = re.search(r'Time taken for tests:\s+([\d.]+)\s+seconds', content)
            rps_match = re.search(r'Requests per second:\s+([\d.]+)', content)
            
            if not all([requests_match, total_time_match, rps_match]):
                raise ValueError("Invalid Apache Bench output format")
            
            total_requests = int(requests_match.group(1))
            failed_requests = int(failed_match.group(1)) if failed_match else 0
            total_time = float(total_time_match.group(1))
            requests_per_second = float(rps_match.group(1))
            
            # Extract response time percentiles
            percentile_patterns = {
                'p50': r'50%\s+([\d.]+)',
                'p66': r'66%\s+([\d.]+)',
                'p75': r'75%\s+([\d.]+)',
                'p80': r'80%\s+([\d.]+)',
                'p90': r'90%\s+([\d.]+)',
                'p95': r'95%\s+([\d.]+)',
                'p98': r'98%\s+([\d.]+)',
                'p99': r'99%\s+([\d.]+)',
                'p100': r'100%\s+([\d.]+)'
            }
            
            response_times = {}
            for percentile, pattern in percentile_patterns.items():
                match = re.search(pattern, content)
                if match:
                    response_times[f'{percentile}_ms'] = float(match.group(1))
            
            # Extract mean response time
            mean_match = re.search(r'Time per request:\s+([\d.]+)\s+\[ms\].*mean', content)
            if mean_match:
                response_times['mean_ms'] = float(mean_match.group(1))
            
            # Build response time metrics
            endpoint_key = "GET /benchmark"  # Default endpoint for Apache Bench
            test_summary.response_time_metrics = {
                endpoint_key: response_times
            }
            
            # Build throughput metrics
            test_summary.throughput_metrics = {
                'total_requests': total_requests,
                'successful_requests': total_requests - failed_requests,
                'failed_requests': failed_requests,
                'requests_per_second': requests_per_second,
                'test_duration_seconds': total_time
            }
            
            # Build error metrics
            error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0
            test_summary.error_metrics = {
                'overall_error_rate': error_rate,
                'total_failures': failed_requests
            }
            
            # Build resource utilization (basic)
            test_summary.resource_utilization = {
                'requests_per_second': requests_per_second,
                'avg_response_time_ms': response_times.get('mean_ms', 0)
            }
            
            # Set test metadata
            test_summary.sample_size = total_requests
            test_summary.test_duration_seconds = total_time
            
            # Perform baseline comparison
            test_summary.baseline_comparison = self._compare_with_baseline(test_summary)
            test_summary.variance_analysis = self._calculate_variance_analysis(test_summary)
            test_summary.compliance_status = self._assess_compliance_status(test_summary)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Apache Bench results parsing completed",
                    total_requests=total_requests,
                    requests_per_second=requests_per_second,
                    error_rate=error_rate,
                    mean_response_time=response_times.get('mean_ms', 0)
                )
            
            return test_summary
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error(
                    "Failed to parse Apache Bench results",
                    results_path=str(ab_results_path),
                    error=str(e)
                )
            raise ValueError(f"Invalid Apache Bench results format: {str(e)}")
    
    def _process_test_results(self, test_results: List[TestResultSummary]) -> List[TestResultSummary]:
        """
        Process and validate test results for report generation.
        
        Args:
            test_results: Raw test result summaries
            
        Returns:
            Processed and validated test result summaries
        """
        processed_results = []
        
        for result in test_results:
            # Validate test result completeness
            if not result.test_name or not result.response_time_metrics:
                if STRUCTLOG_AVAILABLE:
                    self.logger.warning(
                        "Skipping incomplete test result",
                        test_name=result.test_name,
                        has_response_times=bool(result.response_time_metrics)
                    )
                continue
            
            # Calculate derived metrics
            if not result.variance_analysis:
                result.variance_analysis = self._calculate_variance_analysis(result)
            
            if not result.compliance_status:
                result.compliance_status = self._assess_compliance_status(result)
            
            if not result.baseline_comparison:
                result.baseline_comparison = self._compare_with_baseline(result)
            
            # Calculate overall compliance
            result.overall_compliance = all(result.compliance_status.values())
            
            # Calculate performance grade
            result.performance_grade = self._calculate_performance_grade(result)
            
            # Calculate statistical confidence
            result.statistical_confidence = self._calculate_statistical_confidence(result.sample_size)
            
            # Calculate test reliability score
            result.test_reliability_score = self._calculate_test_reliability(result)
            
            processed_results.append(result)
        
        return processed_results
    
    def _analyze_performance_data(
        self,
        test_results: List[TestResultSummary],
        config: ReportConfiguration
    ) -> Dict[str, Any]:
        """
        Analyze performance data across test results for comprehensive insights.
        
        Args:
            test_results: Processed test result summaries
            config: Report configuration parameters
            
        Returns:
            Dictionary containing comprehensive performance analysis
        """
        analysis = {
            'summary_statistics': {},
            'trend_analysis': {},
            'variance_analysis': {},
            'compliance_assessment': {},
            'performance_patterns': {},
            'outlier_detection': {}
        }
        
        if not test_results:
            return analysis
        
        # Summary statistics across all tests
        all_variances = []
        all_response_times = []
        all_throughput = []
        compliance_rates = []
        
        for result in test_results:
            # Collect variance data
            for variance in result.variance_analysis.values():
                if isinstance(variance, (int, float)) and not math.isinf(variance):
                    all_variances.append(abs(variance))
            
            # Collect response time data
            for endpoint_data in result.response_time_metrics.values():
                if 'mean_ms' in endpoint_data:
                    all_response_times.append(endpoint_data['mean_ms'])
                elif 'avg_ms' in endpoint_data:
                    all_response_times.append(endpoint_data['avg_ms'])
            
            # Collect throughput data
            if 'requests_per_second' in result.throughput_metrics:
                all_throughput.append(result.throughput_metrics['requests_per_second'])
            
            # Calculate compliance rate
            if result.compliance_status:
                compliance_rate = sum(1 for compliant in result.compliance_status.values() if compliant) / len(result.compliance_status)
                compliance_rates.append(compliance_rate)
        
        # Calculate summary statistics
        if all_variances:
            analysis['summary_statistics']['variance'] = {
                'mean': statistics.mean(all_variances),
                'median': statistics.median(all_variances),
                'std_dev': statistics.stdev(all_variances) if len(all_variances) > 1 else 0,
                'min': min(all_variances),
                'max': max(all_variances),
                'p95': statistics.quantiles(all_variances, n=20)[18] if len(all_variances) >= 20 else max(all_variances)
            }
        
        if all_response_times:
            analysis['summary_statistics']['response_time'] = {
                'mean': statistics.mean(all_response_times),
                'median': statistics.median(all_response_times),
                'std_dev': statistics.stdev(all_response_times) if len(all_response_times) > 1 else 0,
                'min': min(all_response_times),
                'max': max(all_response_times),
                'p95': statistics.quantiles(all_response_times, n=20)[18] if len(all_response_times) >= 20 else max(all_response_times)
            }
        
        if all_throughput:
            analysis['summary_statistics']['throughput'] = {
                'mean': statistics.mean(all_throughput),
                'median': statistics.median(all_throughput),
                'std_dev': statistics.stdev(all_throughput) if len(all_throughput) > 1 else 0,
                'min': min(all_throughput),
                'max': max(all_throughput)
            }
        
        # Compliance assessment
        if compliance_rates:
            analysis['compliance_assessment'] = {
                'overall_compliance_rate': statistics.mean(compliance_rates),
                'compliant_tests': sum(1 for rate in compliance_rates if rate >= 0.9),
                'total_tests': len(compliance_rates),
                'variance_threshold_violations': sum(1 for v in all_variances if v > config.variance_threshold)
            }
        
        # Trend analysis (if multiple test results)
        if len(test_results) > 1:
            analysis['trend_analysis'] = self._analyze_performance_trends(test_results)
        
        # Outlier detection
        if all_variances:
            analysis['outlier_detection'] = self._detect_performance_outliers(all_variances, all_response_times)
        
        return analysis
    
    def _detect_performance_issues(
        self,
        analysis_results: Dict[str, Any],
        config: ReportConfiguration
    ) -> List[PerformanceIssue]:
        """
        Detect performance issues based on analysis results and thresholds.
        
        Args:
            analysis_results: Performance analysis results
            config: Report configuration with thresholds
            
        Returns:
            List of detected performance issues
        """
        detected_issues = []
        
        # Check variance threshold violations
        compliance_data = analysis_results.get('compliance_assessment', {})
        variance_violations = compliance_data.get('variance_threshold_violations', 0)
        
        if variance_violations > 0:
            issue = PerformanceIssue(
                issue_type=PerformanceIssueType.RESPONSE_TIME_DEGRADATION,
                severity=ReportSeverity.CRITICAL if variance_violations > 3 else ReportSeverity.HIGH,
                title=f"Performance Variance Threshold Violations ({variance_violations})",
                description=f"Detected {variance_violations} tests with performance variance exceeding ±{config.variance_threshold}% threshold",
                variance_percent=config.variance_threshold,
                impact_assessment=f"Performance degradation detected in {variance_violations} test scenarios",
                recommendation="Investigate response time degradation and optimize performance bottlenecks"
            )
            detected_issues.append(issue)
        
        # Check overall compliance rate
        compliance_rate = compliance_data.get('overall_compliance_rate', 1.0)
        if compliance_rate < 0.9:
            issue = PerformanceIssue(
                issue_type=PerformanceIssueType.REGRESSION_DETECTION,
                severity=ReportSeverity.HIGH,
                title=f"Low Performance Compliance Rate ({compliance_rate:.1%})",
                description=f"Overall compliance rate of {compliance_rate:.1%} is below 90% threshold",
                current_value=compliance_rate * 100,
                baseline_value=90.0,
                variance_percent=(90.0 - compliance_rate * 100),
                impact_assessment="System performance does not meet baseline requirements",
                recommendation="Review failing tests and implement performance optimizations"
            )
            detected_issues.append(issue)
        
        # Check response time statistics
        response_time_stats = analysis_results.get('summary_statistics', {}).get('response_time', {})
        if response_time_stats:
            mean_response_time = response_time_stats.get('mean', 0)
            p95_response_time = response_time_stats.get('p95', 0)
            
            if p95_response_time > RESPONSE_TIME_THRESHOLD_MS:
                issue = PerformanceIssue(
                    issue_type=PerformanceIssueType.RESPONSE_TIME_DEGRADATION,
                    severity=ReportSeverity.HIGH,
                    title=f"High 95th Percentile Response Time ({p95_response_time:.1f}ms)",
                    description=f"95th percentile response time of {p95_response_time:.1f}ms exceeds {RESPONSE_TIME_THRESHOLD_MS}ms threshold",
                    current_value=p95_response_time,
                    baseline_value=RESPONSE_TIME_THRESHOLD_MS,
                    variance_percent=((p95_response_time - RESPONSE_TIME_THRESHOLD_MS) / RESPONSE_TIME_THRESHOLD_MS) * 100,
                    impact_assessment="User experience may be degraded due to slow response times",
                    recommendation="Optimize slow endpoints and implement caching strategies"
                )
                detected_issues.append(issue)
        
        # Check throughput statistics
        throughput_stats = analysis_results.get('summary_statistics', {}).get('throughput', {})
        if throughput_stats:
            mean_throughput = throughput_stats.get('mean', 0)
            
            if mean_throughput < THROUGHPUT_THRESHOLD_RPS:
                issue = PerformanceIssue(
                    issue_type=PerformanceIssueType.THROUGHPUT_REDUCTION,
                    severity=ReportSeverity.MEDIUM,
                    title=f"Low Throughput ({mean_throughput:.1f} req/sec)",
                    description=f"Average throughput of {mean_throughput:.1f} req/sec is below {THROUGHPUT_THRESHOLD_RPS} req/sec threshold",
                    current_value=mean_throughput,
                    baseline_value=THROUGHPUT_THRESHOLD_RPS,
                    variance_percent=((THROUGHPUT_THRESHOLD_RPS - mean_throughput) / THROUGHPUT_THRESHOLD_RPS) * 100,
                    impact_assessment="System may not handle expected load capacity",
                    recommendation="Optimize request processing and consider horizontal scaling"
                )
                detected_issues.append(issue)
        
        # Check variance distribution
        variance_stats = analysis_results.get('summary_statistics', {}).get('variance', {})
        if variance_stats:
            max_variance = variance_stats.get('max', 0)
            mean_variance = variance_stats.get('mean', 0)
            
            if max_variance > config.variance_threshold * 2:
                issue = PerformanceIssue(
                    issue_type=PerformanceIssueType.REGRESSION_DETECTION,
                    severity=ReportSeverity.CRITICAL,
                    title=f"Extreme Performance Variance ({max_variance:.1f}%)",
                    description=f"Maximum variance of {max_variance:.1f}% is significantly above acceptable threshold",
                    current_value=max_variance,
                    baseline_value=config.variance_threshold,
                    variance_percent=max_variance,
                    impact_assessment="Critical performance regression detected",
                    recommendation="Immediate investigation required for performance degradation root cause"
                )
                detected_issues.append(issue)
        
        return detected_issues
    
    def _generate_recommendations(
        self,
        analysis_results: Dict[str, Any],
        detected_issues: List[PerformanceIssue],
        config: ReportConfiguration
    ) -> List[str]:
        """
        Generate automated performance optimization recommendations.
        
        Args:
            analysis_results: Performance analysis results
            detected_issues: List of detected performance issues
            config: Report configuration parameters
            
        Returns:
            List of actionable performance recommendations
        """
        recommendations = []
        
        # Base recommendations always included
        recommendations.extend([
            "🔍 Continue monitoring performance metrics for trend analysis",
            "📊 Maintain baseline comparison validation in CI/CD pipeline",
            "⚡ Consider implementing performance budgets for regression prevention"
        ])
        
        # Issue-specific recommendations
        critical_issues = [issue for issue in detected_issues if issue.severity == ReportSeverity.CRITICAL]
        high_issues = [issue for issue in detected_issues if issue.severity == ReportSeverity.HIGH]
        
        if critical_issues:
            recommendations.extend([
                "🚨 CRITICAL: Immediate action required for critical performance issues",
                "🔴 Review recent code changes for performance impact",
                "📞 Escalate to Performance Engineering Team for urgent investigation",
                "🔄 Consider rollback to previous stable version if regression detected"
            ])
        
        if high_issues:
            recommendations.extend([
                "⚠️ HIGH PRIORITY: Address high-severity performance issues within 24 hours",
                "🔧 Implement performance optimizations for identified bottlenecks",
                "💾 Review caching strategies and database query optimization"
            ])
        
        # Response time specific recommendations
        response_time_stats = analysis_results.get('summary_statistics', {}).get('response_time', {})
        if response_time_stats:
            p95_response_time = response_time_stats.get('p95', 0)
            
            if p95_response_time > RESPONSE_TIME_THRESHOLD_MS:
                recommendations.extend([
                    f"⏱️ RESPONSE TIME: Optimize endpoints with >500ms response times",
                    "🗃️ Implement API response caching for frequently accessed data",
                    "🔗 Review database connection pooling configuration",
                    "📈 Consider implementing CDN for static content delivery"
                ])
        
        # Throughput specific recommendations
        throughput_stats = analysis_results.get('summary_statistics', {}).get('throughput', {})
        if throughput_stats:
            mean_throughput = throughput_stats.get('mean', 0)
            
            if mean_throughput < THROUGHPUT_THRESHOLD_RPS:
                recommendations.extend([
                    f"📊 THROUGHPUT: Scale application to meet {THROUGHPUT_THRESHOLD_RPS} req/sec minimum",
                    "🏗️ Evaluate horizontal scaling options (container orchestration)",
                    "⚙️ Optimize worker process configuration and connection pools",
                    "🔄 Implement asynchronous processing for heavy operations"
                ])
        
        # Variance specific recommendations
        variance_stats = analysis_results.get('summary_statistics', {}).get('variance', {})
        if variance_stats:
            mean_variance = variance_stats.get('mean', 0)
            max_variance = variance_stats.get('max', 0)
            
            if mean_variance > config.variance_threshold:
                recommendations.extend([
                    f"📏 VARIANCE: Reduce performance variance to maintain ≤{config.variance_threshold}% threshold",
                    "🎯 Implement consistent resource allocation and environment configuration",
                    "📋 Review test environment parity with production settings",
                    "🔍 Analyze performance patterns for systematic optimization opportunities"
                ])
        
        # Compliance specific recommendations
        compliance_data = analysis_results.get('compliance_assessment', {})
        compliance_rate = compliance_data.get('overall_compliance_rate', 1.0)
        
        if compliance_rate < 0.9:
            recommendations.extend([
                f"✅ COMPLIANCE: Improve compliance rate from {compliance_rate:.1%} to >90%",
                "🧪 Review failing test scenarios for optimization opportunities",
                "📝 Update performance baselines if improvements are validated",
                "🔄 Implement automated performance regression detection"
            ])
        
        # Success case recommendations
        if not detected_issues or all(issue.severity in [ReportSeverity.LOW, ReportSeverity.INFO] for issue in detected_issues):
            recommendations.extend([
                "🎉 EXCELLENT: All performance metrics within acceptable thresholds",
                "📈 Consider updating baselines to reflect improved performance",
                "🔬 Focus on maintaining current performance levels",
                "🚀 Explore opportunities for further optimization"
            ])
        
        return recommendations[:15]  # Limit to top 15 recommendations
    
    def _create_report_data(
        self,
        test_results: List[TestResultSummary],
        analysis_results: Dict[str, Any],
        detected_issues: List[PerformanceIssue],
        recommendations: List[str],
        config: ReportConfiguration
    ) -> Dict[str, Any]:
        """
        Create comprehensive report data structure for template rendering.
        
        Args:
            test_results: Processed test result summaries
            analysis_results: Performance analysis results
            detected_issues: List of detected performance issues
            recommendations: List of performance recommendations
            config: Report configuration parameters
            
        Returns:
            Comprehensive report data dictionary
        """
        # Get Node.js baseline for comparison
        nodejs_baseline = self.baseline_manager.get_default_baseline()
        
        report_data = {
            # Report metadata
            'metadata': {
                'title': config.report_title,
                'description': config.report_description,
                'generated_by': config.generated_by,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'target_audience': config.target_audience.value,
                'report_version': '1.0.0',
                'python_version': '3.11',
                'flask_version': '2.3+'
            },
            
            # Executive summary
            'executive_summary': {
                'total_tests': len(test_results),
                'overall_compliance': all(result.overall_compliance for result in test_results),
                'compliance_rate': statistics.mean([
                    sum(1 for compliant in result.compliance_status.values() if compliant) / len(result.compliance_status)
                    for result in test_results if result.compliance_status
                ]) if test_results else 0,
                'critical_issues': len([issue for issue in detected_issues if issue.severity == ReportSeverity.CRITICAL]),
                'high_issues': len([issue for issue in detected_issues if issue.severity == ReportSeverity.HIGH]),
                'total_issues': len(detected_issues),
                'performance_grade': self._calculate_overall_performance_grade(test_results),
                'baseline_compliance': all(
                    abs(variance) <= config.variance_threshold
                    for result in test_results
                    for variance in result.variance_analysis.values()
                    if isinstance(variance, (int, float)) and not math.isinf(variance)
                )
            },
            
            # Test results summary
            'test_results': [
                {
                    'test_id': result.test_id,
                    'test_name': result.test_name,
                    'test_timestamp': result.test_timestamp.isoformat(),
                    'test_duration_seconds': result.test_duration_seconds,
                    'test_environment': result.test_environment,
                    'overall_compliance': result.overall_compliance,
                    'performance_grade': result.performance_grade,
                    'sample_size': result.sample_size,
                    'statistical_confidence': result.statistical_confidence,
                    'response_time_metrics': result.response_time_metrics,
                    'throughput_metrics': result.throughput_metrics,
                    'error_metrics': result.error_metrics,
                    'variance_analysis': result.variance_analysis,
                    'compliance_status': result.compliance_status
                }
                for result in test_results
            ],
            
            # Performance analysis
            'performance_analysis': analysis_results,
            
            # Baseline comparison
            'baseline_comparison': {
                'nodejs_baseline': {
                    'version': nodejs_baseline.nodejs_version,
                    'express_version': nodejs_baseline.express_version,
                    'collection_timestamp': nodejs_baseline.collection_timestamp.isoformat(),
                    'response_time_p95': nodejs_baseline.api_response_time_p95,
                    'requests_per_second': nodejs_baseline.requests_per_second_sustained,
                    'memory_usage_mb': nodejs_baseline.memory_usage_baseline_mb,
                    'cpu_utilization': nodejs_baseline.cpu_utilization_average,
                    'error_rate': nodejs_baseline.error_rate_overall
                },
                'variance_threshold': config.variance_threshold,
                'warning_threshold': config.warning_threshold,
                'memory_threshold': config.memory_threshold
            },
            
            # Detected issues
            'issues': [issue.to_dict() for issue in detected_issues],
            
            # Recommendations
            'recommendations': recommendations,
            
            # Configuration
            'config': {
                'include_charts': config.include_charts,
                'include_trend_analysis': config.include_trend_analysis,
                'include_baseline_comparison': config.include_baseline_comparison,
                'include_issue_analysis': config.include_issue_analysis,
                'chart_style': config.chart_style,
                'color_scheme': config.color_scheme
            }
        }
        
        return report_data
    
    def _generate_format_specific_report(
        self,
        report_data: Dict[str, Any],
        output_format: ReportFormat,
        config: ReportConfiguration
    ) -> Path:
        """
        Generate report in specific output format.
        
        Args:
            report_data: Comprehensive report data
            output_format: Desired output format
            config: Report configuration parameters
            
        Returns:
            Path to generated report file
            
        Raises:
            NotImplementedError: If output format is not supported
            RuntimeError: If report generation fails
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"performance_report_{timestamp}"
        
        if output_format == ReportFormat.JSON:
            return self._generate_json_report(report_data, filename_base)
        elif output_format == ReportFormat.HTML:
            return self._generate_html_report(report_data, config, filename_base)
        elif output_format == ReportFormat.PDF:
            return self._generate_pdf_report(report_data, config, filename_base)
        elif output_format == ReportFormat.CSV:
            return self._generate_csv_report(report_data, filename_base)
        elif output_format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(report_data, filename_base)
        else:
            raise NotImplementedError(f"Output format {output_format.value} not supported")
    
    def _generate_json_report(self, report_data: Dict[str, Any], filename_base: str) -> Path:
        """
        Generate JSON format performance report.
        
        Args:
            report_data: Comprehensive report data
            filename_base: Base filename for output
            
        Returns:
            Path to generated JSON report file
        """
        output_path = self.output_directory / f"{filename_base}.json"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "JSON performance report generated",
                    output_path=str(output_path),
                    file_size_kb=output_path.stat().st_size / 1024
                )
            
            return output_path
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate JSON report: {str(e)}")
    
    def _generate_html_report(
        self,
        report_data: Dict[str, Any],
        config: ReportConfiguration,
        filename_base: str
    ) -> Path:
        """
        Generate HTML format performance report with interactive elements.
        
        Args:
            report_data: Comprehensive report data
            config: Report configuration parameters
            filename_base: Base filename for output
            
        Returns:
            Path to generated HTML report file
        """
        if not JINJA2_AVAILABLE:
            raise RuntimeError("Jinja2 not available - HTML reporting disabled")
        
        output_path = self.output_directory / f"{filename_base}.html"
        
        try:
            # Generate charts if enabled
            chart_data = {}
            if config.include_charts and VISUALIZATION_AVAILABLE:
                chart_data = self._generate_performance_charts(report_data, config)
            
            # Prepare template context
            template_context = {
                **report_data,
                'charts': chart_data,
                'css_styles': self._get_report_css_styles(config),
                'javascript': self._get_report_javascript()
            }
            
            # Render HTML template
            template = self.template_env.get_template('base_report.html')
            html_content = template.render(**template_context)
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "HTML performance report generated",
                    output_path=str(output_path),
                    file_size_kb=output_path.stat().st_size / 1024,
                    charts_included=len(chart_data)
                )
            
            return output_path
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate HTML report: {str(e)}")
    
    def _generate_pdf_report(
        self,
        report_data: Dict[str, Any],
        config: ReportConfiguration,
        filename_base: str
    ) -> Path:
        """
        Generate PDF format performance report for stakeholder distribution.
        
        Args:
            report_data: Comprehensive report data
            config: Report configuration parameters
            filename_base: Base filename for output
            
        Returns:
            Path to generated PDF report file
        """
        if not PDF_GENERATION_AVAILABLE:
            raise RuntimeError("WeasyPrint not available - PDF generation disabled")
        
        output_path = self.output_directory / f"{filename_base}.pdf"
        
        try:
            # First generate HTML content
            html_report_path = self._generate_html_report(report_data, config, f"{filename_base}_temp")
            
            # Convert HTML to PDF
            html_content = html_report_path.read_text(encoding='utf-8')
            
            # Generate PDF using WeasyPrint
            pdf_document = weasyprint.HTML(string=html_content, base_url=str(self.output_directory))
            pdf_document.write_pdf(str(output_path))
            
            # Clean up temporary HTML file
            html_report_path.unlink()
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "PDF performance report generated",
                    output_path=str(output_path),
                    file_size_kb=output_path.stat().st_size / 1024
                )
            
            return output_path
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate PDF report: {str(e)}")
    
    def _generate_csv_report(self, report_data: Dict[str, Any], filename_base: str) -> Path:
        """
        Generate CSV format performance report for data analysis.
        
        Args:
            report_data: Comprehensive report data
            filename_base: Base filename for output
            
        Returns:
            Path to generated CSV report file
        """
        output_path = self.output_directory / f"{filename_base}.csv"
        
        try:
            # Create CSV data from test results
            csv_data = []
            
            for test_result in report_data.get('test_results', []):
                # Base test information
                base_row = {
                    'test_id': test_result['test_id'],
                    'test_name': test_result['test_name'],
                    'test_timestamp': test_result['test_timestamp'],
                    'test_duration_seconds': test_result['test_duration_seconds'],
                    'test_environment': test_result['test_environment'],
                    'overall_compliance': test_result['overall_compliance'],
                    'performance_grade': test_result['performance_grade'],
                    'sample_size': test_result['sample_size'],
                    'statistical_confidence': test_result['statistical_confidence']
                }
                
                # Add response time metrics
                for endpoint, metrics in test_result.get('response_time_metrics', {}).items():
                    row = base_row.copy()
                    row['endpoint'] = endpoint
                    row['metric_type'] = 'response_time'
                    
                    for metric_name, value in metrics.items():
                        row[f'response_time_{metric_name}'] = value
                    
                    csv_data.append(row)
                
                # Add throughput metrics
                row = base_row.copy()
                row['endpoint'] = 'overall'
                row['metric_type'] = 'throughput'
                
                for metric_name, value in test_result.get('throughput_metrics', {}).items():
                    row[f'throughput_{metric_name}'] = value
                
                csv_data.append(row)
                
                # Add variance analysis
                for metric_name, variance in test_result.get('variance_analysis', {}).items():
                    row = base_row.copy()
                    row['endpoint'] = metric_name
                    row['metric_type'] = 'variance'
                    row['variance_percent'] = variance
                    
                    csv_data.append(row)
            
            # Write CSV file
            if csv_data:
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = set()
                    for row in csv_data:
                        fieldnames.update(row.keys())
                    
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "CSV performance report generated",
                    output_path=str(output_path),
                    rows_written=len(csv_data),
                    file_size_kb=output_path.stat().st_size / 1024
                )
            
            return output_path
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate CSV report: {str(e)}")
    
    def _generate_markdown_report(self, report_data: Dict[str, Any], filename_base: str) -> Path:
        """
        Generate Markdown format performance report for documentation.
        
        Args:
            report_data: Comprehensive report data
            filename_base: Base filename for output
            
        Returns:
            Path to generated Markdown report file
        """
        output_path = self.output_directory / f"{filename_base}.md"
        
        try:
            markdown_content = self._create_markdown_content(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Markdown performance report generated",
                    output_path=str(output_path),
                    file_size_kb=output_path.stat().st_size / 1024
                )
            
            return output_path
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate Markdown report: {str(e)}")
    
    def _create_markdown_content(self, report_data: Dict[str, Any]) -> str:
        """
        Create comprehensive Markdown content for performance report.
        
        Args:
            report_data: Comprehensive report data
            
        Returns:
            Formatted Markdown content string
        """
        content = StringIO()
        
        # Report header
        metadata = report_data.get('metadata', {})
        content.write(f"# {metadata.get('title', 'Performance Analysis Report')}\n\n")
        content.write(f"**Generated:** {metadata.get('generated_at', 'Unknown')}\n")
        content.write(f"**Generated By:** {metadata.get('generated_by', 'Unknown')}\n")
        content.write(f"**Target Audience:** {metadata.get('target_audience', 'Technical')}\n\n")
        content.write(f"{metadata.get('description', '')}\n\n")
        
        # Executive Summary
        exec_summary = report_data.get('executive_summary', {})
        content.write("## Executive Summary\n\n")
        content.write(f"- **Total Tests:** {exec_summary.get('total_tests', 0)}\n")
        content.write(f"- **Overall Compliance:** {'✅ Yes' if exec_summary.get('overall_compliance') else '❌ No'}\n")
        content.write(f"- **Compliance Rate:** {exec_summary.get('compliance_rate', 0):.1%}\n")
        content.write(f"- **Performance Grade:** {exec_summary.get('performance_grade', 'N/A')}\n")
        content.write(f"- **Critical Issues:** {exec_summary.get('critical_issues', 0)}\n")
        content.write(f"- **High Priority Issues:** {exec_summary.get('high_issues', 0)}\n")
        content.write(f"- **Baseline Compliance:** {'✅ Yes' if exec_summary.get('baseline_compliance') else '❌ No'}\n\n")
        
        # Performance Analysis
        analysis = report_data.get('performance_analysis', {})
        if analysis:
            content.write("## Performance Analysis\n\n")
            
            # Summary statistics
            summary_stats = analysis.get('summary_statistics', {})
            if summary_stats:
                content.write("### Summary Statistics\n\n")
                
                for stat_type, stats in summary_stats.items():
                    content.write(f"#### {stat_type.replace('_', ' ').title()}\n\n")
                    content.write("| Metric | Value |\n")
                    content.write("|--------|-------|\n")
                    for metric, value in stats.items():
                        if isinstance(value, float):
                            content.write(f"| {metric.replace('_', ' ').title()} | {value:.2f} |\n")
                        else:
                            content.write(f"| {metric.replace('_', ' ').title()} | {value} |\n")
                    content.write("\n")
        
        # Baseline Comparison
        baseline = report_data.get('baseline_comparison', {})
        if baseline:
            content.write("## Baseline Comparison\n\n")
            nodejs_baseline = baseline.get('nodejs_baseline', {})
            content.write(f"**Node.js Baseline Version:** {nodejs_baseline.get('version', 'Unknown')}\n")
            content.write(f"**Express Version:** {nodejs_baseline.get('express_version', 'Unknown')}\n")
            content.write(f"**Collection Date:** {nodejs_baseline.get('collection_timestamp', 'Unknown')}\n\n")
            
            content.write("### Baseline Metrics\n\n")
            content.write("| Metric | Baseline Value | Threshold |\n")
            content.write("|--------|---------------|----------|\n")
            content.write(f"| Response Time P95 | {nodejs_baseline.get('response_time_p95', 0):.1f}ms | ±{baseline.get('variance_threshold', 10)}% |\n")
            content.write(f"| Requests per Second | {nodejs_baseline.get('requests_per_second', 0):.1f} | ±{baseline.get('variance_threshold', 10)}% |\n")
            content.write(f"| Memory Usage | {nodejs_baseline.get('memory_usage_mb', 0):.1f}MB | ±{baseline.get('memory_threshold', 15)}% |\n")
            content.write(f"| CPU Utilization | {nodejs_baseline.get('cpu_utilization', 0):.1f}% | ±{baseline.get('variance_threshold', 10)}% |\n")
            content.write(f"| Error Rate | {nodejs_baseline.get('error_rate', 0):.2f}% | ±{baseline.get('variance_threshold', 10)}% |\n\n")
        
        # Detected Issues
        issues = report_data.get('issues', [])
        if issues:
            content.write("## Detected Issues\n\n")
            
            for issue in issues:
                severity_icon = {
                    'critical': '🚨',
                    'high': '⚠️',
                    'medium': '📋',
                    'low': '📝',
                    'info': 'ℹ️'
                }.get(issue.get('severity', 'info'), 'ℹ️')
                
                content.write(f"### {severity_icon} {issue.get('title', 'Unknown Issue')} ({issue.get('severity', 'Unknown').upper()})\n\n")
                content.write(f"**Description:** {issue.get('description', 'No description available')}\n\n")
                
                if issue.get('current_value') and issue.get('baseline_value'):
                    content.write(f"**Current Value:** {issue.get('current_value'):.2f}\n")
                    content.write(f"**Baseline Value:** {issue.get('baseline_value'):.2f}\n")
                    content.write(f"**Variance:** {issue.get('variance_percent', 0):.2f}%\n\n")
                
                content.write(f"**Impact:** {issue.get('impact_assessment', 'Impact assessment not available')}\n\n")
                content.write(f"**Recommendation:** {issue.get('recommendation', 'No specific recommendation')}\n\n")
        
        # Recommendations
        recommendations = report_data.get('recommendations', [])
        if recommendations:
            content.write("## Recommendations\n\n")
            for i, recommendation in enumerate(recommendations, 1):
                content.write(f"{i}. {recommendation}\n")
            content.write("\n")
        
        # Test Results Summary
        test_results = report_data.get('test_results', [])
        if test_results:
            content.write("## Test Results Summary\n\n")
            content.write("| Test Name | Environment | Grade | Compliance | Duration | Sample Size |\n")
            content.write("|-----------|-------------|-------|------------|----------|-------------|\n")
            
            for test in test_results:
                compliance_icon = "✅" if test.get('overall_compliance') else "❌"
                content.write(f"| {test.get('test_name', 'Unknown')} | ")
                content.write(f"{test.get('test_environment', 'Unknown')} | ")
                content.write(f"{test.get('performance_grade', 'N/A')} | ")
                content.write(f"{compliance_icon} | ")
                content.write(f"{test.get('test_duration_seconds', 0):.1f}s | ")
                content.write(f"{test.get('sample_size', 0):,} |\n")
            content.write("\n")
        
        # Footer
        content.write("---\n\n")
        content.write("*This report was automatically generated by the Flask Migration Performance System*\n")
        content.write(f"*Report generated at: {metadata.get('generated_at', 'Unknown')}*\n")
        
        return content.getvalue()
    
    def _compare_with_baseline(self, test_result: TestResultSummary) -> Dict[str, Dict[str, Any]]:
        """
        Compare test result with Node.js baseline performance metrics.
        
        Args:
            test_result: Test result summary to compare
            
        Returns:
            Dictionary containing baseline comparison results
        """
        comparison_results = {}
        
        try:
            # Get Node.js baseline
            nodejs_baseline = self.baseline_manager.get_default_baseline()
            
            # Compare response times
            for endpoint, metrics in test_result.response_time_metrics.items():
                endpoint_comparison = {}
                
                # Compare average/mean response time
                current_avg = metrics.get('avg_ms') or metrics.get('mean_ms', 0)
                baseline_avg = nodejs_baseline.endpoint_baselines.get(endpoint, {}).get('mean', nodejs_baseline.api_response_time_mean)
                
                if baseline_avg > 0:
                    variance = ((current_avg - baseline_avg) / baseline_avg) * 100
                    endpoint_comparison['response_time_variance'] = variance
                    endpoint_comparison['current_avg_ms'] = current_avg
                    endpoint_comparison['baseline_avg_ms'] = baseline_avg
                    endpoint_comparison['compliant'] = abs(variance) <= CRITICAL_VARIANCE_THRESHOLD
                
                # Compare P95 response time
                current_p95 = metrics.get('p95_ms', 0)
                baseline_p95 = nodejs_baseline.endpoint_baselines.get(endpoint, {}).get('p95', nodejs_baseline.api_response_time_p95)
                
                if baseline_p95 > 0:
                    p95_variance = ((current_p95 - baseline_p95) / baseline_p95) * 100
                    endpoint_comparison['p95_variance'] = p95_variance
                    endpoint_comparison['current_p95_ms'] = current_p95
                    endpoint_comparison['baseline_p95_ms'] = baseline_p95
                    endpoint_comparison['p95_compliant'] = abs(p95_variance) <= CRITICAL_VARIANCE_THRESHOLD
                
                comparison_results[endpoint] = endpoint_comparison
            
            # Compare overall throughput
            current_rps = test_result.throughput_metrics.get('requests_per_second', 0)
            baseline_rps = nodejs_baseline.requests_per_second_sustained
            
            if baseline_rps > 0:
                rps_variance = ((current_rps - baseline_rps) / baseline_rps) * 100
                comparison_results['throughput'] = {
                    'variance': rps_variance,
                    'current_rps': current_rps,
                    'baseline_rps': baseline_rps,
                    'compliant': abs(rps_variance) <= CRITICAL_VARIANCE_THRESHOLD
                }
            
            # Compare error rates
            current_error_rate = test_result.error_metrics.get('overall_error_rate', 0)
            baseline_error_rate = nodejs_baseline.error_rate_overall
            
            if baseline_error_rate >= 0:
                error_variance = current_error_rate - baseline_error_rate  # Absolute difference for error rates
                comparison_results['error_rate'] = {
                    'variance': error_variance,
                    'current_error_rate': current_error_rate,
                    'baseline_error_rate': baseline_error_rate,
                    'compliant': current_error_rate <= baseline_error_rate * 1.5  # Allow 50% increase
                }
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning(
                    "Failed to perform baseline comparison",
                    test_name=test_result.test_name,
                    error=str(e)
                )
        
        return comparison_results
    
    def _calculate_variance_analysis(self, test_result: TestResultSummary) -> Dict[str, float]:
        """
        Calculate comprehensive variance analysis for test result.
        
        Args:
            test_result: Test result summary to analyze
            
        Returns:
            Dictionary containing variance analysis results
        """
        variance_analysis = {}
        
        # Extract variances from baseline comparison
        for endpoint, comparison in test_result.baseline_comparison.items():
            if 'response_time_variance' in comparison:
                variance_analysis[f"{endpoint}_response_time"] = comparison['response_time_variance']
            
            if 'p95_variance' in comparison:
                variance_analysis[f"{endpoint}_p95"] = comparison['p95_variance']
            
            if 'variance' in comparison:
                variance_analysis[endpoint] = comparison['variance']
        
        return variance_analysis
    
    def _assess_compliance_status(self, test_result: TestResultSummary) -> Dict[str, bool]:
        """
        Assess compliance status for test result across different metrics.
        
        Args:
            test_result: Test result summary to assess
            
        Returns:
            Dictionary containing compliance status for each metric
        """
        compliance_status = {}
        
        # Check compliance from baseline comparison
        for endpoint, comparison in test_result.baseline_comparison.items():
            if 'compliant' in comparison:
                compliance_status[f"{endpoint}_response_time"] = comparison['compliant']
            
            if 'p95_compliant' in comparison:
                compliance_status[f"{endpoint}_p95"] = comparison['p95_compliant']
        
        # Check overall error rate compliance
        error_rate = test_result.error_metrics.get('overall_error_rate', 0)
        compliance_status['error_rate'] = error_rate <= 1.0  # Error rate should be ≤1%
        
        # Check throughput compliance
        rps = test_result.throughput_metrics.get('requests_per_second', 0)
        compliance_status['throughput'] = rps >= THROUGHPUT_THRESHOLD_RPS
        
        return compliance_status
    
    def _calculate_performance_grade(self, test_result: TestResultSummary) -> str:
        """
        Calculate performance grade based on compliance and variance metrics.
        
        Args:
            test_result: Test result summary to grade
            
        Returns:
            Performance grade (A-F)
        """
        if not test_result.variance_analysis:
            return "C"  # Default grade if no variance data
        
        # Calculate average absolute variance
        variances = [
            abs(variance) for variance in test_result.variance_analysis.values()
            if isinstance(variance, (int, float)) and not math.isinf(variance)
        ]
        
        if not variances:
            return "C"
        
        avg_variance = statistics.mean(variances)
        compliance_rate = sum(1 for compliant in test_result.compliance_status.values() if compliant) / len(test_result.compliance_status) if test_result.compliance_status else 0
        
        # Grade based on average variance and compliance
        if avg_variance <= 2.0 and compliance_rate >= 0.95:
            return "A"  # Excellent
        elif avg_variance <= 5.0 and compliance_rate >= 0.9:
            return "B"  # Good
        elif avg_variance <= 10.0 and compliance_rate >= 0.8:
            return "C"  # Acceptable
        elif avg_variance <= 15.0 and compliance_rate >= 0.7:
            return "D"  # Poor
        else:
            return "F"  # Failing
    
    def _calculate_overall_performance_grade(self, test_results: List[TestResultSummary]) -> str:
        """
        Calculate overall performance grade across all test results.
        
        Args:
            test_results: List of test result summaries
            
        Returns:
            Overall performance grade (A-F)
        """
        if not test_results:
            return "F"
        
        # Calculate grade points
        grade_points = {'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0}
        total_points = sum(grade_points.get(result.performance_grade, 0) for result in test_results)
        avg_points = total_points / len(test_results)
        
        # Convert back to letter grade
        if avg_points >= 3.5:
            return "A"
        elif avg_points >= 2.5:
            return "B"
        elif avg_points >= 1.5:
            return "C"
        elif avg_points >= 0.5:
            return "D"
        else:
            return "F"
    
    def _calculate_statistical_confidence(self, sample_size: int) -> float:
        """
        Calculate statistical confidence level based on sample size.
        
        Args:
            sample_size: Total number of samples
            
        Returns:
            Statistical confidence level as percentage (0-100)
        """
        if sample_size >= 10000:
            return 99.0
        elif sample_size >= 5000:
            return 95.0
        elif sample_size >= 1000:
            return 90.0
        elif sample_size >= 500:
            return 85.0
        elif sample_size >= 100:
            return 75.0
        else:
            return 50.0
    
    def _calculate_test_reliability(self, test_result: TestResultSummary) -> float:
        """
        Calculate test reliability score based on various factors.
        
        Args:
            test_result: Test result summary to evaluate
            
        Returns:
            Test reliability score (0-100)
        """
        reliability_score = 100.0
        
        # Penalize for low sample size
        if test_result.sample_size < 100:
            reliability_score -= 30.0
        elif test_result.sample_size < 500:
            reliability_score -= 15.0
        elif test_result.sample_size < 1000:
            reliability_score -= 5.0
        
        # Penalize for high error rate
        error_rate = test_result.error_metrics.get('overall_error_rate', 0)
        if error_rate > 5.0:
            reliability_score -= 40.0
        elif error_rate > 1.0:
            reliability_score -= 20.0
        elif error_rate > 0.5:
            reliability_score -= 10.0
        
        # Penalize for short test duration
        if test_result.test_duration_seconds < 60:
            reliability_score -= 20.0
        elif test_result.test_duration_seconds < 300:
            reliability_score -= 10.0
        
        return max(0.0, reliability_score)
    
    def _flatten_throughput_data(self, throughput_data: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
        """
        Flatten throughput data dictionary for easier access.
        
        Args:
            throughput_data: Nested throughput data dictionary
            
        Returns:
            Flattened throughput metrics dictionary
        """
        flattened = {}
        
        # Calculate overall metrics
        total_requests = sum(data.get('total_requests', 0) for data in throughput_data.values())
        total_successful = sum(data.get('successful_requests', 0) for data in throughput_data.values())
        total_failed = sum(data.get('failed_requests', 0) for data in throughput_data.values())
        total_rps = sum(data.get('requests_per_second', 0) for data in throughput_data.values())
        
        flattened.update({
            'total_requests': total_requests,
            'successful_requests': total_successful,
            'failed_requests': total_failed,
            'requests_per_second': total_rps,
            'success_rate': (total_successful / total_requests * 100) if total_requests > 0 else 0
        })
        
        return flattened
    
    def _flatten_error_data(self, error_data: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
        """
        Flatten error data dictionary for easier access.
        
        Args:
            error_data: Nested error data dictionary
            
        Returns:
            Flattened error metrics dictionary
        """
        flattened = {}
        
        # Calculate overall error metrics
        error_rates = [data.get('error_rate_percent', 0) for data in error_data.values()]
        total_failures = sum(data.get('total_failures', 0) for data in error_data.values())
        
        if error_rates:
            flattened.update({
                'overall_error_rate': statistics.mean(error_rates),
                'max_error_rate': max(error_rates),
                'min_error_rate': min(error_rates),
                'total_failures': total_failures
            })
        
        return flattened
    
    def _analyze_performance_trends(self, test_results: List[TestResultSummary]) -> Dict[str, Any]:
        """
        Analyze performance trends across multiple test results.
        
        Args:
            test_results: List of test result summaries
            
        Returns:
            Dictionary containing trend analysis results
        """
        if len(test_results) < 2:
            return {}
        
        # Sort by timestamp
        sorted_results = sorted(test_results, key=lambda x: x.test_timestamp)
        
        trend_analysis = {}
        
        # Analyze response time trends
        response_time_trends = defaultdict(list)
        for result in sorted_results:
            for endpoint, metrics in result.response_time_metrics.items():
                avg_time = metrics.get('avg_ms') or metrics.get('mean_ms', 0)
                response_time_trends[endpoint].append(avg_time)
        
        for endpoint, times in response_time_trends.items():
            if len(times) >= 2:
                trend_direction = "improving" if times[-1] < times[0] else "degrading" if times[-1] > times[0] else "stable"
                trend_analysis[f"{endpoint}_response_time_trend"] = {
                    'direction': trend_direction,
                    'change_percent': ((times[-1] - times[0]) / times[0] * 100) if times[0] > 0 else 0,
                    'values': times
                }
        
        # Analyze throughput trends
        throughput_values = []
        for result in sorted_results:
            rps = result.throughput_metrics.get('requests_per_second', 0)
            throughput_values.append(rps)
        
        if len(throughput_values) >= 2:
            trend_direction = "improving" if throughput_values[-1] > throughput_values[0] else "degrading" if throughput_values[-1] < throughput_values[0] else "stable"
            trend_analysis['throughput_trend'] = {
                'direction': trend_direction,
                'change_percent': ((throughput_values[-1] - throughput_values[0]) / throughput_values[0] * 100) if throughput_values[0] > 0 else 0,
                'values': throughput_values
            }
        
        return trend_analysis
    
    def _detect_performance_outliers(
        self,
        variances: List[float],
        response_times: List[float]
    ) -> Dict[str, Any]:
        """
        Detect performance outliers using statistical analysis.
        
        Args:
            variances: List of variance values
            response_times: List of response time values
            
        Returns:
            Dictionary containing outlier detection results
        """
        outlier_detection = {}
        
        if variances:
            # Detect variance outliers using IQR method
            q1 = statistics.quantiles(variances, n=4)[0]
            q3 = statistics.quantiles(variances, n=4)[2]
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            variance_outliers = [v for v in variances if v < lower_bound or v > upper_bound]
            outlier_detection['variance_outliers'] = {
                'count': len(variance_outliers),
                'values': variance_outliers,
                'outlier_percentage': (len(variance_outliers) / len(variances)) * 100
            }
        
        if response_times:
            # Detect response time outliers
            mean_rt = statistics.mean(response_times)
            std_rt = statistics.stdev(response_times) if len(response_times) > 1 else 0
            
            rt_outliers = [rt for rt in response_times if abs(rt - mean_rt) > 2 * std_rt]
            outlier_detection['response_time_outliers'] = {
                'count': len(rt_outliers),
                'values': rt_outliers,
                'outlier_percentage': (len(rt_outliers) / len(response_times)) * 100
            }
        
        return outlier_detection
    
    def _generate_performance_charts(
        self,
        report_data: Dict[str, Any],
        config: ReportConfiguration
    ) -> Dict[str, str]:
        """
        Generate performance visualization charts for HTML reports.
        
        Args:
            report_data: Comprehensive report data
            config: Report configuration parameters
            
        Returns:
            Dictionary mapping chart names to base64 encoded chart images
        """
        if not VISUALIZATION_AVAILABLE:
            return {}
        
        charts = {}
        
        try:
            # Chart 1: Variance Distribution
            variance_data = []
            test_results = report_data.get('test_results', [])
            
            for result in test_results:
                for variance in result.get('variance_analysis', {}).values():
                    if isinstance(variance, (int, float)) and not math.isinf(variance):
                        variance_data.append(abs(variance))
            
            if variance_data:
                plt.figure(figsize=(10, 6))
                plt.hist(variance_data, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
                plt.axvline(x=config.variance_threshold, color='red', linestyle='--', 
                           label=f'Threshold ({config.variance_threshold}%)')
                plt.xlabel('Variance Percentage (%)')
                plt.ylabel('Frequency')
                plt.title('Performance Variance Distribution')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                charts['variance_distribution'] = self._chart_to_base64()
                plt.close()
            
            # Chart 2: Response Time Comparison
            if test_results:
                endpoints = set()
                for result in test_results:
                    endpoints.update(result.get('response_time_metrics', {}).keys())
                
                if endpoints:
                    plt.figure(figsize=(12, 8))
                    endpoint_list = list(endpoints)[:10]  # Limit to top 10 endpoints
                    
                    for i, endpoint in enumerate(endpoint_list):
                        current_times = []
                        baseline_times = []
                        
                        for result in test_results:
                            metrics = result.get('response_time_metrics', {}).get(endpoint, {})
                            current_avg = metrics.get('avg_ms') or metrics.get('mean_ms', 0)
                            if current_avg > 0:
                                current_times.append(current_avg)
                        
                        if current_times:
                            plt.bar(i, statistics.mean(current_times), alpha=0.7, 
                                   label=endpoint if len(endpoint) < 30 else endpoint[:27] + '...')
                    
                    plt.xlabel('Endpoints')
                    plt.ylabel('Average Response Time (ms)')
                    plt.title('Response Time by Endpoint')
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    
                    charts['response_time_comparison'] = self._chart_to_base64()
                    plt.close()
            
            # Chart 3: Performance Trend (if trend analysis available)
            analysis = report_data.get('performance_analysis', {})
            trend_data = analysis.get('trend_analysis', {})
            
            if trend_data:
                plt.figure(figsize=(12, 6))
                
                for metric_name, trend_info in trend_data.items():
                    if 'values' in trend_info and len(trend_info['values']) > 1:
                        x_values = list(range(len(trend_info['values'])))
                        plt.plot(x_values, trend_info['values'], marker='o', 
                                label=metric_name.replace('_', ' ').title())
                
                plt.xlabel('Test Sequence')
                plt.ylabel('Performance Metric Value')
                plt.title('Performance Trends Over Time')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                charts['performance_trends'] = self._chart_to_base64()
                plt.close()
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning(
                    "Failed to generate performance charts",
                    error=str(e)
                )
        
        return charts
    
    def _chart_to_base64(self) -> str:
        """
        Convert current matplotlib figure to base64 encoded string.
        
        Returns:
            Base64 encoded chart image string
        """
        import io
        import base64
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.read()).decode('utf-8')
        buffer.close()
        
        return f"data:image/png;base64,{chart_data}"
    
    def _get_base_html_template(self) -> str:
        """Get base HTML template for report generation."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>{{ css_styles }}</style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <h1>{{ metadata.title }}</h1>
            <p class="subtitle">{{ metadata.description }}</p>
            <div class="metadata">
                <p><strong>Generated:</strong> {{ metadata.generated_at }}</p>
                <p><strong>Target Audience:</strong> {{ metadata.target_audience.title() }}</p>
                <p><strong>Version:</strong> {{ metadata.report_version }}</p>
            </div>
        </header>

        {% if config.include_executive_summary %}
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-cards">
                <div class="card {% if executive_summary.overall_compliance %}success{% else %}error{% endif %}">
                    <h3>Overall Compliance</h3>
                    <p class="value">{{ "✅ PASS" if executive_summary.overall_compliance else "❌ FAIL" }}</p>
                </div>
                <div class="card">
                    <h3>Performance Grade</h3>
                    <p class="value grade-{{ executive_summary.performance_grade.lower() }}">{{ executive_summary.performance_grade }}</p>
                </div>
                <div class="card">
                    <h3>Tests Executed</h3>
                    <p class="value">{{ executive_summary.total_tests }}</p>
                </div>
                <div class="card {% if executive_summary.critical_issues == 0 %}success{% else %}error{% endif %}">
                    <h3>Critical Issues</h3>
                    <p class="value">{{ executive_summary.critical_issues }}</p>
                </div>
            </div>
        </section>
        {% endif %}

        {% if config.include_baseline_comparison %}
        <section class="baseline-comparison">
            <h2>Baseline Comparison</h2>
            <p><strong>Node.js Version:</strong> {{ baseline_comparison.nodejs_baseline.version }}</p>
            <p><strong>Express Version:</strong> {{ baseline_comparison.nodejs_baseline.express_version }}</p>
            <p><strong>Variance Threshold:</strong> ±{{ baseline_comparison.variance_threshold }}%</p>
        </section>
        {% endif %}

        {% if config.include_charts and charts %}
        <section class="performance-charts">
            <h2>Performance Analysis Charts</h2>
            {% for chart_name, chart_data in charts.items() %}
            <div class="chart-container">
                <h3>{{ chart_name.replace('_', ' ').title() }}</h3>
                <img src="{{ chart_data }}" alt="{{ chart_name }}" class="chart-image">
            </div>
            {% endfor %}
        </section>
        {% endif %}

        {% if config.include_issue_analysis and issues %}
        <section class="issues-analysis">
            <h2>Detected Issues</h2>
            {% for issue in issues %}
            <div class="issue-card severity-{{ issue.severity }}">
                <h3>{{ issue.title }}</h3>
                <p><strong>Severity:</strong> {{ issue.severity.upper() }}</p>
                <p><strong>Description:</strong> {{ issue.description }}</p>
                {% if issue.current_value and issue.baseline_value %}
                <p><strong>Current:</strong> {{ "%.2f"|format(issue.current_value) }} | <strong>Baseline:</strong> {{ "%.2f"|format(issue.baseline_value) }} | <strong>Variance:</strong> {{ "%.2f"|format(issue.variance_percent) }}%</p>
                {% endif %}
                <p><strong>Impact:</strong> {{ issue.impact_assessment }}</p>
                <p><strong>Recommendation:</strong> {{ issue.recommendation }}</p>
            </div>
            {% endfor %}
        </section>
        {% endif %}

        {% if config.include_recommendations and recommendations %}
        <section class="recommendations">
            <h2>Performance Recommendations</h2>
            <ul>
                {% for recommendation in recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </section>
        {% endif %}

        <footer class="report-footer">
            <p>Generated by {{ metadata.generated_by }} at {{ metadata.generated_at }}</p>
        </footer>
    </div>

    <script>{{ javascript }}</script>
</body>
</html>
        '''
    
    def _get_executive_summary_template(self) -> str:
        """Get executive summary template."""
        return '''
<div class="executive-summary">
    <!-- Executive summary content -->
</div>
        '''
    
    def _get_technical_details_template(self) -> str:
        """Get technical details template."""
        return '''
<div class="technical-details">
    <!-- Technical details content -->
</div>
        '''
    
    def _get_performance_charts_template(self) -> str:
        """Get performance charts template."""
        return '''
<div class="performance-charts">
    <!-- Charts content -->
</div>
        '''
    
    def _get_issue_analysis_template(self) -> str:
        """Get issue analysis template."""
        return '''
<div class="issue-analysis">
    <!-- Issue analysis content -->
</div>
        '''
    
    def _get_recommendations_template(self) -> str:
        """Get recommendations template."""
        return '''
<div class="recommendations">
    <!-- Recommendations content -->
</div>
        '''
    
    def _get_report_css_styles(self, config: ReportConfiguration) -> str:
        """Get CSS styles for HTML report."""
        return '''
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        .report-header {
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .report-header h1 {
            color: #007bff;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        
        .metadata {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
            font-size: 0.9em;
            color: #777;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .card.success {
            background: #d4edda;
            border-color: #c3e6cb;
        }
        
        .card.error {
            background: #f8d7da;
            border-color: #f5c6cb;
        }
        
        .card h3 {
            margin: 0 0 10px 0;
            color: #495057;
        }
        
        .card .value {
            font-size: 1.5em;
            font-weight: bold;
            margin: 0;
        }
        
        .grade-a { color: #28a745; }
        .grade-b { color: #17a2b8; }
        .grade-c { color: #ffc107; }
        .grade-d { color: #fd7e14; }
        .grade-f { color: #dc3545; }
        
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        
        .chart-image {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        
        .issue-card {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #007bff;
        }
        
        .issue-card.severity-critical {
            border-left-color: #dc3545;
            background: #fdf2f2;
        }
        
        .issue-card.severity-high {
            border-left-color: #fd7e14;
            background: #fef8f3;
        }
        
        .issue-card.severity-medium {
            border-left-color: #ffc107;
            background: #fffdf3;
        }
        
        .issue-card.severity-low {
            border-left-color: #17a2b8;
            background: #f3fbfd;
        }
        
        .recommendations ul {
            list-style-type: none;
            padding: 0;
        }
        
        .recommendations li {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px 15px;
            margin: 8px 0;
        }
        
        .report-footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #777;
            font-size: 0.9em;
        }
        
        section {
            margin: 30px 0;
        }
        
        section h2 {
            color: #007bff;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 10px;
        }
        
        @media (max-width: 768px) {
            .metadata {
                flex-direction: column;
                gap: 10px;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
        '''
    
    def _get_report_javascript(self) -> str:
        """Get JavaScript for interactive HTML report features."""
        return '''
        // Interactive features for performance reports
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for expandable sections
            const sections = document.querySelectorAll('section h2');
            sections.forEach(function(header) {
                header.style.cursor = 'pointer';
                header.addEventListener('click', function() {
                    const content = header.nextElementSibling;
                    if (content.style.display === 'none') {
                        content.style.display = 'block';
                        header.textContent = header.textContent.replace('▶', '▼');
                    } else {
                        content.style.display = 'none';
                        header.textContent = '▶ ' + header.textContent.replace('▼ ', '');
                    }
                });
            });
            
            // Add tooltips for grade explanations
            const gradeElements = document.querySelectorAll('[class*="grade-"]');
            gradeElements.forEach(function(element) {
                const grade = element.textContent.trim();
                let tooltip = '';
                
                switch(grade) {
                    case 'A':
                        tooltip = 'Excellent: ≤2% variance, >95% compliance';
                        break;
                    case 'B':
                        tooltip = 'Good: ≤5% variance, >90% compliance';
                        break;
                    case 'C':
                        tooltip = 'Acceptable: ≤10% variance, >80% compliance';
                        break;
                    case 'D':
                        tooltip = 'Poor: ≤15% variance, >70% compliance';
                        break;
                    case 'F':
                        tooltip = 'Failing: >15% variance or <70% compliance';
                        break;
                }
                
                if (tooltip) {
                    element.title = tooltip;
                }
            });
        });
        '''


# Export public interface
__all__ = [
    # Core classes
    'PerformanceReportGenerator',
    'TestResultSummary',
    'PerformanceIssue',
    'ReportConfiguration',
    
    # Enumerations
    'ReportFormat',
    'StakeholderType',
    'ReportSeverity',
    'PerformanceIssueType'
]