"""
Performance Report Templates and Formatting Utilities Module

This module provides comprehensive performance report templates and formatting utilities
for the Flask migration project, implementing standardized report layouts, visualization
templates, and multi-format export configurations per technical specification requirements.

Key Features:
- Standardized report template library per Section 0.3.4 documentation requirements
- Multi-format export capabilities (HTML, PDF, JSON) per Section 0.3.4
- Visualization template library for charts and graphs per Section 6.5.1.5 dashboard design
- Consistent branding and formatting standards per Section 0.3.4 documentation requirements
- Responsive template design for different devices per Section 0.3.4
- Template customization for different stakeholder audiences per Section 0.3.4

Architecture Integration:
- Section 0.3.4: Comprehensive documentation updates with multi-format export and responsive design
- Section 6.5.1.5: Dashboard design with visualization templates and stakeholder-specific views
- Section 0.1.1: ≤10% variance requirement integration in all report templates
- Section 6.6.3: Quality metrics documentation with consistent reporting standards
- Section 6.5.5: Improvement tracking with trend visualization and analysis templates

Author: Flask Migration Team
Version: 1.0.0
Dependencies: Jinja2 ≥3.x, matplotlib ≥3.7+, plotly ≥5.15+, weasyprint ≥60+
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import statistics
import tempfile
import logging

# Template engine and visualization dependencies
try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend for report generation
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.figure import Figure
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.io as pio
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

# Performance configuration dependency
from tests.performance.performance_config import (
    BasePerformanceConfig,
    PerformanceConfigFactory,
    PerformanceThreshold,
    BaselineMetrics,
    PerformanceTestType,
    PerformanceEnvironment
)


class ReportFormat(Enum):
    """Report format enumeration for export capabilities."""
    
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"
    CSV = "csv"
    XLSX = "xlsx"


class ReportAudience(Enum):
    """Report audience enumeration for stakeholder-specific customization."""
    
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    OPERATIONS = "operations"
    PERFORMANCE_TEAM = "performance_team"
    DEVELOPMENT = "development"
    QA_TESTING = "qa_testing"
    COMPLIANCE = "compliance"


class ReportTheme(Enum):
    """Report theme enumeration for visual customization."""
    
    CORPORATE = "corporate"
    TECHNICAL = "technical"
    MINIMAL = "minimal"
    DASHBOARD = "dashboard"
    EXECUTIVE = "executive"
    COMPLIANCE = "compliance"


class ChartType(Enum):
    """Chart type enumeration for visualization templates."""
    
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    AREA_CHART = "area_chart"
    SCATTER_PLOT = "scatter_plot"
    PIE_CHART = "pie_chart"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"
    HEATMAP = "heatmap"
    GAUGE_CHART = "gauge_chart"
    TIMELINE = "timeline"


@dataclass
class ReportBranding:
    """Report branding configuration for consistent visual identity."""
    
    company_name: str = "Flask Migration Project"
    logo_path: Optional[str] = None
    logo_base64: Optional[str] = None
    primary_color: str = "#1f77b4"
    secondary_color: str = "#ff7f0e"
    accent_color: str = "#2ca02c"
    warning_color: str = "#ff7f0e"
    danger_color: str = "#d62728"
    success_color: str = "#2ca02c"
    
    # Typography settings
    font_family: str = "Arial, sans-serif"
    title_font_size: str = "24px"
    heading_font_size: str = "18px"
    body_font_size: str = "14px"
    small_font_size: str = "12px"
    
    # Layout settings
    page_margin: str = "20px"
    content_width: str = "100%"
    section_spacing: str = "30px"
    
    def get_color_palette(self) -> List[str]:
        """
        Get standardized color palette for charts and visualizations.
        
        Returns:
            List of hex color codes for consistent visualization styling
        """
        return [
            self.primary_color,
            self.secondary_color,
            self.accent_color,
            "#9467bd",
            "#8c564b",
            "#e377c2",
            "#7f7f7f",
            "#bcbd22",
            "#17becf"
        ]
    
    def get_status_colors(self) -> Dict[str, str]:
        """
        Get status-specific color mapping for performance indicators.
        
        Returns:
            Dictionary mapping status types to color codes
        """
        return {
            "ok": self.success_color,
            "warning": self.warning_color,
            "critical": self.danger_color,
            "failure": self.danger_color,
            "pass": self.success_color,
            "fail": self.danger_color,
            "within_threshold": self.success_color,
            "above_threshold": self.danger_color
        }


@dataclass
class ChartConfiguration:
    """Chart configuration for visualization templates."""
    
    chart_type: ChartType
    title: str
    width: int = 800
    height: int = 400
    show_legend: bool = True
    responsive: bool = True
    
    # Axis configuration
    x_axis_title: Optional[str] = None
    y_axis_title: Optional[str] = None
    x_axis_format: Optional[str] = None
    y_axis_format: Optional[str] = None
    
    # Data configuration
    data_labels: bool = False
    grid_lines: bool = True
    animation: bool = False
    
    # Styling
    color_palette: Optional[List[str]] = None
    background_color: str = "#ffffff"
    plot_background_color: str = "#fafafa"
    
    def to_plotly_config(self) -> Dict[str, Any]:
        """
        Convert chart configuration to Plotly-compatible configuration.
        
        Returns:
            Dictionary of Plotly configuration parameters
        """
        config = {
            "displayModeBar": True,
            "displaylogo": False,
            "modeBarButtonsToRemove": ["pan2d", "lasso2d", "select2d"],
            "responsive": self.responsive,
            "toImageButtonOptions": {
                "format": "png",
                "filename": f"chart_{self.title.lower().replace(' ', '_')}",
                "height": self.height,
                "width": self.width,
                "scale": 2
            }
        }
        
        return config
    
    def to_matplotlib_config(self) -> Dict[str, Any]:
        """
        Convert chart configuration to Matplotlib-compatible configuration.
        
        Returns:
            Dictionary of Matplotlib configuration parameters
        """
        return {
            "figsize": (self.width / 100, self.height / 100),
            "facecolor": self.background_color,
            "edgecolor": "none",
            "dpi": 100
        }


@dataclass
class ReportMetadata:
    """Report metadata for comprehensive documentation and tracking."""
    
    report_id: str
    title: str
    description: str
    generated_at: datetime
    generated_by: str = "Flask Migration Performance System"
    version: str = "1.0.0"
    
    # Report configuration
    format: ReportFormat = ReportFormat.HTML
    audience: ReportAudience = ReportAudience.TECHNICAL
    theme: ReportTheme = ReportTheme.TECHNICAL
    
    # Data source information
    data_sources: List[str] = field(default_factory=list)
    baseline_date: Optional[datetime] = None
    test_environment: str = "development"
    
    # Performance context
    variance_threshold: float = 0.10  # 10% variance threshold per Section 0.1.1
    baseline_type: str = "nodejs"
    
    # Security and compliance
    classification: str = "internal"
    retention_period_days: int = 365
    
    def generate_report_id(self) -> str:
        """
        Generate unique report identifier with timestamp and content hash.
        
        Returns:
            Unique report identifier string
        """
        timestamp = self.generated_at.strftime("%Y%m%d_%H%M%S")
        content_hash = hashlib.md5(
            f"{self.title}_{self.audience.value}_{timestamp}".encode()
        ).hexdigest()[:8]
        
        return f"perf_report_{timestamp}_{content_hash}"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metadata to dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of report metadata
        """
        return {
            "report_id": self.report_id,
            "title": self.title,
            "description": self.description,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "version": self.version,
            "format": self.format.value,
            "audience": self.audience.value,
            "theme": self.theme.value,
            "data_sources": self.data_sources,
            "baseline_date": self.baseline_date.isoformat() if self.baseline_date else None,
            "test_environment": self.test_environment,
            "variance_threshold": self.variance_threshold,
            "baseline_type": self.baseline_type,
            "classification": self.classification,
            "retention_period_days": self.retention_period_days
        }


class PerformanceReportTemplate:
    """
    Base performance report template providing standardized structure and formatting.
    
    Implements comprehensive report template functionality with multi-format export
    capabilities, responsive design, and stakeholder-specific customization per
    technical specification requirements.
    """
    
    def __init__(
        self,
        metadata: ReportMetadata,
        branding: Optional[ReportBranding] = None,
        config: Optional[BasePerformanceConfig] = None
    ):
        """
        Initialize performance report template.
        
        Args:
            metadata: Report metadata and configuration
            branding: Visual branding configuration
            config: Performance testing configuration
        """
        self.metadata = metadata
        self.branding = branding or ReportBranding()
        self.config = config or PerformanceConfigFactory.get_config()
        
        # Template engine setup
        self.jinja_env = self._setup_jinja_environment()
        
        # Chart configuration
        self.default_chart_config = ChartConfiguration(
            chart_type=ChartType.LINE_CHART,
            title="Performance Chart",
            color_palette=self.branding.get_color_palette()
        )
        
        # Report sections
        self.sections: List[Dict[str, Any]] = []
        self.charts: List[Dict[str, Any]] = []
        
        # Performance data
        self.performance_data: Dict[str, Any] = {}
        self.baseline_data: Dict[str, Any] = {}
        self.variance_analysis: Dict[str, Any] = {}
    
    def _setup_jinja_environment(self) -> Optional[jinja2.Environment]:
        """
        Setup Jinja2 template environment with custom filters and functions.
        
        Returns:
            Configured Jinja2 environment or None if unavailable
        """
        if not JINJA2_AVAILABLE:
            return None
        
        # Template loader for embedded templates
        loader = jinja2.DictLoader(self._get_embedded_templates())
        env = jinja2.Environment(
            loader=loader,
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Custom filters
        env.filters['format_percentage'] = self._format_percentage
        env.filters['format_duration'] = self._format_duration
        env.filters['format_timestamp'] = self._format_timestamp
        env.filters['status_color'] = self._get_status_color
        env.filters['format_number'] = self._format_number
        
        # Custom functions
        env.globals['get_variance_status'] = self._get_variance_status
        env.globals['calculate_trend'] = self._calculate_trend
        env.globals['get_recommendation'] = self._get_recommendation
        
        return env
    
    def _get_embedded_templates(self) -> Dict[str, str]:
        """
        Get embedded HTML templates for different report types and audiences.
        
        Returns:
            Dictionary of template names to template content
        """
        templates = {}
        
        # Base template
        templates['base.html'] = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }}</title>
    <style>
        {{ css_styles }}
    </style>
    {% if plotly_available %}
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    {% endif %}
</head>
<body>
    <div class="container">
        {% block header %}
        <header class="report-header">
            {% if branding.logo_base64 %}
            <img src="data:image/png;base64,{{ branding.logo_base64 }}" 
                 alt="{{ branding.company_name }}" class="logo">
            {% endif %}
            <h1>{{ metadata.title }}</h1>
            <div class="report-info">
                <span class="generated-date">Generated: {{ metadata.generated_at | format_timestamp }}</span>
                <span class="environment">Environment: {{ metadata.test_environment }}</span>
                <span class="audience">Audience: {{ metadata.audience.value.title() }}</span>
            </div>
        </header>
        {% endblock %}
        
        {% block summary %}
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            {{ summary_content | safe }}
        </section>
        {% endblock %}
        
        {% block content %}
        {% for section in sections %}
        <section class="report-section" id="{{ section.id }}">
            <h2>{{ section.title }}</h2>
            {% if section.description %}
            <p class="section-description">{{ section.description }}</p>
            {% endif %}
            {{ section.content | safe }}
        </section>
        {% endfor %}
        {% endblock %}
        
        {% block charts %}
        {% if charts %}
        <section class="charts-section">
            <h2>Performance Visualizations</h2>
            {% for chart in charts %}
            <div class="chart-container" id="chart-{{ chart.id }}">
                <h3>{{ chart.title }}</h3>
                {{ chart.content | safe }}
            </div>
            {% endfor %}
        </section>
        {% endif %}
        {% endblock %}
        
        {% block footer %}
        <footer class="report-footer">
            <div class="footer-info">
                <span>{{ branding.company_name }}</span>
                <span>Report ID: {{ metadata.report_id }}</span>
                <span>Version: {{ metadata.version }}</span>
            </div>
            <div class="disclaimer">
                <p>This report contains performance data for the Flask migration project.
                   All metrics are compared against Node.js baseline with ≤10% variance threshold.</p>
            </div>
        </footer>
        {% endblock %}
    </div>
    
    {% block scripts %}
    <script>
        // Chart interactivity and responsive behavior
        function resizeCharts() {
            if (typeof Plotly !== 'undefined') {
                Plotly.Plots.resize(document.querySelectorAll('.plotly-graph-div'));
            }
        }
        
        window.addEventListener('resize', resizeCharts);
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize tooltips and interactive elements
            const statusElements = document.querySelectorAll('.status-indicator');
            statusElements.forEach(el => {
                el.addEventListener('click', function() {
                    alert(this.getAttribute('data-details'));
                });
            });
        });
    </script>
    {% endblock %}
</body>
</html>
        '''
        
        # Executive template
        templates['executive.html'] = '''
{% extends "base.html" %}

{% block summary %}
<section class="executive-summary">
    <h2>Performance Migration Summary</h2>
    
    <div class="kpi-grid">
        <div class="kpi-card {{ 'success' if performance_summary.within_threshold else 'failure' }}">
            <h3>Performance Variance</h3>
            <div class="kpi-value">{{ performance_summary.variance_percentage | format_percentage }}</div>
            <div class="kpi-target">Target: ≤10%</div>
            <div class="kpi-status">{{ get_variance_status(performance_summary.variance_percentage) }}</div>
        </div>
        
        <div class="kpi-card">
            <h3>Response Time</h3>
            <div class="kpi-value">{{ performance_summary.avg_response_time }}ms</div>
            <div class="kpi-baseline">Baseline: {{ baseline_summary.avg_response_time }}ms</div>
            <div class="kpi-trend">{{ calculate_trend(performance_summary.response_time_trend) }}</div>
        </div>
        
        <div class="kpi-card">
            <h3>Throughput</h3>
            <div class="kpi-value">{{ performance_summary.requests_per_second }} req/s</div>
            <div class="kpi-baseline">Baseline: {{ baseline_summary.requests_per_second }} req/s</div>
            <div class="kpi-trend">{{ calculate_trend(performance_summary.throughput_trend) }}</div>
        </div>
        
        <div class="kpi-card">
            <h3>Error Rate</h3>
            <div class="kpi-value">{{ performance_summary.error_rate | format_percentage }}</div>
            <div class="kpi-target">Target: ≤0.1%</div>
            <div class="kpi-status">{{ 'success' if performance_summary.error_rate <= 0.001 else 'warning' }}</div>
        </div>
    </div>
    
    <div class="recommendations">
        <h3>Key Recommendations</h3>
        <ul>
        {% for recommendation in recommendations[:3] %}
            <li class="recommendation-item priority-{{ recommendation.priority }}">
                <strong>{{ recommendation.title }}</strong>: {{ recommendation.description }}
            </li>
        {% endfor %}
        </ul>
    </div>
</section>
{% endblock %}
        '''
        
        # Technical template
        templates['technical.html'] = '''
{% extends "base.html" %}

{% block content %}
<section class="technical-metrics">
    <h2>Detailed Performance Analysis</h2>
    
    <div class="metrics-grid">
        {% for metric_name, metric_data in detailed_metrics.items() %}
        <div class="metric-card">
            <h3>{{ metric_name.replace('_', ' ').title() }}</h3>
            <div class="metric-values">
                <div class="current-value">
                    <label>Current:</label>
                    <span class="value">{{ metric_data.current_value }}{{ metric_data.unit }}</span>
                </div>
                <div class="baseline-value">
                    <label>Baseline:</label>
                    <span class="value">{{ metric_data.baseline_value }}{{ metric_data.unit }}</span>
                </div>
                <div class="variance {{ metric_data.status }}">
                    <label>Variance:</label>
                    <span class="value">{{ metric_data.variance_percent | format_percentage }}</span>
                </div>
            </div>
            <div class="metric-status status-{{ metric_data.status }}">
                {{ metric_data.status.upper() }}
            </div>
        </div>
        {% endfor %}
    </div>
    
    <div class="detailed-analysis">
        <h3>Statistical Analysis</h3>
        <table class="metrics-table">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Mean</th>
                    <th>Median</th>
                    <th>95th Percentile</th>
                    <th>99th Percentile</th>
                    <th>Standard Deviation</th>
                    <th>Variance Status</th>
                </tr>
            </thead>
            <tbody>
            {% for metric_name, stats in statistical_analysis.items() %}
                <tr class="metric-row status-{{ stats.status }}">
                    <td>{{ metric_name.replace('_', ' ').title() }}</td>
                    <td>{{ stats.mean | format_number }}{{ stats.unit }}</td>
                    <td>{{ stats.median | format_number }}{{ stats.unit }}</td>
                    <td>{{ stats.p95 | format_number }}{{ stats.unit }}</td>
                    <td>{{ stats.p99 | format_number }}{{ stats.unit }}</td>
                    <td>{{ stats.std_dev | format_number }}{{ stats.unit }}</td>
                    <td class="status-indicator status-{{ stats.status }}" 
                        data-details="{{ stats.details }}">
                        {{ stats.status.upper() }}
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</section>
{% endblock %}
        '''
        
        return templates
    
    def _get_css_styles(self, theme: ReportTheme = None) -> str:
        """
        Generate CSS styles for report templates based on theme and branding.
        
        Args:
            theme: Report theme for styling customization
            
        Returns:
            CSS stylesheet string
        """
        theme = theme or self.metadata.theme
        branding = self.branding
        
        # Base styles
        css = f'''
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: {branding.font_family};
            font-size: {branding.body_font_size};
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: {branding.page_margin};
            background-color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        
        .report-header {{
            border-bottom: 3px solid {branding.primary_color};
            padding-bottom: 20px;
            margin-bottom: {branding.section_spacing};
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        
        .logo {{
            max-height: 60px;
            margin-right: 20px;
        }}
        
        h1 {{
            font-size: {branding.title_font_size};
            color: {branding.primary_color};
            margin-bottom: 10px;
        }}
        
        h2 {{
            font-size: {branding.heading_font_size};
            color: {branding.secondary_color};
            margin-bottom: 15px;
            border-left: 4px solid {branding.accent_color};
            padding-left: 15px;
        }}
        
        h3 {{
            font-size: 16px;
            color: #333;
            margin-bottom: 10px;
        }}
        
        .report-info {{
            display: flex;
            flex-direction: column;
            gap: 5px;
            font-size: {branding.small_font_size};
            color: #666;
        }}
        
        .report-section {{
            margin-bottom: {branding.section_spacing};
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background-color: #fdfdfd;
        }}
        
        .section-description {{
            color: #666;
            margin-bottom: 20px;
            font-style: italic;
        }}
        
        /* KPI Grid for Executive Summary */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .kpi-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .kpi-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        
        .kpi-card.success {{
            border-left: 5px solid {branding.success_color};
        }}
        
        .kpi-card.warning {{
            border-left: 5px solid {branding.warning_color};
        }}
        
        .kpi-card.failure {{
            border-left: 5px solid {branding.danger_color};
        }}
        
        .kpi-value {{
            font-size: 2em;
            font-weight: bold;
            color: {branding.primary_color};
            margin: 10px 0;
        }}
        
        .kpi-target, .kpi-baseline {{
            color: #666;
            font-size: {branding.small_font_size};
        }}
        
        .kpi-status {{
            font-weight: bold;
            text-transform: uppercase;
            font-size: {branding.small_font_size};
        }}
        
        .kpi-trend {{
            font-size: {branding.small_font_size};
            color: #666;
        }}
        
        /* Metrics Grid for Technical Reports */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .metric-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .metric-values {{
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin: 15px 0;
        }}
        
        .metric-values > div {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .metric-values label {{
            font-weight: bold;
            color: #666;
        }}
        
        .metric-values .value {{
            font-family: 'Courier New', monospace;
            color: #333;
        }}
        
        .metric-status {{
            text-align: center;
            padding: 8px;
            border-radius: 4px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: {branding.small_font_size};
        }}
        
        .status-ok, .status-success {{
            background-color: {branding.success_color};
            color: white;
        }}
        
        .status-warning {{
            background-color: {branding.warning_color};
            color: white;
        }}
        
        .status-critical, .status-failure {{
            background-color: {branding.danger_color};
            color: white;
        }}
        
        /* Tables */
        .metrics-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: {branding.small_font_size};
        }}
        
        .metrics-table th,
        .metrics-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .metrics-table th {{
            background-color: {branding.primary_color};
            color: white;
            font-weight: bold;
        }}
        
        .metrics-table tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        
        .metrics-table tr:hover {{
            background-color: #e8f4f8;
        }}
        
        .status-indicator {{
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            min-width: 60px;
            text-align: center;
        }}
        
        /* Charts */
        .charts-section {{
            margin-top: 40px;
        }}
        
        .chart-container {{
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background-color: white;
        }}
        
        .chart-container h3 {{
            margin-bottom: 15px;
            color: {branding.primary_color};
        }}
        
        /* Recommendations */
        .recommendations {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid {branding.accent_color};
        }}
        
        .recommendation-item {{
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 4px;
        }}
        
        .recommendation-item.priority-high {{
            background-color: #fff3cd;
            border-left: 3px solid {branding.warning_color};
        }}
        
        .recommendation-item.priority-medium {{
            background-color: #d4edda;
            border-left: 3px solid {branding.success_color};
        }}
        
        .recommendation-item.priority-low {{
            background-color: #d1ecf1;
            border-left: 3px solid {branding.primary_color};
        }}
        
        /* Footer */
        .report-footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid {branding.primary_color};
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            font-size: {branding.small_font_size};
            color: #666;
        }}
        
        .footer-info {{
            display: flex;
            gap: 20px;
        }}
        
        .disclaimer {{
            max-width: 400px;
            text-align: right;
        }}
        
        /* Responsive Design */
        @media (max-width: 768px) {{
            .container {{
                margin: 0;
                padding: 10px;
            }}
            
            .report-header {{
                flex-direction: column;
                text-align: center;
            }}
            
            .kpi-grid,
            .metrics-grid {{
                grid-template-columns: 1fr;
            }}
            
            .footer-info {{
                flex-direction: column;
                gap: 10px;
            }}
            
            .disclaimer {{
                text-align: left;
                margin-top: 20px;
            }}
            
            .metrics-table {{
                font-size: 10px;
            }}
            
            .metrics-table th,
            .metrics-table td {{
                padding: 8px 4px;
            }}
        }}
        
        @media print {{
            .container {{
                box-shadow: none;
                margin: 0;
            }}
            
            .chart-container {{
                page-break-inside: avoid;
            }}
            
            .kpi-card,
            .metric-card {{
                page-break-inside: avoid;
            }}
        }}
        '''
        
        return css
    
    def _format_percentage(self, value: float) -> str:
        """Format percentage values for display."""
        if value is None:
            return "N/A"
        return f"{value:.1f}%"
    
    def _format_duration(self, milliseconds: float) -> str:
        """Format duration values for display."""
        if milliseconds is None:
            return "N/A"
        if milliseconds < 1000:
            return f"{milliseconds:.1f}ms"
        else:
            return f"{milliseconds/1000:.2f}s"
    
    def _format_timestamp(self, timestamp: datetime) -> str:
        """Format timestamp for display."""
        if timestamp is None:
            return "N/A"
        return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    def _format_number(self, value: float) -> str:
        """Format numeric values for display."""
        if value is None:
            return "N/A"
        if value >= 1000000:
            return f"{value/1000000:.1f}M"
        elif value >= 1000:
            return f"{value/1000:.1f}K"
        else:
            return f"{value:.1f}"
    
    def _get_status_color(self, status: str) -> str:
        """Get color for status indicator."""
        return self.branding.get_status_colors().get(status.lower(), "#666")
    
    def _get_variance_status(self, variance_percent: float) -> str:
        """Get variance status description."""
        if variance_percent <= 5.0:
            return "Excellent Performance"
        elif variance_percent <= 10.0:
            return "Within Threshold"
        elif variance_percent <= 15.0:
            return "Approaching Limit"
        else:
            return "Exceeds Threshold"
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from values."""
        if not values or len(values) < 2:
            return "No Trend Data"
        
        if values[-1] > values[0]:
            return "↗ Increasing"
        elif values[-1] < values[0]:
            return "↘ Decreasing"
        else:
            return "→ Stable"
    
    def _get_recommendation(self, metric_name: str, status: str) -> str:
        """Get recommendation based on metric performance."""
        recommendations = {
            "response_time": {
                "failure": "Optimize database queries and reduce middleware overhead",
                "warning": "Monitor response time trends and consider caching",
                "ok": "Response time is within acceptable limits"
            },
            "memory_usage": {
                "failure": "Investigate memory leaks and optimize object lifecycle",
                "warning": "Monitor memory usage patterns and consider garbage collection tuning",
                "ok": "Memory usage is stable and efficient"
            },
            "error_rate": {
                "failure": "Immediate investigation required for error sources",
                "warning": "Monitor error patterns and improve error handling",
                "ok": "Error rate is within acceptable limits"
            }
        }
        
        return recommendations.get(metric_name, {}).get(status, "Monitor performance trends")
    
    def add_section(
        self,
        title: str,
        content: str,
        description: Optional[str] = None,
        section_id: Optional[str] = None
    ) -> None:
        """
        Add content section to report.
        
        Args:
            title: Section title
            content: Section content (HTML)
            description: Optional section description
            section_id: Optional section identifier
        """
        if section_id is None:
            section_id = title.lower().replace(' ', '_').replace('-', '_')
        
        self.sections.append({
            "id": section_id,
            "title": title,
            "content": content,
            "description": description
        })
    
    def add_chart(
        self,
        chart_id: str,
        title: str,
        chart_content: str,
        chart_type: ChartType = ChartType.LINE_CHART
    ) -> None:
        """
        Add chart to report.
        
        Args:
            chart_id: Unique chart identifier
            title: Chart title
            chart_content: Chart HTML content
            chart_type: Type of chart for categorization
        """
        self.charts.append({
            "id": chart_id,
            "title": title,
            "content": chart_content,
            "type": chart_type.value
        })
    
    def set_performance_data(
        self,
        current_metrics: Dict[str, Any],
        baseline_metrics: Dict[str, Any],
        variance_analysis: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Set performance data for report generation.
        
        Args:
            current_metrics: Current performance metrics
            baseline_metrics: Baseline comparison metrics
            variance_analysis: Optional variance analysis results
        """
        self.performance_data = current_metrics
        self.baseline_data = baseline_metrics
        self.variance_analysis = variance_analysis or {}
    
    def generate_html(self, template_name: Optional[str] = None) -> str:
        """
        Generate HTML report content.
        
        Args:
            template_name: Optional specific template name
            
        Returns:
            Generated HTML content
            
        Raises:
            ValueError: If Jinja2 is not available or template not found
        """
        if not JINJA2_AVAILABLE:
            raise ValueError("Jinja2 is required for HTML report generation")
        
        # Determine template based on audience
        if template_name is None:
            if self.metadata.audience == ReportAudience.EXECUTIVE:
                template_name = "executive.html"
            else:
                template_name = "technical.html"
        
        template = self.jinja_env.get_template(template_name)
        
        # Prepare template context
        context = {
            "metadata": self.metadata,
            "branding": self.branding,
            "sections": self.sections,
            "charts": self.charts,
            "performance_data": self.performance_data,
            "baseline_data": self.baseline_data,
            "variance_analysis": self.variance_analysis,
            "css_styles": self._get_css_styles(),
            "plotly_available": PLOTLY_AVAILABLE,
            # Template-specific data
            "performance_summary": self._generate_performance_summary(),
            "baseline_summary": self._generate_baseline_summary(),
            "detailed_metrics": self._generate_detailed_metrics(),
            "statistical_analysis": self._generate_statistical_analysis(),
            "recommendations": self._generate_recommendations()
        }
        
        return template.render(**context)
    
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance summary for executive template."""
        if not self.performance_data:
            return {}
        
        # Calculate key metrics
        avg_response_time = self.performance_data.get('avg_response_time', 0)
        baseline_response_time = self.baseline_data.get('avg_response_time', avg_response_time)
        
        variance_percentage = 0
        if baseline_response_time > 0:
            variance_percentage = ((avg_response_time - baseline_response_time) / baseline_response_time) * 100
        
        return {
            "variance_percentage": abs(variance_percentage),
            "within_threshold": abs(variance_percentage) <= 10.0,
            "avg_response_time": avg_response_time,
            "requests_per_second": self.performance_data.get('requests_per_second', 0),
            "error_rate": self.performance_data.get('error_rate', 0) * 100,  # Convert to percentage
            "response_time_trend": self.performance_data.get('response_time_trend', []),
            "throughput_trend": self.performance_data.get('throughput_trend', [])
        }
    
    def _generate_baseline_summary(self) -> Dict[str, Any]:
        """Generate baseline summary for comparison."""
        return {
            "avg_response_time": self.baseline_data.get('avg_response_time', 0),
            "requests_per_second": self.baseline_data.get('requests_per_second', 0),
            "error_rate": self.baseline_data.get('error_rate', 0) * 100
        }
    
    def _generate_detailed_metrics(self) -> Dict[str, Any]:
        """Generate detailed metrics for technical template."""
        detailed_metrics = {}
        
        for metric_name, current_value in self.performance_data.items():
            if metric_name.endswith('_trend'):
                continue
                
            baseline_value = self.baseline_data.get(metric_name, current_value)
            
            # Calculate variance
            variance_percent = 0
            if baseline_value > 0:
                variance_percent = ((current_value - baseline_value) / baseline_value) * 100
            
            # Determine status
            status = "ok"
            if abs(variance_percent) > 15:
                status = "failure"
            elif abs(variance_percent) > 10:
                status = "critical"
            elif abs(variance_percent) > 5:
                status = "warning"
            
            # Determine unit
            unit = ""
            if "time" in metric_name or "latency" in metric_name:
                unit = "ms"
            elif "rate" in metric_name or "throughput" in metric_name:
                unit = " req/s"
            elif "memory" in metric_name:
                unit = "MB"
            elif "cpu" in metric_name:
                unit = "%"
            
            detailed_metrics[metric_name] = {
                "current_value": current_value,
                "baseline_value": baseline_value,
                "variance_percent": variance_percent,
                "status": status,
                "unit": unit
            }
        
        return detailed_metrics
    
    def _generate_statistical_analysis(self) -> Dict[str, Any]:
        """Generate statistical analysis for technical template."""
        statistical_analysis = {}
        
        # Mock statistical data - in real implementation, this would come from test results
        for metric_name in self.performance_data.keys():
            if metric_name.endswith('_trend'):
                continue
                
            # Generate mock statistical data
            current_value = self.performance_data[metric_name]
            baseline_value = self.baseline_data.get(metric_name, current_value)
            
            # Simulate statistical distribution
            variance = abs(current_value - baseline_value) * 0.1
            
            unit = ""
            if "time" in metric_name or "latency" in metric_name:
                unit = "ms"
            elif "rate" in metric_name or "throughput" in metric_name:
                unit = " req/s"
            elif "memory" in metric_name:
                unit = "MB"
            elif "cpu" in metric_name:
                unit = "%"
            
            # Calculate variance percentage
            variance_percent = 0
            if baseline_value > 0:
                variance_percent = ((current_value - baseline_value) / baseline_value) * 100
            
            status = "ok"
            if abs(variance_percent) > 10:
                status = "failure"
            elif abs(variance_percent) > 5:
                status = "warning"
            
            statistical_analysis[metric_name] = {
                "mean": current_value,
                "median": current_value * 0.95,
                "p95": current_value * 1.2,
                "p99": current_value * 1.5,
                "std_dev": variance,
                "unit": unit,
                "status": status,
                "details": f"Variance: {variance_percent:.1f}% from baseline"
            }
        
        return statistical_analysis
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations based on performance analysis."""
        recommendations = []
        
        # Analyze performance data and generate recommendations
        performance_summary = self._generate_performance_summary()
        
        if not performance_summary.get('within_threshold', True):
            recommendations.append({
                "title": "Performance Optimization Required",
                "description": "Current performance variance exceeds 10% threshold. Immediate optimization needed.",
                "priority": "high"
            })
        
        if performance_summary.get('error_rate', 0) > 0.1:
            recommendations.append({
                "title": "Error Rate Investigation",
                "description": "Error rate exceeds acceptable threshold. Review error logs and improve error handling.",
                "priority": "high"
            })
        
        if performance_summary.get('avg_response_time', 0) > 500:
            recommendations.append({
                "title": "Response Time Optimization",
                "description": "Response time exceeds target. Consider database query optimization and caching.",
                "priority": "medium"
            })
        
        # Add default recommendations
        if not recommendations:
            recommendations.append({
                "title": "Continuous Monitoring",
                "description": "Maintain current performance monitoring and trend analysis.",
                "priority": "low"
            })
        
        return recommendations
    
    def generate_json(self) -> str:
        """
        Generate JSON report content.
        
        Returns:
            JSON formatted report data
        """
        report_data = {
            "metadata": self.metadata.to_dict(),
            "branding": {
                "company_name": self.branding.company_name,
                "primary_color": self.branding.primary_color,
                "theme": self.metadata.theme.value
            },
            "performance_data": self.performance_data,
            "baseline_data": self.baseline_data,
            "variance_analysis": self.variance_analysis,
            "sections": self.sections,
            "charts": [
                {
                    "id": chart["id"],
                    "title": chart["title"],
                    "type": chart["type"]
                }
                for chart in self.charts
            ],
            "summary": {
                "performance_summary": self._generate_performance_summary(),
                "baseline_summary": self._generate_baseline_summary(),
                "recommendations": self._generate_recommendations()
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def generate_pdf(self, html_content: Optional[str] = None) -> bytes:
        """
        Generate PDF report from HTML content.
        
        Args:
            html_content: Optional HTML content (generated if not provided)
            
        Returns:
            PDF content as bytes
            
        Raises:
            ValueError: If WeasyPrint is not available
        """
        if not WEASYPRINT_AVAILABLE:
            raise ValueError("WeasyPrint is required for PDF report generation")
        
        if html_content is None:
            html_content = self.generate_html()
        
        # Create PDF from HTML
        html_doc = weasyprint.HTML(string=html_content)
        pdf_bytes = html_doc.write_pdf()
        
        return pdf_bytes
    
    def save_report(
        self,
        output_path: str,
        format: ReportFormat = ReportFormat.HTML
    ) -> str:
        """
        Save report to file in specified format.
        
        Args:
            output_path: Output file path
            format: Report format for export
            
        Returns:
            Path to saved report file
            
        Raises:
            ValueError: If format is not supported
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == ReportFormat.HTML:
            content = self.generate_html()
            output_path = output_path.with_suffix('.html')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        elif format == ReportFormat.JSON:
            content = self.generate_json()
            output_path = output_path.with_suffix('.json')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        elif format == ReportFormat.PDF:
            content = self.generate_pdf()
            output_path = output_path.with_suffix('.pdf')
            with open(output_path, 'wb') as f:
                f.write(content)
        
        elif format == ReportFormat.MARKDOWN:
            content = self._generate_markdown()
            output_path = output_path.with_suffix('.md')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        else:
            raise ValueError(f"Unsupported report format: {format}")
        
        return str(output_path)
    
    def _generate_markdown(self) -> str:
        """
        Generate Markdown report content.
        
        Returns:
            Markdown formatted report content
        """
        lines = []
        
        # Header
        lines.append(f"# {self.metadata.title}")
        lines.append("")
        lines.append(f"**Generated:** {self._format_timestamp(self.metadata.generated_at)}")
        lines.append(f"**Environment:** {self.metadata.test_environment}")
        lines.append(f"**Audience:** {self.metadata.audience.value.title()}")
        lines.append("")
        
        # Performance Summary
        performance_summary = self._generate_performance_summary()
        if performance_summary:
            lines.append("## Performance Summary")
            lines.append("")
            lines.append(f"- **Performance Variance:** {performance_summary.get('variance_percentage', 0):.1f}%")
            lines.append(f"- **Response Time:** {performance_summary.get('avg_response_time', 0):.1f}ms")
            lines.append(f"- **Throughput:** {performance_summary.get('requests_per_second', 0):.1f} req/s")
            lines.append(f"- **Error Rate:** {performance_summary.get('error_rate', 0):.1f}%")
            lines.append("")
        
        # Recommendations
        recommendations = self._generate_recommendations()
        if recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for rec in recommendations[:5]:  # Top 5 recommendations
                lines.append(f"### {rec['title']} ({rec['priority'].upper()} PRIORITY)")
                lines.append(f"{rec['description']}")
                lines.append("")
        
        # Sections
        for section in self.sections:
            lines.append(f"## {section['title']}")
            if section.get('description'):
                lines.append(f"*{section['description']}*")
            lines.append("")
            # Strip HTML tags for markdown (simplified)
            content = section['content'].replace('<p>', '').replace('</p>', '\n')
            content = content.replace('<br>', '\n').replace('<br/>', '\n')
            lines.append(content)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Report generated by {self.metadata.generated_by} v{self.metadata.version}*")
        lines.append(f"*Report ID: {self.metadata.report_id}*")
        
        return '\n'.join(lines)


class ChartTemplateLibrary:
    """
    Chart template library providing visualization templates for performance data.
    
    Implements comprehensive chart generation capabilities with responsive design,
    interactive features, and consistent styling per Section 6.5.1.5 dashboard
    design requirements.
    """
    
    def __init__(self, branding: Optional[ReportBranding] = None):
        """
        Initialize chart template library.
        
        Args:
            branding: Visual branding configuration
        """
        self.branding = branding or ReportBranding()
        self.color_palette = self.branding.get_color_palette()
        
        # Configure plotting backends
        if MATPLOTLIB_AVAILABLE:
            plt.style.use('seaborn-v0_8')
            sns.set_palette(self.color_palette)
        
        if PLOTLY_AVAILABLE:
            pio.templates.default = "plotly_white"
    
    def create_performance_variance_chart(
        self,
        metrics_data: Dict[str, Dict[str, float]],
        config: Optional[ChartConfiguration] = None
    ) -> str:
        """
        Create performance variance chart showing current vs baseline metrics.
        
        Args:
            metrics_data: Dictionary of metric name to current/baseline values
            config: Optional chart configuration
            
        Returns:
            HTML content for chart visualization
        """
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Performance Variance Chart", "Plotly not available")
        
        config = config or ChartConfiguration(
            chart_type=ChartType.BAR_CHART,
            title="Performance Variance vs Baseline",
            height=500
        )
        
        # Prepare data
        metric_names = list(metrics_data.keys())
        current_values = [data.get('current', 0) for data in metrics_data.values()]
        baseline_values = [data.get('baseline', 0) for data in metrics_data.values()]
        variance_percentages = []
        
        for current, baseline in zip(current_values, baseline_values):
            if baseline > 0:
                variance = ((current - baseline) / baseline) * 100
            else:
                variance = 0
            variance_percentages.append(variance)
        
        # Create figure
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Current vs Baseline Values', 'Variance Percentage'),
            specs=[[{"secondary_y": False}], [{"secondary_y": False}]],
            vertical_spacing=0.1
        )
        
        # Current vs Baseline bars
        fig.add_trace(
            go.Bar(
                name='Current',
                x=metric_names,
                y=current_values,
                marker_color=self.color_palette[0],
                text=[f"{val:.1f}" for val in current_values],
                textposition='outside'
            ),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Bar(
                name='Baseline',
                x=metric_names,
                y=baseline_values,
                marker_color=self.color_palette[1],
                text=[f"{val:.1f}" for val in baseline_values],
                textposition='outside'
            ),
            row=1, col=1
        )
        
        # Variance percentage bars with color coding
        variance_colors = []
        for variance in variance_percentages:
            if abs(variance) <= 5:
                variance_colors.append(self.branding.success_color)
            elif abs(variance) <= 10:
                variance_colors.append(self.branding.warning_color)
            else:
                variance_colors.append(self.branding.danger_color)
        
        fig.add_trace(
            go.Bar(
                name='Variance %',
                x=metric_names,
                y=variance_percentages,
                marker_color=variance_colors,
                text=[f"{val:+.1f}%" for val in variance_percentages],
                textposition='outside',
                showlegend=False
            ),
            row=2, col=1
        )
        
        # Add threshold lines
        fig.add_hline(y=10, line_dash="dash", line_color="red", 
                     annotation_text="10% Threshold", row=2, col=1)
        fig.add_hline(y=-10, line_dash="dash", line_color="red", row=2, col=1)
        
        # Update layout
        fig.update_layout(
            title=config.title,
            height=config.height,
            showlegend=True,
            barmode='group',
            font=dict(family=self.branding.font_family),
            plot_bgcolor=config.plot_background_color,
            paper_bgcolor=config.background_color
        )
        
        fig.update_xaxes(title_text="Metrics", row=2, col=1)
        fig.update_yaxes(title_text="Values", row=1, col=1)
        fig.update_yaxes(title_text="Variance %", row=2, col=1)
        
        # Convert to HTML
        chart_html = pio.to_html(
            fig,
            include_plotlyjs='cdn',
            config=config.to_plotly_config(),
            div_id=f"chart-{config.title.lower().replace(' ', '-')}"
        )
        
        return chart_html
    
    def create_response_time_trend_chart(
        self,
        time_series_data: List[Tuple[datetime, float]],
        baseline_value: Optional[float] = None,
        config: Optional[ChartConfiguration] = None
    ) -> str:
        """
        Create response time trend chart with baseline comparison.
        
        Args:
            time_series_data: List of (timestamp, response_time) tuples
            baseline_value: Optional baseline response time value
            config: Optional chart configuration
            
        Returns:
            HTML content for chart visualization
        """
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Response Time Trend", "Plotly not available")
        
        config = config or ChartConfiguration(
            chart_type=ChartType.LINE_CHART,
            title="Response Time Trend Analysis",
            height=400
        )
        
        if not time_series_data:
            return self._create_fallback_chart(config.title, "No data available")
        
        # Extract timestamps and values
        timestamps = [item[0] for item in time_series_data]
        response_times = [item[1] for item in time_series_data]
        
        # Create figure
        fig = go.Figure()
        
        # Response time line
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=response_times,
                mode='lines+markers',
                name='Response Time',
                line=dict(color=self.color_palette[0], width=2),
                marker=dict(size=6),
                hovertemplate='<b>%{x}</b><br>Response Time: %{y:.1f}ms<extra></extra>'
            )
        )
        
        # Baseline line
        if baseline_value:
            fig.add_hline(
                y=baseline_value,
                line_dash="dash",
                line_color=self.color_palette[1],
                annotation_text=f"Baseline: {baseline_value:.1f}ms"
            )
        
        # Threshold lines
        if baseline_value:
            upper_threshold = baseline_value * 1.1  # 10% above baseline
            lower_threshold = baseline_value * 0.9  # 10% below baseline
            
            fig.add_hline(
                y=upper_threshold,
                line_dash="dot",
                line_color=self.branding.danger_color,
                annotation_text="+10% Threshold"
            )
            fig.add_hline(
                y=lower_threshold,
                line_dash="dot",
                line_color=self.branding.success_color,
                annotation_text="-10% Threshold"
            )
        
        # Update layout
        fig.update_layout(
            title=config.title,
            xaxis_title="Time",
            yaxis_title="Response Time (ms)",
            height=config.height,
            font=dict(family=self.branding.font_family),
            plot_bgcolor=config.plot_background_color,
            paper_bgcolor=config.background_color,
            hovermode='x unified'
        )
        
        # Convert to HTML
        chart_html = pio.to_html(
            fig,
            include_plotlyjs='cdn',
            config=config.to_plotly_config(),
            div_id=f"chart-response-time-trend"
        )
        
        return chart_html
    
    def create_throughput_comparison_chart(
        self,
        current_throughput: List[float],
        baseline_throughput: List[float],
        labels: List[str],
        config: Optional[ChartConfiguration] = None
    ) -> str:
        """
        Create throughput comparison chart between current and baseline.
        
        Args:
            current_throughput: Current throughput values
            baseline_throughput: Baseline throughput values
            labels: Labels for data points
            config: Optional chart configuration
            
        Returns:
            HTML content for chart visualization
        """
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Throughput Comparison", "Plotly not available")
        
        config = config or ChartConfiguration(
            chart_type=ChartType.BAR_CHART,
            title="Throughput Comparison: Current vs Baseline",
            height=400
        )
        
        # Create figure
        fig = go.Figure()
        
        # Current throughput bars
        fig.add_trace(
            go.Bar(
                name='Current',
                x=labels,
                y=current_throughput,
                marker_color=self.color_palette[0],
                text=[f"{val:.1f}" for val in current_throughput],
                textposition='outside'
            )
        )
        
        # Baseline throughput bars
        fig.add_trace(
            go.Bar(
                name='Baseline',
                x=labels,
                y=baseline_throughput,
                marker_color=self.color_palette[1],
                text=[f"{val:.1f}" for val in baseline_throughput],
                textposition='outside'
            )
        )
        
        # Update layout
        fig.update_layout(
            title=config.title,
            xaxis_title="Test Scenarios",
            yaxis_title="Throughput (req/s)",
            barmode='group',
            height=config.height,
            font=dict(family=self.branding.font_family),
            plot_bgcolor=config.plot_background_color,
            paper_bgcolor=config.background_color
        )
        
        # Convert to HTML
        chart_html = pio.to_html(
            fig,
            include_plotlyjs='cdn',
            config=config.to_plotly_config(),
            div_id="chart-throughput-comparison"
        )
        
        return chart_html
    
    def create_performance_gauge_chart(
        self,
        current_value: float,
        baseline_value: float,
        metric_name: str,
        unit: str = "",
        config: Optional[ChartConfiguration] = None
    ) -> str:
        """
        Create performance gauge chart showing current performance against baseline.
        
        Args:
            current_value: Current metric value
            baseline_value: Baseline metric value
            metric_name: Name of the metric
            unit: Unit of measurement
            config: Optional chart configuration
            
        Returns:
            HTML content for gauge chart
        """
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Performance Gauge", "Plotly not available")
        
        config = config or ChartConfiguration(
            chart_type=ChartType.GAUGE_CHART,
            title=f"{metric_name} Performance Gauge",
            height=400,
            width=400
        )
        
        # Calculate variance percentage
        if baseline_value > 0:
            variance_percent = ((current_value - baseline_value) / baseline_value) * 100
        else:
            variance_percent = 0
        
        # Determine gauge color based on variance
        if abs(variance_percent) <= 5:
            gauge_color = self.branding.success_color
        elif abs(variance_percent) <= 10:
            gauge_color = self.branding.warning_color
        else:
            gauge_color = self.branding.danger_color
        
        # Create gauge chart
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=current_value,
            delta={'reference': baseline_value, 'relative': True, 'valueformat': '.1%'},
            title={'text': f"{metric_name} ({unit})"},
            gauge={
                'axis': {
                    'range': [None, max(current_value, baseline_value) * 1.5]
                },
                'bar': {'color': gauge_color},
                'steps': [
                    {'range': [0, baseline_value * 0.95], 'color': "lightgray"},
                    {'range': [baseline_value * 0.95, baseline_value * 1.05], 'color': "yellow"},
                    {'range': [baseline_value * 1.05, baseline_value * 1.1], 'color': "orange"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': baseline_value * 1.1
                }
            }
        ))
        
        fig.update_layout(
            title=config.title,
            height=config.height,
            width=config.width,
            font=dict(family=self.branding.font_family),
            paper_bgcolor=config.background_color
        )
        
        # Convert to HTML
        chart_html = pio.to_html(
            fig,
            include_plotlyjs='cdn',
            config=config.to_plotly_config(),
            div_id=f"gauge-{metric_name.lower().replace(' ', '-')}"
        )
        
        return chart_html
    
    def create_performance_heatmap(
        self,
        data_matrix: List[List[float]],
        x_labels: List[str],
        y_labels: List[str],
        config: Optional[ChartConfiguration] = None
    ) -> str:
        """
        Create performance heatmap for correlation analysis.
        
        Args:
            data_matrix: 2D matrix of values
            x_labels: Labels for x-axis
            y_labels: Labels for y-axis
            config: Optional chart configuration
            
        Returns:
            HTML content for heatmap
        """
        if not PLOTLY_AVAILABLE:
            return self._create_fallback_chart("Performance Heatmap", "Plotly not available")
        
        config = config or ChartConfiguration(
            chart_type=ChartType.HEATMAP,
            title="Performance Correlation Heatmap",
            height=500
        )
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=data_matrix,
            x=x_labels,
            y=y_labels,
            colorscale='RdYlBu_r',
            colorbar=dict(title="Correlation"),
            text=[[f"{val:.2f}" for val in row] for row in data_matrix],
            texttemplate="%{text}",
            textfont={"size": 10}
        ))
        
        fig.update_layout(
            title=config.title,
            height=config.height,
            font=dict(family=self.branding.font_family),
            plot_bgcolor=config.plot_background_color,
            paper_bgcolor=config.background_color
        )
        
        # Convert to HTML
        chart_html = pio.to_html(
            fig,
            include_plotlyjs='cdn',
            config=config.to_plotly_config(),
            div_id="heatmap-performance-correlation"
        )
        
        return chart_html
    
    def _create_fallback_chart(self, title: str, message: str) -> str:
        """
        Create fallback chart content when visualization libraries are unavailable.
        
        Args:
            title: Chart title
            message: Fallback message
            
        Returns:
            HTML content for fallback chart
        """
        return f'''
        <div class="chart-fallback" style="
            width: 100%;
            height: 300px;
            border: 2px dashed #ccc;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background-color: #f9f9f9;
            border-radius: 8px;
            margin: 20px 0;
        ">
            <h3 style="color: #666; margin-bottom: 10px;">{title}</h3>
            <p style="color: #888; text-align: center;">{message}</p>
            <p style="color: #999; font-size: 12px; margin-top: 10px;">
                Install required dependencies for chart visualization
            </p>
        </div>
        '''


class ReportTemplateFactory:
    """
    Factory for creating standardized report templates with predefined configurations.
    
    Provides convenient methods for generating different types of performance reports
    with appropriate templates, styling, and configuration per stakeholder requirements.
    """
    
    @staticmethod
    def create_executive_summary_report(
        performance_data: Dict[str, Any],
        baseline_data: Dict[str, Any],
        environment: str = "production"
    ) -> PerformanceReportTemplate:
        """
        Create executive summary report template.
        
        Args:
            performance_data: Current performance metrics
            baseline_data: Baseline comparison metrics
            environment: Test environment name
            
        Returns:
            Configured executive report template
        """
        metadata = ReportMetadata(
            report_id="",  # Will be generated
            title="Performance Migration Executive Summary",
            description="High-level performance analysis for Flask migration project",
            generated_at=datetime.now(timezone.utc),
            audience=ReportAudience.EXECUTIVE,
            theme=ReportTheme.EXECUTIVE,
            test_environment=environment
        )
        metadata.report_id = metadata.generate_report_id()
        
        branding = ReportBranding(
            company_name="Flask Migration Project",
            primary_color="#1f77b4",
            secondary_color="#ff7f0e"
        )
        
        template = PerformanceReportTemplate(metadata, branding)
        template.set_performance_data(performance_data, baseline_data)
        
        return template
    
    @staticmethod
    def create_technical_analysis_report(
        performance_data: Dict[str, Any],
        baseline_data: Dict[str, Any],
        variance_analysis: Dict[str, Any],
        environment: str = "staging"
    ) -> PerformanceReportTemplate:
        """
        Create technical analysis report template.
        
        Args:
            performance_data: Current performance metrics
            baseline_data: Baseline comparison metrics
            variance_analysis: Detailed variance analysis
            environment: Test environment name
            
        Returns:
            Configured technical report template
        """
        metadata = ReportMetadata(
            report_id="",  # Will be generated
            title="Performance Technical Analysis Report",
            description="Detailed technical performance analysis with statistical breakdown",
            generated_at=datetime.now(timezone.utc),
            audience=ReportAudience.TECHNICAL,
            theme=ReportTheme.TECHNICAL,
            test_environment=environment
        )
        metadata.report_id = metadata.generate_report_id()
        
        branding = ReportBranding(
            primary_color="#2ca02c",
            secondary_color="#d62728"
        )
        
        template = PerformanceReportTemplate(metadata, branding)
        template.set_performance_data(performance_data, baseline_data, variance_analysis)
        
        return template
    
    @staticmethod
    def create_operations_dashboard_report(
        performance_data: Dict[str, Any],
        baseline_data: Dict[str, Any],
        environment: str = "production"
    ) -> PerformanceReportTemplate:
        """
        Create operations dashboard report template.
        
        Args:
            performance_data: Current performance metrics
            baseline_data: Baseline comparison metrics
            environment: Test environment name
            
        Returns:
            Configured operations report template
        """
        metadata = ReportMetadata(
            report_id="",  # Will be generated
            title="Performance Operations Dashboard",
            description="Real-time performance monitoring and operational insights",
            generated_at=datetime.now(timezone.utc),
            audience=ReportAudience.OPERATIONS,
            theme=ReportTheme.DASHBOARD,
            test_environment=environment
        )
        metadata.report_id = metadata.generate_report_id()
        
        branding = ReportBranding(
            primary_color="#ff7f0e",
            secondary_color="#9467bd"
        )
        
        template = PerformanceReportTemplate(metadata, branding)
        template.set_performance_data(performance_data, baseline_data)
        
        return template
    
    @staticmethod
    def create_compliance_audit_report(
        performance_data: Dict[str, Any],
        baseline_data: Dict[str, Any],
        compliance_data: Dict[str, Any],
        environment: str = "production"
    ) -> PerformanceReportTemplate:
        """
        Create compliance audit report template.
        
        Args:
            performance_data: Current performance metrics
            baseline_data: Baseline comparison metrics
            compliance_data: Compliance validation data
            environment: Test environment name
            
        Returns:
            Configured compliance report template
        """
        metadata = ReportMetadata(
            report_id="",  # Will be generated
            title="Performance Compliance Audit Report",
            description="Comprehensive compliance validation and audit documentation",
            generated_at=datetime.now(timezone.utc),
            audience=ReportAudience.COMPLIANCE,
            theme=ReportTheme.COMPLIANCE,
            test_environment=environment,
            classification="confidential",
            retention_period_days=2555  # 7 years for compliance
        )
        metadata.report_id = metadata.generate_report_id()
        
        branding = ReportBranding(
            primary_color="#8c564b",
            secondary_color="#e377c2"
        )
        
        template = PerformanceReportTemplate(metadata, branding)
        template.set_performance_data(performance_data, baseline_data, compliance_data)
        
        return template


# Utility Functions

def create_performance_report(
    report_type: str,
    performance_data: Dict[str, Any],
    baseline_data: Dict[str, Any],
    output_path: str,
    format: ReportFormat = ReportFormat.HTML,
    environment: str = "development"
) -> str:
    """
    Create performance report with specified type and configuration.
    
    Args:
        report_type: Type of report ('executive', 'technical', 'operations', 'compliance')
        performance_data: Current performance metrics
        baseline_data: Baseline comparison metrics
        output_path: Output file path
        format: Report format for export
        environment: Test environment name
        
    Returns:
        Path to generated report file
        
    Raises:
        ValueError: If report type is not supported
    """
    factory = ReportTemplateFactory()
    
    if report_type.lower() == "executive":
        template = factory.create_executive_summary_report(
            performance_data, baseline_data, environment
        )
    elif report_type.lower() == "technical":
        template = factory.create_technical_analysis_report(
            performance_data, baseline_data, {}, environment
        )
    elif report_type.lower() == "operations":
        template = factory.create_operations_dashboard_report(
            performance_data, baseline_data, environment
        )
    elif report_type.lower() == "compliance":
        template = factory.create_compliance_audit_report(
            performance_data, baseline_data, {}, environment
        )
    else:
        raise ValueError(f"Unsupported report type: {report_type}")
    
    return template.save_report(output_path, format)


def generate_chart_gallery(
    performance_data: Dict[str, Any],
    baseline_data: Dict[str, Any],
    output_path: str,
    branding: Optional[ReportBranding] = None
) -> str:
    """
    Generate comprehensive chart gallery for performance visualization.
    
    Args:
        performance_data: Current performance metrics
        baseline_data: Baseline comparison metrics
        output_path: Output directory path
        branding: Optional branding configuration
        
    Returns:
        Path to generated chart gallery HTML file
    """
    chart_lib = ChartTemplateLibrary(branding)
    
    # Create chart gallery HTML
    charts_html = []
    
    # Performance variance chart
    if performance_data and baseline_data:
        metrics_data = {}
        for key in performance_data.keys():
            if key in baseline_data:
                metrics_data[key] = {
                    'current': performance_data[key],
                    'baseline': baseline_data[key]
                }
        
        if metrics_data:
            variance_chart = chart_lib.create_performance_variance_chart(metrics_data)
            charts_html.append(variance_chart)
    
    # Generate gallery HTML
    gallery_html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Performance Chart Gallery</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .chart-gallery {{ display: grid; gap: 30px; }}
            .chart-item {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; }}
        </style>
    </head>
    <body>
        <h1>Performance Chart Gallery</h1>
        <div class="chart-gallery">
            {"".join(charts_html)}
        </div>
    </body>
    </html>
    '''
    
    # Save gallery
    output_file = Path(output_path) / "chart_gallery.html"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(gallery_html)
    
    return str(output_file)


# Export public API
__all__ = [
    'PerformanceReportTemplate',
    'ChartTemplateLibrary',
    'ReportTemplateFactory',
    'ReportFormat',
    'ReportAudience',
    'ReportTheme',
    'ChartType',
    'ReportBranding',
    'ChartConfiguration',
    'ReportMetadata',
    'create_performance_report',
    'generate_chart_gallery'
]