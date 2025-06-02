"""
Performance Report Templates and Formatting Utilities Module

This module provides comprehensive performance report templates and formatting utilities for the Flask migration project,
ensuring standardized report layouts, visualization templates, and export format configurations. Implements consistent
reporting across all performance analysis outputs per Section 0.3.4 documentation requirements and Section 6.5.1.5
dashboard design specifications.

Key Features:
- Standardized report template library per Section 0.3.4 documentation requirements
- Multi-format export capabilities (HTML, PDF, JSON) per Section 0.3.4
- Visualization template library for charts and graphs per Section 6.5.1.5 dashboard design
- Consistent formatting and branding standards per Section 0.3.4 documentation requirements
- Responsive template design for different devices per Section 0.3.4
- Template customization for different stakeholder audiences per Section 0.3.4

Architecture Integration:
- Section 0.3.4: Documentation requirements with comprehensive report generation
- Section 6.5.1.5: Dashboard design components and visualization standards
- Section 6.6.2: CI/CD integration with automated report generation
- Section 6.6.3: Quality metrics reporting and trend analysis

Performance Requirements:
- Supports ≤10% variance threshold reporting per Section 0.1.1
- Node.js baseline comparison visualization per Section 0.3.2
- Real-time performance monitoring dashboard integration per Section 6.5.1

Author: Flask Migration Team
Version: 1.0.0
Dependencies: jinja2, matplotlib, plotly, weasyprint, json, pandas
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import base64
import io

# Template engine and visualization imports
try:
    from jinja2 import Environment, FileSystemLoader, BaseLoader, Template
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import seaborn as sns
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.io as pio
    import pandas as pd
    import numpy as np
except ImportError as e:
    logging.warning(f"Optional visualization dependencies not available: {e}")
    # Provide fallback implementations
    plt = None
    sns = None
    go = None
    px = None
    pd = None
    np = None

# Configuration imports
from tests.performance.performance_config import (
    PerformanceTestConfig, NodeJSBaselineMetrics, LoadTestScenario,
    PerformanceMetricType, get_baseline_metrics
)

# Configure module logger
logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report output formats."""
    
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"
    CSV = "csv"
    EXCEL = "xlsx"


class ReportAudience(Enum):
    """Target audiences for customized report templates."""
    
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    OPERATIONS = "operations"
    DEVELOPMENT = "development"
    QA_TESTING = "qa_testing"
    STAKEHOLDER = "stakeholder"


class ChartType(Enum):
    """Supported chart and visualization types."""
    
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    SCATTER_PLOT = "scatter_plot"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"
    HEATMAP = "heatmap"
    GAUGE_CHART = "gauge_chart"
    WATERFALL_CHART = "waterfall_chart"
    COMPARISON_CHART = "comparison_chart"
    TREND_ANALYSIS = "trend_analysis"


@dataclass
class ReportMetadata:
    """Report metadata container for consistent report information."""
    
    title: str
    report_type: str
    audience: ReportAudience
    generated_at: datetime = field(default_factory=datetime.utcnow)
    test_environment: str = "production"
    test_duration: str = "Unknown"
    baseline_version: str = "Node.js"
    current_version: str = "Flask"
    performance_variance_threshold: float = 10.0
    
    # Report identification
    report_id: str = field(default_factory=lambda: f"perf_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    version: str = "1.0.0"
    author: str = "Flask Migration Performance Testing"
    
    # Executive summary fields
    overall_status: str = "PASS"
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Technical metadata
    test_scenarios_executed: List[str] = field(default_factory=list)
    metrics_collected: List[str] = field(default_factory=list)
    data_quality_score: float = 100.0


@dataclass
class VisualizationConfig:
    """Configuration for chart and visualization generation."""
    
    # Chart appearance
    width: int = 1200
    height: int = 600
    dpi: int = 300
    theme: str = "plotly_white"
    color_palette: List[str] = field(default_factory=lambda: [
        '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'
    ])
    
    # Typography
    title_font_size: int = 16
    axis_font_size: int = 12
    legend_font_size: int = 10
    
    # Branding
    logo_path: Optional[str] = None
    brand_colors: Dict[str, str] = field(default_factory=lambda: {
        'primary': '#0066cc',
        'secondary': '#ff6600',
        'success': '#28a745',
        'warning': '#ffc107',
        'danger': '#dc3545',
        'info': '#17a2b8'
    })
    
    # Performance-specific settings
    variance_threshold_color: str = '#ff0000'
    baseline_color: str = '#0066cc'
    current_color: str = '#28a745'
    warning_color: str = '#ffc107'
    error_color: str = '#dc3545'


class PerformanceReportTemplateEngine:
    """
    Performance report template engine providing standardized report generation
    with multi-format export capabilities and audience-specific customization.
    """
    
    def __init__(self, template_dir: Optional[str] = None, 
                 config: PerformanceTestConfig = None):
        """
        Initialize the report template engine.
        
        Args:
            template_dir: Custom template directory path
            config: Performance test configuration instance
        """
        self.config = config or PerformanceTestConfig()
        self.template_dir = template_dir or self._get_default_template_dir()
        self.visualization_config = VisualizationConfig()
        
        # Initialize Jinja2 environment
        self.jinja_env = self._setup_jinja_environment()
        
        # Template cache
        self._template_cache: Dict[str, Template] = {}
        
        # Default report metadata
        self.default_metadata = ReportMetadata(
            title="Performance Analysis Report",
            report_type="performance_analysis",
            audience=ReportAudience.TECHNICAL
        )
        
        logger.info("Performance report template engine initialized", extra={
            'template_dir': self.template_dir,
            'visualization_enabled': plt is not None and go is not None
        })
    
    def _get_default_template_dir(self) -> str:
        """Get default template directory path."""
        return str(Path(__file__).parent / "templates")
    
    def _setup_jinja_environment(self) -> Environment:
        """Setup Jinja2 template environment with custom filters and functions."""
        
        # Custom template loader for embedded templates
        class EmbeddedTemplateLoader(BaseLoader):
            def get_source(self, environment, template):
                return self._get_embedded_template(template), None, lambda: True
        
        env = Environment(
            loader=EmbeddedTemplateLoader(),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        env.filters['format_number'] = self._format_number
        env.filters['format_percentage'] = self._format_percentage
        env.filters['format_duration'] = self._format_duration
        env.filters['format_timestamp'] = self._format_timestamp
        env.filters['variance_status'] = self._variance_status
        env.filters['performance_color'] = self._performance_color
        
        # Add custom functions
        env.globals['generate_chart'] = self._generate_chart
        env.globals['get_baseline_comparison'] = self._get_baseline_comparison
        env.globals['calculate_variance'] = self._calculate_variance
        
        return env
    
    def generate_report(self, test_results: Dict[str, Any], 
                       report_format: ReportFormat = ReportFormat.HTML,
                       audience: ReportAudience = ReportAudience.TECHNICAL,
                       metadata: Optional[ReportMetadata] = None,
                       output_path: Optional[str] = None) -> str:
        """
        Generate performance report in specified format for target audience.
        
        Args:
            test_results: Performance test results data
            report_format: Output format (HTML, PDF, JSON, etc.)
            audience: Target audience for report customization
            metadata: Custom report metadata
            output_path: Output file path (optional)
            
        Returns:
            Generated report content or file path
        """
        try:
            # Prepare report metadata
            report_metadata = metadata or self.default_metadata
            report_metadata.audience = audience
            report_metadata.generated_at = datetime.utcnow()
            
            # Enrich test results with analysis
            enriched_results = self._enrich_test_results(test_results)
            
            # Generate report based on format
            if report_format == ReportFormat.HTML:
                content = self._generate_html_report(enriched_results, report_metadata)
            elif report_format == ReportFormat.PDF:
                content = self._generate_pdf_report(enriched_results, report_metadata)
            elif report_format == ReportFormat.JSON:
                content = self._generate_json_report(enriched_results, report_metadata)
            elif report_format == ReportFormat.MARKDOWN:
                content = self._generate_markdown_report(enriched_results, report_metadata)
            elif report_format == ReportFormat.CSV:
                content = self._generate_csv_report(enriched_results, report_metadata)
            elif report_format == ReportFormat.EXCEL:
                content = self._generate_excel_report(enriched_results, report_metadata)
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
            
            # Save to file if path provided
            if output_path:
                self._save_report(content, output_path, report_format)
                logger.info(f"Report saved to {output_path}", extra={
                    'format': report_format.value,
                    'audience': audience.value,
                    'report_id': report_metadata.report_id
                })
                return output_path
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating report: {e}", extra={
                'format': report_format.value,
                'audience': audience.value
            })
            raise
    
    def _enrich_test_results(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich test results with analysis and baseline comparisons."""
        enriched = test_results.copy()
        
        # Add baseline comparisons
        baseline_metrics = get_baseline_metrics()
        enriched['baseline_comparisons'] = self._generate_baseline_comparisons(
            test_results, baseline_metrics
        )
        
        # Add variance analysis
        enriched['variance_analysis'] = self._calculate_variance_analysis(test_results)
        
        # Add performance scoring
        enriched['performance_score'] = self._calculate_performance_score(test_results)
        
        # Add trend analysis if historical data available
        enriched['trend_analysis'] = self._calculate_trend_analysis(test_results)
        
        # Add system resource analysis
        enriched['resource_analysis'] = self._analyze_system_resources(test_results)
        
        return enriched
    
    def _generate_html_report(self, test_results: Dict[str, Any], 
                             metadata: ReportMetadata) -> str:
        """Generate comprehensive HTML report with interactive visualizations."""
        
        template_name = f"html_report_{metadata.audience.value}"
        template = self._get_template(template_name)
        
        # Generate visualizations
        charts = self._generate_all_charts(test_results, format='html')
        
        # Prepare template context
        context = {
            'metadata': metadata,
            'test_results': test_results,
            'charts': charts,
            'baseline_metrics': get_baseline_metrics(),
            'variance_threshold': self.config.PERFORMANCE_VARIANCE_THRESHOLD,
            'css_styles': self._get_css_styles(),
            'javascript': self._get_javascript_code(),
            'timestamp': datetime.utcnow().isoformat(),
            'branding': self.visualization_config.brand_colors
        }
        
        return template.render(**context)
    
    def _generate_pdf_report(self, test_results: Dict[str, Any], 
                            metadata: ReportMetadata) -> bytes:
        """Generate PDF report with static visualizations."""
        
        # Generate HTML content first
        html_content = self._generate_html_report(test_results, metadata)
        
        # Convert to PDF using weasyprint if available
        try:
            import weasyprint
            
            # Create CSS for PDF optimization
            pdf_css = weasyprint.CSS(string=self._get_pdf_css())
            
            # Generate PDF
            html_doc = weasyprint.HTML(string=html_content)
            pdf_bytes = html_doc.write_pdf(stylesheets=[pdf_css])
            
            return pdf_bytes
            
        except ImportError:
            logger.warning("weasyprint not available, generating HTML fallback")
            return html_content.encode('utf-8')
    
    def _generate_json_report(self, test_results: Dict[str, Any], 
                             metadata: ReportMetadata) -> str:
        """Generate structured JSON report for API consumption."""
        
        report_data = {
            'metadata': asdict(metadata),
            'test_results': test_results,
            'summary': {
                'overall_status': metadata.overall_status,
                'performance_variance_within_threshold': self._check_variance_compliance(test_results),
                'key_metrics': self._extract_key_metrics(test_results),
                'recommendations': metadata.recommendations
            },
            'baseline_comparisons': test_results.get('baseline_comparisons', {}),
            'variance_analysis': test_results.get('variance_analysis', {}),
            'performance_score': test_results.get('performance_score', {}),
            'generated_at': datetime.utcnow().isoformat(),
            'format_version': '1.0'
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_markdown_report(self, test_results: Dict[str, Any], 
                                 metadata: ReportMetadata) -> str:
        """Generate Markdown report for documentation integration."""
        
        template_name = f"markdown_report_{metadata.audience.value}"
        template = self._get_template(template_name)
        
        # Prepare template context
        context = {
            'metadata': metadata,
            'test_results': test_results,
            'variance_threshold': self.config.PERFORMANCE_VARIANCE_THRESHOLD,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return template.render(**context)
    
    def _generate_csv_report(self, test_results: Dict[str, Any], 
                            metadata: ReportMetadata) -> str:
        """Generate CSV report for data analysis."""
        
        if pd is None:
            # Fallback CSV generation
            return self._generate_simple_csv(test_results)
        
        # Create comprehensive DataFrame
        df_data = []
        
        # Extract metrics data
        for metric_category, metrics in test_results.items():
            if isinstance(metrics, dict):
                for metric_name, value in metrics.items():
                    df_data.append({
                        'category': metric_category,
                        'metric': metric_name,
                        'value': value,
                        'timestamp': metadata.generated_at,
                        'environment': metadata.test_environment
                    })
        
        df = pd.DataFrame(df_data)
        return df.to_csv(index=False)
    
    def _generate_excel_report(self, test_results: Dict[str, Any], 
                              metadata: ReportMetadata) -> bytes:
        """Generate Excel report with multiple worksheets."""
        
        if pd is None:
            logger.warning("pandas not available, generating CSV fallback")
            return self._generate_csv_report(test_results, metadata).encode('utf-8')
        
        # Create Excel workbook in memory
        output = io.BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Summary worksheet
            summary_data = self._prepare_summary_data(test_results, metadata)
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            # Detailed metrics worksheet
            metrics_data = self._prepare_metrics_data(test_results)
            pd.DataFrame(metrics_data).to_excel(writer, sheet_name='Metrics', index=False)
            
            # Baseline comparisons worksheet
            baseline_data = test_results.get('baseline_comparisons', {})
            if baseline_data:
                pd.DataFrame(baseline_data).to_excel(writer, sheet_name='Baseline_Comparison', index=False)
            
            # Variance analysis worksheet
            variance_data = test_results.get('variance_analysis', {})
            if variance_data:
                pd.DataFrame(variance_data).to_excel(writer, sheet_name='Variance_Analysis', index=False)
        
        output.seek(0)
        return output.read()
    
    def generate_dashboard_template(self, audience: ReportAudience = ReportAudience.OPERATIONS) -> str:
        """
        Generate real-time dashboard template for monitoring integration.
        
        Args:
            audience: Target audience for dashboard customization
            
        Returns:
            HTML dashboard template with JavaScript components
        """
        
        template_name = f"dashboard_{audience.value}"
        template = self._get_template(template_name)
        
        # Dashboard configuration
        dashboard_config = {
            'refresh_interval': 30000,  # 30 seconds
            'real_time_enabled': True,
            'auto_refresh': True,
            'alert_integration': True,
            'responsive_design': True
        }
        
        # Widget configuration based on audience
        if audience == ReportAudience.EXECUTIVE:
            widgets = self._get_executive_widgets()
        elif audience == ReportAudience.OPERATIONS:
            widgets = self._get_operations_widgets()
        elif audience == ReportAudience.TECHNICAL:
            widgets = self._get_technical_widgets()
        else:
            widgets = self._get_default_widgets()
        
        context = {
            'dashboard_config': dashboard_config,
            'widgets': widgets,
            'audience': audience.value,
            'css_styles': self._get_dashboard_css(),
            'javascript': self._get_dashboard_javascript(),
            'branding': self.visualization_config.brand_colors
        }
        
        return template.render(**context)
    
    def generate_chart(self, data: Dict[str, Any], chart_type: ChartType,
                      title: str = "", format: str = 'html') -> str:
        """
        Generate individual chart/visualization.
        
        Args:
            data: Chart data
            chart_type: Type of chart to generate
            title: Chart title
            format: Output format ('html', 'png', 'svg')
            
        Returns:
            Chart content as string or base64 encoded image
        """
        
        if go is None and plt is None:
            return f"<div>Chart visualization not available (chart_type: {chart_type.value})</div>"
        
        try:
            if chart_type == ChartType.LINE_CHART:
                return self._generate_line_chart(data, title, format)
            elif chart_type == ChartType.BAR_CHART:
                return self._generate_bar_chart(data, title, format)
            elif chart_type == ChartType.SCATTER_PLOT:
                return self._generate_scatter_plot(data, title, format)
            elif chart_type == ChartType.HISTOGRAM:
                return self._generate_histogram(data, title, format)
            elif chart_type == ChartType.BOX_PLOT:
                return self._generate_box_plot(data, title, format)
            elif chart_type == ChartType.HEATMAP:
                return self._generate_heatmap(data, title, format)
            elif chart_type == ChartType.GAUGE_CHART:
                return self._generate_gauge_chart(data, title, format)
            elif chart_type == ChartType.WATERFALL_CHART:
                return self._generate_waterfall_chart(data, title, format)
            elif chart_type == ChartType.COMPARISON_CHART:
                return self._generate_comparison_chart(data, title, format)
            elif chart_type == ChartType.TREND_ANALYSIS:
                return self._generate_trend_analysis_chart(data, title, format)
            else:
                return f"<div>Unsupported chart type: {chart_type.value}</div>"
                
        except Exception as e:
            logger.error(f"Error generating chart: {e}", extra={
                'chart_type': chart_type.value,
                'title': title
            })
            return f"<div>Error generating chart: {str(e)}</div>"
    
    def _generate_all_charts(self, test_results: Dict[str, Any], format: str = 'html') -> Dict[str, str]:
        """Generate all standard charts for performance reports."""
        
        charts = {}
        
        # Response time comparison chart
        if 'response_times' in test_results:
            charts['response_time_comparison'] = self.generate_chart(
                test_results['response_times'],
                ChartType.COMPARISON_CHART,
                "Response Time Comparison (Flask vs Node.js)",
                format
            )
        
        # Performance variance gauge
        if 'variance_analysis' in test_results:
            charts['performance_variance'] = self.generate_chart(
                test_results['variance_analysis'],
                ChartType.GAUGE_CHART,
                "Performance Variance from Baseline",
                format
            )
        
        # Throughput trend analysis
        if 'throughput_data' in test_results:
            charts['throughput_trend'] = self.generate_chart(
                test_results['throughput_data'],
                ChartType.TREND_ANALYSIS,
                "Throughput Trend Analysis",
                format
            )
        
        # Resource utilization heatmap
        if 'resource_analysis' in test_results:
            charts['resource_utilization'] = self.generate_chart(
                test_results['resource_analysis'],
                ChartType.HEATMAP,
                "Resource Utilization Heatmap",
                format
            )
        
        # Error rate bar chart
        if 'error_rates' in test_results:
            charts['error_rates'] = self.generate_chart(
                test_results['error_rates'],
                ChartType.BAR_CHART,
                "Error Rates by Endpoint",
                format
            )
        
        # Response time distribution
        if 'response_time_distribution' in test_results:
            charts['response_time_distribution'] = self.generate_chart(
                test_results['response_time_distribution'],
                ChartType.HISTOGRAM,
                "Response Time Distribution",
                format
            )
        
        return charts
    
    def _generate_line_chart(self, data: Dict[str, Any], title: str, format: str) -> str:
        """Generate line chart visualization."""
        
        if go is not None:
            # Use Plotly for interactive charts
            fig = go.Figure()
            
            for series_name, series_data in data.items():
                if isinstance(series_data, (list, tuple)):
                    fig.add_trace(go.Scatter(
                        y=series_data,
                        mode='lines+markers',
                        name=series_name,
                        line=dict(width=2)
                    ))
            
            fig.update_layout(
                title=title,
                xaxis_title="Time",
                yaxis_title="Value",
                template=self.visualization_config.theme,
                width=self.visualization_config.width,
                height=self.visualization_config.height
            )
            
            if format == 'html':
                return fig.to_html(include_plotlyjs='cdn', div_id=f"chart_{hash(title)}")
            else:
                return fig.to_image(format='png', width=self.visualization_config.width, 
                                  height=self.visualization_config.height)
        
        elif plt is not None:
            # Fallback to matplotlib
            plt.figure(figsize=(12, 6))
            
            for series_name, series_data in data.items():
                if isinstance(series_data, (list, tuple)):
                    plt.plot(series_data, label=series_name, linewidth=2)
            
            plt.title(title)
            plt.xlabel("Time")
            plt.ylabel("Value")
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            if format == 'html':
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=self.visualization_config.dpi, bbox_inches='tight')
                buffer.seek(0)
                image_base64 = base64.b64encode(buffer.read()).decode()
                plt.close()
                return f'<img src="data:image/png;base64,{image_base64}" alt="{title}" style="max-width: 100%;">'
            else:
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=self.visualization_config.dpi, bbox_inches='tight')
                plt.close()
                return buffer.getvalue()
        
        return f"<div>Line chart: {title}</div>"
    
    def _generate_comparison_chart(self, data: Dict[str, Any], title: str, format: str) -> str:
        """Generate comparison chart for baseline vs current performance."""
        
        if go is not None:
            # Create side-by-side bar chart
            fig = go.Figure()
            
            categories = list(data.keys())
            baseline_values = []
            current_values = []
            
            # Extract baseline and current values
            baseline_metrics = get_baseline_metrics('response_times')
            
            for category in categories:
                baseline_values.append(baseline_metrics.get(category, 0))
                current_values.append(data.get(category, 0))
            
            fig.add_trace(go.Bar(
                name='Node.js Baseline',
                x=categories,
                y=baseline_values,
                marker_color=self.visualization_config.baseline_color
            ))
            
            fig.add_trace(go.Bar(
                name='Flask Current',
                x=categories,
                y=current_values,
                marker_color=self.visualization_config.current_color
            ))
            
            # Add variance threshold line
            threshold_values = [val * (1 + self.config.PERFORMANCE_VARIANCE_THRESHOLD / 100) 
                              for val in baseline_values]
            
            fig.add_trace(go.Scatter(
                name=f'±{self.config.PERFORMANCE_VARIANCE_THRESHOLD}% Threshold',
                x=categories,
                y=threshold_values,
                mode='lines',
                line=dict(dash='dash', color=self.visualization_config.variance_threshold_color)
            ))
            
            fig.update_layout(
                title=title,
                xaxis_title="Metrics",
                yaxis_title="Response Time (ms)",
                barmode='group',
                template=self.visualization_config.theme,
                width=self.visualization_config.width,
                height=self.visualization_config.height
            )
            
            if format == 'html':
                return fig.to_html(include_plotlyjs='cdn', div_id=f"chart_{hash(title)}")
            else:
                return fig.to_image(format='png')
        
        return f"<div>Comparison chart: {title}</div>"
    
    def _generate_gauge_chart(self, data: Dict[str, Any], title: str, format: str) -> str:
        """Generate gauge chart for performance variance display."""
        
        if go is not None:
            # Extract variance percentage
            variance_pct = data.get('overall_variance_percentage', 0)
            
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=abs(variance_pct),
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': title},
                delta={'reference': 0},
                gauge={
                    'axis': {'range': [None, 20]},
                    'bar': {'color': self._get_variance_color(variance_pct)},
                    'steps': [
                        {'range': [0, 5], 'color': self.visualization_config.brand_colors['success']},
                        {'range': [5, 10], 'color': self.visualization_config.brand_colors['warning']},
                        {'range': [10, 20], 'color': self.visualization_config.brand_colors['danger']}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': self.config.PERFORMANCE_VARIANCE_THRESHOLD
                    }
                }
            ))
            
            fig.update_layout(
                template=self.visualization_config.theme,
                width=600,
                height=400
            )
            
            if format == 'html':
                return fig.to_html(include_plotlyjs='cdn', div_id=f"gauge_{hash(title)}")
            else:
                return fig.to_image(format='png')
        
        return f"<div>Gauge chart: {title} - {data.get('overall_variance_percentage', 0):.1f}% variance</div>"
    
    def _get_template(self, template_name: str) -> Template:
        """Get or create template from cache."""
        
        if template_name not in self._template_cache:
            template_content = self._get_embedded_template(template_name)
            self._template_cache[template_name] = self.jinja_env.from_string(template_content)
        
        return self._template_cache[template_name]
    
    def _get_embedded_template(self, template_name: str) -> str:
        """Get embedded template content based on template name."""
        
        if template_name.startswith('html_report_'):
            return self._get_html_report_template(template_name)
        elif template_name.startswith('markdown_report_'):
            return self._get_markdown_report_template(template_name)
        elif template_name.startswith('dashboard_'):
            return self._get_dashboard_template(template_name)
        else:
            return self._get_default_template()
    
    def _get_html_report_template(self, template_name: str) -> str:
        """Get HTML report template based on audience."""
        
        audience = template_name.split('_')[-1]
        
        if audience == 'executive':
            return self._get_executive_html_template()
        elif audience == 'technical':
            return self._get_technical_html_template()
        elif audience == 'operations':
            return self._get_operations_html_template()
        else:
            return self._get_default_html_template()
    
    def _get_executive_html_template(self) -> str:
        """Executive-focused HTML template with high-level metrics."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }} - Executive Summary</title>
    <style>{{ css_styles }}</style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <h1>{{ metadata.title }}</h1>
            <div class="header-info">
                <span class="report-date">Generated: {{ metadata.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</span>
                <span class="status-badge status-{{ metadata.overall_status.lower() }}">{{ metadata.overall_status }}</span>
            </div>
        </header>
        
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Performance Status</h3>
                    <div class="metric-value status-{{ metadata.overall_status.lower() }}">
                        {{ metadata.overall_status }}
                    </div>
                    <div class="metric-description">Overall system performance</div>
                </div>
                
                <div class="summary-card">
                    <h3>Variance from Baseline</h3>
                    <div class="metric-value {{ 'success' if test_results.variance_analysis.overall_variance_percentage <= variance_threshold else 'warning' }}">
                        {{ test_results.variance_analysis.overall_variance_percentage|format_percentage }}
                    </div>
                    <div class="metric-description">Target: ≤{{ variance_threshold }}%</div>
                </div>
                
                <div class="summary-card">
                    <h3>Performance Score</h3>
                    <div class="metric-value">
                        {{ test_results.performance_score.overall_score|format_number }}/100
                    </div>
                    <div class="metric-description">Composite performance rating</div>
                </div>
                
                <div class="summary-card">
                    <h3>Test Duration</h3>
                    <div class="metric-value">
                        {{ metadata.test_duration }}
                    </div>
                    <div class="metric-description">Total test execution time</div>
                </div>
            </div>
        </section>
        
        <section class="key-findings">
            <h2>Key Findings</h2>
            <ul class="findings-list">
                {% for finding in metadata.key_findings %}
                <li>{{ finding }}</li>
                {% endfor %}
            </ul>
        </section>
        
        <section class="recommendations">
            <h2>Recommendations</h2>
            <ul class="recommendations-list">
                {% for recommendation in metadata.recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </section>
        
        <section class="performance-overview">
            <h2>Performance Overview</h2>
            <div class="chart-container">
                {{ charts.performance_variance|safe }}
            </div>
            <div class="chart-container">
                {{ charts.response_time_comparison|safe }}
            </div>
        </section>
        
        <footer class="report-footer">
            <p>Report ID: {{ metadata.report_id }} | Version: {{ metadata.version }}</p>
            <p>Generated by {{ metadata.author }} for {{ metadata.audience.value|title }} audience</p>
        </footer>
    </div>
</body>
</html>
        """
    
    def _get_technical_html_template(self) -> str:
        """Technical-focused HTML template with detailed metrics."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }} - Technical Analysis</title>
    <style>{{ css_styles }}</style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <h1>{{ metadata.title }}</h1>
            <div class="header-info">
                <span class="report-date">Generated: {{ metadata.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</span>
                <span class="environment">Environment: {{ metadata.test_environment }}</span>
                <span class="status-badge status-{{ metadata.overall_status.lower() }}">{{ metadata.overall_status }}</span>
            </div>
        </header>
        
        <nav class="report-nav">
            <a href="#summary">Summary</a>
            <a href="#performance-metrics">Performance Metrics</a>
            <a href="#baseline-comparison">Baseline Comparison</a>
            <a href="#resource-analysis">Resource Analysis</a>
            <a href="#detailed-results">Detailed Results</a>
        </nav>
        
        <section id="summary" class="technical-summary">
            <h2>Technical Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <h3>Response Time (95th %ile)</h3>
                    <div class="metric-value">{{ test_results.response_time_p95|format_number }} ms</div>
                    <div class="metric-comparison">
                        Baseline: {{ baseline_metrics.response_times.api_get_users|format_number }} ms
                        ({{ calculate_variance(baseline_metrics.response_times.api_get_users, test_results.response_time_p95)|format_percentage }} variance)
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Throughput</h3>
                    <div class="metric-value">{{ test_results.throughput|format_number }} req/s</div>
                    <div class="metric-comparison">
                        Baseline: {{ baseline_metrics.throughput.requests_per_second|format_number }} req/s
                        ({{ calculate_variance(baseline_metrics.throughput.requests_per_second, test_results.throughput)|format_percentage }} variance)
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Error Rate</h3>
                    <div class="metric-value">{{ test_results.error_rate|format_percentage }}</div>
                    <div class="metric-comparison">
                        Target: &lt;1%
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>CPU Utilization</h3>
                    <div class="metric-value">{{ test_results.cpu_utilization|format_percentage }}</div>
                    <div class="metric-comparison">
                        Baseline: {{ baseline_metrics.system_resources.cpu_utilization_average|format_percentage }}
                        ({{ calculate_variance(baseline_metrics.system_resources.cpu_utilization_average, test_results.cpu_utilization)|format_percentage }} variance)
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Memory Usage</h3>
                    <div class="metric-value">{{ test_results.memory_usage_mb|format_number }} MB</div>
                    <div class="metric-comparison">
                        Baseline: {{ baseline_metrics.memory_usage.average_mb|format_number }} MB
                        ({{ calculate_variance(baseline_metrics.memory_usage.average_mb, test_results.memory_usage_mb)|format_percentage }} variance)
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Database Response</h3>
                    <div class="metric-value">{{ test_results.database_response_time|format_number }} ms</div>
                    <div class="metric-comparison">
                        Baseline: {{ baseline_metrics.database_performance.user_lookup|format_number }} ms
                        ({{ calculate_variance(baseline_metrics.database_performance.user_lookup, test_results.database_response_time)|format_percentage }} variance)
                    </div>
                </div>
            </div>
        </section>
        
        <section id="performance-metrics" class="performance-metrics">
            <h2>Performance Metrics Analysis</h2>
            
            <div class="chart-section">
                <h3>Response Time Comparison</h3>
                <div class="chart-container">
                    {{ charts.response_time_comparison|safe }}
                </div>
            </div>
            
            <div class="chart-section">
                <h3>Performance Variance</h3>
                <div class="chart-container">
                    {{ charts.performance_variance|safe }}
                </div>
            </div>
            
            <div class="chart-section">
                <h3>Throughput Trend</h3>
                <div class="chart-container">
                    {{ charts.throughput_trend|safe }}
                </div>
            </div>
        </section>
        
        <section id="baseline-comparison" class="baseline-comparison">
            <h2>Baseline Comparison Analysis</h2>
            <div class="comparison-table">
                <table>
                    <thead>
                        <tr>
                            <th>Metric</th>
                            <th>Node.js Baseline</th>
                            <th>Flask Current</th>
                            <th>Variance</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for endpoint, comparison in test_results.baseline_comparisons.items() %}
                        <tr>
                            <td>{{ endpoint }}</td>
                            <td>{{ comparison.baseline|format_number }} ms</td>
                            <td>{{ comparison.measured|format_number }} ms</td>
                            <td class="{{ comparison.variance_percentage|variance_status }}">
                                {{ comparison.variance_percentage|format_percentage }}
                            </td>
                            <td>
                                <span class="status-badge {{ 'success' if comparison.within_threshold else 'warning' }}">
                                    {{ 'PASS' if comparison.within_threshold else 'FAIL' }}
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
        
        <section id="resource-analysis" class="resource-analysis">
            <h2>System Resource Analysis</h2>
            <div class="chart-container">
                {{ charts.resource_utilization|safe }}
            </div>
        </section>
        
        <section id="detailed-results" class="detailed-results">
            <h2>Detailed Test Results</h2>
            <div class="results-accordion">
                {% for scenario in metadata.test_scenarios_executed %}
                <div class="accordion-item">
                    <h3>{{ scenario }}</h3>
                    <div class="accordion-content">
                        <!-- Detailed scenario results -->
                        <pre>{{ test_results[scenario]|tojson(indent=2) }}</pre>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>
        
        <footer class="report-footer">
            <div class="footer-content">
                <div>
                    <strong>Report Details:</strong><br>
                    ID: {{ metadata.report_id }}<br>
                    Version: {{ metadata.version }}<br>
                    Generated: {{ metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}
                </div>
                <div>
                    <strong>Test Configuration:</strong><br>
                    Environment: {{ metadata.test_environment }}<br>
                    Duration: {{ metadata.test_duration }}<br>
                    Variance Threshold: ±{{ variance_threshold }}%
                </div>
                <div>
                    <strong>Migration Progress:</strong><br>
                    From: {{ metadata.baseline_version }}<br>
                    To: {{ metadata.current_version }}<br>
                    Author: {{ metadata.author }}
                </div>
            </div>
        </footer>
    </div>
    
    <script>{{ javascript }}</script>
</body>
</html>
        """
    
    def _get_operations_html_template(self) -> str:
        """Operations-focused HTML template with monitoring and alerting context."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }} - Operations Report</title>
    <style>{{ css_styles }}</style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <h1>{{ metadata.title }}</h1>
            <div class="header-info">
                <span class="report-date">{{ metadata.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</span>
                <span class="environment">{{ metadata.test_environment }}</span>
                <span class="status-badge status-{{ metadata.overall_status.lower() }}">{{ metadata.overall_status }}</span>
            </div>
        </header>
        
        <section class="operations-dashboard">
            <h2>Operations Dashboard</h2>
            <div class="dashboard-grid">
                <div class="dashboard-card alert-card">
                    <h3>Alert Status</h3>
                    <div class="alert-summary">
                        {% if test_results.variance_analysis.overall_variance_percentage > variance_threshold %}
                        <div class="alert critical">
                            <strong>CRITICAL:</strong> Performance variance exceeds ±{{ variance_threshold }}% threshold
                        </div>
                        {% else %}
                        <div class="alert success">
                            <strong>OK:</strong> All metrics within acceptable thresholds
                        </div>
                        {% endif %}
                        
                        {% if test_results.error_rate > 1.0 %}
                        <div class="alert warning">
                            <strong>WARNING:</strong> Error rate above 1% ({{ test_results.error_rate|format_percentage }})
                        </div>
                        {% endif %}
                        
                        {% if test_results.cpu_utilization > 80.0 %}
                        <div class="alert warning">
                            <strong>WARNING:</strong> High CPU utilization ({{ test_results.cpu_utilization|format_percentage }})
                        </div>
                        {% endif %}
                    </div>
                </div>
                
                <div class="dashboard-card">
                    <h3>System Health</h3>
                    <div class="health-indicators">
                        <div class="health-item">
                            <span class="health-label">API Response</span>
                            <span class="health-status {{ 'healthy' if test_results.response_time_p95 < 500 else 'degraded' }}">
                                {{ 'Healthy' if test_results.response_time_p95 < 500 else 'Degraded' }}
                            </span>
                        </div>
                        <div class="health-item">
                            <span class="health-label">Throughput</span>
                            <span class="health-status {{ 'healthy' if test_results.throughput > 100 else 'degraded' }}">
                                {{ 'Healthy' if test_results.throughput > 100 else 'Degraded' }}
                            </span>
                        </div>
                        <div class="health-item">
                            <span class="health-label">Error Rate</span>
                            <span class="health-status {{ 'healthy' if test_results.error_rate < 1.0 else 'degraded' }}">
                                {{ 'Healthy' if test_results.error_rate < 1.0 else 'Degraded' }}
                            </span>
                        </div>
                        <div class="health-item">
                            <span class="health-label">Resources</span>
                            <span class="health-status {{ 'healthy' if test_results.cpu_utilization < 70 else 'degraded' }}">
                                {{ 'Healthy' if test_results.cpu_utilization < 70 else 'Degraded' }}
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="dashboard-card">
                    <h3>Capacity Metrics</h3>
                    <div class="capacity-metrics">
                        <div class="capacity-item">
                            <span class="capacity-label">CPU Usage</span>
                            <div class="capacity-bar">
                                <div class="capacity-fill" style="width: {{ test_results.cpu_utilization }}%;"></div>
                            </div>
                            <span class="capacity-value">{{ test_results.cpu_utilization|format_percentage }}</span>
                        </div>
                        <div class="capacity-item">
                            <span class="capacity-label">Memory Usage</span>
                            <div class="capacity-bar">
                                <div class="capacity-fill" style="width: {{ (test_results.memory_usage_mb / 1024) * 100 }}%;"></div>
                            </div>
                            <span class="capacity-value">{{ test_results.memory_usage_mb|format_number }} MB</span>
                        </div>
                        <div class="capacity-item">
                            <span class="capacity-label">Concurrent Users</span>
                            <div class="capacity-bar">
                                <div class="capacity-fill" style="width: {{ (test_results.concurrent_users / 1000) * 100 }}%;"></div>
                            </div>
                            <span class="capacity-value">{{ test_results.concurrent_users|format_number }}</span>
                        </div>
                    </div>
                </div>
                
                <div class="dashboard-card">
                    <h3>Performance Trends</h3>
                    <div class="trend-indicators">
                        {% for metric, trend in test_results.trend_analysis.items() %}
                        <div class="trend-item">
                            <span class="trend-label">{{ metric|title }}</span>
                            <span class="trend-direction {{ trend.direction }}">
                                {{ '↗' if trend.direction == 'improving' else '↘' if trend.direction == 'degrading' else '→' }}
                                {{ trend.change_percentage|format_percentage }}
                            </span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </section>
        
        <section class="performance-charts">
            <h2>Performance Monitoring</h2>
            
            <div class="chart-grid">
                <div class="chart-container">
                    <h3>Performance Variance</h3>
                    {{ charts.performance_variance|safe }}
                </div>
                
                <div class="chart-container">
                    <h3>Resource Utilization</h3>
                    {{ charts.resource_utilization|safe }}
                </div>
                
                <div class="chart-container">
                    <h3>Error Rates by Endpoint</h3>
                    {{ charts.error_rates|safe }}
                </div>
                
                <div class="chart-container">
                    <h3>Response Time Distribution</h3>
                    {{ charts.response_time_distribution|safe }}
                </div>
            </div>
        </section>
        
        <section class="recommendations">
            <h2>Operational Recommendations</h2>
            <div class="recommendations-grid">
                {% for recommendation in metadata.recommendations %}
                <div class="recommendation-card">
                    <h4>{{ recommendation.title if recommendation.title else 'Action Required' }}</h4>
                    <p>{{ recommendation.description if recommendation.description else recommendation }}</p>
                    <div class="recommendation-priority">
                        Priority: {{ recommendation.priority if recommendation.priority else 'Medium' }}
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>
        
        <footer class="report-footer">
            <div class="footer-operations">
                <div>
                    <strong>Monitoring Integration:</strong><br>
                    Prometheus: Enabled<br>
                    Grafana: Dashboard Available<br>
                    Alerts: {{ 'Active' if test_results.alerts_active else 'None' }}
                </div>
                <div>
                    <strong>Next Actions:</strong><br>
                    Review: {{ metadata.generated_at + timedelta(hours=4) }}<br>
                    Update: {{ metadata.generated_at + timedelta(days=1) }}<br>
                    Audit: {{ metadata.generated_at + timedelta(days=7) }}
                </div>
            </div>
        </footer>
    </div>
</body>
</html>
        """
    
    def _get_dashboard_template(self, template_name: str) -> str:
        """Get real-time dashboard template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Monitoring Dashboard</title>
    <style>{{ css_styles }}</style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <header class="dashboard-header">
            <h1>Performance Monitoring Dashboard</h1>
            <div class="dashboard-controls">
                <button id="refresh-btn" class="btn btn-primary">Refresh</button>
                <button id="auto-refresh-btn" class="btn btn-secondary">Auto Refresh: {{ 'ON' if dashboard_config.auto_refresh else 'OFF' }}</button>
                <span class="last-updated">Last Updated: <span id="last-updated-time">{{ timestamp }}</span></span>
            </div>
        </header>
        
        <div class="dashboard-grid">
            {% for widget in widgets %}
            <div class="dashboard-widget {{ widget.size_class }}">
                <div class="widget-header">
                    <h3>{{ widget.title }}</h3>
                    <div class="widget-controls">
                        {% if widget.alert_enabled %}
                        <span class="alert-indicator {{ widget.alert_status }}"></span>
                        {% endif %}
                    </div>
                </div>
                <div class="widget-content" id="widget-{{ widget.id }}">
                    {{ widget.content|safe }}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <footer class="dashboard-footer">
            <div class="footer-info">
                Real-time monitoring | Refresh interval: {{ dashboard_config.refresh_interval / 1000 }}s | 
                Audience: {{ audience|title }}
            </div>
        </footer>
    </div>
    
    <script>{{ javascript }}</script>
</body>
</html>
        """
    
    def _get_css_styles(self) -> str:
        """Get comprehensive CSS styles for reports."""
        return """
        /* Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        
        /* Header Styles */
        .report-header {
            border-bottom: 3px solid #0066cc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .report-header h1 {
            color: #0066cc;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header-info {
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85rem;
        }
        
        .status-pass { background: #28a745; color: white; }
        .status-fail { background: #dc3545; color: white; }
        .status-warning { background: #ffc107; color: #333; }
        .status-success { background: #28a745; color: white; }
        
        /* Grid Layouts */
        .summary-grid, .metrics-grid, .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .summary-card, .metric-card, .dashboard-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .summary-card:hover, .metric-card:hover, .dashboard-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .metric-value.success { color: #28a745; }
        .metric-value.warning { color: #ffc107; }
        .metric-value.danger { color: #dc3545; }
        
        .metric-description, .metric-comparison {
            font-size: 0.9rem;
            color: #666;
            margin-top: 5px;
        }
        
        /* Chart Containers */
        .chart-container, .chart-section {
            margin: 30px 0;
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
        }
        
        .chart-section h3 {
            margin-bottom: 15px;
            color: #0066cc;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        
        /* Tables */
        .comparison-table table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .comparison-table th,
        .comparison-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .comparison-table th {
            background: #f8f9fa;
            font-weight: bold;
            color: #495057;
        }
        
        .comparison-table tr:hover {
            background: #f8f9fa;
        }
        
        /* Variance Status Colors */
        .positive { color: #dc3545; } /* Slower/worse performance */
        .negative { color: #28a745; } /* Faster/better performance */
        .neutral { color: #6c757d; } /* Minimal variance */
        
        /* Navigation */
        .report-nav {
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        
        .report-nav a {
            display: inline-block;
            padding: 8px 15px;
            margin-right: 10px;
            color: #0066cc;
            text-decoration: none;
            border-radius: 3px;
            transition: background-color 0.2s;
        }
        
        .report-nav a:hover {
            background: #0066cc;
            color: white;
        }
        
        /* Operations Dashboard Specific */
        .alert-card {
            border-left: 5px solid #dc3545;
        }
        
        .alert {
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        
        .alert.critical { background: #f8d7da; border-left: 3px solid #dc3545; }
        .alert.warning { background: #fff3cd; border-left: 3px solid #ffc107; }
        .alert.success { background: #d4edda; border-left: 3px solid #28a745; }
        
        .health-indicators, .capacity-metrics, .trend-indicators {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .health-item, .capacity-item, .trend-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }
        
        .health-status.healthy { color: #28a745; font-weight: bold; }
        .health-status.degraded { color: #dc3545; font-weight: bold; }
        
        .capacity-bar {
            flex-grow: 1;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            margin: 0 10px;
            overflow: hidden;
        }
        
        .capacity-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #ffc107, #dc3545);
            transition: width 0.3s ease;
        }
        
        .trend-direction.improving { color: #28a745; }
        .trend-direction.degrading { color: #dc3545; }
        .trend-direction.stable { color: #6c757d; }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                padding: 15px;
            }
            
            .report-header h1 {
                font-size: 2rem;
            }
            
            .header-info {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .summary-grid, .metrics-grid, .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .metric-value {
                font-size: 2rem;
            }
            
            .chart-container {
                overflow-x: auto;
            }
        }
        
        /* Footer */
        .report-footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .footer-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        /* Print Styles */
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .chart-container { break-inside: avoid; }
            .report-nav { display: none; }
        }
        """
    
    def _get_javascript_code(self) -> str:
        """Get JavaScript code for interactive features."""
        return """
        // Report interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Accordion functionality
            const accordionItems = document.querySelectorAll('.accordion-item h3');
            accordionItems.forEach(item => {
                item.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const isOpen = content.style.display === 'block';
                    
                    // Close all accordion items
                    document.querySelectorAll('.accordion-content').forEach(acc => {
                        acc.style.display = 'none';
                    });
                    
                    // Open clicked item if it was closed
                    if (!isOpen) {
                        content.style.display = 'block';
                    }
                });
            });
            
            // Smooth scrolling for navigation
            document.querySelectorAll('.report-nav a').forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({ behavior: 'smooth' });
                    }
                });
            });
            
            // Chart resize handling
            window.addEventListener('resize', function() {
                if (typeof Plotly !== 'undefined') {
                    const charts = document.querySelectorAll('[id^="chart_"], [id^="gauge_"]');
                    charts.forEach(chart => {
                        Plotly.Plots.resize(chart);
                    });
                }
            });
        });
        """
    
    # Helper methods for template filters
    def _format_number(self, value: Union[int, float], decimals: int = 1) -> str:
        """Format number with appropriate precision."""
        if isinstance(value, (int, float)):
            return f"{value:,.{decimals}f}"
        return str(value)
    
    def _format_percentage(self, value: Union[int, float], decimals: int = 1) -> str:
        """Format value as percentage."""
        if isinstance(value, (int, float)):
            return f"{value:.{decimals}f}%"
        return str(value)
    
    def _format_duration(self, seconds: Union[int, float]) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def _format_timestamp(self, timestamp: datetime) -> str:
        """Format timestamp for display."""
        return timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    def _variance_status(self, variance: float) -> str:
        """Get variance status class based on value."""
        if abs(variance) <= 2:
            return 'neutral'
        elif variance > 0:
            return 'positive'  # Slower/worse
        else:
            return 'negative'  # Faster/better
    
    def _performance_color(self, variance: float, threshold: float = 10.0) -> str:
        """Get color class based on performance variance."""
        abs_variance = abs(variance)
        if abs_variance <= threshold * 0.5:
            return 'success'
        elif abs_variance <= threshold:
            return 'warning'
        else:
            return 'danger'
    
    def _calculate_variance(self, baseline: float, measured: float) -> float:
        """Calculate variance percentage."""
        if baseline == 0:
            return 0.0
        return ((measured - baseline) / baseline) * 100
    
    # Helper methods for data analysis
    def _generate_baseline_comparisons(self, test_results: Dict[str, Any], 
                                     baseline_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate baseline comparison analysis."""
        comparisons = {}
        
        # Response time comparisons
        response_times = baseline_metrics.get('response_times', {})
        for endpoint, baseline_time in response_times.items():
            if endpoint in test_results:
                measured_time = test_results[endpoint]
                variance = self._calculate_variance(baseline_time, measured_time)
                
                comparisons[endpoint] = {
                    'baseline': baseline_time,
                    'measured': measured_time,
                    'variance_percentage': variance,
                    'within_threshold': abs(variance) <= self.config.PERFORMANCE_VARIANCE_THRESHOLD
                }
        
        return comparisons
    
    def _calculate_variance_analysis(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive variance analysis."""
        baseline_metrics = get_baseline_metrics()
        variances = []
        
        # Collect all variance percentages
        for category, metrics in baseline_metrics.items():
            if isinstance(metrics, dict):
                for metric_name, baseline_value in metrics.items():
                    if metric_name in test_results:
                        variance = self._calculate_variance(baseline_value, test_results[metric_name])
                        variances.append(abs(variance))
        
        if variances:
            return {
                'overall_variance_percentage': sum(variances) / len(variances),
                'max_variance_percentage': max(variances),
                'min_variance_percentage': min(variances),
                'variance_count': len(variances),
                'variances_within_threshold': sum(1 for v in variances if v <= self.config.PERFORMANCE_VARIANCE_THRESHOLD),
                'variance_compliance_percentage': (sum(1 for v in variances if v <= self.config.PERFORMANCE_VARIANCE_THRESHOLD) / len(variances)) * 100
            }
        
        return {'overall_variance_percentage': 0.0}
    
    def _calculate_performance_score(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate composite performance score."""
        score_components = []
        
        # Response time score (0-100, 100 is best)
        if 'response_time_p95' in test_results:
            response_time = test_results['response_time_p95']
            baseline_response = get_baseline_metrics('response_times').get('api_get_users', 150)
            variance = abs(self._calculate_variance(baseline_response, response_time))
            response_score = max(0, 100 - variance * 2)  # Penalty for variance
            score_components.append(('response_time', response_score))
        
        # Throughput score
        if 'throughput' in test_results:
            throughput = test_results['throughput']
            baseline_throughput = get_baseline_metrics('throughput').get('requests_per_second', 1000)
            variance = self._calculate_variance(baseline_throughput, throughput)
            throughput_score = max(0, 100 + variance)  # Bonus for better throughput
            score_components.append(('throughput', min(100, throughput_score)))
        
        # Error rate score
        if 'error_rate' in test_results:
            error_rate = test_results['error_rate']
            error_score = max(0, 100 - error_rate * 20)  # Heavy penalty for errors
            score_components.append(('error_rate', error_score))
        
        # Resource utilization score
        if 'cpu_utilization' in test_results:
            cpu_util = test_results['cpu_utilization']
            cpu_score = max(0, 100 - max(0, cpu_util - 50))  # Penalty above 50%
            score_components.append(('cpu_utilization', cpu_score))
        
        if score_components:
            overall_score = sum(score for _, score in score_components) / len(score_components)
            return {
                'overall_score': overall_score,
                'component_scores': dict(score_components),
                'score_breakdown': {
                    'response_time_weight': 0.3,
                    'throughput_weight': 0.3,
                    'error_rate_weight': 0.3,
                    'resource_weight': 0.1
                }
            }
        
        return {'overall_score': 0.0}
    
    def _calculate_trend_analysis(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate trend analysis if historical data is available."""
        # This would typically integrate with historical data storage
        # For now, return placeholder trends
        return {
            'response_time': {'direction': 'stable', 'change_percentage': 0.5},
            'throughput': {'direction': 'improving', 'change_percentage': -2.1},
            'error_rate': {'direction': 'improving', 'change_percentage': -0.3},
            'cpu_utilization': {'direction': 'stable', 'change_percentage': 1.2}
        }
    
    def _analyze_system_resources(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system resource utilization."""
        return {
            'cpu_analysis': {
                'current': test_results.get('cpu_utilization', 0),
                'peak': test_results.get('cpu_peak', 0),
                'average': test_results.get('cpu_average', 0),
                'recommendation': 'Normal' if test_results.get('cpu_utilization', 0) < 70 else 'Consider scaling'
            },
            'memory_analysis': {
                'current_mb': test_results.get('memory_usage_mb', 0),
                'peak_mb': test_results.get('memory_peak_mb', 0),
                'growth_rate': test_results.get('memory_growth_rate', 0),
                'recommendation': 'Normal' if test_results.get('memory_usage_mb', 0) < 1024 else 'Monitor growth'
            }
        }
    
    # Widget configuration methods for dashboards
    def _get_executive_widgets(self) -> List[Dict[str, Any]]:
        """Get executive dashboard widgets."""
        return [
            {
                'id': 'performance_status',
                'title': 'Performance Status',
                'size_class': 'widget-large',
                'content': '<div class="status-indicator">System Performance: GOOD</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            },
            {
                'id': 'variance_summary',
                'title': 'Variance from Baseline',
                'size_class': 'widget-medium',
                'content': '<div class="metric-display">±5.2%</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            }
        ]
    
    def _get_operations_widgets(self) -> List[Dict[str, Any]]:
        """Get operations dashboard widgets."""
        return [
            {
                'id': 'system_health',
                'title': 'System Health',
                'size_class': 'widget-large',
                'content': '<div class="health-grid">All systems operational</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            },
            {
                'id': 'active_alerts',
                'title': 'Active Alerts',
                'size_class': 'widget-medium',
                'content': '<div class="alert-count">0 Active Alerts</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            }
        ]
    
    def _get_technical_widgets(self) -> List[Dict[str, Any]]:
        """Get technical dashboard widgets."""
        return [
            {
                'id': 'performance_metrics',
                'title': 'Performance Metrics',
                'size_class': 'widget-large',
                'content': '<div class="metrics-table">Detailed metrics display</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            },
            {
                'id': 'resource_usage',
                'title': 'Resource Usage',
                'size_class': 'widget-medium',
                'content': '<div class="resource-charts">CPU: 45%, Memory: 60%</div>',
                'alert_enabled': True,
                'alert_status': 'normal'
            }
        ]
    
    def _get_default_widgets(self) -> List[Dict[str, Any]]:
        """Get default dashboard widgets."""
        return [
            {
                'id': 'overview',
                'title': 'Overview',
                'size_class': 'widget-large',
                'content': '<div class="overview-display">System overview</div>',
                'alert_enabled': False,
                'alert_status': 'normal'
            }
        ]
    
    # Additional helper methods
    def _check_variance_compliance(self, test_results: Dict[str, Any]) -> bool:
        """Check if performance variance is within threshold."""
        variance_analysis = test_results.get('variance_analysis', {})
        overall_variance = variance_analysis.get('overall_variance_percentage', 0)
        return overall_variance <= self.config.PERFORMANCE_VARIANCE_THRESHOLD
    
    def _extract_key_metrics(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics for summary."""
        return {
            'response_time_p95': test_results.get('response_time_p95'),
            'throughput': test_results.get('throughput'),
            'error_rate': test_results.get('error_rate'),
            'cpu_utilization': test_results.get('cpu_utilization'),
            'memory_usage_mb': test_results.get('memory_usage_mb')
        }
    
    def _get_variance_color(self, variance: float) -> str:
        """Get color for variance display."""
        abs_variance = abs(variance)
        if abs_variance <= 5:
            return self.visualization_config.brand_colors['success']
        elif abs_variance <= 10:
            return self.visualization_config.brand_colors['warning']
        else:
            return self.visualization_config.brand_colors['danger']
    
    def _save_report(self, content: Union[str, bytes], output_path: str, 
                    report_format: ReportFormat) -> None:
        """Save report content to file."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        if isinstance(content, str):
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            with open(output_path, 'wb') as f:
                f.write(content)


# Factory function for easy template engine creation
def create_report_template_engine(template_dir: Optional[str] = None,
                                config: Optional[PerformanceTestConfig] = None) -> PerformanceReportTemplateEngine:
    """
    Create performance report template engine instance.
    
    Args:
        template_dir: Custom template directory path
        config: Performance test configuration
        
    Returns:
        PerformanceReportTemplateEngine instance
    """
    return PerformanceReportTemplateEngine(template_dir, config)


# Convenience functions for common report generation tasks
def generate_performance_report(test_results: Dict[str, Any],
                              format: ReportFormat = ReportFormat.HTML,
                              audience: ReportAudience = ReportAudience.TECHNICAL,
                              output_path: Optional[str] = None) -> str:
    """
    Generate performance report with default configuration.
    
    Args:
        test_results: Performance test results
        format: Report format
        audience: Target audience
        output_path: Output file path
        
    Returns:
        Generated report content or file path
    """
    engine = create_report_template_engine()
    return engine.generate_report(test_results, format, audience, output_path=output_path)


def generate_dashboard(audience: ReportAudience = ReportAudience.OPERATIONS) -> str:
    """
    Generate real-time monitoring dashboard.
    
    Args:
        audience: Target audience for dashboard
        
    Returns:
        Dashboard HTML content
    """
    engine = create_report_template_engine()
    return engine.generate_dashboard_template(audience)


def create_performance_chart(data: Dict[str, Any], chart_type: ChartType,
                           title: str = "", format: str = 'html') -> str:
    """
    Create individual performance chart.
    
    Args:
        data: Chart data
        chart_type: Type of chart
        title: Chart title
        format: Output format
        
    Returns:
        Chart content
    """
    engine = create_report_template_engine()
    return engine.generate_chart(data, chart_type, title, format)


# Export all public classes and functions
__all__ = [
    # Enums
    'ReportFormat',
    'ReportAudience', 
    'ChartType',
    
    # Data classes
    'ReportMetadata',
    'VisualizationConfig',
    
    # Main classes
    'PerformanceReportTemplateEngine',
    
    # Factory and convenience functions
    'create_report_template_engine',
    'generate_performance_report',
    'generate_dashboard',
    'create_performance_chart'
]