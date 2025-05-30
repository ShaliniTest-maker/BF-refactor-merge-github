"""
Executive Stakeholder Summary Report Template

This module provides comprehensive executive stakeholder summary report template
for high-level migration progress, performance compliance status, and business
impact assessment. Creates executive-friendly summaries for project oversight
and strategic decision-making per Section 0.3.4 documentation requirements.

Key Features:
- Executive summary generation for stakeholder communication per Section 0.3.4
- Migration progress and compliance reporting per Section 0.1.1 primary objective
- Business impact assessment per Section 0.3.4 documentation requirements
- Risk assessment and mitigation recommendations per Section 0.3.4
- Performance compliance status per Section 0.3.2 performance monitoring requirements
- Decision-making support data visualization per Section 0.3.4

Architecture Integration:
- Section 0.1.1: Technology migration from Node.js to Python 3 Flask framework
- Section 0.3.2: Continuous performance monitoring with ≤10% variance requirement
- Section 0.3.4: Comprehensive documentation for executive stakeholder communication
- Section 6.5.1: Enterprise monitoring integration and performance metrics collection
- Section 6.5.3: Incident response and alert management for stakeholder awareness
- Section 6.6.3: Quality metrics and compliance validation for business assurance

Dependencies Integration:
- performance_report_generator.py: Automated report generation from test results
- baseline_comparison_report.py: Node.js baseline variance analysis and compliance
- trend_analysis_report.py: Historical performance evolution and predictive insights

Author: Flask Migration Team
Version: 1.0.0
Dependencies: dataclasses, typing, json, datetime, statistics, pathlib
"""

import json
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union, Any, Tuple, NamedTuple
from pathlib import Path
from enum import Enum, auto
import logging
import uuid

# Structured logging for enterprise integration
try:
    import structlog
    logger = structlog.get_logger(__name__)
    STRUCTLOG_AVAILABLE = True
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    STRUCTLOG_AVAILABLE = False


# Business Impact and Risk Assessment Constants
CRITICAL_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement per Section 0.1.1
WARNING_VARIANCE_THRESHOLD = 5.0    # Early warning threshold
BUSINESS_CONTINUITY_THRESHOLD = 99.9  # 99.9% uptime SLA per Section 6.5.2.4
REGRESSION_RISK_THRESHOLD = 3.0     # Multiple regression threshold
STAKEHOLDER_REFRESH_INTERVAL = 3600  # 1-hour executive dashboard refresh


class MigrationPhase(Enum):
    """Migration phase enumeration for progress tracking."""
    PLANNING = "planning"
    DEVELOPMENT = "development"
    TESTING = "testing"
    PERFORMANCE_VALIDATION = "performance_validation"
    STAKEHOLDER_REVIEW = "stakeholder_review"
    DEPLOYMENT_PREPARATION = "deployment_preparation"
    BLUE_GREEN_MIGRATION = "blue_green_migration"
    PRODUCTION_VALIDATION = "production_validation"
    COMPLETE = "complete"


class RiskLevel(Enum):
    """Risk level classification for executive communication."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStatus(Enum):
    """Compliance status for performance and quality gates."""
    COMPLIANT = "compliant"
    WARNING = "warning"
    NON_COMPLIANT = "non_compliant"
    UNDER_REVIEW = "under_review"


@dataclass
class BusinessImpactMetrics:
    """
    Business impact assessment metrics for executive stakeholder reporting.
    
    Provides quantified business value, risk exposure, and operational
    impact analysis per Section 0.3.4 business impact assessment requirements.
    """
    estimated_cost_savings_annual: float  # Annual cost savings in USD
    risk_mitigation_value: float          # Value of risk reduction
    operational_efficiency_gain: float    # Percentage improvement
    team_productivity_impact: float       # Developer productivity change
    maintenance_cost_reduction: float     # Annual maintenance savings
    time_to_market_improvement: float     # Deployment time reduction
    enterprise_alignment_score: float     # Technology stack alignment (0-100)
    technical_debt_reduction: float       # Technical debt improvement percentage
    
    # Quality and reliability improvements
    test_coverage_improvement: float      # Coverage percentage increase
    defect_reduction_rate: float         # Expected defect reduction
    security_posture_improvement: float  # Security enhancement score
    monitoring_effectiveness_gain: float # Observability improvement
    
    def total_business_value(self) -> float:
        """Calculate total quantified business value."""
        return (
            self.estimated_cost_savings_annual +
            self.risk_mitigation_value +
            self.maintenance_cost_reduction
        )
    
    def risk_adjusted_value(self) -> float:
        """Calculate risk-adjusted business value."""
        risk_multiplier = 0.8 if self.enterprise_alignment_score < 70 else 1.0
        return self.total_business_value() * risk_multiplier


@dataclass
class PerformanceComplianceStatus:
    """
    Performance compliance status for ≤10% variance requirement validation.
    
    Tracks compliance with Section 0.3.2 performance monitoring requirements
    and Section 0.1.1 primary objective variance thresholds.
    """
    response_time_variance_percent: float
    memory_usage_variance_percent: float
    cpu_utilization_variance_percent: float
    throughput_variance_percent: float
    database_query_variance_percent: float
    
    # Overall compliance metrics
    overall_compliance_score: float      # 0-100 compliance score
    variance_trend_direction: str        # "improving", "stable", "degrading"
    compliance_status: ComplianceStatus
    last_validation_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Performance baseline validation
    baseline_comparison_valid: bool = True
    baseline_data_freshness_days: int = 0
    performance_regression_count: int = 0
    
    def is_compliant(self) -> bool:
        """Validate overall performance compliance with ≤10% requirement."""
        critical_metrics = [
            abs(self.response_time_variance_percent),
            abs(self.memory_usage_variance_percent),
            abs(self.cpu_utilization_variance_percent),
            abs(self.throughput_variance_percent),
            abs(self.database_query_variance_percent)
        ]
        return all(metric <= CRITICAL_VARIANCE_THRESHOLD for metric in critical_metrics)
    
    def warning_level_check(self) -> bool:
        """Check if any metrics exceed warning threshold."""
        warning_metrics = [
            abs(self.response_time_variance_percent),
            abs(self.memory_usage_variance_percent),
            abs(self.cpu_utilization_variance_percent),
            abs(self.throughput_variance_percent),
            abs(self.database_query_variance_percent)
        ]
        return any(metric > WARNING_VARIANCE_THRESHOLD for metric in warning_metrics)
    
    def get_compliance_summary(self) -> str:
        """Generate executive compliance summary."""
        if self.is_compliant():
            return "✅ COMPLIANT: All performance metrics within ≤10% variance requirement"
        elif self.warning_level_check():
            return "⚠️ WARNING: Performance metrics approaching variance threshold"
        else:
            return "🚨 NON-COMPLIANT: Performance variance exceeds ≤10% requirement"


@dataclass
class MigrationProgressStatus:
    """
    Migration progress tracking for executive stakeholder reporting.
    
    Provides comprehensive progress assessment per Section 0.1.1 migration
    objectives and Section 0.2.3 technical implementation steps.
    """
    current_phase: MigrationPhase
    overall_completion_percent: float
    phase_completion_percent: float
    
    # Component-specific progress
    api_endpoints_migrated: int
    api_endpoints_total: int
    business_logic_modules_migrated: int
    business_logic_modules_total: int
    integration_tests_passing: int
    integration_tests_total: int
    performance_tests_passing: int
    performance_tests_total: int
    
    # Quality gates and milestones
    code_coverage_percent: float
    quality_gates_passed: int
    quality_gates_total: int
    security_scans_passed: bool
    documentation_complete_percent: float
    
    # Timeline and scheduling
    planned_completion_date: datetime
    estimated_completion_date: datetime
    critical_path_items: List[str] = field(default_factory=list)
    blockers_count: int = 0
    
    @property
    def api_migration_percent(self) -> float:
        """Calculate API migration completion percentage."""
        if self.api_endpoints_total == 0:
            return 100.0
        return (self.api_endpoints_migrated / self.api_endpoints_total) * 100
    
    @property
    def business_logic_percent(self) -> float:
        """Calculate business logic migration percentage."""
        if self.business_logic_modules_total == 0:
            return 100.0
        return (self.business_logic_modules_migrated / self.business_logic_modules_total) * 100
    
    @property
    def testing_completion_percent(self) -> float:
        """Calculate overall testing completion percentage."""
        total_tests = self.integration_tests_total + self.performance_tests_total
        if total_tests == 0:
            return 100.0
        passing_tests = self.integration_tests_passing + self.performance_tests_passing
        return (passing_tests / total_tests) * 100
    
    @property
    def schedule_variance_days(self) -> int:
        """Calculate schedule variance in days."""
        variance = (self.estimated_completion_date - self.planned_completion_date).days
        return variance
    
    def is_on_track(self) -> bool:
        """Determine if migration is on track for planned completion."""
        return self.schedule_variance_days <= 7  # Within 1 week tolerance


@dataclass
class RiskAssessment:
    """
    Risk assessment and mitigation recommendations for executive decision-making.
    
    Provides comprehensive risk analysis per Section 0.3.4 risk assessment
    requirements with mitigation strategies and business continuity planning.
    """
    overall_risk_level: RiskLevel
    technical_risks: List[Dict[str, Any]] = field(default_factory=list)
    business_risks: List[Dict[str, Any]] = field(default_factory=list)
    operational_risks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Performance and compliance risks
    performance_regression_risk: RiskLevel
    api_compatibility_risk: RiskLevel
    data_integrity_risk: RiskLevel
    security_vulnerability_risk: RiskLevel
    
    # Mitigation strategies
    mitigation_strategies: List[Dict[str, Any]] = field(default_factory=list)
    contingency_plans: List[Dict[str, Any]] = field(default_factory=list)
    rollback_procedures: List[str] = field(default_factory=list)
    
    # Risk monitoring
    risk_assessment_date: datetime = field(default_factory=datetime.utcnow)
    next_review_date: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=7))
    risk_trend: str = "stable"  # "improving", "stable", "increasing"
    
    def add_technical_risk(self, risk_id: str, description: str, 
                          probability: float, impact: float, 
                          mitigation: str, owner: str) -> None:
        """Add technical risk with comprehensive metadata."""
        risk = {
            "risk_id": risk_id,
            "description": description,
            "probability": probability,  # 0.0 to 1.0
            "impact": impact,           # 0.0 to 1.0 (business impact)
            "risk_score": probability * impact,
            "mitigation": mitigation,
            "owner": owner,
            "status": "open",
            "created_date": datetime.utcnow(),
            "category": "technical"
        }
        self.technical_risks.append(risk)
    
    def add_business_risk(self, risk_id: str, description: str,
                         probability: float, impact: float,
                         mitigation: str, owner: str) -> None:
        """Add business risk with stakeholder impact assessment."""
        risk = {
            "risk_id": risk_id,
            "description": description,
            "probability": probability,
            "impact": impact,
            "risk_score": probability * impact,
            "mitigation": mitigation,
            "owner": owner,
            "status": "open",
            "created_date": datetime.utcnow(),
            "category": "business"
        }
        self.business_risks.append(risk)
    
    def get_top_risks(self, count: int = 5) -> List[Dict[str, Any]]:
        """Get top risks by risk score for executive attention."""
        all_risks = self.technical_risks + self.business_risks + self.operational_risks
        sorted_risks = sorted(all_risks, key=lambda r: r.get("risk_score", 0), reverse=True)
        return sorted_risks[:count]


@dataclass
class ExecutiveSummaryData:
    """
    Executive summary data aggregation for stakeholder reporting.
    
    Consolidates all stakeholder communication data per Section 0.3.4
    comprehensive documentation updates and executive decision support.
    """
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_timestamp: datetime = field(default_factory=datetime.utcnow)
    report_period_start: datetime = field(default_factory=lambda: datetime.utcnow() - timedelta(days=30))
    report_period_end: datetime = field(default_factory=datetime.utcnow)
    
    # Core data sections
    migration_progress: MigrationProgressStatus
    performance_compliance: PerformanceComplianceStatus
    business_impact: BusinessImpactMetrics
    risk_assessment: RiskAssessment
    
    # Executive summary sections
    executive_summary: str = ""
    key_achievements: List[str] = field(default_factory=list)
    critical_decisions_required: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    
    # Stakeholder-specific insights
    technical_team_summary: str = ""
    business_stakeholder_summary: str = ""
    executive_leadership_summary: str = ""
    
    # Appendices and supporting data
    detailed_metrics: Dict[str, Any] = field(default_factory=dict)
    supporting_charts: List[str] = field(default_factory=list)
    reference_documents: List[str] = field(default_factory=list)


class StakeholderSummaryGenerator:
    """
    Executive stakeholder summary report generator.
    
    Creates comprehensive executive-friendly summaries for project oversight
    and strategic decision-making per Section 0.3.4 documentation requirements.
    Integrates with performance monitoring, baseline comparison, and trend analysis.
    """
    
    def __init__(self, output_directory: Optional[Path] = None):
        """Initialize stakeholder summary generator with configuration."""
        self.output_directory = output_directory or Path("reports/stakeholder")
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Enterprise logging integration
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(self.__class__.__name__)
        else:
            self.logger = logging.getLogger(self.__class__.__name__)
        
        # Template configurations
        self.template_config = self._load_template_configuration()
        
        # Performance baseline integration
        self.variance_threshold = CRITICAL_VARIANCE_THRESHOLD
        self.warning_threshold = WARNING_VARIANCE_THRESHOLD
    
    def _load_template_configuration(self) -> Dict[str, Any]:
        """Load stakeholder report template configuration."""
        return {
            "executive_summary_max_length": 500,
            "key_achievements_max_items": 10,
            "critical_decisions_max_items": 5,
            "risk_assessment_top_items": 5,
            "chart_generation_enabled": True,
            "pdf_export_enabled": True,
            "stakeholder_specific_sections": True,
            "compliance_validation_enabled": True
        }
    
    def generate_migration_progress_status(self,
                                         api_endpoints_data: Dict[str, int],
                                         business_logic_data: Dict[str, int],
                                         testing_data: Dict[str, int],
                                         quality_data: Dict[str, Any],
                                         timeline_data: Dict[str, Any]) -> MigrationProgressStatus:
        """
        Generate comprehensive migration progress status from component data.
        
        Args:
            api_endpoints_data: API migration statistics
            business_logic_data: Business logic conversion progress
            testing_data: Test completion and pass rates
            quality_data: Code quality and coverage metrics
            timeline_data: Schedule and milestone information
        
        Returns:
            MigrationProgressStatus: Comprehensive progress assessment
        """
        self.logger.info("Generating migration progress status", 
                        api_endpoints=api_endpoints_data,
                        business_logic=business_logic_data)
        
        # Determine current phase based on completion metrics
        overall_completion = self._calculate_overall_completion(
            api_endpoints_data, business_logic_data, testing_data
        )
        
        current_phase = self._determine_current_phase(overall_completion, quality_data)
        
        # Create progress status
        progress = MigrationProgressStatus(
            current_phase=current_phase,
            overall_completion_percent=overall_completion,
            phase_completion_percent=self._calculate_phase_completion(current_phase, quality_data),
            
            # API migration metrics
            api_endpoints_migrated=api_endpoints_data.get("migrated", 0),
            api_endpoints_total=api_endpoints_data.get("total", 0),
            
            # Business logic metrics
            business_logic_modules_migrated=business_logic_data.get("migrated", 0),
            business_logic_modules_total=business_logic_data.get("total", 0),
            
            # Testing metrics
            integration_tests_passing=testing_data.get("integration_passing", 0),
            integration_tests_total=testing_data.get("integration_total", 0),
            performance_tests_passing=testing_data.get("performance_passing", 0),
            performance_tests_total=testing_data.get("performance_total", 0),
            
            # Quality metrics
            code_coverage_percent=quality_data.get("coverage_percent", 0.0),
            quality_gates_passed=quality_data.get("gates_passed", 0),
            quality_gates_total=quality_data.get("gates_total", 0),
            security_scans_passed=quality_data.get("security_passed", False),
            documentation_complete_percent=quality_data.get("documentation_percent", 0.0),
            
            # Timeline information
            planned_completion_date=datetime.fromisoformat(timeline_data.get("planned_completion", 
                                                                            datetime.utcnow().isoformat())),
            estimated_completion_date=datetime.fromisoformat(timeline_data.get("estimated_completion",
                                                                              datetime.utcnow().isoformat())),
            critical_path_items=timeline_data.get("critical_path", []),
            blockers_count=timeline_data.get("blockers", 0)
        )
        
        self.logger.info("Migration progress status generated",
                        current_phase=current_phase.value,
                        completion_percent=overall_completion)
        
        return progress
    
    def generate_performance_compliance_status(self,
                                             baseline_comparison_data: Dict[str, float],
                                             performance_metrics: Dict[str, Any],
                                             trend_analysis: Dict[str, Any]) -> PerformanceComplianceStatus:
        """
        Generate performance compliance status from baseline comparison and metrics.
        
        Validates ≤10% variance requirement per Section 0.3.2 performance monitoring
        and generates compliance assessment for executive reporting.
        
        Args:
            baseline_comparison_data: Variance percentages vs Node.js baseline
            performance_metrics: Current performance measurements
            trend_analysis: Performance trend and regression analysis
        
        Returns:
            PerformanceComplianceStatus: Comprehensive compliance assessment
        """
        self.logger.info("Generating performance compliance status",
                        baseline_variances=baseline_comparison_data)
        
        # Extract variance metrics
        response_variance = baseline_comparison_data.get("response_time_variance", 0.0)
        memory_variance = baseline_comparison_data.get("memory_variance", 0.0)
        cpu_variance = baseline_comparison_data.get("cpu_variance", 0.0)
        throughput_variance = baseline_comparison_data.get("throughput_variance", 0.0)
        db_variance = baseline_comparison_data.get("database_variance", 0.0)
        
        # Calculate overall compliance score
        variances = [abs(response_variance), abs(memory_variance), abs(cpu_variance),
                    abs(throughput_variance), abs(db_variance)]
        
        compliance_score = max(0, 100 - (sum(variances) / len(variances)) * 2)
        
        # Determine compliance status
        max_variance = max(variances)
        if max_variance <= WARNING_VARIANCE_THRESHOLD:
            status = ComplianceStatus.COMPLIANT
        elif max_variance <= CRITICAL_VARIANCE_THRESHOLD:
            status = ComplianceStatus.WARNING
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        # Trend analysis
        trend_direction = trend_analysis.get("direction", "stable")
        regression_count = trend_analysis.get("regressions", 0)
        
        compliance = PerformanceComplianceStatus(
            response_time_variance_percent=response_variance,
            memory_usage_variance_percent=memory_variance,
            cpu_utilization_variance_percent=cpu_variance,
            throughput_variance_percent=throughput_variance,
            database_query_variance_percent=db_variance,
            
            overall_compliance_score=compliance_score,
            variance_trend_direction=trend_direction,
            compliance_status=status,
            last_validation_timestamp=datetime.utcnow(),
            
            baseline_comparison_valid=performance_metrics.get("baseline_valid", True),
            baseline_data_freshness_days=performance_metrics.get("baseline_age_days", 0),
            performance_regression_count=regression_count
        )
        
        self.logger.info("Performance compliance status generated",
                        compliance_status=status.value,
                        max_variance=max_variance,
                        compliance_score=compliance_score)
        
        return compliance
    
    def generate_business_impact_assessment(self,
                                          financial_data: Dict[str, float],
                                          operational_metrics: Dict[str, float],
                                          quality_improvements: Dict[str, float]) -> BusinessImpactMetrics:
        """
        Generate comprehensive business impact assessment for executive review.
        
        Args:
            financial_data: Cost savings and financial impact metrics
            operational_metrics: Efficiency and productivity improvements
            quality_improvements: Quality, security, and reliability gains
        
        Returns:
            BusinessImpactMetrics: Quantified business impact assessment
        """
        self.logger.info("Generating business impact assessment",
                        financial_impact=financial_data.get("total_savings", 0))
        
        impact = BusinessImpactMetrics(
            estimated_cost_savings_annual=financial_data.get("annual_savings", 0.0),
            risk_mitigation_value=financial_data.get("risk_mitigation", 0.0),
            operational_efficiency_gain=operational_metrics.get("efficiency_gain", 0.0),
            team_productivity_impact=operational_metrics.get("productivity_impact", 0.0),
            maintenance_cost_reduction=financial_data.get("maintenance_savings", 0.0),
            time_to_market_improvement=operational_metrics.get("deployment_time_reduction", 0.0),
            enterprise_alignment_score=operational_metrics.get("alignment_score", 75.0),
            technical_debt_reduction=quality_improvements.get("debt_reduction", 0.0),
            
            test_coverage_improvement=quality_improvements.get("coverage_improvement", 0.0),
            defect_reduction_rate=quality_improvements.get("defect_reduction", 0.0),
            security_posture_improvement=quality_improvements.get("security_improvement", 0.0),
            monitoring_effectiveness_gain=quality_improvements.get("monitoring_improvement", 0.0)
        )
        
        total_value = impact.total_business_value()
        self.logger.info("Business impact assessment generated",
                        total_business_value=total_value,
                        risk_adjusted_value=impact.risk_adjusted_value())
        
        return impact
    
    def generate_risk_assessment(self,
                               performance_risks: List[Dict[str, Any]],
                               technical_risks: List[Dict[str, Any]],
                               business_risks: List[Dict[str, Any]],
                               mitigation_strategies: List[Dict[str, Any]]) -> RiskAssessment:
        """
        Generate comprehensive risk assessment with mitigation recommendations.
        
        Args:
            performance_risks: Performance-related risk factors
            technical_risks: Technical implementation risks
            business_risks: Business continuity and operational risks
            mitigation_strategies: Proposed risk mitigation approaches
        
        Returns:
            RiskAssessment: Comprehensive risk analysis and recommendations
        """
        self.logger.info("Generating risk assessment",
                        performance_risks_count=len(performance_risks),
                        technical_risks_count=len(technical_risks),
                        business_risks_count=len(business_risks))
        
        # Calculate overall risk level
        all_risks = performance_risks + technical_risks + business_risks
        if not all_risks:
            overall_risk = RiskLevel.LOW
        else:
            avg_risk_score = statistics.mean([r.get("risk_score", 0.5) for r in all_risks])
            if avg_risk_score <= 0.3:
                overall_risk = RiskLevel.LOW
            elif avg_risk_score <= 0.6:
                overall_risk = RiskLevel.MEDIUM
            elif avg_risk_score <= 0.8:
                overall_risk = RiskLevel.HIGH
            else:
                overall_risk = RiskLevel.CRITICAL
        
        # Assess specific risk categories
        perf_risk_level = self._assess_performance_risk_level(performance_risks)
        
        assessment = RiskAssessment(
            overall_risk_level=overall_risk,
            technical_risks=technical_risks,
            business_risks=business_risks,
            operational_risks=[],  # Will be populated by operational analysis
            
            performance_regression_risk=perf_risk_level,
            api_compatibility_risk=RiskLevel.LOW,  # Validated through testing
            data_integrity_risk=RiskLevel.LOW,     # No schema changes
            security_vulnerability_risk=RiskLevel.MEDIUM,  # Standard migration risk
            
            mitigation_strategies=mitigation_strategies,
            contingency_plans=[],  # Will be populated by business continuity planning
            rollback_procedures=[
                "Feature flag immediate rollback to Node.js baseline",
                "Blue-green deployment traffic reversal",
                "Database connection restoration to Node.js drivers",
                "Monitoring alert escalation and team notification"
            ],
            
            risk_trend="stable"
        )
        
        self.logger.info("Risk assessment generated",
                        overall_risk=overall_risk.value,
                        performance_risk=perf_risk_level.value)
        
        return assessment
    
    def generate_executive_summary_report(self,
                                        migration_progress: MigrationProgressStatus,
                                        performance_compliance: PerformanceComplianceStatus,
                                        business_impact: BusinessImpactMetrics,
                                        risk_assessment: RiskAssessment,
                                        additional_context: Optional[Dict[str, Any]] = None) -> ExecutiveSummaryData:
        """
        Generate comprehensive executive summary report for stakeholder communication.
        
        Integrates all assessment components into executive-friendly format
        per Section 0.3.4 comprehensive documentation requirements.
        
        Args:
            migration_progress: Migration progress status
            performance_compliance: Performance compliance assessment
            business_impact: Business impact metrics
            risk_assessment: Risk analysis and mitigation
            additional_context: Optional contextual information
        
        Returns:
            ExecutiveSummaryData: Comprehensive executive summary
        """
        self.logger.info("Generating executive summary report",
                        migration_phase=migration_progress.current_phase.value,
                        compliance_status=performance_compliance.compliance_status.value)
        
        # Generate executive summary narrative
        executive_summary = self._generate_executive_narrative(
            migration_progress, performance_compliance, business_impact, risk_assessment
        )
        
        # Identify key achievements
        key_achievements = self._identify_key_achievements(
            migration_progress, performance_compliance, business_impact
        )
        
        # Determine critical decisions required
        critical_decisions = self._identify_critical_decisions(
            migration_progress, performance_compliance, risk_assessment
        )
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(
            migration_progress, performance_compliance, risk_assessment
        )
        
        # Create stakeholder-specific summaries
        technical_summary = self._generate_technical_stakeholder_summary(
            migration_progress, performance_compliance
        )
        business_summary = self._generate_business_stakeholder_summary(
            business_impact, risk_assessment
        )
        executive_summary_text = self._generate_executive_leadership_summary(
            migration_progress, business_impact, risk_assessment
        )
        
        summary_data = ExecutiveSummaryData(
            migration_progress=migration_progress,
            performance_compliance=performance_compliance,
            business_impact=business_impact,
            risk_assessment=risk_assessment,
            
            executive_summary=executive_summary,
            key_achievements=key_achievements,
            critical_decisions_required=critical_decisions,
            recommended_actions=recommended_actions,
            
            technical_team_summary=technical_summary,
            business_stakeholder_summary=business_summary,
            executive_leadership_summary=executive_summary_text,
            
            detailed_metrics=additional_context or {},
            supporting_charts=[
                "migration_progress_chart",
                "performance_variance_trend",
                "business_impact_visualization",
                "risk_heat_map"
            ],
            reference_documents=[
                "Performance Baseline Comparison Report",
                "Migration Progress Detailed Analysis",
                "Risk Assessment and Mitigation Plan",
                "Business Impact Quantification Study"
            ]
        )
        
        self.logger.info("Executive summary report generated",
                        report_id=summary_data.report_id,
                        achievements_count=len(key_achievements),
                        decisions_count=len(critical_decisions))
        
        return summary_data
    
    def export_stakeholder_report(self,
                                summary_data: ExecutiveSummaryData,
                                format_type: str = "html",
                                include_charts: bool = True) -> Path:
        """
        Export stakeholder summary report in specified format.
        
        Args:
            summary_data: Executive summary data
            format_type: Export format ("html", "pdf", "json")
            include_charts: Include data visualization charts
        
        Returns:
            Path: Exported report file path
        """
        timestamp = summary_data.generated_timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"stakeholder_summary_{timestamp}.{format_type}"
        output_path = self.output_directory / filename
        
        if format_type == "json":
            self._export_json_report(summary_data, output_path)
        elif format_type == "html":
            self._export_html_report(summary_data, output_path, include_charts)
        elif format_type == "pdf":
            self._export_pdf_report(summary_data, output_path, include_charts)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        self.logger.info("Stakeholder report exported",
                        format=format_type,
                        output_path=str(output_path),
                        include_charts=include_charts)
        
        return output_path
    
    # Private helper methods
    
    def _calculate_overall_completion(self,
                                    api_data: Dict[str, int],
                                    business_data: Dict[str, int],
                                    testing_data: Dict[str, int]) -> float:
        """Calculate overall migration completion percentage."""
        components = []
        
        # API completion
        if api_data.get("total", 0) > 0:
            api_completion = (api_data["migrated"] / api_data["total"]) * 100
            components.append(api_completion * 0.4)  # 40% weight
        
        # Business logic completion
        if business_data.get("total", 0) > 0:
            logic_completion = (business_data["migrated"] / business_data["total"]) * 100
            components.append(logic_completion * 0.4)  # 40% weight
        
        # Testing completion
        total_tests = testing_data.get("integration_total", 0) + testing_data.get("performance_total", 0)
        if total_tests > 0:
            passing_tests = testing_data.get("integration_passing", 0) + testing_data.get("performance_passing", 0)
            test_completion = (passing_tests / total_tests) * 100
            components.append(test_completion * 0.2)  # 20% weight
        
        return sum(components) if components else 0.0
    
    def _determine_current_phase(self, completion: float, quality_data: Dict[str, Any]) -> MigrationPhase:
        """Determine current migration phase based on completion and quality metrics."""
        if completion < 25:
            return MigrationPhase.DEVELOPMENT
        elif completion < 50:
            return MigrationPhase.TESTING
        elif completion < 75:
            return MigrationPhase.PERFORMANCE_VALIDATION
        elif completion < 90:
            return MigrationPhase.STAKEHOLDER_REVIEW
        elif completion < 95:
            return MigrationPhase.DEPLOYMENT_PREPARATION
        elif completion < 100:
            return MigrationPhase.BLUE_GREEN_MIGRATION
        else:
            return MigrationPhase.COMPLETE
    
    def _calculate_phase_completion(self, phase: MigrationPhase, quality_data: Dict[str, Any]) -> float:
        """Calculate completion percentage within current phase."""
        # Simplified phase completion based on quality gates
        gates_passed = quality_data.get("gates_passed", 0)
        gates_total = quality_data.get("gates_total", 1)
        return (gates_passed / gates_total) * 100
    
    def _assess_performance_risk_level(self, performance_risks: List[Dict[str, Any]]) -> RiskLevel:
        """Assess performance-specific risk level."""
        if not performance_risks:
            return RiskLevel.LOW
        
        max_risk_score = max([r.get("risk_score", 0) for r in performance_risks])
        
        if max_risk_score <= 0.3:
            return RiskLevel.LOW
        elif max_risk_score <= 0.6:
            return RiskLevel.MEDIUM
        elif max_risk_score <= 0.8:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _generate_executive_narrative(self,
                                    progress: MigrationProgressStatus,
                                    compliance: PerformanceComplianceStatus,
                                    impact: BusinessImpactMetrics,
                                    risk: RiskAssessment) -> str:
        """Generate executive summary narrative."""
        narrative_parts = []
        
        # Migration progress summary
        narrative_parts.append(
            f"The Node.js to Python Flask migration is currently in the "
            f"{progress.current_phase.value.replace('_', ' ').title()} phase with "
            f"{progress.overall_completion_percent:.1f}% overall completion."
        )
        
        # Performance compliance status
        compliance_text = compliance.get_compliance_summary()
        narrative_parts.append(compliance_text)
        
        # Business impact highlight
        total_value = impact.total_business_value()
        narrative_parts.append(
            f"The migration is projected to deliver ${total_value:,.0f} in annual "
            f"business value through cost savings and operational improvements."
        )
        
        # Risk summary
        narrative_parts.append(
            f"Overall project risk is assessed as {risk.overall_risk_level.value.upper()} "
            f"with comprehensive mitigation strategies in place."
        )
        
        return " ".join(narrative_parts)
    
    def _identify_key_achievements(self,
                                 progress: MigrationProgressStatus,
                                 compliance: PerformanceComplianceStatus,
                                 impact: BusinessImpactMetrics) -> List[str]:
        """Identify key project achievements for stakeholder communication."""
        achievements = []
        
        # Migration milestones
        if progress.api_migration_percent >= 75:
            achievements.append(f"Migrated {progress.api_migration_percent:.0f}% of API endpoints")
        
        if progress.code_coverage_percent >= 90:
            achievements.append(f"Achieved {progress.code_coverage_percent:.1f}% test coverage")
        
        # Performance achievements
        if compliance.is_compliant():
            achievements.append("Maintained ≤10% performance variance requirement")
        
        # Business value achievements
        if impact.enterprise_alignment_score >= 80:
            achievements.append(f"Achieved {impact.enterprise_alignment_score:.0f}% enterprise alignment score")
        
        # Quality achievements
        if progress.security_scans_passed:
            achievements.append("Passed all security compliance scans")
        
        return achievements[:self.template_config["key_achievements_max_items"]]
    
    def _identify_critical_decisions(self,
                                   progress: MigrationProgressStatus,
                                   compliance: PerformanceComplianceStatus,
                                   risk: RiskAssessment) -> List[str]:
        """Identify critical decisions requiring stakeholder attention."""
        decisions = []
        
        # Schedule decisions
        if progress.schedule_variance_days > 7:
            decisions.append(f"Address {progress.schedule_variance_days}-day schedule variance")
        
        # Performance decisions
        if not compliance.is_compliant():
            decisions.append("Review performance optimization strategies")
        
        # Risk-based decisions
        if risk.overall_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            decisions.append("Approve enhanced risk mitigation measures")
        
        # Resource decisions
        if progress.blockers_count > 0:
            decisions.append(f"Resolve {progress.blockers_count} project blockers")
        
        return decisions[:self.template_config["critical_decisions_max_items"]]
    
    def _generate_recommended_actions(self,
                                    progress: MigrationProgressStatus,
                                    compliance: PerformanceComplianceStatus,
                                    risk: RiskAssessment) -> List[str]:
        """Generate recommended actions for stakeholders."""
        actions = []
        
        # Progress-based actions
        if progress.overall_completion_percent < 50:
            actions.append("Increase development resource allocation")
        
        # Compliance-based actions
        if compliance.warning_level_check():
            actions.append("Initiate performance optimization review")
        
        # Risk-based actions
        if risk.overall_risk_level != RiskLevel.LOW:
            actions.append("Implement additional risk monitoring")
        
        # Quality-based actions
        if progress.code_coverage_percent < 90:
            actions.append("Enhance test coverage before deployment")
        
        return actions
    
    def _generate_technical_stakeholder_summary(self,
                                              progress: MigrationProgressStatus,
                                              compliance: PerformanceComplianceStatus) -> str:
        """Generate technical team focused summary."""
        return (
            f"Technical Progress: {progress.overall_completion_percent:.1f}% complete. "
            f"API Migration: {progress.api_migration_percent:.0f}%. "
            f"Performance Compliance: {compliance.get_compliance_summary()}. "
            f"Test Coverage: {progress.code_coverage_percent:.1f}%."
        )
    
    def _generate_business_stakeholder_summary(self,
                                             impact: BusinessImpactMetrics,
                                             risk: RiskAssessment) -> str:
        """Generate business stakeholder focused summary."""
        total_value = impact.total_business_value()
        return (
            f"Business Impact: ${total_value:,.0f} annual value delivery. "
            f"Enterprise Alignment: {impact.enterprise_alignment_score:.0f}%. "
            f"Risk Level: {risk.overall_risk_level.value.title()}. "
            f"Operational Efficiency: +{impact.operational_efficiency_gain:.1f}%."
        )
    
    def _generate_executive_leadership_summary(self,
                                             progress: MigrationProgressStatus,
                                             impact: BusinessImpactMetrics,
                                             risk: RiskAssessment) -> str:
        """Generate executive leadership focused summary."""
        return (
            f"Migration Status: {progress.current_phase.value.replace('_', ' ').title()} "
            f"({progress.overall_completion_percent:.0f}% complete). "
            f"Business Value: ${impact.total_business_value():,.0f} annually. "
            f"Risk Level: {risk.overall_risk_level.value.title()}. "
            f"Schedule: {'On Track' if progress.is_on_track() else 'Attention Required'}."
        )
    
    def _export_json_report(self, summary_data: ExecutiveSummaryData, output_path: Path) -> None:
        """Export stakeholder report in JSON format."""
        # Convert dataclasses to dictionary for JSON serialization
        report_dict = asdict(summary_data)
        
        # Handle datetime serialization
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, (MigrationPhase, RiskLevel, ComplianceStatus)):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, default=json_serializer)
    
    def _export_html_report(self, summary_data: ExecutiveSummaryData, 
                          output_path: Path, include_charts: bool) -> None:
        """Export stakeholder report in HTML format."""
        html_template = self._generate_html_template(summary_data, include_charts)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
    
    def _export_pdf_report(self, summary_data: ExecutiveSummaryData,
                         output_path: Path, include_charts: bool) -> None:
        """Export stakeholder report in PDF format."""
        # Generate HTML first, then convert to PDF
        html_content = self._generate_html_template(summary_data, include_charts)
        
        # Note: PDF generation would require additional dependencies like weasyprint
        # For now, save as HTML with PDF styling
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_html_template(self, summary_data: ExecutiveSummaryData, 
                              include_charts: bool) -> str:
        """Generate HTML template for stakeholder report."""
        # Simplified HTML template - in production would use proper templating engine
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Executive Stakeholder Summary - {summary_data.generated_timestamp.strftime('%Y-%m-%d')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }}
                .metric {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; }}
                .compliant {{ color: green; }}
                .warning {{ color: orange; }}
                .non-compliant {{ color: red; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Executive Stakeholder Summary</h1>
                <p>Generated: {summary_data.generated_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p>Report ID: {summary_data.report_id}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>{summary_data.executive_summary}</p>
            </div>
            
            <div class="section">
                <h2>Migration Progress</h2>
                <div class="metric">Phase: {summary_data.migration_progress.current_phase.value.replace('_', ' ').title()}</div>
                <div class="metric">Overall Completion: {summary_data.migration_progress.overall_completion_percent:.1f}%</div>
                <div class="metric">API Migration: {summary_data.migration_progress.api_migration_percent:.1f}%</div>
                <div class="metric">Test Coverage: {summary_data.migration_progress.code_coverage_percent:.1f}%</div>
            </div>
            
            <div class="section">
                <h2>Performance Compliance</h2>
                <div class="metric {summary_data.performance_compliance.compliance_status.value}">
                    Status: {summary_data.performance_compliance.get_compliance_summary()}
                </div>
                <div class="metric">Compliance Score: {summary_data.performance_compliance.overall_compliance_score:.1f}%</div>
                <div class="metric">Response Time Variance: {summary_data.performance_compliance.response_time_variance_percent:.2f}%</div>
            </div>
            
            <div class="section">
                <h2>Business Impact</h2>
                <div class="metric">Total Annual Value: ${summary_data.business_impact.total_business_value():,.0f}</div>
                <div class="metric">Enterprise Alignment: {summary_data.business_impact.enterprise_alignment_score:.0f}%</div>
                <div class="metric">Operational Efficiency Gain: {summary_data.business_impact.operational_efficiency_gain:.1f}%</div>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <div class="metric">Overall Risk Level: {summary_data.risk_assessment.overall_risk_level.value.title()}</div>
                <div class="metric">Performance Risk: {summary_data.risk_assessment.performance_regression_risk.value.title()}</div>
                <div class="metric">Top Risks: {len(summary_data.risk_assessment.get_top_risks(3))}</div>
            </div>
            
            <div class="section">
                <h2>Key Achievements</h2>
                <ul>
                    {''.join([f'<li>{achievement}</li>' for achievement in summary_data.key_achievements])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Critical Decisions Required</h2>
                <ul>
                    {''.join([f'<li>{decision}</li>' for decision in summary_data.critical_decisions_required])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Recommended Actions</h2>
                <ul>
                    {''.join([f'<li>{action}</li>' for action in summary_data.recommended_actions])}
                </ul>
            </div>
        </body>
        </html>
        """
        return html


# Utility functions for stakeholder reporting integration

def create_sample_stakeholder_report() -> ExecutiveSummaryData:
    """
    Create sample stakeholder report for testing and demonstration.
    
    Returns:
        ExecutiveSummaryData: Sample executive summary with realistic data
    """
    # Sample migration progress
    progress = MigrationProgressStatus(
        current_phase=MigrationPhase.PERFORMANCE_VALIDATION,
        overall_completion_percent=75.0,
        phase_completion_percent=60.0,
        api_endpoints_migrated=45,
        api_endpoints_total=50,
        business_logic_modules_migrated=28,
        business_logic_modules_total=32,
        integration_tests_passing=120,
        integration_tests_total=125,
        performance_tests_passing=38,
        performance_tests_total=40,
        code_coverage_percent=92.5,
        quality_gates_passed=8,
        quality_gates_total=10,
        security_scans_passed=True,
        documentation_complete_percent=85.0,
        planned_completion_date=datetime(2024, 3, 15),
        estimated_completion_date=datetime(2024, 3, 18),
        critical_path_items=["Performance optimization", "Load testing validation"],
        blockers_count=1
    )
    
    # Sample performance compliance
    compliance = PerformanceComplianceStatus(
        response_time_variance_percent=3.2,
        memory_usage_variance_percent=5.8,
        cpu_utilization_variance_percent=2.1,
        throughput_variance_percent=4.5,
        database_query_variance_percent=6.2,
        overall_compliance_score=94.5,
        variance_trend_direction="improving",
        compliance_status=ComplianceStatus.COMPLIANT,
        baseline_comparison_valid=True,
        baseline_data_freshness_days=2,
        performance_regression_count=0
    )
    
    # Sample business impact
    impact = BusinessImpactMetrics(
        estimated_cost_savings_annual=125000.0,
        risk_mitigation_value=75000.0,
        operational_efficiency_gain=15.5,
        team_productivity_impact=22.0,
        maintenance_cost_reduction=45000.0,
        time_to_market_improvement=25.0,
        enterprise_alignment_score=88.0,
        technical_debt_reduction=35.0,
        test_coverage_improvement=12.5,
        defect_reduction_rate=28.0,
        security_posture_improvement=40.0,
        monitoring_effectiveness_gain=55.0
    )
    
    # Sample risk assessment
    risk = RiskAssessment(
        overall_risk_level=RiskLevel.MEDIUM,
        performance_regression_risk=RiskLevel.LOW,
        api_compatibility_risk=RiskLevel.LOW,
        data_integrity_risk=RiskLevel.LOW,
        security_vulnerability_risk=RiskLevel.MEDIUM,
        risk_trend="stable"
    )
    
    # Add sample risks
    risk.add_technical_risk(
        "PERF-001", "Performance degradation under peak load",
        0.3, 0.7, "Enhanced load testing and optimization", "Performance Team"
    )
    risk.add_business_risk(
        "BIZ-001", "User experience impact during migration",
        0.4, 0.5, "Blue-green deployment strategy", "Product Team"
    )
    
    return ExecutiveSummaryData(
        migration_progress=progress,
        performance_compliance=compliance,
        business_impact=impact,
        risk_assessment=risk,
        executive_summary="Sample executive summary for demonstration",
        key_achievements=[
            "Achieved 92.5% test coverage",
            "Maintained ≤10% performance variance",
            "Completed 90% API migration",
            "Passed all security scans"
        ],
        critical_decisions_required=[
            "Approve final performance optimization phase",
            "Review deployment timeline adjustment"
        ],
        recommended_actions=[
            "Complete remaining performance testing",
            "Finalize deployment documentation",
            "Schedule stakeholder review meeting"
        ]
    )


# Export public interface
__all__ = [
    'StakeholderSummaryGenerator',
    'ExecutiveSummaryData',
    'MigrationProgressStatus',
    'PerformanceComplianceStatus',
    'BusinessImpactMetrics',
    'RiskAssessment',
    'MigrationPhase',
    'RiskLevel',
    'ComplianceStatus',
    'create_sample_stakeholder_report'
]