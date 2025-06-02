#!/usr/bin/env python3
"""
Bandit Baseline Comparison Tool
Compares current Bandit security scan results with established baseline for trend analysis.

This script provides enterprise-grade security trend monitoring with comprehensive
vulnerability tracking, risk assessment, and automated reporting for security dashboards.
"""

import json
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class SecurityFinding:
    """
    Represents a security finding from Bandit scan.
    
    Attributes:
        test_id: Bandit test identifier (e.g., B101, B201)
        test_name: Human-readable test name
        severity: Severity level (LOW, MEDIUM, HIGH)
        confidence: Confidence level (LOW, MEDIUM, HIGH)
        filename: Source file containing the finding
        line_number: Line number of the finding
        issue_text: Description of the security issue
        code: Relevant code snippet
        more_info: URL with additional information
    """
    test_id: str
    test_name: str
    severity: str
    confidence: str
    filename: str
    line_number: int
    issue_text: str
    code: str
    more_info: str
    
    def get_signature(self) -> str:
        """
        Generate unique signature for finding comparison.
        
        Returns:
            Unique signature string for this finding
        """
        return f"{self.test_id}:{self.filename}:{self.line_number}:{hash(self.code)}"
    
    def get_risk_score(self) -> int:
        """
        Calculate numerical risk score for prioritization.
        
        Returns:
            Risk score (1-9, higher is more critical)
        """
        severity_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        confidence_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        
        return severity_scores.get(self.severity, 1) * confidence_scores.get(self.confidence, 1)


@dataclass
class ComparisonResult:
    """
    Results of baseline comparison analysis.
    
    Attributes:
        new_findings: Findings present in current but not baseline
        resolved_findings: Findings present in baseline but not current
        persistent_findings: Findings present in both scans
        baseline_summary: Summary statistics from baseline
        current_summary: Summary statistics from current scan
        trend_analysis: Analysis of security trends
        risk_assessment: Overall risk assessment
    """
    new_findings: List[SecurityFinding]
    resolved_findings: List[SecurityFinding]
    persistent_findings: List[SecurityFinding]
    baseline_summary: Dict[str, Any]
    current_summary: Dict[str, Any]
    trend_analysis: Dict[str, Any]
    risk_assessment: Dict[str, Any]


class BanditBaselineComparator:
    """
    Comprehensive Bandit security scan baseline comparison and trend analysis.
    
    Features:
    - Security finding deduplication and tracking
    - Risk score calculation and prioritization
    - Trend analysis with statistical insights
    - Enterprise reporting and dashboard integration
    - Automated remediation guidance
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize Bandit baseline comparator.
        
        Args:
            verbose: Enable verbose logging output
        """
        self.verbose = verbose
        self.risk_thresholds = {
            "critical": 8,
            "high": 6,
            "medium": 4,
            "low": 1
        }
    
    def _log(self, message: str) -> None:
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def parse_bandit_results(self, bandit_data: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Parse Bandit JSON output into structured security findings.
        
        Args:
            bandit_data: Parsed Bandit JSON output
            
        Returns:
            List of structured security findings
        """
        findings = []
        
        # Extract results from Bandit JSON structure
        results = bandit_data.get("results", [])
        
        for result in results:
            finding = SecurityFinding(
                test_id=result.get("test_id", "UNKNOWN"),
                test_name=result.get("test_name", "Unknown Test"),
                severity=result.get("issue_severity", "LOW").upper(),
                confidence=result.get("issue_confidence", "LOW").upper(),
                filename=result.get("filename", "unknown"),
                line_number=result.get("line_number", 0),
                issue_text=result.get("issue_text", ""),
                code=result.get("code", "").strip(),
                more_info=result.get("more_info", "")
            )
            findings.append(finding)
        
        self._log(f"Parsed {len(findings)} security findings from Bandit results")
        return findings
    
    def generate_finding_signatures(self, findings: List[SecurityFinding]) -> Dict[str, SecurityFinding]:
        """
        Generate signature mapping for findings deduplication.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary mapping signatures to findings
        """
        signature_map = {}
        
        for finding in findings:
            signature = finding.get_signature()
            signature_map[signature] = finding
        
        self._log(f"Generated {len(signature_map)} unique finding signatures")
        return signature_map
    
    def calculate_summary_statistics(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """
        Calculate comprehensive summary statistics for findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary with summary statistics
        """
        if not findings:
            return {
                "total_findings": 0,
                "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "confidence_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "test_id_breakdown": {},
                "file_breakdown": {},
                "average_risk_score": 0.0,
                "max_risk_score": 0,
                "critical_findings": 0
            }
        
        # Calculate severity and confidence breakdowns
        severity_counts = defaultdict(int)
        confidence_counts = defaultdict(int)
        test_id_counts = defaultdict(int)
        file_counts = defaultdict(int)
        risk_scores = []
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            confidence_counts[finding.confidence] += 1
            test_id_counts[finding.test_id] += 1
            file_counts[finding.filename] += 1
            risk_scores.append(finding.get_risk_score())
        
        # Calculate risk metrics
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        max_risk_score = max(risk_scores) if risk_scores else 0
        critical_findings = sum(1 for score in risk_scores if score >= self.risk_thresholds["critical"])
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": dict(severity_counts),
            "confidence_breakdown": dict(confidence_counts),
            "test_id_breakdown": dict(test_id_counts),
            "file_breakdown": dict(file_counts),
            "average_risk_score": round(avg_risk_score, 2),
            "max_risk_score": max_risk_score,
            "critical_findings": critical_findings,
            "risk_distribution": {
                "critical": sum(1 for s in risk_scores if s >= self.risk_thresholds["critical"]),
                "high": sum(1 for s in risk_scores if self.risk_thresholds["high"] <= s < self.risk_thresholds["critical"]),
                "medium": sum(1 for s in risk_scores if self.risk_thresholds["medium"] <= s < self.risk_thresholds["high"]),
                "low": sum(1 for s in risk_scores if s < self.risk_thresholds["medium"])
            }
        }
    
    def analyze_trends(self, baseline_stats: Dict[str, Any], current_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security trends between baseline and current scan.
        
        Args:
            baseline_stats: Baseline scan statistics
            current_stats: Current scan statistics
            
        Returns:
            Comprehensive trend analysis
        """
        def calculate_change_percentage(baseline_val: float, current_val: float) -> float:
            """Calculate percentage change between baseline and current values."""
            if baseline_val == 0:
                return 100.0 if current_val > 0 else 0.0
            return round(((current_val - baseline_val) / baseline_val) * 100, 2)
        
        # Calculate overall trends
        total_change = current_stats["total_findings"] - baseline_stats["total_findings"]
        total_change_pct = calculate_change_percentage(
            baseline_stats["total_findings"], 
            current_stats["total_findings"]
        )
        
        # Calculate severity trends
        severity_trends = {}
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            baseline_count = baseline_stats["severity_breakdown"].get(severity, 0)
            current_count = current_stats["severity_breakdown"].get(severity, 0)
            change = current_count - baseline_count
            change_pct = calculate_change_percentage(baseline_count, current_count)
            
            severity_trends[severity] = {
                "baseline": baseline_count,
                "current": current_count,
                "change": change,
                "change_percentage": change_pct
            }
        
        # Calculate risk score trends
        risk_score_change = current_stats["average_risk_score"] - baseline_stats["average_risk_score"]
        risk_score_change_pct = calculate_change_percentage(
            baseline_stats["average_risk_score"],
            current_stats["average_risk_score"]
        )
        
        # Determine overall trend direction
        if total_change_pct <= -10:
            trend_direction = "significant_improvement"
        elif total_change_pct <= -5:
            trend_direction = "improvement"
        elif total_change_pct <= 5:
            trend_direction = "stable"
        elif total_change_pct <= 10:
            trend_direction = "degradation"
        else:
            trend_direction = "significant_degradation"
        
        return {
            "scan_comparison": {
                "baseline_findings": baseline_stats["total_findings"],
                "current_findings": current_stats["total_findings"],
                "total_change": total_change,
                "total_change_percentage": total_change_pct
            },
            "severity_trends": severity_trends,
            "risk_score_trends": {
                "baseline_avg": baseline_stats["average_risk_score"],
                "current_avg": current_stats["average_risk_score"],
                "change": round(risk_score_change, 2),
                "change_percentage": risk_score_change_pct
            },
            "critical_findings_trend": {
                "baseline": baseline_stats["critical_findings"],
                "current": current_stats["critical_findings"],
                "change": current_stats["critical_findings"] - baseline_stats["critical_findings"]
            },
            "trend_direction": trend_direction,
            "trend_assessment": self._assess_trend_significance(trend_direction, current_stats)
        }
    
    def _assess_trend_significance(self, trend_direction: str, current_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the significance and impact of security trends.
        
        Args:
            trend_direction: Overall trend direction
            current_stats: Current scan statistics
            
        Returns:
            Trend significance assessment
        """
        significance_levels = {
            "significant_improvement": {
                "level": "positive",
                "priority": "low",
                "action_required": "continue_monitoring"
            },
            "improvement": {
                "level": "positive", 
                "priority": "low",
                "action_required": "continue_monitoring"
            },
            "stable": {
                "level": "neutral",
                "priority": "medium",
                "action_required": "regular_monitoring"
            },
            "degradation": {
                "level": "negative",
                "priority": "medium", 
                "action_required": "investigation_required"
            },
            "significant_degradation": {
                "level": "negative",
                "priority": "high",
                "action_required": "immediate_attention"
            }
        }
        
        assessment = significance_levels.get(trend_direction, significance_levels["stable"])
        
        # Adjust priority based on critical findings
        if current_stats["critical_findings"] > 0:
            assessment["priority"] = "high"
            assessment["action_required"] = "immediate_attention"
        
        return assessment
    
    def perform_risk_assessment(self, comparison_result: 'ComparisonResult') -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment based on comparison results.
        
        Args:
            comparison_result: Comparison analysis results
            
        Returns:
            Detailed risk assessment
        """
        # Calculate risk metrics for different finding categories
        new_findings_risk = sum(f.get_risk_score() for f in comparison_result.new_findings)
        persistent_findings_risk = sum(f.get_risk_score() for f in comparison_result.persistent_findings)
        total_current_risk = new_findings_risk + persistent_findings_risk
        
        # Calculate risk reduction from resolved findings
        resolved_findings_risk = sum(f.get_risk_score() for f in comparison_result.resolved_findings)
        
        # Determine overall risk level
        if total_current_risk >= 50:
            risk_level = "critical"
        elif total_current_risk >= 30:
            risk_level = "high"
        elif total_current_risk >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate risk recommendations
        recommendations = []
        
        if len(comparison_result.new_findings) > 0:
            recommendations.append(f"Address {len(comparison_result.new_findings)} new security findings")
        
        if len(comparison_result.persistent_findings) > 5:
            recommendations.append(f"Prioritize resolution of {len(comparison_result.persistent_findings)} persistent findings")
        
        critical_new = [f for f in comparison_result.new_findings if f.get_risk_score() >= self.risk_thresholds["critical"]]
        if critical_new:
            recommendations.append(f"Immediately address {len(critical_new)} critical new findings")
        
        return {
            "overall_risk_level": risk_level,
            "total_risk_score": total_current_risk,
            "risk_breakdown": {
                "new_findings_risk": new_findings_risk,
                "persistent_findings_risk": persistent_findings_risk,
                "resolved_risk_reduction": resolved_findings_risk
            },
            "finding_analysis": {
                "new_findings_count": len(comparison_result.new_findings),
                "resolved_findings_count": len(comparison_result.resolved_findings),
                "persistent_findings_count": len(comparison_result.persistent_findings)
            },
            "recommendations": recommendations,
            "priority_actions": self._generate_priority_actions(comparison_result),
            "compliance_impact": self._assess_compliance_impact(risk_level, comparison_result)
        }
    
    def _generate_priority_actions(self, comparison_result: 'ComparisonResult') -> List[Dict[str, Any]]:
        """Generate prioritized action items based on findings."""
        actions = []
        
        # Sort new findings by risk score
        critical_new = sorted(
            [f for f in comparison_result.new_findings if f.get_risk_score() >= self.risk_thresholds["critical"]],
            key=lambda x: x.get_risk_score(),
            reverse=True
        )
        
        for finding in critical_new[:5]:  # Top 5 critical findings
            actions.append({
                "priority": "critical",
                "action": f"Fix {finding.test_name} in {finding.filename}:{finding.line_number}",
                "finding_id": finding.test_id,
                "risk_score": finding.get_risk_score(),
                "estimated_effort": "immediate"
            })
        
        # Add actions for persistent high-risk findings
        persistent_high = sorted(
            [f for f in comparison_result.persistent_findings if f.get_risk_score() >= self.risk_thresholds["high"]],
            key=lambda x: x.get_risk_score(),
            reverse=True
        )
        
        for finding in persistent_high[:3]:  # Top 3 persistent findings
            actions.append({
                "priority": "high",
                "action": f"Address persistent {finding.test_name} in {finding.filename}",
                "finding_id": finding.test_id,
                "risk_score": finding.get_risk_score(),
                "estimated_effort": "short_term"
            })
        
        return actions
    
    def _assess_compliance_impact(self, risk_level: str, comparison_result: 'ComparisonResult') -> Dict[str, Any]:
        """Assess impact on compliance and security posture."""
        compliance_status = "compliant"
        
        if risk_level in ["critical", "high"]:
            compliance_status = "non_compliant"
        elif len(comparison_result.new_findings) > 10:
            compliance_status = "at_risk"
        
        return {
            "status": compliance_status,
            "risk_level": risk_level,
            "findings_impact": {
                "new_security_debt": len(comparison_result.new_findings),
                "resolved_issues": len(comparison_result.resolved_findings),
                "ongoing_concerns": len(comparison_result.persistent_findings)
            },
            "regulatory_considerations": [
                "OWASP Top 10 compliance",
                "SOC 2 security controls",
                "ISO 27001 risk management"
            ] if risk_level in ["critical", "high"] else []
        }
    
    def compare_scans(self, baseline_data: Dict[str, Any], current_data: Dict[str, Any]) -> ComparisonResult:
        """
        Perform comprehensive comparison between baseline and current scans.
        
        Args:
            baseline_data: Baseline Bandit scan results
            current_data: Current Bandit scan results
            
        Returns:
            Detailed comparison results with trend analysis
        """
        self._log("Starting baseline comparison analysis...")
        
        # Parse findings from both scans
        baseline_findings = self.parse_bandit_results(baseline_data)
        current_findings = self.parse_bandit_results(current_data)
        
        # Generate finding signatures for comparison
        baseline_signatures = self.generate_finding_signatures(baseline_findings)
        current_signatures = self.generate_finding_signatures(current_findings)
        
        # Identify finding differences
        baseline_sig_set = set(baseline_signatures.keys())
        current_sig_set = set(current_signatures.keys())
        
        new_signatures = current_sig_set - baseline_sig_set
        resolved_signatures = baseline_sig_set - current_sig_set
        persistent_signatures = baseline_sig_set & current_sig_set
        
        # Extract corresponding findings
        new_findings = [current_signatures[sig] for sig in new_signatures]
        resolved_findings = [baseline_signatures[sig] for sig in resolved_signatures]
        persistent_findings = [current_signatures[sig] for sig in persistent_signatures]
        
        self._log(f"Found {len(new_findings)} new, {len(resolved_findings)} resolved, {len(persistent_findings)} persistent findings")
        
        # Calculate summary statistics
        baseline_summary = self.calculate_summary_statistics(baseline_findings)
        current_summary = self.calculate_summary_statistics(current_findings)
        
        # Perform trend analysis
        trend_analysis = self.analyze_trends(baseline_summary, current_summary)
        
        # Create comparison result
        comparison_result = ComparisonResult(
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            baseline_summary=baseline_summary,
            current_summary=current_summary,
            trend_analysis=trend_analysis,
            risk_assessment={}  # Will be populated below
        )
        
        # Perform risk assessment
        comparison_result.risk_assessment = self.perform_risk_assessment(comparison_result)
        
        self._log("Baseline comparison analysis completed")
        return comparison_result
    
    def generate_comparison_report(self, comparison_result: ComparisonResult) -> Dict[str, Any]:
        """
        Generate comprehensive comparison report for enterprise reporting.
        
        Args:
            comparison_result: Comparison analysis results
            
        Returns:
            Complete comparison report
        """
        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "report_type": "bandit_baseline_comparison",
                "version": "1.0.0"
            },
            "executive_summary": {
                "overall_trend": comparison_result.trend_analysis["trend_direction"],
                "risk_level": comparison_result.risk_assessment["overall_risk_level"],
                "new_findings": len(comparison_result.new_findings),
                "resolved_findings": len(comparison_result.resolved_findings),
                "net_change": len(comparison_result.new_findings) - len(comparison_result.resolved_findings)
            },
            "detailed_analysis": {
                "baseline_summary": comparison_result.baseline_summary,
                "current_summary": comparison_result.current_summary,
                "trend_analysis": comparison_result.trend_analysis,
                "risk_assessment": comparison_result.risk_assessment
            },
            "findings_breakdown": {
                "new_findings": [asdict(f) for f in comparison_result.new_findings],
                "resolved_findings": [asdict(f) for f in comparison_result.resolved_findings],
                "persistent_findings": [asdict(f) for f in comparison_result.persistent_findings]
            },
            "recommendations": {
                "immediate_actions": comparison_result.risk_assessment.get("priority_actions", []),
                "general_recommendations": comparison_result.risk_assessment.get("recommendations", []),
                "compliance_guidance": comparison_result.risk_assessment.get("compliance_impact", {})
            }
        }


def main():
    """Main entry point for Bandit baseline comparison."""
    parser = argparse.ArgumentParser(
        description="Compare current Bandit security scan results with baseline for trend analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bandit_baseline_compare.py -c current.json -b baseline.json -o comparison.json
  python bandit_baseline_compare.py --current bandit-results.json --baseline baseline.json --output report.json --verbose
        """
    )
    
    parser.add_argument(
        "-c", "--current",
        required=True,
        help="Current Bandit scan results JSON file"
    )
    
    parser.add_argument(
        "-b", "--baseline", 
        required=True,
        help="Baseline Bandit scan results JSON file"
    )
    
    parser.add_argument(
        "-o", "--output",
        required=True, 
        help="Output comparison report JSON file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    try:
        # Load baseline data
        if args.verbose:
            print(f"Loading baseline data from: {args.baseline}")
        
        with open(args.baseline, 'r', encoding='utf-8') as f:
            baseline_data = json.load(f)
        
        # Load current data
        if args.verbose:
            print(f"Loading current scan data from: {args.current}")
        
        with open(args.current, 'r', encoding='utf-8') as f:
            current_data = json.load(f)
        
        # Initialize comparator
        comparator = BanditBaselineComparator(verbose=args.verbose)
        
        # Perform comparison
        if args.verbose:
            print("Performing baseline comparison analysis...")
        
        comparison_result = comparator.compare_scans(baseline_data, current_data)
        
        # Generate report
        report = comparator.generate_comparison_report(comparison_result)
        
        # Save comparison report
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        if args.verbose:
            print(f"Comparison report saved to: {args.output}")
            print(f"Overall trend: {report['executive_summary']['overall_trend']}")
            print(f"Risk level: {report['executive_summary']['risk_level']}")
            print(f"New findings: {report['executive_summary']['new_findings']}")
            print(f"Resolved findings: {report['executive_summary']['resolved_findings']}")
        
        # Set exit code based on risk level
        risk_level = report['executive_summary']['risk_level']
        if risk_level == "critical":
            sys.exit(2)  # Critical findings detected
        elif risk_level == "high":
            sys.exit(1)  # High risk findings detected
        else:
            sys.exit(0)  # Acceptable risk level
        
    except FileNotFoundError as e:
        print(f"Error: File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during comparison: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()