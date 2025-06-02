#!/usr/bin/env python3
"""
Safety to SARIF Converter
Converts Safety vulnerability scan results to SARIF format for GitHub Security tab integration.

This script provides enterprise-grade conversion capabilities with comprehensive vulnerability
mapping, remediation guidance, and compliance metadata for security dashboard integration.
"""

import json
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class SafetyToSARIFConverter:
    """
    Converts Safety JSON vulnerability reports to SARIF format with enterprise features.
    
    Features:
    - SARIF 2.1.0 specification compliance
    - CVE ID and CVSS score mapping
    - Automated remediation guidance
    - Enterprise security metadata
    - GitHub Security tab integration
    """
    
    def __init__(self, tool_name: str = "safety", tool_version: str = "3.0.1"):
        """
        Initialize SARIF converter with tool metadata.
        
        Args:
            tool_name: Security scanning tool name
            tool_version: Tool version for tracking
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.sarif_version = "2.1.0"
    
    def create_sarif_template(self) -> Dict[str, Any]:
        """
        Create SARIF 2.1.0 compliant template with enterprise metadata.
        
        Returns:
            Base SARIF structure with tool information
        """
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/pyupio/safety",
                            "organization": "PyUp.io",
                            "semanticVersion": self.tool_version,
                            "rules": [],
                            "notifications": [],
                            "supportedTaxonomies": [
                                {
                                    "name": "CWE",
                                    "index": 0,
                                    "guid": "25f72d7e-8a92-459d-ad67-64853f788765"
                                }
                            ]
                        }
                    },
                    "results": [],
                    "columnKind": "utf16CodeUnits",
                    "originalUriBaseIds": {
                        "PROJECTROOT": {
                            "uri": "file:///"
                        }
                    },
                    "properties": {
                        "scanTimestamp": datetime.utcnow().isoformat() + "Z",
                        "scanType": "dependency_vulnerability",
                        "compliance": {
                            "owasp": "A06:2021 - Vulnerable and Outdated Components",
                            "sans": "CWE-1104: Use of Unmaintained Third Party Components"
                        }
                    }
                }
            ]
        }
    
    def map_severity_to_sarif(self, safety_severity: str) -> str:
        """
        Map Safety vulnerability severity to SARIF specification levels.
        
        Args:
            safety_severity: Safety severity level
            
        Returns:
            SARIF compliant severity level
        """
        severity_mapping = {
            "critical": "error",
            "high": "error", 
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return severity_mapping.get(safety_severity.lower(), "warning")
    
    def extract_cve_ids(self, vulnerability: Dict[str, Any]) -> List[str]:
        """
        Extract CVE identifiers from vulnerability data.
        
        Args:
            vulnerability: Safety vulnerability object
            
        Returns:
            List of CVE identifiers
        """
        cve_ids = []
        
        # Extract from vulnerability ID field
        vuln_id = vulnerability.get("vulnerability_id", "")
        if vuln_id.startswith("CVE-"):
            cve_ids.append(vuln_id)
        
        # Extract from advisory field
        advisory = vulnerability.get("advisory", "")
        if "CVE-" in advisory:
            import re
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            found_cves = re.findall(cve_pattern, advisory)
            cve_ids.extend(found_cves)
        
        return list(set(cve_ids))  # Remove duplicates
    
    def generate_remediation_guidance(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate automated remediation guidance for vulnerabilities.
        
        Args:
            vulnerability: Safety vulnerability data
            
        Returns:
            SARIF remediation object with guidance
        """
        package_name = vulnerability.get("package_name", "unknown")
        current_version = vulnerability.get("analyzed_version", "unknown")
        safe_versions = vulnerability.get("more_info_url", "")
        
        # Generate remediation text
        remediation_text = f"Update {package_name} from {current_version} to a secure version. "
        
        if safe_versions:
            remediation_text += f"Refer to {safe_versions} for version guidance."
        else:
            remediation_text += "Check package documentation for latest secure version."
        
        return {
            "description": {
                "text": remediation_text
            },
            "properties": {
                "package": package_name,
                "currentVersion": current_version,
                "remediationType": "version_update",
                "automationLevel": "semi_automatic"
            }
        }
    
    def create_sarif_rule(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create SARIF rule definition for vulnerability.
        
        Args:
            vulnerability: Safety vulnerability data
            
        Returns:
            SARIF rule object
        """
        vuln_id = vulnerability.get("vulnerability_id", "UNKNOWN")
        package_name = vulnerability.get("package_name", "unknown")
        cve_ids = self.extract_cve_ids(vulnerability)
        
        rule = {
            "id": f"safety-{vuln_id}",
            "name": f"VulnerablePackage/{package_name}",
            "shortDescription": {
                "text": f"Vulnerable dependency: {package_name}"
            },
            "fullDescription": {
                "text": vulnerability.get("advisory", f"Security vulnerability in {package_name}")
            },
            "defaultConfiguration": {
                "level": self.map_severity_to_sarif("high")  # Default to high for dependencies
            },
            "helpUri": vulnerability.get("more_info_url", ""),
            "properties": {
                "category": "dependency_vulnerability",
                "vulnerability_id": vuln_id,
                "package_name": package_name,
                "cve_ids": cve_ids,
                "tags": ["security", "dependency", "vulnerability"]
            }
        }
        
        # Add CVE metadata if available
        if cve_ids:
            rule["relationships"] = [
                {
                    "target": {
                        "id": cve_id,
                        "toolComponent": {
                            "name": "CVE"
                        }
                    },
                    "kinds": ["references"]
                }
                for cve_id in cve_ids
            ]
        
        return rule
    
    def create_sarif_result(self, vulnerability: Dict[str, Any], rule_index: int) -> Dict[str, Any]:
        """
        Create SARIF result object for vulnerability finding.
        
        Args:
            vulnerability: Safety vulnerability data
            rule_index: Index of the rule in SARIF rules array
            
        Returns:
            SARIF result object
        """
        vuln_id = vulnerability.get("vulnerability_id", "UNKNOWN")
        package_name = vulnerability.get("package_name", "unknown")
        current_version = vulnerability.get("analyzed_version", "unknown")
        
        # Determine file location (requirements.txt or similar)
        artifact_location = {
            "uri": "requirements.txt",
            "uriBaseId": "PROJECTROOT"
        }
        
        result = {
            "ruleId": f"safety-{vuln_id}",
            "ruleIndex": rule_index,
            "level": self.map_severity_to_sarif("high"),
            "message": {
                "text": f"Vulnerability in {package_name} {current_version}: {vulnerability.get('advisory', 'Security issue detected')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": artifact_location,
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                            "endLine": 1,
                            "endColumn": len(package_name) + len(current_version) + 2
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": package_name,
                            "kind": "package",
                            "fullyQualifiedName": f"{package_name}=={current_version}"
                        }
                    ]
                }
            ],
            "fixes": [
                self.generate_remediation_guidance(vulnerability)
            ],
            "properties": {
                "vulnerability_id": vuln_id,
                "package_name": package_name,
                "analyzed_version": current_version,
                "severity": "high",
                "confidence": "high",
                "security_severity": "7.5"  # Default CVSS score
            }
        }
        
        # Add CVE information if available
        cve_ids = self.extract_cve_ids(vulnerability)
        if cve_ids:
            result["properties"]["cve_ids"] = cve_ids
            result["properties"]["external_references"] = [
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                for cve_id in cve_ids
            ]
        
        return result
    
    def convert_safety_to_sarif(self, safety_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Safety JSON output to SARIF format.
        
        Args:
            safety_data: Parsed Safety JSON vulnerability data
            
        Returns:
            Complete SARIF report
        """
        sarif_report = self.create_sarif_template()
        run = sarif_report["runs"][0]
        
        # Process vulnerabilities from Safety output
        vulnerabilities = safety_data.get("vulnerabilities", [])
        if not vulnerabilities:
            # Handle case where Safety uses different JSON structure
            vulnerabilities = safety_data if isinstance(safety_data, list) else []
        
        rules = []
        results = []
        
        for index, vulnerability in enumerate(vulnerabilities):
            # Create rule for this vulnerability
            rule = self.create_sarif_rule(vulnerability)
            rules.append(rule)
            
            # Create result for this finding
            result = self.create_sarif_result(vulnerability, index)
            results.append(result)
        
        # Update SARIF report
        run["tool"]["driver"]["rules"] = rules
        run["results"] = results
        
        # Add summary statistics
        run["properties"]["statistics"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "unique_packages": len(set(v.get("package_name", "") for v in vulnerabilities)),
            "scan_status": "completed"
        }
        
        return sarif_report
    
    def save_sarif_report(self, sarif_report: Dict[str, Any], output_path: str) -> None:
        """
        Save SARIF report to file with proper formatting.
        
        Args:
            sarif_report: Complete SARIF report
            output_path: Output file path
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2, ensure_ascii=False)
        
        print(f"SARIF report saved to: {output_path}")


def main():
    """Main entry point for Safety to SARIF conversion."""
    parser = argparse.ArgumentParser(
        description="Convert Safety vulnerability scan results to SARIF format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python safety_to_sarif.py -i safety-results.json -o safety-results.sarif
  python safety_to_sarif.py -i safety.json -o output.sarif --tool-name safety --tool-version 3.0.1
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input Safety JSON file path"
    )
    
    parser.add_argument(
        "-o", "--output", 
        required=True,
        help="Output SARIF file path"
    )
    
    parser.add_argument(
        "--tool-name",
        default="safety",
        help="Tool name for SARIF metadata (default: safety)"
    )
    
    parser.add_argument(
        "--tool-version",
        default="3.0.1", 
        help="Tool version for SARIF metadata (default: 3.0.1)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    try:
        # Load Safety JSON data
        if args.verbose:
            print(f"Loading Safety data from: {args.input}")
        
        with open(args.input, 'r', encoding='utf-8') as f:
            safety_data = json.load(f)
        
        # Initialize converter
        converter = SafetyToSARIFConverter(
            tool_name=args.tool_name,
            tool_version=args.tool_version
        )
        
        # Convert to SARIF
        if args.verbose:
            print("Converting Safety data to SARIF format...")
        
        sarif_report = converter.convert_safety_to_sarif(safety_data)
        
        # Save SARIF report
        converter.save_sarif_report(sarif_report, args.output)
        
        if args.verbose:
            vulnerability_count = len(sarif_report["runs"][0]["results"])
            print(f"Conversion completed successfully!")
            print(f"Total vulnerabilities: {vulnerability_count}")
            print(f"SARIF version: {sarif_report['version']}")
        
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()