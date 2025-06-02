#!/bin/bash

# =============================================================================
# Flask Application Security Scanning and Compliance Validation Script
# =============================================================================
#
# This script implements comprehensive security scanning and compliance validation
# for the Flask application migration project, including container vulnerability
# scanning, dependency security assessment, and comprehensive security policy
# enforcement per Sections 8.5.1, 8.5.2, and 6.4 of the technical specification.
#
# Dependencies:
# - Trivy 0.48+ for container vulnerability scanning
# - safety 3.0+ for dependency vulnerability scanning  
# - bandit 1.7+ for Python security analysis
# - flake8 6.1+ for code style compliance
# - mypy 1.8+ for type safety validation
# - pytest for security test validation
#
# Integration:
# - GitHub Actions CI/CD pipeline
# - AWS Security Hub and CloudWatch
# - Prometheus metrics collection
# - Enterprise monitoring systems
#
# Usage:
#   ./scripts/security.sh [OPTIONS]
#
# Options:
#   --container-scan        Run container vulnerability scanning with Trivy
#   --dependency-scan       Run dependency vulnerability scanning with safety/pip-audit
#   --static-analysis       Run static code analysis with bandit/flake8/mypy
#   --security-tests        Run security test suite validation
#   --compliance-check      Run comprehensive compliance validation
#   --all                   Run all security scans (default)
#   --output-format FORMAT  Output format: json, sarif, table (default: table)
#   --report-dir DIR        Directory for security reports (default: security-reports)
#   --fail-on-critical      Fail on critical vulnerabilities (default: true)
#   --metrics-endpoint URL  Prometheus metrics endpoint for reporting
#   --aws-integration       Enable AWS Security Hub integration
#   --verbose               Enable verbose logging
#   --help                  Show this help message
#
# Exit Codes:
#   0 - Success, no critical security issues found
#   1 - Critical security vulnerabilities found, deployment blocked
#   2 - Configuration or tool errors
#   3 - Compliance violations detected
#
# =============================================================================

set -euo pipefail

# Script configuration and constants
readonly SCRIPT_NAME="security.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"

# Security tool versions per technical specification requirements
readonly TRIVY_MIN_VERSION="0.48.0"
readonly SAFETY_MIN_VERSION="3.0.0"
readonly BANDIT_MIN_VERSION="1.7.0"
readonly FLAKE8_MIN_VERSION="6.1.0"
readonly MYPY_MIN_VERSION="1.8.0"

# Default configuration
CONTAINER_SCAN=false
DEPENDENCY_SCAN=false
STATIC_ANALYSIS=false
SECURITY_TESTS=false
COMPLIANCE_CHECK=false
RUN_ALL=true
OUTPUT_FORMAT="table"
REPORT_DIR="${PROJECT_ROOT}/security-reports"
FAIL_ON_CRITICAL=true
METRICS_ENDPOINT=""
AWS_INTEGRATION=false
VERBOSE=false

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_CRITICAL_VULNERABILITIES=1
readonly EXIT_CONFIGURATION_ERROR=2
readonly EXIT_COMPLIANCE_VIOLATION=3

# Colors for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# Utility Functions
# =============================================================================

# Logging functions with structured output
log_info() {
    local message="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    echo -e "${GREEN}[INFO]${NC} ${timestamp} - ${message}" >&2
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "{\"level\":\"info\",\"timestamp\":\"${timestamp}\",\"message\":\"${message}\",\"component\":\"security-scanner\"}" >> "${REPORT_DIR}/security.log"
    fi
}

log_warn() {
    local message="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    echo -e "${YELLOW}[WARN]${NC} ${timestamp} - ${message}" >&2
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "{\"level\":\"warning\",\"timestamp\":\"${timestamp}\",\"message\":\"${message}\",\"component\":\"security-scanner\"}" >> "${REPORT_DIR}/security.log"
    fi
}

log_error() {
    local message="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    echo -e "${RED}[ERROR]${NC} ${timestamp} - ${message}" >&2
    
    echo "{\"level\":\"error\",\"timestamp\":\"${timestamp}\",\"message\":\"${message}\",\"component\":\"security-scanner\"}" >> "${REPORT_DIR}/security.log"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="$1"
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
        echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - ${message}" >&2
        
        echo "{\"level\":\"debug\",\"timestamp\":\"${timestamp}\",\"message\":\"${message}\",\"component\":\"security-scanner\"}" >> "${REPORT_DIR}/security.log"
    fi
}

# Display help information
show_help() {
    cat << EOF
Flask Application Security Scanner v${SCRIPT_VERSION}

This script implements comprehensive security scanning and compliance validation
for the Flask application migration project per technical specification
requirements (Sections 8.5.1, 8.5.2, and 6.4).

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    --container-scan        Run container vulnerability scanning with Trivy 0.48+
    --dependency-scan       Run dependency vulnerability scanning with safety 3.0+
    --static-analysis       Run static code analysis with bandit/flake8/mypy
    --security-tests        Run security test suite validation
    --compliance-check      Run comprehensive compliance validation
    --all                   Run all security scans (default)
    --output-format FORMAT  Output format: json, sarif, table (default: table)
    --report-dir DIR        Directory for security reports (default: security-reports)
    --fail-on-critical      Fail on critical vulnerabilities (default: true)
    --metrics-endpoint URL  Prometheus metrics endpoint for reporting
    --aws-integration       Enable AWS Security Hub integration
    --verbose               Enable verbose logging
    --help                  Show this help message

EXAMPLES:
    # Run comprehensive security scan (default)
    ./${SCRIPT_NAME}
    
    # Run only container vulnerability scanning
    ./${SCRIPT_NAME} --container-scan
    
    # Run dependency scanning with JSON output
    ./${SCRIPT_NAME} --dependency-scan --output-format json
    
    # Run all scans with AWS integration and metrics
    ./${SCRIPT_NAME} --all --aws-integration --metrics-endpoint http://prometheus:9090
    
    # Run compliance validation only
    ./${SCRIPT_NAME} --compliance-check --verbose

EXIT CODES:
    0 - Success, no critical security issues found
    1 - Critical security vulnerabilities found, deployment blocked
    2 - Configuration or tool errors  
    3 - Compliance violations detected

SECURITY TOOLS INTEGRATED:
    - Trivy ${TRIVY_MIN_VERSION}+ (Container vulnerability scanning)
    - safety ${SAFETY_MIN_VERSION}+ (Dependency vulnerability scanning)
    - bandit ${BANDIT_MIN_VERSION}+ (Python security analysis)
    - flake8 ${FLAKE8_MIN_VERSION}+ (Code style compliance)
    - mypy ${MYPY_MIN_VERSION}+ (Type safety validation)
    - pip-audit 2.7+ (Additional dependency scanning)

For more information, see the technical specification Section 8.5 (CI/CD Pipeline)
and Section 6.4 (Security Architecture).
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --container-scan)
                CONTAINER_SCAN=true
                RUN_ALL=false
                shift
                ;;
            --dependency-scan)
                DEPENDENCY_SCAN=true
                RUN_ALL=false
                shift
                ;;
            --static-analysis)
                STATIC_ANALYSIS=true
                RUN_ALL=false
                shift
                ;;
            --security-tests)
                SECURITY_TESTS=true
                RUN_ALL=false
                shift
                ;;
            --compliance-check)
                COMPLIANCE_CHECK=true
                RUN_ALL=false
                shift
                ;;
            --all)
                RUN_ALL=true
                shift
                ;;
            --output-format)
                OUTPUT_FORMAT="$2"
                if [[ ! "$OUTPUT_FORMAT" =~ ^(json|sarif|table)$ ]]; then
                    log_error "Invalid output format: $OUTPUT_FORMAT. Must be one of: json, sarif, table"
                    exit $EXIT_CONFIGURATION_ERROR
                fi
                shift 2
                ;;
            --report-dir)
                REPORT_DIR="$2"
                shift 2
                ;;
            --fail-on-critical)
                FAIL_ON_CRITICAL=true
                shift
                ;;
            --no-fail-on-critical)
                FAIL_ON_CRITICAL=false
                shift
                ;;
            --metrics-endpoint)
                METRICS_ENDPOINT="$2"
                shift 2
                ;;
            --aws-integration)
                AWS_INTEGRATION=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                show_help
                exit $EXIT_SUCCESS
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information."
                exit $EXIT_CONFIGURATION_ERROR
                ;;
        esac
    done
    
    # Set all scan types if running all
    if [[ "$RUN_ALL" == "true" ]]; then
        CONTAINER_SCAN=true
        DEPENDENCY_SCAN=true
        STATIC_ANALYSIS=true
        SECURITY_TESTS=true
        COMPLIANCE_CHECK=true
    fi
}

# Validate environment and tool availability
validate_environment() {
    log_info "Validating security scanning environment..."
    
    # Create report directory
    mkdir -p "$REPORT_DIR"
    touch "${REPORT_DIR}/security.log"
    
    # Validate project structure
    if [[ ! -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        log_error "requirements.txt not found in project root"
        exit $EXIT_CONFIGURATION_ERROR
    fi
    
    if [[ ! -d "${PROJECT_ROOT}/src" ]]; then
        log_error "Source directory 'src' not found in project root"
        exit $EXIT_CONFIGURATION_ERROR
    fi
    
    # Check Docker availability for container scanning
    if [[ "$CONTAINER_SCAN" == "true" ]]; then
        if ! command -v docker &> /dev/null; then
            log_error "Docker is required for container scanning but not found"
            exit $EXIT_CONFIGURATION_ERROR
        fi
        
        if ! docker info &> /dev/null; then
            log_error "Docker daemon is not running"
            exit $EXIT_CONFIGURATION_ERROR
        fi
    fi
    
    # Validate AWS CLI for AWS integration
    if [[ "$AWS_INTEGRATION" == "true" ]]; then
        if ! command -v aws &> /dev/null; then
            log_error "AWS CLI is required for AWS integration but not found"
            exit $EXIT_CONFIGURATION_ERROR
        fi
        
        # Verify AWS credentials
        if ! aws sts get-caller-identity &> /dev/null; then
            log_error "AWS credentials not configured or invalid"
            exit $EXIT_CONFIGURATION_ERROR
        fi
    fi
    
    log_info "Environment validation completed successfully"
}

# Check and install security tools
install_security_tools() {
    log_info "Checking and installing security tools..."
    
    # Check Python and pip availability
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not found"
        exit $EXIT_CONFIGURATION_ERROR
    fi
    
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not found"
        exit $EXIT_CONFIGURATION_ERROR
    fi
    
    # Install/update Python security tools
    local python_tools=(
        "safety>=${SAFETY_MIN_VERSION}"
        "bandit>=${BANDIT_MIN_VERSION}"
        "flake8>=${FLAKE8_MIN_VERSION}"
        "mypy>=${MYPY_MIN_VERSION}"
        "pip-audit>=2.7.0"
        "pytest>=7.4.0"
        "pytest-cov>=4.1.0"
    )
    
    for tool in "${python_tools[@]}"; do
        log_debug "Installing/updating: $tool"
        if ! pip3 install --quiet --upgrade "$tool"; then
            log_error "Failed to install $tool"
            exit $EXIT_CONFIGURATION_ERROR
        fi
    done
    
    # Install Trivy for container scanning
    if [[ "$CONTAINER_SCAN" == "true" ]]; then
        if ! command -v trivy &> /dev/null; then
            log_info "Installing Trivy container scanner..."
            
            # Detect OS and install Trivy accordingly
            if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                # Linux installation
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
            elif [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS installation
                if command -v brew &> /dev/null; then
                    brew install trivy
                else
                    log_error "Homebrew required for Trivy installation on macOS"
                    exit $EXIT_CONFIGURATION_ERROR
                fi
            else
                log_error "Unsupported OS for automatic Trivy installation: $OSTYPE"
                exit $EXIT_CONFIGURATION_ERROR
            fi
        fi
        
        # Verify Trivy version
        local trivy_version=$(trivy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if ! version_compare "$trivy_version" "$TRIVY_MIN_VERSION"; then
            log_error "Trivy version $trivy_version is below minimum required version $TRIVY_MIN_VERSION"
            exit $EXIT_CONFIGURATION_ERROR
        fi
        
        log_info "Trivy $trivy_version installed successfully"
    fi
    
    log_info "Security tools installation completed"
}

# Version comparison utility
version_compare() {
    local version1="$1"
    local version2="$2"
    
    # Convert versions to comparable format
    local v1=$(echo "$version1" | sed 's/[^0-9.]//g')
    local v2=$(echo "$version2" | sed 's/[^0-9.]//g')
    
    # Use sort -V for version comparison
    if [[ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -1)" == "$v2" ]]; then
        return 0  # version1 >= version2
    else
        return 1  # version1 < version2
    fi
}

# =============================================================================
# Container Security Scanning (Trivy 0.48+)
# =============================================================================

run_container_vulnerability_scan() {
    log_info "Starting container vulnerability scanning with Trivy..."
    
    local scan_results="${REPORT_DIR}/trivy-container-scan-${TIMESTAMP}.json"
    local sarif_output="${REPORT_DIR}/trivy-container-scan-${TIMESTAMP}.sarif"
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    
    # Build Flask application Docker image for scanning
    log_info "Building Docker image for security scanning..."
    if ! docker build -t flask-security-scan:latest "${PROJECT_ROOT}" -f "${PROJECT_ROOT}/Dockerfile" &> "${REPORT_DIR}/docker-build.log"; then
        log_error "Failed to build Docker image for scanning"
        return $EXIT_CONFIGURATION_ERROR
    fi
    
    # Run Trivy vulnerability scan with comprehensive configuration
    log_info "Running Trivy container vulnerability scan..."
    
    local trivy_cmd=(
        trivy image
        --format json
        --output "$scan_results"
        --severity "CRITICAL,HIGH,MEDIUM,LOW"
        --vuln-type "os,library"
        --scanners "vuln,secret,config"
        --timeout 15m
        --cache-dir "${REPORT_DIR}/.trivy-cache"
        --db-repository "ghcr.io/aquasecurity/trivy-db"
        --java-db-repository "ghcr.io/aquasecurity/trivy-java-db"
        flask-security-scan:latest
    )
    
    if ! "${trivy_cmd[@]}" 2> "${REPORT_DIR}/trivy-error.log"; then
        log_error "Trivy container scan failed. Check ${REPORT_DIR}/trivy-error.log for details"
        return $EXIT_CONFIGURATION_ERROR
    fi
    
    # Generate SARIF format for GitHub Actions integration
    trivy image --format sarif --output "$sarif_output" flask-security-scan:latest 2>/dev/null || true
    
    # Parse scan results and count vulnerabilities by severity
    if [[ -f "$scan_results" ]]; then
        # Extract vulnerability counts using jq
        if command -v jq &> /dev/null; then
            critical_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$scan_results" 2>/dev/null || echo 0)
            high_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$scan_results" 2>/dev/null || echo 0)
            medium_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$scan_results" 2>/dev/null || echo 0)
            low_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$scan_results" 2>/dev/null || echo 0)
        else
            # Fallback parsing without jq
            critical_count=$(grep -c '"Severity": "CRITICAL"' "$scan_results" 2>/dev/null || echo 0)
            high_count=$(grep -c '"Severity": "HIGH"' "$scan_results" 2>/dev/null || echo 0)
            medium_count=$(grep -c '"Severity": "MEDIUM"' "$scan_results" 2>/dev/null || echo 0)
            low_count=$(grep -c '"Severity": "LOW"' "$scan_results" 2>/dev/null || echo 0)
        fi
    fi
    
    # Generate human-readable report
    generate_container_scan_report "$scan_results" "$critical_count" "$high_count" "$medium_count" "$low_count"
    
    # Send metrics to Prometheus if endpoint configured
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        send_container_scan_metrics "$critical_count" "$high_count" "$medium_count" "$low_count"
    fi
    
    # Upload to AWS Security Hub if integration enabled
    if [[ "$AWS_INTEGRATION" == "true" ]]; then
        upload_container_scan_to_aws_security_hub "$scan_results"
    fi
    
    # Apply security policy enforcement per Section 8.5.2
    if [[ $critical_count -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "Container scan found $critical_count critical vulnerabilities - Build terminated per security policy"
        return $EXIT_CRITICAL_VULNERABILITIES
    elif [[ $high_count -gt 10 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_warn "Container scan found $high_count high-severity vulnerabilities - Security review required"
        return $EXIT_CRITICAL_VULNERABILITIES
    fi
    
    log_info "Container vulnerability scan completed successfully"
    return $EXIT_SUCCESS
}

generate_container_scan_report() {
    local scan_results="$1"
    local critical_count="$2"
    local high_count="$3"
    local medium_count="$4"
    local low_count="$5"
    
    local report_file="${REPORT_DIR}/container-security-report-${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Flask Application Container Security Scan Report
================================================
Scan Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Scanner: Trivy ${TRIVY_MIN_VERSION}+
Image: flask-security-scan:latest

VULNERABILITY SUMMARY
=====================
Critical: ${critical_count}
High:     ${high_count}
Medium:   ${medium_count}
Low:      ${low_count}

SECURITY POLICY COMPLIANCE
==========================
$(if [[ $critical_count -eq 0 ]]; then
    echo "✅ PASSED - No critical vulnerabilities found"
else
    echo "❌ FAILED - Critical vulnerabilities detected (Policy: Block deployment)"
fi)

$(if [[ $high_count -le 10 ]]; then
    echo "✅ PASSED - High-severity vulnerabilities within acceptable threshold"
else
    echo "⚠️  WARNING - High-severity vulnerabilities exceed threshold (${high_count} > 10)"
fi)

REMEDIATION RECOMMENDATIONS
===========================
EOF
    
    # Add specific remediation recommendations if jq is available
    if command -v jq &> /dev/null && [[ -f "$scan_results" ]]; then
        echo "" >> "$report_file"
        echo "TOP CRITICAL VULNERABILITIES:" >> "$report_file"
        echo "==============================" >> "$report_file"
        
        jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | "• \(.VulnerabilityID): \(.Title // "No title") - \(.InstalledVersion) -> \(.FixedVersion // "No fix available")"' "$scan_results" 2>/dev/null | head -5 >> "$report_file" || true
        
        echo "" >> "$report_file"
        echo "For complete details, see: $scan_results" >> "$report_file"
    fi
    
    log_info "Container security report generated: $report_file"
}

send_container_scan_metrics() {
    local critical_count="$1"
    local high_count="$2"
    local medium_count="$3"
    local low_count="$4"
    
    log_debug "Sending container scan metrics to Prometheus endpoint: $METRICS_ENDPOINT"
    
    # Send metrics using curl (Prometheus pushgateway format)
    local metrics_data="
# TYPE container_vulnerabilities_critical gauge
container_vulnerabilities_critical{scanner=\"trivy\",image=\"flask-security-scan\"} ${critical_count}
# TYPE container_vulnerabilities_high gauge
container_vulnerabilities_high{scanner=\"trivy\",image=\"flask-security-scan\"} ${high_count}
# TYPE container_vulnerabilities_medium gauge
container_vulnerabilities_medium{scanner=\"trivy\",image=\"flask-security-scan\"} ${medium_count}
# TYPE container_vulnerabilities_low gauge
container_vulnerabilities_low{scanner=\"trivy\",image=\"flask-security-scan\"} ${low_count}
# TYPE container_scan_timestamp gauge
container_scan_timestamp{scanner=\"trivy\",image=\"flask-security-scan\"} $(date +%s)
"
    
    if curl -X POST --data-binary "$metrics_data" "${METRICS_ENDPOINT}/metrics/job/security-scanner/instance/container-scan" &>/dev/null; then
        log_debug "Container scan metrics sent successfully"
    else
        log_warn "Failed to send container scan metrics to Prometheus"
    fi
}

upload_container_scan_to_aws_security_hub() {
    local scan_results="$1"
    
    log_debug "Uploading container scan results to AWS Security Hub..."
    
    # Convert Trivy JSON to AWS Security Hub format
    # This would require a more complex transformation - placeholder for enterprise integration
    if command -v aws &> /dev/null; then
        local finding_data="{
            \"SchemaVersion\": \"2018-10-08\",
            \"Id\": \"trivy-container-scan-$(date +%s)\",
            \"ProductArn\": \"arn:aws:securityhub:::product/aquasecurity/trivy\",
            \"GeneratorId\": \"trivy-container-scanner\",
            \"AwsAccountId\": \"$(aws sts get-caller-identity --query Account --output text)\",
            \"CreatedAt\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",
            \"UpdatedAt\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",
            \"Severity\": {
                \"Label\": \"HIGH\"
            },
            \"Title\": \"Container Vulnerability Scan\",
            \"Description\": \"Trivy container vulnerability scan results for Flask application\"
        }"
        
        # Note: This is a simplified example. Production implementation would
        # require proper transformation of Trivy JSON to Security Hub format
        log_debug "AWS Security Hub integration placeholder - implement full transformation in production"
    fi
}

# =============================================================================
# Dependency Vulnerability Scanning (safety 3.0+ & pip-audit)
# =============================================================================

run_dependency_vulnerability_scan() {
    log_info "Starting dependency vulnerability scanning with safety and pip-audit..."
    
    local safety_results="${REPORT_DIR}/safety-scan-${TIMESTAMP}.json"
    local pip_audit_results="${REPORT_DIR}/pip-audit-scan-${TIMESTAMP}.json"
    local combined_report="${REPORT_DIR}/dependency-security-report-${TIMESTAMP}.txt"
    local total_vulnerabilities=0
    local critical_vulnerabilities=0
    
    # Run safety vulnerability scan
    log_info "Running safety dependency vulnerability scan..."
    
    if ! safety check --json --output "$safety_results" 2>"${REPORT_DIR}/safety-error.log"; then
        log_warn "Safety scan completed with findings. Analyzing results..."
    fi
    
    # Run pip-audit for additional vulnerability detection
    log_info "Running pip-audit dependency vulnerability scan..."
    
    if ! pip-audit --format=json --output="$pip_audit_results" --require="${PROJECT_ROOT}/requirements.txt" 2>"${REPORT_DIR}/pip-audit-error.log"; then
        log_warn "pip-audit scan completed with findings. Analyzing results..."
    fi
    
    # Analyze safety results
    if [[ -f "$safety_results" ]] && command -v jq &> /dev/null; then
        # Count vulnerabilities from safety results
        local safety_vuln_count=$(jq 'length' "$safety_results" 2>/dev/null || echo 0)
        total_vulnerabilities=$((total_vulnerabilities + safety_vuln_count))
        
        # Count critical vulnerabilities (CVE score >= 9.0)
        local safety_critical=$(jq '[.[] | select(.vulnerability.specs[0] >= "9.0")] | length' "$safety_results" 2>/dev/null || echo 0)
        critical_vulnerabilities=$((critical_vulnerabilities + safety_critical))
    fi
    
    # Analyze pip-audit results
    if [[ -f "$pip_audit_results" ]] && command -v jq &> /dev/null; then
        # Count vulnerabilities from pip-audit results
        local pip_audit_vuln_count=$(jq '[.vulnerabilities] | flatten | length' "$pip_audit_results" 2>/dev/null || echo 0)
        total_vulnerabilities=$((total_vulnerabilities + pip_audit_vuln_count))
        
        # Count critical vulnerabilities (CVSS >= 9.0)
        local pip_audit_critical=$(jq '[.vulnerabilities | flatten[] | select(.advisory.summary | test("CVSS:9|CVSS:10"))] | length' "$pip_audit_results" 2>/dev/null || echo 0)
        critical_vulnerabilities=$((critical_vulnerabilities + pip_audit_critical))
    fi
    
    # Generate comprehensive dependency security report
    generate_dependency_scan_report "$safety_results" "$pip_audit_results" "$total_vulnerabilities" "$critical_vulnerabilities"
    
    # Send metrics to Prometheus if endpoint configured
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        send_dependency_scan_metrics "$total_vulnerabilities" "$critical_vulnerabilities"
    fi
    
    # Apply security policy enforcement per Section 8.5.1
    if [[ $critical_vulnerabilities -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "Dependency scan found $critical_vulnerabilities critical vulnerabilities - Deployment blocked per security policy"
        return $EXIT_CRITICAL_VULNERABILITIES
    elif [[ $total_vulnerabilities -gt 20 ]]; then
        log_warn "Dependency scan found $total_vulnerabilities total vulnerabilities - Security review recommended"
    fi
    
    log_info "Dependency vulnerability scan completed successfully"
    return $EXIT_SUCCESS
}

generate_dependency_scan_report() {
    local safety_results="$1"
    local pip_audit_results="$2"
    local total_vulnerabilities="$3"
    local critical_vulnerabilities="$4"
    
    local report_file="${REPORT_DIR}/dependency-security-report-${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Flask Application Dependency Security Scan Report
=================================================
Scan Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Scanners: safety ${SAFETY_MIN_VERSION}+, pip-audit 2.7+
Requirements File: ${PROJECT_ROOT}/requirements.txt

VULNERABILITY SUMMARY
=====================
Total Vulnerabilities: ${total_vulnerabilities}
Critical Vulnerabilities: ${critical_vulnerabilities}

SECURITY POLICY COMPLIANCE
==========================
$(if [[ $critical_vulnerabilities -eq 0 ]]; then
    echo "✅ PASSED - No critical vulnerabilities found"
else
    echo "❌ FAILED - Critical vulnerabilities detected (Policy: Block deployment)"
fi)

$(if [[ $total_vulnerabilities -le 20 ]]; then
    echo "✅ PASSED - Total vulnerabilities within acceptable threshold"
else
    echo "⚠️  WARNING - Total vulnerabilities exceed recommended threshold (${total_vulnerabilities} > 20)"
fi)

REMEDIATION RECOMMENDATIONS
===========================
EOF
    
    # Add specific remediation recommendations from safety results
    if command -v jq &> /dev/null && [[ -f "$safety_results" ]]; then
        echo "" >> "$report_file"
        echo "SAFETY SCAN FINDINGS:" >> "$report_file"
        echo "=====================" >> "$report_file"
        
        jq -r '.[] | "• \(.package_name) \(.version): \(.advisory) (ID: \(.vulnerability.id))"' "$safety_results" 2>/dev/null >> "$report_file" || echo "No safety vulnerabilities found" >> "$report_file"
    fi
    
    # Add specific remediation recommendations from pip-audit results
    if command -v jq &> /dev/null && [[ -f "$pip_audit_results" ]]; then
        echo "" >> "$report_file"
        echo "PIP-AUDIT SCAN FINDINGS:" >> "$report_file"
        echo "========================" >> "$report_file"
        
        jq -r '.vulnerabilities | flatten[] | "• \(.package) \(.installed_version): \(.advisory.summary) (Fix: \(.fix_versions[]? // "No fix available"))"' "$pip_audit_results" 2>/dev/null >> "$report_file" || echo "No pip-audit vulnerabilities found" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "AUTOMATED REMEDIATION COMMANDS:" >> "$report_file"
    echo "===============================" >> "$report_file"
    echo "# Update all packages to latest versions:" >> "$report_file"
    echo "pip install --upgrade -r requirements.txt" >> "$report_file"
    echo "" >> "$report_file"
    echo "# Generate updated requirements with security fixes:" >> "$report_file"
    echo "pip-audit --fix --require requirements.txt --output requirements-fixed.txt" >> "$report_file"
    echo "" >> "$report_file"
    echo "For complete details, see:" >> "$report_file"
    echo "- Safety results: $safety_results" >> "$report_file"
    echo "- pip-audit results: $pip_audit_results" >> "$report_file"
    
    log_info "Dependency security report generated: $report_file"
}

send_dependency_scan_metrics() {
    local total_vulnerabilities="$1"
    local critical_vulnerabilities="$2"
    
    log_debug "Sending dependency scan metrics to Prometheus endpoint: $METRICS_ENDPOINT"
    
    local metrics_data="
# TYPE dependency_vulnerabilities_total gauge
dependency_vulnerabilities_total{scanner=\"safety+pip-audit\",project=\"flask-app\"} ${total_vulnerabilities}
# TYPE dependency_vulnerabilities_critical gauge
dependency_vulnerabilities_critical{scanner=\"safety+pip-audit\",project=\"flask-app\"} ${critical_vulnerabilities}
# TYPE dependency_scan_timestamp gauge
dependency_scan_timestamp{scanner=\"safety+pip-audit\",project=\"flask-app\"} $(date +%s)
"
    
    if curl -X POST --data-binary "$metrics_data" "${METRICS_ENDPOINT}/metrics/job/security-scanner/instance/dependency-scan" &>/dev/null; then
        log_debug "Dependency scan metrics sent successfully"
    else
        log_warn "Failed to send dependency scan metrics to Prometheus"
    fi
}

# =============================================================================
# Static Code Analysis (bandit, flake8, mypy)
# =============================================================================

run_static_code_analysis() {
    log_info "Starting static code analysis with bandit, flake8, and mypy..."
    
    local bandit_results="${REPORT_DIR}/bandit-scan-${TIMESTAMP}.json"
    local flake8_results="${REPORT_DIR}/flake8-scan-${TIMESTAMP}.txt"
    local mypy_results="${REPORT_DIR}/mypy-scan-${TIMESTAMP}.txt"
    local analysis_report="${REPORT_DIR}/static-analysis-report-${TIMESTAMP}.txt"
    
    local bandit_issues=0
    local flake8_issues=0
    local mypy_issues=0
    local critical_security_issues=0
    
    # Run bandit security analysis
    log_info "Running bandit Python security analysis..."
    
    if ! bandit -r "${PROJECT_ROOT}/src" -f json -o "$bandit_results" -ll -x "${PROJECT_ROOT}/src/tests" 2>"${REPORT_DIR}/bandit-error.log"; then
        log_warn "Bandit analysis completed with findings. Analyzing results..."
    fi
    
    # Count bandit issues
    if [[ -f "$bandit_results" ]] && command -v jq &> /dev/null; then
        bandit_issues=$(jq '.results | length' "$bandit_results" 2>/dev/null || echo 0)
        critical_security_issues=$(jq '[.results[] | select(.issue_severity == "HIGH" or .issue_severity == "CRITICAL")] | length' "$bandit_results" 2>/dev/null || echo 0)
    fi
    
    # Run flake8 code style analysis
    log_info "Running flake8 code style analysis..."
    
    if ! flake8 "${PROJECT_ROOT}/src" --config="${PROJECT_ROOT}/.flake8" --output-file="$flake8_results" --statistics --count 2>/dev/null; then
        log_warn "flake8 analysis completed with findings. Analyzing results..."
    fi
    
    # Count flake8 issues
    if [[ -f "$flake8_results" ]]; then
        flake8_issues=$(wc -l < "$flake8_results" 2>/dev/null || echo 0)
    fi
    
    # Run mypy type checking
    log_info "Running mypy type safety validation..."
    
    if ! mypy "${PROJECT_ROOT}/src" --config-file="${PROJECT_ROOT}/mypy.ini" > "$mypy_results" 2>&1; then
        log_warn "mypy analysis completed with findings. Analyzing results..."
    fi
    
    # Count mypy issues
    if [[ -f "$mypy_results" ]]; then
        mypy_issues=$(grep -c "error:" "$mypy_results" 2>/dev/null || echo 0)
    fi
    
    # Generate static analysis report
    generate_static_analysis_report "$bandit_results" "$flake8_results" "$mypy_results" "$bandit_issues" "$flake8_issues" "$mypy_issues" "$critical_security_issues"
    
    # Send metrics to Prometheus if endpoint configured
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        send_static_analysis_metrics "$bandit_issues" "$flake8_issues" "$mypy_issues" "$critical_security_issues"
    fi
    
    # Apply quality gate enforcement per Section 8.5.1
    local exit_code=$EXIT_SUCCESS
    
    if [[ $critical_security_issues -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "Static analysis found $critical_security_issues critical security issues - Build terminated per security policy"
        exit_code=$EXIT_CRITICAL_VULNERABILITIES
    fi
    
    if [[ $flake8_issues -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "flake8 found $flake8_issues code style violations - Zero errors required per quality gate"
        exit_code=$EXIT_CRITICAL_VULNERABILITIES
    fi
    
    if [[ $mypy_issues -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "mypy found $mypy_issues type checking issues - 100% type check success required per quality gate"
        exit_code=$EXIT_CRITICAL_VULNERABILITIES
    fi
    
    if [[ $exit_code -eq $EXIT_SUCCESS ]]; then
        log_info "Static code analysis completed successfully - All quality gates passed"
    fi
    
    return $exit_code
}

generate_static_analysis_report() {
    local bandit_results="$1"
    local flake8_results="$2"
    local mypy_results="$3"
    local bandit_issues="$4"
    local flake8_issues="$5"
    local mypy_issues="$6"
    local critical_security_issues="$7"
    
    local report_file="${REPORT_DIR}/static-analysis-report-${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Flask Application Static Code Analysis Report
=============================================
Analysis Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Analyzers: bandit ${BANDIT_MIN_VERSION}+, flake8 ${FLAKE8_MIN_VERSION}+, mypy ${MYPY_MIN_VERSION}+
Source Directory: ${PROJECT_ROOT}/src

ANALYSIS SUMMARY
================
Bandit Security Issues: ${bandit_issues} (Critical/High: ${critical_security_issues})
flake8 Style Issues: ${flake8_issues}
mypy Type Issues: ${mypy_issues}

QUALITY GATE COMPLIANCE
========================
$(if [[ $critical_security_issues -eq 0 ]]; then
    echo "✅ PASSED - No critical security issues found (bandit)"
else
    echo "❌ FAILED - Critical security issues detected (Policy: Block deployment)"
fi)

$(if [[ $flake8_issues -eq 0 ]]; then
    echo "✅ PASSED - Zero code style violations (flake8)"
else
    echo "❌ FAILED - Code style violations detected (Policy: Zero errors required)"
fi)

$(if [[ $mypy_issues -eq 0 ]]; then
    echo "✅ PASSED - 100% type check success (mypy)"
else
    echo "❌ FAILED - Type checking issues detected (Policy: 100% success required)"
fi)

REMEDIATION RECOMMENDATIONS
===========================
EOF
    
    # Add bandit findings if available
    if command -v jq &> /dev/null && [[ -f "$bandit_results" ]]; then
        echo "" >> "$report_file"
        echo "TOP SECURITY ISSUES (bandit):" >> "$report_file"
        echo "==============================" >> "$report_file"
        
        jq -r '.results[] | "• \(.filename):\(.line_number): \(.test_id) - \(.issue_text) (\(.issue_severity))"' "$bandit_results" 2>/dev/null | head -10 >> "$report_file" || echo "No bandit issues found" >> "$report_file"
    fi
    
    # Add flake8 findings
    if [[ -f "$flake8_results" && -s "$flake8_results" ]]; then
        echo "" >> "$report_file"
        echo "CODE STYLE ISSUES (flake8):" >> "$report_file"
        echo "============================" >> "$report_file"
        head -10 "$flake8_results" >> "$report_file"
        if [[ $(wc -l < "$flake8_results") -gt 10 ]]; then
            echo "... and $((flake8_issues - 10)) more issues" >> "$report_file"
        fi
    fi
    
    # Add mypy findings
    if [[ -f "$mypy_results" && -s "$mypy_results" ]]; then
        echo "" >> "$report_file"
        echo "TYPE CHECKING ISSUES (mypy):" >> "$report_file"
        echo "=============================" >> "$report_file"
        grep "error:" "$mypy_results" | head -10 >> "$report_file" || echo "No mypy issues found" >> "$report_file"
        if [[ $mypy_issues -gt 10 ]]; then
            echo "... and $((mypy_issues - 10)) more issues" >> "$report_file"
        fi
    fi
    
    echo "" >> "$report_file"
    echo "AUTOMATED REMEDIATION COMMANDS:" >> "$report_file"
    echo "===============================" >> "$report_file"
    echo "# Fix code style issues automatically:" >> "$report_file"
    echo "autopep8 --in-place --recursive src/" >> "$report_file"
    echo "black src/" >> "$report_file"
    echo "" >> "$report_file"
    echo "# Check specific bandit findings:" >> "$report_file"
    echo "bandit -r src/ -ll" >> "$report_file"
    echo "" >> "$report_file"
    echo "# Run type checking with detailed output:" >> "$report_file"
    echo "mypy src/ --show-error-codes --show-error-context" >> "$report_file"
    echo "" >> "$report_file"
    echo "For complete details, see:" >> "$report_file"
    echo "- Bandit results: $bandit_results" >> "$report_file"
    echo "- flake8 results: $flake8_results" >> "$report_file"
    echo "- mypy results: $mypy_results" >> "$report_file"
    
    log_info "Static analysis report generated: $report_file"
}

send_static_analysis_metrics() {
    local bandit_issues="$1"
    local flake8_issues="$2"
    local mypy_issues="$3"
    local critical_security_issues="$4"
    
    log_debug "Sending static analysis metrics to Prometheus endpoint: $METRICS_ENDPOINT"
    
    local metrics_data="
# TYPE static_analysis_security_issues gauge
static_analysis_security_issues{analyzer=\"bandit\",project=\"flask-app\"} ${bandit_issues}
# TYPE static_analysis_security_critical gauge
static_analysis_security_critical{analyzer=\"bandit\",project=\"flask-app\"} ${critical_security_issues}
# TYPE static_analysis_style_issues gauge
static_analysis_style_issues{analyzer=\"flake8\",project=\"flask-app\"} ${flake8_issues}
# TYPE static_analysis_type_issues gauge
static_analysis_type_issues{analyzer=\"mypy\",project=\"flask-app\"} ${mypy_issues}
# TYPE static_analysis_timestamp gauge
static_analysis_timestamp{project=\"flask-app\"} $(date +%s)
"
    
    if curl -X POST --data-binary "$metrics_data" "${METRICS_ENDPOINT}/metrics/job/security-scanner/instance/static-analysis" &>/dev/null; then
        log_debug "Static analysis metrics sent successfully"
    else
        log_warn "Failed to send static analysis metrics to Prometheus"
    fi
}

# =============================================================================
# Security Test Suite Validation
# =============================================================================

run_security_test_validation() {
    log_info "Starting security test suite validation..."
    
    local test_results="${REPORT_DIR}/security-tests-${TIMESTAMP}.xml"
    local coverage_results="${REPORT_DIR}/security-coverage-${TIMESTAMP}.xml"
    local test_report="${REPORT_DIR}/security-test-report-${TIMESTAMP}.txt"
    
    local test_exit_code=0
    local coverage_percentage=0
    local security_tests_passed=0
    local security_tests_failed=0
    
    # Run security-focused test suite with coverage
    log_info "Running security test suite with pytest..."
    
    local pytest_cmd=(
        pytest
        "${PROJECT_ROOT}/tests/security"
        "${PROJECT_ROOT}/tests/integration"
        --cov="${PROJECT_ROOT}/src"
        --cov-config="${PROJECT_ROOT}/.coveragerc"
        --cov-report=xml:"$coverage_results"
        --cov-report=term-missing
        --junit-xml="$test_results"
        --verbose
        --tb=short
        -k "security or auth or validation"
    )
    
    if ! "${pytest_cmd[@]}" > "${REPORT_DIR}/pytest-output.log" 2>&1; then
        test_exit_code=1
        log_warn "Security test suite completed with failures. Analyzing results..."
    fi
    
    # Parse test results
    if [[ -f "$test_results" ]] && command -v xml2 &> /dev/null; then
        # Count passed and failed tests from JUnit XML
        security_tests_passed=$(xml2 < "$test_results" | grep -c "/testcase=" 2>/dev/null || echo 0)
        security_tests_failed=$(xml2 < "$test_results" | grep -c "failure=" 2>/dev/null || echo 0)
    elif [[ -f "${REPORT_DIR}/pytest-output.log" ]]; then
        # Fallback parsing from pytest output
        security_tests_passed=$(grep -c "PASSED" "${REPORT_DIR}/pytest-output.log" 2>/dev/null || echo 0)
        security_tests_failed=$(grep -c "FAILED" "${REPORT_DIR}/pytest-output.log" 2>/dev/null || echo 0)
    fi
    
    # Parse coverage percentage
    if [[ -f "$coverage_results" ]]; then
        coverage_percentage=$(grep -o 'line-rate="[0-9.]*"' "$coverage_results" | head -1 | cut -d'"' -f2 | awk '{print int($1*100)}' || echo 0)
    fi
    
    # Generate security test report
    generate_security_test_report "$test_results" "$coverage_results" "$security_tests_passed" "$security_tests_failed" "$coverage_percentage"
    
    # Send metrics to Prometheus if endpoint configured
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        send_security_test_metrics "$security_tests_passed" "$security_tests_failed" "$coverage_percentage"
    fi
    
    # Apply test coverage quality gate per Section 8.5.1
    local required_coverage=90
    if [[ $coverage_percentage -lt $required_coverage ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "Security test coverage is ${coverage_percentage}% - Below required ${required_coverage}% threshold"
        return $EXIT_CRITICAL_VULNERABILITIES
    fi
    
    if [[ $security_tests_failed -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log_error "Security test suite has $security_tests_failed failing tests - All security tests must pass"
        return $EXIT_CRITICAL_VULNERABILITIES
    fi
    
    log_info "Security test validation completed successfully"
    return $EXIT_SUCCESS
}

generate_security_test_report() {
    local test_results="$1"
    local coverage_results="$2"
    local tests_passed="$3"
    local tests_failed="$4"
    local coverage_percentage="$5"
    
    local report_file="${REPORT_DIR}/security-test-report-${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Flask Application Security Test Validation Report
=================================================
Test Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Test Framework: pytest with coverage
Test Scope: Security, Authentication, Validation

TEST SUMMARY
============
Tests Passed: ${tests_passed}
Tests Failed: ${tests_failed}
Security Coverage: ${coverage_percentage}%

QUALITY GATE COMPLIANCE
========================
$(if [[ $tests_failed -eq 0 ]]; then
    echo "✅ PASSED - All security tests passing"
else
    echo "❌ FAILED - Security test failures detected (Policy: All tests must pass)"
fi)

$(if [[ $coverage_percentage -ge 90 ]]; then
    echo "✅ PASSED - Security test coverage ≥90% requirement met"
else
    echo "❌ FAILED - Security test coverage below 90% threshold (${coverage_percentage}%)"
fi)

SECURITY TEST CATEGORIES
========================
EOF
    
    # Add test category breakdown if available
    if [[ -f "${REPORT_DIR}/pytest-output.log" ]]; then
        echo "" >> "$report_file"
        echo "TEST EXECUTION DETAILS:" >> "$report_file"
        echo "=======================" >> "$report_file"
        
        # Extract test categories from pytest output
        grep -E "(test_.*security|test_.*auth|test_.*validation)" "${REPORT_DIR}/pytest-output.log" | head -20 >> "$report_file" 2>/dev/null || echo "Detailed test information not available" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "REMEDIATION RECOMMENDATIONS:" >> "$report_file"
    echo "============================" >> "$report_file"
    echo "# Run specific security test categories:" >> "$report_file"
    echo "pytest tests/security/ -v" >> "$report_file"
    echo "pytest tests/integration/ -k 'auth' -v" >> "$report_file"
    echo "" >> "$report_file"
    echo "# Generate detailed coverage report:" >> "$report_file"
    echo "pytest --cov=src --cov-report=html --cov-report=term-missing" >> "$report_file"
    echo "" >> "$report_file"
    echo "# Run security tests with specific markers:" >> "$report_file"
    echo "pytest -m 'security or authentication' -v" >> "$report_file"
    echo "" >> "$report_file"
    echo "For complete details, see:" >> "$report_file"
    echo "- Test results: $test_results" >> "$report_file"
    echo "- Coverage results: $coverage_results" >> "$report_file"
    echo "- Test output: ${REPORT_DIR}/pytest-output.log" >> "$report_file"
    
    log_info "Security test report generated: $report_file"
}

send_security_test_metrics() {
    local tests_passed="$1"
    local tests_failed="$2"
    local coverage_percentage="$3"
    
    log_debug "Sending security test metrics to Prometheus endpoint: $METRICS_ENDPOINT"
    
    local metrics_data="
# TYPE security_tests_passed gauge
security_tests_passed{project=\"flask-app\",suite=\"security\"} ${tests_passed}
# TYPE security_tests_failed gauge
security_tests_failed{project=\"flask-app\",suite=\"security\"} ${tests_failed}
# TYPE security_test_coverage_percentage gauge
security_test_coverage_percentage{project=\"flask-app\",suite=\"security\"} ${coverage_percentage}
# TYPE security_test_timestamp gauge
security_test_timestamp{project=\"flask-app\",suite=\"security\"} $(date +%s)
"
    
    if curl -X POST --data-binary "$metrics_data" "${METRICS_ENDPOINT}/metrics/job/security-scanner/instance/security-tests" &>/dev/null; then
        log_debug "Security test metrics sent successfully"
    else
        log_warn "Failed to send security test metrics to Prometheus"
    fi
}

# =============================================================================
# Compliance Validation
# =============================================================================

run_compliance_validation() {
    log_info "Starting comprehensive compliance validation..."
    
    local compliance_report="${REPORT_DIR}/compliance-validation-${TIMESTAMP}.txt"
    local compliance_score=0
    local total_checks=0
    local compliance_violations=()
    
    # Initialize compliance report
    cat > "$compliance_report" << EOF
Flask Application Compliance Validation Report
==============================================
Validation Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Compliance Frameworks: SOC 2, ISO 27001, OWASP Top 10, NIST Framework
Project: Flask Application Security Migration

COMPLIANCE VALIDATION SUMMARY
==============================
EOF
    
    # Security Configuration Compliance
    log_info "Validating security configuration compliance..."
    
    local config_checks=0
    local config_passed=0
    
    # Check Flask-Talisman security headers configuration
    if [[ -f "${PROJECT_ROOT}/src/config/security.py" ]]; then
        ((config_checks++))
        if grep -q "Flask-Talisman" "${PROJECT_ROOT}/src/config/security.py"; then
            ((config_passed++))
            log_debug "✅ Flask-Talisman security headers configured"
        else
            compliance_violations+=("Flask-Talisman security headers not configured")
            log_warn "❌ Flask-Talisman security headers not configured"
        fi
        
        # Check HTTPS enforcement
        ((config_checks++))
        if grep -q "force_https.*True" "${PROJECT_ROOT}/src/config/security.py"; then
            ((config_passed++))
            log_debug "✅ HTTPS enforcement configured"
        else
            compliance_violations+=("HTTPS enforcement not configured")
            log_warn "❌ HTTPS enforcement not configured"
        fi
        
        # Check Content Security Policy
        ((config_checks++))
        if grep -q "content_security_policy" "${PROJECT_ROOT}/src/config/security.py"; then
            ((config_passed++))
            log_debug "✅ Content Security Policy configured"
        else
            compliance_violations+=("Content Security Policy not configured")
            log_warn "❌ Content Security Policy not configured"
        fi
        
        # Check session security configuration
        ((config_checks++))
        if grep -q "session_cookie_secure.*True" "${PROJECT_ROOT}/src/config/security.py"; then
            ((config_passed++))
            log_debug "✅ Secure session cookies configured"
        else
            compliance_violations+=("Secure session cookies not configured")
            log_warn "❌ Secure session cookies not configured"
        fi
    else
        compliance_violations+=("Security configuration file not found")
        log_warn "❌ Security configuration file not found"
    fi
    
    total_checks=$((total_checks + config_checks))
    compliance_score=$((compliance_score + config_passed))
    
    # Authentication and Authorization Compliance
    log_info "Validating authentication and authorization compliance..."
    
    local auth_checks=0
    local auth_passed=0
    
    # Check Auth0 integration
    if [[ -f "${PROJECT_ROOT}/src/config/auth.py" ]]; then
        ((auth_checks++))
        if grep -q "Auth0" "${PROJECT_ROOT}/src/config/auth.py"; then
            ((auth_passed++))
            log_debug "✅ Auth0 integration configured"
        else
            compliance_violations+=("Auth0 integration not configured")
            log_warn "❌ Auth0 integration not configured"
        fi
        
        # Check JWT validation
        ((auth_checks++))
        if grep -q "PyJWT" "${PROJECT_ROOT}/src/config/auth.py"; then
            ((auth_passed++))
            log_debug "✅ JWT validation configured"
        else
            compliance_violations+=("JWT validation not configured")
            log_warn "❌ JWT validation not configured"
        fi
        
        # Check Flask-Login integration
        ((auth_checks++))
        if grep -q "Flask-Login" "${PROJECT_ROOT}/src/config/auth.py"; then
            ((auth_passed++))
            log_debug "✅ Flask-Login session management configured"
        else
            compliance_violations+=("Flask-Login session management not configured")
            log_warn "❌ Flask-Login session management not configured"
        fi
    else
        compliance_violations+=("Authentication configuration file not found")
        log_warn "❌ Authentication configuration file not found"
    fi
    
    total_checks=$((total_checks + auth_checks))
    compliance_score=$((compliance_score + auth_passed))
    
    # Encryption and Data Protection Compliance
    log_info "Validating encryption and data protection compliance..."
    
    local encryption_checks=0
    local encryption_passed=0
    
    # Check requirements.txt for security dependencies
    if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        ((encryption_checks++))
        if grep -q "cryptography" "${PROJECT_ROOT}/requirements.txt"; then
            ((encryption_passed++))
            log_debug "✅ Cryptography library included"
        else
            compliance_violations+=("Cryptography library not included in requirements")
            log_warn "❌ Cryptography library not included in requirements"
        fi
        
        # Check for secure Redis configuration
        ((encryption_checks++))
        if grep -q "redis" "${PROJECT_ROOT}/requirements.txt"; then
            ((encryption_passed++))
            log_debug "✅ Redis client library included"
        else
            compliance_violations+=("Redis client library not included in requirements")
            log_warn "❌ Redis client library not included in requirements"
        fi
        
        # Check for input validation libraries
        ((encryption_checks++))
        if grep -qE "(marshmallow|pydantic)" "${PROJECT_ROOT}/requirements.txt"; then
            ((encryption_passed++))
            log_debug "✅ Input validation libraries included"
        else
            compliance_violations+=("Input validation libraries not included in requirements")
            log_warn "❌ Input validation libraries not included in requirements"
        fi
    fi
    
    total_checks=$((total_checks + encryption_checks))
    compliance_score=$((compliance_score + encryption_passed))
    
    # CI/CD Security Integration Compliance
    log_info "Validating CI/CD security integration compliance..."
    
    local cicd_checks=0
    local cicd_passed=0
    
    # Check for GitHub Actions security workflow
    if [[ -f "${PROJECT_ROOT}/.github/workflows/security.yml" ]] || [[ -f "${PROJECT_ROOT}/.github/workflows/ci.yml" ]]; then
        ((cicd_checks++))
        ((cicd_passed++))
        log_debug "✅ GitHub Actions security workflow configured"
    else
        compliance_violations+=("GitHub Actions security workflow not configured")
        log_warn "❌ GitHub Actions security workflow not configured"
    fi
    
    # Check for Docker security configuration
    if [[ -f "${PROJECT_ROOT}/Dockerfile" ]]; then
        ((cicd_checks++))
        if grep -q "python:.*slim" "${PROJECT_ROOT}/Dockerfile"; then
            ((cicd_passed++))
            log_debug "✅ Secure Docker base image configured"
        else
            compliance_violations+=("Secure Docker base image not configured")
            log_warn "❌ Secure Docker base image not configured"
        fi
    fi
    
    total_checks=$((total_checks + cicd_checks))
    compliance_score=$((compliance_score + cicd_passed))
    
    # Calculate compliance percentage
    local compliance_percentage=0
    if [[ $total_checks -gt 0 ]]; then
        compliance_percentage=$((compliance_score * 100 / total_checks))
    fi
    
    # Generate detailed compliance report
    generate_compliance_report "$compliance_report" "$compliance_score" "$total_checks" "$compliance_percentage" "${compliance_violations[@]}"
    
    # Send metrics to Prometheus if endpoint configured
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        send_compliance_metrics "$compliance_score" "$total_checks" "$compliance_percentage"
    fi
    
    # Apply compliance enforcement policy
    local required_compliance=85
    if [[ $compliance_percentage -lt $required_compliance ]]; then
        log_error "Compliance validation failed: ${compliance_percentage}% (Required: ${required_compliance}%)"
        return $EXIT_COMPLIANCE_VIOLATION
    fi
    
    log_info "Compliance validation completed successfully: ${compliance_percentage}%"
    return $EXIT_SUCCESS
}

generate_compliance_report() {
    local report_file="$1"
    local compliance_score="$2"
    local total_checks="$3"
    local compliance_percentage="$4"
    shift 4
    local violations=("$@")
    
    cat >> "$report_file" << EOF
Compliance Score: ${compliance_score}/${total_checks} (${compliance_percentage}%)

COMPLIANCE STATUS
=================
$(if [[ $compliance_percentage -ge 85 ]]; then
    echo "✅ PASSED - Compliance requirements met (≥85%)"
else
    echo "❌ FAILED - Compliance requirements not met (<85%)"
fi)

FRAMEWORK COMPLIANCE BREAKDOWN
==============================
• SOC 2 Type II: Security controls and audit trails
• ISO 27001: Information security management
• OWASP Top 10: Web application security vulnerabilities
• NIST Cybersecurity Framework: Security controls implementation

COMPLIANCE VIOLATIONS
======================
EOF
    
    if [[ ${#violations[@]} -eq 0 ]]; then
        echo "No compliance violations detected." >> "$report_file"
    else
        for violation in "${violations[@]}"; do
            echo "❌ $violation" >> "$report_file"
        done
    fi
    
    cat >> "$report_file" << EOF

REMEDIATION RECOMMENDATIONS
===========================
• Implement missing security configurations per Section 6.4 requirements
• Enable comprehensive security headers with Flask-Talisman
• Configure proper authentication and authorization controls
• Implement encryption for data in transit and at rest
• Set up automated security scanning in CI/CD pipeline
• Establish comprehensive audit logging with structlog
• Configure monitoring and alerting for security events

COMPLIANCE FRAMEWORKS REFERENCE
===============================
• SOC 2: System and Organization Controls for service organizations
• ISO 27001: International standard for information security management
• OWASP Top 10: Most critical web application security risks
• NIST Framework: Framework for improving critical infrastructure cybersecurity
• PCI DSS: Payment card industry data security standards
• GDPR: General data protection regulation compliance

For detailed remediation guidance, refer to:
- Technical Specification Section 6.4 (Security Architecture)
- Technical Specification Section 8.5 (CI/CD Pipeline)
- OWASP Security Verification Standard
- NIST Cybersecurity Framework Guidelines
EOF
    
    log_info "Compliance validation report generated: $report_file"
}

send_compliance_metrics() {
    local compliance_score="$1"
    local total_checks="$2"
    local compliance_percentage="$3"
    
    log_debug "Sending compliance metrics to Prometheus endpoint: $METRICS_ENDPOINT"
    
    local metrics_data="
# TYPE compliance_score gauge
compliance_score{project=\"flask-app\",framework=\"comprehensive\"} ${compliance_score}
# TYPE compliance_total_checks gauge
compliance_total_checks{project=\"flask-app\",framework=\"comprehensive\"} ${total_checks}
# TYPE compliance_percentage gauge
compliance_percentage{project=\"flask-app\",framework=\"comprehensive\"} ${compliance_percentage}
# TYPE compliance_validation_timestamp gauge
compliance_validation_timestamp{project=\"flask-app\",framework=\"comprehensive\"} $(date +%s)
"
    
    if curl -X POST --data-binary "$metrics_data" "${METRICS_ENDPOINT}/metrics/job/security-scanner/instance/compliance-validation" &>/dev/null; then
        log_debug "Compliance metrics sent successfully"
    else
        log_warn "Failed to send compliance metrics to Prometheus"
    fi
}

# =============================================================================
# Main Execution Flow
# =============================================================================

# Comprehensive security scan execution with proper error handling
run_comprehensive_security_scan() {
    log_info "Starting comprehensive Flask application security scan..."
    
    local overall_exit_code=$EXIT_SUCCESS
    local scan_summary=()
    
    # Container vulnerability scanning
    if [[ "$CONTAINER_SCAN" == "true" ]]; then
        log_info "Executing container vulnerability scanning phase..."
        if ! run_container_vulnerability_scan; then
            local container_exit_code=$?
            overall_exit_code=$container_exit_code
            scan_summary+=("Container scan: FAILED (exit code: $container_exit_code)")
        else
            scan_summary+=("Container scan: PASSED")
        fi
    fi
    
    # Dependency vulnerability scanning
    if [[ "$DEPENDENCY_SCAN" == "true" ]]; then
        log_info "Executing dependency vulnerability scanning phase..."
        if ! run_dependency_vulnerability_scan; then
            local dependency_exit_code=$?
            if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
                overall_exit_code=$dependency_exit_code
            fi
            scan_summary+=("Dependency scan: FAILED (exit code: $dependency_exit_code)")
        else
            scan_summary+=("Dependency scan: PASSED")
        fi
    fi
    
    # Static code analysis
    if [[ "$STATIC_ANALYSIS" == "true" ]]; then
        log_info "Executing static code analysis phase..."
        if ! run_static_code_analysis; then
            local static_exit_code=$?
            if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
                overall_exit_code=$static_exit_code
            fi
            scan_summary+=("Static analysis: FAILED (exit code: $static_exit_code)")
        else
            scan_summary+=("Static analysis: PASSED")
        fi
    fi
    
    # Security test validation
    if [[ "$SECURITY_TESTS" == "true" ]]; then
        log_info "Executing security test validation phase..."
        if ! run_security_test_validation; then
            local test_exit_code=$?
            if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
                overall_exit_code=$test_exit_code
            fi
            scan_summary+=("Security tests: FAILED (exit code: $test_exit_code)")
        else
            scan_summary+=("Security tests: PASSED")
        fi
    fi
    
    # Compliance validation
    if [[ "$COMPLIANCE_CHECK" == "true" ]]; then
        log_info "Executing compliance validation phase..."
        if ! run_compliance_validation; then
            local compliance_exit_code=$?
            if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
                overall_exit_code=$compliance_exit_code
            fi
            scan_summary+=("Compliance check: FAILED (exit code: $compliance_exit_code)")
        else
            scan_summary+=("Compliance check: PASSED")
        fi
    fi
    
    # Generate final security scan summary
    generate_final_scan_summary "${scan_summary[@]}"
    
    return $overall_exit_code
}

# Generate comprehensive final scan summary
generate_final_scan_summary() {
    local scan_results=("$@")
    local summary_report="${REPORT_DIR}/security-scan-summary-${TIMESTAMP}.txt"
    
    cat > "$summary_report" << EOF
Flask Application Security Scan Summary
========================================
Scan Completed: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Scanner Version: ${SCRIPT_VERSION}
Project: Flask Application Security Migration
Report Directory: ${REPORT_DIR}

SECURITY SCAN RESULTS
=====================
EOF
    
    for result in "${scan_results[@]}"; do
        echo "• $result" >> "$summary_report"
    done
    
    cat >> "$summary_report" << EOF

REPORT FILES GENERATED
======================
• Security scan summary: ${summary_report}
• Container scan results: ${REPORT_DIR}/trivy-container-scan-${TIMESTAMP}.json
• Dependency scan results: ${REPORT_DIR}/safety-scan-${TIMESTAMP}.json
• Static analysis results: ${REPORT_DIR}/bandit-scan-${TIMESTAMP}.json
• Security test results: ${REPORT_DIR}/security-tests-${TIMESTAMP}.xml
• Compliance validation: ${REPORT_DIR}/compliance-validation-${TIMESTAMP}.txt
• Security logs: ${REPORT_DIR}/security.log

NEXT STEPS
==========
$(if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
cat << 'EOF_SUCCESS'
✅ All security scans completed successfully
• Deployment can proceed per security policy
• Continue with blue-green deployment process
• Monitor security metrics in production
• Schedule next security assessment
EOF_SUCCESS
else
cat << 'EOF_FAILURE'
❌ Security scan failures detected
• Review detailed scan reports above
• Address critical vulnerabilities before deployment
• Re-run security scans after remediation
• Consult security team for risk assessment
EOF_FAILURE
fi)

TECHNICAL SPECIFICATION REFERENCES
===================================
• Section 8.5.1: Build Pipeline Security Requirements
• Section 8.5.2: Deployment Pipeline Security Controls
• Section 6.4: Security Architecture Implementation
• Section 3.6: Monitoring & Observability Integration

For support and escalation:
• Security Team: Review critical vulnerabilities
• DevOps Team: CI/CD pipeline integration
• Development Team: Code remediation guidance
EOF
    
    # Display summary to console
    log_info "Security scan completed. Summary report: $summary_report"
    
    if [[ $overall_exit_code -eq $EXIT_SUCCESS ]]; then
        echo -e "${GREEN}"
        echo "=============================================="
        echo "  ✅ SECURITY SCAN COMPLETED SUCCESSFULLY"
        echo "=============================================="
        echo -e "${NC}"
    else
        echo -e "${RED}"
        echo "=============================================="
        echo "  ❌ SECURITY SCAN FAILED - REVIEW REQUIRED"
        echo "=============================================="
        echo -e "${NC}"
    fi
    
    echo "📋 Report Summary: $summary_report"
    echo "📁 All Reports: $REPORT_DIR"
    
    if [[ -n "$METRICS_ENDPOINT" ]]; then
        echo "📊 Metrics: $METRICS_ENDPOINT"
    fi
}

# Script cleanup function
cleanup() {
    log_debug "Performing security scan cleanup..."
    
    # Clean up temporary Docker images
    if [[ "$CONTAINER_SCAN" == "true" ]]; then
        docker rmi flask-security-scan:latest &>/dev/null || true
    fi
    
    # Clean up temporary files older than 7 days
    find "$REPORT_DIR" -name "*.tmp" -mtime +7 -delete 2>/dev/null || true
    
    log_debug "Security scan cleanup completed"
}

# Signal handler for graceful shutdown
signal_handler() {
    log_warn "Security scan interrupted by signal. Performing cleanup..."
    cleanup
    exit $EXIT_CONFIGURATION_ERROR
}

# =============================================================================
# Script Entry Point
# =============================================================================

main() {
    # Set up signal handlers
    trap signal_handler SIGINT SIGTERM
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Display script header
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  Flask Application Security Scanner v${SCRIPT_VERSION}"
    echo "=============================================="
    echo -e "${NC}"
    log_info "Starting security scanning process..."
    
    # Validate environment and install tools
    validate_environment
    install_security_tools
    
    # Run comprehensive security scan
    local exit_code=$EXIT_SUCCESS
    if ! run_comprehensive_security_scan; then
        exit_code=$?
    fi
    
    # Perform cleanup
    cleanup
    
    # Final status message
    case $exit_code in
        $EXIT_SUCCESS)
            log_info "Security scan completed successfully - No critical issues found"
            ;;
        $EXIT_CRITICAL_VULNERABILITIES)
            log_error "Security scan failed - Critical vulnerabilities detected"
            ;;
        $EXIT_CONFIGURATION_ERROR)
            log_error "Security scan failed - Configuration or tool errors"
            ;;
        $EXIT_COMPLIANCE_VIOLATION)
            log_error "Security scan failed - Compliance violations detected"
            ;;
        *)
            log_error "Security scan failed - Unknown error (exit code: $exit_code)"
            ;;
    esac
    
    exit $exit_code
}

# Execute main function with all command line arguments
main "$@"