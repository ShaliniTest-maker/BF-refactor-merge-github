#!/bin/bash

# =============================================================================
# Security Scanning and Compliance Validation Script
# =============================================================================
# This script implements comprehensive security scanning and compliance 
# validation for Flask application security compliance including container 
# vulnerability scanning, dependency security assessment, and comprehensive 
# security policy enforcement.
#
# Features:
# - Container Security Framework with automated security scanning
# - Security Scanning using bandit static analysis, safety vulnerability scanning
# - Dependency Security Validation with safety 3.0+ and pip-audit 2.7+
# - Container Vulnerability Scanning using Trivy 0.48+ with automated policy enforcement
# - Comprehensive compliance validation with enterprise requirements
# =============================================================================

set -euo pipefail

# Script metadata and configuration
readonly SCRIPT_NAME="security.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Security tool versions and configuration
readonly TRIVY_VERSION="0.48.3"
readonly SAFETY_VERSION="3.0.1"
readonly BANDIT_VERSION="1.7.5"
readonly PIP_AUDIT_VERSION="2.7.3"
readonly FLAKE8_VERSION="6.1.0"
readonly MYPY_VERSION="1.8.0"

# Default configuration values
DEFAULT_PROJECT_ROOT="$(pwd)"
DEFAULT_OUTPUT_DIR="./security-reports"
DEFAULT_CONFIG_DIR="./config"
DEFAULT_SEVERITY_THRESHOLD="HIGH"
DEFAULT_FAIL_ON_CRITICAL="true"
DEFAULT_GENERATE_REPORTS="true"
DEFAULT_UPLOAD_RESULTS="false"
DEFAULT_CONTAINER_IMAGE=""
DEFAULT_REQUIREMENTS_FILE="requirements.txt"

# Configuration variables with defaults
PROJECT_ROOT="${PROJECT_ROOT:-$DEFAULT_PROJECT_ROOT}"
OUTPUT_DIR="${OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}"
CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-$DEFAULT_SEVERITY_THRESHOLD}"
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-$DEFAULT_FAIL_ON_CRITICAL}"
GENERATE_REPORTS="${GENERATE_REPORTS:-$DEFAULT_GENERATE_REPORTS}"
UPLOAD_RESULTS="${UPLOAD_RESULTS:-$DEFAULT_UPLOAD_RESULTS}"
CONTAINER_IMAGE="${CONTAINER_IMAGE:-$DEFAULT_CONTAINER_IMAGE}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$DEFAULT_REQUIREMENTS_FILE}"

# CI/CD environment detection
CI_ENVIRONMENT="${CI:-false}"
GITHUB_ACTIONS="${GITHUB_ACTIONS:-false}"

# Security scanning results tracking
declare -g CRITICAL_VULNERABILITIES=0
declare -g HIGH_VULNERABILITIES=0
declare -g MEDIUM_VULNERABILITIES=0
declare -g LOW_VULNERABILITIES=0
declare -g SECURITY_SCAN_FAILED=false
declare -g TOTAL_SCANS=0
declare -g FAILED_SCANS=0

# =============================================================================
# Utility Functions
# =============================================================================

# Print formatted log messages
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} ${TIMESTAMP} - $message" >&1
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} ${TIMESTAMP} - $message" >&2
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${TIMESTAMP} - $message" >&2
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} ${TIMESTAMP} - $message" >&1
            ;;
        "DEBUG")
            if [[ "${DEBUG:-false}" == "true" ]]; then
                echo -e "${PURPLE}[DEBUG]${NC} ${TIMESTAMP} - $message" >&1
            fi
            ;;
        *)
            echo -e "${CYAN}[${level}]${NC} ${TIMESTAMP} - $message" >&1
            ;;
    esac
}

# Display script usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Security Scanning and Compliance Validation Script for Flask Applications

This script performs comprehensive security scanning including:
- Container vulnerability scanning with Trivy 0.48+
- Python dependency vulnerability scanning with safety 3.0+ and pip-audit 2.7+
- Static code analysis with bandit 1.7+ for Python security patterns
- Code quality validation with flake8 6.1+ and mypy 1.8+
- Enterprise compliance validation and reporting

OPTIONS:
  -h, --help                 Show this help message and exit
  -v, --version             Show script version
  -d, --debug               Enable debug output
  
  Security Scanning Options:
  --project-root PATH       Project root directory (default: current directory)
  --output-dir PATH         Output directory for reports (default: ./security-reports)
  --config-dir PATH         Configuration directory (default: ./config)
  --requirements FILE       Requirements file to scan (default: requirements.txt)
  --container-image IMAGE   Container image to scan for vulnerabilities
  
  Scanning Control Options:
  --severity-threshold LEVEL    Minimum severity threshold [LOW|MEDIUM|HIGH|CRITICAL] (default: HIGH)
  --fail-on-critical BOOL      Fail on critical vulnerabilities [true|false] (default: true)
  --generate-reports BOOL      Generate detailed reports [true|false] (default: true)
  --upload-results BOOL        Upload results to security platform [true|false] (default: false)
  
  Scanning Modes:
  --scan-dependencies       Run dependency vulnerability scanning only
  --scan-container         Run container vulnerability scanning only
  --scan-code              Run static code analysis only
  --scan-all               Run all security scans (default)

EXAMPLES:
  # Run complete security scanning suite
  $SCRIPT_NAME --scan-all

  # Scan specific container image with high severity threshold
  $SCRIPT_NAME --container-image flask-app:latest --severity-threshold HIGH

  # Run dependency scanning only with custom requirements file
  $SCRIPT_NAME --scan-dependencies --requirements requirements-prod.txt

  # Generate reports in custom directory with debug output
  $SCRIPT_NAME --output-dir ./reports --debug

  # CI/CD integration with critical vulnerability blocking
  $SCRIPT_NAME --fail-on-critical true --upload-results true

ENVIRONMENT VARIABLES:
  PROJECT_ROOT              Project root directory path
  OUTPUT_DIR                Security reports output directory
  CONFIG_DIR                Security configuration directory
  SEVERITY_THRESHOLD        Minimum vulnerability severity threshold
  FAIL_ON_CRITICAL          Fail build on critical vulnerabilities
  GENERATE_REPORTS          Generate detailed security reports
  UPLOAD_RESULTS            Upload results to security platform
  CONTAINER_IMAGE           Container image name for scanning
  REQUIREMENTS_FILE         Python requirements file path
  DEBUG                     Enable debug logging

EXIT CODES:
  0    Success - No critical security issues found
  1    Critical vulnerabilities found (when --fail-on-critical=true)
  2    Security scanning tool failure
  3    Configuration or setup error
  4    Invalid command line arguments

For more information, see the technical specification Section 6.4 Security Architecture.
EOF
}

# Display script version information
show_version() {
    cat << EOF
$SCRIPT_NAME version $SCRIPT_VERSION

Security Tools Versions:
- Trivy: $TRIVY_VERSION
- Safety: $SAFETY_VERSION  
- Bandit: $BANDIT_VERSION
- pip-audit: $PIP_AUDIT_VERSION
- flake8: $FLAKE8_VERSION
- mypy: $MYPY_VERSION

Copyright (c) 2024 Flask Security Framework
License: Enterprise License
EOF
}

# Validate and create output directories
setup_directories() {
    log "INFO" "Setting up security scanning directories..."
    
    # Validate project root exists
    if [[ ! -d "$PROJECT_ROOT" ]]; then
        log "ERROR" "Project root directory does not exist: $PROJECT_ROOT"
        exit 3
    fi
    
    # Create output directory structure
    local dirs=(
        "$OUTPUT_DIR"
        "$OUTPUT_DIR/trivy"
        "$OUTPUT_DIR/safety"
        "$OUTPUT_DIR/bandit"
        "$OUTPUT_DIR/pip-audit"
        "$OUTPUT_DIR/flake8"
        "$OUTPUT_DIR/mypy"
        "$OUTPUT_DIR/compliance"
        "$OUTPUT_DIR/summary"
    )
    
    for dir in "${dirs[@]}"; do
        if ! mkdir -p "$dir"; then
            log "ERROR" "Failed to create directory: $dir"
            exit 3
        fi
        log "DEBUG" "Created directory: $dir"
    done
    
    log "SUCCESS" "Security scanning directories setup completed"
}

# Check if required security tools are installed
check_tool_dependencies() {
    log "INFO" "Checking security tool dependencies..."
    
    local tools=(
        "python3:Python 3.8+ runtime"
        "pip:Python package manager"
        "docker:Container runtime for Trivy scanning"
        "curl:HTTP client for tool downloads"
        "jq:JSON processor for result parsing"
    )
    
    local missing_tools=()
    
    for tool_info in "${tools[@]}"; do
        local tool_name="${tool_info%%:*}"
        local tool_desc="${tool_info##*:}"
        
        if ! command -v "$tool_name" &> /dev/null; then
            missing_tools+=("$tool_name ($tool_desc)")
            log "ERROR" "Missing required tool: $tool_name - $tool_desc"
        else
            local version=""
            case "$tool_name" in
                "python3")
                    version=$(python3 --version 2>&1 | cut -d' ' -f2)
                    ;;
                "docker")
                    version=$(docker --version 2>&1 | cut -d' ' -f3 | tr -d ',')
                    ;;
                *)
                    version="installed"
                    ;;
            esac
            log "DEBUG" "Found $tool_name: $version"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "ERROR" "Missing required dependencies:"
        printf '%s\n' "${missing_tools[@]}" | sed 's/^/  - /'
        log "ERROR" "Please install missing tools and retry"
        exit 3
    fi
    
    log "SUCCESS" "All required tool dependencies are available"
}

# Install or upgrade security scanning tools
install_security_tools() {
    log "INFO" "Installing/upgrading security scanning tools..."
    
    # Create virtual environment for security tools if needed
    local venv_dir="$OUTPUT_DIR/.security-venv"
    if [[ ! -d "$venv_dir" ]]; then
        log "INFO" "Creating virtual environment for security tools..."
        python3 -m venv "$venv_dir"
    fi
    
    # Activate virtual environment
    # shellcheck source=/dev/null
    source "$venv_dir/bin/activate"
    
    # Upgrade pip to latest version
    log "INFO" "Upgrading pip to latest version..."
    pip install --upgrade pip setuptools wheel
    
    # Install Python security tools with specific versions
    log "INFO" "Installing Python security scanning tools..."
    local python_tools=(
        "safety==$SAFETY_VERSION"
        "bandit==$BANDIT_VERSION"
        "pip-audit==$PIP_AUDIT_VERSION"
        "flake8==$FLAKE8_VERSION"
        "mypy==$MYPY_VERSION"
        "pytest>=7.4.0"
        "pytest-cov>=4.1.0"
    )
    
    for tool in "${python_tools[@]}"; do
        log "INFO" "Installing $tool..."
        if ! pip install "$tool"; then
            log "ERROR" "Failed to install $tool"
            exit 3
        fi
    done
    
    # Install Trivy container scanner
    install_trivy
    
    log "SUCCESS" "Security scanning tools installation completed"
}

# Install Trivy container vulnerability scanner
install_trivy() {
    log "INFO" "Installing Trivy $TRIVY_VERSION container scanner..."
    
    local trivy_binary="/usr/local/bin/trivy"
    local trivy_version_output=""
    
    # Check if Trivy is already installed with correct version
    if command -v trivy &> /dev/null; then
        trivy_version_output=$(trivy --version 2>&1 | head -n1)
        if [[ "$trivy_version_output" == *"$TRIVY_VERSION"* ]]; then
            log "INFO" "Trivy $TRIVY_VERSION already installed"
            return 0
        fi
    fi
    
    # Determine system architecture
    local arch
    arch=$(uname -m)
    case "$arch" in
        "x86_64") arch="64bit" ;;
        "arm64"|"aarch64") arch="ARM64" ;;
        *) 
            log "ERROR" "Unsupported architecture: $arch"
            exit 3
            ;;
    esac
    
    # Download and install Trivy
    local trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log "INFO" "Downloading Trivy from: $trivy_url"
    
    if ! curl -sSL "$trivy_url" | tar -xz -C "$temp_dir"; then
        log "ERROR" "Failed to download and extract Trivy"
        rm -rf "$temp_dir"
        exit 3
    fi
    
    # Install Trivy binary
    if ! sudo mv "$temp_dir/trivy" "$trivy_binary"; then
        log "ERROR" "Failed to install Trivy binary (sudo required)"
        rm -rf "$temp_dir"
        exit 3
    fi
    
    # Set executable permissions
    sudo chmod +x "$trivy_binary"
    
    # Cleanup
    rm -rf "$temp_dir"
    
    # Verify installation
    if trivy_version_output=$(trivy --version 2>&1); then
        log "SUCCESS" "Trivy installed successfully: $trivy_version_output"
    else
        log "ERROR" "Trivy installation verification failed"
        exit 3
    fi
}

# =============================================================================
# Security Scanning Functions
# =============================================================================

# Run comprehensive dependency vulnerability scanning
scan_dependencies() {
    log "INFO" "Starting dependency vulnerability scanning..."
    ((TOTAL_SCANS++))
    
    local scan_success=true
    
    # Validate requirements file exists
    local req_file="$PROJECT_ROOT/$REQUIREMENTS_FILE"
    if [[ ! -f "$req_file" ]]; then
        log "ERROR" "Requirements file not found: $req_file"
        ((FAILED_SCANS++))
        return 1
    fi
    
    log "INFO" "Scanning dependencies from: $req_file"
    
    # Run Safety vulnerability scanning
    log "INFO" "Running Safety dependency vulnerability scan..."
    if ! run_safety_scan "$req_file"; then
        scan_success=false
    fi
    
    # Run pip-audit vulnerability scanning  
    log "INFO" "Running pip-audit dependency security assessment..."
    if ! run_pip_audit_scan "$req_file"; then
        scan_success=false
    fi
    
    # Generate dependency scan summary
    generate_dependency_summary
    
    if [[ "$scan_success" == "true" ]]; then
        log "SUCCESS" "Dependency vulnerability scanning completed successfully"
        return 0
    else
        log "ERROR" "Dependency vulnerability scanning failed"
        ((FAILED_SCANS++))
        SECURITY_SCAN_FAILED=true
        return 1
    fi
}

# Run Safety vulnerability scanning with comprehensive reporting
run_safety_scan() {
    local requirements_file="$1"
    local output_file="$OUTPUT_DIR/safety/safety-report.json"
    local summary_file="$OUTPUT_DIR/safety/safety-summary.txt"
    
    log "INFO" "Executing Safety $SAFETY_VERSION vulnerability scan..."
    
    # Run Safety scan with JSON output
    local safety_cmd=(
        safety check
        --requirements "$requirements_file"
        --json
        --output "$output_file"
    )
    
    # Add CI-specific options
    if [[ "$CI_ENVIRONMENT" == "true" ]]; then
        safety_cmd+=(--continue-on-error)
    fi
    
    local exit_code=0
    if ! "${safety_cmd[@]}" 2>&1 | tee "$OUTPUT_DIR/safety/safety-output.log"; then
        exit_code=$?
        log "WARN" "Safety scan completed with warnings (exit code: $exit_code)"
    fi
    
    # Parse Safety results if JSON output exists
    if [[ -f "$output_file" ]]; then
        parse_safety_results "$output_file" "$summary_file"
    else
        log "WARN" "Safety JSON output not generated, creating basic summary"
        echo "Safety scan completed at $TIMESTAMP" > "$summary_file"
        echo "No vulnerabilities detected or scan failed" >> "$summary_file"
    fi
    
    # Check for critical vulnerabilities
    local critical_count=0
    if [[ -f "$output_file" ]] && command -v jq &> /dev/null; then
        critical_count=$(jq -r '. | length' "$output_file" 2>/dev/null || echo "0")
    fi
    
    if [[ "$critical_count" -gt 0 ]]; then
        log "WARN" "Safety found $critical_count vulnerable dependencies"
        ((HIGH_VULNERABILITIES += critical_count))
        
        if [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
            log "ERROR" "Critical dependencies vulnerabilities found - failing build"
            return 1
        fi
    else
        log "SUCCESS" "Safety scan: No vulnerable dependencies detected"
    fi
    
    return 0
}

# Parse and analyze Safety scan results
parse_safety_results() {
    local json_file="$1"
    local summary_file="$2"
    
    log "DEBUG" "Parsing Safety results from: $json_file"
    
    if ! command -v jq &> /dev/null; then
        log "WARN" "jq not available - skipping detailed Safety result parsing"
        return 0
    fi
    
    # Generate comprehensive summary
    cat > "$summary_file" << EOF
Safety Dependency Vulnerability Scan Report
Generated: $TIMESTAMP
Requirements File: $REQUIREMENTS_FILE

EOF
    
    # Parse vulnerabilities if any exist
    local vuln_count
    vuln_count=$(jq -r '. | length' "$json_file" 2>/dev/null || echo "0")
    
    if [[ "$vuln_count" -gt 0 ]]; then
        echo "VULNERABILITIES FOUND: $vuln_count" >> "$summary_file"
        echo "----------------------------------------" >> "$summary_file"
        
        # Extract vulnerability details
        jq -r '.[] | "Package: \(.package_name) \(.installed_version)\nVulnerability: \(.vulnerability_id)\nSeverity: \(.advisory)\nAffected Versions: \(.affected_versions)\nSafe Versions: \(.safe_versions)\n"' "$json_file" >> "$summary_file" 2>/dev/null || true
    else
        echo "STATUS: No vulnerabilities detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    log "DEBUG" "Safety results summary generated: $summary_file"
}

# Run pip-audit comprehensive dependency scanning
run_pip_audit_scan() {
    local requirements_file="$1"
    local output_file="$OUTPUT_DIR/pip-audit/pip-audit-report.json"
    local summary_file="$OUTPUT_DIR/pip-audit/pip-audit-summary.txt"
    
    log "INFO" "Executing pip-audit $PIP_AUDIT_VERSION security assessment..."
    
    # Run pip-audit with comprehensive options
    local pip_audit_cmd=(
        pip-audit
        --requirement "$requirements_file"
        --format json
        --output "$output_file"
        --progress-spinner off
    )
    
    # Add vulnerability database options
    pip_audit_cmd+=(--vulnerability-service pypi)
    
    local exit_code=0
    if ! "${pip_audit_cmd[@]}" 2>&1 | tee "$OUTPUT_DIR/pip-audit/pip-audit-output.log"; then
        exit_code=$?
        log "WARN" "pip-audit scan completed with issues (exit code: $exit_code)"
    fi
    
    # Parse pip-audit results
    if [[ -f "$output_file" ]]; then
        parse_pip_audit_results "$output_file" "$summary_file"
    else
        log "WARN" "pip-audit JSON output not generated"
        echo "pip-audit scan completed at $TIMESTAMP" > "$summary_file"
        echo "No output file generated" >> "$summary_file"
    fi
    
    # Check for vulnerabilities
    local vuln_count=0
    if [[ -f "$output_file" ]] && command -v jq &> /dev/null; then
        vuln_count=$(jq -r '.vulnerabilities | length' "$output_file" 2>/dev/null || echo "0")
    fi
    
    if [[ "$vuln_count" -gt 0 ]]; then
        log "WARN" "pip-audit found $vuln_count package vulnerabilities"
        ((MEDIUM_VULNERABILITIES += vuln_count))
    else
        log "SUCCESS" "pip-audit scan: No package vulnerabilities detected"
    fi
    
    return 0
}

# Parse and analyze pip-audit scan results
parse_pip_audit_results() {
    local json_file="$1"
    local summary_file="$2"
    
    log "DEBUG" "Parsing pip-audit results from: $json_file"
    
    if ! command -v jq &> /dev/null; then
        log "WARN" "jq not available - skipping detailed pip-audit result parsing"
        return 0
    fi
    
    # Generate comprehensive summary
    cat > "$summary_file" << EOF
pip-audit Dependency Security Assessment Report
Generated: $TIMESTAMP
Requirements File: $REQUIREMENTS_FILE

EOF
    
    # Parse vulnerability information
    local vuln_count
    vuln_count=$(jq -r '.vulnerabilities | length' "$json_file" 2>/dev/null || echo "0")
    
    if [[ "$vuln_count" -gt 0 ]]; then
        echo "VULNERABILITIES FOUND: $vuln_count" >> "$summary_file"
        echo "----------------------------------------" >> "$summary_file"
        
        # Extract detailed vulnerability information
        jq -r '.vulnerabilities[] | "Package: \(.package.name) \(.package.version)\nID: \(.id)\nDescription: \(.description // "No description")\nAliases: \(.aliases[]? // "None")\nFixed Versions: \(.fix_versions[]? // "None available")\n"' "$json_file" >> "$summary_file" 2>/dev/null || true
    else
        echo "STATUS: No vulnerabilities detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    log "DEBUG" "pip-audit results summary generated: $summary_file"
}

# Generate comprehensive dependency scanning summary
generate_dependency_summary() {
    local summary_file="$OUTPUT_DIR/summary/dependency-scan-summary.json"
    
    log "INFO" "Generating dependency scanning summary report..."
    
    # Create structured summary report
    cat > "$summary_file" << EOF
{
  "scan_info": {
    "timestamp": "$TIMESTAMP",
    "requirements_file": "$REQUIREMENTS_FILE",
    "scan_tools": ["safety", "pip-audit"]
  },
  "vulnerability_counts": {
    "critical": $CRITICAL_VULNERABILITIES,
    "high": $HIGH_VULNERABILITIES,
    "medium": $MEDIUM_VULNERABILITIES,
    "low": $LOW_VULNERABILITIES
  },
  "scan_status": {
    "total_scans": $TOTAL_SCANS,
    "failed_scans": $FAILED_SCANS,
    "overall_status": "$([ "$SECURITY_SCAN_FAILED" == "true" ] && echo "FAILED" || echo "PASSED")"
  },
  "tool_reports": {
    "safety": "$OUTPUT_DIR/safety/safety-report.json",
    "pip_audit": "$OUTPUT_DIR/pip-audit/pip-audit-report.json"
  }
}
EOF
    
    log "SUCCESS" "Dependency scanning summary generated: $summary_file"
}

# Run container vulnerability scanning with Trivy
scan_container() {
    log "INFO" "Starting container vulnerability scanning..."
    ((TOTAL_SCANS++))
    
    # Validate container image is specified
    if [[ -z "$CONTAINER_IMAGE" ]]; then
        log "ERROR" "Container image not specified for scanning"
        log "INFO" "Use --container-image flag or set CONTAINER_IMAGE environment variable"
        ((FAILED_SCANS++))
        return 1
    fi
    
    log "INFO" "Scanning container image: $CONTAINER_IMAGE"
    
    # Run Trivy container vulnerability scan
    if run_trivy_scan "$CONTAINER_IMAGE"; then
        log "SUCCESS" "Container vulnerability scanning completed successfully"
        return 0
    else
        log "ERROR" "Container vulnerability scanning failed"
        ((FAILED_SCANS++))
        SECURITY_SCAN_FAILED=true
        return 1
    fi
}

# Execute Trivy container vulnerability scanning
run_trivy_scan() {
    local image="$1"
    local output_file="$OUTPUT_DIR/trivy/trivy-report.json"
    local summary_file="$OUTPUT_DIR/trivy/trivy-summary.txt"
    
    log "INFO" "Executing Trivy $TRIVY_VERSION container scan..."
    
    # Update Trivy vulnerability database
    log "INFO" "Updating Trivy vulnerability database..."
    if ! trivy image --download-db-only 2>&1 | tee "$OUTPUT_DIR/trivy/trivy-db-update.log"; then
        log "WARN" "Trivy database update failed - continuing with existing database"
    fi
    
    # Configure Trivy scan parameters
    local trivy_cmd=(
        trivy image
        --format json
        --output "$output_file"
        --severity "$SEVERITY_THRESHOLD,CRITICAL"
        --no-progress
        --timeout 15m
    )
    
    # Add CI-specific options
    if [[ "$CI_ENVIRONMENT" == "true" ]]; then
        trivy_cmd+=(--quiet)
    fi
    
    # Add the image to scan
    trivy_cmd+=("$image")
    
    # Execute Trivy scan
    local exit_code=0
    if ! "${trivy_cmd[@]}" 2>&1 | tee "$OUTPUT_DIR/trivy/trivy-output.log"; then
        exit_code=$?
        log "ERROR" "Trivy scan failed with exit code: $exit_code"
        return 1
    fi
    
    # Parse Trivy results
    if [[ -f "$output_file" ]]; then
        parse_trivy_results "$output_file" "$summary_file"
    else
        log "ERROR" "Trivy output file not generated"
        return 1
    fi
    
    # Check vulnerability threshold compliance
    check_trivy_compliance "$output_file"
}

# Parse and analyze Trivy scan results
parse_trivy_results() {
    local json_file="$1"
    local summary_file="$2"
    
    log "DEBUG" "Parsing Trivy results from: $json_file"
    
    if ! command -v jq &> /dev/null; then
        log "WARN" "jq not available - skipping detailed Trivy result parsing"
        return 0
    fi
    
    # Extract vulnerability counts by severity
    local critical_count high_count medium_count low_count
    critical_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file" 2>/dev/null || echo "0")
    high_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$json_file" 2>/dev/null || echo "0")
    medium_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$json_file" 2>/dev/null || echo "0")
    low_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$json_file" 2>/dev/null || echo "0")
    
    # Update global counters
    ((CRITICAL_VULNERABILITIES += critical_count))
    ((HIGH_VULNERABILITIES += high_count))
    ((MEDIUM_VULNERABILITIES += medium_count))
    ((LOW_VULNERABILITIES += low_count))
    
    # Generate comprehensive summary
    cat > "$summary_file" << EOF
Trivy Container Vulnerability Scan Report
Generated: $TIMESTAMP
Image: $CONTAINER_IMAGE
Trivy Version: $TRIVY_VERSION

VULNERABILITY SUMMARY:
- Critical: $critical_count
- High: $high_count  
- Medium: $medium_count
- Low: $low_count
- Total: $((critical_count + high_count + medium_count + low_count))

EOF
    
    # Add detailed vulnerability information if vulnerabilities exist
    local total_vulns=$((critical_count + high_count + medium_count + low_count))
    if [[ "$total_vulns" -gt 0 ]]; then
        echo "DETAILED VULNERABILITIES:" >> "$summary_file"
        echo "=========================" >> "$summary_file"
        
        # Extract top critical and high vulnerabilities
        jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "Severity: \(.Severity)\nCVE: \(.VulnerabilityID)\nPackage: \(.PkgName) \(.InstalledVersion)\nDescription: \(.Description // "No description")\nFixed Version: \(.FixedVersion // "Not available")\n"' "$json_file" >> "$summary_file" 2>/dev/null || true
    else
        echo "STATUS: No vulnerabilities detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    log "INFO" "Container vulnerabilities found - Critical: $critical_count, High: $high_count, Medium: $medium_count, Low: $low_count"
    log "DEBUG" "Trivy results summary generated: $summary_file"
}

# Check Trivy scan compliance against security policies
check_trivy_compliance() {
    local json_file="$1"
    
    if ! command -v jq &> /dev/null; then
        log "WARN" "jq not available - skipping compliance check"
        return 0
    fi
    
    # Extract critical vulnerability count
    local critical_count
    critical_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file" 2>/dev/null || echo "0")
    
    # Security policy enforcement
    if [[ "$critical_count" -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log "ERROR" "Security policy violation: $critical_count critical vulnerabilities found"
        log "ERROR" "Critical vulnerabilities must be remediated before deployment"
        
        # Display critical CVEs for immediate attention
        if critical_cves=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' "$json_file" 2>/dev/null); then
            log "ERROR" "Critical CVEs requiring immediate attention:"
            echo "$critical_cves" | head -10 | sed 's/^/  - /'
        fi
        
        return 1
    fi
    
    return 0
}

# Run comprehensive static code security analysis
scan_code() {
    log "INFO" "Starting static code security analysis..."
    ((TOTAL_SCANS++))
    
    local scan_success=true
    
    # Run Bandit security analysis
    log "INFO" "Running Bandit static security analysis..."
    if ! run_bandit_scan; then
        scan_success=false
    fi
    
    # Run flake8 code quality analysis
    log "INFO" "Running flake8 code quality analysis..."
    if ! run_flake8_scan; then
        scan_success=false
    fi
    
    # Run mypy type safety analysis
    log "INFO" "Running mypy type safety analysis..."
    if ! run_mypy_scan; then
        scan_success=false
    fi
    
    # Generate code scanning summary
    generate_code_scan_summary
    
    if [[ "$scan_success" == "true" ]]; then
        log "SUCCESS" "Static code security analysis completed successfully"
        return 0
    else
        log "ERROR" "Static code security analysis failed"
        ((FAILED_SCANS++))
        SECURITY_SCAN_FAILED=true
        return 1
    fi
}

# Run Bandit static security analysis
run_bandit_scan() {
    local output_file="$OUTPUT_DIR/bandit/bandit-report.json"
    local summary_file="$OUTPUT_DIR/bandit/bandit-summary.txt"
    
    log "INFO" "Executing Bandit $BANDIT_VERSION static security analysis..."
    
    # Configure Bandit scan parameters
    local bandit_cmd=(
        bandit
        --recursive "$PROJECT_ROOT"
        --format json
        --output "$output_file"
        --confidence-level medium
        --severity-level medium
    )
    
    # Add exclusions for common non-security directories
    bandit_cmd+=(
        --exclude "$PROJECT_ROOT/tests,$PROJECT_ROOT/.git,$PROJECT_ROOT/venv,$PROJECT_ROOT/.venv,$PROJECT_ROOT/build,$PROJECT_ROOT/dist"
    )
    
    # Execute Bandit scan
    local exit_code=0
    if ! "${bandit_cmd[@]}" 2>&1 | tee "$OUTPUT_DIR/bandit/bandit-output.log"; then
        exit_code=$?
        log "WARN" "Bandit scan completed with findings (exit code: $exit_code)"
    fi
    
    # Parse Bandit results
    if [[ -f "$output_file" ]]; then
        parse_bandit_results "$output_file" "$summary_file"
    else
        log "WARN" "Bandit output file not generated"
        echo "Bandit scan completed at $TIMESTAMP" > "$summary_file"
        echo "No output file generated" >> "$summary_file"
    fi
    
    # Check for high/critical security issues
    local high_issues=0
    if [[ -f "$output_file" ]] && command -v jq &> /dev/null; then
        high_issues=$(jq -r '.results[] | select(.issue_severity == "HIGH" or .issue_severity == "CRITICAL") | length' "$output_file" 2>/dev/null | wc -l)
    fi
    
    if [[ "$high_issues" -gt 0 ]]; then
        log "WARN" "Bandit found $high_issues high/critical security issues"
        ((HIGH_VULNERABILITIES += high_issues))
        
        if [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
            log "ERROR" "Critical security issues found - failing build"
            return 1
        fi
    else
        log "SUCCESS" "Bandit scan: No critical security issues detected"
    fi
    
    return 0
}

# Parse and analyze Bandit scan results
parse_bandit_results() {
    local json_file="$1"
    local summary_file="$2"
    
    log "DEBUG" "Parsing Bandit results from: $json_file"
    
    if ! command -v jq &> /dev/null; then
        log "WARN" "jq not available - skipping detailed Bandit result parsing"
        return 0
    fi
    
    # Extract issue counts by severity
    local high_count medium_count low_count
    high_count=$(jq -r '[.results[] | select(.issue_severity == "HIGH")] | length' "$json_file" 2>/dev/null || echo "0")
    medium_count=$(jq -r '[.results[] | select(.issue_severity == "MEDIUM")] | length' "$json_file" 2>/dev/null || echo "0")
    low_count=$(jq -r '[.results[] | select(.issue_severity == "LOW")] | length' "$json_file" 2>/dev/null || echo "0")
    
    # Generate comprehensive summary
    cat > "$summary_file" << EOF
Bandit Static Security Analysis Report
Generated: $TIMESTAMP
Project: $PROJECT_ROOT
Bandit Version: $BANDIT_VERSION

SECURITY ISSUE SUMMARY:
- High: $high_count
- Medium: $medium_count
- Low: $low_count
- Total: $((high_count + medium_count + low_count))

EOF
    
    # Add detailed issue information if issues exist
    local total_issues=$((high_count + medium_count + low_count))
    if [[ "$total_issues" -gt 0 ]]; then
        echo "DETAILED SECURITY ISSUES:" >> "$summary_file"
        echo "=========================" >> "$summary_file"
        
        # Extract high severity issues
        jq -r '.results[] | select(.issue_severity == "HIGH") | "Severity: \(.issue_severity)\nTest: \(.test_name)\nFile: \(.filename):\(.line_number)\nIssue: \(.issue_text)\nConfidence: \(.issue_confidence)\n"' "$json_file" >> "$summary_file" 2>/dev/null || true
    else
        echo "STATUS: No security issues detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    log "DEBUG" "Bandit results summary generated: $summary_file"
}

# Run flake8 code quality analysis
run_flake8_scan() {
    local output_file="$OUTPUT_DIR/flake8/flake8-report.txt"
    local summary_file="$OUTPUT_DIR/flake8/flake8-summary.txt"
    
    log "INFO" "Executing flake8 $FLAKE8_VERSION code quality analysis..."
    
    # Configure flake8 scan parameters
    local flake8_cmd=(
        flake8
        "$PROJECT_ROOT"
        --output-file "$output_file"
        --statistics
        --count
    )
    
    # Add configuration file if exists
    local config_files=("$PROJECT_ROOT/.flake8" "$PROJECT_ROOT/setup.cfg" "$PROJECT_ROOT/tox.ini")
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            flake8_cmd+=(--config "$config")
            break
        fi
    done
    
    # Execute flake8 scan
    local exit_code=0
    if ! "${flake8_cmd[@]}" 2>&1 | tee "$OUTPUT_DIR/flake8/flake8-output.log"; then
        exit_code=$?
        log "WARN" "flake8 scan found code quality issues (exit code: $exit_code)"
    fi
    
    # Generate summary
    cat > "$summary_file" << EOF
flake8 Code Quality Analysis Report
Generated: $TIMESTAMP
Project: $PROJECT_ROOT
flake8 Version: $FLAKE8_VERSION

EOF
    
    # Add issue count if output file exists
    if [[ -f "$output_file" ]]; then
        local issue_count
        issue_count=$(wc -l < "$output_file")
        echo "TOTAL ISSUES FOUND: $issue_count" >> "$summary_file"
        
        if [[ "$issue_count" -gt 0 ]]; then
            echo "" >> "$summary_file"
            echo "TOP ISSUES:" >> "$summary_file"
            head -20 "$output_file" >> "$summary_file"
        fi
    else
        echo "STATUS: No issues detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    # flake8 issues are warnings, not failures
    log "SUCCESS" "flake8 code quality analysis completed"
    return 0
}

# Run mypy type safety analysis
run_mypy_scan() {
    local output_file="$OUTPUT_DIR/mypy/mypy-report.txt"
    local summary_file="$OUTPUT_DIR/mypy/mypy-summary.txt"
    
    log "INFO" "Executing mypy $MYPY_VERSION type safety analysis..."
    
    # Configure mypy scan parameters
    local mypy_cmd=(
        mypy
        "$PROJECT_ROOT"
        --txt-report "$OUTPUT_DIR/mypy"
        --no-error-summary
    )
    
    # Add configuration file if exists
    local config_files=("$PROJECT_ROOT/mypy.ini" "$PROJECT_ROOT/.mypy.ini" "$PROJECT_ROOT/setup.cfg")
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            mypy_cmd+=(--config-file "$config")
            break
        fi
    done
    
    # Execute mypy scan
    local exit_code=0
    if ! "${mypy_cmd[@]}" 2>&1 | tee "$output_file"; then
        exit_code=$?
        log "WARN" "mypy scan found type safety issues (exit code: $exit_code)"
    fi
    
    # Generate summary
    cat > "$summary_file" << EOF
mypy Type Safety Analysis Report
Generated: $TIMESTAMP
Project: $PROJECT_ROOT
mypy Version: $MYPY_VERSION

EOF
    
    # Add issue analysis
    if [[ -f "$output_file" ]]; then
        local error_count
        error_count=$(grep -c "error:" "$output_file" 2>/dev/null || echo "0")
        echo "TYPE ERRORS FOUND: $error_count" >> "$summary_file"
        
        if [[ "$error_count" -gt 0 ]]; then
            echo "" >> "$summary_file"
            echo "TOP TYPE ERRORS:" >> "$summary_file"
            grep "error:" "$output_file" | head -20 >> "$summary_file"
        fi
    else
        echo "STATUS: No type errors detected" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "Scan completed at: $TIMESTAMP" >> "$summary_file"
    
    # mypy issues are warnings, not failures
    log "SUCCESS" "mypy type safety analysis completed"
    return 0
}

# Generate comprehensive code scanning summary
generate_code_scan_summary() {
    local summary_file="$OUTPUT_DIR/summary/code-scan-summary.json"
    
    log "INFO" "Generating code scanning summary report..."
    
    # Create structured summary report
    cat > "$summary_file" << EOF
{
  "scan_info": {
    "timestamp": "$TIMESTAMP",
    "project_root": "$PROJECT_ROOT",
    "scan_tools": ["bandit", "flake8", "mypy"]
  },
  "security_issues": {
    "critical": $CRITICAL_VULNERABILITIES,
    "high": $HIGH_VULNERABILITIES,
    "medium": $MEDIUM_VULNERABILITIES,
    "low": $LOW_VULNERABILITIES
  },
  "scan_status": {
    "total_scans": $TOTAL_SCANS,
    "failed_scans": $FAILED_SCANS,
    "overall_status": "$([ "$SECURITY_SCAN_FAILED" == "true" ] && echo "FAILED" || echo "PASSED")"
  },
  "tool_reports": {
    "bandit": "$OUTPUT_DIR/bandit/bandit-report.json",
    "flake8": "$OUTPUT_DIR/flake8/flake8-report.txt",
    "mypy": "$OUTPUT_DIR/mypy/mypy-report.txt"
  }
}
EOF
    
    log "SUCCESS" "Code scanning summary generated: $summary_file"
}

# =============================================================================
# Report Generation and Upload Functions
# =============================================================================

# Generate comprehensive security compliance report
generate_compliance_report() {
    log "INFO" "Generating comprehensive security compliance report..."
    
    local compliance_file="$OUTPUT_DIR/compliance/security-compliance-report.json"
    local executive_summary="$OUTPUT_DIR/compliance/executive-summary.txt"
    
    # Create comprehensive compliance report
    cat > "$compliance_file" << EOF
{
  "report_metadata": {
    "generated_at": "$TIMESTAMP",
    "script_version": "$SCRIPT_VERSION",
    "project_root": "$PROJECT_ROOT",
    "report_type": "comprehensive_security_assessment"
  },
  "scan_configuration": {
    "severity_threshold": "$SEVERITY_THRESHOLD",
    "fail_on_critical": "$FAIL_ON_CRITICAL",
    "container_image": "$CONTAINER_IMAGE",
    "requirements_file": "$REQUIREMENTS_FILE"
  },
  "vulnerability_summary": {
    "total_vulnerabilities": $((CRITICAL_VULNERABILITIES + HIGH_VULNERABILITIES + MEDIUM_VULNERABILITIES + LOW_VULNERABILITIES)),
    "critical_vulnerabilities": $CRITICAL_VULNERABILITIES,
    "high_vulnerabilities": $HIGH_VULNERABILITIES,
    "medium_vulnerabilities": $MEDIUM_VULNERABILITIES,
    "low_vulnerabilities": $LOW_VULNERABILITIES
  },
  "scan_execution": {
    "total_scans_executed": $TOTAL_SCANS,
    "failed_scans": $FAILED_SCANS,
    "overall_status": "$([ "$SECURITY_SCAN_FAILED" == "true" ] && echo "FAILED" || echo "PASSED")",
    "compliance_status": "$([ "$CRITICAL_VULNERABILITIES" -eq 0 ] && echo "COMPLIANT" || echo "NON_COMPLIANT")"
  },
  "tool_versions": {
    "trivy": "$TRIVY_VERSION",
    "safety": "$SAFETY_VERSION",
    "bandit": "$BANDIT_VERSION",
    "pip_audit": "$PIP_AUDIT_VERSION",
    "flake8": "$FLAKE8_VERSION",
    "mypy": "$MYPY_VERSION"
  },
  "report_files": {
    "dependency_scan": "$OUTPUT_DIR/summary/dependency-scan-summary.json",
    "container_scan": "$OUTPUT_DIR/trivy/trivy-report.json",
    "code_scan": "$OUTPUT_DIR/summary/code-scan-summary.json"
  }
}
EOF
    
    # Generate executive summary
    cat > "$executive_summary" << EOF
SECURITY COMPLIANCE EXECUTIVE SUMMARY
=====================================
Generated: $TIMESTAMP
Project: $PROJECT_ROOT

OVERALL STATUS: $([ "$SECURITY_SCAN_FAILED" == "true" ] && echo "FAILED ❌" || echo "PASSED ✅")
COMPLIANCE STATUS: $([ "$CRITICAL_VULNERABILITIES" -eq 0 ] && echo "COMPLIANT ✅" || echo "NON-COMPLIANT ❌")

VULNERABILITY SUMMARY:
- Critical: $CRITICAL_VULNERABILITIES $([ "$CRITICAL_VULNERABILITIES" -eq 0 ] && echo "✅" || echo "❌")
- High: $HIGH_VULNERABILITIES $([ "$HIGH_VULNERABILITIES" -eq 0 ] && echo "✅" || echo "⚠️")
- Medium: $MEDIUM_VULNERABILITIES
- Low: $LOW_VULNERABILITIES

SCAN EXECUTION:
- Total Scans: $TOTAL_SCANS
- Failed Scans: $FAILED_SCANS
- Success Rate: $(( (TOTAL_SCANS - FAILED_SCANS) * 100 / TOTAL_SCANS ))%

RECOMMENDATIONS:
$([ "$CRITICAL_VULNERABILITIES" -gt 0 ] && echo "❌ IMMEDIATE ACTION REQUIRED: Critical vulnerabilities must be remediated before deployment")
$([ "$HIGH_VULNERABILITIES" -gt 0 ] && echo "⚠️  HIGH PRIORITY: Schedule remediation for high severity vulnerabilities")
$([ "$MEDIUM_VULNERABILITIES" -gt 0 ] && echo "📋 MEDIUM PRIORITY: Plan remediation for medium severity vulnerabilities")
$([ "$CRITICAL_VULNERABILITIES" -eq 0 ] && [ "$HIGH_VULNERABILITIES" -eq 0 ] && echo "✅ EXCELLENT: No critical or high severity vulnerabilities found")

For detailed findings, review individual scan reports in: $OUTPUT_DIR
EOF
    
    log "SUCCESS" "Security compliance report generated: $compliance_file"
    log "INFO" "Executive summary available: $executive_summary"
}

# Upload security scan results to centralized security platform
upload_security_results() {
    if [[ "$UPLOAD_RESULTS" != "true" ]]; then
        log "INFO" "Result upload disabled - skipping upload to security platform"
        return 0
    fi
    
    log "INFO" "Uploading security scan results to centralized security platform..."
    
    # Implementation would depend on specific security platform
    # This is a placeholder for enterprise security platform integration
    
    local upload_endpoint="${SECURITY_PLATFORM_ENDPOINT:-https://security.company.com/api/upload}"
    local api_key="${SECURITY_PLATFORM_API_KEY:-}"
    
    if [[ -z "$api_key" ]]; then
        log "WARN" "Security platform API key not configured - skipping upload"
        return 0
    fi
    
    # Create upload payload
    local upload_payload="$OUTPUT_DIR/compliance/upload-payload.json"
    jq -n \
        --arg project "$PROJECT_ROOT" \
        --arg timestamp "$TIMESTAMP" \
        --arg status "$([ "$SECURITY_SCAN_FAILED" == "true" ] && echo "FAILED" || echo "PASSED")" \
        --argjson critical "$CRITICAL_VULNERABILITIES" \
        --argjson high "$HIGH_VULNERABILITIES" \
        --argjson medium "$MEDIUM_VULNERABILITIES" \
        --argjson low "$LOW_VULNERABILITIES" \
        '{
            project: $project,
            timestamp: $timestamp,
            scan_status: $status,
            vulnerabilities: {
                critical: $critical,
                high: $high,
                medium: $medium,
                low: $low
            }
        }' > "$upload_payload"
    
    # Upload results (placeholder implementation)
    if curl -X POST \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d "@$upload_payload" \
        "$upload_endpoint" \
        --max-time 30 \
        --retry 3; then
        log "SUCCESS" "Security scan results uploaded successfully"
    else
        log "WARN" "Failed to upload security scan results - continuing execution"
    fi
}

# =============================================================================
# Main Execution Functions
# =============================================================================

# Parse command line arguments
parse_arguments() {
    local scan_mode="all"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -d|--debug)
                export DEBUG="true"
                ;;
            --project-root)
                PROJECT_ROOT="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --config-dir)
                CONFIG_DIR="$2"
                shift 2
                ;;
            --requirements)
                REQUIREMENTS_FILE="$2"
                shift 2
                ;;
            --container-image)
                CONTAINER_IMAGE="$2"
                shift 2
                ;;
            --severity-threshold)
                SEVERITY_THRESHOLD="$2"
                shift 2
                ;;
            --fail-on-critical)
                FAIL_ON_CRITICAL="$2"
                shift 2
                ;;
            --generate-reports)
                GENERATE_REPORTS="$2"
                shift 2
                ;;
            --upload-results)
                UPLOAD_RESULTS="$2"
                shift 2
                ;;
            --scan-dependencies)
                scan_mode="dependencies"
                shift
                ;;
            --scan-container)
                scan_mode="container"
                shift
                ;;
            --scan-code)
                scan_mode="code"
                shift
                ;;
            --scan-all)
                scan_mode="all"
                shift
                ;;
            *)
                log "ERROR" "Unknown argument: $1"
                log "INFO" "Use --help for usage information"
                exit 4
                ;;
        esac
    done
    
    # Validate severity threshold
    case "$SEVERITY_THRESHOLD" in
        LOW|MEDIUM|HIGH|CRITICAL) ;;
        *)
            log "ERROR" "Invalid severity threshold: $SEVERITY_THRESHOLD"
            log "INFO" "Valid options: LOW, MEDIUM, HIGH, CRITICAL"
            exit 4
            ;;
    esac
    
    # Store scan mode for main execution
    export SCAN_MODE="$scan_mode"
}

# Execute security scanning based on selected mode
execute_security_scans() {
    local scan_mode="$SCAN_MODE"
    local overall_success=true
    
    log "INFO" "Executing security scans in mode: $scan_mode"
    
    case "$scan_mode" in
        "dependencies")
            if ! scan_dependencies; then
                overall_success=false
            fi
            ;;
        "container")
            if ! scan_container; then
                overall_success=false
            fi
            ;;
        "code")
            if ! scan_code; then
                overall_success=false
            fi
            ;;
        "all")
            # Run all security scans
            if ! scan_dependencies; then
                overall_success=false
            fi
            
            if [[ -n "$CONTAINER_IMAGE" ]] && ! scan_container; then
                overall_success=false
            fi
            
            if ! scan_code; then
                overall_success=false
            fi
            ;;
        *)
            log "ERROR" "Invalid scan mode: $scan_mode"
            exit 4
            ;;
    esac
    
    # Generate comprehensive reports if enabled
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        generate_compliance_report
    fi
    
    # Upload results if enabled
    if [[ "$UPLOAD_RESULTS" == "true" ]]; then
        upload_security_results
    fi
    
    return $([ "$overall_success" == "true" ] && echo 0 || echo 1)
}

# Display final security scan results
display_final_results() {
    local exit_code="$1"
    
    echo ""
    log "INFO" "=========================================="
    log "INFO" "SECURITY SCANNING RESULTS SUMMARY"
    log "INFO" "=========================================="
    
    log "INFO" "Scan Configuration:"
    log "INFO" "  - Project Root: $PROJECT_ROOT"
    log "INFO" "  - Scan Mode: $SCAN_MODE"
    log "INFO" "  - Severity Threshold: $SEVERITY_THRESHOLD"
    log "INFO" "  - Fail on Critical: $FAIL_ON_CRITICAL"
    log "INFO" "  - Container Image: ${CONTAINER_IMAGE:-"Not specified"}"
    
    echo ""
    log "INFO" "Vulnerability Summary:"
    log "INFO" "  - Critical: $CRITICAL_VULNERABILITIES $([ "$CRITICAL_VULNERABILITIES" -eq 0 ] && echo "✅" || echo "❌")"
    log "INFO" "  - High: $HIGH_VULNERABILITIES $([ "$HIGH_VULNERABILITIES" -eq 0 ] && echo "✅" || echo "⚠️")"
    log "INFO" "  - Medium: $MEDIUM_VULNERABILITIES"
    log "INFO" "  - Low: $LOW_VULNERABILITIES"
    log "INFO" "  - Total: $((CRITICAL_VULNERABILITIES + HIGH_VULNERABILITIES + MEDIUM_VULNERABILITIES + LOW_VULNERABILITIES))"
    
    echo ""
    log "INFO" "Scan Execution Summary:"
    log "INFO" "  - Total Scans: $TOTAL_SCANS"
    log "INFO" "  - Failed Scans: $FAILED_SCANS"
    log "INFO" "  - Success Rate: $([ "$TOTAL_SCANS" -gt 0 ] && echo "$(( (TOTAL_SCANS - FAILED_SCANS) * 100 / TOTAL_SCANS ))%" || echo "N/A")"
    
    echo ""
    if [[ "$exit_code" -eq 0 ]]; then
        log "SUCCESS" "🎉 All security scans completed successfully!"
        log "SUCCESS" "✅ No critical security issues found"
        log "INFO" "System is ready for deployment"
    else
        log "ERROR" "💥 Security scanning failed!"
        if [[ "$CRITICAL_VULNERABILITIES" -gt 0 ]]; then
            log "ERROR" "❌ Critical vulnerabilities found - deployment blocked"
        fi
        if [[ "$FAILED_SCANS" -gt 0 ]]; then
            log "ERROR" "❌ $FAILED_SCANS scan(s) failed to execute properly"
        fi
        log "ERROR" "🔒 Security issues must be resolved before deployment"
    fi
    
    echo ""
    log "INFO" "📊 Detailed reports available in: $OUTPUT_DIR"
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        log "INFO" "📋 Executive summary: $OUTPUT_DIR/compliance/executive-summary.txt"
        log "INFO" "📈 Compliance report: $OUTPUT_DIR/compliance/security-compliance-report.json"
    fi
    
    echo ""
    log "INFO" "=========================================="
}

# Main function - orchestrates the entire security scanning process
main() {
    # Script initialization
    log "INFO" "Starting Flask Application Security Scanning and Compliance Validation"
    log "INFO" "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log "INFO" "Timestamp: $TIMESTAMP"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Environment validation and setup
    check_tool_dependencies
    setup_directories
    install_security_tools
    
    # Execute security scanning
    local exit_code=0
    if ! execute_security_scans; then
        exit_code=1
    fi
    
    # Final security policy enforcement
    if [[ "$CRITICAL_VULNERABILITIES" -gt 0 ]] && [[ "$FAIL_ON_CRITICAL" == "true" ]]; then
        log "ERROR" "Security policy enforcement: Critical vulnerabilities found"
        exit_code=1
    fi
    
    # Display final results
    display_final_results "$exit_code"
    
    # Exit with appropriate code
    exit "$exit_code"
}

# =============================================================================
# Script Execution Entry Point
# =============================================================================

# Execute main function with all provided arguments
main "$@"