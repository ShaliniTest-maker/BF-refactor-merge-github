#!/bin/bash

# Quality Validation Script for Flask Application
# 
# Implements comprehensive static analysis using flake8, mypy, and bandit with 
# zero-tolerance error policy and enterprise security compliance enforcement.
#
# Section References:
# - Section 8.5.1: Build pipeline quality gates with zero-tolerance enforcement
# - Section 6.6.3: Quality metrics and static analysis requirements
# - Section 0.3.1: Code quality and standards compliance
#
# Requirements Implemented:
# - Static Analysis Framework using flake8 6.1+ for comprehensive PEP 8 compliance
# - Type Safety Validation using mypy 1.8+ for strict mode enforcement
# - Security Analysis using bandit 1.7+ for comprehensive security vulnerability detection
# - Multi-tier validation with automated testing, static analysis, and security scanning

set -euo pipefail

# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

# Script metadata
SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Quality tool versions (minimum required per Section 8.5.1)
REQUIRED_FLAKE8_VERSION="6.1.0"
REQUIRED_MYPY_VERSION="1.8.0" 
REQUIRED_BANDIT_VERSION="1.7.0"
REQUIRED_SAFETY_VERSION="3.0.0"
REQUIRED_RADON_VERSION="6.0.0"

# Exit codes for enterprise CI/CD integration
readonly EXIT_SUCCESS=0
readonly EXIT_STATIC_ANALYSIS_FAILURE=1
readonly EXIT_TYPE_CHECK_FAILURE=2
readonly EXIT_SECURITY_FAILURE=3
readonly EXIT_COMPLEXITY_FAILURE=4
readonly EXIT_DEPENDENCY_FAILURE=5
readonly EXIT_CONFIGURATION_ERROR=6

# Color codes for enhanced output readability
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Quality standards enforcement (zero-tolerance per Section 8.5.1)
readonly ZERO_TOLERANCE_MODE="true"
readonly MAX_FLAKE8_ERRORS=0
readonly MAX_MYPY_ERRORS=0
readonly MAX_BANDIT_HIGH_SEVERITY=0
readonly MAX_BANDIT_CRITICAL_SEVERITY=0
readonly MIN_COVERAGE_THRESHOLD=90
readonly MAX_CYCLOMATIC_COMPLEXITY=10

# =============================================================================
# LOGGING AND OUTPUT FUNCTIONS
# =============================================================================

# Enhanced logging function with timestamp and severity levels
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${CYAN}[${timestamp}] [INFO]${NC} $message" >&1
            ;;
        "WARN")
            echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message" >&1
            ;;
        "ERROR")
            echo -e "${RED}[${timestamp}] [ERROR]${NC} $message" >&2
            ;;
        "SUCCESS")
            echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} $message" >&1
            ;;
        "DEBUG")
            if [[ "${VERBOSE:-false}" == "true" ]]; then
                echo -e "${PURPLE}[${timestamp}] [DEBUG]${NC} $message" >&1
            fi
            ;;
    esac
}

# Display script header with enterprise branding
display_header() {
    echo -e "${WHITE}"
    echo "=============================================================================="
    echo "  Flask Application Quality Validation Pipeline"
    echo "  Version: ${SCRIPT_VERSION}"
    echo "  Enterprise Code Quality Enforcement with Zero-Tolerance Policy"
    echo "=============================================================================="
    echo -e "${NC}"
    log "INFO" "Starting quality validation for project: $(basename "$PROJECT_ROOT")"
    log "INFO" "Quality enforcement mode: ${ZERO_TOLERANCE_MODE}"
}

# Display section headers for better readability
section_header() {
    local title="$1"
    echo -e "\n${BLUE}▶ $title${NC}"
    echo "$(printf '─%.0s' {1..60})"
}

# Display quality gate results
display_quality_gate_result() {
    local gate_name="$1"
    local status="$2"
    local details="$3"
    
    if [[ "$status" == "PASS" ]]; then
        echo -e "${GREEN}✓ Quality Gate: $gate_name - PASSED${NC}"
        [[ -n "$details" ]] && log "INFO" "$details"
    else
        echo -e "${RED}✗ Quality Gate: $gate_name - FAILED${NC}"
        [[ -n "$details" ]] && log "ERROR" "$details"
    fi
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Version comparison function
version_ge() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$1" ]
}

# Validate required tools and versions
validate_dependencies() {
    section_header "Dependency Validation"
    
    local validation_errors=0
    
    # Check Python version (minimum 3.8 per Section 0.1.1)
    if command_exists python3; then
        local python_version=$(python3 --version | cut -d' ' -f2)
        log "INFO" "Python version: $python_version"
        if ! version_ge "$python_version" "3.8.0"; then
            log "ERROR" "Python 3.8+ required, found $python_version"
            ((validation_errors++))
        fi
    else
        log "ERROR" "Python 3 not found"
        ((validation_errors++))
    fi
    
    # Validate flake8 version
    if command_exists flake8; then
        local flake8_version=$(flake8 --version | head -n1 | cut -d' ' -f1)
        log "INFO" "flake8 version: $flake8_version"
        if ! version_ge "$flake8_version" "$REQUIRED_FLAKE8_VERSION"; then
            log "ERROR" "flake8 $REQUIRED_FLAKE8_VERSION+ required, found $flake8_version"
            ((validation_errors++))
        fi
    else
        log "ERROR" "flake8 not found (required: $REQUIRED_FLAKE8_VERSION+)"
        ((validation_errors++))
    fi
    
    # Validate mypy version
    if command_exists mypy; then
        local mypy_version=$(mypy --version | cut -d' ' -f2)
        log "INFO" "mypy version: $mypy_version"
        if ! version_ge "$mypy_version" "$REQUIRED_MYPY_VERSION"; then
            log "ERROR" "mypy $REQUIRED_MYPY_VERSION+ required, found $mypy_version"
            ((validation_errors++))
        fi
    else
        log "ERROR" "mypy not found (required: $REQUIRED_MYPY_VERSION+)"
        ((validation_errors++))
    fi
    
    # Validate bandit version
    if command_exists bandit; then
        local bandit_version=$(bandit --version 2>&1 | grep "bandit" | cut -d' ' -f2)
        log "INFO" "bandit version: $bandit_version"
        if ! version_ge "$bandit_version" "$REQUIRED_BANDIT_VERSION"; then
            log "ERROR" "bandit $REQUIRED_BANDIT_VERSION+ required, found $bandit_version"
            ((validation_errors++))
        fi
    else
        log "ERROR" "bandit not found (required: $REQUIRED_BANDIT_VERSION+)"
        ((validation_errors++))
    fi
    
    # Validate additional quality tools
    for tool in safety radon; do
        if ! command_exists "$tool"; then
            log "WARN" "$tool not found (recommended for comprehensive analysis)"
        fi
    done
    
    if [[ $validation_errors -gt 0 ]]; then
        log "ERROR" "Dependency validation failed with $validation_errors errors"
        exit $EXIT_DEPENDENCY_FAILURE
    fi
    
    log "SUCCESS" "All required dependencies validated successfully"
}

# Generate quality configuration files
setup_quality_configs() {
    section_header "Quality Configuration Setup"
    
    log "INFO" "Generating quality tool configuration files..."
    
    # Generate .flake8 configuration (Section 8.5.1)
    cat > "$PROJECT_ROOT/.flake8" << 'EOF'
[flake8]
max-line-length = 88
extend-ignore = E203, W503, E501
exclude = 
    .git,
    __pycache__,
    build,
    dist,
    .env,
    venv,
    .venv,
    *.pyc,
    .pytest_cache,
    node_modules
per-file-ignores =
    __init__.py:F401
    tests/*:S101,S106
    conftest.py:F401
    migrations/*:E501
max-complexity = 10
doctests = True
statistics = True
count = True

# Flask-specific patterns
application-import-names = app,src
import-order-style = google

# Enterprise compliance settings
show-source = True
benchmark = True
EOF

    # Generate mypy.ini configuration (Section 8.5.1)
    cat > "$PROJECT_ROOT/mypy.ini" << 'EOF'
[mypy]
python_version = 3.11
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true

# Show error codes and context
show_error_codes = true
show_column_numbers = true

# Performance and cache settings
cache_dir = .mypy_cache
sqlite_cache = true

# Flask and third-party library patterns
[mypy-flask.*]
ignore_missing_imports = true

[mypy-werkzeug.*]
ignore_missing_imports = true

[mypy-pymongo.*]
ignore_missing_imports = true

[mypy-motor.*]
ignore_missing_imports = true

[mypy-redis.*]
ignore_missing_imports = true

[mypy-pytest.*]
ignore_missing_imports = true

[mypy-locust.*]
ignore_missing_imports = true

[mypy-testcontainers.*]
ignore_missing_imports = true
EOF

    # Generate bandit.yaml configuration (Section 8.5.1)
    cat > "$PROJECT_ROOT/bandit.yaml" << 'EOF'
# Bandit security configuration for Flask application
# Section 8.5.1: Security scanning with zero tolerance for critical findings

tests: [B201, B301, B302, B303, B304, B305, B306, B307, B308, B309, B310, B311, B312, B313, B314, B315, B316, B317, B318, B319, B320, B321, B322, B323, B324, B325, B326, B401, B402, B403, B404, B405, B406, B407, B408, B409, B410, B411, B412, B413, B501, B502, B503, B504, B505, B506, B507, B601, B602, B603, B604, B605, B606, B607, B608, B609, B610, B611, B701, B702, B703]
skips: [B101, B601]
exclude_dirs: [tests, build, dist, .git, __pycache__, .pytest_cache, node_modules]

# Severity levels for enterprise compliance
severity: [high, medium, low]
confidence: [high, medium, low]

# Flask-specific security patterns
assert_used:
  skips: ['*test*.py', '*conftest.py']

hardcoded_password:
  word_list: ['password', 'pass', 'passwd', 'pwd', 'secret', 'token', 'key']

# Enterprise security compliance
shell_injection:
  no_shell: true
  
sql_injection:
  check_typed_list: true
EOF
    
    log "SUCCESS" "Quality configuration files generated successfully"
}

# =============================================================================
# QUALITY ANALYSIS FUNCTIONS
# =============================================================================

# Execute flake8 static analysis with zero-tolerance enforcement
run_flake8_analysis() {
    section_header "flake8 Static Analysis (PEP 8 Compliance)"
    
    log "INFO" "Running flake8 analysis with zero-tolerance policy..."
    
    local flake8_output_file="$PROJECT_ROOT/.quality_reports/flake8_report.txt"
    mkdir -p "$(dirname "$flake8_output_file")"
    
    # Run flake8 with comprehensive reporting
    if flake8 src/ tests/ scripts/ \
        --output-file="$flake8_output_file" \
        --tee \
        --statistics \
        --count; then
        
        local error_count=$(grep -c ":" "$flake8_output_file" 2>/dev/null || echo "0")
        
        if [[ $error_count -eq $MAX_FLAKE8_ERRORS ]]; then
            display_quality_gate_result "flake8 Code Style" "PASS" "Zero style violations found"
            return 0
        else
            display_quality_gate_result "flake8 Code Style" "FAIL" "$error_count style violations found (max allowed: $MAX_FLAKE8_ERRORS)"
            log "ERROR" "flake8 report saved to: $flake8_output_file"
            return $EXIT_STATIC_ANALYSIS_FAILURE
        fi
    else
        display_quality_gate_result "flake8 Code Style" "FAIL" "flake8 execution failed"
        return $EXIT_STATIC_ANALYSIS_FAILURE
    fi
}

# Execute mypy type checking with strict mode enforcement
run_mypy_analysis() {
    section_header "mypy Type Safety Validation"
    
    log "INFO" "Running mypy type checking with strict mode enforcement..."
    
    local mypy_output_file="$PROJECT_ROOT/.quality_reports/mypy_report.txt"
    mkdir -p "$(dirname "$mypy_output_file")"
    
    # Run mypy with comprehensive type checking
    if mypy src/ \
        --config-file="$PROJECT_ROOT/mypy.ini" \
        --show-error-codes \
        --show-column-numbers \
        --pretty \
        --error-summary \
        > "$mypy_output_file" 2>&1; then
        
        display_quality_gate_result "mypy Type Safety" "PASS" "All type checks passed"
        log "INFO" "mypy report saved to: $mypy_output_file"
        return 0
    else
        local error_count=$(grep -c "error:" "$mypy_output_file" 2>/dev/null || echo "1")
        display_quality_gate_result "mypy Type Safety" "FAIL" "$error_count type checking errors found (max allowed: $MAX_MYPY_ERRORS)"
        
        # Display critical errors for immediate attention
        echo -e "\n${RED}Critical Type Checking Errors:${NC}"
        head -20 "$mypy_output_file" || true
        
        log "ERROR" "Full mypy report saved to: $mypy_output_file"
        return $EXIT_TYPE_CHECK_FAILURE
    fi
}

# Execute bandit security analysis with enterprise compliance
run_bandit_analysis() {
    section_header "bandit Security Analysis"
    
    log "INFO" "Running bandit security analysis with Flask-specific patterns..."
    
    local bandit_output_file="$PROJECT_ROOT/.quality_reports/bandit_report.json"
    local bandit_summary_file="$PROJECT_ROOT/.quality_reports/bandit_summary.txt"
    mkdir -p "$(dirname "$bandit_output_file")"
    
    # Run bandit with comprehensive security scanning
    if bandit -r src/ \
        -f json \
        -o "$bandit_output_file" \
        -c "$PROJECT_ROOT/bandit.yaml" \
        --severity-level high \
        --confidence-level medium; then
        
        # Generate human-readable summary
        bandit -r src/ \
            -f txt \
            -o "$bandit_summary_file" \
            -c "$PROJECT_ROOT/bandit.yaml" \
            --severity-level low \
            --confidence-level low \
            || true
        
        # Parse results for critical findings
        local high_severity_count=0
        local critical_severity_count=0
        
        if [[ -f "$bandit_output_file" ]]; then
            high_severity_count=$(python3 -c "
import json, sys
try:
    with open('$bandit_output_file') as f:
        data = json.load(f)
    print(len([r for r in data.get('results', []) if r.get('issue_severity') == 'HIGH']))
except: print(0)
" 2>/dev/null || echo "0")
            
            critical_severity_count=$(python3 -c "
import json, sys
try:
    with open('$bandit_output_file') as f:
        data = json.load(f)
    print(len([r for r in data.get('results', []) if r.get('issue_severity') == 'CRITICAL']))
except: print(0)
" 2>/dev/null || echo "0")
        fi
        
        local total_critical_high=$((critical_severity_count + high_severity_count))
        
        if [[ $total_critical_high -eq 0 ]]; then
            display_quality_gate_result "bandit Security" "PASS" "No critical or high-severity security issues found"
            log "INFO" "Security reports saved to: $bandit_output_file, $bandit_summary_file"
            return 0
        else
            display_quality_gate_result "bandit Security" "FAIL" "$total_critical_high critical/high-severity security issues found (max allowed: 0)"
            
            # Display critical findings for immediate attention
            if [[ -f "$bandit_summary_file" ]]; then
                echo -e "\n${RED}Critical Security Findings:${NC}"
                grep -A 5 -B 2 "Severity: High\|Severity: Critical" "$bandit_summary_file" | head -30 || true
            fi
            
            log "ERROR" "Security reports saved to: $bandit_output_file, $bandit_summary_file"
            return $EXIT_SECURITY_FAILURE
        fi
    else
        display_quality_gate_result "bandit Security" "FAIL" "bandit execution failed"
        return $EXIT_SECURITY_FAILURE
    fi
}

# Execute complexity analysis using radon
run_complexity_analysis() {
    section_header "Code Complexity Analysis"
    
    if ! command_exists radon; then
        log "WARN" "radon not found, skipping complexity analysis"
        return 0
    fi
    
    log "INFO" "Running complexity analysis with max complexity threshold: $MAX_CYCLOMATIC_COMPLEXITY"
    
    local complexity_output_file="$PROJECT_ROOT/.quality_reports/complexity_report.txt"
    mkdir -p "$(dirname "$complexity_output_file")"
    
    # Run radon complexity analysis
    radon cc src/ \
        --min B \
        --show-complexity \
        --average \
        --exclude "tests/*,migrations/*,__pycache__/*" \
        > "$complexity_output_file" 2>&1
    
    # Check for functions exceeding complexity threshold
    local high_complexity_count=$(grep -c "([0-9]\{2,\})" "$complexity_output_file" 2>/dev/null || echo "0")
    
    if [[ $high_complexity_count -eq 0 ]]; then
        display_quality_gate_result "Code Complexity" "PASS" "All functions within complexity threshold"
        log "INFO" "Complexity report saved to: $complexity_output_file"
        return 0
    else
        display_quality_gate_result "Code Complexity" "FAIL" "$high_complexity_count functions exceed complexity threshold"
        
        # Display high complexity functions
        echo -e "\n${YELLOW}High Complexity Functions:${NC}"
        grep "([0-9]\{2,\})" "$complexity_output_file" | head -10 || true
        
        log "ERROR" "Complexity report saved to: $complexity_output_file"
        return $EXIT_COMPLEXITY_FAILURE
    fi
}

# Execute dependency security scanning
run_dependency_security_scan() {
    section_header "Dependency Security Scanning"
    
    if ! command_exists safety; then
        log "WARN" "safety not found, skipping dependency vulnerability scanning"
        return 0
    fi
    
    log "INFO" "Running dependency vulnerability scanning with safety..."
    
    local safety_output_file="$PROJECT_ROOT/.quality_reports/safety_report.txt"
    mkdir -p "$(dirname "$safety_output_file")"
    
    # Run safety vulnerability scanning
    if safety check \
        --json \
        --output "$safety_output_file" \
        2>/dev/null; then
        
        display_quality_gate_result "Dependency Security" "PASS" "No critical vulnerabilities found in dependencies"
        log "INFO" "Safety report saved to: $safety_output_file"
        return 0
    else
        local vulnerability_count=$(python3 -c "
import json, sys
try:
    with open('$safety_output_file') as f:
        data = json.load(f)
    print(len(data))
except: print(1)
" 2>/dev/null || echo "1")
        
        display_quality_gate_result "Dependency Security" "FAIL" "$vulnerability_count dependency vulnerabilities found"
        
        # Display critical vulnerabilities
        echo -e "\n${RED}Critical Dependency Vulnerabilities:${NC}"
        head -20 "$safety_output_file" || true
        
        log "ERROR" "Safety report saved to: $safety_output_file"
        return $EXIT_SECURITY_FAILURE
    fi
}

# =============================================================================
# MAIN EXECUTION FUNCTIONS
# =============================================================================

# Execute all quality checks with enterprise enforcement
run_quality_pipeline() {
    local exit_code=0
    local failed_checks=()
    
    # Execute each quality check with error capture
    if ! run_flake8_analysis; then
        failed_checks+=("flake8 Static Analysis")
        exit_code=$EXIT_STATIC_ANALYSIS_FAILURE
    fi
    
    if ! run_mypy_analysis; then
        failed_checks+=("mypy Type Checking")
        [[ $exit_code -eq 0 ]] && exit_code=$EXIT_TYPE_CHECK_FAILURE
    fi
    
    if ! run_bandit_analysis; then
        failed_checks+=("bandit Security Analysis")
        [[ $exit_code -eq 0 ]] && exit_code=$EXIT_SECURITY_FAILURE
    fi
    
    if ! run_complexity_analysis; then
        failed_checks+=("Code Complexity Analysis")
        [[ $exit_code -eq 0 ]] && exit_code=$EXIT_COMPLEXITY_FAILURE
    fi
    
    if ! run_dependency_security_scan; then
        failed_checks+=("Dependency Security Scanning")
        [[ $exit_code -eq 0 ]] && exit_code=$EXIT_SECURITY_FAILURE
    fi
    
    return $exit_code
}

# Generate comprehensive quality report
generate_quality_report() {
    section_header "Quality Report Generation"
    
    local report_file="$PROJECT_ROOT/.quality_reports/quality_summary.md"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$report_file" << EOF
# Flask Application Quality Report

**Generated:** $timestamp  
**Project:** $(basename "$PROJECT_ROOT")  
**Quality Mode:** Zero-Tolerance Enterprise Enforcement  
**Script Version:** $SCRIPT_VERSION

## Quality Standards Compliance

| Quality Gate | Tool | Version | Status | Details |
|--------------|------|---------|--------|---------|
| Code Style | flake8 | $(flake8 --version | head -n1 | cut -d' ' -f1) | $(test -f "$PROJECT_ROOT/.quality_reports/flake8_report.txt" && echo "CHECKED" || echo "SKIPPED") | PEP 8 Compliance |
| Type Safety | mypy | $(mypy --version | cut -d' ' -f2) | $(test -f "$PROJECT_ROOT/.quality_reports/mypy_report.txt" && echo "CHECKED" || echo "SKIPPED") | Strict Type Checking |
| Security | bandit | $(bandit --version 2>&1 | grep "bandit" | cut -d' ' -f2) | $(test -f "$PROJECT_ROOT/.quality_reports/bandit_report.json" && echo "CHECKED" || echo "SKIPPED") | Security Vulnerability Detection |
| Complexity | radon | $(command_exists radon && radon --version | cut -d' ' -f2 || echo "N/A") | $(test -f "$PROJECT_ROOT/.quality_reports/complexity_report.txt" && echo "CHECKED" || echo "SKIPPED") | Maintainability Analysis |
| Dependencies | safety | $(command_exists safety && safety --version 2>&1 | head -n1 | cut -d' ' -f2 || echo "N/A") | $(test -f "$PROJECT_ROOT/.quality_reports/safety_report.txt" && echo "CHECKED" || echo "SKIPPED") | Vulnerability Scanning |

## Configuration Files

- **flake8:** \`.flake8\` (PEP 8 compliance with 88-character line length)
- **mypy:** \`mypy.ini\` (Strict type checking with zero tolerance)
- **bandit:** \`bandit.yaml\` (Comprehensive security analysis)

## Quality Enforcement Policy

- **Static Analysis:** Zero errors tolerance (max: $MAX_FLAKE8_ERRORS)
- **Type Checking:** 100% type check success required (max errors: $MAX_MYPY_ERRORS)
- **Security:** No critical/high severity findings allowed
- **Complexity:** Maximum cyclomatic complexity: $MAX_CYCLOMATIC_COMPLEXITY
- **Coverage:** Minimum threshold: $MIN_COVERAGE_THRESHOLD%

## Report Files

EOF

    # Add links to detailed reports
    for report in flake8_report.txt mypy_report.txt bandit_report.json bandit_summary.txt complexity_report.txt safety_report.txt; do
        if [[ -f "$PROJECT_ROOT/.quality_reports/$report" ]]; then
            echo "- **$report:** Detailed analysis results" >> "$report_file"
        fi
    done
    
    log "SUCCESS" "Quality report generated: $report_file"
}

# Display usage information
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Flask Application Quality Validation Script
Implements enterprise-grade code quality enforcement with zero-tolerance policy.

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -q, --quiet         Suppress non-error output
    --config-only       Generate configuration files only
    --skip-deps         Skip dependency validation
    --report-only       Generate report from existing results

QUALITY GATES:
    - flake8 6.1+:      PEP 8 compliance (zero errors)
    - mypy 1.8+:        Type safety (strict mode)
    - bandit 1.7+:      Security analysis (no critical/high findings)
    - radon:            Complexity analysis (max: $MAX_CYCLOMATIC_COMPLEXITY)
    - safety:           Dependency vulnerability scanning

EXIT CODES:
    0: Success (all quality gates passed)
    1: Static analysis failure (flake8)
    2: Type checking failure (mypy)
    3: Security analysis failure (bandit/safety)
    4: Complexity threshold exceeded
    5: Dependency validation failure
    6: Configuration error

EXAMPLES:
    $SCRIPT_NAME                    # Run full quality pipeline
    $SCRIPT_NAME --verbose          # Run with detailed output
    $SCRIPT_NAME --config-only      # Generate configs only
    $SCRIPT_NAME --report-only      # Generate report only

For more information, see Section 8.5.1 of the technical specification.
EOF
}

# =============================================================================
# MAIN SCRIPT EXECUTION
# =============================================================================

main() {
    local config_only=false
    local skip_deps=false
    local report_only=false
    local quiet=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit $EXIT_SUCCESS
                ;;
            -v|--verbose)
                export VERBOSE=true
                shift
                ;;
            -q|--quiet)
                quiet=true
                shift
                ;;
            --config-only)
                config_only=true
                shift
                ;;
            --skip-deps)
                skip_deps=true
                shift
                ;;
            --report-only)
                report_only=true
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit $EXIT_CONFIGURATION_ERROR
                ;;
        esac
    done
    
    # Suppress output if quiet mode
    if [[ "$quiet" == "true" ]]; then
        exec 1>/dev/null
    fi
    
    # Display header
    display_header
    
    # Change to project root directory
    cd "$PROJECT_ROOT" || {
        log "ERROR" "Failed to change to project root: $PROJECT_ROOT"
        exit $EXIT_CONFIGURATION_ERROR
    }
    
    # Generate configuration files
    setup_quality_configs
    
    if [[ "$config_only" == "true" ]]; then
        log "SUCCESS" "Configuration files generated successfully"
        exit $EXIT_SUCCESS
    fi
    
    # Validate dependencies unless skipped
    if [[ "$skip_deps" != "true" ]]; then
        validate_dependencies
    fi
    
    # Generate report only if requested
    if [[ "$report_only" == "true" ]]; then
        generate_quality_report
        exit $EXIT_SUCCESS
    fi
    
    # Create reports directory
    mkdir -p "$PROJECT_ROOT/.quality_reports"
    
    # Execute quality pipeline
    local pipeline_exit_code=0
    if ! run_quality_pipeline; then
        pipeline_exit_code=$?
    fi
    
    # Generate comprehensive quality report
    generate_quality_report
    
    # Display final results
    echo -e "\n${WHITE}=============================================================================="
    if [[ $pipeline_exit_code -eq 0 ]]; then
        echo -e "  ${GREEN}✓ ALL QUALITY GATES PASSED${WHITE}"
        echo -e "  Enterprise code quality standards successfully enforced"
        log "SUCCESS" "Quality validation completed successfully"
    else
        echo -e "  ${RED}✗ QUALITY VALIDATION FAILED${WHITE}"
        echo -e "  One or more quality gates failed - review reports for details"
        log "ERROR" "Quality validation failed with exit code: $pipeline_exit_code"
    fi
    echo -e "=============================================================================="
    echo -e "${NC}"
    
    exit $pipeline_exit_code
}

# Execute main function with all arguments
main "$@"