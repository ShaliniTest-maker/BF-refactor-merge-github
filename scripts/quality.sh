#!/bin/bash

#######################################################################
# Code Quality Validation Script for Flask Application
#
# This script executes comprehensive static analysis using flake8, mypy,
# and bandit with zero-tolerance error policy and enterprise security
# compliance enforcement as specified in Section 8.5.1.
#
# Requirements:
# - flake8 6.1+ for comprehensive PEP 8 compliance
# - mypy 1.8+ for static type checking with strict mode enforcement
# - bandit 1.7+ for comprehensive Python security vulnerability detection
# - Zero-tolerance error policy with pipeline termination on failures
#
# Usage: ./scripts/quality.sh [options]
#
# Exit Codes:
#   0 - All quality checks passed
#   1 - Static analysis failures (flake8/mypy)
#   2 - Security analysis failures (bandit)
#   3 - Configuration or dependency errors
#   4 - Script execution errors
#######################################################################

set -euo pipefail  # Exit on any error, undefined variable, or pipe failure

# Script metadata and configuration
readonly SCRIPT_NAME="quality.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LOG_PREFIX="[QUALITY]"

# Color codes for enhanced output readability
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Quality tool versions and requirements per Section 8.5.1
readonly FLAKE8_MIN_VERSION="6.1.0"
readonly MYPY_MIN_VERSION="1.8.0"
readonly BANDIT_MIN_VERSION="1.7.0"

# Default configuration paths
readonly FLAKE8_CONFIG="${PROJECT_ROOT}/.flake8"
readonly MYPY_CONFIG="${PROJECT_ROOT}/mypy.ini"
readonly BANDIT_CONFIG="${PROJECT_ROOT}/bandit.yaml"
readonly QUALITY_CONFIG="${PROJECT_ROOT}/src/config/quality.py"

# Output and reporting directories
readonly REPORTS_DIR="${PROJECT_ROOT}/reports"
readonly QUALITY_REPORTS_DIR="${REPORTS_DIR}/quality"

# Zero-tolerance policy flags
STRICT_MODE=true
FAIL_ON_ANY_ERROR=true
ENTERPRISE_COMPLIANCE=true

# Execution control flags
VERBOSE=false
QUIET=false
PARALLEL_EXECUTION=true
GENERATE_REPORTS=true

#######################################################################
# Utility Functions
#######################################################################

# Enhanced logging function with timestamps and structured output
log() {
    local level="$1"
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${timestamp} ${LOG_PREFIX} ${BLUE}[INFO]${NC} $*" >&1
            ;;
        "WARN")
            echo -e "${timestamp} ${LOG_PREFIX} ${YELLOW}[WARN]${NC} $*" >&2
            ;;
        "ERROR")
            echo -e "${timestamp} ${LOG_PREFIX} ${RED}[ERROR]${NC} $*" >&2
            ;;
        "SUCCESS")
            echo -e "${timestamp} ${LOG_PREFIX} ${GREEN}[SUCCESS]${NC} $*" >&1
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == "true" ]]; then
                echo -e "${timestamp} ${LOG_PREFIX} ${PURPLE}[DEBUG]${NC} $*" >&1
            fi
            ;;
    esac
}

# Progress indicator for long-running operations
show_progress() {
    local message="$1"
    local pid="$2"
    
    if [[ "$QUIET" != "true" ]]; then
        echo -n -e "${CYAN}${message}${NC}"
        while kill -0 "$pid" 2>/dev/null; do
            echo -n "."
            sleep 0.5
        done
        echo " ${GREEN}Done${NC}"
    fi
}

# Version comparison utility for dependency validation
version_compare() {
    local version1="$1"
    local version2="$2"
    
    if [[ "$version1" == "$version2" ]]; then
        return 0
    fi
    
    local IFS=.
    local i ver1=($version1) ver2=($version2)
    
    # Compare version components
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

# Error handling with comprehensive context and remediation guidance
handle_error() {
    local exit_code="$1"
    local error_message="$2"
    local remediation="${3:-}"
    
    log "ERROR" "Quality validation failed with exit code: $exit_code"
    log "ERROR" "Error details: $error_message"
    
    if [[ -n "$remediation" ]]; then
        log "INFO" "Remediation guidance: $remediation"
    fi
    
    # Generate failure report if reports are enabled
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        generate_failure_report "$exit_code" "$error_message" "$remediation"
    fi
    
    exit "$exit_code"
}

# Comprehensive dependency validation with version checking
validate_dependencies() {
    log "INFO" "Validating quality tool dependencies and versions..."
    
    local missing_tools=()
    local version_issues=()
    
    # Check flake8 availability and version
    if ! command -v flake8 &> /dev/null; then
        missing_tools+=("flake8")
    else
        local flake8_version=$(flake8 --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -n1)
        version_compare "$flake8_version" "$FLAKE8_MIN_VERSION"
        local result=$?
        if [[ $result -eq 2 ]]; then
            version_issues+=("flake8: found $flake8_version, required >= $FLAKE8_MIN_VERSION")
        else
            log "DEBUG" "flake8 version $flake8_version meets requirement >= $FLAKE8_MIN_VERSION"
        fi
    fi
    
    # Check mypy availability and version
    if ! command -v mypy &> /dev/null; then
        missing_tools+=("mypy")
    else
        local mypy_version=$(mypy --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -n1)
        version_compare "$mypy_version" "$MYPY_MIN_VERSION"
        local result=$?
        if [[ $result -eq 2 ]]; then
            version_issues+=("mypy: found $mypy_version, required >= $MYPY_MIN_VERSION")
        else
            log "DEBUG" "mypy version $mypy_version meets requirement >= $MYPY_MIN_VERSION"
        fi
    fi
    
    # Check bandit availability and version
    if ! command -v bandit &> /dev/null; then
        missing_tools+=("bandit")
    else
        local bandit_version=$(bandit --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -n1)
        version_compare "$bandit_version" "$BANDIT_MIN_VERSION"
        local result=$?
        if [[ $result -eq 2 ]]; then
            version_issues+=("bandit: found $bandit_version, required >= $BANDIT_MIN_VERSION")
        else
            log "DEBUG" "bandit version $bandit_version meets requirement >= $BANDIT_MIN_VERSION"
        fi
    fi
    
    # Report missing tools
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "ERROR" "Missing required quality tools: ${missing_tools[*]}"
        log "INFO" "Install missing tools with: pip install ${missing_tools[*]}"
        handle_error 3 "Missing dependencies" "pip install ${missing_tools[*]}"
    fi
    
    # Report version issues
    if [[ ${#version_issues[@]} -gt 0 ]]; then
        log "ERROR" "Version requirement issues:"
        for issue in "${version_issues[@]}"; do
            log "ERROR" "  - $issue"
        done
        handle_error 3 "Version requirements not met" "pip install --upgrade flake8 mypy bandit"
    fi
    
    log "SUCCESS" "All quality tool dependencies validated"
}

# Configuration file validation and setup
validate_configuration() {
    log "INFO" "Validating quality configuration files..."
    
    # Create reports directory if it doesn't exist
    mkdir -p "$QUALITY_REPORTS_DIR"
    
    # Validate flake8 configuration
    if [[ ! -f "$FLAKE8_CONFIG" ]]; then
        log "WARN" "flake8 configuration not found at $FLAKE8_CONFIG, creating default"
        create_default_flake8_config
    else
        log "DEBUG" "Found flake8 configuration at $FLAKE8_CONFIG"
    fi
    
    # Validate mypy configuration
    if [[ ! -f "$MYPY_CONFIG" ]]; then
        log "WARN" "mypy configuration not found at $MYPY_CONFIG, creating default"
        create_default_mypy_config
    else
        log "DEBUG" "Found mypy configuration at $MYPY_CONFIG"
    fi
    
    # Validate bandit configuration
    if [[ ! -f "$BANDIT_CONFIG" ]]; then
        log "WARN" "bandit configuration not found at $BANDIT_CONFIG, creating default"
        create_default_bandit_config
    else
        log "DEBUG" "Found bandit configuration at $BANDIT_CONFIG"
    fi
    
    # Check for quality configuration module (optional)
    if [[ -f "$QUALITY_CONFIG" ]]; then
        log "DEBUG" "Found quality configuration module at $QUALITY_CONFIG"
    else
        log "DEBUG" "Quality configuration module not found (optional): $QUALITY_CONFIG"
    fi
    
    log "SUCCESS" "Configuration validation completed"
}

# Create default flake8 configuration with enterprise standards
create_default_flake8_config() {
    cat > "$FLAKE8_CONFIG" << 'EOF'
[flake8]
# Maximum line length per Section 8.5.1 enterprise standards
max-line-length = 88

# Ignore specific errors while maintaining strict compliance
extend-ignore = E203, W503, E501

# Exclude common non-source directories
exclude = 
    .git,
    __pycache__,
    build,
    dist,
    .env,
    venv,
    .venv,
    .pytest_cache,
    .mypy_cache,
    reports

# Per-file ignores for specific patterns
per-file-ignores =
    __init__.py:F401
    tests/*:S101,S106
    conftest.py:F401

# Maximum cyclomatic complexity per maintainability requirements
max-complexity = 10

# Enable doctests checking for documentation quality
doctests = True

# Show statistics and counts for comprehensive reporting
statistics = True
count = True

# Enable comprehensive checks
select = E,W,F,C

# Ensure comprehensive coverage of all error types
enable-extensions = G,B,B9,Q0
EOF
    log "INFO" "Created default flake8 configuration with enterprise standards"
}

# Create default mypy configuration with strict type checking
create_default_mypy_config() {
    cat > "$MYPY_CONFIG" << 'EOF'
[mypy]
# Python version target per project requirements
python_version = 3.11

# Strict mode enforcement per Section 8.5.1
strict = True

# Comprehensive type checking options
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_decorators = True
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True
strict_equality = True

# Additional strict checks for enterprise compliance
disallow_any_unimported = True
disallow_any_expr = False
disallow_any_decorated = False
disallow_any_explicit = False
disallow_any_generics = True
disallow_subclassing_any = True

# Error output formatting
show_error_codes = True
show_column_numbers = True
show_error_context = True
pretty = True

# Follow imports for complete type coverage
follow_imports = normal
ignore_missing_imports = False

# Cache configuration for performance
cache_dir = .mypy_cache

# Module-specific configurations
[mypy-tests.*]
# Allow some flexibility in test files
disallow_untyped_defs = False
ignore_errors = False

[mypy-conftest]
# Configuration for pytest conftest files
ignore_errors = False
EOF
    log "INFO" "Created default mypy configuration with strict enforcement"
}

# Create default bandit configuration for security analysis
create_default_bandit_config() {
    cat > "$BANDIT_CONFIG" << 'EOF'
# Bandit security configuration per Section 8.5.1
# Comprehensive security tests for Flask applications

tests: 
  # Common Python security issues
  - B201  # Test for use of flask debug mode
  - B301  # Pickle usage security check
  - B302  # Use of insecure MD2, MD4, MD5, or SHA1 hash functions
  - B303  # Use of insecure MD2, MD4, MD5, or SHA1 hash functions
  - B304  # Use of insecure cipher modes
  - B305  # Use of insecure cipher
  - B306  # Use of insecure and deprecated mktemp
  - B307  # Use of possibly insecure eval
  - B308  # Mark use of insecure MD2, MD4, MD5, or SHA1 hash functions
  - B309  # Use of HTTPSConnection without certificate verification
  - B310  # Audit url open for permitted schemes
  - B311  # Standard pseudo-random generators are not suitable for security
  - B312  # Telnetlib usage might be insecure
  - B313  # Using xml to parse untrusted data is known to be vulnerable
  - B314  # Blacklist of xml.etree.ElementTree methods
  - B315  # Blacklist of xml.sax methods
  - B316  # Blacklist of xml.minidom methods
  - B317  # Using xml to parse untrusted data is known to be vulnerable
  - B318  # Blacklist of xml.dom.pulldom methods
  - B319  # Using xml to parse untrusted data is known to be vulnerable
  - B320  # Blacklist of lxml methods that can lead to vulnerabilities
  - B321  # Use of FTP-related functions that might be insecure
  - B322  # Use of input() might be vulnerable
  - B323  # Use of unverified context
  - B324  # Use of hashlib.new() with insecure hashing algorithm
  - B325  # Use of tempfile.mktemp() might be vulnerable
  - B326  # Use of tempfile.NamedTemporaryFile might be vulnerable
  
  # Authentication and authorization issues
  - B401  # Import of subprocess with shell=True
  - B402  # Import and use of pycrypto
  - B403  # Consider possible security implications of pickle
  - B404  # Consider possible security implications of subprocess
  - B405  # Import and use of xml.etree.ElementTree and xml.dom.minidom
  - B406  # Import and use of xml.sax
  - B407  # Import and use of xml.dom.pulldom
  - B408  # Import and use of xml.dom.minidom
  - B409  # Import and use of xml.etree.ElementTree
  - B410  # Import and use of lxml
  - B411  # Import and use of xmlrpclib
  - B412  # Import and use of httplib/http.client
  - B413  # Import and use of pycryptodome

  # Web application specific security issues
  - B501  # Test for missing certificate validation
  - B502  # Test for SSL with bad version
  - B503  # Test for SSL with bad defaults
  - B504  # Test for SSL with no version specified
  - B505  # Test for weak cryptographic key use
  - B506  # Test for use of yaml load
  - B507  # Test for missing host key validation

  # Input validation and injection issues
  - B601  # Parameterized shell usage should be avoided
  - B602  # Test for use of popen with shell equals true
  - B603  # Test for use of subprocess without shell equals true
  - B604  # Test for any function with shell equals true
  - B605  # Test for starting a process with a shell
  - B606  # Test for starting a process with no shell
  - B607  # Test for starting a process with a partial path
  - B608  # Test for SQL injection
  - B609  # Test for use of wildcard in SQL queries
  - B610  # Test for SQL injection through string formatting
  - B611  # Test for SQL injection through string interpolation

  # General coding issues that may lead to security problems
  - B701  # Test for use of jinja2 templates without autoescape
  - B702  # Test for use of mako templates
  - B703  # Test for potential XSS on mark_safe usage

# Skip these tests that may have false positives in test environments
skips: 
  - B101  # Test for use of assert (common in tests)
  - B601  # Parameterized shell usage (may be needed for legitimate shell operations)

# Exclude directories that don't contain source code
exclude_dirs: 
  - tests
  - build
  - dist
  - .git
  - __pycache__
  - .pytest_cache
  - .mypy_cache
  - reports

# Confidence levels to report (HIGH, MEDIUM, LOW)
confidence: HIGH

# Security issue severity levels to report
level: MEDIUM
EOF
    log "INFO" "Created default bandit configuration with Flask-specific security patterns"
}

#######################################################################
# Static Analysis Functions
#######################################################################

# Comprehensive flake8 code style validation
run_flake8_analysis() {
    log "INFO" "Running flake8 static analysis with zero-tolerance enforcement..."
    
    local output_file="${QUALITY_REPORTS_DIR}/flake8_report.txt"
    local exit_code=0
    
    # Run flake8 with comprehensive reporting
    if [[ "$VERBOSE" == "true" ]]; then
        flake8 "$PROJECT_ROOT/src" "$PROJECT_ROOT/tests" \
            --config="$FLAKE8_CONFIG" \
            --output-file="$output_file" \
            --tee \
            --statistics \
            --count || exit_code=$?
    else
        flake8 "$PROJECT_ROOT/src" "$PROJECT_ROOT/tests" \
            --config="$FLAKE8_CONFIG" \
            --output-file="$output_file" \
            --statistics \
            --count || exit_code=$?
    fi
    
    # Analyze results with zero-tolerance policy
    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "flake8 analysis passed with zero violations"
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "flake8 analysis: PASSED (0 violations)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        return 0
    else
        local violation_count=$(grep -c "^" "$output_file" 2>/dev/null || echo "0")
        log "ERROR" "flake8 analysis failed with $violation_count violations"
        
        if [[ "$VERBOSE" == "true" ]]; then
            log "ERROR" "flake8 violations details:"
            cat "$output_file" | head -20
            if [[ $violation_count -gt 20 ]]; then
                log "INFO" "... and $(($violation_count - 20)) more violations (see $output_file)"
            fi
        fi
        
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "flake8 analysis: FAILED ($violation_count violations)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        
        if [[ "$STRICT_MODE" == "true" ]]; then
            handle_error 1 "flake8 style violations detected" "Fix all PEP 8 compliance issues: see $output_file"
        fi
        return 1
    fi
}

# Strict mypy type checking validation
run_mypy_analysis() {
    log "INFO" "Running mypy type checking with strict mode enforcement..."
    
    local output_file="${QUALITY_REPORTS_DIR}/mypy_report.txt"
    local exit_code=0
    
    # Run mypy with strict configuration
    if [[ "$VERBOSE" == "true" ]]; then
        mypy "$PROJECT_ROOT/src" \
            --config-file="$MYPY_CONFIG" \
            --no-error-summary \
            --show-column-numbers \
            --show-error-codes \
            --pretty 2>&1 | tee "$output_file" || exit_code=${PIPESTATUS[0]}
    else
        mypy "$PROJECT_ROOT/src" \
            --config-file="$MYPY_CONFIG" \
            --no-error-summary \
            --show-column-numbers \
            --show-error-codes \
            --pretty > "$output_file" 2>&1 || exit_code=$?
    fi
    
    # Analyze results with 100% success requirement
    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "mypy type checking passed with 100% success"
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "mypy analysis: PASSED (100% type check success)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        return 0
    else
        local error_count=$(grep -c "error:" "$output_file" 2>/dev/null || echo "0")
        log "ERROR" "mypy type checking failed with $error_count errors"
        
        if [[ "$VERBOSE" == "true" ]]; then
            log "ERROR" "mypy type errors details:"
            grep "error:" "$output_file" | head -10
            if [[ $error_count -gt 10 ]]; then
                log "INFO" "... and $(($error_count - 10)) more errors (see $output_file)"
            fi
        fi
        
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "mypy analysis: FAILED ($error_count type errors)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        
        if [[ "$STRICT_MODE" == "true" ]]; then
            handle_error 1 "mypy type checking errors detected" "Fix all type annotation issues: see $output_file"
        fi
        return 1
    fi
}

#######################################################################
# Security Analysis Functions
#######################################################################

# Comprehensive bandit security analysis
run_bandit_analysis() {
    log "INFO" "Running bandit security analysis with enterprise compliance..."
    
    local output_file="${QUALITY_REPORTS_DIR}/bandit_report.json"
    local text_output="${QUALITY_REPORTS_DIR}/bandit_report.txt"
    local exit_code=0
    
    # Run bandit with comprehensive security analysis
    bandit -r "$PROJECT_ROOT/src" \
        -c "$BANDIT_CONFIG" \
        -f json \
        -o "$output_file" \
        --quiet 2>/dev/null || exit_code=$?
    
    # Generate human-readable report
    bandit -r "$PROJECT_ROOT/src" \
        -c "$BANDIT_CONFIG" \
        -f txt \
        -o "$text_output" \
        --quiet 2>/dev/null || true
    
    # Analyze security findings with enterprise policy
    if [[ -f "$output_file" ]]; then
        local high_severity=$(jq -r '.results[] | select(.issue_severity == "HIGH") | .issue_severity' "$output_file" 2>/dev/null | wc -l || echo "0")
        local medium_severity=$(jq -r '.results[] | select(.issue_severity == "MEDIUM") | .issue_severity' "$output_file" 2>/dev/null | wc -l || echo "0")
        local low_severity=$(jq -r '.results[] | select(.issue_severity == "LOW") | .issue_severity' "$output_file" 2>/dev/null | wc -l || echo "0")
        
        log "INFO" "Security analysis results: High: $high_severity, Medium: $medium_severity, Low: $low_severity"
        
        # Enterprise compliance check: no high/critical findings allowed
        if [[ $high_severity -gt 0 ]]; then
            log "ERROR" "Found $high_severity high-severity security issues"
            
            if [[ "$VERBOSE" == "true" ]]; then
                log "ERROR" "High-severity security issues:"
                jq -r '.results[] | select(.issue_severity == "HIGH") | "  - \(.test_name): \(.issue_text) (File: \(.filename):\(.line_number))"' "$output_file" 2>/dev/null || true
            fi
            
            if [[ "$GENERATE_REPORTS" == "true" ]]; then
                echo "bandit analysis: FAILED ($high_severity high-severity issues)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
            fi
            
            if [[ "$ENTERPRISE_COMPLIANCE" == "true" ]]; then
                handle_error 2 "High-severity security vulnerabilities detected" "Review and fix security issues: see $text_output"
            fi
            return 2
        elif [[ $medium_severity -gt 0 ]]; then
            log "WARN" "Found $medium_severity medium-severity security issues - review recommended"
            if [[ "$GENERATE_REPORTS" == "true" ]]; then
                echo "bandit analysis: WARNING ($medium_severity medium-severity issues)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
            fi
        else
            log "SUCCESS" "bandit security analysis passed with no high/medium severity issues"
            if [[ "$GENERATE_REPORTS" == "true" ]]; then
                echo "bandit analysis: PASSED (0 high/medium severity issues)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
            fi
        fi
        
        return 0
    else
        log "ERROR" "bandit security analysis failed to generate report"
        handle_error 2 "bandit execution failure" "Check bandit installation and configuration"
    fi
}

# Additional security validation using safety for dependency scanning
run_safety_analysis() {
    log "INFO" "Running safety dependency vulnerability scanning..."
    
    if ! command -v safety &> /dev/null; then
        log "WARN" "safety not available, skipping dependency vulnerability scan"
        return 0
    fi
    
    local output_file="${QUALITY_REPORTS_DIR}/safety_report.txt"
    local exit_code=0
    
    # Run safety check on current environment
    safety check --json --output "$output_file" 2>/dev/null || exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "safety dependency scan passed - no known vulnerabilities"
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "safety analysis: PASSED (no known vulnerabilities)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        return 0
    else
        local vuln_count=$(jq length "$output_file" 2>/dev/null || echo "unknown")
        log "ERROR" "safety found $vuln_count dependency vulnerabilities"
        
        if [[ "$VERBOSE" == "true" && -f "$output_file" ]]; then
            log "ERROR" "Dependency vulnerabilities:"
            jq -r '.[] | "  - \(.package_name) \(.installed_version): \(.advisory)"' "$output_file" 2>/dev/null | head -5
        fi
        
        if [[ "$GENERATE_REPORTS" == "true" ]]; then
            echo "safety analysis: FAILED ($vuln_count vulnerabilities)" >> "${QUALITY_REPORTS_DIR}/summary.txt"
        fi
        
        if [[ "$ENTERPRISE_COMPLIANCE" == "true" ]]; then
            handle_error 2 "Dependency vulnerabilities detected" "Update vulnerable dependencies: see $output_file"
        fi
        return 2
    fi
}

#######################################################################
# Report Generation Functions
#######################################################################

# Generate comprehensive quality report
generate_quality_report() {
    log "INFO" "Generating comprehensive quality report..."
    
    local report_file="${QUALITY_REPORTS_DIR}/quality_report.html"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Code Quality Report - Flask Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .code { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Code Quality Report</h1>
        <p><strong>Generated:</strong> $timestamp</p>
        <p><strong>Project:</strong> Flask Application Migration</p>
        <p><strong>Quality Standards:</strong> Enterprise Compliance (Section 8.5.1)</p>
    </div>
EOF
    
    # Add summary section
    if [[ -f "${QUALITY_REPORTS_DIR}/summary.txt" ]]; then
        echo '<div class="section">' >> "$report_file"
        echo '<h2>Quality Analysis Summary</h2>' >> "$report_file"
        echo '<div class="code">' >> "$report_file"
        cat "${QUALITY_REPORTS_DIR}/summary.txt" >> "$report_file"
        echo '</div>' >> "$report_file"
        echo '</div>' >> "$report_file"
    fi
    
    # Add detailed sections for each tool
    add_tool_section_to_report "$report_file" "flake8" "Code Style Analysis"
    add_tool_section_to_report "$report_file" "mypy" "Type Checking Analysis"
    add_tool_section_to_report "$report_file" "bandit" "Security Analysis"
    add_tool_section_to_report "$report_file" "safety" "Dependency Security"
    
    # Close HTML
    echo '</body></html>' >> "$report_file"
    
    log "SUCCESS" "Quality report generated: $report_file"
}

# Add tool section to HTML report
add_tool_section_to_report() {
    local report_file="$1"
    local tool="$2"
    local title="$3"
    
    local tool_report="${QUALITY_REPORTS_DIR}/${tool}_report.txt"
    
    if [[ -f "$tool_report" ]]; then
        echo "<div class=\"section\">" >> "$report_file"
        echo "<h2>$title ($tool)</h2>" >> "$report_file"
        echo "<div class=\"code\">" >> "$report_file"
        head -50 "$tool_report" >> "$report_file"
        echo "</div>" >> "$report_file"
        echo "</div>" >> "$report_file"
    fi
}

# Generate failure report for pipeline integration
generate_failure_report() {
    local exit_code="$1"
    local error_message="$2"
    local remediation="$3"
    
    local failure_file="${QUALITY_REPORTS_DIR}/failure_report.json"
    local timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    cat > "$failure_file" << EOF
{
    "timestamp": "$timestamp",
    "script": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION",
    "exit_code": $exit_code,
    "error_message": "$error_message",
    "remediation": "$remediation",
    "project_root": "$PROJECT_ROOT",
    "reports_directory": "$QUALITY_REPORTS_DIR"
}
EOF
    
    log "INFO" "Failure report generated: $failure_file"
}

#######################################################################
# Parallel Execution Functions
#######################################################################

# Execute quality checks in parallel for performance optimization
run_parallel_quality_checks() {
    log "INFO" "Executing quality checks in parallel mode..."
    
    local pids=()
    local results=()
    
    # Start flake8 analysis in background
    (run_flake8_analysis; echo $? > "${QUALITY_REPORTS_DIR}/flake8_exit") &
    pids[0]=$!
    
    # Start mypy analysis in background
    (run_mypy_analysis; echo $? > "${QUALITY_REPORTS_DIR}/mypy_exit") &
    pids[1]=$!
    
    # Start bandit analysis in background
    (run_bandit_analysis; echo $? > "${QUALITY_REPORTS_DIR}/bandit_exit") &
    pids[2]=$!
    
    # Start safety analysis in background
    (run_safety_analysis; echo $? > "${QUALITY_REPORTS_DIR}/safety_exit") &
    pids[3]=$!
    
    # Wait for all processes and collect results
    local tool_names=("flake8" "mypy" "bandit" "safety")
    local overall_exit=0
    
    for i in "${!pids[@]}"; do
        local pid=${pids[$i]}
        local tool=${tool_names[$i]}
        
        if [[ "$QUIET" != "true" ]]; then
            show_progress "Waiting for $tool analysis" "$pid"
        else
            wait "$pid"
        fi
        
        # Read exit code from file
        local exit_file="${QUALITY_REPORTS_DIR}/${tool}_exit"
        if [[ -f "$exit_file" ]]; then
            local tool_exit=$(cat "$exit_file")
            results[$i]=$tool_exit
            rm -f "$exit_file"
            
            if [[ $tool_exit -ne 0 ]]; then
                overall_exit=$tool_exit
                log "ERROR" "$tool analysis failed with exit code: $tool_exit"
            else
                log "SUCCESS" "$tool analysis completed successfully"
            fi
        else
            log "ERROR" "Could not determine exit status for $tool"
            overall_exit=4
        fi
    done
    
    return $overall_exit
}

# Execute quality checks sequentially
run_sequential_quality_checks() {
    log "INFO" "Executing quality checks in sequential mode..."
    
    local overall_exit=0
    
    # Run each tool sequentially and collect results
    if ! run_flake8_analysis; then
        overall_exit=1
        if [[ "$FAIL_ON_ANY_ERROR" == "true" ]]; then
            return $overall_exit
        fi
    fi
    
    if ! run_mypy_analysis; then
        overall_exit=1
        if [[ "$FAIL_ON_ANY_ERROR" == "true" ]]; then
            return $overall_exit
        fi
    fi
    
    if ! run_bandit_analysis; then
        overall_exit=2
        if [[ "$FAIL_ON_ANY_ERROR" == "true" ]]; then
            return $overall_exit
        fi
    fi
    
    if ! run_safety_analysis; then
        overall_exit=2
        if [[ "$FAIL_ON_ANY_ERROR" == "true" ]]; then
            return $overall_exit
        fi
    fi
    
    return $overall_exit
}

#######################################################################
# Main Execution Functions
#######################################################################

# Display help information
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Code Quality Validation Script for Flask Application Migration

This script executes comprehensive static analysis using flake8, mypy, and bandit
with zero-tolerance error policy and enterprise security compliance enforcement.

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output with detailed error information
    -q, --quiet             Enable quiet mode with minimal output
    -s, --sequential        Run quality checks sequentially instead of parallel
    --no-strict             Disable strict mode (allow warnings)
    --no-reports            Disable report generation
    --flake8-only           Run only flake8 analysis
    --mypy-only            Run only mypy analysis
    --bandit-only          Run only bandit analysis
    --safety-only          Run only safety analysis

ENVIRONMENT VARIABLES:
    QUALITY_STRICT_MODE     Set to 'false' to disable strict mode
    QUALITY_PARALLEL        Set to 'false' to disable parallel execution
    QUALITY_REPORTS_DIR     Override default reports directory

EXAMPLES:
    $0                      Run all quality checks with default settings
    $0 -v                   Run with verbose output
    $0 --flake8-only -v     Run only flake8 with verbose output
    $0 --no-strict          Run in non-strict mode allowing warnings

EXIT CODES:
    0 - All quality checks passed
    1 - Static analysis failures (flake8/mypy)
    2 - Security analysis failures (bandit/safety)
    3 - Configuration or dependency errors
    4 - Script execution errors

For more information, see Section 8.5.1 of the technical specification.
EOF
}

# Parse command line arguments
parse_arguments() {
    local run_specific_tool=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                QUIET=false
                shift
                ;;
            -q|--quiet)
                QUIET=true
                VERBOSE=false
                shift
                ;;
            -s|--sequential)
                PARALLEL_EXECUTION=false
                shift
                ;;
            --no-strict)
                STRICT_MODE=false
                FAIL_ON_ANY_ERROR=false
                shift
                ;;
            --no-reports)
                GENERATE_REPORTS=false
                shift
                ;;
            --flake8-only)
                run_specific_tool="flake8"
                shift
                ;;
            --mypy-only)
                run_specific_tool="mypy"
                shift
                ;;
            --bandit-only)
                run_specific_tool="bandit"
                shift
                ;;
            --safety-only)
                run_specific_tool="safety"
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                log "INFO" "Use --help for usage information"
                exit 4
                ;;
        esac
    done
    
    # Apply environment variable overrides
    if [[ "${QUALITY_STRICT_MODE:-}" == "false" ]]; then
        STRICT_MODE=false
        FAIL_ON_ANY_ERROR=false
    fi
    
    if [[ "${QUALITY_PARALLEL:-}" == "false" ]]; then
        PARALLEL_EXECUTION=false
    fi
    
    if [[ -n "${QUALITY_REPORTS_DIR:-}" ]]; then
        QUALITY_REPORTS_DIR="$QUALITY_REPORTS_DIR"
    fi
    
    # Handle specific tool execution
    if [[ -n "$run_specific_tool" ]]; then
        PARALLEL_EXECUTION=false
        case "$run_specific_tool" in
            "flake8")
                RUN_SPECIFIC_TOOL="flake8"
                ;;
            "mypy")
                RUN_SPECIFIC_TOOL="mypy"
                ;;
            "bandit")
                RUN_SPECIFIC_TOOL="bandit"
                ;;
            "safety")
                RUN_SPECIFIC_TOOL="safety"
                ;;
        esac
    fi
}

# Main execution function
main() {
    local start_time=$(date +%s)
    
    # Initialize summary file
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        echo "# Code Quality Analysis Summary - $(date)" > "${QUALITY_REPORTS_DIR}/summary.txt"
    fi
    
    log "INFO" "Starting code quality validation (version $SCRIPT_VERSION)"
    log "INFO" "Project root: $PROJECT_ROOT"
    log "INFO" "Configuration: Strict=$STRICT_MODE, Parallel=$PARALLEL_EXECUTION, Reports=$GENERATE_REPORTS"
    
    # Validate dependencies and configuration
    validate_dependencies
    validate_configuration
    
    local exit_code=0
    
    # Execute quality checks based on mode
    if [[ -n "${RUN_SPECIFIC_TOOL:-}" ]]; then
        log "INFO" "Running specific tool: $RUN_SPECIFIC_TOOL"
        case "$RUN_SPECIFIC_TOOL" in
            "flake8")
                run_flake8_analysis || exit_code=$?
                ;;
            "mypy")
                run_mypy_analysis || exit_code=$?
                ;;
            "bandit")
                run_bandit_analysis || exit_code=$?
                ;;
            "safety")
                run_safety_analysis || exit_code=$?
                ;;
        esac
    elif [[ "$PARALLEL_EXECUTION" == "true" ]]; then
        run_parallel_quality_checks || exit_code=$?
    else
        run_sequential_quality_checks || exit_code=$?
    fi
    
    # Generate comprehensive report
    if [[ "$GENERATE_REPORTS" == "true" ]]; then
        generate_quality_report
    fi
    
    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Final status reporting
    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "All quality checks passed successfully (${duration}s)"
        log "INFO" "Code quality validation completed with enterprise compliance"
    else
        log "ERROR" "Quality validation failed with exit code: $exit_code (${duration}s)"
        log "ERROR" "Review quality reports in: $QUALITY_REPORTS_DIR"
        
        if [[ "$STRICT_MODE" == "true" ]]; then
            log "ERROR" "Strict mode enabled - all issues must be resolved before deployment"
        fi
    fi
    
    exit $exit_code
}

#######################################################################
# Script Entry Point
#######################################################################

# Ensure we're in the correct directory
cd "$PROJECT_ROOT"

# Parse command line arguments
parse_arguments "$@"

# Execute main function
main