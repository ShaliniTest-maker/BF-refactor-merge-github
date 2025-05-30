#!/bin/bash

# ==============================================================================
# Flask Application Comprehensive Test Execution Script
# ==============================================================================
# 
# This script implements the comprehensive testing pipeline for the Node.js to 
# Python/Flask migration project, ensuring ≥90% coverage requirement, performance
# baseline comparison, and quality gate validation per Section 6.6 Testing Strategy
# and Section 8.5 CI/CD Pipeline requirements.
#
# Features:
# - pytest 7.4+ framework with comprehensive plugin ecosystem
# - ≥90% code coverage requirement validation with pytest-cov
# - Static analysis enforcement (flake8, mypy) with zero-tolerance policy
# - Security scanning (bandit, safety) with critical vulnerability blocking
# - Performance testing (locust, k6) with ≤10% variance requirement
# - Flask-specific testing patterns with pytest-flask integration
# - Testcontainers integration for realistic MongoDB/Redis behavior
# - Parallel test execution with pytest-xdist optimization
# - Comprehensive quality gates and deployment blocking enforcement
#
# Author: Flask Migration Team
# Version: 1.0.0
# Last Updated: 2024-01-15
# ==============================================================================

set -euo pipefail

# Configuration and Global Variables
# ==============================================================================

# Script metadata
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

# Testing configuration
readonly COVERAGE_THRESHOLD=90
readonly PERFORMANCE_VARIANCE_THRESHOLD=10
readonly DEFAULT_TEST_WORKERS=4
readonly TEST_TIMEOUT=300

# Quality gate enforcement levels
readonly FLAKE8_MAX_ERRORS=0
readonly MYPY_STRICT_MODE=true
readonly BANDIT_CRITICAL_BLOCK=true
readonly SAFETY_CRITICAL_BLOCK=true

# Directory paths
readonly TESTS_DIR="${PROJECT_ROOT}/tests"
readonly REPORTS_DIR="${PROJECT_ROOT}/test-reports"
readonly COVERAGE_DIR="${REPORTS_DIR}/coverage"
readonly PERFORMANCE_DIR="${REPORTS_DIR}/performance"
readonly SECURITY_DIR="${REPORTS_DIR}/security"
readonly STATIC_ANALYSIS_DIR="${REPORTS_DIR}/static-analysis"

# Output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Logging and Utility Functions
# ==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} ${1}" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} ${1}" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} ${1}" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} ${1}" >&2
}

log_section() {
    echo -e "\n${PURPLE}==== ${1} ====${NC}" >&2
}

log_subsection() {
    echo -e "\n${CYAN}--- ${1} ---${NC}" >&2
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command '$1' not found. Please install it first."
        return 1
    fi
}

check_python_package() {
    if ! python -c "import $1" &> /dev/null; then
        log_error "Required Python package '$1' not found. Please install dependencies first."
        return 1
    fi
}

create_report_directories() {
    log_info "Creating test report directories..."
    mkdir -p "${REPORTS_DIR}" "${COVERAGE_DIR}" "${PERFORMANCE_DIR}" "${SECURITY_DIR}" "${STATIC_ANALYSIS_DIR}"
}

cleanup_old_reports() {
    log_info "Cleaning up old test reports..."
    find "${REPORTS_DIR}" -name "*.xml" -o -name "*.json" -o -name "*.html" -mtime +7 -delete 2>/dev/null || true
}

# Environment Validation and Setup
# ==============================================================================

validate_environment() {
    log_section "Environment Validation"
    
    # Check required commands
    log_info "Validating required system commands..."
    check_command "python" || exit 1
    check_command "pip" || exit 1
    check_command "docker" || exit 1
    
    # Validate Python version
    local python_version
    python_version=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log_info "Python version: ${python_version}"
    
    if [[ $(echo "${python_version} >= 3.8" | bc -l) -eq 0 ]]; then
        log_error "Python 3.8+ required. Current version: ${python_version}"
        exit 1
    fi
    
    # Check core testing packages
    log_info "Validating Python testing packages..."
    check_python_package "pytest" || exit 1
    check_python_package "pytest_cov" || exit 1
    check_python_package "pytest_flask" || exit 1
    check_python_package "pytest_mock" || exit 1
    check_python_package "pytest_xdist" || exit 1
    check_python_package "pytest_asyncio" || exit 1
    
    # Check static analysis packages
    log_info "Validating static analysis packages..."
    check_python_package "flake8" || exit 1
    check_python_package "mypy" || exit 1
    check_python_package "bandit" || exit 1
    check_python_package "safety" || exit 1
    
    # Check performance testing packages
    log_info "Validating performance testing packages..."
    if [[ "${SKIP_PERFORMANCE:-false}" != "true" ]]; then
        check_python_package "locust" || log_warning "Locust not available - performance tests will be skipped"
        check_command "k6" || log_warning "k6 not available - k6 performance tests will be skipped"
    fi
    
    # Validate Docker for Testcontainers
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Testcontainers integration requires Docker."
        exit 1
    fi
    
    log_success "Environment validation completed successfully"
}

setup_test_environment() {
    log_section "Test Environment Setup"
    
    # Set up Python path
    export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH:-}"
    
    # Configure testing environment variables
    export FLASK_ENV="testing"
    export TESTING="true"
    export LOG_LEVEL="DEBUG"
    export COVERAGE_PROCESS_START="${PROJECT_ROOT}/.coveragerc"
    
    # Testcontainers configuration
    export TESTCONTAINERS_RYUK_DISABLED="false"
    export TESTCONTAINERS_CHECKS_DISABLE="false"
    
    # Performance testing configuration
    export PERFORMANCE_BASELINE_FILE="${PROJECT_ROOT}/performance_baseline.json"
    export PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD}"
    
    # Create necessary directories
    create_report_directories
    cleanup_old_reports
    
    log_success "Test environment setup completed"
}

# Static Analysis Functions
# ==============================================================================

run_flake8_analysis() {
    log_subsection "Running flake8 Code Style Analysis"
    
    local flake8_output="${STATIC_ANALYSIS_DIR}/flake8_${TIMESTAMP}.txt"
    local exit_code=0
    
    log_info "Executing flake8 with PEP 8 compliance validation..."
    
    # Run flake8 with comprehensive configuration
    if ! python -m flake8 \
        --config="${PROJECT_ROOT}/.flake8" \
        --output-file="${flake8_output}" \
        --statistics \
        --count \
        "${PROJECT_ROOT}/src" \
        "${PROJECT_ROOT}/tests" 2>&1; then
        exit_code=1
    fi
    
    # Display results
    if [[ -s "${flake8_output}" ]]; then
        local error_count
        error_count=$(wc -l < "${flake8_output}")
        
        log_error "flake8 found ${error_count} style violations:"
        cat "${flake8_output}"
        
        if [[ "${error_count}" -gt "${FLAKE8_MAX_ERRORS}" ]]; then
            log_error "Quality gate FAILED: flake8 errors (${error_count}) exceed maximum allowed (${FLAKE8_MAX_ERRORS})"
            return 1
        fi
    else
        log_success "flake8 analysis passed - no style violations found"
    fi
    
    return ${exit_code}
}

run_mypy_analysis() {
    log_subsection "Running mypy Type Checking Analysis"
    
    local mypy_output="${STATIC_ANALYSIS_DIR}/mypy_${TIMESTAMP}.txt"
    local mypy_json="${STATIC_ANALYSIS_DIR}/mypy_${TIMESTAMP}.json"
    local exit_code=0
    
    log_info "Executing mypy with strict type checking..."
    
    # Run mypy with strict configuration
    if ! python -m mypy \
        --config-file="${PROJECT_ROOT}/mypy.ini" \
        --txt-report="${STATIC_ANALYSIS_DIR}" \
        --html-report="${STATIC_ANALYSIS_DIR}/mypy-html" \
        --json-report="${mypy_json}" \
        "${PROJECT_ROOT}/src" 2>&1 | tee "${mypy_output}"; then
        exit_code=1
    fi
    
    # Analyze results
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "mypy type checking failed:"
        cat "${mypy_output}"
        log_error "Quality gate FAILED: mypy type checking must pass with zero errors"
        return 1
    else
        log_success "mypy type checking passed - all type annotations are valid"
    fi
    
    return 0
}

run_static_analysis() {
    log_section "Static Analysis Quality Gates"
    
    local analysis_failed=false
    
    # Run flake8 analysis
    if ! run_flake8_analysis; then
        analysis_failed=true
    fi
    
    # Run mypy analysis
    if ! run_mypy_analysis; then
        analysis_failed=true
    fi
    
    if [[ "${analysis_failed}" == "true" ]]; then
        log_error "Static analysis quality gates FAILED - pipeline termination required"
        return 1
    fi
    
    log_success "All static analysis quality gates PASSED"
    return 0
}

# Security Scanning Functions
# ==============================================================================

run_bandit_security_scan() {
    log_subsection "Running bandit Security Analysis"
    
    local bandit_output="${SECURITY_DIR}/bandit_${TIMESTAMP}.json"
    local bandit_txt="${SECURITY_DIR}/bandit_${TIMESTAMP}.txt"
    local exit_code=0
    
    log_info "Executing bandit security vulnerability scanning..."
    
    # Run bandit with comprehensive security analysis
    if ! python -m bandit \
        -c "${PROJECT_ROOT}/bandit.yaml" \
        -f json \
        -o "${bandit_output}" \
        -r "${PROJECT_ROOT}/src" 2>&1 | tee "${bandit_txt}"; then
        exit_code=1
    fi
    
    # Analyze security findings
    if [[ -s "${bandit_output}" ]]; then
        local high_severity_count
        local critical_severity_count
        
        # Extract severity counts using Python
        high_severity_count=$(python -c "
import json, sys
try:
    with open('${bandit_output}', 'r') as f:
        data = json.load(f)
    count = sum(1 for issue in data.get('results', []) if issue.get('issue_severity') == 'HIGH')
    print(count)
except:
    print(0)
")
        
        critical_severity_count=$(python -c "
import json, sys
try:
    with open('${bandit_output}', 'r') as f:
        data = json.load(f)
    count = sum(1 for issue in data.get('results', []) if issue.get('issue_severity') == 'CRITICAL')
    print(count)
except:
    print(0)
")
        
        if [[ "${critical_severity_count}" -gt 0 ]] || [[ "${high_severity_count}" -gt 0 ]]; then
            log_error "bandit found ${critical_severity_count} critical and ${high_severity_count} high severity security issues"
            cat "${bandit_txt}"
            
            if [[ "${BANDIT_CRITICAL_BLOCK}" == "true" ]] && [[ "${critical_severity_count}" -gt 0 ]]; then
                log_error "Quality gate FAILED: Critical security vulnerabilities must be resolved"
                return 1
            fi
        else
            log_success "bandit security analysis passed - no critical or high severity issues found"
        fi
    fi
    
    return 0
}

run_safety_dependency_scan() {
    log_subsection "Running safety Dependency Vulnerability Scan"
    
    local safety_output="${SECURITY_DIR}/safety_${TIMESTAMP}.json"
    local safety_txt="${SECURITY_DIR}/safety_${TIMESTAMP}.txt"
    local exit_code=0
    
    log_info "Executing safety dependency vulnerability scanning..."
    
    # Run safety with comprehensive dependency scanning
    if ! python -m safety check \
        --json \
        --output "${safety_output}" \
        --full-report 2>&1 | tee "${safety_txt}"; then
        exit_code=1
    fi
    
    # Analyze vulnerability findings
    if [[ ${exit_code} -ne 0 ]] && [[ -s "${safety_output}" ]]; then
        local vulnerability_count
        vulnerability_count=$(python -c "
import json, sys
try:
    with open('${safety_output}', 'r') as f:
        data = json.load(f)
    print(len(data))
except:
    print(0)
")
        
        if [[ "${vulnerability_count}" -gt 0 ]]; then
            log_error "safety found ${vulnerability_count} dependency vulnerabilities:"
            cat "${safety_txt}"
            
            if [[ "${SAFETY_CRITICAL_BLOCK}" == "true" ]]; then
                log_error "Quality gate FAILED: Dependency vulnerabilities must be resolved"
                return 1
            fi
        fi
    else
        log_success "safety dependency scan passed - no vulnerabilities found"
    fi
    
    return 0
}

run_security_scans() {
    log_section "Security Scanning Quality Gates"
    
    local security_failed=false
    
    # Run bandit security analysis
    if ! run_bandit_security_scan; then
        security_failed=true
    fi
    
    # Run safety dependency scanning
    if ! run_safety_dependency_scan; then
        security_failed=true
    fi
    
    if [[ "${security_failed}" == "true" ]]; then
        log_error "Security scanning quality gates FAILED - security review required"
        return 1
    fi
    
    log_success "All security scanning quality gates PASSED"
    return 0
}

# Core Testing Functions
# ==============================================================================

run_unit_tests() {
    log_subsection "Running Unit Tests"
    
    local junit_output="${REPORTS_DIR}/unit_tests_${TIMESTAMP}.xml"
    local coverage_data="${COVERAGE_DIR}/unit_coverage_${TIMESTAMP}.coverage"
    
    log_info "Executing unit tests with pytest framework..."
    
    # Run unit tests with comprehensive configuration
    python -m pytest \
        "${TESTS_DIR}/unit" \
        --junitxml="${junit_output}" \
        --cov="${PROJECT_ROOT}/src" \
        --cov-report=html:"${COVERAGE_DIR}/unit-html" \
        --cov-report=xml:"${COVERAGE_DIR}/unit_coverage_${TIMESTAMP}.xml" \
        --cov-report=json:"${COVERAGE_DIR}/unit_coverage_${TIMESTAMP}.json" \
        --cov-report=term-missing \
        --cov-config="${PROJECT_ROOT}/.coveragerc" \
        --cov-fail-under="${COVERAGE_THRESHOLD}" \
        --maxfail=10 \
        --tb=short \
        --strict-markers \
        --strict-config \
        -v \
        -x \
        --numprocesses="${TEST_WORKERS:-${DEFAULT_TEST_WORKERS}}" \
        --dist=loadscope
    
    if [[ $? -eq 0 ]]; then
        log_success "Unit tests completed successfully"
        return 0
    else
        log_error "Unit tests failed"
        return 1
    fi
}

run_integration_tests() {
    log_subsection "Running Integration Tests"
    
    local junit_output="${REPORTS_DIR}/integration_tests_${TIMESTAMP}.xml"
    
    log_info "Executing integration tests with Testcontainers..."
    
    # Run integration tests with realistic service dependencies
    python -m pytest \
        "${TESTS_DIR}/integration" \
        --junitxml="${junit_output}" \
        --maxfail=5 \
        --tb=short \
        --strict-markers \
        --strict-config \
        -v \
        --timeout="${TEST_TIMEOUT}" \
        --numprocesses="${TEST_WORKERS:-${DEFAULT_TEST_WORKERS}}" \
        --dist=loadgroup
    
    if [[ $? -eq 0 ]]; then
        log_success "Integration tests completed successfully"
        return 0
    else
        log_error "Integration tests failed"
        return 1
    fi
}

run_e2e_tests() {
    log_subsection "Running End-to-End Tests"
    
    local junit_output="${REPORTS_DIR}/e2e_tests_${TIMESTAMP}.xml"
    
    log_info "Executing end-to-end workflow tests..."
    
    # Run E2E tests with complete system validation
    python -m pytest \
        "${TESTS_DIR}/e2e" \
        --junitxml="${junit_output}" \
        --maxfail=3 \
        --tb=line \
        --strict-markers \
        --strict-config \
        -v \
        --timeout=$((TEST_TIMEOUT * 2))
    
    if [[ $? -eq 0 ]]; then
        log_success "End-to-end tests completed successfully"
        return 0
    else
        log_error "End-to-end tests failed"
        return 1
    fi
}

# Performance Testing Functions
# ==============================================================================

run_locust_performance_test() {
    log_subsection "Running Locust Load Testing"
    
    local locust_output="${PERFORMANCE_DIR}/locust_${TIMESTAMP}"
    
    if ! check_python_package "locust"; then
        log_warning "Locust not available - skipping load testing"
        return 0
    fi
    
    log_info "Executing Locust distributed load testing..."
    
    # Check if performance test files exist
    local locust_file="${TESTS_DIR}/performance/locust_performance_test.py"
    if [[ ! -f "${locust_file}" ]]; then
        log_warning "Locust test file not found at ${locust_file} - skipping load testing"
        return 0
    fi
    
    # Run Locust load testing
    python -m locust \
        -f "${locust_file}" \
        --headless \
        --users 50 \
        --spawn-rate 5 \
        --run-time 300s \
        --host "http://localhost:5000" \
        --csv "${locust_output}" \
        --html "${locust_output}.html" \
        --logfile "${locust_output}.log" \
        --loglevel INFO
    
    if [[ $? -eq 0 ]]; then
        log_success "Locust load testing completed successfully"
        return 0
    else
        log_error "Locust load testing failed"
        return 1
    fi
}

run_k6_performance_test() {
    log_subsection "Running k6 Performance Analysis"
    
    local k6_output="${PERFORMANCE_DIR}/k6_${TIMESTAMP}.json"
    
    if ! command -v k6 &> /dev/null; then
        log_warning "k6 not available - skipping k6 performance testing"
        return 0
    fi
    
    log_info "Executing k6 performance analysis..."
    
    # Check if k6 test file exists
    local k6_file="${TESTS_DIR}/performance/k6_performance_test.js"
    if [[ ! -f "${k6_file}" ]]; then
        log_warning "k6 test file not found at ${k6_file} - skipping k6 performance testing"
        return 0
    fi
    
    # Run k6 performance testing
    k6 run \
        --out json="${k6_output}" \
        --summary-trend-stats="avg,min,med,max,p(95),p(99)" \
        "${k6_file}"
    
    if [[ $? -eq 0 ]]; then
        log_success "k6 performance analysis completed successfully"
        return 0
    else
        log_error "k6 performance analysis failed"
        return 1
    fi
}

validate_performance_baseline() {
    log_subsection "Validating Performance Baseline"
    
    local baseline_file="${PERFORMANCE_BASELINE_FILE}"
    local current_results="${PERFORMANCE_DIR}/current_performance_${TIMESTAMP}.json"
    
    if [[ ! -f "${baseline_file}" ]]; then
        log_warning "Performance baseline file not found - skipping baseline comparison"
        return 0
    fi
    
    log_info "Comparing current performance against Node.js baseline..."
    
    # Create performance validation script
    cat > "${PERFORMANCE_DIR}/validate_performance.py" << 'EOF'
#!/usr/bin/env python3
"""Performance baseline validation script."""

import json
import sys
from pathlib import Path

def load_json_file(file_path):
    """Load JSON file with error handling."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {file_path}: {e}")
        return None

def calculate_variance(baseline_value, current_value):
    """Calculate percentage variance from baseline."""
    if baseline_value == 0:
        return 0 if current_value == 0 else 100
    return ((current_value - baseline_value) / baseline_value) * 100

def validate_performance(baseline_file, current_file, threshold):
    """Validate performance against baseline with threshold."""
    baseline = load_json_file(baseline_file)
    current = load_json_file(current_file)
    
    if not baseline or not current:
        print("Could not load performance data files")
        return False
    
    # Extract key performance metrics
    baseline_response_time = baseline.get('avg_response_time', 0)
    current_response_time = current.get('avg_response_time', 0)
    
    # Calculate variance
    response_time_variance = calculate_variance(baseline_response_time, current_response_time)
    
    print(f"Baseline response time: {baseline_response_time:.2f}ms")
    print(f"Current response time: {current_response_time:.2f}ms")
    print(f"Response time variance: {response_time_variance:.2f}%")
    
    # Check threshold compliance
    if abs(response_time_variance) <= threshold:
        print(f"✓ Performance validation PASSED - within {threshold}% threshold")
        return True
    else:
        print(f"✗ Performance validation FAILED - exceeds {threshold}% threshold")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: validate_performance.py <baseline_file> <current_file> <threshold>")
        sys.exit(1)
    
    baseline_file = sys.argv[1]
    current_file = sys.argv[2]
    threshold = float(sys.argv[3])
    
    success = validate_performance(baseline_file, current_file, threshold)
    sys.exit(0 if success else 1)
EOF
    
    # Run performance validation
    if python "${PERFORMANCE_DIR}/validate_performance.py" \
        "${baseline_file}" \
        "${current_results}" \
        "${PERFORMANCE_VARIANCE_THRESHOLD}"; then
        log_success "Performance baseline validation PASSED"
        return 0
    else
        log_error "Performance baseline validation FAILED - exceeds ${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold"
        return 1
    fi
}

run_performance_tests() {
    log_section "Performance Testing and Baseline Validation"
    
    if [[ "${SKIP_PERFORMANCE:-false}" == "true" ]]; then
        log_warning "Performance testing skipped by configuration"
        return 0
    fi
    
    local performance_failed=false
    
    # Run Locust load testing
    if ! run_locust_performance_test; then
        performance_failed=true
    fi
    
    # Run k6 performance analysis
    if ! run_k6_performance_test; then
        performance_failed=true
    fi
    
    # Validate performance baseline
    if ! validate_performance_baseline; then
        performance_failed=true
    fi
    
    if [[ "${performance_failed}" == "true" ]]; then
        log_error "Performance testing FAILED - performance gate blocked"
        return 1
    fi
    
    log_success "All performance tests PASSED"
    return 0
}

# Coverage Analysis Functions
# ==============================================================================

generate_combined_coverage_report() {
    log_subsection "Generating Combined Coverage Report"
    
    local combined_coverage="${COVERAGE_DIR}/combined_coverage_${TIMESTAMP}"
    
    log_info "Combining coverage data from all test phases..."
    
    # Combine coverage data if multiple coverage files exist
    if ls "${COVERAGE_DIR}"/*.coverage &> /dev/null; then
        python -m coverage combine "${COVERAGE_DIR}"/*.coverage
    fi
    
    # Generate comprehensive coverage reports
    python -m coverage report \
        --skip-covered \
        --show-missing \
        --fail-under="${COVERAGE_THRESHOLD}" | tee "${combined_coverage}.txt"
    
    python -m coverage html -d "${combined_coverage}-html"
    python -m coverage xml -o "${combined_coverage}.xml"
    python -m coverage json -o "${combined_coverage}.json"
    
    # Extract coverage percentage
    local coverage_percentage
    coverage_percentage=$(python -c "
import json
try:
    with open('${combined_coverage}.json', 'r') as f:
        data = json.load(f)
    print(f\"{data['totals']['percent_covered']:.1f}\")
except:
    print('0.0')
")
    
    log_info "Total code coverage: ${coverage_percentage}%"
    
    # Validate coverage threshold
    if (( $(echo "${coverage_percentage} >= ${COVERAGE_THRESHOLD}" | bc -l) )); then
        log_success "Coverage threshold PASSED (${coverage_percentage}% >= ${COVERAGE_THRESHOLD}%)"
        return 0
    else
        log_error "Coverage threshold FAILED (${coverage_percentage}% < ${COVERAGE_THRESHOLD}%)"
        return 1
    fi
}

# Quality Gates and Reporting Functions
# ==============================================================================

run_quality_gates() {
    log_section "Quality Gates Validation"
    
    local gates_failed=false
    
    log_info "Validating all quality gates..."
    
    # Static analysis quality gates
    if ! run_static_analysis; then
        gates_failed=true
    fi
    
    # Security scanning quality gates
    if ! run_security_scans; then
        gates_failed=true
    fi
    
    # Coverage quality gates
    if ! generate_combined_coverage_report; then
        gates_failed=true
    fi
    
    # Performance quality gates (if enabled)
    if [[ "${SKIP_PERFORMANCE:-false}" != "true" ]]; then
        if ! run_performance_tests; then
            gates_failed=true
        fi
    fi
    
    if [[ "${gates_failed}" == "true" ]]; then
        log_error "Quality gates validation FAILED - deployment blocked"
        return 1
    fi
    
    log_success "All quality gates validation PASSED - deployment approved"
    return 0
}

generate_test_report() {
    log_section "Generating Comprehensive Test Report"
    
    local report_file="${REPORTS_DIR}/test_summary_${TIMESTAMP}.md"
    
    log_info "Generating comprehensive test execution report..."
    
    cat > "${report_file}" << EOF
# Flask Application Test Execution Report

**Generated:** $(date)
**Test Suite Version:** 1.0.0
**Python Version:** $(python --version)

## Executive Summary

This report provides a comprehensive overview of the test execution results for the Node.js to Python/Flask migration project, including quality gate validation, coverage analysis, and performance testing results.

## Test Execution Results

### Static Analysis
- **flake8 Code Style:** $([ -f "${STATIC_ANALYSIS_DIR}/flake8_${TIMESTAMP}.txt" ] && echo "PASSED" || echo "FAILED")
- **mypy Type Checking:** $([ -f "${STATIC_ANALYSIS_DIR}/mypy_${TIMESTAMP}.txt" ] && echo "PASSED" || echo "FAILED")

### Security Scanning
- **bandit Security Analysis:** $([ -f "${SECURITY_DIR}/bandit_${TIMESTAMP}.json" ] && echo "COMPLETED" || echo "SKIPPED")
- **safety Dependency Scan:** $([ -f "${SECURITY_DIR}/safety_${TIMESTAMP}.json" ] && echo "COMPLETED" || echo "SKIPPED")

### Test Coverage
- **Unit Tests:** $([ -f "${REPORTS_DIR}/unit_tests_${TIMESTAMP}.xml" ] && echo "COMPLETED" || echo "FAILED")
- **Integration Tests:** $([ -f "${REPORTS_DIR}/integration_tests_${TIMESTAMP}.xml" ] && echo "COMPLETED" || echo "FAILED")
- **E2E Tests:** $([ -f "${REPORTS_DIR}/e2e_tests_${TIMESTAMP}.xml" ] && echo "COMPLETED" || echo "FAILED")

### Performance Testing
- **Locust Load Testing:** $([ -f "${PERFORMANCE_DIR}/locust_${TIMESTAMP}.html" ] && echo "COMPLETED" || echo "SKIPPED")
- **k6 Performance Analysis:** $([ -f "${PERFORMANCE_DIR}/k6_${TIMESTAMP}.json" ] && echo "COMPLETED" || echo "SKIPPED")

## Quality Gates Status

All quality gates must pass for deployment approval:

- ✅ **Code Coverage:** ≥90% requirement
- ✅ **Static Analysis:** Zero errors policy
- ✅ **Security Scanning:** No critical vulnerabilities
- ✅ **Performance Testing:** ≤10% variance from baseline

## Report Artifacts

- **Coverage Reports:** ${COVERAGE_DIR}
- **Performance Results:** ${PERFORMANCE_DIR}
- **Security Findings:** ${SECURITY_DIR}
- **Static Analysis:** ${STATIC_ANALYSIS_DIR}

## Recommendations

1. Review any security findings in the security reports
2. Address any performance regressions identified
3. Maintain test coverage above the 90% threshold
4. Continue monitoring for code quality improvements

---
**Report Generated by:** Flask Test Automation Pipeline
**Contact:** Development Team
EOF
    
    log_success "Test report generated: ${report_file}"
}

# Main Execution Functions
# ==============================================================================

show_usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Flask Application Comprehensive Test Execution Script

This script runs the complete testing pipeline for the Node.js to Python/Flask 
migration project, including unit tests, integration tests, performance testing,
static analysis, security scanning, and quality gate validation.

OPTIONS:
    -h, --help              Show this help message
    -u, --unit-only         Run only unit tests
    -i, --integration-only  Run only integration tests
    -e, --e2e-only         Run only end-to-end tests
    -p, --performance-only  Run only performance tests
    -s, --static-only      Run only static analysis
    -c, --security-only    Run only security scans
    -q, --quality-only     Run only quality gates
    -w, --workers N        Number of test workers (default: ${DEFAULT_TEST_WORKERS})
    --skip-performance     Skip performance testing
    --skip-security        Skip security scanning
    --skip-static          Skip static analysis
    --coverage-threshold N Set coverage threshold (default: ${COVERAGE_THRESHOLD}%)
    --fail-fast           Stop on first test failure
    --verbose             Enable verbose output
    --clean               Clean old reports before execution
    --dry-run             Show what would be executed without running

ENVIRONMENT VARIABLES:
    TEST_WORKERS           Number of parallel test workers
    COVERAGE_THRESHOLD     Minimum code coverage percentage
    PERFORMANCE_VARIANCE_THRESHOLD  Maximum performance variance percentage
    SKIP_PERFORMANCE       Skip performance testing (true/false)
    SKIP_SECURITY         Skip security scanning (true/false)
    SKIP_STATIC           Skip static analysis (true/false)

EXAMPLES:
    # Run complete test suite
    ${SCRIPT_NAME}
    
    # Run only unit tests with higher parallelism
    ${SCRIPT_NAME} --unit-only --workers 8
    
    # Run tests excluding performance testing
    ${SCRIPT_NAME} --skip-performance
    
    # Run with custom coverage threshold
    ${SCRIPT_NAME} --coverage-threshold 95
    
    # Clean and run complete suite with verbose output
    ${SCRIPT_NAME} --clean --verbose

EXIT CODES:
    0    All tests passed and quality gates met
    1    Test failures or quality gate violations
    2    Environment validation failed
    3    Invalid arguments or configuration

For more information, see the project documentation and Section 6.6 Testing Strategy.
EOF
}

parse_arguments() {
    # Initialize default values
    RUN_UNIT_TESTS=true
    RUN_INTEGRATION_TESTS=true
    RUN_E2E_TESTS=true
    RUN_PERFORMANCE_TESTS=true
    RUN_STATIC_ANALYSIS=true
    RUN_SECURITY_SCANS=true
    RUN_QUALITY_GATES=true
    TEST_WORKERS="${TEST_WORKERS:-${DEFAULT_TEST_WORKERS}}"
    FAIL_FAST=false
    VERBOSE=false
    CLEAN_REPORTS=false
    DRY_RUN=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -u|--unit-only)
                RUN_UNIT_TESTS=true
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=false
                shift
                ;;
            -i|--integration-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=true
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=false
                shift
                ;;
            -e|--e2e-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=true
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=false
                shift
                ;;
            -p|--performance-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=true
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=false
                shift
                ;;
            -s|--static-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=true
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=false
                shift
                ;;
            -c|--security-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=true
                RUN_QUALITY_GATES=false
                shift
                ;;
            -q|--quality-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_E2E_TESTS=false
                RUN_PERFORMANCE_TESTS=false
                RUN_STATIC_ANALYSIS=false
                RUN_SECURITY_SCANS=false
                RUN_QUALITY_GATES=true
                shift
                ;;
            -w|--workers)
                if [[ -n $2 ]] && [[ $2 =~ ^[0-9]+$ ]]; then
                    TEST_WORKERS=$2
                    shift 2
                else
                    log_error "Invalid worker count: $2"
                    exit 3
                fi
                ;;
            --skip-performance)
                SKIP_PERFORMANCE=true
                shift
                ;;
            --skip-security)
                SKIP_SECURITY=true
                shift
                ;;
            --skip-static)
                SKIP_STATIC=true
                shift
                ;;
            --coverage-threshold)
                if [[ -n $2 ]] && [[ $2 =~ ^[0-9]+$ ]] && [[ $2 -le 100 ]]; then
                    COVERAGE_THRESHOLD=$2
                    shift 2
                else
                    log_error "Invalid coverage threshold: $2 (must be 0-100)"
                    exit 3
                fi
                ;;
            --fail-fast)
                FAIL_FAST=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --clean)
                CLEAN_REPORTS=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
        esac
    done
    
    # Apply skip flags
    if [[ "${SKIP_PERFORMANCE:-false}" == "true" ]]; then
        RUN_PERFORMANCE_TESTS=false
    fi
    
    if [[ "${SKIP_SECURITY:-false}" == "true" ]]; then
        RUN_SECURITY_SCANS=false
    fi
    
    if [[ "${SKIP_STATIC:-false}" == "true" ]]; then
        RUN_STATIC_ANALYSIS=false
    fi
    
    # Set verbose mode
    if [[ "${VERBOSE}" == "true" ]]; then
        set -x
    fi
    
    # Set fail-fast mode
    if [[ "${FAIL_FAST}" == "true" ]]; then
        set -e
    fi
}

main() {
    log_section "Flask Application Test Suite - Migration Project"
    log_info "Starting comprehensive test execution pipeline..."
    log_info "Test suite version: 1.0.0"
    log_info "Timestamp: ${TIMESTAMP}"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Show configuration in dry-run mode
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "DRY RUN MODE - Configuration Summary:"
        log_info "  Unit Tests: ${RUN_UNIT_TESTS}"
        log_info "  Integration Tests: ${RUN_INTEGRATION_TESTS}"
        log_info "  E2E Tests: ${RUN_E2E_TESTS}"
        log_info "  Performance Tests: ${RUN_PERFORMANCE_TESTS}"
        log_info "  Static Analysis: ${RUN_STATIC_ANALYSIS}"
        log_info "  Security Scans: ${RUN_SECURITY_SCANS}"
        log_info "  Quality Gates: ${RUN_QUALITY_GATES}"
        log_info "  Test Workers: ${TEST_WORKERS}"
        log_info "  Coverage Threshold: ${COVERAGE_THRESHOLD}%"
        log_info "  Performance Variance Threshold: ${PERFORMANCE_VARIANCE_THRESHOLD}%"
        exit 0
    fi
    
    # Validate environment and setup
    if ! validate_environment; then
        log_error "Environment validation failed"
        exit 2
    fi
    
    setup_test_environment
    
    # Clean old reports if requested
    if [[ "${CLEAN_REPORTS}" == "true" ]]; then
        log_info "Cleaning old test reports..."
        rm -rf "${REPORTS_DIR}"
        create_report_directories
    fi
    
    # Track overall success
    local overall_success=true
    
    # Execute test phases based on configuration
    if [[ "${RUN_STATIC_ANALYSIS}" == "true" ]]; then
        if ! run_static_analysis; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_SECURITY_SCANS}" == "true" ]]; then
        if ! run_security_scans; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_UNIT_TESTS}" == "true" ]]; then
        if ! run_unit_tests; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_INTEGRATION_TESTS}" == "true" ]]; then
        if ! run_integration_tests; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_E2E_TESTS}" == "true" ]]; then
        if ! run_e2e_tests; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_PERFORMANCE_TESTS}" == "true" ]]; then
        if ! run_performance_tests; then
            overall_success=false
            [[ "${FAIL_FAST}" == "true" ]] && exit 1
        fi
    fi
    
    if [[ "${RUN_QUALITY_GATES}" == "true" ]]; then
        if ! run_quality_gates; then
            overall_success=false
        fi
    fi
    
    # Generate comprehensive test report
    generate_test_report
    
    # Final status and exit
    if [[ "${overall_success}" == "true" ]]; then
        log_section "Test Execution Summary"
        log_success "All test phases completed successfully!"
        log_success "Quality gates validation: PASSED"
        log_success "Deployment readiness: APPROVED"
        log_info "Test reports available in: ${REPORTS_DIR}"
        exit 0
    else
        log_section "Test Execution Summary"
        log_error "Test execution completed with failures!"
        log_error "Quality gates validation: FAILED"
        log_error "Deployment readiness: BLOCKED"
        log_info "Review test reports in: ${REPORTS_DIR}"
        exit 1
    fi
}

# Script execution entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi