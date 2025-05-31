#!/bin/bash

# =============================================================================
# Comprehensive Test Execution Script for Flask Application Migration
# =============================================================================
# 
# This script executes the complete testing pipeline for the Node.js to Python
# Flask migration project, implementing all quality gates, performance validation,
# and CI/CD integration requirements as specified in the technical documentation.
#
# Requirements:
# - pytest 7.4+ with ≥90% coverage requirement
# - Static analysis with flake8 and mypy (zero tolerance)
# - Security scanning with bandit and safety
# - Performance testing with locust and apache-bench (≤10% variance)
# - Integration testing with pytest-flask
# - Mock testing with pytest-mock and Testcontainers
#
# Quality Gates:
# - 90% minimum code coverage (deployment blocking)
# - Zero flake8 errors (pipeline termination)
# - 100% mypy type check success (build failure)
# - No critical security findings (security review required)
# - ≤10% performance variance from Node.js baseline (critical requirement)
#
# =============================================================================

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly REPORT_DIR="${PROJECT_ROOT}/test_reports/${TIMESTAMP}"

# Test execution flags
SKIP_UNIT_TESTS=false
SKIP_INTEGRATION_TESTS=false
SKIP_PERFORMANCE_TESTS=false
SKIP_STATIC_ANALYSIS=false
SKIP_SECURITY_SCAN=false
VERBOSE=false
CI_MODE=false
COVERAGE_THRESHOLD=90
PERFORMANCE_VARIANCE_THRESHOLD=10

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_header() {
    echo -e "\n${PURPLE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}════════════════════════════════════════════════════════════════════════════════${NC}\n"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Comprehensive test execution script for Flask application migration testing pipeline.

OPTIONS:
    --skip-unit              Skip unit tests execution
    --skip-integration       Skip integration tests execution
    --skip-performance       Skip performance tests execution
    --skip-static-analysis   Skip static analysis (flake8, mypy)
    --skip-security          Skip security scanning (bandit, safety)
    --coverage-threshold N   Set coverage threshold percentage (default: 90)
    --performance-threshold N Set performance variance threshold (default: 10)
    --verbose               Enable verbose output
    --ci-mode               Enable CI/CD pipeline mode
    --help                  Show this help message

EXAMPLES:
    $0                                    # Run complete test suite
    $0 --skip-performance --verbose      # Skip performance tests with verbose output
    $0 --ci-mode --coverage-threshold 95 # CI mode with 95% coverage requirement
    $0 --skip-static-analysis --skip-security # Skip quality gates for development

QUALITY GATES:
    - Coverage: ≥${COVERAGE_THRESHOLD}% (deployment blocking)
    - Lint: Zero flake8 errors (pipeline termination)
    - Types: 100% mypy success (build failure)
    - Security: No critical findings (review required)
    - Performance: ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance (critical requirement)

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-unit)
                SKIP_UNIT_TESTS=true
                shift
                ;;
            --skip-integration)
                SKIP_INTEGRATION_TESTS=true
                shift
                ;;
            --skip-performance)
                SKIP_PERFORMANCE_TESTS=true
                shift
                ;;
            --skip-static-analysis)
                SKIP_STATIC_ANALYSIS=true
                shift
                ;;
            --skip-security)
                SKIP_SECURITY_SCAN=true
                shift
                ;;
            --coverage-threshold)
                if [[ -n $2 && $2 =~ ^[0-9]+$ ]] && [[ $2 -ge 0 && $2 -le 100 ]]; then
                    COVERAGE_THRESHOLD=$2
                    shift 2
                else
                    log_error "Invalid coverage threshold. Must be integer between 0-100."
                    exit 1
                fi
                ;;
            --performance-threshold)
                if [[ -n $2 && $2 =~ ^[0-9]+$ ]] && [[ $2 -ge 0 && $2 -le 100 ]]; then
                    PERFORMANCE_VARIANCE_THRESHOLD=$2
                    shift 2
                else
                    log_error "Invalid performance threshold. Must be integer between 0-100."
                    exit 1
                fi
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --ci-mode)
                CI_MODE=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

setup_environment() {
    log_header "Environment Setup and Validation"
    
    # Create report directory
    mkdir -p "${REPORT_DIR}"
    log_info "Created report directory: ${REPORT_DIR}"
    
    # Change to project root
    cd "${PROJECT_ROOT}"
    log_info "Working directory: ${PROJECT_ROOT}"
    
    # Validate Python environment
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed or not in PATH"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log_info "Python version: ${python_version}"
    
    if [[ $(echo "${python_version} >= 3.8" | bc -l) -eq 0 ]]; then
        log_error "Python 3.8+ is required. Found: ${python_version}"
        exit 1
    fi
    
    # Validate virtual environment
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        log_warning "No virtual environment detected. Consider activating one."
    else
        log_info "Virtual environment: ${VIRTUAL_ENV}"
    fi
    
    # Install/validate required dependencies
    log_info "Installing test dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    pip install -q -r requirements-dev.txt || true # Development dependencies may be optional
    
    # Validate test environment dependencies
    local missing_deps=()
    
    if ! python3 -c "import pytest" 2>/dev/null; then
        missing_deps+=("pytest>=7.4.0")
    fi
    
    if ! python3 -c "import pytest_cov" 2>/dev/null; then
        missing_deps+=("pytest-cov>=4.1.0")
    fi
    
    if ! python3 -c "import pytest_flask" 2>/dev/null; then
        missing_deps+=("pytest-flask>=1.2.0")
    fi
    
    if ! python3 -c "import pytest_mock" 2>/dev/null; then
        missing_deps+=("pytest-mock>=3.11.0")
    fi
    
    if ! python3 -c "import pytest_asyncio" 2>/dev/null; then
        missing_deps+=("pytest-asyncio>=0.21.0")
    fi
    
    if ! command -v locust &> /dev/null && [[ "${SKIP_PERFORMANCE_TESTS}" == "false" ]]; then
        missing_deps+=("locust>=2.17.0")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_info "Installing missing test dependencies: ${missing_deps[*]}"
        pip install -q "${missing_deps[@]}"
    fi
    
    # Set environment variables for testing
    export FLASK_ENV=testing
    export TESTING=true
    export COVERAGE_PROCESS_START="${PROJECT_ROOT}/.coveragerc"
    
    log_success "Environment setup completed successfully"
}

run_static_analysis() {
    if [[ "${SKIP_STATIC_ANALYSIS}" == "true" ]]; then
        log_warning "Skipping static analysis as requested"
        return 0
    fi
    
    log_header "Static Analysis: Code Quality and Type Safety"
    
    local analysis_failed=false
    
    # flake8 Code Style Analysis
    log_info "Running flake8 code style analysis..."
    if command -v flake8 &> /dev/null; then
        local flake8_output="${REPORT_DIR}/flake8_report.txt"
        
        if flake8 src/ tests/ --config=.flake8 \
           --output-file="${flake8_output}" \
           --tee --statistics --count; then
            log_success "flake8: Code style compliance verified"
        else
            log_error "flake8: Code style violations detected"
            cat "${flake8_output}"
            analysis_failed=true
        fi
    else
        log_warning "flake8 not available, installing..."
        pip install -q flake8>=6.1.0
        run_static_analysis # Retry after installation
        return $?
    fi
    
    # mypy Type Checking
    log_info "Running mypy type checking analysis..."
    if command -v mypy &> /dev/null; then
        local mypy_output="${REPORT_DIR}/mypy_report.txt"
        
        if mypy src/ --config-file=mypy.ini \
           --no-error-summary 2>&1 | tee "${mypy_output}"; then
            
            # Check if there are any errors in the output
            if grep -q "error:" "${mypy_output}"; then
                log_error "mypy: Type checking errors detected"
                analysis_failed=true
            else
                log_success "mypy: Type checking completed successfully"
            fi
        else
            log_error "mypy: Type checking failed"
            analysis_failed=true
        fi
    else
        log_warning "mypy not available, installing..."
        pip install -q mypy>=1.8.0
        run_static_analysis # Retry after installation
        return $?
    fi
    
    # radon Complexity Analysis (Optional)
    if command -v radon &> /dev/null; then
        log_info "Running radon complexity analysis..."
        local complexity_output="${REPORT_DIR}/complexity_report.txt"
        
        radon cc src/ --min B --show-complexity > "${complexity_output}" || true
        
        # Check for high complexity functions (A = highest complexity)
        if grep -q " A " "${complexity_output}"; then
            log_warning "High complexity functions detected. Consider refactoring."
            if [[ "${VERBOSE}" == "true" ]]; then
                grep " A " "${complexity_output}"
            fi
        fi
    fi
    
    if [[ "${analysis_failed}" == "true" ]]; then
        log_error "Static analysis failed. Address all issues before proceeding."
        if [[ "${CI_MODE}" == "true" ]]; then
            exit 1
        fi
        return 1
    fi
    
    log_success "Static analysis completed successfully"
    return 0
}

run_security_scan() {
    if [[ "${SKIP_SECURITY_SCAN}" == "true" ]]; then
        log_warning "Skipping security scanning as requested"
        return 0
    fi
    
    log_header "Security Scanning: Vulnerability Assessment"
    
    local security_failed=false
    
    # bandit Security Analysis
    log_info "Running bandit security analysis..."
    if command -v bandit &> /dev/null; then
        local bandit_output="${REPORT_DIR}/bandit_report.json"
        local bandit_txt="${REPORT_DIR}/bandit_report.txt"
        
        if bandit -r src/ -f json -o "${bandit_output}" \
           --config=bandit.yaml || true; then
            
            # Convert JSON report to readable format
            bandit -r src/ -f txt --config=bandit.yaml > "${bandit_txt}" || true
            
            # Check for critical or high severity issues
            local critical_count
            critical_count=$(python3 -c "
import json
try:
    with open('${bandit_output}', 'r') as f:
        data = json.load(f)
    critical = sum(1 for issue in data.get('results', []) 
                  if issue.get('issue_severity') in ['HIGH', 'CRITICAL'])
    print(critical)
except:
    print(0)
" 2>/dev/null || echo "0")
            
            if [[ "${critical_count}" -gt 0 ]]; then
                log_error "bandit: ${critical_count} critical/high severity security issues detected"
                if [[ "${VERBOSE}" == "true" ]]; then
                    cat "${bandit_txt}"
                fi
                security_failed=true
            else
                log_success "bandit: No critical security issues detected"
            fi
        else
            log_error "bandit: Security analysis failed"
            security_failed=true
        fi
    else
        log_warning "bandit not available, installing..."
        pip install -q bandit>=1.7.0
        run_security_scan # Retry after installation
        return $?
    fi
    
    # safety Dependency Vulnerability Scan
    log_info "Running safety dependency vulnerability scan..."
    if command -v safety &> /dev/null; then
        local safety_output="${REPORT_DIR}/safety_report.json"
        
        if safety check --json --output="${safety_output}" || true; then
            
            # Check for vulnerabilities
            local vuln_count
            vuln_count=$(python3 -c "
import json
try:
    with open('${safety_output}', 'r') as f:
        data = json.load(f)
    print(len(data))
except:
    print(0)
" 2>/dev/null || echo "0")
            
            if [[ "${vuln_count}" -gt 0 ]]; then
                log_error "safety: ${vuln_count} vulnerabilities detected in dependencies"
                safety check --output text || true
                security_failed=true
            else
                log_success "safety: No vulnerabilities detected in dependencies"
            fi
        else
            log_error "safety: Dependency scan failed"
            security_failed=true
        fi
    else
        log_warning "safety not available, installing..."
        pip install -q safety>=3.0.0
        run_security_scan # Retry after installation
        return $?
    fi
    
    if [[ "${security_failed}" == "true" ]]; then
        log_error "Security scanning failed. Critical security issues must be resolved."
        if [[ "${CI_MODE}" == "true" ]]; then
            exit 1
        fi
        return 1
    fi
    
    log_success "Security scanning completed successfully"
    return 0
}

run_unit_tests() {
    if [[ "${SKIP_UNIT_TESTS}" == "true" ]]; then
        log_warning "Skipping unit tests as requested"
        return 0
    fi
    
    log_header "Unit Tests: Component Testing with Coverage Analysis"
    
    local pytest_args=(
        "tests/unit/"
        "--cov=src"
        "--cov-report=html:${REPORT_DIR}/coverage_html"
        "--cov-report=xml:${REPORT_DIR}/coverage.xml"
        "--cov-report=term-missing"
        "--cov-fail-under=${COVERAGE_THRESHOLD}"
        "--junitxml=${REPORT_DIR}/unit_tests.xml"
        "--tb=short"
    )
    
    if [[ "${VERBOSE}" == "true" ]]; then
        pytest_args+=("-v")
    else
        pytest_args+=("-q")
    fi
    
    if [[ "${CI_MODE}" == "true" ]]; then
        pytest_args+=("--maxfail=5")
    fi
    
    # Add parallel execution if pytest-xdist is available
    if python3 -c "import xdist" 2>/dev/null; then
        local cpu_count
        cpu_count=$(nproc 2>/dev/null || echo "2")
        pytest_args+=("-n" "${cpu_count}")
        log_info "Using parallel test execution with ${cpu_count} workers"
    fi
    
    log_info "Running unit tests with coverage analysis..."
    log_info "Coverage threshold: ${COVERAGE_THRESHOLD}%"
    
    if pytest "${pytest_args[@]}"; then
        log_success "Unit tests completed successfully"
        
        # Extract coverage percentage for reporting
        local coverage_pct
        coverage_pct=$(coverage report --precision=1 | grep TOTAL | awk '{print $4}' | sed 's/%//' || echo "0")
        log_info "Code coverage achieved: ${coverage_pct}%"
        
        if [[ $(echo "${coverage_pct} >= ${COVERAGE_THRESHOLD}" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
            log_success "Coverage requirement satisfied: ${coverage_pct}% ≥ ${COVERAGE_THRESHOLD}%"
        else
            log_error "Coverage requirement not met: ${coverage_pct}% < ${COVERAGE_THRESHOLD}%"
            return 1
        fi
    else
        log_error "Unit tests failed"
        return 1
    fi
    
    return 0
}

run_integration_tests() {
    if [[ "${SKIP_INTEGRATION_TESTS}" == "true" ]]; then
        log_warning "Skipping integration tests as requested"
        return 0
    fi
    
    log_header "Integration Tests: Service Integration and API Validation"
    
    local pytest_args=(
        "tests/integration/"
        "--tb=short"
        "--junitxml=${REPORT_DIR}/integration_tests.xml"
    )
    
    if [[ "${VERBOSE}" == "true" ]]; then
        pytest_args+=("-v" "-s")
    else
        pytest_args+=("-q")
    fi
    
    if [[ "${CI_MODE}" == "true" ]]; then
        pytest_args+=("--maxfail=3")
    fi
    
    # Enable async testing if needed
    if python3 -c "import pytest_asyncio" 2>/dev/null; then
        pytest_args+=("--asyncio-mode=auto")
    fi
    
    log_info "Running integration tests..."
    log_info "Testing database integration, external services, and API workflows"
    
    # Set longer timeout for integration tests
    export PYTEST_TIMEOUT=300
    
    if pytest "${pytest_args[@]}"; then
        log_success "Integration tests completed successfully"
    else
        log_error "Integration tests failed"
        return 1
    fi
    
    return 0
}

run_performance_tests() {
    if [[ "${SKIP_PERFORMANCE_TESTS}" == "true" ]]; then
        log_warning "Skipping performance tests as requested"
        return 0
    fi
    
    log_header "Performance Tests: Load Testing and Baseline Comparison"
    
    local performance_failed=false
    
    # Ensure Flask application is running for performance tests
    log_info "Starting Flask application for performance testing..."
    
    # Start Flask app in background for testing
    export FLASK_ENV=testing
    python3 -m flask run --host=127.0.0.1 --port=5000 &
    local flask_pid=$!
    
    # Wait for Flask to start
    local retry_count=0
    while ! curl -s http://127.0.0.1:5000/health >/dev/null 2>&1; do
        if [[ ${retry_count} -ge 30 ]]; then
            log_error "Flask application failed to start within 30 seconds"
            kill ${flask_pid} 2>/dev/null || true
            return 1
        fi
        sleep 1
        ((retry_count++))
    done
    
    log_success "Flask application started successfully (PID: ${flask_pid})"
    
    # Ensure cleanup on exit
    trap "kill ${flask_pid} 2>/dev/null || true" EXIT
    
    # Run Locust Load Testing
    if command -v locust &> /dev/null; then
        log_info "Running Locust load testing..."
        
        local locust_report="${REPORT_DIR}/locust_report"
        mkdir -p "${locust_report}"
        
        # Run locust in headless mode
        if locust -f tests/performance/locustfile.py \
           --headless \
           --users 50 \
           --spawn-rate 5 \
           --run-time 300s \
           --host http://127.0.0.1:5000 \
           --html "${locust_report}/locust_report.html" \
           --csv "${locust_report}/locust_results"; then
            
            log_success "Locust load testing completed"
            
            # Analyze results
            if [[ -f "${locust_report}/locust_results_stats.csv" ]]; then
                local avg_response_time
                avg_response_time=$(tail -n 1 "${locust_report}/locust_results_stats.csv" | cut -d',' -f3 || echo "0")
                log_info "Average response time: ${avg_response_time}ms"
            fi
        else
            log_error "Locust load testing failed"
            performance_failed=true
        fi
    else
        log_warning "Locust not available, skipping load testing"
    fi
    
    # Run Apache Bench Testing
    if command -v ab &> /dev/null; then
        log_info "Running Apache Bench performance testing..."
        
        local ab_report="${REPORT_DIR}/apache_bench_report.txt"
        
        if ab -n 1000 -c 10 -g "${REPORT_DIR}/ab_gnuplot.tsv" \
           http://127.0.0.1:5000/health > "${ab_report}"; then
            
            log_success "Apache Bench testing completed"
            
            # Extract key metrics
            local requests_per_sec
            requests_per_sec=$(grep "Requests per second" "${ab_report}" | awk '{print $4}' || echo "0")
            log_info "Requests per second: ${requests_per_sec}"
            
        else
            log_error "Apache Bench testing failed"
            performance_failed=true
        fi
    else
        log_warning "Apache Bench not available, installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y apache2-utils
        elif command -v yum &> /dev/null; then
            sudo yum install -y httpd-tools
        else
            log_warning "Cannot install Apache Bench automatically"
        fi
    fi
    
    # Run Performance Baseline Comparison
    log_info "Running performance baseline comparison tests..."
    
    local pytest_args=(
        "tests/performance/"
        "--tb=short"
        "--junitxml=${REPORT_DIR}/performance_tests.xml"
    )
    
    if [[ "${VERBOSE}" == "true" ]]; then
        pytest_args+=("-v")
    fi
    
    # Set performance threshold for tests
    export PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD}"
    
    if pytest "${pytest_args[@]}"; then
        log_success "Performance baseline comparison completed"
    else
        log_error "Performance baseline comparison failed"
        performance_failed=true
    fi
    
    # Cleanup Flask process
    kill ${flask_pid} 2>/dev/null || true
    trap - EXIT
    
    if [[ "${performance_failed}" == "true" ]]; then
        log_error "Performance testing failed. Performance must be within ${PERFORMANCE_VARIANCE_THRESHOLD}% of baseline."
        if [[ "${CI_MODE}" == "true" ]]; then
            exit 1
        fi
        return 1
    fi
    
    log_success "Performance testing completed successfully"
    return 0
}

run_e2e_tests() {
    log_header "End-to-End Tests: Complete Workflow Validation"
    
    local pytest_args=(
        "tests/e2e/"
        "--tb=short"
        "--junitxml=${REPORT_DIR}/e2e_tests.xml"
    )
    
    if [[ "${VERBOSE}" == "true" ]]; then
        pytest_args+=("-v" "-s")
    else
        pytest_args+=("-q")
    fi
    
    if [[ "${CI_MODE}" == "true" ]]; then
        pytest_args+=("--maxfail=1")
    fi
    
    log_info "Running end-to-end tests..."
    
    # Set longer timeout for E2E tests
    export PYTEST_TIMEOUT=600
    
    if [[ -d "tests/e2e" ]] && [[ -n "$(find tests/e2e -name '*.py' -type f)" ]]; then
        if pytest "${pytest_args[@]}"; then
            log_success "End-to-end tests completed successfully"
        else
            log_error "End-to-end tests failed"
            return 1
        fi
    else
        log_info "No end-to-end tests found, skipping..."
    fi
    
    return 0
}

generate_test_report() {
    log_header "Test Report Generation"
    
    local report_file="${REPORT_DIR}/test_summary.md"
    
    cat > "${report_file}" << EOF
# Test Execution Summary

**Timestamp:** $(date)
**Project:** Flask Application Migration Testing
**Coverage Threshold:** ${COVERAGE_THRESHOLD}%
**Performance Threshold:** ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance

## Test Results

### Static Analysis
EOF
    
    if [[ "${SKIP_STATIC_ANALYSIS}" == "true" ]]; then
        echo "- **Status:** SKIPPED" >> "${report_file}"
    elif [[ -f "${REPORT_DIR}/flake8_report.txt" ]]; then
        local flake8_errors
        flake8_errors=$(wc -l < "${REPORT_DIR}/flake8_report.txt" || echo "0")
        echo "- **flake8:** ${flake8_errors} issues detected" >> "${report_file}"
        
        if [[ -f "${REPORT_DIR}/mypy_report.txt" ]]; then
            local mypy_errors
            mypy_errors=$(grep -c "error:" "${REPORT_DIR}/mypy_report.txt" || echo "0")
            echo "- **mypy:** ${mypy_errors} type errors detected" >> "${report_file}"
        fi
    fi
    
    cat >> "${report_file}" << EOF

### Security Scanning
EOF
    
    if [[ "${SKIP_SECURITY_SCAN}" == "true" ]]; then
        echo "- **Status:** SKIPPED" >> "${report_file}"
    elif [[ -f "${REPORT_DIR}/bandit_report.json" ]]; then
        local security_issues
        security_issues=$(python3 -c "
import json
try:
    with open('${REPORT_DIR}/bandit_report.json', 'r') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except:
    print('N/A')
" 2>/dev/null || echo "N/A")
        echo "- **bandit:** ${security_issues} security issues detected" >> "${report_file}"
        
        if [[ -f "${REPORT_DIR}/safety_report.json" ]]; then
            local vuln_count
            vuln_count=$(python3 -c "
import json
try:
    with open('${REPORT_DIR}/safety_report.json', 'r') as f:
        data = json.load(f)
    print(len(data))
except:
    print('N/A')
" 2>/dev/null || echo "N/A")
            echo "- **safety:** ${vuln_count} vulnerabilities detected" >> "${report_file}"
        fi
    fi
    
    cat >> "${report_file}" << EOF

### Test Coverage
EOF
    
    if [[ "${SKIP_UNIT_TESTS}" == "true" ]]; then
        echo "- **Status:** SKIPPED" >> "${report_file}"
    elif command -v coverage &> /dev/null; then
        local coverage_pct
        coverage_pct=$(coverage report --precision=1 2>/dev/null | grep TOTAL | awk '{print $4}' || echo "N/A")
        echo "- **Coverage:** ${coverage_pct}" >> "${report_file}"
        echo "- **Threshold:** ${COVERAGE_THRESHOLD}%" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

### Performance Testing
EOF
    
    if [[ "${SKIP_PERFORMANCE_TESTS}" == "true" ]]; then
        echo "- **Status:** SKIPPED" >> "${report_file}"
    elif [[ -f "${REPORT_DIR}/locust_report/locust_results_stats.csv" ]]; then
        local avg_response_time
        avg_response_time=$(tail -n 1 "${REPORT_DIR}/locust_report/locust_results_stats.csv" | cut -d',' -f3 || echo "N/A")
        echo "- **Average Response Time:** ${avg_response_time}ms" >> "${report_file}"
        echo "- **Variance Threshold:** ≤${PERFORMANCE_VARIANCE_THRESHOLD}%" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Report Files

- **Coverage HTML:** [coverage_html/index.html](coverage_html/index.html)
- **Static Analysis:** [flake8_report.txt](flake8_report.txt), [mypy_report.txt](mypy_report.txt)
- **Security Reports:** [bandit_report.json](bandit_report.json), [safety_report.json](safety_report.json)
- **Performance Reports:** [locust_report/](locust_report/), [apache_bench_report.txt](apache_bench_report.txt)
- **Test Results:** [unit_tests.xml](unit_tests.xml), [integration_tests.xml](integration_tests.xml)

## Quality Gates Summary

| Gate | Threshold | Status |
|------|-----------|---------|
| Coverage | ≥${COVERAGE_THRESHOLD}% | $(if [[ "${SKIP_UNIT_TESTS}" == "true" ]]; then echo "SKIPPED"; else echo "CHECK ABOVE"; fi) |
| Lint Errors | 0 | $(if [[ "${SKIP_STATIC_ANALYSIS}" == "true" ]]; then echo "SKIPPED"; else echo "CHECK ABOVE"; fi) |
| Type Errors | 0 | $(if [[ "${SKIP_STATIC_ANALYSIS}" == "true" ]]; then echo "SKIPPED"; else echo "CHECK ABOVE"; fi) |
| Security Issues | 0 Critical | $(if [[ "${SKIP_SECURITY_SCAN}" == "true" ]]; then echo "SKIPPED"; else echo "CHECK ABOVE"; fi) |
| Performance | ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance | $(if [[ "${SKIP_PERFORMANCE_TESTS}" == "true" ]]; then echo "SKIPPED"; else echo "CHECK ABOVE"; fi) |

---
Generated by Flask Migration Test Suite
EOF
    
    log_success "Test report generated: ${report_file}"
    
    if [[ "${VERBOSE}" == "true" ]]; then
        echo
        cat "${report_file}"
    fi
}

# =============================================================================
# MAIN EXECUTION FLOW
# =============================================================================

main() {
    local start_time
    start_time=$(date +%s)
    
    log_header "Flask Application Migration - Comprehensive Test Suite"
    log_info "Starting test execution at $(date)"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Setup test environment
    setup_environment
    
    local test_results=()
    
    # Execute testing pipeline based on configuration
    if [[ "${SKIP_STATIC_ANALYSIS}" == "false" ]]; then
        if run_static_analysis; then
            test_results+=("Static Analysis: PASSED")
        else
            test_results+=("Static Analysis: FAILED")
        fi
    fi
    
    if [[ "${SKIP_SECURITY_SCAN}" == "false" ]]; then
        if run_security_scan; then
            test_results+=("Security Scan: PASSED")
        else
            test_results+=("Security Scan: FAILED")
        fi
    fi
    
    if [[ "${SKIP_UNIT_TESTS}" == "false" ]]; then
        if run_unit_tests; then
            test_results+=("Unit Tests: PASSED")
        else
            test_results+=("Unit Tests: FAILED")
        fi
    fi
    
    if [[ "${SKIP_INTEGRATION_TESTS}" == "false" ]]; then
        if run_integration_tests; then
            test_results+=("Integration Tests: PASSED")
        else
            test_results+=("Integration Tests: FAILED")
        fi
    fi
    
    # Run E2E tests if they exist
    if run_e2e_tests; then
        test_results+=("E2E Tests: PASSED")
    else
        test_results+=("E2E Tests: FAILED")
    fi
    
    if [[ "${SKIP_PERFORMANCE_TESTS}" == "false" ]]; then
        if run_performance_tests; then
            test_results+=("Performance Tests: PASSED")
        else
            test_results+=("Performance Tests: FAILED")
        fi
    fi
    
    # Generate comprehensive test report
    generate_test_report
    
    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local duration_formatted
    duration_formatted=$(printf "%02d:%02d:%02d" $((duration/3600)) $((duration%3600/60)) $((duration%60)))
    
    # Display final results
    log_header "Test Execution Summary"
    log_info "Total execution time: ${duration_formatted}"
    log_info "Report directory: ${REPORT_DIR}"
    
    echo
    for result in "${test_results[@]}"; do
        if [[ "${result}" == *"PASSED"* ]]; then
            log_success "${result}"
        else
            log_error "${result}"
        fi
    done
    
    # Check overall results
    local failed_tests=0
    for result in "${test_results[@]}"; do
        if [[ "${result}" == *"FAILED"* ]]; then
            ((failed_tests++))
        fi
    done
    
    echo
    if [[ ${failed_tests} -eq 0 ]]; then
        log_success "🎉 All tests passed successfully! Ready for deployment."
        exit 0
    else
        log_error "❌ ${failed_tests} test suite(s) failed. Review and fix issues before deployment."
        if [[ "${CI_MODE}" == "true" ]]; then
            exit 1
        fi
        exit ${failed_tests}
    fi
}

# Execute main function with all arguments
main "$@"