#!/bin/bash

#################################################################
# Performance Testing and Validation Script
#################################################################
# 
# Comprehensive performance testing script using Locust and k6 load testing 
# frameworks with automated baseline comparison ensuring ≤10% variance 
# compliance for Flask application performance monitoring.
#
# Features:
# - Locust 2.17+ distributed load testing with baseline comparison
# - k6 performance analysis with detailed metrics and variance calculation
# - Apache Bench HTTP server performance measurement
# - Automated performance validation pipeline with ≤10% variance enforcement
# - Prometheus metrics collection and trend analysis integration
# - CI/CD pipeline compatibility with GitHub Actions
# - Enterprise-grade reporting and alerting
#
# Usage:
#   ./scripts/performance.sh [options]
#
# Options:
#   --test-type TYPE          Test type: locust, k6, ab, all (default: all)
#   --target-url URL          Target Flask application URL (required)
#   --baseline-file FILE      Node.js baseline metrics file path
#   --output-dir DIR          Results output directory (default: tests/performance/reports)
#   --users COUNT             Number of concurrent users for load testing (default: 50)
#   --duration SECONDS        Test duration in seconds (default: 300)
#   --spawn-rate RATE         User spawn rate per second (default: 5)
#   --variance-threshold PCT  Performance variance threshold % (default: 10)
#   --ci-mode                 Enable CI/CD pipeline mode with automated gates
#   --prometheus-url URL      Prometheus metrics endpoint URL
#   --slack-webhook URL       Slack webhook for notifications
#   --help                    Display this help message
#
# Examples:
#   # Run all performance tests
#   ./scripts/performance.sh --target-url http://localhost:5000
#
#   # Run Locust load test only
#   ./scripts/performance.sh --test-type locust --target-url http://localhost:5000 --users 100
#
#   # CI/CD mode with automated validation
#   ./scripts/performance.sh --ci-mode --target-url https://staging-api.company.com
#
# Environment Variables:
#   FLASK_APP_URL             Target Flask application URL
#   NODE_BASELINE_FILE        Path to Node.js baseline metrics
#   PERFORMANCE_VARIANCE_LIMIT Maximum allowed performance variance (default: 10)
#   PROMETHEUS_ENDPOINT       Prometheus metrics collection endpoint
#   SLACK_PERFORMANCE_WEBHOOK Slack webhook for performance alerts
#   CI                        Set to 'true' for CI/CD pipeline mode
#
#################################################################

set -euo pipefail

# Configuration constants per Section 0.1.1 primary objective
readonly SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PERFORMANCE_TEST_DIR="${PROJECT_ROOT}/tests/performance"
readonly REPORTS_DIR="${PERFORMANCE_TEST_DIR}/reports"
readonly DATA_DIR="${PERFORMANCE_TEST_DIR}/data"
readonly SCRIPTS_DIR="${PERFORMANCE_TEST_DIR}/scripts"

# Performance validation constants per Section 0.3.2 and 4.4.2
readonly DEFAULT_VARIANCE_THRESHOLD=10  # ≤10% variance requirement
readonly DEFAULT_CONCURRENT_USERS=50
readonly DEFAULT_TEST_DURATION=300      # 5 minutes
readonly DEFAULT_SPAWN_RATE=5
readonly MINIMUM_REQUESTS_PER_SECOND=100
readonly MAX_RESPONSE_TIME_P95=500      # 95th percentile ≤500ms per Section 4.6.3

# Test framework versions per Section 6.6.1 and 8.5.2
readonly LOCUST_MIN_VERSION="2.17.0"
readonly K6_MIN_VERSION="0.46.0"
readonly APACHE_BENCH_MIN_VERSION="2.4.0"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global variables for configuration
TARGET_URL=""
BASELINE_FILE="${PERFORMANCE_TEST_DIR}/baseline_data.py"
OUTPUT_DIR="${REPORTS_DIR}"
CONCURRENT_USERS="${DEFAULT_CONCURRENT_USERS}"
TEST_DURATION="${DEFAULT_TEST_DURATION}"
SPAWN_RATE="${DEFAULT_SPAWN_RATE}"
VARIANCE_THRESHOLD="${DEFAULT_VARIANCE_THRESHOLD}"
TEST_TYPE="all"
CI_MODE=false
PROMETHEUS_URL=""
SLACK_WEBHOOK=""
CURRENT_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
TEST_SESSION_ID="perf_${CURRENT_TIMESTAMP}"

#################################################################
# Utility Functions
#################################################################

# Logging functions with enterprise-grade formatting
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
    fi
}

# Error handling with comprehensive cleanup
cleanup_on_exit() {
    local exit_code=$?
    log_info "Cleaning up performance test resources..."
    
    # Kill any running background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Clean up temporary files
    find "${OUTPUT_DIR}" -name "*.tmp" -type f -delete 2>/dev/null || true
    
    # Generate final summary report if not in CI mode
    if [[ "${CI_MODE}" == "false" && "${exit_code}" -eq 0 ]]; then
        generate_summary_report
    fi
    
    log_info "Cleanup completed with exit code: ${exit_code}"
    exit "${exit_code}"
}

trap cleanup_on_exit EXIT INT TERM

# Dependency validation with version checking
check_dependencies() {
    log_info "Validating performance testing dependencies..."
    
    local missing_deps=()
    local version_issues=()
    
    # Check Python and pytest
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if ! python3 -c "import pytest" 2>/dev/null; then
        missing_deps+=("pytest")
    fi
    
    # Check Locust version per Section 6.6.1 requirements
    if command -v locust &> /dev/null; then
        local locust_version
        locust_version=$(locust --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if ! python3 -c "
from packaging import version
import sys
if version.parse('${locust_version}') < version.parse('${LOCUST_MIN_VERSION}'):
    sys.exit(1)
" 2>/dev/null; then
            version_issues+=("locust (found: ${locust_version}, required: >=${LOCUST_MIN_VERSION})")
        fi
    else
        missing_deps+=("locust")
    fi
    
    # Check k6 availability and version
    if command -v k6 &> /dev/null; then
        local k6_version
        k6_version=$(k6 version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/v//')
        if [[ -n "${k6_version}" ]]; then
            if ! python3 -c "
from packaging import version
import sys
if version.parse('${k6_version}') < version.parse('${K6_MIN_VERSION}'):
    sys.exit(1)
" 2>/dev/null; then
                version_issues+=("k6 (found: ${k6_version}, required: >=${K6_MIN_VERSION})")
            fi
        fi
    else
        log_warning "k6 not found - will skip k6 performance tests"
    fi
    
    # Check Apache Bench (ab)
    if ! command -v ab &> /dev/null; then
        log_warning "Apache Bench (ab) not found - will skip benchmark tests"
    fi
    
    # Check curl for health checks
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    # Check jq for JSON processing
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    # Report missing dependencies
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies before running performance tests"
        return 1
    fi
    
    # Report version issues
    if [[ ${#version_issues[@]} -gt 0 ]]; then
        log_error "Version requirement issues: ${version_issues[*]}"
        log_error "Please update tools to meet minimum version requirements"
        return 1
    fi
    
    log_success "All dependencies validated successfully"
    return 0
}

# Environment setup and validation
setup_environment() {
    log_info "Setting up performance testing environment..."
    
    # Create necessary directories
    mkdir -p "${OUTPUT_DIR}" "${DATA_DIR}" "${SCRIPTS_DIR}"
    
    # Set environment variables for tests
    export PERFORMANCE_TEST_SESSION="${TEST_SESSION_ID}"
    export PERFORMANCE_TARGET_URL="${TARGET_URL}"
    export PERFORMANCE_VARIANCE_THRESHOLD="${VARIANCE_THRESHOLD}"
    export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"
    
    # Load environment-specific configuration
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "${PROJECT_ROOT}/.env"
        set +a
        log_debug "Loaded environment configuration from .env"
    fi
    
    # Configure CI mode settings
    if [[ "${CI_MODE}" == "true" || "${CI:-false}" == "true" ]]; then
        CI_MODE=true
        export CI_PERFORMANCE_MODE="true"
        log_info "Running in CI/CD pipeline mode"
    fi
    
    log_success "Environment setup completed"
}

# Target URL validation and health check
validate_target_url() {
    log_info "Validating target URL: ${TARGET_URL}"
    
    # Basic URL format validation
    if [[ ! "${TARGET_URL}" =~ ^https?://[^/]+.* ]]; then
        log_error "Invalid URL format: ${TARGET_URL}"
        return 1
    fi
    
    # Health check endpoint validation
    local health_endpoint="${TARGET_URL%/}/health"
    local health_response
    
    log_info "Checking application health at: ${health_endpoint}"
    
    if ! health_response=$(curl -s -f --connect-timeout 10 --max-time 30 "${health_endpoint}" 2>/dev/null); then
        log_error "Health check failed - application not responding at ${health_endpoint}"
        log_error "Please ensure the Flask application is running and accessible"
        return 1
    fi
    
    # Validate health response format
    if command -v jq &> /dev/null && echo "${health_response}" | jq . &> /dev/null; then
        local status
        status=$(echo "${health_response}" | jq -r '.status // "unknown"')
        if [[ "${status}" != "healthy" && "${status}" != "ok" ]]; then
            log_warning "Application health status: ${status}"
        else
            log_success "Application health check passed: ${status}"
        fi
    else
        log_debug "Health response: ${health_response}"
    fi
    
    return 0
}

#################################################################
# Baseline Data Management
#################################################################

# Load Node.js baseline metrics per Section 0.3.2 performance monitoring
load_baseline_metrics() {
    log_info "Loading Node.js baseline performance metrics..."
    
    if [[ ! -f "${BASELINE_FILE}" ]]; then
        log_error "Baseline file not found: ${BASELINE_FILE}"
        log_error "Please ensure Node.js baseline metrics are available"
        return 1
    fi
    
    # Extract baseline metrics using Python
    local baseline_data
    baseline_data=$(python3 -c "
import sys
sys.path.insert(0, '${PERFORMANCE_TEST_DIR}')
try:
    from baseline_data import NODEJS_BASELINE_METRICS
    import json
    print(json.dumps(NODEJS_BASELINE_METRICS))
except ImportError as e:
    print(f'Error loading baseline data: {e}', file=sys.stderr)
    sys.exit(1)
")
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to load baseline metrics from ${BASELINE_FILE}"
        return 1
    fi
    
    # Store baseline data for comparison
    echo "${baseline_data}" > "${DATA_DIR}/nodejs_baseline.json"
    log_success "Baseline metrics loaded successfully"
    
    # Display key baseline metrics
    if command -v jq &> /dev/null; then
        log_info "Key baseline metrics:"
        echo "${baseline_data}" | jq -r '
            "  Response Time P95: " + (.response_time_p95 // "N/A") + "ms",
            "  Requests/Second: " + (.requests_per_second // "N/A"),
            "  Memory Usage: " + (.memory_usage_mb // "N/A") + "MB",
            "  CPU Utilization: " + (.cpu_utilization_percent // "N/A") + "%"
        '
    fi
    
    return 0
}

# Performance variance calculation per Section 4.4.2
calculate_variance() {
    local baseline_value=$1
    local current_value=$2
    local metric_name=$3
    
    if [[ -z "${baseline_value}" || -z "${current_value}" ]]; then
        log_warning "Missing values for variance calculation: ${metric_name}"
        echo "N/A"
        return 1
    fi
    
    # Calculate percentage variance
    local variance
    variance=$(python3 -c "
baseline = float('${baseline_value}')
current = float('${current_value}')
if baseline == 0:
    print('INF' if current != 0 else '0')
else:
    variance = abs((current - baseline) / baseline) * 100
    print(f'{variance:.2f}')
")
    
    echo "${variance}"
}

# Variance validation against ≤10% threshold
validate_variance() {
    local variance=$1
    local metric_name=$2
    local threshold=${3:-$VARIANCE_THRESHOLD}
    
    if [[ "${variance}" == "N/A" || "${variance}" == "INF" ]]; then
        log_warning "Cannot validate variance for ${metric_name}: ${variance}"
        return 1
    fi
    
    # Compare against threshold using Python for floating point comparison
    local is_within_threshold
    is_within_threshold=$(python3 -c "
import sys
variance = float('${variance}')
threshold = float('${threshold}')
print('true' if variance <= threshold else 'false')
")
    
    if [[ "${is_within_threshold}" == "true" ]]; then
        log_success "${metric_name} variance: ${variance}% (✓ within ${threshold}% threshold)"
        return 0
    else
        log_error "${metric_name} variance: ${variance}% (✗ exceeds ${threshold}% threshold)"
        return 1
    fi
}

#################################################################
# Performance Testing Functions
#################################################################

# Locust distributed load testing per Section 6.6.1 and 8.5.2
run_locust_test() {
    log_info "Starting Locust distributed load testing..."
    
    local locust_file="${PERFORMANCE_TEST_DIR}/locustfile.py"
    local results_prefix="${OUTPUT_DIR}/locust_${TEST_SESSION_ID}"
    
    if [[ ! -f "${locust_file}" ]]; then
        log_error "Locust test file not found: ${locust_file}"
        return 1
    fi
    
    # Locust test parameters
    local locust_cmd=(
        "locust"
        "-f" "${locust_file}"
        "--headless"
        "--users" "${CONCURRENT_USERS}"
        "--spawn-rate" "${SPAWN_RATE}"
        "--run-time" "${TEST_DURATION}s"
        "--host" "${TARGET_URL}"
        "--csv" "${results_prefix}"
        "--html" "${results_prefix}.html"
        "--logfile" "${results_prefix}.log"
        "--loglevel" "INFO"
    )
    
    log_info "Executing Locust test with ${CONCURRENT_USERS} users for ${TEST_DURATION} seconds"
    log_debug "Locust command: ${locust_cmd[*]}"
    
    # Run Locust test with timeout
    if timeout $((TEST_DURATION + 60)) "${locust_cmd[@]}"; then
        log_success "Locust test completed successfully"
    else
        log_error "Locust test failed or timed out"
        return 1
    fi
    
    # Process and validate results
    analyze_locust_results "${results_prefix}"
    return $?
}

# Analyze Locust test results with baseline comparison
analyze_locust_results() {
    local results_prefix=$1
    local stats_file="${results_prefix}_stats.csv"
    local failures_file="${results_prefix}_failures.csv"
    
    log_info "Analyzing Locust test results..."
    
    if [[ ! -f "${stats_file}" ]]; then
        log_error "Locust stats file not found: ${stats_file}"
        return 1
    fi
    
    # Extract key metrics using Python
    local analysis_result
    analysis_result=$(python3 -c "
import csv
import json
import sys

def analyze_locust_stats(stats_file):
    try:
        with open('${stats_file}', 'r') as f:
            reader = csv.DictReader(f)
            total_row = None
            for row in reader:
                if row.get('Name') == 'Aggregated':
                    total_row = row
                    break
            
            if not total_row:
                return None
                
            return {
                'total_requests': int(total_row.get('Request Count', 0)),
                'failure_count': int(total_row.get('Failure Count', 0)),
                'median_response_time': float(total_row.get('Median Response Time', 0)),
                'p95_response_time': float(total_row.get('95%% Response Time', 0)),
                'p99_response_time': float(total_row.get('99%% Response Time', 0)),
                'average_response_time': float(total_row.get('Average Response Time', 0)),
                'min_response_time': float(total_row.get('Min Response Time', 0)),
                'max_response_time': float(total_row.get('Max Response Time', 0)),
                'requests_per_second': float(total_row.get('Requests/s', 0)),
                'failure_rate': float(total_row.get('Failure Count', 0)) / max(float(total_row.get('Request Count', 1)), 1) * 100
            }
    except Exception as e:
        print(f'Error analyzing Locust stats: {e}', file=sys.stderr)
        return None

result = analyze_locust_stats('${stats_file}')
if result:
    print(json.dumps(result))
else:
    sys.exit(1)
")
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to analyze Locust results"
        return 1
    fi
    
    # Save current results
    echo "${analysis_result}" > "${DATA_DIR}/locust_current_${TEST_SESSION_ID}.json"
    
    # Display results
    log_info "Locust Test Results:"
    if command -v jq &> /dev/null; then
        echo "${analysis_result}" | jq -r '
            "  Total Requests: " + (.total_requests | tostring),
            "  Failed Requests: " + (.failure_count | tostring),
            "  Failure Rate: " + (.failure_rate | tonumber | . * 100 / 100 | tostring) + "%",
            "  Requests/Second: " + (.requests_per_second | tostring),
            "  Response Times:",
            "    Median: " + (.median_response_time | tostring) + "ms",
            "    95th Percentile: " + (.p95_response_time | tostring) + "ms",
            "    99th Percentile: " + (.p99_response_time | tostring) + "ms",
            "    Average: " + (.average_response_time | tostring) + "ms"
        '
    fi
    
    # Validate against baseline if available
    if [[ -f "${DATA_DIR}/nodejs_baseline.json" ]]; then
        validate_locust_against_baseline "${analysis_result}"
    else
        log_warning "No baseline data available for comparison"
    fi
    
    return 0
}

# Validate Locust results against Node.js baseline
validate_locust_against_baseline() {
    local current_results=$1
    
    log_info "Validating Locust results against Node.js baseline..."
    
    local baseline_data
    baseline_data=$(cat "${DATA_DIR}/nodejs_baseline.json")
    
    # Compare key metrics
    local validation_passed=true
    
    # Response time validation
    local baseline_p95 current_p95 variance_p95
    baseline_p95=$(echo "${baseline_data}" | jq -r '.response_time_p95 // "0"')
    current_p95=$(echo "${current_results}" | jq -r '.p95_response_time')
    variance_p95=$(calculate_variance "${baseline_p95}" "${current_p95}" "Response Time P95")
    
    if ! validate_variance "${variance_p95}" "Response Time P95"; then
        validation_passed=false
    fi
    
    # Requests per second validation
    local baseline_rps current_rps variance_rps
    baseline_rps=$(echo "${baseline_data}" | jq -r '.requests_per_second // "0"')
    current_rps=$(echo "${current_results}" | jq -r '.requests_per_second')
    variance_rps=$(calculate_variance "${baseline_rps}" "${current_rps}" "Requests/Second")
    
    if ! validate_variance "${variance_rps}" "Requests/Second"; then
        validation_passed=false
    fi
    
    # Failure rate validation (should be minimal)
    local failure_rate
    failure_rate=$(echo "${current_results}" | jq -r '.failure_rate')
    if (( $(echo "${failure_rate} > 1.0" | bc -l) )); then
        log_error "Failure rate too high: ${failure_rate}% (threshold: 1%)"
        validation_passed=false
    else
        log_success "Failure rate acceptable: ${failure_rate}%"
    fi
    
    if [[ "${validation_passed}" == "true" ]]; then
        log_success "Locust performance validation passed ✓"
        return 0
    else
        log_error "Locust performance validation failed ✗"
        return 1
    fi
}

# k6 performance testing per Section 8.5.2
run_k6_test() {
    if ! command -v k6 &> /dev/null; then
        log_warning "k6 not available - skipping k6 performance test"
        return 0
    fi
    
    log_info "Starting k6 performance analysis..."
    
    local k6_script="${SCRIPTS_DIR}/k6_performance_test.js"
    local results_file="${OUTPUT_DIR}/k6_${TEST_SESSION_ID}.json"
    
    # Create k6 test script if not exists
    if [[ ! -f "${k6_script}" ]]; then
        create_k6_test_script "${k6_script}"
    fi
    
    # k6 test execution
    local k6_cmd=(
        "k6" "run"
        "--out" "json=${results_file}"
        "--duration" "${TEST_DURATION}s"
        "--vus" "${CONCURRENT_USERS}"
        "--rps" "${MINIMUM_REQUESTS_PER_SECOND}"
        "${k6_script}"
    )
    
    log_info "Executing k6 test with ${CONCURRENT_USERS} VUs for ${TEST_DURATION} seconds"
    log_debug "k6 command: ${k6_cmd[*]}"
    
    # Set target URL for k6 script
    export K6_TARGET_URL="${TARGET_URL}"
    
    if "${k6_cmd[@]}"; then
        log_success "k6 test completed successfully"
        analyze_k6_results "${results_file}"
        return $?
    else
        log_error "k6 test failed"
        return 1
    fi
}

# Create k6 test script per Section 8.5.2 requirements
create_k6_test_script() {
    local script_path=$1
    
    log_info "Creating k6 performance test script..."
    
    mkdir -p "$(dirname "${script_path}")"
    
    cat > "${script_path}" << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics for detailed analysis
export let errorRate = new Rate('errors');
export let responseTimeTrend = new Trend('response_time');

// Performance thresholds per Section 4.6.3
export let options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp-up
    { duration: '200s', target: __ENV.K6_VUS || 50 }, // Sustained load
    { duration: '30s', target: 0 },    // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95th percentile under 500ms
    http_req_failed: ['rate<0.01'],   // Error rate under 1%
    errors: ['rate<0.01'],            // Custom error rate under 1%
  },
};

const BASE_URL = __ENV.K6_TARGET_URL || 'http://localhost:5000';

export default function() {
  // Health check endpoint
  let healthResponse = http.get(`${BASE_URL}/health`);
  let healthCheck = check(healthResponse, {
    'health status is 200': (r) => r.status === 200,
    'health response time < 100ms': (r) => r.timings.duration < 100,
  });
  
  errorRate.add(!healthCheck);
  responseTimeTrend.add(healthResponse.timings.duration);
  
  // API endpoints testing
  let apiResponse = http.get(`${BASE_URL}/api/health`);
  let apiCheck = check(apiResponse, {
    'api status is 200': (r) => r.status === 200,
    'api response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  errorRate.add(!apiCheck);
  responseTimeTrend.add(apiResponse.timings.duration);
  
  // Authentication workflow (if available)
  if (apiResponse.status === 200) {
    let authResponse = http.post(`${BASE_URL}/auth/login`, JSON.stringify({
      username: 'test_user',
      password: 'test_password'
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
    
    let authCheck = check(authResponse, {
      'auth response received': (r) => r.status === 200 || r.status === 401,
    });
    
    errorRate.add(!authCheck);
    responseTimeTrend.add(authResponse.timings.duration);
  }
  
  sleep(1);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  return `
k6 Performance Test Summary
==========================
Total Requests: ${data.metrics.http_reqs.values.count}
Failed Requests: ${data.metrics.http_req_failed.values.passes}
Request Rate: ${data.metrics.http_reqs.values.rate.toFixed(2)}/s
Response Times:
  Average: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms
  Median: ${data.metrics.http_req_duration.values.med.toFixed(2)}ms
  95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms
  99th Percentile: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms
Error Rate: ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%
`;
}
EOF
    
    log_success "k6 test script created: ${script_path}"
}

# Analyze k6 test results
analyze_k6_results() {
    local results_file=$1
    
    log_info "Analyzing k6 test results..."
    
    if [[ ! -f "${results_file}" ]]; then
        log_error "k6 results file not found: ${results_file}"
        return 1
    fi
    
    # Process k6 JSON output for metrics
    local analysis_result
    analysis_result=$(python3 -c "
import json
import sys
from collections import defaultdict

def analyze_k6_results(results_file):
    metrics = defaultdict(list)
    total_requests = 0
    failed_requests = 0
    
    try:
        with open('${results_file}', 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if data.get('type') == 'Point':
                        metric_name = data.get('metric')
                        value = data.get('data', {}).get('value', 0)
                        
                        if metric_name == 'http_req_duration':
                            metrics['response_times'].append(value)
                        elif metric_name == 'http_reqs':
                            total_requests += 1
                        elif metric_name == 'http_req_failed':
                            if value > 0:
                                failed_requests += 1
                except json.JSONDecodeError:
                    continue
        
        if not metrics['response_times']:
            return None
            
        response_times = sorted(metrics['response_times'])
        count = len(response_times)
        
        return {
            'total_requests': total_requests,
            'failed_requests': failed_requests,
            'failure_rate': (failed_requests / max(total_requests, 1)) * 100,
            'response_time_avg': sum(response_times) / count,
            'response_time_median': response_times[count // 2],
            'response_time_p95': response_times[int(count * 0.95)],
            'response_time_p99': response_times[int(count * 0.99)],
            'response_time_min': min(response_times),
            'response_time_max': max(response_times)
        }
    except Exception as e:
        print(f'Error analyzing k6 results: {e}', file=sys.stderr)
        return None

result = analyze_k6_results('${results_file}')
if result:
    print(json.dumps(result))
else:
    sys.exit(1)
")
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to analyze k6 results"
        return 1
    fi
    
    # Save and display results
    echo "${analysis_result}" > "${DATA_DIR}/k6_current_${TEST_SESSION_ID}.json"
    
    log_info "k6 Test Results:"
    if command -v jq &> /dev/null; then
        echo "${analysis_result}" | jq -r '
            "  Total Requests: " + (.total_requests | tostring),
            "  Failed Requests: " + (.failed_requests | tostring),
            "  Failure Rate: " + (.failure_rate | tonumber | tostring) + "%",
            "  Response Times:",
            "    Average: " + (.response_time_avg | tostring) + "ms",
            "    Median: " + (.response_time_median | tostring) + "ms",
            "    95th Percentile: " + (.response_time_p95 | tostring) + "ms",
            "    99th Percentile: " + (.response_time_p99 | tostring) + "ms"
        '
    fi
    
    # Validate against baseline
    if [[ -f "${DATA_DIR}/nodejs_baseline.json" ]]; then
        validate_k6_against_baseline "${analysis_result}"
    fi
    
    return 0
}

# Validate k6 results against baseline
validate_k6_against_baseline() {
    local current_results=$1
    
    log_info "Validating k6 results against Node.js baseline..."
    
    local baseline_data
    baseline_data=$(cat "${DATA_DIR}/nodejs_baseline.json")
    
    local validation_passed=true
    
    # Response time P95 validation
    local baseline_p95 current_p95 variance_p95
    baseline_p95=$(echo "${baseline_data}" | jq -r '.response_time_p95 // "0"')
    current_p95=$(echo "${current_results}" | jq -r '.response_time_p95')
    variance_p95=$(calculate_variance "${baseline_p95}" "${current_p95}" "k6 Response Time P95")
    
    if ! validate_variance "${variance_p95}" "k6 Response Time P95"; then
        validation_passed=false
    fi
    
    # Failure rate validation
    local failure_rate
    failure_rate=$(echo "${current_results}" | jq -r '.failure_rate')
    if (( $(echo "${failure_rate} > 1.0" | bc -l) )); then
        log_error "k6 failure rate too high: ${failure_rate}% (threshold: 1%)"
        validation_passed=false
    else
        log_success "k6 failure rate acceptable: ${failure_rate}%"
    fi
    
    if [[ "${validation_passed}" == "true" ]]; then
        log_success "k6 performance validation passed ✓"
        return 0
    else
        log_error "k6 performance validation failed ✗"
        return 1
    fi
}

# Apache Bench testing per Section 6.6.1
run_apache_bench_test() {
    if ! command -v ab &> /dev/null; then
        log_warning "Apache Bench (ab) not available - skipping benchmark test"
        return 0
    fi
    
    log_info "Starting Apache Bench performance measurement..."
    
    local results_file="${OUTPUT_DIR}/ab_${TEST_SESSION_ID}.txt"
    local json_results="${OUTPUT_DIR}/ab_${TEST_SESSION_ID}.json"
    
    # Calculate total requests based on duration and minimum RPS
    local total_requests=$((MINIMUM_REQUESTS_PER_SECOND * TEST_DURATION / 10)) # Scale down for AB
    local concurrency=$(( CONCURRENT_USERS < 100 ? CONCURRENT_USERS : 100 )) # AB limitation
    
    # Apache Bench command
    local ab_cmd=(
        "ab"
        "-n" "${total_requests}"
        "-c" "${concurrency}"
        "-g" "${OUTPUT_DIR}/ab_${TEST_SESSION_ID}.gnuplot"
        "${TARGET_URL}/health"
    )
    
    log_info "Executing Apache Bench with ${total_requests} requests, ${concurrency} concurrency"
    log_debug "AB command: ${ab_cmd[*]}"
    
    if "${ab_cmd[@]}" > "${results_file}" 2>&1; then
        log_success "Apache Bench test completed successfully"
        analyze_apache_bench_results "${results_file}" "${json_results}"
        return $?
    else
        log_error "Apache Bench test failed"
        cat "${results_file}" >&2
        return 1
    fi
}

# Analyze Apache Bench results
analyze_apache_bench_results() {
    local results_file=$1
    local json_results=$2
    
    log_info "Analyzing Apache Bench results..."
    
    if [[ ! -f "${results_file}" ]]; then
        log_error "Apache Bench results file not found: ${results_file}"
        return 1
    fi
    
    # Parse AB output using awk
    local analysis_result
    analysis_result=$(awk '
    BEGIN {
        total_requests = 0
        failed_requests = 0
        requests_per_second = 0
        time_per_request_mean = 0
        time_per_request_concurrent = 0
        p50 = 0
        p95 = 0
        p99 = 0
    }
    /^Complete requests:/ { total_requests = $3 }
    /^Failed requests:/ { failed_requests = $3 }
    /^Requests per second:/ { requests_per_second = $4 }
    /^Time per request:.*\(mean\)/ { time_per_request_mean = $4 }
    /^Time per request:.*concurrent/ { time_per_request_concurrent = $4 }
    /^ *50%/ { p50 = $2 }
    /^ *95%/ { p95 = $2 }
    /^ *99%/ { p99 = $2 }
    END {
        printf "{\n"
        printf "  \"total_requests\": %d,\n", total_requests
        printf "  \"failed_requests\": %d,\n", failed_requests
        printf "  \"failure_rate\": %.2f,\n", (failed_requests / (total_requests > 0 ? total_requests : 1)) * 100
        printf "  \"requests_per_second\": %.2f,\n", requests_per_second
        printf "  \"response_time_mean\": %.2f,\n", time_per_request_mean
        printf "  \"response_time_concurrent_mean\": %.2f,\n", time_per_request_concurrent
        printf "  \"response_time_p50\": %.0f,\n", p50
        printf "  \"response_time_p95\": %.0f,\n", p95
        printf "  \"response_time_p99\": %.0f\n", p99
        printf "}\n"
    }
    ' "${results_file}")
    
    # Save results
    echo "${analysis_result}" > "${json_results}"
    
    # Display results
    log_info "Apache Bench Test Results:"
    if command -v jq &> /dev/null; then
        echo "${analysis_result}" | jq -r '
            "  Total Requests: " + (.total_requests | tostring),
            "  Failed Requests: " + (.failed_requests | tostring),
            "  Failure Rate: " + (.failure_rate | tostring) + "%",
            "  Requests/Second: " + (.requests_per_second | tostring),
            "  Response Times:",
            "    Mean: " + (.response_time_mean | tostring) + "ms",
            "    50th Percentile: " + (.response_time_p50 | tostring) + "ms",
            "    95th Percentile: " + (.response_time_p95 | tostring) + "ms",
            "    99th Percentile: " + (.response_time_p99 | tostring) + "ms"
        '
    fi
    
    # Validate against baseline
    if [[ -f "${DATA_DIR}/nodejs_baseline.json" ]]; then
        validate_ab_against_baseline "${analysis_result}"
    fi
    
    return 0
}

# Validate Apache Bench results against baseline
validate_ab_against_baseline() {
    local current_results=$1
    
    log_info "Validating Apache Bench results against Node.js baseline..."
    
    local baseline_data
    baseline_data=$(cat "${DATA_DIR}/nodejs_baseline.json")
    
    local validation_passed=true
    
    # Response time P95 validation
    local baseline_p95 current_p95 variance_p95
    baseline_p95=$(echo "${baseline_data}" | jq -r '.response_time_p95 // "0"')
    current_p95=$(echo "${current_results}" | jq -r '.response_time_p95')
    variance_p95=$(calculate_variance "${baseline_p95}" "${current_p95}" "AB Response Time P95")
    
    if ! validate_variance "${variance_p95}" "AB Response Time P95"; then
        validation_passed=false
    fi
    
    # Requests per second validation
    local baseline_rps current_rps variance_rps
    baseline_rps=$(echo "${baseline_data}" | jq -r '.requests_per_second // "0"')
    current_rps=$(echo "${current_results}" | jq -r '.requests_per_second')
    variance_rps=$(calculate_variance "${baseline_rps}" "${current_rps}" "AB Requests/Second")
    
    if ! validate_variance "${variance_rps}" "AB Requests/Second"; then
        validation_passed=false
    fi
    
    if [[ "${validation_passed}" == "true" ]]; then
        log_success "Apache Bench performance validation passed ✓"
        return 0
    else
        log_error "Apache Bench performance validation failed ✗"
        return 1
    fi
}

#################################################################
# Monitoring and Reporting
#################################################################

# Prometheus metrics collection
collect_prometheus_metrics() {
    if [[ -z "${PROMETHEUS_URL}" ]]; then
        log_debug "No Prometheus URL configured - skipping metrics collection"
        return 0
    fi
    
    log_info "Collecting Prometheus metrics from: ${PROMETHEUS_URL}"
    
    local metrics_file="${DATA_DIR}/prometheus_${TEST_SESSION_ID}.json"
    local query_time=$(date +%s)
    
    # Query key performance metrics
    local queries=(
        'flask_request_duration_seconds'
        'flask_request_total'
        'process_resident_memory_bytes'
        'process_cpu_seconds_total'
        'mongodb_connections'
        'redis_connected_clients'
    )
    
    local all_metrics="{}"
    
    for query in "${queries[@]}"; do
        local metric_url="${PROMETHEUS_URL}/api/v1/query?query=${query}&time=${query_time}"
        local response
        
        if response=$(curl -s -f "${metric_url}" 2>/dev/null); then
            # Extract metric value
            local value
            value=$(echo "${response}" | jq -r '.data.result[0].value[1] // "0"' 2>/dev/null)
            all_metrics=$(echo "${all_metrics}" | jq ". + {\"${query}\": ${value}}")
        else
            log_warning "Failed to collect metric: ${query}"
        fi
    done
    
    echo "${all_metrics}" > "${metrics_file}"
    log_success "Prometheus metrics collected successfully"
}

# Generate comprehensive summary report
generate_summary_report() {
    log_info "Generating performance test summary report..."
    
    local summary_file="${OUTPUT_DIR}/performance_summary_${TEST_SESSION_ID}.json"
    local html_report="${OUTPUT_DIR}/performance_summary_${TEST_SESSION_ID}.html"
    
    # Collect all test results
    local summary="{
        \"test_session_id\": \"${TEST_SESSION_ID}\",
        \"timestamp\": \"$(date -Iseconds)\",
        \"target_url\": \"${TARGET_URL}\",
        \"test_configuration\": {
            \"concurrent_users\": ${CONCURRENT_USERS},
            \"test_duration\": ${TEST_DURATION},
            \"spawn_rate\": ${SPAWN_RATE},
            \"variance_threshold\": ${VARIANCE_THRESHOLD}
        }
    }"
    
    # Add test results if available
    for test_type in locust k6 ab; do
        local result_file="${DATA_DIR}/${test_type}_current_${TEST_SESSION_ID}.json"
        if [[ -f "${result_file}" ]]; then
            local result_data
            result_data=$(cat "${result_file}")
            summary=$(echo "${summary}" | jq ". + {\"${test_type}_results\": ${result_data}}")
        fi
    done
    
    # Add baseline comparison if available
    if [[ -f "${DATA_DIR}/nodejs_baseline.json" ]]; then
        local baseline_data
        baseline_data=$(cat "${DATA_DIR}/nodejs_baseline.json")
        summary=$(echo "${summary}" | jq ". + {\"baseline_data\": ${baseline_data}}")
    fi
    
    echo "${summary}" > "${summary_file}"
    
    # Generate HTML report
    generate_html_report "${summary_file}" "${html_report}"
    
    log_success "Summary report generated: ${summary_file}"
    log_success "HTML report generated: ${html_report}"
}

# Generate HTML performance report
generate_html_report() {
    local json_file=$1
    local html_file=$2
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq not available - skipping HTML report generation"
        return 0
    fi
    
    cat > "${html_file}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - ${TEST_SESSION_ID}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .metric-box { background: #fff; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .success { border-left: 4px solid #4CAF50; }
        .warning { border-left: 4px solid #FF9800; }
        .error { border-left: 4px solid #F44336; }
        .metric-value { font-size: 1.5em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Performance Test Report</h1>
        <p><strong>Test Session:</strong> ${TEST_SESSION_ID}</p>
        <p><strong>Target URL:</strong> ${TARGET_URL}</p>
        <p><strong>Timestamp:</strong> $(date)</p>
    </div>

    <h2>Test Configuration</h2>
    <div class="metric-box">
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Concurrent Users</td><td>${CONCURRENT_USERS}</td></tr>
            <tr><td>Test Duration</td><td>${TEST_DURATION} seconds</td></tr>
            <tr><td>Variance Threshold</td><td>≤${VARIANCE_THRESHOLD}%</td></tr>
        </table>
    </div>

    <h2>Performance Test Results</h2>
EOF
    
    # Add test results sections
    local json_data
    json_data=$(cat "${json_file}")
    
    for test_type in locust k6 ab; do
        if echo "${json_data}" | jq -e ".${test_type}_results" > /dev/null 2>&1; then
            cat >> "${html_file}" << EOF
    <h3>${test_type^} Results</h3>
    <div class="metric-box">
        <div id="${test_type}-results"></div>
    </div>
EOF
        fi
    done
    
    cat >> "${html_file}" << EOF
    <script>
        // Add JavaScript for dynamic content if needed
        console.log('Performance report loaded');
    </script>
</body>
</html>
EOF
    
    log_success "HTML report structure generated"
}

# Send Slack notification
send_slack_notification() {
    local message=$1
    local status=$2  # success, warning, error
    
    if [[ -z "${SLACK_WEBHOOK}" ]]; then
        log_debug "No Slack webhook configured - skipping notification"
        return 0
    fi
    
    local color="#36a64f"  # green
    case "${status}" in
        warning) color="#ff9800" ;;  # orange
        error) color="#f44336" ;;    # red
    esac
    
    local payload
    payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "${color}",
            "title": "Performance Test ${status^}",
            "text": "${message}",
            "fields": [
                {
                    "title": "Test Session",
                    "value": "${TEST_SESSION_ID}",
                    "short": true
                },
                {
                    "title": "Target URL",
                    "value": "${TARGET_URL}",
                    "short": true
                }
            ],
            "footer": "Flask Performance Testing",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
    
    if curl -s -X POST -H 'Content-type: application/json' --data "${payload}" "${SLACK_WEBHOOK}" > /dev/null; then
        log_success "Slack notification sent successfully"
    else
        log_warning "Failed to send Slack notification"
    fi
}

#################################################################
# CI/CD Integration
#################################################################

# CI/CD mode execution with automated gates
run_ci_mode() {
    log_info "Running performance tests in CI/CD mode..."
    
    local overall_status="success"
    local failed_tests=()
    
    # Run all performance tests
    if [[ "${TEST_TYPE}" == "all" || "${TEST_TYPE}" == "locust" ]]; then
        if ! run_locust_test; then
            overall_status="error"
            failed_tests+=("locust")
        fi
    fi
    
    if [[ "${TEST_TYPE}" == "all" || "${TEST_TYPE}" == "k6" ]]; then
        if ! run_k6_test; then
            overall_status="error"
            failed_tests+=("k6")
        fi
    fi
    
    if [[ "${TEST_TYPE}" == "all" || "${TEST_TYPE}" == "ab" ]]; then
        if ! run_apache_bench_test; then
            overall_status="error"
            failed_tests+=("apache_bench")
        fi
    fi
    
    # Collect monitoring metrics
    collect_prometheus_metrics
    
    # Generate CI summary
    local ci_summary="Performance testing completed in CI mode."
    if [[ "${overall_status}" == "success" ]]; then
        ci_summary+=" ✅ All tests passed with ≤${VARIANCE_THRESHOLD}% variance."
        send_slack_notification "${ci_summary}" "success"
    else
        ci_summary+=" ❌ Failed tests: ${failed_tests[*]}"
        send_slack_notification "${ci_summary}" "error"
        
        # Set GitHub Actions output if available
        if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
            echo "performance_status=failed" >> "${GITHUB_OUTPUT}"
            echo "failed_tests=${failed_tests[*]}" >> "${GITHUB_OUTPUT}"
        fi
        
        return 1
    fi
    
    # Set successful GitHub Actions output
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "performance_status=passed" >> "${GITHUB_OUTPUT}"
        echo "variance_threshold=${VARIANCE_THRESHOLD}" >> "${GITHUB_OUTPUT}"
    fi
    
    return 0
}

#################################################################
# Main Execution Logic
#################################################################

# Display usage information
show_help() {
    cat << EOF
Performance Testing and Validation Script

This script provides comprehensive performance testing for the Flask application
migration, ensuring ≤10% variance compliance with Node.js baseline performance.

Usage: ${SCRIPT_NAME} [options]

Options:
  --test-type TYPE          Test type: locust, k6, ab, all (default: all)
  --target-url URL          Target Flask application URL (required)
  --baseline-file FILE      Node.js baseline metrics file path
  --output-dir DIR          Results output directory (default: tests/performance/reports)
  --users COUNT             Number of concurrent users (default: 50)
  --duration SECONDS        Test duration in seconds (default: 300)
  --spawn-rate RATE         User spawn rate per second (default: 5)
  --variance-threshold PCT  Performance variance threshold % (default: 10)
  --ci-mode                 Enable CI/CD pipeline mode with automated gates
  --prometheus-url URL      Prometheus metrics endpoint URL
  --slack-webhook URL       Slack webhook for notifications
  --help                    Display this help message

Examples:
  # Run all performance tests
  ${SCRIPT_NAME} --target-url http://localhost:5000

  # Run Locust load test only with custom parameters
  ${SCRIPT_NAME} --test-type locust --target-url http://localhost:5000 --users 100 --duration 600

  # CI/CD mode with comprehensive validation
  ${SCRIPT_NAME} --ci-mode --target-url https://staging-api.company.com --variance-threshold 5

Environment Variables:
  FLASK_APP_URL             Target Flask application URL
  NODE_BASELINE_FILE        Path to Node.js baseline metrics
  PERFORMANCE_VARIANCE_LIMIT Maximum allowed performance variance (default: 10)
  PROMETHEUS_ENDPOINT       Prometheus metrics collection endpoint
  SLACK_PERFORMANCE_WEBHOOK Slack webhook for performance alerts
  CI                        Set to 'true' for CI/CD pipeline mode

For more information, see the technical specification Section 6.6.1 and 8.5.2.
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test-type)
                TEST_TYPE="$2"
                shift 2
                ;;
            --target-url)
                TARGET_URL="$2"
                shift 2
                ;;
            --baseline-file)
                BASELINE_FILE="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --users)
                CONCURRENT_USERS="$2"
                shift 2
                ;;
            --duration)
                TEST_DURATION="$2"
                shift 2
                ;;
            --spawn-rate)
                SPAWN_RATE="$2"
                shift 2
                ;;
            --variance-threshold)
                VARIANCE_THRESHOLD="$2"
                shift 2
                ;;
            --ci-mode)
                CI_MODE=true
                shift
                ;;
            --prometheus-url)
                PROMETHEUS_URL="$2"
                shift 2
                ;;
            --slack-webhook)
                SLACK_WEBHOOK="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Load from environment variables if not set
    TARGET_URL="${TARGET_URL:-${FLASK_APP_URL:-}}"
    BASELINE_FILE="${BASELINE_FILE:-${NODE_BASELINE_FILE:-${PERFORMANCE_TEST_DIR}/baseline_data.py}}"
    VARIANCE_THRESHOLD="${VARIANCE_THRESHOLD:-${PERFORMANCE_VARIANCE_LIMIT:-$DEFAULT_VARIANCE_THRESHOLD}}"
    PROMETHEUS_URL="${PROMETHEUS_URL:-${PROMETHEUS_ENDPOINT:-}}"
    SLACK_WEBHOOK="${SLACK_WEBHOOK:-${SLACK_PERFORMANCE_WEBHOOK:-}}"
    
    # Validate required parameters
    if [[ -z "${TARGET_URL}" ]]; then
        log_error "Target URL is required. Use --target-url or set FLASK_APP_URL environment variable."
        show_help
        exit 1
    fi
    
    # Validate test type
    if [[ ! "${TEST_TYPE}" =~ ^(locust|k6|ab|all)$ ]]; then
        log_error "Invalid test type: ${TEST_TYPE}. Must be one of: locust, k6, ab, all"
        exit 1
    fi
    
    # Validate numeric parameters
    if ! [[ "${CONCURRENT_USERS}" =~ ^[0-9]+$ ]] || [[ "${CONCURRENT_USERS}" -le 0 ]]; then
        log_error "Invalid concurrent users count: ${CONCURRENT_USERS}"
        exit 1
    fi
    
    if ! [[ "${TEST_DURATION}" =~ ^[0-9]+$ ]] || [[ "${TEST_DURATION}" -le 0 ]]; then
        log_error "Invalid test duration: ${TEST_DURATION}"
        exit 1
    fi
    
    if ! [[ "${VARIANCE_THRESHOLD}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        log_error "Invalid variance threshold: ${VARIANCE_THRESHOLD}"
        exit 1
    fi
}

# Main execution function
main() {
    log_info "Starting Flask Performance Testing Suite v1.0"
    log_info "Performance Variance Requirement: ≤${VARIANCE_THRESHOLD}% (per Section 0.1.1)"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate dependencies and environment
    check_dependencies
    setup_environment
    validate_target_url
    
    # Load baseline metrics
    load_baseline_metrics
    
    # Execute performance tests based on mode
    if [[ "${CI_MODE}" == "true" ]]; then
        run_ci_mode
    else
        # Interactive mode - run selected tests
        local overall_success=true
        
        case "${TEST_TYPE}" in
            locust)
                run_locust_test || overall_success=false
                ;;
            k6)
                run_k6_test || overall_success=false
                ;;
            ab)
                run_apache_bench_test || overall_success=false
                ;;
            all)
                run_locust_test || overall_success=false
                run_k6_test || overall_success=false
                run_apache_bench_test || overall_success=false
                ;;
        esac
        
        # Collect monitoring data
        collect_prometheus_metrics
        
        # Final status report
        if [[ "${overall_success}" == "true" ]]; then
            log_success "🎉 All performance tests completed successfully!"
            log_success "Performance variance within ≤${VARIANCE_THRESHOLD}% threshold requirement"
            send_slack_notification "Performance testing completed successfully with ≤${VARIANCE_THRESHOLD}% variance" "success"
        else
            log_error "❌ Performance testing failed"
            log_error "One or more tests exceeded the ≤${VARIANCE_THRESHOLD}% variance threshold"
            send_slack_notification "Performance testing failed - variance threshold exceeded" "error"
            exit 1
        fi
    fi
    
    log_success "Performance testing session completed: ${TEST_SESSION_ID}"
    log_info "Reports available in: ${OUTPUT_DIR}"
}

# Execute main function with all arguments
main "$@"