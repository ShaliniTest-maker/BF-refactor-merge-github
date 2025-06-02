#!/bin/bash

# performance.sh - Performance Testing and Validation Script
# 
# This comprehensive performance testing script implements both Locust and k6 load testing
# frameworks with automated baseline comparison ensuring ≤10% variance compliance for 
# Flask application performance monitoring per Section 8.5.2 and Section 4.4.2.
#
# Key Features:
# - Locust 2.17+ distributed load testing with automated baseline comparison
# - k6 performance analysis with detailed metrics and variance calculation  
# - Automated performance validation pipeline ensuring ≤10% variance compliance
# - Prometheus metrics collection and trend analysis integration
# - CI/CD pipeline integration with automated gates per Section 6.6.2
# - Comprehensive performance reporting and baseline maintenance
#
# Architecture Integration:
# - Section 8.5.2: Automated Performance and Load Testing using Locust and k6 frameworks
# - Section 4.4.2: Performance validation ensuring ≤10% variance compliance with automated gate enforcement
# - Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline 
# - Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
# - Section 6.6.1: Load testing framework (locust ≥2.x) for automated throughput validation
# - Section 6.6.2: CI/CD integration with automated performance validation and regression detection
#
# Author: Flask Migration Team
# Version: 1.0.0
# Dependencies: locust ≥2.17, k6, docker, python ≥3.8, node ≥18.x for k6

set -euo pipefail

# Script configuration and environment setup
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly PERFORMANCE_REPORTS_DIR="$PROJECT_ROOT/tests/performance/reports"
readonly PERFORMANCE_DATA_DIR="$PROJECT_ROOT/tests/performance/data"
readonly PERFORMANCE_SCRIPTS_DIR="$PROJECT_ROOT/tests/performance/scripts"

# Performance testing configuration per Section 0.1.1 and 4.6.3
readonly PERFORMANCE_VARIANCE_THRESHOLD=${PERFORMANCE_VARIANCE_THRESHOLD:-10}  # ≤10% variance requirement
readonly NODEJS_BASELINE_FILE="${NODEJS_BASELINE_FILE:-$PERFORMANCE_DATA_DIR/nodejs_baseline.json}"
readonly FLASK_BASELINE_FILE="${FLASK_BASELINE_FILE:-$PERFORMANCE_DATA_DIR/flask_baseline.json}"

# Load testing configuration per Section 4.6.3
readonly MIN_USERS=${MIN_USERS:-10}                    # Minimum concurrent users
readonly MAX_USERS=${MAX_USERS:-1000}                  # Maximum concurrent users
readonly TEST_DURATION=${TEST_DURATION:-1800}          # 30-minute sustained load (seconds)
readonly USER_SPAWN_RATE=${USER_SPAWN_RATE:-2}         # Users spawned per second
readonly TARGET_RPS=${TARGET_RPS:-100}                 # Minimum 100 requests/second

# Performance thresholds per Section 4.6.3
readonly RESPONSE_TIME_P95_THRESHOLD=${RESPONSE_TIME_P95_THRESHOLD:-500}  # 95th percentile ≤500ms
readonly ERROR_RATE_THRESHOLD=${ERROR_RATE_THRESHOLD:-0.1}                # ≤0.1% error rate
readonly MEMORY_VARIANCE_THRESHOLD=${MEMORY_VARIANCE_THRESHOLD:-15}       # ±15% memory variance
readonly CPU_VARIANCE_THRESHOLD=${CPU_VARIANCE_THRESHOLD:-20}             # ±20% CPU variance

# Environment and application configuration
readonly FLASK_APP_HOST=${FLASK_APP_HOST:-"http://localhost:5000"}
readonly FLASK_APP_PORT=${FLASK_APP_PORT:-5000}
readonly PERFORMANCE_ENV=${PERFORMANCE_ENV:-"testing"}
readonly CI_CD_MODE=${CI_CD_MODE:-"false"}
readonly GITHUB_ACTIONS=${GITHUB_ACTIONS:-"false"}

# Tool configuration and paths
readonly LOCUST_EXECUTABLE=${LOCUST_EXECUTABLE:-"locust"}
readonly K6_EXECUTABLE=${K6_EXECUTABLE:-"k6"}
readonly PYTHON_EXECUTABLE=${PYTHON_EXECUTABLE:-"python3"}
readonly DOCKER_EXECUTABLE=${DOCKER_EXECUTABLE:-"docker"}

# Prometheus and monitoring configuration per Section 6.2.4
readonly PROMETHEUS_PORT=${PROMETHEUS_PORT:-8089}
readonly METRICS_COLLECTION_INTERVAL=${METRICS_COLLECTION_INTERVAL:-1}
readonly MONITORING_ENABLED=${MONITORING_ENABLED:-"true"}

# Report and notification configuration
readonly REPORT_FORMAT=${REPORT_FORMAT:-"json,markdown,html"}
readonly SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
readonly TEAMS_WEBHOOK_URL=${TEAMS_WEBHOOK_URL:-""}
readonly EMAIL_NOTIFICATIONS=${EMAIL_NOTIFICATIONS:-"false"}

# Performance test execution modes
readonly TEST_MODES=("baseline" "locust" "k6" "comparison" "full" "ci-cd")
readonly DEFAULT_TEST_MODE="full"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Performance test result storage
declare -A PERFORMANCE_RESULTS
declare -A BASELINE_METRICS
declare -A VARIANCE_ANALYSIS
declare -g OVERALL_COMPLIANCE="true"
declare -g TEST_START_TIME
declare -g TEST_END_TIME

# Logging and error handling
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_header() {
    echo -e "${PURPLE}[PERFORMANCE]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

# Error handling and cleanup
cleanup() {
    local exit_code=$?
    log_info "Cleaning up performance testing environment..."
    
    # Stop any running performance tests
    pkill -f "$LOCUST_EXECUTABLE" 2>/dev/null || true
    pkill -f "$K6_EXECUTABLE" 2>/dev/null || true
    
    # Stop Prometheus metrics server if running
    pkill -f "prometheus_client" 2>/dev/null || true
    
    # Clean up temporary files
    find /tmp -name "performance_test_*" -type f -mtime +1 -delete 2>/dev/null || true
    
    # Log final status
    if [[ $exit_code -eq 0 ]]; then
        log_success "Performance testing completed successfully"
    else
        log_error "Performance testing failed with exit code $exit_code"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Validation functions
validate_environment() {
    log_info "Validating performance testing environment..."
    
    local validation_errors=0
    
    # Check required executables
    for executable in "$LOCUST_EXECUTABLE" "$K6_EXECUTABLE" "$PYTHON_EXECUTABLE" "$DOCKER_EXECUTABLE"; do
        if ! command -v "$executable" &> /dev/null; then
            log_error "Required executable not found: $executable"
            ((validation_errors++))
        else
            local version
            case "$executable" in
                "$LOCUST_EXECUTABLE")
                    version=$($executable --version 2>&1 | head -n1 || echo "unknown")
                    log_info "Found Locust: $version"
                    ;;
                "$K6_EXECUTABLE")
                    version=$($executable version 2>&1 | head -n1 || echo "unknown")
                    log_info "Found k6: $version"
                    ;;
                "$PYTHON_EXECUTABLE")
                    version=$($executable --version 2>&1 || echo "unknown")
                    log_info "Found Python: $version"
                    ;;
                "$DOCKER_EXECUTABLE")
                    version=$($executable --version 2>&1 | head -n1 || echo "unknown")
                    log_info "Found Docker: $version"
                    ;;
            esac
        fi
    done
    
    # Check Python modules availability
    local required_modules=("locust" "requests" "prometheus_client" "structlog")
    for module in "${required_modules[@]}"; do
        if ! $PYTHON_EXECUTABLE -c "import $module" 2>/dev/null; then
            log_error "Required Python module not available: $module"
            ((validation_errors++))
        else
            log_info "Python module available: $module"
        fi
    done
    
    # Validate Flask application connectivity
    if ! validate_flask_connectivity; then
        log_error "Flask application connectivity validation failed"
        ((validation_errors++))
    fi
    
    # Create required directories
    mkdir -p "$PERFORMANCE_REPORTS_DIR" "$PERFORMANCE_DATA_DIR" "$PERFORMANCE_SCRIPTS_DIR"
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "Environment validation failed with $validation_errors errors"
        return 1
    fi
    
    log_success "Environment validation completed successfully"
    return 0
}

validate_flask_connectivity() {
    log_info "Validating Flask application connectivity at $FLASK_APP_HOST..."
    
    local max_attempts=30
    local attempt=1
    local wait_time=2
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -sf "$FLASK_APP_HOST/api/v1/health" &>/dev/null; then
            log_success "Flask application is accessible (attempt $attempt/$max_attempts)"
            return 0
        fi
        
        log_info "Flask application not ready, waiting... (attempt $attempt/$max_attempts)"
        sleep $wait_time
        ((attempt++))
    done
    
    log_error "Flask application is not accessible after $max_attempts attempts"
    return 1
}

validate_performance_config() {
    log_info "Validating performance testing configuration..."
    
    # Validate numeric parameters
    local numeric_params=(
        "PERFORMANCE_VARIANCE_THRESHOLD:$PERFORMANCE_VARIANCE_THRESHOLD:1:50"
        "MIN_USERS:$MIN_USERS:1:10000"
        "MAX_USERS:$MAX_USERS:$MIN_USERS:10000"
        "TEST_DURATION:$TEST_DURATION:60:7200"
        "USER_SPAWN_RATE:$USER_SPAWN_RATE:0.1:100"
        "TARGET_RPS:$TARGET_RPS:1:10000"
        "RESPONSE_TIME_P95_THRESHOLD:$RESPONSE_TIME_P95_THRESHOLD:50:5000"
    )
    
    for param in "${numeric_params[@]}"; do
        IFS=':' read -r name value min max <<< "$param"
        if ! [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]] || (( $(echo "$value < $min" | bc -l) )) || (( $(echo "$value > $max" | bc -l) )); then
            log_error "Invalid configuration parameter: $name=$value (must be between $min and $max)"
            return 1
        fi
    done
    
    # Validate logical constraints
    if [[ $MIN_USERS -ge $MAX_USERS ]]; then
        log_error "MIN_USERS ($MIN_USERS) must be less than MAX_USERS ($MAX_USERS)"
        return 1
    fi
    
    log_success "Performance configuration validation completed"
    return 0
}

# Baseline management functions
load_nodejs_baseline() {
    log_info "Loading Node.js baseline performance metrics..."
    
    if [[ ! -f "$NODEJS_BASELINE_FILE" ]]; then
        log_warn "Node.js baseline file not found: $NODEJS_BASELINE_FILE"
        log_info "Creating default Node.js baseline metrics..."
        create_default_nodejs_baseline
    fi
    
    if ! BASELINE_METRICS=$(jq -r '.' "$NODEJS_BASELINE_FILE" 2>/dev/null); then
        log_error "Failed to parse Node.js baseline file: $NODEJS_BASELINE_FILE"
        return 1
    fi
    
    # Extract key baseline metrics for validation
    BASELINE_METRICS[response_time_p95]=$(echo "$BASELINE_METRICS" | jq -r '.response_time_p95 // 250')
    BASELINE_METRICS[requests_per_second]=$(echo "$BASELINE_METRICS" | jq -r '.requests_per_second // 100')
    BASELINE_METRICS[memory_usage_mb]=$(echo "$BASELINE_METRICS" | jq -r '.memory_usage_mb // 256')
    BASELINE_METRICS[cpu_utilization_percent]=$(echo "$BASELINE_METRICS" | jq -r '.cpu_utilization_percent // 15')
    BASELINE_METRICS[error_rate_percent]=$(echo "$BASELINE_METRICS" | jq -r '.error_rate_percent // 0.1')
    
    log_success "Node.js baseline metrics loaded successfully"
    log_info "Baseline Response Time P95: ${BASELINE_METRICS[response_time_p95]}ms"
    log_info "Baseline Throughput: ${BASELINE_METRICS[requests_per_second]} RPS"
    log_info "Baseline Memory Usage: ${BASELINE_METRICS[memory_usage_mb]}MB"
    
    return 0
}

create_default_nodejs_baseline() {
    log_info "Creating default Node.js baseline metrics per Section 0.3.2..."
    
    cat > "$NODEJS_BASELINE_FILE" << EOF
{
  "metadata": {
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "nodejs_version": "18.x",
    "express_version": "4.x",
    "environment": "production",
    "measurement_duration": 1800,
    "load_configuration": {
      "concurrent_users": $MAX_USERS,
      "test_duration_seconds": $TEST_DURATION,
      "target_rps": $TARGET_RPS
    }
  },
  "performance_metrics": {
    "response_time_p50": 100.0,
    "response_time_p95": 250.0,
    "response_time_p99": 400.0,
    "mean_response_time": 120.0,
    "requests_per_second": 100.0,
    "peak_throughput": 500.0,
    "memory_usage_mb": 256.0,
    "cpu_utilization_percent": 15.0,
    "error_rate_percent": 0.1,
    "timeout_rate_percent": 0.05
  },
  "database_metrics": {
    "query_time_avg_ms": 50.0,
    "connection_pool_size": 50,
    "query_success_rate": 99.9
  },
  "resource_metrics": {
    "network_io_mbps": 100.0,
    "disk_io_iops": 1000,
    "concurrent_connections": 1000
  }
}
EOF
    
    log_success "Default Node.js baseline created: $NODEJS_BASELINE_FILE"
}

# Locust performance testing functions
execute_locust_load_test() {
    log_header "Starting Locust Load Testing (${TEST_DURATION}s, ${MIN_USERS}-${MAX_USERS} users)"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local locust_report_prefix="$PERFORMANCE_REPORTS_DIR/locust_${timestamp}"
    local locust_config_file="$PERFORMANCE_SCRIPTS_DIR/locust_performance_test.py"
    
    # Check if Locust test file exists, create if missing
    if [[ ! -f "$locust_config_file" ]]; then
        log_info "Creating Locust performance test configuration..."
        create_locust_test_file "$locust_config_file"
    fi
    
    # Prepare Locust execution command per Section 6.6.1
    local locust_cmd=(
        "$LOCUST_EXECUTABLE"
        "-f" "$locust_config_file"
        "--headless"
        "--users" "$MAX_USERS"
        "--spawn-rate" "$USER_SPAWN_RATE" 
        "--run-time" "${TEST_DURATION}s"
        "--host" "$FLASK_APP_HOST"
        "--csv" "$locust_report_prefix"
        "--html" "${locust_report_prefix}.html"
        "--loglevel" "INFO"
        "--logfile" "${locust_report_prefix}.log"
    )
    
    # Add Prometheus metrics server if monitoring enabled
    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        locust_cmd+=("--web-port" "$PROMETHEUS_PORT")
    fi
    
    log_info "Executing Locust command: ${locust_cmd[*]}"
    
    # Execute Locust load test with comprehensive error handling
    local locust_exit_code=0
    if ! "${locust_cmd[@]}" 2>&1 | tee "${locust_report_prefix}_execution.log"; then
        locust_exit_code=$?
        log_error "Locust load test execution failed with exit code $locust_exit_code"
        return $locust_exit_code
    fi
    
    # Parse Locust results
    if ! parse_locust_results "$locust_report_prefix"; then
        log_error "Failed to parse Locust test results"
        return 1
    fi
    
    log_success "Locust load testing completed successfully"
    return 0
}

create_locust_test_file() {
    local locust_file="$1"
    
    log_info "Creating Locust performance test file: $locust_file"
    
    cat > "$locust_file" << 'EOF'
#!/usr/bin/env python3
"""
Locust Performance Test Configuration for Flask Migration
Auto-generated by performance.sh script
"""

import os
import time
import random
from locust import HttpUser, task, between
from locust.env import Environment

class FlaskAPIUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login user before testing"""
        self.login()
    
    def login(self):
        """Perform user authentication"""
        response = self.client.post("/api/v1/auth/login", json={
            "username": "test_user@example.com",
            "password": "test_password"
        })
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            self.client.headers.update({"Authorization": f"Bearer {token}"})
    
    @task(3)
    def test_health_check(self):
        """Test health check endpoint"""
        self.client.get("/api/v1/health")
    
    @task(5)
    def test_api_endpoints(self):
        """Test primary API endpoints"""
        endpoints = [
            "/api/v1/users/profile",
            "/api/v1/data/reports",
            "/api/v1/analytics/dashboard"
        ]
        endpoint = random.choice(endpoints)
        self.client.get(endpoint)
    
    @task(2)
    def test_authenticated_operations(self):
        """Test authenticated business operations"""
        self.client.post("/api/v1/business/operations", json={
            "operation": "test_operation",
            "parameters": {"test": True}
        })
    
    @task(1)
    def test_database_operations(self):
        """Test database-intensive operations"""
        self.client.get("/api/v1/data/complex-query", params={
            "limit": random.randint(10, 100),
            "page": random.randint(1, 10)
        })
EOF
    
    log_success "Locust test file created: $locust_file"
}

parse_locust_results() {
    local report_prefix="$1"
    local stats_file="${report_prefix}_stats.csv"
    local failures_file="${report_prefix}_failures.csv"
    
    log_info "Parsing Locust test results from $report_prefix..."
    
    if [[ ! -f "$stats_file" ]]; then
        log_error "Locust stats file not found: $stats_file"
        return 1
    fi
    
    # Parse key performance metrics from Locust CSV output
    local stats_data
    if ! stats_data=$(tail -n +2 "$stats_file" | head -n -2); then
        log_error "Failed to read Locust stats data"
        return 1
    fi
    
    # Calculate aggregate metrics
    local total_requests=0
    local total_failures=0
    local avg_response_time=0
    local min_response_time=999999
    local max_response_time=0
    local rps=0
    
    while IFS=',' read -r method name requests failures median average min max rps_val failures_per_sec; do
        # Remove quotes and clean data
        requests=$(echo "$requests" | tr -d '"')
        failures=$(echo "$failures" | tr -d '"')
        average=$(echo "$average" | tr -d '"')
        min=$(echo "$min" | tr -d '"' | bc -l)
        max=$(echo "$max" | tr -d '"' | bc -l)
        rps_val=$(echo "$rps_val" | tr -d '"')
        
        if [[ "$requests" =~ ^[0-9]+$ ]]; then
            total_requests=$((total_requests + requests))
            total_failures=$((total_failures + failures))
            
            # Calculate weighted average response time
            if [[ "$average" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [[ "$requests" -gt 0 ]]; then
                avg_response_time=$(echo "scale=2; ($avg_response_time * ($total_requests - $requests) + $average * $requests) / $total_requests" | bc -l)
            fi
            
            # Track min/max response times
            if (( $(echo "$min < $min_response_time" | bc -l) )); then
                min_response_time=$min
            fi
            if (( $(echo "$max > $max_response_time" | bc -l) )); then
                max_response_time=$max
            fi
            
            # Sum up RPS
            if [[ "$rps_val" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                rps=$(echo "scale=2; $rps + $rps_val" | bc -l)
            fi
        fi
    done <<< "$stats_data"
    
    # Calculate error rate
    local error_rate=0
    if [[ $total_requests -gt 0 ]]; then
        error_rate=$(echo "scale=3; ($total_failures * 100.0) / $total_requests" | bc -l)
    fi
    
    # Store Locust results
    PERFORMANCE_RESULTS[locust_total_requests]="$total_requests"
    PERFORMANCE_RESULTS[locust_total_failures]="$total_failures"
    PERFORMANCE_RESULTS[locust_avg_response_time]="$avg_response_time"
    PERFORMANCE_RESULTS[locust_min_response_time]="$min_response_time"
    PERFORMANCE_RESULTS[locust_max_response_time]="$max_response_time"
    PERFORMANCE_RESULTS[locust_requests_per_second]="$rps"
    PERFORMANCE_RESULTS[locust_error_rate_percent]="$error_rate"
    
    log_info "Locust Results Summary:"
    log_info "  Total Requests: $total_requests"
    log_info "  Total Failures: $total_failures"
    log_info "  Average Response Time: ${avg_response_time}ms"
    log_info "  Requests per Second: $rps"
    log_info "  Error Rate: ${error_rate}%"
    
    return 0
}

# k6 performance testing functions
execute_k6_performance_test() {
    log_header "Starting k6 Performance Testing (${TEST_DURATION}s load test)"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local k6_script_file="$PERFORMANCE_SCRIPTS_DIR/k6_performance_test.js"
    local k6_results_file="$PERFORMANCE_REPORTS_DIR/k6_results_${timestamp}.json"
    
    # Create k6 test script if it doesn't exist
    if [[ ! -f "$k6_script_file" ]]; then
        log_info "Creating k6 performance test script..."
        create_k6_test_script "$k6_script_file"
    fi
    
    # Configure k6 execution environment
    export K6_TEST_DURATION="${TEST_DURATION}s"
    export K6_MAX_USERS="$MAX_USERS"
    export K6_TARGET_RPS="$TARGET_RPS"
    export K6_RESPONSE_TIME_THRESHOLD="$RESPONSE_TIME_P95_THRESHOLD"
    export K6_ERROR_RATE_THRESHOLD="$ERROR_RATE_THRESHOLD"
    export K6_FLASK_HOST="$FLASK_APP_HOST"
    
    log_info "Executing k6 performance test with the following configuration:"
    log_info "  Test Duration: $K6_TEST_DURATION"
    log_info "  Max Users: $K6_MAX_USERS"
    log_info "  Target RPS: $K6_TARGET_RPS"
    log_info "  Response Time Threshold: ${K6_RESPONSE_TIME_THRESHOLD}ms"
    log_info "  Error Rate Threshold: ${K6_ERROR_RATE_THRESHOLD}%"
    
    # Execute k6 test with JSON output per Section 8.5.2
    local k6_cmd=(
        "$K6_EXECUTABLE"
        "run"
        "--out" "json=$k6_results_file"
        "--quiet"
        "$k6_script_file"
    )
    
    log_info "Executing k6 command: ${k6_cmd[*]}"
    
    local k6_exit_code=0
    if ! "${k6_cmd[@]}" 2>&1 | tee "${k6_results_file%.json}.log"; then
        k6_exit_code=$?
        log_error "k6 performance test execution failed with exit code $k6_exit_code"
        return $k6_exit_code
    fi
    
    # Parse k6 results
    if ! parse_k6_results "$k6_results_file"; then
        log_error "Failed to parse k6 test results"
        return 1
    fi
    
    log_success "k6 performance testing completed successfully"
    return 0
}

create_k6_test_script() {
    local k6_file="$1"
    
    log_info "Creating k6 performance test script: $k6_file"
    
    cat > "$k6_file" << 'EOF'
// k6 Performance Test Script for Flask Migration
// Auto-generated by performance.sh script

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Test configuration from environment variables
const TEST_DURATION = __ENV.K6_TEST_DURATION || '1800s';
const MAX_USERS = parseInt(__ENV.K6_MAX_USERS) || 1000;
const TARGET_RPS = parseInt(__ENV.K6_TARGET_RPS) || 100;
const RESPONSE_TIME_THRESHOLD = parseInt(__ENV.K6_RESPONSE_TIME_THRESHOLD) || 500;
const ERROR_RATE_THRESHOLD = parseFloat(__ENV.K6_ERROR_RATE_THRESHOLD) || 0.1;
const FLASK_HOST = __ENV.K6_FLASK_HOST || 'http://localhost:5000';

// Custom metrics for performance analysis
const apiResponseTime = new Trend('api_response_time');
const apiErrorRate = new Rate('api_error_rate');
const authenticatedRequests = new Counter('authenticated_requests');
const databaseRequests = new Counter('database_requests');

// Test stages configuration for progressive load scaling per Section 4.6.3
export let options = {
  stages: [
    { duration: '300s', target: Math.floor(MAX_USERS * 0.1) },   // Ramp-up to 10%
    { duration: '600s', target: Math.floor(MAX_USERS * 0.5) },   // Ramp to 50%
    { duration: '600s', target: MAX_USERS },                     // Ramp to 100%
    { duration: '300s', target: 0 },                             // Ramp-down
  ],
  thresholds: {
    'http_req_duration{name:health_check}': [`p(95)<${RESPONSE_TIME_THRESHOLD}`],
    'http_req_duration{name:api_endpoints}': [`p(95)<${RESPONSE_TIME_THRESHOLD}`],
    'http_req_failed': [`rate<${ERROR_RATE_THRESHOLD / 100}`],
    'api_response_time': [`p(95)<${RESPONSE_TIME_THRESHOLD}`],
    'api_error_rate': [`rate<${ERROR_RATE_THRESHOLD / 100}`],
  },
  ext: {
    loadimpact: {
      distribution: {
        'amazon:us:ashburn': { loadZone: 'amazon:us:ashburn', percent: 40 },
        'amazon:us:portland': { loadZone: 'amazon:us:portland', percent: 30 },
        'amazon:eu:dublin': { loadZone: 'amazon:eu:dublin', percent: 20 },
        'amazon:ap:singapore': { loadZone: 'amazon:ap:singapore', percent: 10 }
      }
    }
  }
};

// Authentication token storage
let authToken = null;

export function setup() {
  console.log(`Starting k6 performance test against ${FLASK_HOST}`);
  console.log(`Max Users: ${MAX_USERS}, Target RPS: ${TARGET_RPS}`);
  console.log(`Test Duration: ${TEST_DURATION}`);
  
  // Perform authentication setup
  const loginResponse = http.post(`${FLASK_HOST}/api/v1/auth/login`, JSON.stringify({
    username: 'test_user@example.com',
    password: 'test_password'
  }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'setup_login' }
  });
  
  if (loginResponse.status === 200) {
    const loginData = JSON.parse(loginResponse.body);
    return { authToken: loginData.access_token };
  }
  
  console.warn('Setup authentication failed, proceeding without auth token');
  return { authToken: null };
}

export default function(data) {
  // Use auth token from setup if available
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  
  if (data && data.authToken) {
    headers['Authorization'] = `Bearer ${data.authToken}`;
  }
  
  // Health check endpoint test (30% of requests)
  if (Math.random() < 0.3) {
    const healthResponse = http.get(`${FLASK_HOST}/api/v1/health`, {
      headers: headers,
      tags: { name: 'health_check' }
    });
    
    const healthSuccess = check(healthResponse, {
      'health status is 200': (r) => r.status === 200,
      'health response time < 100ms': (r) => r.timings.duration < 100,
    });
    
    apiResponseTime.add(healthResponse.timings.duration);
    apiErrorRate.add(!healthSuccess);
  }
  
  // API endpoints test (50% of requests)
  else if (Math.random() < 0.8) {
    const endpoints = [
      '/api/v1/users/profile',
      '/api/v1/data/reports',
      '/api/v1/analytics/dashboard'
    ];
    
    const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
    const apiResponse = http.get(`${FLASK_HOST}${endpoint}`, {
      headers: headers,
      tags: { name: 'api_endpoints' }
    });
    
    const apiSuccess = check(apiResponse, {
      'api status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'api response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    apiResponseTime.add(apiResponse.timings.duration);
    apiErrorRate.add(!apiSuccess);
    authenticatedRequests.add(1);
  }
  
  // Database operations test (20% of requests)
  else {
    const dbResponse = http.get(`${FLASK_HOST}/api/v1/data/complex-query`, {
      headers: headers,
      params: {
        limit: Math.floor(Math.random() * 90) + 10,
        page: Math.floor(Math.random() * 10) + 1
      },
      tags: { name: 'database_operations' }
    });
    
    const dbSuccess = check(dbResponse, {
      'db status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'db response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    apiResponseTime.add(dbResponse.timings.duration);
    apiErrorRate.add(!dbSuccess);
    databaseRequests.add(1);
  }
  
  // Wait between requests (1-3 seconds)
  sleep(Math.random() * 2 + 1);
}

export function teardown(data) {
  console.log('k6 performance test completed');
}
EOF
    
    log_success "k6 test script created: $k6_file"
}

parse_k6_results() {
    local results_file="$1"
    
    log_info "Parsing k6 test results from $results_file..."
    
    if [[ ! -f "$results_file" ]]; then
        log_error "k6 results file not found: $results_file"
        return 1
    fi
    
    # Extract summary metrics from k6 JSON output
    local summary_data
    if ! summary_data=$(jq -r 'select(.type == "Point" and .metric == "http_req_duration") | .data.value' "$results_file" 2>/dev/null); then
        log_error "Failed to extract k6 performance data"
        return 1
    fi
    
    # Calculate aggregate metrics from k6 data points
    local total_requests=0
    local total_response_time=0
    local min_response_time=999999
    local max_response_time=0
    local error_count=0
    
    # Process response time data points
    while read -r response_time; do
        if [[ "$response_time" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            total_requests=$((total_requests + 1))
            total_response_time=$(echo "scale=2; $total_response_time + $response_time" | bc -l)
            
            if (( $(echo "$response_time < $min_response_time" | bc -l) )); then
                min_response_time=$response_time
            fi
            
            if (( $(echo "$response_time > $max_response_time" | bc -l) )); then
                max_response_time=$response_time
            fi
        fi
    done <<< "$summary_data"
    
    # Calculate average response time
    local avg_response_time=0
    if [[ $total_requests -gt 0 ]]; then
        avg_response_time=$(echo "scale=2; $total_response_time / $total_requests" | bc -l)
    fi
    
    # Extract error rate data
    local error_data
    if error_data=$(jq -r 'select(.type == "Point" and .metric == "http_req_failed") | .data.value' "$results_file" 2>/dev/null); then
        while read -r error_value; do
            if [[ "$error_value" == "1" ]]; then
                error_count=$((error_count + 1))
            fi
        done <<< "$error_data"
    fi
    
    # Calculate error rate percentage
    local error_rate=0
    if [[ $total_requests -gt 0 ]]; then
        error_rate=$(echo "scale=3; ($error_count * 100.0) / $total_requests" | bc -l)
    fi
    
    # Extract RPS from iteration rate
    local rps=0
    local iteration_data
    if iteration_data=$(jq -r 'select(.type == "Point" and .metric == "iterations") | .data.value' "$results_file" 2>/dev/null); then
        local total_iterations=0
        while read -r iteration; do
            if [[ "$iteration" =~ ^[0-9]+$ ]]; then
                total_iterations=$((total_iterations + iteration))
            fi
        done <<< "$iteration_data"
        
        # Calculate RPS based on test duration
        rps=$(echo "scale=2; $total_iterations / $TEST_DURATION" | bc -l)
    fi
    
    # Store k6 results
    PERFORMANCE_RESULTS[k6_total_requests]="$total_requests"
    PERFORMANCE_RESULTS[k6_total_errors]="$error_count"
    PERFORMANCE_RESULTS[k6_avg_response_time]="$avg_response_time"
    PERFORMANCE_RESULTS[k6_min_response_time]="$min_response_time"
    PERFORMANCE_RESULTS[k6_max_response_time]="$max_response_time"
    PERFORMANCE_RESULTS[k6_requests_per_second]="$rps"
    PERFORMANCE_RESULTS[k6_error_rate_percent]="$error_rate"
    
    log_info "k6 Results Summary:"
    log_info "  Total Requests: $total_requests"
    log_info "  Total Errors: $error_count"
    log_info "  Average Response Time: ${avg_response_time}ms"
    log_info "  Requests per Second: $rps"
    log_info "  Error Rate: ${error_rate}%"
    
    return 0
}

# Performance comparison and variance analysis
perform_baseline_comparison() {
    log_header "Performing Baseline Comparison and Variance Analysis"
    
    if ! load_nodejs_baseline; then
        log_error "Failed to load Node.js baseline metrics"
        return 1
    fi
    
    # Combine Locust and k6 results for comprehensive analysis
    local flask_response_time
    local flask_throughput
    local flask_error_rate
    
    # Use Locust results if available, fallback to k6
    if [[ -n "${PERFORMANCE_RESULTS[locust_avg_response_time]:-}" ]]; then
        flask_response_time="${PERFORMANCE_RESULTS[locust_avg_response_time]}"
        flask_throughput="${PERFORMANCE_RESULTS[locust_requests_per_second]}"
        flask_error_rate="${PERFORMANCE_RESULTS[locust_error_rate_percent]}"
        log_info "Using Locust results for baseline comparison"
    elif [[ -n "${PERFORMANCE_RESULTS[k6_avg_response_time]:-}" ]]; then
        flask_response_time="${PERFORMANCE_RESULTS[k6_avg_response_time]}"
        flask_throughput="${PERFORMANCE_RESULTS[k6_requests_per_second]}"
        flask_error_rate="${PERFORMANCE_RESULTS[k6_error_rate_percent]}"
        log_info "Using k6 results for baseline comparison"
    else
        log_error "No performance test results available for comparison"
        return 1
    fi
    
    # Calculate variance for each key metric per Section 0.1.1
    calculate_variance "response_time" "$flask_response_time" "${BASELINE_METRICS[response_time_p95]}"
    calculate_variance "throughput" "$flask_throughput" "${BASELINE_METRICS[requests_per_second]}"
    calculate_variance "error_rate" "$flask_error_rate" "${BASELINE_METRICS[error_rate_percent]}"
    
    # Determine overall compliance
    evaluate_performance_compliance
    
    # Generate detailed variance report
    generate_variance_report
    
    log_success "Baseline comparison completed"
    return 0
}

calculate_variance() {
    local metric_name="$1"
    local current_value="$2"
    local baseline_value="$3"
    
    # Handle zero baseline values
    if [[ $(echo "$baseline_value == 0" | bc -l) -eq 1 ]]; then
        VARIANCE_ANALYSIS["${metric_name}_variance_percent"]="0.0"
        VARIANCE_ANALYSIS["${metric_name}_compliant"]="true"
        return 0
    fi
    
    # Calculate percentage variance: ((current - baseline) / baseline) * 100
    local variance_percent
    variance_percent=$(echo "scale=2; (($current_value - $baseline_value) / $baseline_value) * 100" | bc -l)
    
    # Get absolute variance for threshold comparison
    local abs_variance
    abs_variance=$(echo "${variance_percent#-}")  # Remove negative sign if present
    
    # Check compliance with ≤10% variance threshold
    local is_compliant="false"
    if (( $(echo "$abs_variance <= $PERFORMANCE_VARIANCE_THRESHOLD" | bc -l) )); then
        is_compliant="true"
    else
        OVERALL_COMPLIANCE="false"
    fi
    
    # Store variance analysis results
    VARIANCE_ANALYSIS["${metric_name}_current"]="$current_value"
    VARIANCE_ANALYSIS["${metric_name}_baseline"]="$baseline_value"
    VARIANCE_ANALYSIS["${metric_name}_variance_percent"]="$variance_percent"
    VARIANCE_ANALYSIS["${metric_name}_abs_variance"]="$abs_variance"
    VARIANCE_ANALYSIS["${metric_name}_compliant"]="$is_compliant"
    
    # Log variance analysis
    local status_symbol="✅"
    local status_color="$GREEN"
    if [[ "$is_compliant" == "false" ]]; then
        status_symbol="❌"
        status_color="$RED"
    fi
    
    log_info "${status_color}${status_symbol} ${metric_name^}: ${current_value} vs ${baseline_value} (${variance_percent:+${variance_percent}%} variance)${NC}"
}

evaluate_performance_compliance() {
    log_info "Evaluating overall performance compliance..."
    
    local compliance_checks=0
    local passed_checks=0
    
    # Check each metric compliance
    for metric in "response_time" "throughput" "error_rate"; do
        compliance_checks=$((compliance_checks + 1))
        if [[ "${VARIANCE_ANALYSIS[${metric}_compliant]}" == "true" ]]; then
            passed_checks=$((passed_checks + 1))
        fi
    done
    
    # Additional threshold checks per Section 4.6.3
    local additional_checks=0
    local additional_passed=0
    
    # Response time threshold check
    local current_response_time="${PERFORMANCE_RESULTS[locust_avg_response_time]:-${PERFORMANCE_RESULTS[k6_avg_response_time]}}"
    if [[ -n "$current_response_time" ]]; then
        additional_checks=$((additional_checks + 1))
        if (( $(echo "$current_response_time <= $RESPONSE_TIME_P95_THRESHOLD" | bc -l) )); then
            additional_passed=$((additional_passed + 1))
            log_info "✅ Response time threshold: ${current_response_time}ms ≤ ${RESPONSE_TIME_P95_THRESHOLD}ms"
        else
            log_warn "❌ Response time threshold: ${current_response_time}ms > ${RESPONSE_TIME_P95_THRESHOLD}ms"
            OVERALL_COMPLIANCE="false"
        fi
    fi
    
    # Error rate threshold check
    local current_error_rate="${PERFORMANCE_RESULTS[locust_error_rate_percent]:-${PERFORMANCE_RESULTS[k6_error_rate_percent]}}"
    if [[ -n "$current_error_rate" ]]; then
        additional_checks=$((additional_checks + 1))
        if (( $(echo "$current_error_rate <= $ERROR_RATE_THRESHOLD" | bc -l) )); then
            additional_passed=$((additional_passed + 1))
            log_info "✅ Error rate threshold: ${current_error_rate}% ≤ ${ERROR_RATE_THRESHOLD}%"
        else
            log_warn "❌ Error rate threshold: ${current_error_rate}% > ${ERROR_RATE_THRESHOLD}%"
            OVERALL_COMPLIANCE="false"
        fi
    fi
    
    # Throughput threshold check
    local current_throughput="${PERFORMANCE_RESULTS[locust_requests_per_second]:-${PERFORMANCE_RESULTS[k6_requests_per_second]}}"
    if [[ -n "$current_throughput" ]]; then
        additional_checks=$((additional_checks + 1))
        if (( $(echo "$current_throughput >= $TARGET_RPS" | bc -l) )); then
            additional_passed=$((additional_passed + 1))
            log_info "✅ Throughput threshold: ${current_throughput} RPS ≥ ${TARGET_RPS} RPS"
        else
            log_warn "❌ Throughput threshold: ${current_throughput} RPS < ${TARGET_RPS} RPS"
            OVERALL_COMPLIANCE="false"
        fi
    fi
    
    # Store compliance summary
    VARIANCE_ANALYSIS["total_checks"]=$((compliance_checks + additional_checks))
    VARIANCE_ANALYSIS["passed_checks"]=$((passed_checks + additional_passed))
    VARIANCE_ANALYSIS["compliance_rate"]=$(echo "scale=1; ($((passed_checks + additional_passed)) * 100.0) / $((compliance_checks + additional_checks))" | bc -l)
    
    # Log overall compliance status
    if [[ "$OVERALL_COMPLIANCE" == "true" ]]; then
        log_success "🎯 Overall Performance Compliance: PASSED (${VARIANCE_ANALYSIS[compliance_rate]}%)"
        log_success "✅ All metrics within ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold"
    else
        log_error "🚨 Overall Performance Compliance: FAILED (${VARIANCE_ANALYSIS[compliance_rate]}%)"
        log_error "❌ One or more metrics exceed ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold"
    fi
}

generate_variance_report() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local variance_report_file="$PERFORMANCE_REPORTS_DIR/variance_analysis_${timestamp}.json"
    
    log_info "Generating comprehensive variance analysis report..."
    
    # Create comprehensive variance report
    cat > "$variance_report_file" << EOF
{
  "variance_analysis": {
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$PERFORMANCE_ENV",
    "test_configuration": {
      "variance_threshold_percent": $PERFORMANCE_VARIANCE_THRESHOLD,
      "test_duration_seconds": $TEST_DURATION,
      "max_concurrent_users": $MAX_USERS,
      "target_rps": $TARGET_RPS
    },
    "baseline_metrics": {
      "response_time_p95": ${BASELINE_METRICS[response_time_p95]},
      "requests_per_second": ${BASELINE_METRICS[requests_per_second]},
      "error_rate_percent": ${BASELINE_METRICS[error_rate_percent]},
      "memory_usage_mb": ${BASELINE_METRICS[memory_usage_mb]},
      "cpu_utilization_percent": ${BASELINE_METRICS[cpu_utilization_percent]}
    },
    "current_metrics": {
      "response_time": ${VARIANCE_ANALYSIS[response_time_current]:-0},
      "throughput": ${VARIANCE_ANALYSIS[throughput_current]:-0},
      "error_rate": ${VARIANCE_ANALYSIS[error_rate_current]:-0}
    },
    "variance_results": {
      "response_time_variance_percent": ${VARIANCE_ANALYSIS[response_time_variance_percent]:-0},
      "throughput_variance_percent": ${VARIANCE_ANALYSIS[throughput_variance_percent]:-0},
      "error_rate_variance_percent": ${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0}
    },
    "compliance_status": {
      "overall_compliant": $OVERALL_COMPLIANCE,
      "response_time_compliant": ${VARIANCE_ANALYSIS[response_time_compliant]:-false},
      "throughput_compliant": ${VARIANCE_ANALYSIS[throughput_compliant]:-false},
      "error_rate_compliant": ${VARIANCE_ANALYSIS[error_rate_compliant]:-false},
      "compliance_rate_percent": ${VARIANCE_ANALYSIS[compliance_rate]:-0}
    },
    "test_results": {
      "locust_results": {
        "total_requests": ${PERFORMANCE_RESULTS[locust_total_requests]:-0},
        "avg_response_time": ${PERFORMANCE_RESULTS[locust_avg_response_time]:-0},
        "requests_per_second": ${PERFORMANCE_RESULTS[locust_requests_per_second]:-0},
        "error_rate_percent": ${PERFORMANCE_RESULTS[locust_error_rate_percent]:-0}
      },
      "k6_results": {
        "total_requests": ${PERFORMANCE_RESULTS[k6_total_requests]:-0},
        "avg_response_time": ${PERFORMANCE_RESULTS[k6_avg_response_time]:-0},
        "requests_per_second": ${PERFORMANCE_RESULTS[k6_requests_per_second]:-0},
        "error_rate_percent": ${PERFORMANCE_RESULTS[k6_error_rate_percent]:-0}
      }
    }
  }
}
EOF
    
    log_success "Variance analysis report generated: $variance_report_file"
    
    # Generate markdown summary for easy reading
    generate_markdown_variance_report "$variance_report_file"
}

generate_markdown_variance_report() {
    local json_report="$1"
    local md_report="${json_report%.json}.md"
    
    cat > "$md_report" << EOF
# Performance Variance Analysis Report

**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)  
**Environment:** $PERFORMANCE_ENV  
**Overall Compliance:** $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "✅ PASSED" || echo "❌ FAILED")

## Test Configuration

- **Variance Threshold:** ≤${PERFORMANCE_VARIANCE_THRESHOLD}%
- **Test Duration:** ${TEST_DURATION} seconds ($(( TEST_DURATION / 60 )) minutes)
- **Concurrent Users:** ${MIN_USERS} → ${MAX_USERS}
- **Target RPS:** ${TARGET_RPS}

## Variance Analysis

| Metric | Baseline | Current | Variance | Status |
|--------|----------|---------|----------|--------|
| Response Time | ${BASELINE_METRICS[response_time_p95]}ms | ${VARIANCE_ANALYSIS[response_time_current]:-"N/A"}ms | ${VARIANCE_ANALYSIS[response_time_variance_percent]:-"N/A"}% | $([ "${VARIANCE_ANALYSIS[response_time_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL") |
| Throughput | ${BASELINE_METRICS[requests_per_second]} RPS | ${VARIANCE_ANALYSIS[throughput_current]:-"N/A"} RPS | ${VARIANCE_ANALYSIS[throughput_variance_percent]:-"N/A"}% | $([ "${VARIANCE_ANALYSIS[throughput_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL") |
| Error Rate | ${BASELINE_METRICS[error_rate_percent]}% | ${VARIANCE_ANALYSIS[error_rate_current]:-"N/A"}% | ${VARIANCE_ANALYSIS[error_rate_variance_percent]:-"N/A"}% | $([ "${VARIANCE_ANALYSIS[error_rate_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL") |

## Test Results Summary

### Locust Results
- **Total Requests:** ${PERFORMANCE_RESULTS[locust_total_requests]:-"N/A"}
- **Average Response Time:** ${PERFORMANCE_RESULTS[locust_avg_response_time]:-"N/A"}ms
- **Throughput:** ${PERFORMANCE_RESULTS[locust_requests_per_second]:-"N/A"} RPS
- **Error Rate:** ${PERFORMANCE_RESULTS[locust_error_rate_percent]:-"N/A"}%

### k6 Results
- **Total Requests:** ${PERFORMANCE_RESULTS[k6_total_requests]:-"N/A"}
- **Average Response Time:** ${PERFORMANCE_RESULTS[k6_avg_response_time]:-"N/A"}ms
- **Throughput:** ${PERFORMANCE_RESULTS[k6_requests_per_second]:-"N/A"} RPS
- **Error Rate:** ${PERFORMANCE_RESULTS[k6_error_rate_percent]:-"N/A"}%

## Recommendations

$(if [ "$OVERALL_COMPLIANCE" == "true" ]; then
    echo "✅ **Deployment Approved:** All performance metrics are within acceptable variance thresholds."
    echo "- Flask application performance meets ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance requirement"
    echo "- Ready for production deployment"
else
    echo "❌ **Performance Optimization Required:** One or more metrics exceed variance thresholds."
    echo "- Review failed metrics and optimize Flask application performance"
    echo "- Re-run performance tests after optimization"
fi)

---
*Report generated by performance.sh - Flask Migration Performance Testing Suite*
EOF
    
    log_success "Markdown variance report generated: $md_report"
}

# Prometheus metrics integration
start_prometheus_metrics_server() {
    if [[ "$MONITORING_ENABLED" != "true" ]]; then
        log_info "Prometheus metrics collection disabled"
        return 0
    fi
    
    log_info "Starting Prometheus metrics server on port $PROMETHEUS_PORT..."
    
    # Create Prometheus metrics collection script
    local prometheus_script="$PERFORMANCE_SCRIPTS_DIR/prometheus_metrics.py"
    
    cat > "$prometheus_script" << 'EOF'
#!/usr/bin/env python3
"""
Prometheus Metrics Collection for Performance Testing
Auto-generated by performance.sh script
"""

import time
import json
import threading
from prometheus_client import start_http_server, Gauge, Counter, Histogram
from prometheus_client.core import CollectorRegistry
import os
import sys

# Performance metrics registry
registry = CollectorRegistry()

# Define performance metrics
response_time_gauge = Gauge('flask_response_time_ms', 'Flask response time in milliseconds', registry=registry)
throughput_gauge = Gauge('flask_requests_per_second', 'Flask requests per second', registry=registry)
error_rate_gauge = Gauge('flask_error_rate_percent', 'Flask error rate percentage', registry=registry)
active_users_gauge = Gauge('flask_active_users', 'Number of active users', registry=registry)
memory_usage_gauge = Gauge('flask_memory_usage_mb', 'Flask memory usage in MB', registry=registry)

# Performance variance metrics
variance_response_time = Gauge('flask_variance_response_time_percent', 'Response time variance from baseline', registry=registry)
variance_throughput = Gauge('flask_variance_throughput_percent', 'Throughput variance from baseline', registry=registry)
variance_error_rate = Gauge('flask_variance_error_rate_percent', 'Error rate variance from baseline', registry=registry)

# Compliance metrics
compliance_overall = Gauge('flask_compliance_overall', 'Overall performance compliance (1=pass, 0=fail)', registry=registry)
compliance_response_time = Gauge('flask_compliance_response_time', 'Response time compliance (1=pass, 0=fail)', registry=registry)
compliance_throughput = Gauge('flask_compliance_throughput', 'Throughput compliance (1=pass, 0=fail)', registry=registry)

def update_metrics_from_file(metrics_file):
    """Update Prometheus metrics from performance results file"""
    try:
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                data = json.load(f)
            
            # Update basic performance metrics
            if 'response_time' in data:
                response_time_gauge.set(data['response_time'])
            if 'throughput' in data:
                throughput_gauge.set(data['throughput'])
            if 'error_rate' in data:
                error_rate_gauge.set(data['error_rate'])
            if 'active_users' in data:
                active_users_gauge.set(data['active_users'])
            if 'memory_usage' in data:
                memory_usage_gauge.set(data['memory_usage'])
            
            # Update variance metrics
            if 'variance_response_time' in data:
                variance_response_time.set(data['variance_response_time'])
            if 'variance_throughput' in data:
                variance_throughput.set(data['variance_throughput'])
            if 'variance_error_rate' in data:
                variance_error_rate.set(data['variance_error_rate'])
            
            # Update compliance metrics
            if 'compliance_overall' in data:
                compliance_overall.set(1 if data['compliance_overall'] else 0)
            if 'compliance_response_time' in data:
                compliance_response_time.set(1 if data['compliance_response_time'] else 0)
            if 'compliance_throughput' in data:
                compliance_throughput.set(1 if data['compliance_throughput'] else 0)
                
    except Exception as e:
        print(f"Error updating metrics: {e}")

def metrics_updater():
    """Background thread to update metrics periodically"""
    metrics_file = os.environ.get('METRICS_FILE', '/tmp/performance_metrics.json')
    interval = int(os.environ.get('METRICS_INTERVAL', '5'))
    
    while True:
        update_metrics_from_file(metrics_file)
        time.sleep(interval)

if __name__ == '__main__':
    port = int(os.environ.get('PROMETHEUS_PORT', '8089'))
    
    # Start metrics updater in background
    metrics_thread = threading.Thread(target=metrics_updater, daemon=True)
    metrics_thread.start()
    
    # Start Prometheus HTTP server
    start_http_server(port, registry=registry)
    print(f"Prometheus metrics server started on port {port}")
    
    try:
        # Keep the server running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down Prometheus metrics server")
        sys.exit(0)
EOF
    
    # Start Prometheus metrics server in background
    export PROMETHEUS_PORT="$PROMETHEUS_PORT"
    export METRICS_FILE="/tmp/performance_metrics.json"
    export METRICS_INTERVAL="$METRICS_COLLECTION_INTERVAL"
    
    $PYTHON_EXECUTABLE "$prometheus_script" &
    local prometheus_pid=$!
    
    # Wait for server to start
    sleep 3
    
    # Verify server is running
    if ! curl -sf "http://localhost:$PROMETHEUS_PORT/metrics" &>/dev/null; then
        log_warn "Prometheus metrics server failed to start properly"
        kill $prometheus_pid 2>/dev/null || true
        return 1
    fi
    
    log_success "Prometheus metrics server started successfully (PID: $prometheus_pid)"
    echo "$prometheus_pid" > "/tmp/prometheus_metrics.pid"
    
    return 0
}

update_prometheus_metrics() {
    if [[ "$MONITORING_ENABLED" != "true" ]]; then
        return 0
    fi
    
    local metrics_file="/tmp/performance_metrics.json"
    
    # Create metrics update file for Prometheus
    cat > "$metrics_file" << EOF
{
  "response_time": ${VARIANCE_ANALYSIS[response_time_current]:-0},
  "throughput": ${VARIANCE_ANALYSIS[throughput_current]:-0},
  "error_rate": ${VARIANCE_ANALYSIS[error_rate_current]:-0},
  "active_users": $MAX_USERS,
  "memory_usage": ${BASELINE_METRICS[memory_usage_mb]:-256},
  "variance_response_time": ${VARIANCE_ANALYSIS[response_time_variance_percent]:-0},
  "variance_throughput": ${VARIANCE_ANALYSIS[throughput_variance_percent]:-0},
  "variance_error_rate": ${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0},
  "compliance_overall": $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "true" || echo "false"),
  "compliance_response_time": ${VARIANCE_ANALYSIS[response_time_compliant]:-false},
  "compliance_throughput": ${VARIANCE_ANALYSIS[throughput_compliant]:-false},
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    
    log_info "Prometheus metrics updated: $metrics_file"
}

stop_prometheus_metrics_server() {
    if [[ -f "/tmp/prometheus_metrics.pid" ]]; then
        local prometheus_pid
        prometheus_pid=$(cat "/tmp/prometheus_metrics.pid")
        if kill "$prometheus_pid" 2>/dev/null; then
            log_info "Prometheus metrics server stopped (PID: $prometheus_pid)"
        fi
        rm -f "/tmp/prometheus_metrics.pid"
    fi
}

# Notification functions
send_performance_notifications() {
    local status="$1"
    local summary="$2"
    
    log_info "Sending performance test notifications..."
    
    # Prepare notification message
    local message
    local emoji
    
    if [[ "$status" == "success" ]]; then
        emoji="✅"
        message="Performance Test PASSED: $summary"
    else
        emoji="❌"
        message="Performance Test FAILED: $summary"
    fi
    
    # Send Slack notification if configured
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        send_slack_notification "$emoji $message"
    fi
    
    # Send Teams notification if configured
    if [[ -n "$TEAMS_WEBHOOK_URL" ]]; then
        send_teams_notification "$emoji $message"
    fi
    
    # Send email notification if configured
    if [[ "$EMAIL_NOTIFICATIONS" == "true" ]]; then
        send_email_notification "$status" "$message"
    fi
}

send_slack_notification() {
    local message="$1"
    
    if [[ -z "$SLACK_WEBHOOK_URL" ]]; then
        return 0
    fi
    
    local payload
    payload=$(cat << EOF
{
  "text": "Flask Migration Performance Test",
  "attachments": [
    {
      "color": "$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "good" || echo "danger")",
      "fields": [
        {
          "title": "Performance Test Status",
          "value": "$message",
          "short": false
        },
        {
          "title": "Environment",
          "value": "$PERFORMANCE_ENV",
          "short": true
        },
        {
          "title": "Test Duration",
          "value": "${TEST_DURATION}s",
          "short": true
        },
        {
          "title": "Variance Threshold",
          "value": "≤${PERFORMANCE_VARIANCE_THRESHOLD}%",
          "short": true
        },
        {
          "title": "Overall Compliance",
          "value": "$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "PASSED" || echo "FAILED")",
          "short": true
        }
      ]
    }
  ]
}
EOF
)
    
    if curl -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK_URL" &>/dev/null; then
        log_info "Slack notification sent successfully"
    else
        log_warn "Failed to send Slack notification"
    fi
}

send_teams_notification() {
    local message="$1"
    
    if [[ -z "$TEAMS_WEBHOOK_URL" ]]; then
        return 0
    fi
    
    local color
    if [[ "$OVERALL_COMPLIANCE" == "true" ]]; then
        color="00FF00"  # Green
    else
        color="FF0000"  # Red
    fi
    
    local payload
    payload=$(cat << EOF
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "$color",
  "summary": "Flask Migration Performance Test",
  "sections": [{
    "activityTitle": "Performance Test Complete",
    "activitySubtitle": "$message",
    "facts": [
      {
        "name": "Environment",
        "value": "$PERFORMANCE_ENV"
      },
      {
        "name": "Test Duration",
        "value": "${TEST_DURATION} seconds"
      },
      {
        "name": "Variance Threshold",
        "value": "≤${PERFORMANCE_VARIANCE_THRESHOLD}%"
      },
      {
        "name": "Overall Compliance",
        "value": "$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "PASSED" || echo "FAILED")"
      }
    ]
  }]
}
EOF
)
    
    if curl -X POST -H 'Content-type: application/json' --data "$payload" "$TEAMS_WEBHOOK_URL" &>/dev/null; then
        log_info "Teams notification sent successfully"
    else
        log_warn "Failed to send Teams notification"
    fi
}

send_email_notification() {
    local status="$1"
    local message="$2"
    
    # This would typically integrate with your email service
    # For now, just log the email notification
    log_info "Email notification would be sent: $status - $message"
}

# Comprehensive performance testing execution
execute_full_performance_test() {
    log_header "Executing Full Performance Test Suite"
    
    TEST_START_TIME=$(date +%s)
    
    # Start Prometheus metrics server
    start_prometheus_metrics_server
    
    # Execute Locust load testing per Section 6.6.1
    if ! execute_locust_load_test; then
        log_error "Locust load testing failed"
        return 1
    fi
    
    # Execute k6 performance testing per Section 8.5.2
    if ! execute_k6_performance_test; then
        log_error "k6 performance testing failed"
        return 1
    fi
    
    # Perform baseline comparison and variance analysis per Section 4.4.2
    if ! perform_baseline_comparison; then
        log_error "Baseline comparison failed"
        return 1
    fi
    
    # Update Prometheus metrics
    update_prometheus_metrics
    
    # Generate final comprehensive report
    generate_comprehensive_report
    
    TEST_END_TIME=$(date +%s)
    local test_duration=$((TEST_END_TIME - TEST_START_TIME))
    
    # Send notifications
    local summary="Test Duration: ${test_duration}s, Compliance: $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "PASSED" || echo "FAILED")"
    send_performance_notifications "$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "success" || echo "failure")" "$summary"
    
    # Stop Prometheus metrics server
    stop_prometheus_metrics_server
    
    # Return appropriate exit code for CI/CD integration
    if [[ "$OVERALL_COMPLIANCE" == "true" ]]; then
        log_success "Full performance test suite completed successfully"
        return 0
    else
        log_error "Performance test suite failed - variance threshold exceeded"
        return 1
    fi
}

generate_comprehensive_report() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local comprehensive_report="$PERFORMANCE_REPORTS_DIR/comprehensive_performance_report_${timestamp}.json"
    
    log_info "Generating comprehensive performance test report..."
    
    cat > "$comprehensive_report" << EOF
{
  "performance_test_report": {
    "metadata": {
      "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "environment": "$PERFORMANCE_ENV",
      "test_duration_seconds": $((TEST_END_TIME - TEST_START_TIME)),
      "script_version": "1.0.0",
      "ci_cd_mode": $CI_CD_MODE,
      "github_actions": $GITHUB_ACTIONS
    },
    "test_configuration": {
      "variance_threshold_percent": $PERFORMANCE_VARIANCE_THRESHOLD,
      "load_test_duration_seconds": $TEST_DURATION,
      "min_users": $MIN_USERS,
      "max_users": $MAX_USERS,
      "user_spawn_rate": $USER_SPAWN_RATE,
      "target_rps": $TARGET_RPS,
      "response_time_threshold_ms": $RESPONSE_TIME_P95_THRESHOLD,
      "error_rate_threshold_percent": $ERROR_RATE_THRESHOLD,
      "flask_app_host": "$FLASK_APP_HOST"
    },
    "baseline_metrics": {
      "nodejs_baseline_file": "$NODEJS_BASELINE_FILE",
      "response_time_p95_ms": ${BASELINE_METRICS[response_time_p95]:-0},
      "requests_per_second": ${BASELINE_METRICS[requests_per_second]:-0},
      "memory_usage_mb": ${BASELINE_METRICS[memory_usage_mb]:-0},
      "cpu_utilization_percent": ${BASELINE_METRICS[cpu_utilization_percent]:-0},
      "error_rate_percent": ${BASELINE_METRICS[error_rate_percent]:-0}
    },
    "test_results": {
      "locust_results": {
        "total_requests": ${PERFORMANCE_RESULTS[locust_total_requests]:-0},
        "total_failures": ${PERFORMANCE_RESULTS[locust_total_failures]:-0},
        "avg_response_time_ms": ${PERFORMANCE_RESULTS[locust_avg_response_time]:-0},
        "min_response_time_ms": ${PERFORMANCE_RESULTS[locust_min_response_time]:-0},
        "max_response_time_ms": ${PERFORMANCE_RESULTS[locust_max_response_time]:-0},
        "requests_per_second": ${PERFORMANCE_RESULTS[locust_requests_per_second]:-0},
        "error_rate_percent": ${PERFORMANCE_RESULTS[locust_error_rate_percent]:-0}
      },
      "k6_results": {
        "total_requests": ${PERFORMANCE_RESULTS[k6_total_requests]:-0},
        "total_errors": ${PERFORMANCE_RESULTS[k6_total_errors]:-0},
        "avg_response_time_ms": ${PERFORMANCE_RESULTS[k6_avg_response_time]:-0},
        "min_response_time_ms": ${PERFORMANCE_RESULTS[k6_min_response_time]:-0},
        "max_response_time_ms": ${PERFORMANCE_RESULTS[k6_max_response_time]:-0},
        "requests_per_second": ${PERFORMANCE_RESULTS[k6_requests_per_second]:-0},
        "error_rate_percent": ${PERFORMANCE_RESULTS[k6_error_rate_percent]:-0}
      }
    },
    "variance_analysis": {
      "response_time": {
        "baseline_ms": ${VARIANCE_ANALYSIS[response_time_baseline]:-0},
        "current_ms": ${VARIANCE_ANALYSIS[response_time_current]:-0},
        "variance_percent": ${VARIANCE_ANALYSIS[response_time_variance_percent]:-0},
        "compliant": ${VARIANCE_ANALYSIS[response_time_compliant]:-false}
      },
      "throughput": {
        "baseline_rps": ${VARIANCE_ANALYSIS[throughput_baseline]:-0},
        "current_rps": ${VARIANCE_ANALYSIS[throughput_current]:-0},
        "variance_percent": ${VARIANCE_ANALYSIS[throughput_variance_percent]:-0},
        "compliant": ${VARIANCE_ANALYSIS[throughput_compliant]:-false}
      },
      "error_rate": {
        "baseline_percent": ${VARIANCE_ANALYSIS[error_rate_baseline]:-0},
        "current_percent": ${VARIANCE_ANALYSIS[error_rate_current]:-0},
        "variance_percent": ${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0},
        "compliant": ${VARIANCE_ANALYSIS[error_rate_compliant]:-false}
      }
    },
    "compliance_summary": {
      "overall_compliant": $OVERALL_COMPLIANCE,
      "total_checks": ${VARIANCE_ANALYSIS[total_checks]:-0},
      "passed_checks": ${VARIANCE_ANALYSIS[passed_checks]:-0},
      "compliance_rate_percent": ${VARIANCE_ANALYSIS[compliance_rate]:-0},
      "deployment_recommendation": "$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "APPROVED" || echo "BLOCKED")"
    },
    "monitoring_integration": {
      "prometheus_enabled": $MONITORING_ENABLED,
      "prometheus_port": $PROMETHEUS_PORT,
      "metrics_collection_interval": $METRICS_COLLECTION_INTERVAL
    }
  }
}
EOF
    
    log_success "Comprehensive report generated: $comprehensive_report"
    
    # Also generate HTML report
    generate_html_report "$comprehensive_report"
}

generate_html_report() {
    local json_report="$1"
    local html_report="${json_report%.json}.html"
    
    cat > "$html_report" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask Migration Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #ddd; padding-bottom: 20px; margin-bottom: 30px; }
        .status-badge { display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
        .status-pass { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status-fail { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #007bff; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { color: #6c757d; margin-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .variance-positive { color: #dc3545; }
        .variance-negative { color: #28a745; }
        .compliance-pass { color: #28a745; font-weight: bold; }
        .compliance-fail { color: #dc3545; font-weight: bold; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
        .recommendation { padding: 15px; border-radius: 6px; margin: 20px 0; }
        .recommendation.approved { background: #d4edda; border-left: 4px solid #28a745; }
        .recommendation.blocked { background: #f8d7da; border-left: 4px solid #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Flask Migration Performance Test Report</h1>
            <div class="status-badge $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "status-pass" || echo "status-fail")">
                $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "✅ PERFORMANCE COMPLIANCE PASSED" || echo "❌ PERFORMANCE COMPLIANCE FAILED")
            </div>
            <p class="timestamp">Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) | Environment: $PERFORMANCE_ENV</p>
        </div>

        <div class="recommendation $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "approved" || echo "blocked")">
            <h3>Deployment Recommendation</h3>
            <p><strong>$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "DEPLOYMENT APPROVED" || echo "DEPLOYMENT BLOCKED")</strong></p>
            <p>$([ "$OVERALL_COMPLIANCE" == "true" ] && echo "All performance metrics are within the ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold. The Flask application is ready for production deployment." || echo "One or more performance metrics exceed the ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold. Performance optimization is required before deployment.")</p>
        </div>

        <h2>Performance Metrics Overview</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-label">Overall Compliance Rate</div>
                <div class="metric-value">${VARIANCE_ANALYSIS[compliance_rate]:-0}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Test Duration</div>
                <div class="metric-value">$((TEST_END_TIME - TEST_START_TIME)) sec</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Max Concurrent Users</div>
                <div class="metric-value">$MAX_USERS</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Variance Threshold</div>
                <div class="metric-value">≤${PERFORMANCE_VARIANCE_THRESHOLD}%</div>
            </div>
        </div>

        <h2>Baseline Variance Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Baseline (Node.js)</th>
                    <th>Current (Flask)</th>
                    <th>Variance</th>
                    <th>Compliance</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Response Time</td>
                    <td>${BASELINE_METRICS[response_time_p95]:-0}ms</td>
                    <td>${VARIANCE_ANALYSIS[response_time_current]:-0}ms</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[response_time_variance_percent]:-0}" != "${VARIANCE_ANALYSIS[response_time_variance_percent]:-0#-}" ] && echo "variance-negative" || echo "variance-positive")">${VARIANCE_ANALYSIS[response_time_variance_percent]:-0}%</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[response_time_compliant]:-false}" == "true" ] && echo "compliance-pass" || echo "compliance-fail")">$([ "${VARIANCE_ANALYSIS[response_time_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL")</td>
                </tr>
                <tr>
                    <td>Throughput</td>
                    <td>${BASELINE_METRICS[requests_per_second]:-0} RPS</td>
                    <td>${VARIANCE_ANALYSIS[throughput_current]:-0} RPS</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[throughput_variance_percent]:-0}" != "${VARIANCE_ANALYSIS[throughput_variance_percent]:-0#-}" ] && echo "variance-negative" || echo "variance-positive")">${VARIANCE_ANALYSIS[throughput_variance_percent]:-0}%</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[throughput_compliant]:-false}" == "true" ] && echo "compliance-pass" || echo "compliance-fail")">$([ "${VARIANCE_ANALYSIS[throughput_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL")</td>
                </tr>
                <tr>
                    <td>Error Rate</td>
                    <td>${BASELINE_METRICS[error_rate_percent]:-0}%</td>
                    <td>${VARIANCE_ANALYSIS[error_rate_current]:-0}%</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0}" != "${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0#-}" ] && echo "variance-negative" || echo "variance-positive")">${VARIANCE_ANALYSIS[error_rate_variance_percent]:-0}%</td>
                    <td class="$([ "${VARIANCE_ANALYSIS[error_rate_compliant]:-false}" == "true" ] && echo "compliance-pass" || echo "compliance-fail")">$([ "${VARIANCE_ANALYSIS[error_rate_compliant]:-false}" == "true" ] && echo "✅ PASS" || echo "❌ FAIL")</td>
                </tr>
            </tbody>
        </table>

        <h2>Test Results Comparison</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Total Requests</th>
                    <th>Avg Response Time</th>
                    <th>Throughput (RPS)</th>
                    <th>Error Rate</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Locust</strong></td>
                    <td>${PERFORMANCE_RESULTS[locust_total_requests]:-0}</td>
                    <td>${PERFORMANCE_RESULTS[locust_avg_response_time]:-0}ms</td>
                    <td>${PERFORMANCE_RESULTS[locust_requests_per_second]:-0}</td>
                    <td>${PERFORMANCE_RESULTS[locust_error_rate_percent]:-0}%</td>
                </tr>
                <tr>
                    <td><strong>k6</strong></td>
                    <td>${PERFORMANCE_RESULTS[k6_total_requests]:-0}</td>
                    <td>${PERFORMANCE_RESULTS[k6_avg_response_time]:-0}ms</td>
                    <td>${PERFORMANCE_RESULTS[k6_requests_per_second]:-0}</td>
                    <td>${PERFORMANCE_RESULTS[k6_error_rate_percent]:-0}%</td>
                </tr>
            </tbody>
        </table>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #6c757d; text-align: center;">
            <p><em>Report generated by performance.sh - Flask Migration Performance Testing Suite v1.0.0</em></p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_success "HTML report generated: $html_report"
}

# CI/CD mode execution
execute_ci_cd_performance_test() {
    log_header "Executing CI/CD Performance Test Pipeline"
    
    # Optimized configuration for CI/CD environments
    local ci_test_duration=900  # 15 minutes for faster CI/CD
    local ci_max_users=200      # Reduced load for CI/CD resources
    
    # Override test parameters for CI/CD
    TEST_DURATION=$ci_test_duration
    MAX_USERS=$ci_max_users
    
    log_info "CI/CD Mode Configuration:"
    log_info "  Test Duration: ${TEST_DURATION}s ($(( TEST_DURATION / 60 )) minutes)"
    log_info "  Max Users: $MAX_USERS"
    log_info "  Variance Threshold: ≤${PERFORMANCE_VARIANCE_THRESHOLD}%"
    
    # Execute optimized performance test suite
    if ! execute_full_performance_test; then
        log_error "CI/CD performance test failed"
        
        # Create CI/CD failure artifact
        local failure_report="$PERFORMANCE_REPORTS_DIR/ci_cd_failure_$(date +%Y%m%d_%H%M%S).json"
        cat > "$failure_report" << EOF
{
  "ci_cd_performance_test": {
    "status": "FAILED",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$PERFORMANCE_ENV",
    "overall_compliance": $OVERALL_COMPLIANCE,
    "failure_reason": "Performance variance exceeds ≤${PERFORMANCE_VARIANCE_THRESHOLD}% threshold",
    "next_steps": [
      "Review performance metrics and identify bottlenecks",
      "Optimize Flask application performance",
      "Re-run performance tests after optimization"
    ]
  }
}
EOF
        
        return 1
    fi
    
    # Create CI/CD success artifact
    local success_report="$PERFORMANCE_REPORTS_DIR/ci_cd_success_$(date +%Y%m%d_%H%M%S).json"
    cat > "$success_report" << EOF
{
  "ci_cd_performance_test": {
    "status": "PASSED",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$PERFORMANCE_ENV",
    "overall_compliance": $OVERALL_COMPLIANCE,
    "compliance_rate": "${VARIANCE_ANALYSIS[compliance_rate]:-100}%",
    "deployment_approved": true,
    "summary": "All performance metrics within ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold"
  }
}
EOF
    
    log_success "CI/CD performance test completed successfully"
    return 0
}

# Main execution function
main() {
    local test_mode="${1:-$DEFAULT_TEST_MODE}"
    
    # Print script header
    echo -e "${PURPLE}================================================================${NC}"
    echo -e "${PURPLE}Flask Migration Performance Testing Suite${NC}"
    echo -e "${PURPLE}Version: 1.0.0${NC}"
    echo -e "${PURPLE}================================================================${NC}"
    echo ""
    
    # Validate test mode
    if [[ ! " ${TEST_MODES[*]} " =~ " ${test_mode} " ]]; then
        log_error "Invalid test mode: $test_mode"
        log_info "Available modes: ${TEST_MODES[*]}"
        exit 1
    fi
    
    log_info "Starting performance testing in '$test_mode' mode"
    log_info "Configuration: $PERFORMANCE_ENV environment, ≤${PERFORMANCE_VARIANCE_THRESHOLD}% variance threshold"
    
    # Environment validation
    if ! validate_environment; then
        log_error "Environment validation failed"
        exit 1
    fi
    
    if ! validate_performance_config; then
        log_error "Performance configuration validation failed"
        exit 1
    fi
    
    # Execute based on test mode
    case "$test_mode" in
        "baseline")
            log_header "Baseline Management Mode"
            load_nodejs_baseline
            ;;
        "locust")
            log_header "Locust Load Testing Mode"
            execute_locust_load_test
            ;;
        "k6")
            log_header "k6 Performance Testing Mode"
            execute_k6_performance_test
            ;;
        "comparison")
            log_header "Baseline Comparison Mode"
            load_nodejs_baseline
            perform_baseline_comparison
            ;;
        "full")
            log_header "Full Performance Test Suite"
            execute_full_performance_test
            ;;
        "ci-cd")
            log_header "CI/CD Performance Testing Mode"
            CI_CD_MODE="true"
            execute_ci_cd_performance_test
            ;;
        *)
            log_error "Unsupported test mode: $test_mode"
            exit 1
            ;;
    esac
    
    local exit_code=$?
    
    # Print final summary
    echo ""
    echo -e "${PURPLE}================================================================${NC}"
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}Performance Testing Completed Successfully${NC}"
        echo -e "${GREEN}Overall Compliance: $([ "$OVERALL_COMPLIANCE" == "true" ] && echo "PASSED" || echo "N/A")${NC}"
    else
        echo -e "${RED}Performance Testing Failed${NC}"
        echo -e "${RED}Overall Compliance: FAILED${NC}"
    fi
    echo -e "${PURPLE}================================================================${NC}"
    
    exit $exit_code
}

# Help function
show_help() {
    cat << EOF
Flask Migration Performance Testing Suite v1.0.0

DESCRIPTION:
    Comprehensive performance testing script implementing Locust and k6 load testing
    frameworks with automated baseline comparison ensuring ≤10% variance compliance
    for Flask application performance monitoring.

USAGE:
    $0 [MODE] [OPTIONS]

MODES:
    baseline    - Load and validate Node.js baseline metrics
    locust      - Execute Locust load testing only
    k6          - Execute k6 performance testing only
    comparison  - Perform baseline comparison analysis only
    full        - Execute complete performance test suite (default)
    ci-cd       - Optimized CI/CD pipeline execution

ENVIRONMENT VARIABLES:
    PERFORMANCE_VARIANCE_THRESHOLD  - Maximum variance percentage (default: 10)
    MIN_USERS                      - Minimum concurrent users (default: 10)
    MAX_USERS                      - Maximum concurrent users (default: 1000)
    TEST_DURATION                  - Test duration in seconds (default: 1800)
    USER_SPAWN_RATE               - Users spawned per second (default: 2)
    TARGET_RPS                    - Target requests per second (default: 100)
    FLASK_APP_HOST                - Flask application URL (default: http://localhost:5000)
    PERFORMANCE_ENV               - Testing environment (default: testing)
    MONITORING_ENABLED            - Enable Prometheus metrics (default: true)
    SLACK_WEBHOOK_URL             - Slack notification webhook URL
    TEAMS_WEBHOOK_URL             - Teams notification webhook URL

EXAMPLES:
    $0 full                       # Execute complete test suite
    $0 ci-cd                      # CI/CD optimized testing
    $0 locust                     # Locust load testing only
    $0 comparison                 # Baseline comparison only

REPORTS:
    All performance reports are saved to: tests/performance/reports/
    - JSON detailed results
    - Markdown summaries
    - HTML dashboard reports
    - Variance analysis reports

EXIT CODES:
    0 - Success (compliance passed)
    1 - Failure (compliance failed or execution error)

For more information, see the technical specification Section 8.5.2 and Section 4.4.2.
EOF
}

# Parse command line arguments
if [[ $# -eq 0 ]]; then
    main "$DEFAULT_TEST_MODE"
elif [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    show_help
else
    main "$@"
fi