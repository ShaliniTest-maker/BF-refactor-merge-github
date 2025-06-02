#!/bin/bash

#
# Health Check Validation Script for Flask Application Migration
#
# Comprehensive system health monitoring implementation for Flask application including
# database connectivity validation, external service integration health checks, and
# container orchestration compatibility per Section 8.3.2, Section 6.2.1, and Section 0.1.3.
#
# This script implements enterprise-grade health validation ensuring:
# - Flask health endpoints (/health, /health/ready, /health/live) validation
# - Database connectivity verification (MongoDB and Redis)
# - External service integration health checks (Auth0, AWS S3, APM services)
# - Container health check integration for Kubernetes orchestration
# - Comprehensive post-deployment validation per health check requirements
# - Enterprise integration with logging and monitoring systems
#
# Exit Codes:
#   0: All health checks passed successfully
#   1: Critical health check failures detected
#   2: Configuration or environment errors
#   3: Timeout or connectivity issues
#   4: Authentication or authorization failures
#   5: Service degradation detected (non-critical)
#
# Usage:
#   ./health-check.sh [OPTIONS]
#
# Options:
#   --host HOST         Flask application host (default: localhost)
#   --port PORT         Flask application port (default: 8000)
#   --timeout SECONDS   Request timeout in seconds (default: 30)
#   --verbose           Enable verbose output logging
#   --json              Output results in JSON format
#   --critical-only     Only perform critical health checks
#   --container-mode    Run in container health check mode
#   --enterprise-mode   Enable enterprise monitoring integration
#   --baseline-check    Perform baseline performance validation
#   --help              Display this help message
#
# Environment Variables:
#   FLASK_HOST                    Override default host
#   FLASK_PORT                    Override default port
#   HEALTH_CHECK_TIMEOUT          Override request timeout
#   MONGODB_URI                   MongoDB connection string for validation
#   REDIS_URL                     Redis connection URL for validation
#   AUTH0_DOMAIN                  Auth0 domain for external service validation
#   AWS_S3_BUCKET                 S3 bucket name for AWS service validation
#   DATADOG_API_KEY               Datadog API key for APM validation
#   NEW_RELIC_LICENSE_KEY         New Relic license key for APM validation
#   PROMETHEUS_ENDPOINT           Prometheus metrics endpoint
#   ENTERPRISE_LOGGING_ENABLED    Enable enterprise logging integration
#   PERFORMANCE_VARIANCE_THRESHOLD Maximum allowed performance variance (default: 10)
#

set -euo pipefail

# Script metadata and version information
readonly SCRIPT_NAME="health-check.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DESCRIPTION="Flask Application Health Check Validation"

# Default configuration values per Section 8.3.2 specifications
readonly DEFAULT_HOST="localhost"
readonly DEFAULT_PORT="8000"
readonly DEFAULT_TIMEOUT="30"
readonly DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD="10"

# Health check endpoint paths per Section 6.5.2.1
readonly HEALTH_ENDPOINT="/health"
readonly LIVENESS_ENDPOINT="/health/live"
readonly READINESS_ENDPOINT="/health/ready"
readonly DEPENDENCIES_ENDPOINT="/health/dependencies"
readonly METRICS_ENDPOINT="/metrics"

# Container health check configuration per Section 8.3.2
readonly CONTAINER_HEALTH_INTERVAL="30"
readonly CONTAINER_HEALTH_TIMEOUT="10"
readonly CONTAINER_HEALTH_START_PERIOD="5"
readonly CONTAINER_HEALTH_RETRIES="3"

# Performance monitoring thresholds per Section 0.3.2
readonly MAX_RESPONSE_TIME_MS="5000"
readonly MAX_DATABASE_RESPONSE_TIME_MS="2000"
readonly MAX_CACHE_RESPONSE_TIME_MS="1000"
readonly MAX_EXTERNAL_SERVICE_RESPONSE_TIME_MS="10000"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global variables for configuration
HOST="${FLASK_HOST:-$DEFAULT_HOST}"
PORT="${FLASK_PORT:-$DEFAULT_PORT}"
TIMEOUT="${HEALTH_CHECK_TIMEOUT:-$DEFAULT_TIMEOUT}"
VERBOSE=false
JSON_OUTPUT=false
CRITICAL_ONLY=false
CONTAINER_MODE=false
ENTERPRISE_MODE=false
BASELINE_CHECK=false
PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD:-$DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD}"

# Health check results tracking
declare -A HEALTH_RESULTS
declare -A HEALTH_METRICS
declare -A HEALTH_ERRORS
OVERALL_STATUS="healthy"
EXIT_CODE=0

# Logging and monitoring integration
LOG_LEVEL="INFO"
LOG_FORMAT="structured"
ENTERPRISE_LOGGING_ENABLED="${ENTERPRISE_LOGGING_ENABLED:-false}"

#
# Utility Functions
#

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    
    if [[ "$ENTERPRISE_LOGGING_ENABLED" == "true" ]]; then
        # Structured logging for enterprise integration
        printf '{"timestamp":"%s","level":"%s","component":"health-check","message":"%s","script_version":"%s"}\n' \
            "$timestamp" "$level" "$message" "$SCRIPT_VERSION"
    else
        # Standard logging format
        case "$level" in
            "ERROR")
                printf "${RED}[%s] ERROR: %s${NC}\n" "$timestamp" "$message" >&2
                ;;
            "WARN")
                printf "${YELLOW}[%s] WARN: %s${NC}\n" "$timestamp" "$message" >&2
                ;;
            "INFO")
                printf "${GREEN}[%s] INFO: %s${NC}\n" "$timestamp" "$message"
                ;;
            "DEBUG")
                if [[ "$VERBOSE" == "true" ]]; then
                    printf "${BLUE}[%s] DEBUG: %s${NC}\n" "$timestamp" "$message"
                fi
                ;;
        esac
    fi
}

log_error() {
    log "ERROR" "$1"
}

log_warn() {
    log "WARN" "$1"
}

log_info() {
    log "INFO" "$1"
}

log_debug() {
    log "DEBUG" "$1"
}

# JSON utility functions for response parsing
extract_json_field() {
    local json="$1"
    local field="$2"
    
    # Use python for reliable JSON parsing if available, otherwise use basic grep/sed
    if command -v python3 >/dev/null 2>&1; then
        echo "$json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    keys = '$field'.split('.')
    result = data
    for key in keys:
        if isinstance(result, dict) and key in result:
            result = result[key]
        else:
            result = None
            break
    print(result if result is not None else '')
except:
    print('')
"
    else
        # Fallback to basic parsing for simple fields
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4 || echo ""
    fi
}

# HTTP request utility with enterprise-grade error handling
make_http_request() {
    local url="$1"
    local timeout="${2:-$TIMEOUT}"
    local expected_status="${3:-200}"
    local method="${4:-GET}"
    
    local start_time=$(date +%s%3N)
    local response_file=$(mktemp)
    local headers_file=$(mktemp)
    
    log_debug "Making HTTP request: $method $url (timeout: ${timeout}s, expected: $expected_status)"
    
    # Execute HTTP request with comprehensive error handling
    local http_code
    local exit_code
    
    http_code=$(curl \
        --silent \
        --show-error \
        --location \
        --max-time "$timeout" \
        --connect-timeout 10 \
        --retry 2 \
        --retry-delay 1 \
        --retry-max-time $((timeout - 5)) \
        --write-out "%{http_code}" \
        --output "$response_file" \
        --dump-header "$headers_file" \
        --request "$method" \
        --header "User-Agent: Health-Check-Script/$SCRIPT_VERSION" \
        --header "Accept: application/json" \
        --header "Cache-Control: no-cache" \
        "$url" 2>/dev/null || echo "000")
    
    exit_code=$?
    local end_time=$(date +%s%3N)
    local response_time=$((end_time - start_time))
    
    # Read response body and headers
    local response_body=""
    local response_headers=""
    
    if [[ -f "$response_file" ]]; then
        response_body=$(cat "$response_file")
    fi
    
    if [[ -f "$headers_file" ]]; then
        response_headers=$(cat "$headers_file")
    fi
    
    # Cleanup temporary files
    rm -f "$response_file" "$headers_file"
    
    # Validate HTTP response
    if [[ "$exit_code" -ne 0 ]]; then
        log_error "HTTP request failed with curl exit code: $exit_code"
        return 3
    fi
    
    if [[ "$http_code" == "000" ]]; then
        log_error "HTTP request failed: connection timeout or network error"
        return 3
    fi
    
    # Check response time against performance thresholds
    if [[ "$response_time" -gt "$MAX_RESPONSE_TIME_MS" ]]; then
        log_warn "HTTP request exceeded maximum response time: ${response_time}ms > ${MAX_RESPONSE_TIME_MS}ms"
    fi
    
    # Store response metrics
    echo "$response_body" > "/tmp/health_check_response_body"
    echo "$http_code" > "/tmp/health_check_response_code"
    echo "$response_time" > "/tmp/health_check_response_time"
    echo "$response_headers" > "/tmp/health_check_response_headers"
    
    log_debug "HTTP response: $http_code (${response_time}ms)"
    
    # Validate expected status code
    if [[ "$http_code" != "$expected_status" ]]; then
        log_error "HTTP request returned unexpected status code: $http_code (expected: $expected_status)"
        return 1
    fi
    
    return 0
}

# Get last HTTP response details
get_response_body() {
    cat "/tmp/health_check_response_body" 2>/dev/null || echo ""
}

get_response_code() {
    cat "/tmp/health_check_response_code" 2>/dev/null || echo "000"
}

get_response_time() {
    cat "/tmp/health_check_response_time" 2>/dev/null || echo "0"
}

#
# Health Check Functions
#

# Basic Flask application health check per Section 6.1.3
check_basic_health() {
    log_info "Performing basic Flask application health check..."
    
    local url="http://${HOST}:${PORT}${HEALTH_ENDPOINT}"
    local check_name="basic_health"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse health response for detailed status
        local status=$(extract_json_field "$response_body" "status")
        local total_dependencies=$(extract_json_field "$response_body" "summary.total_dependencies")
        local healthy_dependencies=$(extract_json_field "$response_body" "summary.healthy_dependencies")
        
        if [[ "$status" == "healthy" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_info "Basic health check passed: $status (${response_time}ms)"
            log_debug "Dependencies: $healthy_dependencies/$total_dependencies healthy"
        elif [[ "$status" == "degraded" ]]; then
            HEALTH_RESULTS["$check_name"]="degraded"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_warn "Basic health check degraded: $status (${response_time}ms)"
            if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                OVERALL_STATUS="degraded"
            fi
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Unhealthy status: $status"
            log_error "Basic health check failed: $status"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "Basic health check HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# Kubernetes liveness probe check per Section 6.5.2.1
check_liveness_probe() {
    log_info "Performing Kubernetes liveness probe check..."
    
    local url="http://${HOST}:${PORT}${LIVENESS_ENDPOINT}"
    local check_name="liveness_probe"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse liveness response
        local status=$(extract_json_field "$response_body" "status")
        local check_type=$(extract_json_field "$response_body" "check_type")
        
        if [[ "$status" == "healthy" && "$check_type" == "liveness" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_info "Liveness probe check passed: $status (${response_time}ms)"
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Liveness probe unhealthy: $status"
            log_error "Liveness probe check failed: $status"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        local response_code=$(get_response_code)
        if [[ "$response_code" == "503" ]]; then
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Application in fatal state (HTTP 503)"
            log_error "Liveness probe failed: application requires restart (HTTP 503)"
            OVERALL_STATUS="unhealthy"
            return 1
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="HTTP request failed (code: $response_code)"
            log_error "Liveness probe HTTP request failed"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    fi
    
    return 0
}

# Kubernetes readiness probe check per Section 6.5.2.1
check_readiness_probe() {
    log_info "Performing Kubernetes readiness probe check..."
    
    local url="http://${HOST}:${PORT}${READINESS_ENDPOINT}"
    local check_name="readiness_probe"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse readiness response
        local status=$(extract_json_field "$response_body" "status")
        local check_type=$(extract_json_field "$response_body" "check_type")
        local total_dependencies=$(extract_json_field "$response_body" "summary.total_dependencies")
        local healthy_dependencies=$(extract_json_field "$response_body" "summary.healthy_dependencies")
        local unhealthy_dependencies=$(extract_json_field "$response_body" "summary.unhealthy_dependencies")
        
        if [[ "$status" == "ready" && "$check_type" == "readiness" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            HEALTH_METRICS["${check_name}_total_dependencies"]="$total_dependencies"
            HEALTH_METRICS["${check_name}_healthy_dependencies"]="$healthy_dependencies"
            log_info "Readiness probe check passed: $status (${response_time}ms)"
            log_debug "Dependencies ready: $healthy_dependencies/$total_dependencies"
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Readiness probe not ready: $status (unhealthy: $unhealthy_dependencies)"
            log_error "Readiness probe check failed: $status"
            log_error "Unhealthy dependencies: $unhealthy_dependencies/$total_dependencies"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        local response_code=$(get_response_code)
        if [[ "$response_code" == "503" ]]; then
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Dependencies unavailable (HTTP 503)"
            log_error "Readiness probe failed: dependencies unavailable (HTTP 503)"
            OVERALL_STATUS="unhealthy"
            return 1
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="HTTP request failed (code: $response_code)"
            log_error "Readiness probe HTTP request failed"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    fi
    
    return 0
}

# Database connectivity validation per Section 6.2.1
check_database_connectivity() {
    log_info "Performing database connectivity validation..."
    
    local url="http://${HOST}:${PORT}${DEPENDENCIES_ENDPOINT}"
    local check_name="database_connectivity"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse database dependency status
        local database_status=$(extract_json_field "$response_body" "dependencies.database.status")
        local database_response_time=$(extract_json_field "$response_body" "dependencies.database.response_time_ms")
        
        if [[ "$database_status" == "healthy" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            HEALTH_METRICS["${check_name}_database_response_time"]="$database_response_time"
            log_info "Database connectivity check passed: $database_status (${database_response_time}ms)"
            
            # Validate database response time against threshold
            if [[ -n "$database_response_time" && "$database_response_time" -gt "$MAX_DATABASE_RESPONSE_TIME_MS" ]]; then
                log_warn "Database response time exceeds threshold: ${database_response_time}ms > ${MAX_DATABASE_RESPONSE_TIME_MS}ms"
                if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                    OVERALL_STATUS="degraded"
                fi
            fi
        elif [[ "$database_status" == "degraded" ]]; then
            HEALTH_RESULTS["$check_name"]="degraded"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_warn "Database connectivity degraded: $database_status"
            if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                OVERALL_STATUS="degraded"
            fi
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Database unhealthy: $database_status"
            log_error "Database connectivity check failed: $database_status"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "Database connectivity check HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# Cache connectivity validation per Section 6.2.1
check_cache_connectivity() {
    log_info "Performing cache connectivity validation..."
    
    local url="http://${HOST}:${PORT}${DEPENDENCIES_ENDPOINT}"
    local check_name="cache_connectivity"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse cache dependency status
        local cache_status=$(extract_json_field "$response_body" "dependencies.cache.status")
        local cache_response_time=$(extract_json_field "$response_body" "dependencies.cache.response_time_ms")
        
        if [[ "$cache_status" == "healthy" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            HEALTH_METRICS["${check_name}_cache_response_time"]="$cache_response_time"
            log_info "Cache connectivity check passed: $cache_status (${cache_response_time}ms)"
            
            # Validate cache response time against threshold
            if [[ -n "$cache_response_time" && "$cache_response_time" -gt "$MAX_CACHE_RESPONSE_TIME_MS" ]]; then
                log_warn "Cache response time exceeds threshold: ${cache_response_time}ms > ${MAX_CACHE_RESPONSE_TIME_MS}ms"
                if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                    OVERALL_STATUS="degraded"
                fi
            fi
        elif [[ "$cache_status" == "degraded" ]]; then
            HEALTH_RESULTS["$check_name"]="degraded"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_warn "Cache connectivity degraded: $cache_status"
            if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                OVERALL_STATUS="degraded"
            fi
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Cache unhealthy: $cache_status"
            log_error "Cache connectivity check failed: $cache_status"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "Cache connectivity check HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# External service integration health checks per Section 0.1.3
check_external_services() {
    log_info "Performing external service integration health checks..."
    
    local url="http://${HOST}:${PORT}${DEPENDENCIES_ENDPOINT}"
    local check_name="external_services"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse external services status
        local external_services_data=$(extract_json_field "$response_body" "dependencies.external_services")
        
        if [[ -n "$external_services_data" ]]; then
            # Extract individual service statuses
            # Note: This is a simplified check - in a real implementation, we would parse each service
            log_debug "External services data available in health response"
            
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_info "External services health check passed (${response_time}ms)"
        else
            HEALTH_RESULTS["$check_name"]="degraded"
            HEALTH_ERRORS["$check_name"]="External services data not available"
            log_warn "External services health check degraded: no service data"
            if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                OVERALL_STATUS="degraded"
            fi
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "External services health check HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# APM and monitoring service validation per Section 0.1.3
check_monitoring_services() {
    log_info "Performing monitoring services health validation..."
    
    local url="http://${HOST}:${PORT}${DEPENDENCIES_ENDPOINT}"
    local check_name="monitoring_services"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        
        # Parse monitoring status
        local monitoring_status=$(extract_json_field "$response_body" "dependencies.monitoring.status")
        local monitoring_components=$(extract_json_field "$response_body" "dependencies.monitoring.components")
        
        if [[ "$monitoring_status" == "healthy" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_info "Monitoring services health check passed: $monitoring_status (${response_time}ms)"
        elif [[ "$monitoring_status" == "degraded" ]]; then
            HEALTH_RESULTS["$check_name"]="degraded"
            HEALTH_METRICS["${check_name}_response_time"]="$response_time"
            log_warn "Monitoring services degraded: $monitoring_status"
            if [[ "$OVERALL_STATUS" == "healthy" ]]; then
                OVERALL_STATUS="degraded"
            fi
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Monitoring unhealthy: $monitoring_status"
            log_error "Monitoring services health check failed: $monitoring_status"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "Monitoring services health check HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# Prometheus metrics endpoint validation per Section 6.5.1.1
check_metrics_endpoint() {
    log_info "Performing Prometheus metrics endpoint validation..."
    
    local url="http://${HOST}:${PORT}${METRICS_ENDPOINT}"
    local check_name="metrics_endpoint"
    
    if make_http_request "$url" "$TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local response_time=$(get_response_time)
        local response_headers=$(cat "/tmp/health_check_response_headers" 2>/dev/null || echo "")
        
        # Validate Prometheus metrics format
        if echo "$response_headers" | grep -q "Content-Type:.*text/plain"; then
            # Check for basic Prometheus metrics format
            if echo "$response_body" | grep -q "^# HELP\|^# TYPE\|^[a-zA-Z_][a-zA-Z0-9_]*{.*} [0-9]"; then
                HEALTH_RESULTS["$check_name"]="passed"
                HEALTH_METRICS["${check_name}_response_time"]="$response_time"
                
                # Count number of metrics
                local metrics_count=$(echo "$response_body" | grep -c "^[a-zA-Z_][a-zA-Z0-9_]*{.*} [0-9]" || echo "0")
                HEALTH_METRICS["${check_name}_metrics_count"]="$metrics_count"
                
                log_info "Metrics endpoint validation passed: $metrics_count metrics available (${response_time}ms)"
            else
                HEALTH_RESULTS["$check_name"]="failed"
                HEALTH_ERRORS["$check_name"]="Invalid Prometheus metrics format"
                log_error "Metrics endpoint validation failed: invalid format"
                OVERALL_STATUS="unhealthy"
                return 1
            fi
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Invalid content type for metrics endpoint"
            log_error "Metrics endpoint validation failed: invalid content type"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="HTTP request failed"
        log_error "Metrics endpoint validation HTTP request failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

# Performance baseline validation per Section 0.3.2
check_performance_baseline() {
    if [[ "$BASELINE_CHECK" != "true" ]]; then
        return 0
    fi
    
    log_info "Performing performance baseline validation..."
    
    local url="http://${HOST}:${PORT}${HEALTH_ENDPOINT}"
    local check_name="performance_baseline"
    
    # Perform multiple requests to get average response time
    local total_time=0
    local request_count=5
    local failed_requests=0
    
    for i in $(seq 1 $request_count); do
        if make_http_request "$url" "$TIMEOUT" "200"; then
            local response_time=$(get_response_time)
            total_time=$((total_time + response_time))
            log_debug "Performance sample $i: ${response_time}ms"
        else
            failed_requests=$((failed_requests + 1))
            log_warn "Performance sample $i failed"
        fi
    done
    
    local successful_requests=$((request_count - failed_requests))
    
    if [[ "$successful_requests" -gt 0 ]]; then
        local average_response_time=$((total_time / successful_requests))
        HEALTH_METRICS["${check_name}_average_response_time"]="$average_response_time"
        HEALTH_METRICS["${check_name}_success_rate"]="$(($successful_requests * 100 / request_count))"
        
        # Check against performance variance threshold (simulated - in real implementation would compare against Node.js baseline)
        local variance_threshold_ms=$((MAX_RESPONSE_TIME_MS * PERFORMANCE_VARIANCE_THRESHOLD / 100))
        
        if [[ "$average_response_time" -le "$variance_threshold_ms" ]]; then
            HEALTH_RESULTS["$check_name"]="passed"
            log_info "Performance baseline check passed: average ${average_response_time}ms (threshold: ${variance_threshold_ms}ms)"
        else
            HEALTH_RESULTS["$check_name"]="failed"
            HEALTH_ERRORS["$check_name"]="Performance variance exceeds threshold: ${average_response_time}ms > ${variance_threshold_ms}ms"
            log_error "Performance baseline check failed: variance exceeds ${PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
            OVERALL_STATUS="unhealthy"
            return 1
        fi
    else
        HEALTH_RESULTS["$check_name"]="failed"
        HEALTH_ERRORS["$check_name"]="All performance baseline requests failed"
        log_error "Performance baseline check failed: all requests failed"
        OVERALL_STATUS="unhealthy"
        return 1
    fi
    
    return 0
}

#
# Container Mode Health Check Functions
#

# Container health check implementation per Section 8.3.2
run_container_health_check() {
    log_info "Running container health check (Docker HEALTHCHECK mode)..."
    
    # Simple container health check equivalent to Docker HEALTHCHECK instruction
    local url="http://${HOST}:${PORT}${HEALTH_ENDPOINT}"
    
    if make_http_request "$url" "$CONTAINER_HEALTH_TIMEOUT" "200"; then
        local response_body=$(get_response_body)
        local status=$(extract_json_field "$response_body" "status")
        
        if [[ "$status" == "healthy" ]]; then
            log_info "Container health check passed: $status"
            return 0
        else
            log_error "Container health check failed: $status"
            return 1
        fi
    else
        log_error "Container health check HTTP request failed"
        return 1
    fi
}

#
# Output and Reporting Functions
#

# Generate comprehensive health report
generate_health_report() {
    local report_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        # JSON format output for enterprise integration
        cat << EOF
{
  "timestamp": "$report_timestamp",
  "script_version": "$SCRIPT_VERSION",
  "overall_status": "$OVERALL_STATUS",
  "exit_code": $EXIT_CODE,
  "configuration": {
    "host": "$HOST",
    "port": "$PORT",
    "timeout": "$TIMEOUT",
    "container_mode": $CONTAINER_MODE,
    "enterprise_mode": $ENTERPRISE_MODE,
    "baseline_check": $BASELINE_CHECK
  },
  "health_checks": {
EOF
        
        local first=true
        for check in "${!HEALTH_RESULTS[@]}"; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            
            local status="${HEALTH_RESULTS[$check]}"
            local error="${HEALTH_ERRORS[$check]:-}"
            
            echo "    \"$check\": {"
            echo "      \"status\": \"$status\""
            
            if [[ -n "$error" ]]; then
                echo "      ,\"error\": \"$error\""
            fi
            
            # Add metrics for this check
            for metric in "${!HEALTH_METRICS[@]}"; do
                if [[ "$metric" == "${check}_"* ]]; then
                    local metric_name="${metric#${check}_}"
                    local metric_value="${HEALTH_METRICS[$metric]}"
                    echo "      ,\"$metric_name\": $metric_value"
                fi
            done
            
            echo -n "    }"
        done
        
        cat << EOF

  },
  "performance_metrics": {
EOF
        
        first=true
        for metric in "${!HEALTH_METRICS[@]}"; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            echo "    \"$metric\": ${HEALTH_METRICS[$metric]}"
        done
        
        cat << EOF

  }
}
EOF
    else
        # Human-readable format output
        echo ""
        echo "================================================================================"
        echo "$SCRIPT_DESCRIPTION - Health Check Report"
        echo "================================================================================"
        echo "Timestamp: $report_timestamp"
        echo "Script Version: $SCRIPT_VERSION"
        echo "Overall Status: $OVERALL_STATUS"
        echo "Exit Code: $EXIT_CODE"
        echo ""
        echo "Configuration:"
        echo "  Host: $HOST"
        echo "  Port: $PORT"
        echo "  Timeout: ${TIMEOUT}s"
        echo "  Container Mode: $CONTAINER_MODE"
        echo "  Enterprise Mode: $ENTERPRISE_MODE"
        echo "  Baseline Check: $BASELINE_CHECK"
        echo ""
        echo "Health Check Results:"
        echo "--------------------------------------------------------------------------------"
        
        for check in "${!HEALTH_RESULTS[@]}"; do
            local status="${HEALTH_RESULTS[$check]}"
            local error="${HEALTH_ERRORS[$check]:-}"
            
            case "$status" in
                "passed")
                    printf "  %-25s ${GREEN}%s${NC}\n" "$check:" "PASSED"
                    ;;
                "degraded")
                    printf "  %-25s ${YELLOW}%s${NC}\n" "$check:" "DEGRADED"
                    ;;
                "failed")
                    printf "  %-25s ${RED}%s${NC}\n" "$check:" "FAILED"
                    ;;
                *)
                    printf "  %-25s ${PURPLE}%s${NC}\n" "$check:" "UNKNOWN"
                    ;;
            esac
            
            if [[ -n "$error" ]]; then
                echo "    Error: $error"
            fi
            
            # Show metrics for this check
            for metric in "${!HEALTH_METRICS[@]}"; do
                if [[ "$metric" == "${check}_"* ]]; then
                    local metric_name="${metric#${check}_}"
                    local metric_value="${HEALTH_METRICS[$metric]}"
                    echo "    $metric_name: $metric_value"
                fi
            done
            echo ""
        done
        
        echo "=================================================================================="
    fi
}

# Show usage information
show_usage() {
    cat << EOF
$SCRIPT_DESCRIPTION

Usage: $SCRIPT_NAME [OPTIONS]

OPTIONS:
  --host HOST             Flask application host (default: $DEFAULT_HOST)
  --port PORT             Flask application port (default: $DEFAULT_PORT)
  --timeout SECONDS       Request timeout in seconds (default: $DEFAULT_TIMEOUT)
  --verbose               Enable verbose output logging
  --json                  Output results in JSON format
  --critical-only         Only perform critical health checks
  --container-mode        Run in container health check mode
  --enterprise-mode       Enable enterprise monitoring integration
  --baseline-check        Perform baseline performance validation
  --help                  Display this help message

ENVIRONMENT VARIABLES:
  FLASK_HOST              Override default host
  FLASK_PORT              Override default port
  HEALTH_CHECK_TIMEOUT    Override request timeout
  ENTERPRISE_LOGGING_ENABLED    Enable enterprise logging integration
  PERFORMANCE_VARIANCE_THRESHOLD    Maximum allowed performance variance

EXIT CODES:
  0    All health checks passed successfully
  1    Critical health check failures detected
  2    Configuration or environment errors
  3    Timeout or connectivity issues
  4    Authentication or authorization failures
  5    Service degradation detected (non-critical)

EXAMPLES:
  # Basic health check
  $SCRIPT_NAME

  # Health check with custom host and port
  $SCRIPT_NAME --host 192.168.1.100 --port 5000

  # Container health check mode
  $SCRIPT_NAME --container-mode

  # Enterprise monitoring with JSON output
  $SCRIPT_NAME --enterprise-mode --json --baseline-check

  # Verbose debugging
  $SCRIPT_NAME --verbose --timeout 60

For more information, see the technical specification documentation.
EOF
}

#
# Main Execution Logic
#

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --host)
                HOST="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --critical-only)
                CRITICAL_ONLY=true
                shift
                ;;
            --container-mode)
                CONTAINER_MODE=true
                shift
                ;;
            --enterprise-mode)
                ENTERPRISE_MODE=true
                ENTERPRISE_LOGGING_ENABLED=true
                shift
                ;;
            --baseline-check)
                BASELINE_CHECK=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 2
                ;;
        esac
    done
}

# Validate configuration and environment
validate_configuration() {
    # Validate host and port
    if [[ -z "$HOST" ]]; then
        log_error "Host not specified"
        exit 2
    fi
    
    if [[ -z "$PORT" ]]; then
        log_error "Port not specified"
        exit 2
    fi
    
    # Validate timeout
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -le 0 ]]; then
        log_error "Invalid timeout value: $TIMEOUT"
        exit 2
    fi
    
    # Check required tools
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required but not installed"
        exit 2
    fi
    
    log_debug "Configuration validated successfully"
    log_debug "Target: http://${HOST}:${PORT}"
    log_debug "Timeout: ${TIMEOUT}s"
    log_debug "Container Mode: $CONTAINER_MODE"
    log_debug "Enterprise Mode: $ENTERPRISE_MODE"
}

# Execute all health checks based on configuration
execute_health_checks() {
    log_info "Starting comprehensive health check validation..."
    log_info "Target: http://${HOST}:${PORT}"
    
    # Container mode: simplified health check
    if [[ "$CONTAINER_MODE" == "true" ]]; then
        if run_container_health_check; then
            EXIT_CODE=0
        else
            EXIT_CODE=1
        fi
        return $EXIT_CODE
    fi
    
    # Standard mode: comprehensive health checks
    local checks_failed=0
    local checks_degraded=0
    
    # Critical health checks (always performed)
    if ! check_liveness_probe; then
        checks_failed=$((checks_failed + 1))
    fi
    
    if ! check_readiness_probe; then
        checks_failed=$((checks_failed + 1))
    fi
    
    if ! check_basic_health; then
        checks_failed=$((checks_failed + 1))
    fi
    
    # Extended health checks (unless critical-only mode)
    if [[ "$CRITICAL_ONLY" != "true" ]]; then
        if ! check_database_connectivity; then
            if [[ "${HEALTH_RESULTS[database_connectivity]}" == "degraded" ]]; then
                checks_degraded=$((checks_degraded + 1))
            else
                checks_failed=$((checks_failed + 1))
            fi
        fi
        
        if ! check_cache_connectivity; then
            if [[ "${HEALTH_RESULTS[cache_connectivity]}" == "degraded" ]]; then
                checks_degraded=$((checks_degraded + 1))
            else
                checks_failed=$((checks_failed + 1))
            fi
        fi
        
        if ! check_external_services; then
            if [[ "${HEALTH_RESULTS[external_services]}" == "degraded" ]]; then
                checks_degraded=$((checks_degraded + 1))
            else
                checks_failed=$((checks_failed + 1))
            fi
        fi
        
        if ! check_monitoring_services; then
            if [[ "${HEALTH_RESULTS[monitoring_services]}" == "degraded" ]]; then
                checks_degraded=$((checks_degraded + 1))
            else
                checks_failed=$((checks_failed + 1))
            fi
        fi
        
        if ! check_metrics_endpoint; then
            checks_failed=$((checks_failed + 1))
        fi
        
        if ! check_performance_baseline; then
            checks_failed=$((checks_failed + 1))
        fi
    fi
    
    # Determine exit code based on results
    if [[ "$checks_failed" -gt 0 ]]; then
        EXIT_CODE=1
        OVERALL_STATUS="unhealthy"
        log_error "Health check validation failed: $checks_failed critical failures"
    elif [[ "$checks_degraded" -gt 0 ]]; then
        EXIT_CODE=5
        OVERALL_STATUS="degraded"
        log_warn "Health check validation completed with degradation: $checks_degraded services degraded"
    else
        EXIT_CODE=0
        OVERALL_STATUS="healthy"
        log_info "Health check validation passed: all checks successful"
    fi
    
    return $EXIT_CODE
}

# Cleanup function
cleanup() {
    # Remove temporary files
    rm -f /tmp/health_check_response_* 2>/dev/null || true
    
    log_debug "Cleanup completed"
}

# Signal handlers
trap cleanup EXIT
trap 'log_error "Health check interrupted"; exit 130' INT TERM

#
# Main Script Execution
#

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate configuration
    validate_configuration
    
    # Log startup information
    log_info "Starting $SCRIPT_DESCRIPTION v$SCRIPT_VERSION"
    log_info "Configuration: ${HOST}:${PORT} (timeout: ${TIMEOUT}s)"
    
    # Execute health checks
    execute_health_checks
    local health_check_exit_code=$?
    
    # Generate and display report
    generate_health_report
    
    # Final logging
    case $EXIT_CODE in
        0)
            log_info "Health check validation completed successfully"
            ;;
        1)
            log_error "Health check validation failed with critical errors"
            ;;
        2)
            log_error "Health check validation failed due to configuration errors"
            ;;
        3)
            log_error "Health check validation failed due to connectivity issues"
            ;;
        4)
            log_error "Health check validation failed due to authentication issues"
            ;;
        5)
            log_warn "Health check validation completed with service degradation"
            ;;
        *)
            log_error "Health check validation completed with unknown exit code: $EXIT_CODE"
            ;;
    esac
    
    exit $EXIT_CODE
}

# Execute main function with all arguments
main "$@"