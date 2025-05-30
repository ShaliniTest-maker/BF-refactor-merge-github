#!/bin/bash

#
# Health Check Validation Script
# 
# Comprehensive system health monitoring for Flask application implementing 
# database connectivity validation, external service integration checks, and 
# container orchestration compatibility per Section 8.3.2 and Section 6.1.3.
#
# This script validates:
# - Flask application health endpoints (/health, /health/ready, /health/live)
# - Database connectivity (MongoDB and Redis) per Section 6.2.1
# - External service integration (Auth0, AWS S3, APM services) per Section 0.1.3
# - Container health validation for Kubernetes orchestration per Section 8.4
# - Prometheus metrics collection endpoint per Section 3.6 monitoring
#
# Exit Codes:
# 0 - All health checks passed
# 1 - Flask application health check failed
# 2 - Database connectivity check failed
# 3 - External service validation failed
# 4 - Metrics endpoint validation failed
# 5 - Configuration error or script failure
#
# Usage:
#   ./health-check.sh [options]
#   
# Options:
#   --host HOST         Application host (default: localhost)
#   --port PORT         Application port (default: 8000)
#   --timeout SECONDS   Request timeout (default: 10)
#   --verbose           Enable verbose logging
#   --skip-external     Skip external service checks (for development)
#   --container-mode    Container/Kubernetes compatibility mode
#   --help              Show this help message
#

set -euo pipefail

# Default configuration values
DEFAULT_HOST="localhost"
DEFAULT_PORT="8000"
DEFAULT_TIMEOUT="10"
DEFAULT_RETRIES="3"
DEFAULT_RETRY_DELAY="2"

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(dirname "$0")"
LOG_PREFIX="[HEALTH-CHECK]"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Health check configuration
HOST="${HEALTH_CHECK_HOST:-$DEFAULT_HOST}"
PORT="${HEALTH_CHECK_PORT:-$DEFAULT_PORT}"
TIMEOUT="${HEALTH_CHECK_TIMEOUT:-$DEFAULT_TIMEOUT}"
RETRIES="${HEALTH_CHECK_RETRIES:-$DEFAULT_RETRIES}"
RETRY_DELAY="${HEALTH_CHECK_RETRY_DELAY:-$DEFAULT_RETRY_DELAY}"
VERBOSE="${HEALTH_CHECK_VERBOSE:-false}"
SKIP_EXTERNAL="${HEALTH_CHECK_SKIP_EXTERNAL:-false}"
CONTAINER_MODE="${HEALTH_CHECK_CONTAINER_MODE:-false}"

# Health check endpoints per Section 8.3.2
BASE_URL="http://${HOST}:${PORT}"
HEALTH_ENDPOINT="${BASE_URL}/health"
READY_ENDPOINT="${BASE_URL}/health/ready" 
LIVE_ENDPOINT="${BASE_URL}/health/live"
METRICS_ENDPOINT="${BASE_URL}/metrics"

# Error tracking
declare -a FAILED_CHECKS=()
OVERALL_STATUS=0

#
# Logging and output functions
#
log_info() {
    echo "$LOG_PREFIX [INFO] [$TIMESTAMP] $*"
}

log_error() {
    echo "$LOG_PREFIX [ERROR] [$TIMESTAMP] $*" >&2
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo "$LOG_PREFIX [DEBUG] [$TIMESTAMP] $*"
    fi
}

log_success() {
    echo "$LOG_PREFIX [SUCCESS] [$TIMESTAMP] $*"
}

#
# Utility functions
#
show_help() {
    cat << EOF
$SCRIPT_NAME - Flask Application Health Check Validator

Comprehensive health validation script implementing enterprise-grade health monitoring
for Flask applications with database connectivity, external service validation, and
container orchestration compatibility.

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --host HOST            Application host (default: $DEFAULT_HOST)
    --port PORT            Application port (default: $DEFAULT_PORT)
    --timeout SECONDS      Request timeout (default: $DEFAULT_TIMEOUT)
    --retries COUNT        Retry attempts for failed checks (default: $DEFAULT_RETRIES)
    --retry-delay SECONDS  Delay between retries (default: $DEFAULT_RETRY_DELAY)
    --verbose              Enable verbose logging output
    --skip-external        Skip external service validation (for local development)
    --container-mode       Enable container/Kubernetes compatibility mode
    --help                 Show this help message

ENVIRONMENT VARIABLES:
    HEALTH_CHECK_HOST            Override default host
    HEALTH_CHECK_PORT            Override default port
    HEALTH_CHECK_TIMEOUT         Override default timeout
    HEALTH_CHECK_RETRIES         Override default retry count
    HEALTH_CHECK_RETRY_DELAY     Override default retry delay
    HEALTH_CHECK_VERBOSE         Enable verbose mode (true/false)
    HEALTH_CHECK_SKIP_EXTERNAL   Skip external services (true/false)
    HEALTH_CHECK_CONTAINER_MODE  Enable container mode (true/false)

EXIT CODES:
    0    All health checks passed successfully
    1    Flask application health check failed
    2    Database connectivity check failed
    3    External service validation failed
    4    Metrics endpoint validation failed
    5    Configuration error or script failure

EXAMPLES:
    # Basic health check
    $SCRIPT_NAME

    # Health check with custom host and port
    $SCRIPT_NAME --host api.example.com --port 5000

    # Verbose health check skipping external services
    $SCRIPT_NAME --verbose --skip-external

    # Container/Kubernetes mode health check
    $SCRIPT_NAME --container-mode --timeout 5

For more information, see the technical specification Section 8.3.2 for container
health validation requirements and Section 6.1.3 for monitoring integration.
EOF
}

#
# HTTP request utility with retry logic and circuit breaker patterns
#
make_http_request() {
    local url="$1"
    local expected_status="${2:-200}"
    local description="${3:-HTTP request}"
    local retry_count=0
    local response_code=""
    local temp_file=""
    
    log_debug "Making HTTP request to: $url (expecting status: $expected_status)"
    
    # Create temporary file for response body
    temp_file=$(mktemp)
    trap "rm -f '$temp_file'" RETURN
    
    while [[ $retry_count -lt $RETRIES ]]; do
        log_debug "Attempt $((retry_count + 1))/$RETRIES for $description"
        
        # Make HTTP request with curl
        if response_code=$(curl \
            --silent \
            --show-error \
            --fail-with-body \
            --connect-timeout "$TIMEOUT" \
            --max-time "$((TIMEOUT * 2))" \
            --write-out "%{http_code}" \
            --output "$temp_file" \
            --header "Accept: application/json" \
            --header "User-Agent: Health-Check-Script/1.0" \
            "$url" 2>/dev/null); then
            
            log_debug "HTTP response code: $response_code"
            
            # Check if response code matches expected status
            if [[ "$response_code" == "$expected_status" ]]; then
                log_debug "$description successful (status: $response_code)"
                
                # Log response body in verbose mode
                if [[ "$VERBOSE" == "true" ]] && [[ -s "$temp_file" ]]; then
                    log_debug "Response body: $(head -c 500 "$temp_file")"
                fi
                
                return 0
            else
                log_debug "$description returned unexpected status: $response_code (expected: $expected_status)"
            fi
        else
            local curl_exit_code=$?
            log_debug "$description failed with curl exit code: $curl_exit_code"
            
            # Log error response if available
            if [[ -s "$temp_file" ]]; then
                log_debug "Error response body: $(head -c 200 "$temp_file")"
            fi
        fi
        
        # Increment retry count and wait before retrying
        ((retry_count++))
        if [[ $retry_count -lt $RETRIES ]]; then
            log_debug "Retrying in ${RETRY_DELAY} seconds..."
            sleep "$RETRY_DELAY"
        fi
    done
    
    # All retries exhausted
    log_error "$description failed after $RETRIES attempts (final status: ${response_code:-'no response'})"
    return 1
}

#
# Flask application health endpoint validation per Section 8.3.2
#
check_flask_health() {
    log_info "Validating Flask application health endpoints..."
    
    local health_checks_passed=0
    local total_health_checks=3
    
    # Basic health endpoint check (/health)
    log_debug "Checking basic health endpoint: $HEALTH_ENDPOINT"
    if make_http_request "$HEALTH_ENDPOINT" "200" "Basic health check"; then
        log_success "Basic health endpoint (/health) - OK"
        ((health_checks_passed++))
    else
        log_error "Basic health endpoint (/health) - FAILED"
        FAILED_CHECKS+=("flask_health_basic")
    fi
    
    # Readiness endpoint check (/health/ready) - Kubernetes readiness probe
    log_debug "Checking readiness endpoint: $READY_ENDPOINT"
    if make_http_request "$READY_ENDPOINT" "200" "Readiness check"; then
        log_success "Readiness endpoint (/health/ready) - OK"
        ((health_checks_passed++))
    else
        log_error "Readiness endpoint (/health/ready) - FAILED"
        FAILED_CHECKS+=("flask_health_ready")
    fi
    
    # Liveness endpoint check (/health/live) - Kubernetes liveness probe
    log_debug "Checking liveness endpoint: $LIVE_ENDPOINT"
    if make_http_request "$LIVE_ENDPOINT" "200" "Liveness check"; then
        log_success "Liveness endpoint (/health/live) - OK"
        ((health_checks_passed++))
    else
        log_error "Liveness endpoint (/health/live) - FAILED"
        FAILED_CHECKS+=("flask_health_live")
    fi
    
    # Evaluate overall Flask health status
    if [[ $health_checks_passed -eq $total_health_checks ]]; then
        log_success "Flask application health validation - ALL PASSED ($health_checks_passed/$total_health_checks)"
        return 0
    else
        log_error "Flask application health validation - FAILED ($health_checks_passed/$total_health_checks)"
        return 1
    fi
}

#
# Database connectivity validation per Section 6.2.1
#
check_database_connectivity() {
    log_info "Validating database connectivity..."
    
    local db_checks_passed=0
    local total_db_checks=2
    
    # MongoDB connectivity check through health endpoint
    log_debug "Validating MongoDB connectivity through Flask health endpoint..."
    local mongodb_health_url="${BASE_URL}/health/database/mongodb"
    if make_http_request "$mongodb_health_url" "200" "MongoDB connectivity check"; then
        log_success "MongoDB connectivity - OK"
        ((db_checks_passed++))
    else
        log_error "MongoDB connectivity - FAILED"
        FAILED_CHECKS+=("database_mongodb")
    fi
    
    # Redis connectivity check through health endpoint
    log_debug "Validating Redis connectivity through Flask health endpoint..."
    local redis_health_url="${BASE_URL}/health/database/redis"
    if make_http_request "$redis_health_url" "200" "Redis connectivity check"; then
        log_success "Redis connectivity - OK"
        ((db_checks_passed++))
    else
        log_error "Redis connectivity - FAILED"
        FAILED_CHECKS+=("database_redis")
    fi
    
    # Evaluate overall database connectivity status
    if [[ $db_checks_passed -eq $total_db_checks ]]; then
        log_success "Database connectivity validation - ALL PASSED ($db_checks_passed/$total_db_checks)"
        return 0
    else
        log_error "Database connectivity validation - FAILED ($db_checks_passed/$total_db_checks)"
        return 1
    fi
}

#
# External service integration validation per Section 0.1.3
#
check_external_services() {
    if [[ "$SKIP_EXTERNAL" == "true" ]]; then
        log_info "Skipping external service validation (--skip-external enabled)"
        return 0
    fi
    
    log_info "Validating external service integration..."
    
    local external_checks_passed=0
    local total_external_checks=3
    
    # Auth0 service integration check
    log_debug "Validating Auth0 integration through Flask health endpoint..."
    local auth0_health_url="${BASE_URL}/health/external/auth0"
    if make_http_request "$auth0_health_url" "200" "Auth0 integration check"; then
        log_success "Auth0 integration - OK"
        ((external_checks_passed++))
    else
        log_error "Auth0 integration - FAILED"
        FAILED_CHECKS+=("external_auth0")
    fi
    
    # AWS S3 service integration check
    log_debug "Validating AWS S3 integration through Flask health endpoint..."
    local s3_health_url="${BASE_URL}/health/external/s3"
    if make_http_request "$s3_health_url" "200" "AWS S3 integration check"; then
        log_success "AWS S3 integration - OK"
        ((external_checks_passed++))
    else
        log_error "AWS S3 integration - FAILED"
        FAILED_CHECKS+=("external_s3")
    fi
    
    # APM service integration check
    log_debug "Validating APM service integration through Flask health endpoint..."
    local apm_health_url="${BASE_URL}/health/external/apm"
    if make_http_request "$apm_health_url" "200" "APM integration check"; then
        log_success "APM integration - OK"
        ((external_checks_passed++))
    else
        log_error "APM integration - FAILED"
        FAILED_CHECKS+=("external_apm")
    fi
    
    # Evaluate overall external service status
    if [[ $external_checks_passed -eq $total_external_checks ]]; then
        log_success "External service validation - ALL PASSED ($external_checks_passed/$total_external_checks)"
        return 0
    else
        log_error "External service validation - FAILED ($external_checks_passed/$total_external_checks)"
        return 1
    fi
}

#
# Prometheus metrics endpoint validation per Section 3.6.2
#
check_metrics_endpoint() {
    log_info "Validating Prometheus metrics endpoint..."
    
    log_debug "Checking metrics endpoint: $METRICS_ENDPOINT"
    if make_http_request "$METRICS_ENDPOINT" "200" "Metrics endpoint check"; then
        log_success "Prometheus metrics endpoint (/metrics) - OK"
        return 0
    else
        log_error "Prometheus metrics endpoint (/metrics) - FAILED"
        FAILED_CHECKS+=("metrics_endpoint")
        return 1
    fi
}

#
# Container health validation for Kubernetes orchestration per Section 8.4
#
check_container_readiness() {
    if [[ "$CONTAINER_MODE" != "true" ]]; then
        log_debug "Container mode disabled, skipping container-specific checks"
        return 0
    fi
    
    log_info "Performing container orchestration readiness validation..."
    
    # Validate that all required environment variables are set for container mode
    local required_env_vars=(
        "FLASK_ENV"
        "DATABASE_URL"
        "REDIS_URL"
    )
    
    local missing_vars=()
    for var in "${required_env_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Container mode validation - missing required environment variables: ${missing_vars[*]}"
        FAILED_CHECKS+=("container_env_vars")
        return 1
    fi
    
    # Check if running inside a container
    if [[ -f /.dockerenv ]] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null; then
        log_debug "Detected container environment"
    else
        log_debug "Not running in container environment"
    fi
    
    # Verify the application is listening on the expected port
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tln | grep -q ":${PORT} "; then
            log_debug "Application is listening on port $PORT"
        else
            log_error "Application is not listening on expected port $PORT"
            FAILED_CHECKS+=("container_port_binding")
            return 1
        fi
    fi
    
    log_success "Container orchestration readiness validation - OK"
    return 0
}

#
# Comprehensive health summary and reporting
#
generate_health_summary() {
    local total_checks_run=0
    local total_checks_failed=${#FAILED_CHECKS[@]}
    
    log_info "=== HEALTH CHECK SUMMARY ==="
    log_info "Timestamp: $TIMESTAMP"
    log_info "Target: $BASE_URL"
    log_info "Configuration: timeout=${TIMEOUT}s, retries=${RETRIES}, delay=${RETRY_DELAY}s"
    
    if [[ $total_checks_failed -eq 0 ]]; then
        log_success "Overall Status: HEALTHY - All checks passed"
        log_info "Flask application is ready for production traffic"
        
        if [[ "$CONTAINER_MODE" == "true" ]]; then
            log_info "Container orchestration compatibility: CONFIRMED"
        fi
        
        OVERALL_STATUS=0
    else
        log_error "Overall Status: UNHEALTHY - $total_checks_failed check(s) failed"
        log_error "Failed checks: ${FAILED_CHECKS[*]}"
        log_error "Flask application is NOT ready for production traffic"
        
        # Determine appropriate exit code based on failure types
        if [[ " ${FAILED_CHECKS[*]} " =~ " flask_health_" ]]; then
            OVERALL_STATUS=1  # Flask application health check failed
        elif [[ " ${FAILED_CHECKS[*]} " =~ " database_" ]]; then
            OVERALL_STATUS=2  # Database connectivity check failed
        elif [[ " ${FAILED_CHECKS[*]} " =~ " external_" ]]; then
            OVERALL_STATUS=3  # External service validation failed
        elif [[ " ${FAILED_CHECKS[*]} " =~ " metrics_" ]]; then
            OVERALL_STATUS=4  # Metrics endpoint validation failed
        else
            OVERALL_STATUS=5  # Configuration error or script failure
        fi
    fi
    
    log_info "=========================="
    
    # Output JSON summary for programmatic consumption
    if [[ "$VERBOSE" == "true" ]]; then
        cat << EOF
{
  "timestamp": "$TIMESTAMP",
  "target": "$BASE_URL",
  "overall_status": "$([[ $OVERALL_STATUS -eq 0 ]] && echo "healthy" || echo "unhealthy")",
  "exit_code": $OVERALL_STATUS,
  "failed_checks": [$(printf '"%s",' "${FAILED_CHECKS[@]}" | sed 's/,$//')]
  "configuration": {
    "timeout": $TIMEOUT,
    "retries": $RETRIES,
    "retry_delay": $RETRY_DELAY,
    "skip_external": $SKIP_EXTERNAL,
    "container_mode": $CONTAINER_MODE
  }
}
EOF
    fi
}

#
# Command line argument parsing
#
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
            --retries)
                RETRIES="$2"
                shift 2
                ;;
            --retry-delay)
                RETRY_DELAY="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --skip-external)
                SKIP_EXTERNAL="true"
                shift
                ;;
            --container-mode)
                CONTAINER_MODE="true"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                log_error "Use --help for usage information"
                exit 5
                ;;
        esac
    done
    
    # Update URLs with parsed host and port
    BASE_URL="http://${HOST}:${PORT}"
    HEALTH_ENDPOINT="${BASE_URL}/health"
    READY_ENDPOINT="${BASE_URL}/health/ready"
    LIVE_ENDPOINT="${BASE_URL}/health/live"
    METRICS_ENDPOINT="${BASE_URL}/metrics"
}

#
# Dependency validation
#
validate_dependencies() {
    log_debug "Validating script dependencies..."
    
    # Check for required commands
    local required_commands=("curl")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_commands[*]}"
        log_error "Please install the missing dependencies and try again"
        exit 5
    fi
    
    # Validate configuration parameters
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]] || [[ "$TIMEOUT" -gt 300 ]]; then
        log_error "Invalid timeout value: $TIMEOUT (must be 1-300 seconds)"
        exit 5
    fi
    
    if ! [[ "$RETRIES" =~ ^[0-9]+$ ]] || [[ "$RETRIES" -lt 1 ]] || [[ "$RETRIES" -gt 10 ]]; then
        log_error "Invalid retries value: $RETRIES (must be 1-10)"
        exit 5
    fi
    
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
        log_error "Invalid port value: $PORT (must be 1-65535)"
        exit 5
    fi
    
    log_debug "Dependency validation completed successfully"
}

#
# Main execution function
#
main() {
    # Initialize script
    log_info "Starting Flask application health check validation"
    log_debug "Script: $SCRIPT_NAME, Version: 1.0"
    log_debug "Configuration: host=$HOST, port=$PORT, timeout=${TIMEOUT}s"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate dependencies and configuration
    validate_dependencies
    
    # Trap signals for cleanup
    trap 'log_error "Health check interrupted"; exit 5' INT TERM
    
    # Execute health checks in sequence
    log_info "Beginning comprehensive health validation..."
    
    # 1. Flask application health endpoints
    if ! check_flask_health; then
        log_error "Critical: Flask application health check failed"
        # Continue with other checks for comprehensive reporting
    fi
    
    # 2. Database connectivity validation
    if ! check_database_connectivity; then
        log_error "Critical: Database connectivity validation failed"
        # Continue with other checks for comprehensive reporting
    fi
    
    # 3. External service integration (optional in development)
    if ! check_external_services; then
        log_error "Warning: External service validation failed"
        # Continue with other checks for comprehensive reporting
    fi
    
    # 4. Prometheus metrics endpoint
    if ! check_metrics_endpoint; then
        log_error "Warning: Metrics endpoint validation failed"
        # Continue with other checks for comprehensive reporting
    fi
    
    # 5. Container orchestration readiness (when enabled)
    if ! check_container_readiness; then
        log_error "Warning: Container readiness validation failed"
        # Continue for comprehensive reporting
    fi
    
    # Generate comprehensive health summary
    generate_health_summary
    
    # Exit with appropriate status code
    exit $OVERALL_STATUS
}

# Execute main function with all arguments
main "$@"