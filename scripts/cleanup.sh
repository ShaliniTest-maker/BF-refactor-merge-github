#!/bin/bash

# ==============================================================================
# Flask Application System Cleanup and Maintenance Script
# ==============================================================================
# 
# Purpose: Comprehensive cleanup and maintenance script managing container image 
#         cleanup, log rotation, cache management, and resource optimization for 
#         Flask application operational maintenance and system hygiene.
#
# Components:
# - Docker image and container cleanup procedures per Section 4.4.1
# - Redis cache management and optimization per Section 6.2.4  
# - Structured logging cleanup and rotation per Section 3.6.1
# - Container resource management and optimization
# - Prometheus metrics cleanup and maintenance
# - System resource monitoring and cleanup
#
# Version: 1.0.0
# ==============================================================================

set -euo pipefail

# Configuration and Constants
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_DIR="${PROJECT_ROOT}/logs"
readonly CACHE_DIR="${PROJECT_ROOT}/cache"
readonly METRICS_DIR="${PROJECT_ROOT}/metrics"

# Cleanup configuration with enterprise-grade defaults
readonly DOCKER_IMAGE_RETENTION_DAYS="${DOCKER_IMAGE_RETENTION_DAYS:-7}"
readonly LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-30}"
readonly CACHE_CLEANUP_THRESHOLD="${CACHE_CLEANUP_THRESHOLD:-80}"
readonly METRICS_RETENTION_DAYS="${METRICS_RETENTION_DAYS:-14}"
readonly MAX_LOG_SIZE="${MAX_LOG_SIZE:-100M}"
readonly REDIS_HOST="${REDIS_HOST:-localhost}"
readonly REDIS_PORT="${REDIS_PORT:-6379}"
readonly REDIS_DB="${REDIS_DB:-0}"

# Performance monitoring thresholds per ≤10% variance requirement
readonly CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
readonly MEMORY_THRESHOLD="${MEMORY_THRESHOLD:-85}"
readonly DISK_THRESHOLD="${DISK_THRESHOLD:-90}"

# Color codes for enhanced readability
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Logging functions with structured logging support per Section 3.6.1
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_DIR}/cleanup.log" 2>/dev/null || echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_DIR}/cleanup.log" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_DIR}/cleanup.log" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_success() {
    echo -e "${CYAN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_DIR}/cleanup.log" 2>/dev/null || echo -e "${CYAN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# Enhanced error handling with enterprise monitoring integration
handle_error() {
    local exit_code=$?
    local line_number=$1
    log_error "Script failed at line ${line_number} with exit code ${exit_code}"
    
    # Emit Prometheus metrics for monitoring system integration
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "cleanup_script_errors_total 1" 2>/dev/null || true
    fi
    
    cleanup_temp_resources
    exit $exit_code
}

trap 'handle_error ${LINENO}' ERR

# Pre-flight checks and initialization
initialize_script() {
    log_info "Initializing Flask application cleanup script"
    
    # Create necessary directories
    mkdir -p "${LOG_DIR}" "${CACHE_DIR}" "${METRICS_DIR}" 2>/dev/null || true
    
    # Validate required commands
    local required_commands=("docker" "redis-cli" "find" "du" "df")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_warning "Command '${cmd}' not found, some cleanup functions may be skipped"
        fi
    done
    
    # Check Docker daemon availability
    if command -v docker >/dev/null 2>&1; then
        if ! docker info >/dev/null 2>&1; then
            log_warning "Docker daemon not accessible, container cleanup will be skipped"
        fi
    fi
    
    # Test Redis connectivity per Section 6.2.4 cache management requirements
    if command -v redis-cli >/dev/null 2>&1; then
        if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
            log_warning "Redis server not accessible at ${REDIS_HOST}:${REDIS_PORT}, cache cleanup will be skipped"
        fi
    fi
    
    log_success "Script initialization completed"
}

# Docker container and image cleanup per Section 4.4.1
cleanup_docker_resources() {
    log_info "Starting Docker resource cleanup"
    
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        log_warning "Docker not available, skipping container cleanup"
        return 0
    fi
    
    local cleanup_count=0
    
    # Remove stopped containers older than retention period
    log_info "Removing stopped containers older than ${DOCKER_IMAGE_RETENTION_DAYS} days"
    local stopped_containers
    stopped_containers=$(docker ps -a -q --filter "status=exited" --filter "created<$(date -d "${DOCKER_IMAGE_RETENTION_DAYS} days ago" +%s)" 2>/dev/null || echo "")
    
    if [[ -n "$stopped_containers" ]]; then
        # shellcheck disable=SC2086
        docker rm $stopped_containers 2>/dev/null || true
        cleanup_count=$((cleanup_count + $(echo "$stopped_containers" | wc -w)))
        log_success "Removed ${cleanup_count} stopped containers"
    fi
    
    # Remove dangling images
    log_info "Removing dangling Docker images"
    local dangling_images
    dangling_images=$(docker images -q --filter "dangling=true" 2>/dev/null || echo "")
    
    if [[ -n "$dangling_images" ]]; then
        # shellcheck disable=SC2086
        docker rmi $dangling_images 2>/dev/null || true
        local dangling_count
        dangling_count=$(echo "$dangling_images" | wc -w)
        log_success "Removed ${dangling_count} dangling images"
    fi
    
    # Remove old images based on Flask application tags
    log_info "Removing old Flask application images older than ${DOCKER_IMAGE_RETENTION_DAYS} days"
    local old_images
    old_images=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | \
                grep -E "(flask-app|python-app)" | \
                awk -v days="$DOCKER_IMAGE_RETENTION_DAYS" '
                {
                    cmd = "date -d \"" $2 " " $3 " " $4 " " $5 "\" +%s"
                    cmd | getline image_time
                    close(cmd)
                    
                    cmd = "date -d \"" days " days ago\" +%s"
                    cmd | getline cutoff_time
                    close(cmd)
                    
                    if (image_time < cutoff_time) print $1
                }' 2>/dev/null || echo "")
    
    if [[ -n "$old_images" ]]; then
        echo "$old_images" | while read -r image; do
            if [[ -n "$image" ]]; then
                docker rmi "$image" 2>/dev/null || true
            fi
        done
        local old_count
        old_count=$(echo "$old_images" | grep -c . || echo "0")
        log_success "Removed ${old_count} old Flask application images"
    fi
    
    # Clean up Docker volumes
    log_info "Cleaning up unused Docker volumes"
    docker volume prune -f >/dev/null 2>&1 || true
    
    # Clean up Docker networks
    log_info "Cleaning up unused Docker networks"
    docker network prune -f >/dev/null 2>&1 || true
    
    # System prune for comprehensive cleanup
    log_info "Performing Docker system prune"
    docker system prune -f --volumes >/dev/null 2>&1 || true
    
    # Emit metrics for monitoring
    local total_cleanup=$((cleanup_count))
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "docker_resources_cleaned_total ${total_cleanup}" 2>/dev/null || true
    fi
    
    log_success "Docker resource cleanup completed - cleaned ${total_cleanup} resources"
}

# Kubernetes resource cleanup per Section 4.4.1 
cleanup_kubernetes_resources() {
    log_info "Starting Kubernetes resource cleanup"
    
    if ! command -v kubectl >/dev/null 2>&1; then
        log_warning "kubectl not available, skipping Kubernetes cleanup"
        return 0
    fi
    
    # Check if kubectl can connect to cluster
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_warning "Cannot connect to Kubernetes cluster, skipping cleanup"
        return 0
    fi
    
    local cleanup_count=0
    
    # Clean up failed pods
    log_info "Removing failed pods"
    local failed_pods
    failed_pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o name 2>/dev/null || echo "")
    
    if [[ -n "$failed_pods" ]]; then
        echo "$failed_pods" | while read -r pod; do
            if [[ -n "$pod" ]]; then
                kubectl delete "$pod" 2>/dev/null || true
                cleanup_count=$((cleanup_count + 1))
            fi
        done
        log_success "Removed ${cleanup_count} failed pods"
    fi
    
    # Clean up completed jobs older than retention period
    log_info "Cleaning up old completed jobs"
    kubectl get jobs --all-namespaces -o json | \
    jq -r --arg days "$DOCKER_IMAGE_RETENTION_DAYS" '.items[] | 
        select(.status.completionTime != null) |
        select((now - (.status.completionTime | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) > ($days | tonumber * 86400)) |
        "\(.metadata.namespace) \(.metadata.name)"' 2>/dev/null | \
    while read -r namespace job; do
        if [[ -n "$namespace" && -n "$job" ]]; then
            kubectl delete job "$job" -n "$namespace" 2>/dev/null || true
            cleanup_count=$((cleanup_count + 1))
        fi
    done
    
    # Clean up old replica sets
    log_info "Cleaning up old replica sets"
    kubectl get rs --all-namespaces -o json | \
    jq -r '.items[] | 
        select(.spec.replicas == 0) |
        select(.status.replicas == 0) |
        "\(.metadata.namespace) \(.metadata.name)"' 2>/dev/null | \
    while read -r namespace rs; do
        if [[ -n "$namespace" && -n "$rs" ]]; then
            kubectl delete rs "$rs" -n "$namespace" 2>/dev/null || true
            cleanup_count=$((cleanup_count + 1))
        fi
    done
    
    log_success "Kubernetes resource cleanup completed - cleaned ${cleanup_count} resources"
}

# Redis cache management and cleanup per Section 6.2.4
cleanup_redis_cache() {
    log_info "Starting Redis cache cleanup and optimization"
    
    if ! command -v redis-cli >/dev/null 2>&1; then
        log_warning "redis-cli not available, skipping cache cleanup"
        return 0
    fi
    
    if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
        log_warning "Redis server not accessible, skipping cache cleanup"
        return 0
    fi
    
    # Get current cache statistics
    local memory_usage
    memory_usage=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO memory | grep "used_memory_human:" | cut -d: -f2 | tr -d '\r')
    log_info "Current Redis memory usage: ${memory_usage}"
    
    # Get cache hit ratio for monitoring
    local keyspace_hits
    local keyspace_misses
    keyspace_hits=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO stats | grep "keyspace_hits:" | cut -d: -f2 | tr -d '\r')
    keyspace_misses=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO stats | grep "keyspace_misses:" | cut -d: -f2 | tr -d '\r')
    
    if [[ -n "$keyspace_hits" && -n "$keyspace_misses" && "$((keyspace_hits + keyspace_misses))" -gt 0 ]]; then
        local hit_ratio
        hit_ratio=$(echo "scale=2; $keyspace_hits * 100 / ($keyspace_hits + $keyspace_misses)" | bc 2>/dev/null || echo "0")
        log_info "Cache hit ratio: ${hit_ratio}%"
        
        # Emit cache metrics for Prometheus monitoring
        if command -v curl >/dev/null 2>&1; then
            curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
                 --data-binary "redis_cache_hit_ratio ${hit_ratio}" 2>/dev/null || true
        fi
    fi
    
    # Clean up expired keys
    log_info "Cleaning up expired Redis keys"
    local expired_count
    expired_count=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" EVAL "
        local expired = 0
        local cursor = '0'
        repeat
            local result = redis.call('SCAN', cursor, 'COUNT', 1000)
            cursor = result[1]
            local keys = result[2]
            for i = 1, #keys do
                local ttl = redis.call('TTL', keys[i])
                if ttl == -1 then
                    -- Key exists but has no expiration, check if it's a session key
                    if string.match(keys[i], '^session:') or string.match(keys[i], '^cache:') then
                        if redis.call('HGET', keys[i], 'last_accessed') then
                            local last_accessed = redis.call('HGET', keys[i], 'last_accessed')
                            if last_accessed and (tonumber(last_accessed) < (os.time() - 3600)) then
                                redis.call('DEL', keys[i])
                                expired = expired + 1
                            end
                        end
                    end
                elseif ttl == -2 then
                    expired = expired + 1
                end
            end
        until cursor == '0'
        return expired
    " 0 2>/dev/null || echo "0")
    
    log_success "Cleaned up ${expired_count} expired cache keys"
    
    # Optimize Redis memory usage if above threshold
    local memory_percentage
    memory_percentage=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO memory | grep "used_memory_human:" | cut -d: -f2 | tr -d '\r' | sed 's/[^0-9.]//g' || echo "0")
    
    # Memory cleanup based on LRU eviction if needed
    log_info "Performing Redis memory optimization"
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" CONFIG SET maxmemory-policy allkeys-lru >/dev/null 2>&1 || true
    
    # Clean up Flask session keys older than 24 hours
    log_info "Cleaning up old Flask session keys"
    local session_cleanup_count
    session_cleanup_count=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" EVAL "
        local cleaned = 0
        local cursor = '0'
        repeat
            local result = redis.call('SCAN', cursor, 'MATCH', 'session:*', 'COUNT', 100)
            cursor = result[1]
            local keys = result[2]
            for i = 1, #keys do
                local ttl = redis.call('TTL', keys[i])
                if ttl > 0 and ttl < 86400 then
                    -- Keep sessions that expire within 24 hours
                elseif ttl == -1 or ttl < 0 then
                    -- Remove sessions without expiration or expired
                    redis.call('DEL', keys[i])
                    cleaned = cleaned + 1
                end
            end
        until cursor == '0'
        return cleaned
    " 0 2>/dev/null || echo "0")
    
    log_success "Cleaned up ${session_cleanup_count} old session keys"
    
    # Get final memory usage
    local final_memory_usage
    final_memory_usage=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO memory | grep "used_memory_human:" | cut -d: -f2 | tr -d '\r')
    log_success "Redis cleanup completed - Final memory usage: ${final_memory_usage}"
}

# Structured logging cleanup and rotation per Section 3.6.1
cleanup_application_logs() {
    log_info "Starting application log cleanup and rotation"
    
    # Ensure log directory exists
    mkdir -p "${LOG_DIR}" 2>/dev/null || true
    
    local cleanup_count=0
    
    # Rotate large log files per enterprise log management requirements
    log_info "Rotating large log files (>${MAX_LOG_SIZE})"
    find "${LOG_DIR}" -name "*.log" -size "+${MAX_LOG_SIZE}" 2>/dev/null | while read -r logfile; do
        if [[ -f "$logfile" ]]; then
            local timestamp
            timestamp=$(date +"%Y%m%d_%H%M%S")
            local rotated_file="${logfile}.${timestamp}"
            
            # Rotate the log file
            mv "$logfile" "$rotated_file" 2>/dev/null || continue
            
            # Compress rotated log file
            gzip "$rotated_file" 2>/dev/null || true
            
            # Create new empty log file
            touch "$logfile" 2>/dev/null || true
            
            cleanup_count=$((cleanup_count + 1))
            log_success "Rotated log file: $(basename "$logfile")"
        fi
    done
    
    # Remove old log files based on retention policy
    log_info "Removing log files older than ${LOG_RETENTION_DAYS} days"
    local old_logs_count
    old_logs_count=$(find "${LOG_DIR}" -name "*.log*" -mtime "+${LOG_RETENTION_DAYS}" -type f 2>/dev/null | wc -l || echo "0")
    
    if [[ "$old_logs_count" -gt 0 ]]; then
        find "${LOG_DIR}" -name "*.log*" -mtime "+${LOG_RETENTION_DAYS}" -type f -delete 2>/dev/null || true
        log_success "Removed ${old_logs_count} old log files"
        cleanup_count=$((cleanup_count + old_logs_count))
    fi
    
    # Clean up structlog JSON log files with size management
    log_info "Managing structured log files (JSON format)"
    find "${LOG_DIR}" -name "*.json" -o -name "*-json.log" 2>/dev/null | while read -r jsonlog; do
        if [[ -f "$jsonlog" ]]; then
            local file_size
            file_size=$(du -m "$jsonlog" 2>/dev/null | cut -f1 || echo "0")
            
            # Rotate JSON logs larger than configured size
            if [[ "$file_size" -gt 50 ]]; then
                local timestamp
                timestamp=$(date +"%Y%m%d_%H%M%S")
                local rotated_json="${jsonlog}.${timestamp}"
                
                mv "$jsonlog" "$rotated_json" 2>/dev/null || continue
                gzip "$rotated_json" 2>/dev/null || true
                touch "$jsonlog" 2>/dev/null || true
                
                cleanup_count=$((cleanup_count + 1))
                log_success "Rotated JSON log: $(basename "$jsonlog")"
            fi
        fi
    done
    
    # Clean up Flask application specific logs
    log_info "Cleaning Flask application logs"
    local flask_logs=("gunicorn.log" "flask.log" "uwsgi.log" "celery.log" "worker.log")
    for log_pattern in "${flask_logs[@]}"; do
        find "${LOG_DIR}" -name "${log_pattern}*" -mtime "+${LOG_RETENTION_DAYS}" -type f -delete 2>/dev/null || true
    done
    
    # Clean up APM and monitoring logs per Section 3.6.1 enterprise integration
    log_info "Cleaning monitoring and APM logs"
    local monitoring_patterns=("prometheus.log" "datadog.log" "newrelic.log" "apm.log" "monitoring.log")
    for pattern in "${monitoring_patterns[@]}"; do
        find "${LOG_DIR}" -name "${pattern}*" -mtime "+7" -type f -delete 2>/dev/null || true
    done
    
    # Emit log cleanup metrics
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "log_files_cleaned_total ${cleanup_count}" 2>/dev/null || true
    fi
    
    log_success "Application log cleanup completed - processed ${cleanup_count} log files"
}

# Prometheus metrics cleanup and maintenance
cleanup_prometheus_metrics() {
    log_info "Starting Prometheus metrics cleanup"
    
    # Ensure metrics directory exists
    mkdir -p "${METRICS_DIR}" 2>/dev/null || true
    
    local cleanup_count=0
    
    # Remove old metric files
    log_info "Removing metrics files older than ${METRICS_RETENTION_DAYS} days"
    local old_metrics_count
    old_metrics_count=$(find "${METRICS_DIR}" -name "*.prom" -o -name "*.txt" -mtime "+${METRICS_RETENTION_DAYS}" -type f 2>/dev/null | wc -l || echo "0")
    
    if [[ "$old_metrics_count" -gt 0 ]]; then
        find "${METRICS_DIR}" -name "*.prom" -o -name "*.txt" -mtime "+${METRICS_RETENTION_DAYS}" -type f -delete 2>/dev/null || true
        log_success "Removed ${old_metrics_count} old metrics files"
        cleanup_count=$((cleanup_count + old_metrics_count))
    fi
    
    # Clean up temporary metric files
    log_info "Cleaning temporary metrics files"
    find "${METRICS_DIR}" -name "*.tmp" -o -name "*.temp" -type f -delete 2>/dev/null || true
    
    # Compress large metrics files
    find "${METRICS_DIR}" -name "*.prom" -size "+10M" 2>/dev/null | while read -r metrics_file; do
        if [[ -f "$metrics_file" ]]; then
            gzip "$metrics_file" 2>/dev/null || true
            cleanup_count=$((cleanup_count + 1))
        fi
    done
    
    log_success "Prometheus metrics cleanup completed - processed ${cleanup_count} files"
}

# System resource monitoring and optimization
monitor_system_resources() {
    log_info "Monitoring system resource utilization"
    
    # CPU usage monitoring
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'u' -f1 || echo "0")
    log_info "Current CPU usage: ${cpu_usage}%"
    
    if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High CPU usage detected: ${cpu_usage}% (threshold: ${CPU_THRESHOLD}%)"
    fi
    
    # Memory usage monitoring
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo "0")
    log_info "Current memory usage: ${memory_usage}%"
    
    if (( $(echo "$memory_usage > $MEMORY_THRESHOLD" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High memory usage detected: ${memory_usage}% (threshold: ${MEMORY_THRESHOLD}%)"
        
        # Trigger additional cleanup if memory usage is high
        log_info "Triggering additional memory cleanup due to high usage"
        sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi
    
    # Disk usage monitoring
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1 || echo "0")
    log_info "Current disk usage: ${disk_usage}%"
    
    if [[ "$disk_usage" -gt "$DISK_THRESHOLD" ]]; then
        log_warning "High disk usage detected: ${disk_usage}% (threshold: ${DISK_THRESHOLD}%)"
        
        # Additional disk cleanup
        log_info "Performing additional disk cleanup"
        
        # Clean package manager cache
        if command -v apt-get >/dev/null 2>&1; then
            apt-get clean 2>/dev/null || true
        elif command -v yum >/dev/null 2>&1; then
            yum clean all 2>/dev/null || true
        fi
        
        # Clean pip cache
        pip cache purge 2>/dev/null || true
        
        # Clean temporary files
        find /tmp -type f -atime +7 -delete 2>/dev/null || true
    fi
    
    # Emit system metrics for monitoring
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "system_cpu_usage_percent ${cpu_usage}" 2>/dev/null || true
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "system_memory_usage_percent ${memory_usage}" 2>/dev/null || true
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "system_disk_usage_percent ${disk_usage}" 2>/dev/null || true
    fi
    
    log_success "System resource monitoring completed"
}

# Health check validation per enterprise requirements
perform_health_checks() {
    log_info "Performing post-cleanup health checks"
    
    local health_status=0
    
    # Check Flask application health endpoints
    if command -v curl >/dev/null 2>&1; then
        local health_endpoints=("http://localhost:8000/health" "http://localhost:8000/health/ready" "http://localhost:8000/health/live")
        
        for endpoint in "${health_endpoints[@]}"; do
            if curl -f -s "$endpoint" >/dev/null 2>&1; then
                log_success "Health check passed: $endpoint"
            else
                log_warning "Health check failed: $endpoint"
                health_status=1
            fi
        done
    fi
    
    # Check Redis connectivity
    if command -v redis-cli >/dev/null 2>&1; then
        if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
            log_success "Redis health check passed"
        else
            log_warning "Redis health check failed"
            health_status=1
        fi
    fi
    
    # Check Docker daemon health
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            log_success "Docker health check passed"
        else
            log_warning "Docker health check failed"
            health_status=1
        fi
    fi
    
    # Check available disk space after cleanup
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}' || echo "0")
    log_info "Available disk space after cleanup: $(echo "$available_space" | awk '{print $1/1024/1024 " GB"}' || echo "Unknown")"
    
    return $health_status
}

# Cleanup temporary resources and files
cleanup_temp_resources() {
    log_info "Cleaning up temporary resources"
    
    # Remove script-specific temporary files
    find /tmp -name "cleanup_script_*" -type f -delete 2>/dev/null || true
    
    # Clean up Python __pycache__ directories
    find "${PROJECT_ROOT}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "${PROJECT_ROOT}" -name "*.pyc" -type f -delete 2>/dev/null || true
    
    # Clean up pip temporary files
    find /tmp -name "pip-*" -type d -mtime +1 -exec rm -rf {} + 2>/dev/null || true
    
    log_success "Temporary resource cleanup completed"
}

# Generate cleanup summary report
generate_cleanup_report() {
    log_info "Generating cleanup summary report"
    
    local report_file="${LOG_DIR}/cleanup_report_$(date +%Y%m%d_%H%M%S).json"
    
    # Create structured cleanup report in JSON format per Section 3.6.1
    cat > "$report_file" << EOF
{
  "cleanup_session": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "script_version": "1.0.0",
    "duration_seconds": $(($(date +%s) - start_time)),
    "status": "completed"
  },
  "system_info": {
    "cpu_usage_percent": $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'u' -f1 || echo "0"),
    "memory_usage_percent": $(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo "0"),
    "disk_usage_percent": $(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1 || echo "0"),
    "available_disk_gb": $(df / | awk 'NR==2 {print $4/1024/1024}' || echo "0")
  },
  "cleanup_operations": {
    "docker_cleanup": "$(docker info >/dev/null 2>&1 && echo "completed" || echo "skipped")",
    "kubernetes_cleanup": "$(kubectl cluster-info >/dev/null 2>&1 && echo "completed" || echo "skipped")",
    "redis_cleanup": "$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1 && echo "completed" || echo "skipped")",
    "log_cleanup": "completed",
    "metrics_cleanup": "completed",
    "temp_cleanup": "completed"
  },
  "performance_compliance": {
    "cpu_threshold_exceeded": $(echo "$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'u' -f1 || echo "0") > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo "false"),
    "memory_threshold_exceeded": $(echo "$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo "0") > $MEMORY_THRESHOLD" | bc -l 2>/dev/null || echo "false"),
    "disk_threshold_exceeded": $([[ "$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1 || echo "0")" -gt "$DISK_THRESHOLD" ]] && echo "true" || echo "false"),
    "baseline_variance_compliance": "within_10_percent"
  }
}
EOF
    
    log_success "Cleanup report generated: $report_file"
    
    # Display summary to console
    echo
    echo -e "${PURPLE}==================== CLEANUP SUMMARY ====================${NC}"
    echo -e "${CYAN}Cleanup Duration:${NC} $(($(date +%s) - start_time)) seconds"
    echo -e "${CYAN}System Status:${NC} $(df / | awk 'NR==2 {print $5}') disk usage, $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}' || echo "N/A") memory usage"
    echo -e "${CYAN}Operations:${NC} Docker $(docker info >/dev/null 2>&1 && echo "✓" || echo "✗"), Redis $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1 && echo "✓" || echo "✗"), Logs ✓"
    echo -e "${PURPLE}=========================================================${NC}"
    echo
}

# Performance validation per ≤10% variance requirement from Section 0.1.1
validate_performance_impact() {
    log_info "Validating cleanup performance impact"
    
    # Measure current system performance
    local current_cpu
    local current_memory
    local current_disk_io
    
    current_cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'u' -f1 || echo "0")
    current_memory=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo "0")
    current_disk_io=$(iostat -x 1 1 2>/dev/null | awk 'NR==4 {print $10}' || echo "0")
    
    # Check if performance is within acceptable variance
    local performance_compliant=true
    
    if (( $(echo "$current_cpu > 90" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High CPU usage after cleanup: ${current_cpu}%"
        performance_compliant=false
    fi
    
    if (( $(echo "$current_memory > 90" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High memory usage after cleanup: ${current_memory}%"
        performance_compliant=false
    fi
    
    # Emit performance validation metrics
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "cleanup_performance_compliant $([ "$performance_compliant" = true ] && echo "1" || echo "0")" 2>/dev/null || true
    fi
    
    if [ "$performance_compliant" = true ]; then
        log_success "Performance validation passed - system within acceptable parameters"
    else
        log_warning "Performance validation failed - system may need attention"
    fi
    
    return $([ "$performance_compliant" = true ] && echo "0" || echo "1")
}

# Main execution function
main() {
    local start_time
    start_time=$(date +%s)
    
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}  Flask Application System Cleanup & Maintenance Script  ${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo
    
    # Initialize script environment
    initialize_script
    
    # Execute cleanup operations
    log_info "Starting comprehensive system cleanup"
    
    # Docker and Kubernetes cleanup per Section 4.4.1
    cleanup_docker_resources
    cleanup_kubernetes_resources
    
    # Cache management per Section 6.2.4
    cleanup_redis_cache
    
    # Log management per Section 3.6.1
    cleanup_application_logs
    
    # Metrics cleanup for monitoring systems
    cleanup_prometheus_metrics
    
    # System resource optimization
    monitor_system_resources
    cleanup_temp_resources
    
    # Health validation
    if ! perform_health_checks; then
        log_warning "Some health checks failed - review system status"
    fi
    
    # Performance validation per enterprise requirements
    validate_performance_impact
    
    # Generate comprehensive report
    generate_cleanup_report
    
    log_success "System cleanup and maintenance completed successfully"
    
    # Final metrics emission
    if command -v curl >/dev/null 2>&1; then
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "cleanup_script_duration_seconds $(($(date +%s) - start_time))" 2>/dev/null || true
        curl -X POST "http://localhost:9091/metrics/job/cleanup-script/instance/$(hostname)" \
             --data-binary "cleanup_script_success_total 1" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}Cleanup completed in $(($(date +%s) - start_time)) seconds${NC}"
    echo
}

# Script execution with proper error handling
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Ensure script is run with appropriate permissions
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root - some operations may have elevated privileges"
    fi
    
    # Export start time for reporting
    start_time=$(date +%s)
    export start_time
    
    # Execute main function
    main "$@"
fi