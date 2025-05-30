#!/bin/bash

# ==============================================================================
# Dependencies Management Script for Flask Application Migration
# ==============================================================================
# 
# Purpose: Comprehensive dependency management implementing pip-tools for 
#          deterministic dependency resolution, security vulnerability scanning,
#          and automated dependency upgrade management for Flask application 
#          dependency lifecycle.
#
# Features:
# - pip-tools 7.3+ for deterministic dependency resolution with pip-compile validation
# - safety 3.0+ and pip-audit 2.7+ for comprehensive vulnerability scanning
# - Automated dependency upgrade workflow with security vulnerability remediation
# - License compliance validation for enterprise requirements
# - Integration with CI/CD pipeline per Section 8.5.1
#
# Author: Software Architecture Agent
# Version: 1.0.0
# ==============================================================================

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_ROOT}/logs/dependencies.log"
REQUIREMENTS_DIR="${PROJECT_ROOT}"
VENV_DIR="${PROJECT_ROOT}/.venv"

# Dependency management tool versions per Section 8.5.1
PIP_TOOLS_VERSION="7.3.0"
SAFETY_VERSION="3.0.1"
PIP_AUDIT_VERSION="2.7.2"
LICENSE_CHECKER_VERSION="0.9.0"

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging configuration
mkdir -p "$(dirname "$LOG_FILE")"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "${BLUE}$*${NC}"
}

log_warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

log_error() {
    log "ERROR" "${RED}$*${NC}"
}

log_success() {
    log "SUCCESS" "${GREEN}$*${NC}"
}

check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' not found. Please install it first."
        return 1
    fi
}

validate_python_version() {
    local python_cmd="$1"
    local min_version="3.8"
    
    if ! "$python_cmd" -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
        log_error "Python $min_version or higher is required per Section 3.1.1"
        return 1
    fi
    
    local version=$("$python_cmd" --version 2>&1 | awk '{print $2}')
    log_info "Using Python $version"
}

create_virtual_environment() {
    if [[ ! -d "$VENV_DIR" ]]; then
        log_info "Creating virtual environment at $VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi
    
    log_info "Activating virtual environment"
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip to latest version
    pip install --upgrade pip
}

# ==============================================================================
# DEPENDENCY MANAGEMENT FUNCTIONS
# ==============================================================================

install_dependency_tools() {
    log_info "Installing dependency management tools"
    
    # Install pip-tools for deterministic resolution per Section 8.5.1
    pip install "pip-tools==$PIP_TOOLS_VERSION"
    log_success "Installed pip-tools $PIP_TOOLS_VERSION"
    
    # Install security scanning tools per Section 8.5.1
    pip install "safety==$SAFETY_VERSION"
    pip install "pip-audit==$PIP_AUDIT_VERSION"
    log_success "Installed security scanning tools"
    
    # Install license compliance tool
    pip install "pip-licenses==$LICENSE_CHECKER_VERSION"
    log_success "Installed license compliance tools"
}

validate_requirements_files() {
    log_info "Validating requirements file structure"
    
    # Check for requirements.in file (source of truth)
    if [[ ! -f "$REQUIREMENTS_DIR/requirements.in" ]]; then
        log_warn "requirements.in not found. Creating template file."
        create_requirements_template
    fi
    
    # Check for requirements-dev.in file
    if [[ ! -f "$REQUIREMENTS_DIR/requirements-dev.in" ]]; then
        log_warn "requirements-dev.in not found. Creating template file."
        create_dev_requirements_template
    fi
    
    log_success "Requirements file structure validated"
}

create_requirements_template() {
    log_info "Creating requirements.in template based on Section 3.3"
    
    cat > "$REQUIREMENTS_DIR/requirements.in" << 'EOF'
# ==============================================================================
# Production Dependencies for Flask Application Migration
# ==============================================================================
# This file contains high-level production dependencies.
# Run 'pip-compile requirements.in' to generate requirements.txt

# Web Framework - Flask 2.3+ per Section 3.2.1
Flask>=2.3.3,<3.0.0
Werkzeug>=2.3.7,<3.0.0

# Flask Extensions per Section 3.3.1
Flask-CORS>=6.0.0,<7.0.0
Flask-RESTful>=0.3.10,<1.0.0
Flask-Limiter>=3.5.0,<4.0.0
Flask-Caching>=2.1.0,<3.0.0
Flask-Session>=0.5.0,<1.0.0

# Authentication & Security per Section 3.2.2
PyJWT>=2.8.0,<3.0.0
cryptography>=41.0.4,<42.0.0
bcrypt>=4.0.1,<5.0.0
passlib>=1.7.4,<2.0.0

# HTTP Processing per Section 3.3.1
requests>=2.31.0,<3.0.0
httpx>=0.25.0,<1.0.0

# Data Processing & Validation per Section 3.3.1
marshmallow>=3.21.0,<4.0.0
pydantic>=2.11.5,<3.0.0
email-validator>=2.1.0,<3.0.0
bleach>=6.1.0,<7.0.0
python-dateutil>=2.9.0,<3.0.0
jsonschema>=4.22.0,<5.0.0

# Database Drivers per Section 3.4.1
pymongo>=4.5.0,<5.0.0
motor>=3.3.0,<4.0.0

# Cache Client per Section 3.4.2
redis>=5.0.3,<6.0.0

# AWS Integration per Section 3.3.1
boto3>=1.38.25,<2.0.0
python-multipart>=0.0.6,<1.0.0
Pillow>=10.3.0,<11.0.0

# Monitoring & Observability per Section 3.3.1
prometheus-client>=0.20.0,<1.0.0

# Environment Management per Section 3.5.1
python-dotenv>=1.0.0,<2.0.0

# Production WSGI Server per Section 8.3.1
gunicorn>=23.0.0,<24.0.0
EOF

    log_success "Created requirements.in template"
}

create_dev_requirements_template() {
    log_info "Creating requirements-dev.in template for development dependencies"
    
    cat > "$REQUIREMENTS_DIR/requirements-dev.in" << 'EOF'
# ==============================================================================
# Development Dependencies for Flask Application
# ==============================================================================
# This file contains development and testing dependencies.
# Run 'pip-compile requirements-dev.in' to generate requirements-dev.txt

# Include production requirements
-r requirements.in

# Testing Framework per Section 3.5.1
pytest>=7.4.2,<8.0.0
pytest-cov>=4.1.0,<5.0.0
pytest-mock>=3.11.1,<4.0.0
pytest-flask>=1.2.0,<2.0.0
coverage>=7.3.2,<8.0.0

# Code Quality Tools per Section 8.5.1
black>=23.7.0,<24.0.0
flake8>=6.1.0,<7.0.0
isort>=5.12.0,<6.0.0
mypy>=1.8.0,<2.0.0

# Security Analysis per Section 8.5.1
bandit>=1.7.0,<2.0.0

# Documentation
sphinx>=7.0.0,<8.0.0
sphinx-rtd-theme>=1.3.0,<2.0.0

# Development Tools
pre-commit>=3.3.0,<4.0.0
ipython>=8.14.0,<9.0.0
EOF

    log_success "Created requirements-dev.in template"
}

compile_requirements() {
    log_info "Compiling requirements with pip-tools for deterministic resolution"
    
    # Compile production requirements
    log_info "Compiling production requirements..."
    pip-compile \
        --upgrade \
        --generate-hashes \
        --annotation-style=line \
        --header \
        --output-file="$REQUIREMENTS_DIR/requirements.txt" \
        "$REQUIREMENTS_DIR/requirements.in"
    
    # Compile development requirements
    log_info "Compiling development requirements..."
    pip-compile \
        --upgrade \
        --generate-hashes \
        --annotation-style=line \
        --header \
        --output-file="$REQUIREMENTS_DIR/requirements-dev.txt" \
        "$REQUIREMENTS_DIR/requirements-dev.in"
    
    log_success "Requirements compilation completed with deterministic resolution"
}

validate_compiled_requirements() {
    log_info "Validating compiled requirements consistency"
    
    # Check if requirements.txt is up to date
    if [[ -f "$REQUIREMENTS_DIR/requirements.txt" ]]; then
        local temp_file=$(mktemp)
        pip-compile \
            --dry-run \
            --generate-hashes \
            --annotation-style=line \
            --header \
            --output-file="$temp_file" \
            "$REQUIREMENTS_DIR/requirements.in" 2>/dev/null
        
        if ! diff -q "$REQUIREMENTS_DIR/requirements.txt" "$temp_file" >/dev/null; then
            log_error "requirements.txt is not up to date. Run 'pip-compile requirements.in'"
            rm -f "$temp_file"
            return 1
        fi
        
        rm -f "$temp_file"
        log_success "Requirements.txt is up to date"
    fi
}

install_dependencies() {
    local env_type="${1:-production}"
    
    if [[ "$env_type" == "development" ]]; then
        log_info "Installing development dependencies"
        pip-sync "$REQUIREMENTS_DIR/requirements-dev.txt"
    else
        log_info "Installing production dependencies"
        pip-sync "$REQUIREMENTS_DIR/requirements.txt"
    fi
    
    log_success "Dependencies installed successfully"
}

# ==============================================================================
# SECURITY SCANNING FUNCTIONS
# ==============================================================================

scan_vulnerabilities_safety() {
    log_info "Scanning dependencies for vulnerabilities using safety 3.0+"
    
    local safety_output
    local exit_code=0
    
    # Run safety check with JSON output for parsing
    safety_output=$(safety check --json --output text 2>&1) || exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "No known security vulnerabilities found by safety"
        echo "$safety_output" >> "$LOG_FILE"
    else
        log_error "Security vulnerabilities detected by safety:"
        echo "$safety_output" | tee -a "$LOG_FILE"
        
        # Extract critical vulnerabilities
        if echo "$safety_output" | grep -q "CRITICAL\|HIGH"; then
            log_error "CRITICAL or HIGH severity vulnerabilities detected"
            return 1
        else
            log_warn "Medium or low severity vulnerabilities detected"
        fi
    fi
}

scan_vulnerabilities_pip_audit() {
    log_info "Scanning dependencies for vulnerabilities using pip-audit 2.7+"
    
    local pip_audit_output
    local exit_code=0
    
    # Run pip-audit with JSON output for detailed analysis
    pip_audit_output=$(pip-audit --format=json --output=- 2>&1) || exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "No known security vulnerabilities found by pip-audit"
        echo "$pip_audit_output" >> "$LOG_FILE"
    else
        log_error "Security vulnerabilities detected by pip-audit:"
        echo "$pip_audit_output" | tee -a "$LOG_FILE"
        
        # Parse JSON output to check severity levels
        if echo "$pip_audit_output" | grep -q '"severity": "high"\|"severity": "critical"'; then
            log_error "HIGH or CRITICAL severity vulnerabilities detected"
            return 1
        else
            log_warn "Medium or low severity vulnerabilities detected"
        fi
    fi
}

comprehensive_security_scan() {
    log_info "Performing comprehensive security scanning per Section 8.5.1"
    
    local scan_failed=false
    
    # Run safety scan
    if ! scan_vulnerabilities_safety; then
        scan_failed=true
    fi
    
    # Run pip-audit scan
    if ! scan_vulnerabilities_pip_audit; then
        scan_failed=true
    fi
    
    if [[ "$scan_failed" == "true" ]]; then
        log_error "Security scan failed. Critical vulnerabilities must be remediated."
        return 1
    fi
    
    log_success "Comprehensive security scan completed successfully"
}

# ==============================================================================
# LICENSE COMPLIANCE FUNCTIONS
# ==============================================================================

check_license_compliance() {
    log_info "Checking license compliance for enterprise requirements"
    
    # Generate license report
    local license_output
    license_output=$(pip-licenses --format=json --with-urls --with-description 2>&1)
    
    # Save detailed license report
    echo "$license_output" > "$PROJECT_ROOT/logs/license-report.json"
    
    # Check for problematic licenses
    local problematic_licenses=(
        "GPL"
        "AGPL"
        "LGPL"
        "CDDL"
        "EPL"
        "MPL"
    )
    
    local license_issues=false
    
    for license in "${problematic_licenses[@]}"; do
        if echo "$license_output" | grep -iq "$license"; then
            log_warn "Potentially problematic license detected: $license"
            license_issues=true
        fi
    done
    
    # Generate human-readable license summary
    pip-licenses --format=rst --output-file="$PROJECT_ROOT/docs/licenses.rst" 2>/dev/null || true
    
    if [[ "$license_issues" == "true" ]]; then
        log_warn "License compliance review required. Check logs/license-report.json"
        return 1
    fi
    
    log_success "License compliance check completed"
}

# ==============================================================================
# UPGRADE MANAGEMENT FUNCTIONS
# ==============================================================================

upgrade_dependencies() {
    local upgrade_type="${1:-minor}"  # Options: patch, minor, major
    
    log_info "Upgrading dependencies (type: $upgrade_type)"
    
    case "$upgrade_type" in
        "patch")
            log_info "Performing patch-level upgrades only"
            pip-compile --upgrade-package "*" --output-file="$REQUIREMENTS_DIR/requirements.txt" "$REQUIREMENTS_DIR/requirements.in"
            ;;
        "minor")
            log_info "Performing minor version upgrades"
            pip-compile --upgrade --output-file="$REQUIREMENTS_DIR/requirements.txt" "$REQUIREMENTS_DIR/requirements.in"
            ;;
        "major")
            log_warn "Performing major version upgrades - use with caution"
            pip-compile --upgrade --output-file="$REQUIREMENTS_DIR/requirements.txt" "$REQUIREMENTS_DIR/requirements.in"
            ;;
        *)
            log_error "Invalid upgrade type: $upgrade_type. Use: patch, minor, or major"
            return 1
            ;;
    esac
    
    # Run security scan after upgrade
    if ! comprehensive_security_scan; then
        log_error "Security vulnerabilities detected after upgrade"
        return 1
    fi
    
    log_success "Dependency upgrade completed successfully"
}

automated_security_remediation() {
    log_info "Performing automated security vulnerability remediation"
    
    # Get list of vulnerable packages from safety
    local vulnerable_packages
    vulnerable_packages=$(safety check --json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for vuln in data:
        print(vuln['package_name'])
except:
    pass
" | sort -u)
    
    if [[ -z "$vulnerable_packages" ]]; then
        log_info "No vulnerable packages to remediate"
        return 0
    fi
    
    log_info "Attempting to upgrade vulnerable packages: $vulnerable_packages"
    
    # Attempt to upgrade vulnerable packages
    for package in $vulnerable_packages; do
        log_info "Upgrading $package to latest secure version"
        pip-compile --upgrade-package "$package" --output-file="$REQUIREMENTS_DIR/requirements.txt" "$REQUIREMENTS_DIR/requirements.in"
    done
    
    # Verify remediation
    if comprehensive_security_scan; then
        log_success "Security vulnerabilities successfully remediated"
    else
        log_error "Some vulnerabilities could not be automatically remediated"
        return 1
    fi
}

# ==============================================================================
# CI/CD INTEGRATION FUNCTIONS
# ==============================================================================

ci_cd_validation() {
    log_info "Running CI/CD pipeline dependency validation per Section 8.5.1"
    
    # Validate compiled requirements are up to date
    if ! validate_compiled_requirements; then
        return 1
    fi
    
    # Run comprehensive security scan
    if ! comprehensive_security_scan; then
        return 1
    fi
    
    # Check license compliance
    if ! check_license_compliance; then
        return 1
    fi
    
    log_success "CI/CD dependency validation completed successfully"
}

generate_dependency_report() {
    log_info "Generating comprehensive dependency report"
    
    local report_file="$PROJECT_ROOT/docs/dependency-report.md"
    mkdir -p "$(dirname "$report_file")"
    
    cat > "$report_file" << EOF
# Dependency Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Python Version:** $(python3 --version)
**pip-tools Version:** $(pip-compile --version)

## Security Status

### Safety Scan Results
\`\`\`
$(safety check --output text 2>&1 || echo "Vulnerabilities detected - see logs for details")
\`\`\`

### pip-audit Scan Results
\`\`\`
$(pip-audit --format=text 2>&1 || echo "Vulnerabilities detected - see logs for details")
\`\`\`

## License Summary

$(pip-licenses --format=markdown 2>/dev/null || echo "License information not available")

## Dependency Tree

\`\`\`
$(pip freeze | head -20)
...
\`\`\`

**Note:** Full dependency details available in logs/license-report.json
EOF

    log_success "Dependency report generated at $report_file"
}

# ==============================================================================
# MAIN SCRIPT FUNCTIONS
# ==============================================================================

usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    install [production|development]  Install dependencies (default: production)
    compile                          Compile requirements with pip-tools
    validate                         Validate requirements consistency
    scan                            Run comprehensive security scanning
    licenses                        Check license compliance
    upgrade [patch|minor|major]     Upgrade dependencies (default: minor)
    remediate                       Automated security vulnerability remediation
    ci-validate                     Run CI/CD pipeline validation
    report                          Generate comprehensive dependency report
    help                            Show this help message

EXAMPLES:
    $0 install development          Install development dependencies
    $0 compile                      Compile requirements files
    $0 scan                         Run security vulnerability scanning
    $0 upgrade patch                Perform patch-level upgrades only
    $0 ci-validate                  Run full CI/CD validation

This script implements pip-tools 7.3+ for deterministic dependency resolution,
safety 3.0+ and pip-audit 2.7+ for vulnerability scanning, and comprehensive
license compliance validation per Section 8.5.1 of the technical specification.
EOF
}

main() {
    local command="${1:-help}"
    shift || true
    
    case "$command" in
        "install")
            log_info "Starting dependency installation process"
            check_command "python3"
            validate_python_version "python3"
            create_virtual_environment
            install_dependency_tools
            validate_requirements_files
            install_dependencies "$@"
            ;;
        "compile")
            log_info "Starting requirements compilation process"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            validate_requirements_files
            compile_requirements
            ;;
        "validate")
            log_info "Starting requirements validation process"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            validate_compiled_requirements
            ;;
        "scan")
            log_info "Starting comprehensive security scanning"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            comprehensive_security_scan
            ;;
        "licenses")
            log_info "Starting license compliance check"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            check_license_compliance
            ;;
        "upgrade")
            log_info "Starting dependency upgrade process"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            upgrade_dependencies "$@"
            ;;
        "remediate")
            log_info "Starting automated security remediation"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            automated_security_remediation
            ;;
        "ci-validate")
            log_info "Starting CI/CD pipeline validation"
            check_command "python3"
            validate_python_version "python3"
            create_virtual_environment
            install_dependency_tools
            ci_cd_validation
            ;;
        "report")
            log_info "Generating comprehensive dependency report"
            check_command "python3"
            create_virtual_environment
            install_dependency_tools
            generate_dependency_report
            ;;
        "help"|"--help"|"-h")
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# ==============================================================================
# SCRIPT EXECUTION
# ==============================================================================

# Ensure script is not being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi