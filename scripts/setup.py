#!/usr/bin/env python3
"""
Flask Application Environment Setup Script

This script provides comprehensive environment setup for the Flask application
migration project, replacing Node.js npm install workflow with Python virtual
environment and pip-tools dependency management. Implements deterministic
dependency resolution, environment configuration, and development server setup
with enterprise-grade quality validation.

Author: Migration Team
Version: 1.0.0
License: Proprietary

Requirements:
- Python 3.8+ runtime environment
- pip package manager
- Virtual environment support (venv/virtualenv)
- Internet connectivity for package downloads
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Configure structured logging for enterprise integration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('setup.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class SetupConfig:
    """Configuration parameters for environment setup process."""
    
    # Environment Configuration
    project_root: Path
    venv_name: str = ".venv"
    python_version: str = "3.11"
    min_python_version: Tuple[int, int] = (3, 8)
    
    # Dependency Management
    use_pip_tools: bool = True
    pip_tools_version: str = "7.3.0"
    requirements_file: str = "requirements.txt"
    requirements_in_file: str = "requirements.in"
    
    # Quality Gates
    enable_quality_checks: bool = True
    flake8_version: str = "6.1.0"
    mypy_version: str = "1.8.0"
    bandit_version: str = "1.7.5"
    safety_version: str = "3.0.0"
    
    # Development Server
    flask_host: str = "127.0.0.1"
    flask_port: int = 5000
    flask_debug: bool = True
    flask_reload: bool = True
    
    # Performance Requirements
    max_setup_time_minutes: int = 10
    dependency_cache_ttl_hours: int = 24
    
    # Security Configuration
    enable_security_scan: bool = True
    vulnerability_policy: str = "strict"  # strict, moderate, permissive
    
    # Container Integration
    docker_support: bool = True
    gunicorn_version: str = "23.0.0"
    
    def __post_init__(self):
        """Initialize configuration with validation."""
        self.project_root = Path(self.project_root).resolve()
        self.venv_path = self.project_root / self.venv_name
        self.requirements_path = self.project_root / self.requirements_file
        self.requirements_in_path = self.project_root / self.requirements_in_file


class EnvironmentSetup:
    """
    Comprehensive environment setup manager for Flask application migration.
    
    Handles virtual environment creation, dependency management with pip-tools,
    quality gate integration, and development server configuration with
    enterprise-grade validation and monitoring.
    """
    
    def __init__(self, config: SetupConfig):
        """
        Initialize environment setup manager with configuration.
        
        Args:
            config: Setup configuration parameters
        """
        self.config = config
        self.start_time = time.time()
        self.setup_summary = {
            "total_duration": 0,
            "steps_completed": [],
            "errors": [],
            "warnings": [],
            "quality_checks": {},
            "dependency_summary": {},
            "performance_metrics": {}
        }
        
        # Platform-specific configuration
        self.is_windows = platform.system() == "Windows"
        self.python_executable = self._find_python_executable()
        
        logger.info(f"Initializing Flask environment setup on {platform.system()}")
        logger.info(f"Project root: {self.config.project_root}")
        logger.info(f"Python executable: {self.python_executable}")

    def _find_python_executable(self) -> str:
        """
        Find appropriate Python executable for virtual environment creation.
        
        Returns:
            Path to Python executable
            
        Raises:
            RuntimeError: If no suitable Python executable found
        """
        python_commands = [
            f"python{self.config.python_version}",
            "python3",
            "python"
        ]
        
        for cmd in python_commands:
            try:
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    version_info = result.stdout.strip()
                    logger.info(f"Found Python: {cmd} ({version_info})")
                    return cmd
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        raise RuntimeError(
            f"No suitable Python executable found. "
            f"Required: Python {self.config.min_python_version[0]}.{self.config.min_python_version[1]}+"
        )

    def validate_python_version(self) -> bool:
        """
        Validate Python version meets minimum requirements.
        
        Returns:
            True if Python version is compatible
            
        Raises:
            RuntimeError: If Python version is incompatible
        """
        logger.info("Validating Python version compatibility...")
        
        try:
            result = subprocess.run(
                [self.python_executable, "-c", 
                 "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to get Python version: {result.stderr}")
            
            version_str = result.stdout.strip()
            major, minor = map(int, version_str.split('.'))
            current_version = (major, minor)
            
            if current_version < self.config.min_python_version:
                raise RuntimeError(
                    f"Python {major}.{minor} is not supported. "
                    f"Minimum required: {self.config.min_python_version[0]}.{self.config.min_python_version[1]}"
                )
            
            logger.info(f"Python version {major}.{minor} meets requirements ✓")
            self.setup_summary["steps_completed"].append("python_version_validation")
            return True
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Python version check timed out")
        except Exception as e:
            raise RuntimeError(f"Python version validation failed: {e}")

    def create_virtual_environment(self) -> bool:
        """
        Create Python virtual environment with optimized configuration.
        
        Returns:
            True if virtual environment creation succeeded
            
        Raises:
            RuntimeError: If virtual environment creation fails
        """
        logger.info("Creating Python virtual environment...")
        
        try:
            # Remove existing virtual environment if present
            if self.config.venv_path.exists():
                logger.warning(f"Removing existing virtual environment: {self.config.venv_path}")
                shutil.rmtree(self.config.venv_path)
            
            # Create new virtual environment
            venv_start_time = time.time()
            venv.create(
                self.config.venv_path,
                with_pip=True,
                upgrade_deps=True,
                clear=True
            )
            venv_duration = time.time() - venv_start_time
            
            # Validate virtual environment creation
            venv_python = self._get_venv_python_path()
            if not venv_python.exists():
                raise RuntimeError(f"Virtual environment Python not found: {venv_python}")
            
            # Test virtual environment activation
            result = subprocess.run(
                [str(venv_python), "-c", "import sys; print(sys.prefix)"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Virtual environment validation failed: {result.stderr}")
            
            venv_prefix = result.stdout.strip()
            expected_prefix = str(self.config.venv_path)
            
            if not venv_prefix.startswith(expected_prefix):
                raise RuntimeError(
                    f"Virtual environment prefix mismatch. "
                    f"Expected: {expected_prefix}, Got: {venv_prefix}"
                )
            
            logger.info(f"Virtual environment created successfully in {venv_duration:.2f}s ✓")
            logger.info(f"Virtual environment path: {self.config.venv_path}")
            
            self.setup_summary["steps_completed"].append("virtual_environment_creation")
            self.setup_summary["performance_metrics"]["venv_creation_time"] = venv_duration
            
            return True
            
        except Exception as e:
            error_msg = f"Virtual environment creation failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            raise RuntimeError(error_msg)

    def _get_venv_python_path(self) -> Path:
        """Get path to Python executable in virtual environment."""
        if self.is_windows:
            return self.config.venv_path / "Scripts" / "python.exe"
        else:
            return self.config.venv_path / "bin" / "python"

    def _get_venv_pip_path(self) -> Path:
        """Get path to pip executable in virtual environment."""
        if self.is_windows:
            return self.config.venv_path / "Scripts" / "pip.exe"
        else:
            return self.config.venv_path / "bin" / "pip"

    def upgrade_pip_and_tools(self) -> bool:
        """
        Upgrade pip and install essential build tools in virtual environment.
        
        Returns:
            True if upgrade succeeded
            
        Raises:
            RuntimeError: If pip upgrade fails
        """
        logger.info("Upgrading pip and installing build tools...")
        
        try:
            venv_python = self._get_venv_python_path()
            upgrade_start_time = time.time()
            
            # Upgrade pip to latest version
            pip_upgrade_result = subprocess.run(
                [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if pip_upgrade_result.returncode != 0:
                raise RuntimeError(f"pip upgrade failed: {pip_upgrade_result.stderr}")
            
            # Install essential build tools
            build_tools = [
                "setuptools>=69.0.0",
                "wheel>=0.42.0",
                f"pip-tools=={self.config.pip_tools_version}"
            ]
            
            for tool in build_tools:
                logger.info(f"Installing {tool}...")
                tool_result = subprocess.run(
                    [str(venv_python), "-m", "pip", "install", tool],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                if tool_result.returncode != 0:
                    raise RuntimeError(f"Failed to install {tool}: {tool_result.stderr}")
            
            # Verify pip-tools installation
            pip_tools_result = subprocess.run(
                [str(venv_python), "-m", "pip", "show", "pip-tools"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if pip_tools_result.returncode != 0:
                raise RuntimeError("pip-tools installation verification failed")
            
            upgrade_duration = time.time() - upgrade_start_time
            
            logger.info(f"pip and build tools upgraded successfully in {upgrade_duration:.2f}s ✓")
            self.setup_summary["steps_completed"].append("pip_tools_installation")
            self.setup_summary["performance_metrics"]["pip_upgrade_time"] = upgrade_duration
            
            return True
            
        except subprocess.TimeoutExpired:
            error_msg = "pip upgrade timed out"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"pip upgrade failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            raise RuntimeError(error_msg)

    def generate_requirements_in(self) -> bool:
        """
        Generate requirements.in file from requirements.txt for pip-tools workflow.
        
        Returns:
            True if requirements.in generation succeeded
        """
        logger.info("Generating requirements.in file for pip-tools workflow...")
        
        try:
            if not self.config.requirements_path.exists():
                logger.warning(f"requirements.txt not found: {self.config.requirements_path}")
                return False
            
            # Read requirements.txt and extract top-level dependencies
            with open(self.config.requirements_path, 'r', encoding='utf-8') as f:
                requirements_content = f.read()
            
            # Parse requirements and create simplified .in file
            requirements_in_content = self._parse_requirements_for_in_file(requirements_content)
            
            # Write requirements.in file
            with open(self.config.requirements_in_path, 'w', encoding='utf-8') as f:
                f.write(requirements_in_content)
            
            logger.info(f"Generated requirements.in with {len(requirements_in_content.splitlines())} dependencies ✓")
            self.setup_summary["steps_completed"].append("requirements_in_generation")
            
            return True
            
        except Exception as e:
            error_msg = f"requirements.in generation failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            return False

    def _parse_requirements_for_in_file(self, requirements_content: str) -> str:
        """
        Parse requirements.txt content and generate simplified requirements.in.
        
        Args:
            requirements_content: Content of requirements.txt file
            
        Returns:
            Simplified requirements.in content
        """
        lines = []
        current_section = None
        
        for line in requirements_content.splitlines():
            line = line.strip()
            
            # Skip empty lines and comments (except section headers)
            if not line or (line.startswith('#') and '=============' not in line):
                continue
            
            # Detect section headers
            if '=============' in line:
                current_section = line
                lines.append(f"\n{line}")
                continue
            
            # Extract package name and version constraint
            if line.startswith('#'):
                # Section description
                lines.append(line)
            elif '==' in line:
                # Extract package name without exact version pinning
                package = line.split('==')[0].strip()
                if package:
                    lines.append(package)
        
        return '\n'.join(lines) + '\n'

    def install_dependencies_with_pip_tools(self) -> bool:
        """
        Install dependencies using pip-tools for deterministic resolution.
        
        Returns:
            True if dependency installation succeeded
            
        Raises:
            RuntimeError: If dependency installation fails
        """
        logger.info("Installing dependencies with pip-tools deterministic resolution...")
        
        try:
            venv_python = self._get_venv_python_path()
            install_start_time = time.time()
            
            # Compile requirements if requirements.in exists
            if self.config.requirements_in_path.exists():
                logger.info("Compiling requirements.in with pip-compile...")
                
                compile_result = subprocess.run(
                    [
                        str(venv_python), "-m", "piptools", "compile",
                        "--upgrade",
                        "--generate-hashes",
                        "--output-file", str(self.config.requirements_path),
                        str(self.config.requirements_in_path)
                    ],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                
                if compile_result.returncode != 0:
                    logger.warning(f"pip-compile failed: {compile_result.stderr}")
                    logger.info("Proceeding with existing requirements.txt...")
            
            # Install requirements with pip-sync for deterministic installation
            if self.config.requirements_path.exists():
                logger.info("Installing dependencies with pip-sync...")
                
                sync_result = subprocess.run(
                    [str(venv_python), "-m", "piptools", "sync", str(self.config.requirements_path)],
                    capture_output=True,
                    text=True,
                    timeout=900
                )
                
                if sync_result.returncode != 0:
                    # Fallback to pip install if pip-sync fails
                    logger.warning(f"pip-sync failed: {sync_result.stderr}")
                    logger.info("Falling back to pip install...")
                    
                    install_result = subprocess.run(
                        [str(venv_python), "-m", "pip", "install", "-r", str(self.config.requirements_path)],
                        capture_output=True,
                        text=True,
                        timeout=900
                    )
                    
                    if install_result.returncode != 0:
                        raise RuntimeError(f"pip install failed: {install_result.stderr}")
            else:
                logger.warning("No requirements.txt found, skipping dependency installation")
                return False
            
            # Verify Flask installation
            flask_result = subprocess.run(
                [str(venv_python), "-c", "import flask; print(f'Flask {flask.__version__} installed')"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if flask_result.returncode != 0:
                raise RuntimeError(f"Flask installation verification failed: {flask_result.stderr}")
            
            install_duration = time.time() - install_start_time
            
            # Get installed package count
            list_result = subprocess.run(
                [str(venv_python), "-m", "pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if list_result.returncode == 0:
                packages = json.loads(list_result.stdout)
                package_count = len(packages)
                self.setup_summary["dependency_summary"]["total_packages"] = package_count
                logger.info(f"Installed {package_count} packages")
            
            logger.info(f"Dependencies installed successfully in {install_duration:.2f}s ✓")
            logger.info(f"Flask verification: {flask_result.stdout.strip()}")
            
            self.setup_summary["steps_completed"].append("dependency_installation")
            self.setup_summary["performance_metrics"]["dependency_install_time"] = install_duration
            
            return True
            
        except subprocess.TimeoutExpired:
            error_msg = "Dependency installation timed out"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"Dependency installation failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            raise RuntimeError(error_msg)

    def setup_environment_configuration(self) -> bool:
        """
        Configure environment variables and development settings.
        
        Returns:
            True if environment configuration succeeded
        """
        logger.info("Configuring environment variables and development settings...")
        
        try:
            # Check for existing .env file
            env_file = self.config.project_root / ".env"
            env_example_file = self.config.project_root / ".env.example"
            
            if not env_file.exists() and env_example_file.exists():
                # Copy .env.example to .env for development
                shutil.copy2(env_example_file, env_file)
                logger.info(f"Created .env file from .env.example template ✓")
                
                # Set development-specific values
                self._update_env_for_development(env_file)
            elif not env_file.exists():
                # Create minimal .env file
                self._create_minimal_env_file(env_file)
                logger.info("Created minimal .env file for development ✓")
            else:
                logger.info(".env file already exists, skipping creation")
            
            # Validate environment configuration
            if self._validate_env_configuration(env_file):
                logger.info("Environment configuration validated ✓")
                self.setup_summary["steps_completed"].append("environment_configuration")
                return True
            else:
                logger.warning("Environment configuration validation failed")
                self.setup_summary["warnings"].append("Environment configuration validation failed")
                return False
                
        except Exception as e:
            error_msg = f"Environment configuration failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            return False

    def _update_env_for_development(self, env_file: Path) -> None:
        """Update .env file with development-specific settings."""
        development_overrides = {
            "FLASK_ENV": "development",
            "FLASK_DEBUG": "True",
            "DEV_FLASK_DEBUG": "True",
            "DEV_FLASK_ENV": "development",
            "DEV_RELOAD": "True",
            "SECRET_KEY": "dev-secret-key-not-for-production",
            "JWT_SECRET_KEY": "dev-jwt-secret-key-not-for-production",
            "LOG_LEVEL": "DEBUG",
            "MONGODB_URL": "mongodb://localhost:27017/dev_database",
            "REDIS_URL": "redis://localhost:6379/1"
        }
        
        # Read existing content
        with open(env_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update development settings
        lines = content.splitlines()
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            if '=' in line and not line.strip().startswith('#'):
                key = line.split('=')[0].strip()
                if key in development_overrides:
                    updated_lines.append(f"{key}={development_overrides[key]}")
                    updated_keys.add(key)
                else:
                    updated_lines.append(line)
            else:
                updated_lines.append(line)
        
        # Add any missing development settings
        if updated_keys != set(development_overrides.keys()):
            updated_lines.append("\n# Development overrides")
            for key, value in development_overrides.items():
                if key not in updated_keys:
                    updated_lines.append(f"{key}={value}")
        
        # Write updated content
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(updated_lines) + '\n')

    def _create_minimal_env_file(self, env_file: Path) -> None:
        """Create minimal .env file for development."""
        minimal_env_content = """# Flask Application Development Environment
# Auto-generated by setup.py

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=dev-secret-key-not-for-production

# Database Configuration
MONGODB_URL=mongodb://localhost:27017/dev_database
REDIS_URL=redis://localhost:6379/1

# Authentication
JWT_SECRET_KEY=dev-jwt-secret-key-not-for-production

# Logging
LOG_LEVEL=DEBUG

# Development Settings
DEV_FLASK_DEBUG=True
DEV_FLASK_ENV=development
DEV_RELOAD=True
"""
        
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(minimal_env_content)

    def _validate_env_configuration(self, env_file: Path) -> bool:
        """
        Validate environment configuration file.
        
        Args:
            env_file: Path to .env file
            
        Returns:
            True if configuration is valid
        """
        try:
            venv_python = self._get_venv_python_path()
            
            # Test loading environment variables with python-dotenv
            validation_script = f"""
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path("{self.config.project_root}")
sys.path.insert(0, str(project_root))

try:
    from dotenv import load_dotenv
    load_dotenv("{env_file}")
    
    # Validate critical variables
    required_vars = ["FLASK_ENV", "SECRET_KEY"]
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"Missing required variables: {{', '.join(missing_vars)}}")
        sys.exit(1)
    
    print("Environment configuration valid")
    sys.exit(0)
    
except ImportError:
    print("python-dotenv not available")
    sys.exit(1)
except Exception as e:
    print(f"Environment validation error: {{e}}")
    sys.exit(1)
"""
            
            result = subprocess.run(
                [str(venv_python), "-c", validation_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.debug(f"Environment validation: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Environment validation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Environment validation error: {e}")
            return False

    def install_quality_tools(self) -> bool:
        """
        Install code quality and security tools for enterprise compliance.
        
        Returns:
            True if quality tools installation succeeded
        """
        if not self.config.enable_quality_checks:
            logger.info("Quality checks disabled, skipping tool installation")
            return True
        
        logger.info("Installing code quality and security tools...")
        
        try:
            venv_python = self._get_venv_python_path()
            quality_start_time = time.time()
            
            # Quality tools with specific versions for enterprise compliance
            quality_tools = [
                f"flake8=={self.config.flake8_version}",
                f"mypy=={self.config.mypy_version}",
                f"bandit=={self.config.bandit_version}",
                f"safety=={self.config.safety_version}",
                "black>=23.11.0",
                "isort>=5.12.0",
                "pytest>=7.4.0",
                "pytest-cov>=4.1.0",
                "pytest-flask>=1.3.0",
                "pip-audit>=2.7.0"
            ]
            
            for tool in quality_tools:
                logger.info(f"Installing {tool}...")
                tool_result = subprocess.run(
                    [str(venv_python), "-m", "pip", "install", tool],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                if tool_result.returncode != 0:
                    logger.warning(f"Failed to install {tool}: {tool_result.stderr}")
                    self.setup_summary["warnings"].append(f"Quality tool installation failed: {tool}")
            
            # Verify quality tools installation
            verification_tools = ["flake8", "mypy", "bandit", "safety", "black", "isort"]
            installed_tools = []
            
            for tool in verification_tools:
                verify_result = subprocess.run(
                    [str(venv_python), "-m", "pip", "show", tool],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if verify_result.returncode == 0:
                    installed_tools.append(tool)
            
            quality_duration = time.time() - quality_start_time
            
            logger.info(f"Quality tools installed in {quality_duration:.2f}s ✓")
            logger.info(f"Installed tools: {', '.join(installed_tools)}")
            
            self.setup_summary["steps_completed"].append("quality_tools_installation")
            self.setup_summary["performance_metrics"]["quality_tools_install_time"] = quality_duration
            self.setup_summary["quality_checks"]["installed_tools"] = installed_tools
            
            return True
            
        except Exception as e:
            error_msg = f"Quality tools installation failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            return False

    def run_security_scan(self) -> bool:
        """
        Execute security vulnerability scan on dependencies.
        
        Returns:
            True if security scan passed or completed successfully
        """
        if not self.config.enable_security_scan:
            logger.info("Security scanning disabled, skipping scan")
            return True
        
        logger.info("Running security vulnerability scan...")
        
        try:
            venv_python = self._get_venv_python_path()
            scan_start_time = time.time()
            
            # Run safety check for dependency vulnerabilities
            safety_result = subprocess.run(
                [str(venv_python), "-m", "safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            vulnerabilities = []
            if safety_result.stdout:
                try:
                    safety_data = json.loads(safety_result.stdout)
                    vulnerabilities = safety_data
                except json.JSONDecodeError:
                    logger.warning("Failed to parse safety check JSON output")
            
            # Run pip-audit for additional vulnerability scanning
            audit_result = subprocess.run(
                [str(venv_python), "-m", "pip_audit", "--format=json"],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            audit_vulnerabilities = []
            if audit_result.stdout and audit_result.returncode == 0:
                try:
                    audit_data = json.loads(audit_result.stdout)
                    audit_vulnerabilities = audit_data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse pip-audit JSON output")
            
            scan_duration = time.time() - scan_start_time
            total_vulnerabilities = len(vulnerabilities) + len(audit_vulnerabilities)
            
            # Evaluate security scan results based on policy
            scan_passed = self._evaluate_security_scan_results(
                vulnerabilities, audit_vulnerabilities
            )
            
            if scan_passed:
                logger.info(f"Security scan completed successfully in {scan_duration:.2f}s ✓")
                if total_vulnerabilities > 0:
                    logger.warning(f"Found {total_vulnerabilities} vulnerabilities (acceptable for {self.config.vulnerability_policy} policy)")
            else:
                logger.error(f"Security scan failed with {total_vulnerabilities} critical vulnerabilities")
            
            self.setup_summary["steps_completed"].append("security_scan")
            self.setup_summary["performance_metrics"]["security_scan_time"] = scan_duration
            self.setup_summary["quality_checks"]["security_scan"] = {
                "vulnerabilities_found": total_vulnerabilities,
                "scan_passed": scan_passed,
                "policy": self.config.vulnerability_policy
            }
            
            return scan_passed
            
        except subprocess.TimeoutExpired:
            logger.warning("Security scan timed out")
            self.setup_summary["warnings"].append("Security scan timed out")
            return self.config.vulnerability_policy != "strict"
        except Exception as e:
            error_msg = f"Security scan failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            return self.config.vulnerability_policy == "permissive"

    def _evaluate_security_scan_results(self, safety_vulns: List, audit_vulns: List) -> bool:
        """
        Evaluate security scan results based on vulnerability policy.
        
        Args:
            safety_vulns: Vulnerabilities found by safety
            audit_vulns: Vulnerabilities found by pip-audit
            
        Returns:
            True if scan results meet policy requirements
        """
        total_vulns = len(safety_vulns) + len(audit_vulns)
        
        if self.config.vulnerability_policy == "strict":
            return total_vulns == 0
        elif self.config.vulnerability_policy == "moderate":
            # Allow low/medium severity, block high/critical
            critical_count = sum(
                1 for vuln in safety_vulns + audit_vulns
                if vuln.get("severity", "").lower() in ["high", "critical"]
            )
            return critical_count == 0
        elif self.config.vulnerability_policy == "permissive":
            # Allow all vulnerabilities but log them
            return True
        else:
            return total_vulns == 0

    def setup_development_server(self) -> bool:
        """
        Configure Flask development server with auto-reload capabilities.
        
        Returns:
            True if development server setup succeeded
        """
        logger.info("Configuring Flask development server...")
        
        try:
            # Create development server startup script
            dev_server_script = self.config.project_root / "run_dev_server.py"
            
            script_content = f'''#!/usr/bin/env python3
"""
Flask Development Server Startup Script

Auto-generated development server configuration for Flask application
migration project. Provides auto-reload, debug mode, and enterprise
monitoring integration for development workflow.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    print("Warning: python-dotenv not available")

# Configure Flask development settings
os.environ.setdefault("FLASK_ENV", "development")
os.environ.setdefault("FLASK_DEBUG", "True")
os.environ.setdefault("FLASK_HOST", "{self.config.flask_host}")
os.environ.setdefault("FLASK_PORT", str({self.config.flask_port}))

def run_development_server():
    """Start Flask development server with auto-reload and debugging."""
    try:
        # Import Flask application
        from app import app
        
        # Get configuration from environment
        host = os.getenv("FLASK_HOST", "{self.config.flask_host}")
        port = int(os.getenv("FLASK_PORT", {self.config.flask_port}))
        debug = os.getenv("FLASK_DEBUG", "True").lower() == "true"
        
        print(f"Starting Flask development server...")
        print(f"Host: {{host}}")
        print(f"Port: {{port}}")
        print(f"Debug: {{debug}}")
        print(f"Auto-reload: {self.config.flask_reload}")
        print("\\nPress CTRL+C to stop the server")
        
        # Start development server
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader={str(self.config.flask_reload).lower()},
            threaded=True
        )
        
    except ImportError as e:
        print(f"Error: Failed to import Flask application: {{e}}")
        print("Make sure app.py exists and Flask is properly installed")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to start development server: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    run_development_server()
'''
            
            with open(dev_server_script, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            # Make script executable on Unix systems
            if not self.is_windows:
                os.chmod(dev_server_script, 0o755)
            
            # Create development server validation script
            self._create_server_validation_script()
            
            logger.info("Development server configuration created ✓")
            logger.info(f"Start server with: python {dev_server_script}")
            logger.info(f"Server will run on http://{self.config.flask_host}:{self.config.flask_port}")
            
            self.setup_summary["steps_completed"].append("development_server_setup")
            
            return True
            
        except Exception as e:
            error_msg = f"Development server setup failed: {e}"
            logger.error(error_msg)
            self.setup_summary["errors"].append(error_msg)
            return False

    def _create_server_validation_script(self) -> None:
        """Create script to validate Flask application startup."""
        validation_script = self.config.project_root / "validate_app.py"
        
        script_content = '''#!/usr/bin/env python3
"""
Flask Application Validation Script

Validates Flask application startup and basic functionality
for development environment verification.
"""

import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def validate_application():
    """Validate Flask application can be imported and started."""
    try:
        # Load environment variables
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
        
        # Import Flask application
        from app import app
        
        # Test application context
        with app.app_context():
            print("✓ Flask application imported successfully")
            print(f"✓ Application name: {app.name}")
            print(f"✓ Debug mode: {app.debug}")
            print(f"✓ Environment: {app.env}")
            
            # Test configuration
            if app.config.get('SECRET_KEY'):
                print("✓ Secret key configured")
            else:
                print("⚠ Warning: Secret key not configured")
            
            print("\\n✅ Flask application validation passed")
            return True
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return False

if __name__ == "__main__":
    success = validate_application()
    sys.exit(0 if success else 1)
'''
        
        with open(validation_script, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        if not self.is_windows:
            os.chmod(validation_script, 0o755)

    def create_setup_summary(self) -> Dict:
        """
        Create comprehensive setup summary with performance metrics.
        
        Returns:
            Dictionary containing setup summary and metrics
        """
        self.setup_summary["total_duration"] = time.time() - self.start_time
        
        # Calculate success rate
        total_steps = len(self.setup_summary["steps_completed"]) + len(self.setup_summary["errors"])
        success_rate = len(self.setup_summary["steps_completed"]) / max(total_steps, 1) * 100
        
        self.setup_summary["success_rate"] = success_rate
        self.setup_summary["setup_status"] = "SUCCESS" if success_rate >= 80 else "PARTIAL" if success_rate >= 50 else "FAILED"
        
        # Add system information
        self.setup_summary["system_info"] = {
            "platform": platform.system(),
            "python_version": sys.version.split()[0],
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count()
        }
        
        return self.setup_summary

    def generate_setup_report(self) -> str:
        """
        Generate comprehensive setup report for documentation.
        
        Returns:
            Formatted setup report string
        """
        summary = self.create_setup_summary()
        
        report = f"""
=============================================================================
Flask Application Environment Setup Report
=============================================================================

Setup Status: {summary['setup_status']}
Success Rate: {summary['success_rate']:.1f}%
Total Duration: {summary['total_duration']:.2f} seconds
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

=============================================================================
SYSTEM INFORMATION
=============================================================================

Platform: {summary['system_info']['platform']}
Python Version: {summary['system_info']['python_version']}
Architecture: {summary['system_info']['architecture']}
CPU Count: {summary['system_info']['cpu_count']}

Project Root: {self.config.project_root}
Virtual Environment: {self.config.venv_path}

=============================================================================
COMPLETED STEPS
=============================================================================

"""
        
        for step in summary["steps_completed"]:
            report += f"✓ {step.replace('_', ' ').title()}\n"
        
        if summary["errors"]:
            report += f"""
=============================================================================
ERRORS ENCOUNTERED
=============================================================================

"""
            for error in summary["errors"]:
                report += f"❌ {error}\n"
        
        if summary["warnings"]:
            report += f"""
=============================================================================
WARNINGS
=============================================================================

"""
            for warning in summary["warnings"]:
                report += f"⚠ {warning}\n"
        
        if summary["performance_metrics"]:
            report += f"""
=============================================================================
PERFORMANCE METRICS
=============================================================================

"""
            for metric, value in summary["performance_metrics"].items():
                report += f"{metric.replace('_', ' ').title()}: {value:.2f}s\n"
        
        if summary["dependency_summary"]:
            report += f"""
=============================================================================
DEPENDENCY SUMMARY
=============================================================================

"""
            for key, value in summary["dependency_summary"].items():
                report += f"{key.replace('_', ' ').title()}: {value}\n"
        
        if summary["quality_checks"]:
            report += f"""
=============================================================================
QUALITY CHECKS
=============================================================================

"""
            for check, details in summary["quality_checks"].items():
                if isinstance(details, dict):
                    report += f"{check.replace('_', ' ').title()}:\n"
                    for key, value in details.items():
                        report += f"  {key.replace('_', ' ').title()}: {value}\n"
                else:
                    report += f"{check.replace('_', ' ').title()}: {details}\n"
        
        report += f"""
=============================================================================
NEXT STEPS
=============================================================================

1. Activate virtual environment:
   {'source .venv/Scripts/activate' if self.is_windows else 'source .venv/bin/activate'}

2. Validate Flask application:
   python validate_app.py

3. Start development server:
   python run_dev_server.py

4. Run tests:
   python -m pytest

5. Check code quality:
   python -m flake8 src/
   python -m mypy src/
   python -m bandit -r src/

=============================================================================
SUPPORT INFORMATION
=============================================================================

For issues with this setup, check:
- setup.log for detailed logs
- .env file for configuration
- requirements.txt for dependencies

Documentation: See README.md for complete setup guide
Support: Contact development team for assistance

=============================================================================
"""
        
        return report


def main():
    """Main entry point for Flask environment setup script."""
    parser = argparse.ArgumentParser(
        description="Flask Application Environment Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/setup.py                    # Full setup
  python scripts/setup.py --quick            # Skip quality tools
  python scripts/setup.py --no-security      # Skip security scan
  python scripts/setup.py --venv-name .env   # Custom venv name
        """
    )
    
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project root directory (default: current directory)"
    )
    
    parser.add_argument(
        "--venv-name",
        type=str,
        default=".venv",
        help="Virtual environment directory name (default: .venv)"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick setup without quality tools and security scan"
    )
    
    parser.add_argument(
        "--no-quality",
        action="store_true",
        help="Skip quality tools installation"
    )
    
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip security vulnerability scan"
    )
    
    parser.add_argument(
        "--vulnerability-policy",
        choices=["strict", "moderate", "permissive"],
        default="moderate",
        help="Security vulnerability policy (default: moderate)"
    )
    
    parser.add_argument(
        "--flask-port",
        type=int,
        default=5000,
        help="Flask development server port (default: 5000)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create setup configuration
    config = SetupConfig(
        project_root=args.project_root,
        venv_name=args.venv_name,
        enable_quality_checks=not (args.quick or args.no_quality),
        enable_security_scan=not (args.quick or args.no_security),
        vulnerability_policy=args.vulnerability_policy,
        flask_port=args.flask_port
    )
    
    # Initialize setup manager
    setup = EnvironmentSetup(config)
    
    try:
        logger.info("Starting Flask application environment setup...")
        logger.info(f"Configuration: {config}")
        
        # Execute setup steps
        steps = [
            ("Python Version Validation", setup.validate_python_version),
            ("Virtual Environment Creation", setup.create_virtual_environment),
            ("Pip and Tools Upgrade", setup.upgrade_pip_and_tools),
            ("Requirements.in Generation", setup.generate_requirements_in),
            ("Dependency Installation", setup.install_dependencies_with_pip_tools),
            ("Environment Configuration", setup.setup_environment_configuration),
        ]
        
        if config.enable_quality_checks:
            steps.append(("Quality Tools Installation", setup.install_quality_tools))
        
        if config.enable_security_scan:
            steps.append(("Security Vulnerability Scan", setup.run_security_scan))
        
        steps.append(("Development Server Setup", setup.setup_development_server))
        
        # Execute all setup steps
        failed_steps = []
        for step_name, step_func in steps:
            try:
                logger.info(f"\n{'='*60}")
                logger.info(f"EXECUTING: {step_name}")
                logger.info(f"{'='*60}")
                
                if not step_func():
                    failed_steps.append(step_name)
                    logger.error(f"Step failed: {step_name}")
                else:
                    logger.info(f"Step completed: {step_name} ✓")
                    
            except Exception as e:
                failed_steps.append(step_name)
                logger.error(f"Step error: {step_name} - {e}")
        
        # Generate setup report
        report = setup.generate_setup_report()
        
        # Write setup report to file
        report_file = config.project_root / "setup_report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Display results
        print(report)
        
        if failed_steps:
            logger.error(f"\nSetup completed with {len(failed_steps)} failed steps")
            logger.error(f"Failed steps: {', '.join(failed_steps)}")
            sys.exit(1)
        else:
            logger.info("\nFlask environment setup completed successfully! ✅")
            logger.info(f"Setup report saved to: {report_file}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.info("\nSetup interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\nSetup failed with unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()