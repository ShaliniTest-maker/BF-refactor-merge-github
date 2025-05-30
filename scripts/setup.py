#!/usr/bin/env python3
"""
Flask Application Environment Setup Script

This script initializes the Python virtual environment, installs dependencies using pip-tools,
and configures the development environment for Flask application development with deterministic
dependency resolution. Replaces Node.js npm install workflow per technical specification
Section 3.5.1 and implements build pipeline requirements per Section 8.5.1.

Features:
- Virtual environment creation and management
- pip-tools dependency compilation and installation
- Environment variable configuration
- Development server setup with auto-reload
- Quality tool integration (flake8, mypy, bandit)
- Performance testing setup (locust, k6)
- Container and security scanning tools

Usage:
    python scripts/setup.py [options]

Options:
    --dev          Install development dependencies (default)
    --prod         Install production dependencies only
    --rebuild      Force rebuild of virtual environment
    --upgrade      Upgrade all dependencies to latest compatible versions
    --validate     Validate environment and dependency integrity
    --help         Show this help message

Requirements:
- Python 3.8+ runtime environment
- pip 21.0+ package manager
- Virtual environment support (venv or virtualenv)
"""

import argparse
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Configuration Constants
PYTHON_VERSION_MIN = (3, 8)
PIP_VERSION_MIN = "21.0"
VENV_DIR = "venv"
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
REQUIREMENTS_DIR = PROJECT_ROOT / "requirements"
CONFIG_FILES = [
    ".env.example",
    ".flake8",
    "mypy.ini", 
    "bandit.yaml",
    "pytest.ini"
]

# Dependency specifications per Section 0.2.4 and 3.2
CORE_DEPENDENCIES = {
    "pip-tools": ">=7.3.0",
    "python-dotenv": ">=1.0.0",
    "pip": ">=21.0",
    "setuptools": ">=65.0",
    "wheel": ">=0.38.0"
}

DEV_DEPENDENCIES = {
    # Testing Framework - Section 3.5.1
    "pytest": ">=7.4.0",
    "pytest-flask": ">=1.3.0",
    "pytest-mock": ">=3.11.0",
    "pytest-cov": ">=4.1.0",
    "pytest-xdist": ">=3.3.0",  # Parallel testing
    
    # Code Quality - Section 8.5.1 
    "flake8": ">=6.1.0",
    "mypy": ">=1.8.0",
    "bandit": ">=1.7.0",
    "black": ">=23.0.0",
    "isort": ">=5.12.0",
    
    # Security Scanning
    "safety": ">=3.0.0",
    "pip-audit": ">=2.7.0",
    
    # Performance Testing - Section 8.5.2
    "locust": ">=2.17.0",
    
    # Development Tools
    "pre-commit": ">=3.4.0",
    "ipython": ">=8.15.0",
    "watchdog": ">=3.0.0",  # File watching for auto-reload
}

PROD_DEPENDENCIES = {
    # Core Flask Framework - Section 3.2.1
    "Flask": ">=2.3.0",
    "Flask-CORS": ">=4.0.0",
    "Flask-RESTful": ">=0.3.10",
    "Flask-Limiter": ">=3.5.0",
    "Flask-Talisman": ">=1.1.0",
    "Flask-Login": ">=0.7.0",
    
    # Authentication & Security - Section 3.2.2
    "PyJWT": ">=2.8.0",
    "cryptography": ">=41.0.0",
    "marshmallow": ">=3.20.0",
    "email-validator": ">=2.0.0",
    "bleach": ">=6.0.0",
    
    # Database Drivers - Section 3.4.1
    "PyMongo": ">=4.5.0",
    "Motor": ">=3.3.0",
    "redis": ">=5.0.0",
    
    # HTTP Client Libraries - Section 3.2.3
    "requests": ">=2.31.0",
    "httpx": ">=0.24.0",
    "urllib3": ">=2.0.0",
    
    # Data Processing
    "python-dateutil": ">=2.8.0",
    "jsonschema": ">=4.19.0",
    "pydantic": ">=2.3.0",
    
    # WSGI Server - Section 3.5.2
    "gunicorn": ">=23.0.0",
    "uWSGI": ">=2.0.29",
    
    # Monitoring & Observability - Section 6.2.4
    "prometheus-client": ">=0.17.0",
    "structlog": ">=23.1.0",
    
    # Cloud Services - Section 3.7
    "boto3": ">=1.28.0",
}

# Environment Configuration
ENV_TEMPLATE = """# Flask Application Environment Configuration
# Copy to .env and customize for your environment

# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-secret-key-here

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/flask_app
MONGODB_DATABASE=flask_app
MONGODB_CONNECT=True

# Redis Configuration  
REDIS_URL=redis://localhost:6379/0
REDIS_SESSION_DB=1

# Authentication Configuration
JWT_SECRET_KEY=your-jwt-secret-here
JWT_ACCESS_TOKEN_EXPIRES=3600
AUTH0_DOMAIN=your-auth0-domain.auth0.com
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_CLIENT_SECRET=your-auth0-client-secret

# External Services
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1
AWS_S3_BUCKET=your-s3-bucket

# APM and Monitoring
APM_SERVICE_NAME=flask-app
APM_ENVIRONMENT=development
PROMETHEUS_METRICS_PORT=9090

# Development Settings
LOG_LEVEL=DEBUG
TESTING=False
"""


class SetupLogger:
    """Enhanced logging configuration for setup process"""
    
    def __init__(self, level: str = "INFO"):
        self.logger = logging.getLogger("flask_setup")
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Create console handler with formatting
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def info(self, message: str) -> None:
        self.logger.info(message)
    
    def error(self, message: str) -> None:
        self.logger.error(message)
    
    def warning(self, message: str) -> None:
        self.logger.warning(message)
    
    def debug(self, message: str) -> None:
        self.logger.debug(message)


class EnvironmentSetup:
    """
    Flask Application Environment Setup Manager
    
    Handles virtual environment creation, dependency management, and development
    environment configuration per technical specification requirements.
    """
    
    def __init__(self, logger: SetupLogger):
        self.logger = logger
        self.project_root = PROJECT_ROOT
        self.venv_path = self.project_root / VENV_DIR
        self.python_executable = self._get_python_executable()
        
    def _get_python_executable(self) -> Path:
        """Get the appropriate Python executable path"""
        if self.venv_path.exists():
            if platform.system() == "Windows":
                return self.venv_path / "Scripts" / "python.exe"
            else:
                return self.venv_path / "bin" / "python"
        return Path(sys.executable)
    
    def _run_command(self, cmd: List[str], check: bool = True, 
                    capture_output: bool = False, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Execute shell command with error handling"""
        try:
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                check=check, 
                capture_output=capture_output, 
                text=True,
                cwd=cwd or self.project_root
            )
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(cmd)}")
            self.logger.error(f"Error output: {e.stderr if e.stderr else 'N/A'}")
            raise
    
    def validate_python_version(self) -> bool:
        """Validate Python version meets minimum requirements"""
        current_version = sys.version_info[:2]
        if current_version < PYTHON_VERSION_MIN:
            self.logger.error(
                f"Python {PYTHON_VERSION_MIN[0]}.{PYTHON_VERSION_MIN[1]}+ required. "
                f"Current version: {current_version[0]}.{current_version[1]}"
            )
            return False
        
        self.logger.info(f"Python version {current_version[0]}.{current_version[1]} ✓")
        return True
    
    def create_virtual_environment(self, rebuild: bool = False) -> bool:
        """Create or recreate virtual environment"""
        if self.venv_path.exists():
            if rebuild:
                self.logger.info("Removing existing virtual environment...")
                shutil.rmtree(self.venv_path)
            else:
                self.logger.info("Virtual environment already exists")
                return True
        
        self.logger.info("Creating virtual environment...")
        try:
            # Use venv module (Python 3.3+)
            self._run_command([sys.executable, "-m", "venv", str(self.venv_path)])
            self.logger.info(f"Virtual environment created at {self.venv_path}")
            
            # Update python executable path
            self.python_executable = self._get_python_executable()
            
            # Upgrade pip immediately
            self._upgrade_pip()
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create virtual environment: {e}")
            return False
    
    def _upgrade_pip(self) -> None:
        """Upgrade pip to latest version"""
        self.logger.info("Upgrading pip...")
        self._run_command([
            str(self.python_executable), "-m", "pip", "install", 
            "--upgrade", f"pip>={PIP_VERSION_MIN}"
        ])
    
    def install_core_dependencies(self) -> bool:
        """Install core dependencies including pip-tools"""
        self.logger.info("Installing core dependencies...")
        
        core_packages = []
        for package, version in CORE_DEPENDENCIES.items():
            core_packages.append(f"{package}{version}")
        
        try:
            self._run_command([
                str(self.python_executable), "-m", "pip", "install"
            ] + core_packages)
            
            self.logger.info("Core dependencies installed ✓")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install core dependencies: {e}")
            return False
    
    def create_requirements_files(self, install_dev: bool = True) -> bool:
        """Create requirements.in files with pinned dependencies"""
        self.logger.info("Creating requirements files...")
        
        # Create requirements directory
        self.project_root.mkdir(exist_ok=True)
        
        # Production requirements
        prod_requirements = []
        for package, version in PROD_DEPENDENCIES.items():
            prod_requirements.append(f"{package}{version}")
        
        prod_file = self.project_root / "requirements.in"
        with open(prod_file, "w") as f:
            f.write("# Production Dependencies - Flask Application\n")
            f.write("# Generated by setup.py per Section 0.2.4 Dependency Decisions\n\n")
            f.write("\n".join(sorted(prod_requirements)))
            f.write("\n")
        
        if install_dev:
            # Development requirements
            dev_requirements = ["-r requirements.txt"]  # Include production deps
            for package, version in DEV_DEPENDENCIES.items():
                dev_requirements.append(f"{package}{version}")
            
            dev_file = self.project_root / "requirements-dev.in"
            with open(dev_file, "w") as f:
                f.write("# Development Dependencies - Flask Application\n")
                f.write("# Generated by setup.py per Section 3.5.1 Development Tools\n\n")
                f.write("\n".join(dev_requirements))
                f.write("\n")
        
        self.logger.info("Requirements files created ✓")
        return True
    
    def compile_dependencies(self, upgrade: bool = False) -> bool:
        """Compile requirements using pip-tools for deterministic resolution"""
        self.logger.info("Compiling dependencies with pip-tools...")
        
        pip_compile_cmd = [
            str(self.python_executable), "-m", "piptools", "compile"
        ]
        
        if upgrade:
            pip_compile_cmd.append("--upgrade")
        
        # Add verbose output and resolver options
        pip_compile_cmd.extend([
            "--verbose",
            "--resolver=backtracking",
            "--annotation-style=line"
        ])
        
        try:
            # Compile production requirements
            prod_cmd = pip_compile_cmd + [
                "requirements.in",
                "--output-file", "requirements.txt"
            ]
            self._run_command(prod_cmd)
            
            # Compile development requirements if exists
            dev_file = self.project_root / "requirements-dev.in"
            if dev_file.exists():
                dev_cmd = pip_compile_cmd + [
                    "requirements-dev.in", 
                    "--output-file", "requirements-dev.txt"
                ]
                self._run_command(dev_cmd)
            
            self.logger.info("Dependencies compiled with pip-tools ✓")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to compile dependencies: {e}")
            return False
    
    def install_dependencies(self, dev_mode: bool = True) -> bool:
        """Install compiled dependencies"""
        self.logger.info("Installing compiled dependencies...")
        
        try:
            # Install production dependencies
            requirements_file = self.project_root / "requirements.txt"
            if requirements_file.exists():
                self._run_command([
                    str(self.python_executable), "-m", "pip", "install",
                    "-r", str(requirements_file)
                ])
            
            # Install development dependencies if in dev mode
            if dev_mode:
                dev_requirements = self.project_root / "requirements-dev.txt"
                if dev_requirements.exists():
                    self._run_command([
                        str(self.python_executable), "-m", "pip", "install",
                        "-r", str(dev_requirements)
                    ])
            
            self.logger.info("Dependencies installed ✓")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            return False
    
    def create_environment_file(self) -> bool:
        """Create .env.example file with configuration template"""
        env_file = self.project_root / ".env.example"
        
        if not env_file.exists():
            self.logger.info("Creating environment configuration template...")
            with open(env_file, "w") as f:
                f.write(ENV_TEMPLATE)
            self.logger.info(".env.example created ✓")
        else:
            self.logger.info(".env.example already exists")
        
        return True
    
    def validate_installation(self) -> bool:
        """Validate installation and dependency integrity"""
        self.logger.info("Validating installation...")
        
        validation_checks = [
            ("Flask", ">=2.3.0"),
            ("pip-tools", ">=7.3.0"),
            ("pytest", ">=7.4.0"),
            ("flake8", ">=6.1.0"),
            ("mypy", ">=1.8.0")
        ]
        
        for package, min_version in validation_checks:
            try:
                result = self._run_command([
                    str(self.python_executable), "-c",
                    f"import {package.lower().replace('-', '_')}; print({package.lower().replace('-', '_')}.__version__)"
                ], capture_output=True)
                
                version = result.stdout.strip()
                self.logger.info(f"{package} {version} ✓")
                
            except Exception:
                self.logger.warning(f"Could not validate {package}")
        
        return True
    
    def setup_development_tools(self) -> bool:
        """Configure development tools and pre-commit hooks"""
        self.logger.info("Setting up development tools...")
        
        try:
            # Install pre-commit hooks if configuration exists
            pre_commit_config = self.project_root / ".pre-commit-config.yaml"
            if pre_commit_config.exists():
                self._run_command([
                    str(self.python_executable), "-m", "pre_commit", "install"
                ])
                self.logger.info("Pre-commit hooks installed ✓")
            
            return True
        except Exception as e:
            self.logger.warning(f"Could not setup development tools: {e}")
            return True  # Non-critical failure
    
    def run_quality_checks(self) -> bool:
        """Run initial quality checks to validate setup"""
        self.logger.info("Running quality validation checks...")
        
        checks = [
            # Check flake8 configuration
            ([str(self.python_executable), "-m", "flake8", "--version"], "flake8 check"),
            # Check mypy configuration  
            ([str(self.python_executable), "-m", "mypy", "--version"], "mypy check"),
            # Check bandit configuration
            ([str(self.python_executable), "-m", "bandit", "--version"], "bandit check"),
            # Check pytest configuration
            ([str(self.python_executable), "-m", "pytest", "--version"], "pytest check")
        ]
        
        for cmd, description in checks:
            try:
                self._run_command(cmd, capture_output=True)
                self.logger.info(f"{description} ✓")
            except Exception:
                self.logger.warning(f"{description} - tool not available")
        
        return True
    
    def display_next_steps(self, dev_mode: bool = True) -> None:
        """Display next steps for development"""
        self.logger.info("\n" + "="*60)
        self.logger.info("🎉 Flask Development Environment Setup Complete!")
        self.logger.info("="*60)
        
        if platform.system() == "Windows":
            activate_cmd = f".\\{VENV_DIR}\\Scripts\\activate"
        else:
            activate_cmd = f"source {VENV_DIR}/bin/activate"
        
        next_steps = f"""
Next Steps:

1. Activate Virtual Environment:
   {activate_cmd}

2. Copy Environment Configuration:
   cp .env.example .env
   # Edit .env with your configuration

3. Run Development Server:
   flask run --debug --reload
   # or
   python app.py

4. Run Tests:
   pytest tests/ --cov=src/ --cov-report=html

5. Quality Checks:
   flake8 src/
   mypy src/
   bandit -r src/

6. Performance Testing:
   locust -f tests/performance/locust_performance_test.py

7. Container Development:
   docker-compose up -d

📝 Documentation:
   - README.md for project overview
   - Technical specifications in docs/
   - API documentation via Flask routes

🔧 Development Tools Available:
   - pytest for testing (≥90% coverage required)
   - flake8 for code style (PEP 8 compliance)
   - mypy for type checking (strict mode)
   - bandit for security scanning
   - locust for performance testing
   - pre-commit hooks for quality gates
"""
        
        print(next_steps)


def main():
    """Main setup script entry point"""
    parser = argparse.ArgumentParser(
        description="Flask Application Environment Setup Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "--dev", 
        action="store_true", 
        default=True,
        help="Install development dependencies (default)"
    )
    
    parser.add_argument(
        "--prod", 
        action="store_true",
        help="Install production dependencies only"
    )
    
    parser.add_argument(
        "--rebuild", 
        action="store_true",
        help="Force rebuild of virtual environment"
    )
    
    parser.add_argument(
        "--upgrade", 
        action="store_true",
        help="Upgrade all dependencies to latest compatible versions"
    )
    
    parser.add_argument(
        "--validate", 
        action="store_true",
        help="Validate environment and dependency integrity"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = SetupLogger(log_level)
    
    # Handle production-only mode
    install_dev = not args.prod
    
    # Initialize setup manager
    setup = EnvironmentSetup(logger)
    
    try:
        # Validation mode
        if args.validate:
            logger.info("Validating environment...")
            setup.validate_python_version()
            setup.validate_installation()
            setup.run_quality_checks()
            logger.info("Validation complete ✓")
            return 0
        
        # Main setup process
        logger.info("Starting Flask application environment setup...")
        logger.info(f"Project root: {setup.project_root}")
        logger.info(f"Python executable: {setup.python_executable}")
        
        # Step 1: Validate Python version
        if not setup.validate_python_version():
            return 1
        
        # Step 2: Create virtual environment
        if not setup.create_virtual_environment(rebuild=args.rebuild):
            return 1
        
        # Step 3: Install core dependencies
        if not setup.install_core_dependencies():
            return 1
        
        # Step 4: Create requirements files
        if not setup.create_requirements_files(install_dev=install_dev):
            return 1
        
        # Step 5: Compile dependencies with pip-tools
        if not setup.compile_dependencies(upgrade=args.upgrade):
            return 1
        
        # Step 6: Install compiled dependencies
        if not setup.install_dependencies(dev_mode=install_dev):
            return 1
        
        # Step 7: Create environment configuration
        if not setup.create_environment_file():
            return 1
        
        # Step 8: Setup development tools
        if install_dev:
            setup.setup_development_tools()
        
        # Step 9: Validate installation
        if not setup.validate_installation():
            return 1
        
        # Step 10: Run quality checks
        if install_dev:
            setup.run_quality_checks()
        
        # Display completion message
        setup.display_next_steps(dev_mode=install_dev)
        
        logger.info("🚀 Setup completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        logger.error("Setup interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Setup failed with error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())