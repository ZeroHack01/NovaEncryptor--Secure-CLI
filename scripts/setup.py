#!/usr/bin/env python3
"""
NovaEncryptor v2.0 Setup Script
Automated installation and configuration
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_step(step_num, description):
    """Print formatted step"""
    print(f"\n🔧 Step {step_num}: {description}")
    print("=" * 50)

def run_command(command, description=""):
    """Run shell command with error handling"""
    try:
        print(f"Running: {command}")
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error {description}: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check Python version compatibility"""
    print_step(1, "Checking Python Version")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
    return True

def create_directories():
    """Create necessary directories"""
    print_step(2, "Creating Directory Structure")
    
    directories = [
        Path.home() / '.nova_encryptor',
        Path.home() / '.nova_encryptor' / 'keys',
        Path.home() / '.nova_encryptor' / 'logs',
        Path.home() / '.nova_encryptor' / 'config',
        Path('src'),
        Path('tests'),
        Path('docs'),
        Path('scripts'),
        Path('config')
    ]
    
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created: {directory}")
            
            # Set secure permissions for user directories
            if '.nova_encryptor' in str(directory):
                if hasattr(os, 'chmod'):
                    os.chmod(directory, 0o700)
                    print(f"🔒 Secured: {directory}")
        except Exception as e:
            print(f"❌ Failed to create {directory}: {e}")
            return False
    
    return True

def setup_virtual_environment():
    """Create and activate virtual environment"""
    print_step(3, "Setting Up Virtual Environment")
    
    venv_path = Path('nova_env')
    
    if venv_path.exists():
        print("📁 Virtual environment already exists")
        return True
    
    # Create virtual environment
    if not run_command(f"{sys.executable} -m venv nova_env", "creating virtual environment"):
        return False
    
    print("✅ Virtual environment created")
    
    # Determine activation script path
    if platform.system() == "Windows":
        activate_script = venv_path / "Scripts" / "activate"
        pip_executable = venv_path / "Scripts" / "pip"
    else:
        activate_script = venv_path / "bin" / "activate"
        pip_executable = venv_path / "bin" / "pip"
    
    print(f"📝 To activate: source {activate_script}")
    return True

def install_dependencies():
    """Install Python dependencies"""
    print_step(4, "Installing Dependencies")
    
    # Determine pip executable
    if platform.system() == "Windows":
        pip_executable = "nova_env\\Scripts\\pip"
    else:
        pip_executable = "nova_env/bin/pip"
    
    # Create requirements.txt if it doesn't exist
    requirements_file = Path('requirements.txt')
    if not requirements_file.exists():
        requirements = [
            "cryptography>=41.0.0",
            "argon2-cffi>=23.0.0", 
            "rich>=13.0.0",
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "bandit>=1.7.0",
            "safety>=2.0.0"
        ]
        
        with open(requirements_file, 'w') as f:
            f.write('\n'.join(requirements))
        print("✅ Created requirements.txt")
    
    # Upgrade pip first
    if not run_command(f"{pip_executable} install --upgrade pip", "upgrading pip"):
        return False
    
    # Install requirements
    if not run_command(f"{pip_executable} install -r requirements.txt", "installing dependencies"):
        return False
    
    print("✅ Dependencies installed successfully")
    return True

def create_config_files():
    """Create default configuration files"""
    print_step(5, "Creating Configuration Files")
    
    # Default configuration
    default_config = {
        "rsa_key_size": 4096,
        "aes_key_size": 32,
        "argon2_time_cost": 3,
        "argon2_memory_cost": 65536,
        "argon2_parallelism": 4,
        "salt_size": 32,
        "nonce_size": 12,
        "audit_enabled": True,
        "key_rotation_days": 90,
        "secure_delete": True
    }
    
    config_file = Path.home() / '.nova_encryptor' / 'config.json'
    
    if not config_file.exists():
        import json
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✅ Created config file: {config_file}")
    else:
        print(f"📁 Config file already exists: {config_file}")
    
    # Create .gitignore
    gitignore_content = """
# Virtual environment
nova_env/

# User data
.nova_encryptor/

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so

# IDE
.vscode/
.idea/
*.swp
*.swo

# Testing
.pytest_cache/
.coverage
htmlcov/

# OS
.DS_Store
Thumbs.db
"""
    
    gitignore_file = Path('.gitignore')
    if not gitignore_file.exists():
        with open(gitignore_file, 'w') as f:
            f.write(gitignore_content.strip())
        print("✅ Created .gitignore")
    
    return True

def create_launcher_scripts():
    """Create launcher scripts for easy execution"""
    print_step(6, "Creating Launcher Scripts")
    
    # Unix launcher
    unix_launcher = """#!/bin/bash
# NovaEncryptor v2.0 Launcher

# Check if virtual environment exists
if [ ! -d "nova_env" ]; then
    echo "❌ Virtual environment not found. Run setup.py first."
    exit 1
fi

# Activate virtual environment and run
source nova_env/bin/activate
python src/nova_encryptor.py "$@"
"""
    
    unix_script = Path('nova-encryptor.sh')
    with open(unix_script, 'w') as f:
        f.write(unix_launcher)
    
    if hasattr(os, 'chmod'):
        os.chmod(unix_script, 0o755)
    print(f"✅ Created Unix launcher: {unix_script}")
    
    # Windows launcher
    windows_launcher = """@echo off
REM NovaEncryptor v2.0 Launcher

REM Check if virtual environment exists
if not exist "nova_env" (
    echo ❌ Virtual environment not found. Run setup.py first.
    pause
    exit /b 1
)

REM Activate virtual environment and run
call nova_env\\Scripts\\activate
python src\\nova_encryptor.py %*
pause
"""
    
    windows_script = Path('nova-encryptor.bat')
    with open(windows_script, 'w') as f:
        f.write(windows_launcher)
    print(f"✅ Created Windows launcher: {windows_script}")
    
    return True

def run_tests():
    """Run initial tests to verify installation"""
    print_step(7, "Running Installation Tests")
    
    # Check if test file exists in src
    test_file = Path('tests') / 'test_nova_encryptor.py'
    if not test_file.exists():
        print("⚠️  Test file not found, skipping tests")
        return True
    
    # Determine python executable
    if platform.system() == "Windows":
        python_executable = "nova_env\\Scripts\\python"
    else:
        python_executable = "nova_env/bin/python"
    
    # Run basic import test
    test_command = f'{python_executable} -c "import sys; sys.path.insert(0, \'src\'); from nova_encryptor import ConfigManager; print(\'✅ Import test passed\')"'
    
    if run_command(test_command, "running import test"):
        print("✅ Installation verified successfully")
        return True
    else:
        print("⚠️  Installation test failed, but setup may still work")
        return True

def print_next_steps():
    """Print next steps for user"""
    print("\n" + "=" * 60)
    print("🎉 SETUP COMPLETE!")
    print("=" * 60)
    
    print("\n📋 Next Steps:")
    print("1. Activate virtual environment:")
    if platform.system() == "Windows":
        print("   nova_env\\Scripts\\activate")
    else:
        print("   source nova_env/bin/activate")
    
    print("\n2. Run NovaEncryptor:")
    print("   python src/nova_encryptor.py")
    print("   OR use launcher scripts:")
    print("   ./nova-encryptor.sh  (Unix/Linux/Mac)")
    print("   nova-encryptor.bat   (Windows)")
    
    print("\n3. Generate your first keypair:")
    print("   - Select option 1 in the main menu")
    print("   - Choose whether to password-protect your private key")
    
    print("\n4. Start encrypting messages:")
    print("   - Select option 2 to encrypt")
    print("   - Select option 3 to decrypt")
    
    print("\n📁 Configuration:")
    config_path = Path.home() / '.nova_encryptor' / 'config.json'
    print(f"   Config file: {config_path}")
    print(f"   Keys stored: {Path.home() / '.nova_encryptor' / 'keys'}")
    print(f"   Logs stored: {Path.home() / '.nova_encryptor' / 'logs'}")
    
    print("\n🔒 Security Tips:")
    print("   - Use strong passwords for private key protection")
    print("   - Backup your keys securely")
    print("   - Keep your private keys secret")
    print("   - Check audit logs regularly")

def main():
    """Main setup function"""
    print("🛡️  NovaEncryptor v2.0 Setup")
    print("Enhanced Security • Modern Architecture")
    print("=" * 50)
    
    steps = [
        check_python_version,
        create_directories,
        setup_virtual_environment,
        install_dependencies,
        create_config_files,
        create_launcher_scripts,
        run_tests
    ]
    
    for step_func in steps:
        if not step_func():
            print(f"\n❌ Setup failed at: {step_func.__name__}")
            print("Please check the errors above and try again.")
            sys.exit(1)
    
    print_next_steps()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        sys.exit(1)