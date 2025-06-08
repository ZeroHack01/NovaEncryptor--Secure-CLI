#!/usr/bin/env python3
"""
NovaEncryptor v2.0 - Setup Script
Automated installation with enhanced features
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_step(step_num, description):
    """Print formatted step"""
    print(f"\n🔧 Step {step_num}: {description}")
    print("=" * 60)

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

def check_requirements():
    """Check system requirements"""
    print_step(1, "Checking System Requirements")
    
    # Check Python version
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
    
    # Check if git is available (optional)
    if shutil.which('git'):
        print("✅ Git available")
    else:
        print("⚠️  Git not found (optional)")
    
    return True

def create_directory_structure():
    """Create enhanced directory structure"""
    print_step(2, "Creating Enhanced Directory Structure")
    
    directories = [
        'src',
        'tests', 
        'scripts',
        'docs',
        'examples',
        'encrypted_files',
        'decrypted_files',
        Path.home() / '.nova_encryptor',
        Path.home() / '.nova_encryptor' / 'keys',
        Path.home() / '.nova_encryptor' / 'logs',
        Path.home() / '.nova_encryptor' / 'config'
    ]
    
    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
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
    """Set up virtual environment"""
    print_step(3, "Setting Up Virtual Environment")
    
    venv_path = Path('nova_env')
    
    if venv_path.exists():
        print("📁 Virtual environment already exists")
        return True
    
    if not run_command(f"{sys.executable} -m venv nova_env", "creating virtual environment"):
        return False
    
    print("✅ Virtual environment created")
    return True

def install_dependencies():
    """Install enhanced dependencies"""
    print_step(4, "Installing Enhanced Dependencies")
    
    # Enhanced requirements
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
    
    requirements_file = Path('requirements.txt')
    with open(requirements_file, 'w') as f:
        f.write('\n'.join(requirements))
    print("✅ Created enhanced requirements.txt")
    
    # Determine pip executable
    if sys.platform == "win32":
        pip_executable = "nova_env\\Scripts\\pip"
    else:
        pip_executable = "nova_env/bin/pip"
    
    # Upgrade pip first
    if not run_command(f"{pip_executable} install --upgrade pip", "upgrading pip"):
        return False
    
    # Install requirements
    if not run_command(f"{pip_executable} install -r requirements.txt", "installing dependencies"):
        return False
    
    print("✅ Enhanced dependencies installed successfully")
    return True

def create_enhanced_config():
    """Create enhanced configuration"""
    print_step(5, "Creating Enhanced Configuration")
    
    # Enhanced configuration
    enhanced_config = {
        "rsa_key_size": 4096,
        "aes_key_size": 32,
        "argon2_time_cost": 3,
        "argon2_memory_cost": 65536,
        "argon2_parallelism": 4,
        "salt_size": 32,
        "nonce_size": 12,
        "audit_enabled": True,
        "max_file_size": 52428800,  # 50MB
        "supported_extensions": [
            ".txt", ".pdf", ".docx", ".xlsx", ".pptx",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".json", ".xml", ".csv", ".html", ".css",
            ".js", ".py", ".cpp", ".java", ".md"
        ],
        "auto_backup": True,
        "secure_delete": True,
        "memory_protection": True
    }
    
    config_file = Path.home() / '.nova_encryptor' / 'config.json'
    
    if not config_file.exists():
        import json
        with open(config_file, 'w') as f:
            json.dump(enhanced_config, f, indent=2)
        print(f"✅ Created enhanced config: {config_file}")
    else:
        print(f"📁 Config file already exists: {config_file}")
    
    return True

def create_launcher_scripts():
    """Create enhanced launcher scripts"""
    print_step(6, "Creating Enhanced Launcher Scripts")
    
    # Enhanced Unix launcher
    unix_launcher = """#!/bin/bash
# NovaEncryptor v2.0 Enhanced Launcher

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

echo -e "${BLUE}🛡️  NovaEncryptor v2.0 Enhanced${NC}"
echo -e "${BLUE}Complete File & Text Encryption System${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d "nova_env" ]; then
    echo -e "${RED}❌ Virtual environment not found. Run setup_enhanced.py first.${NC}"
    exit 1
fi

# Check if enhanced version exists
if [ ! -f "src/nova_encryptor_enhanced.py" ]; then
    echo -e "${RED}❌ Enhanced version not found. Please check installation.${NC}"
    exit 1
fi

# Activate virtual environment and run
source nova_env/bin/activate

# Check command line arguments
if [ "$1" = "--batch" ]; then
    echo -e "${GREEN}🔄 Starting batch mode...${NC}"
    python scripts/batch_file_processor.py "${@:2}"
elif [ "$1" = "--info" ]; then
    echo -e "${GREEN}📋 Showing feature information...${NC}"
    python nova-encryptor-enhanced.py --info
else
    echo -e "${GREEN}🚀 Starting interactive mode...${NC}"
    python nova-encryptor-enhanced.py "$@"
fi
"""
    
    unix_script = Path('nova-encryptor-enhanced.sh')
    with open(unix_script, 'w') as f:
        f.write(unix_launcher)
    
    if hasattr(os, 'chmod'):
        os.chmod(unix_script, 0o755)
    print(f"✅ Created enhanced Unix launcher: {unix_script}")
    
    # Enhanced Windows launcher
    windows_launcher = """@echo off
REM NovaEncryptor v2.0 Enhanced Launcher

echo 🛡️  NovaEncryptor v2.0 Enhanced
echo Complete File ^& Text Encryption System
echo.

REM Check if virtual environment exists
if not exist "nova_env" (
    echo ❌ Virtual environment not found. Run setup_enhanced.py first.
    pause
    exit /b 1
)

REM Check if enhanced version exists
if not exist "src\\nova_encryptor_enhanced.py" (
    echo ❌ Enhanced version not found. Please check installation.
    pause
    exit /b 1
)

REM Activate virtual environment and run
call nova_env\\Scripts\\activate

REM Check command line arguments
if "%1"=="--batch" (
    echo 🔄 Starting batch mode...
    python scripts\\batch_file_processor.py %*
) else if "%1"=="--info" (
    echo 📋 Showing feature information...
    python nova-encryptor-enhanced.py --info
) else (
    echo 🚀 Starting interactive mode...
    python nova-encryptor-enhanced.py %*
)

pause
"""
    
    windows_script = Path('nova-encryptor-enhanced.bat')
    with open(windows_script, 'w') as f:
        f.write(windows_launcher)
    print(f"✅ Created enhanced Windows launcher: {windows_script}")
    
    return True

def create_example_files():
    """Create example files and documentation"""
    print_step(7, "Creating Examples and Documentation")
    
    # Create examples directory content
    examples_dir = Path('examples')
    
    # Example files for testing
    example_files = {
        'test_document.txt': "This is a test document for NovaEncryptor v2.0 Enhanced.\nIt contains multiple lines of text to demonstrate encryption capabilities.",
        'sample_data.json': '{"name": "Test User", "email": "test@example.com", "data": "sensitive information"}',
        'readme_example.md': "# Example File\n\nThis is an example markdown file for testing encryption.\n\n## Features\n- Text encryption\n- File encryption\n- Batch processing"
    }
    
    for filename, content in example_files.items():
        example_file = examples_dir / filename
        with open(example_file, 'w') as f:
            f.write(content)
        print(f"✅ Created example: {filename}")
    
    # Create quick start guide
    quick_start = """# 🚀 NovaEncryptor v2.0 Enhanced - Quick Start

## First Time Setup
1. Run setup: `python setup_enhanced.py`
2. Generate keys: Select option 1 in main menu
3. Start encrypting!

## Interactive Mode
```bash
./nova-encryptor-enhanced.sh          # Linux/macOS
nova-encryptor-enhanced.bat           # Windows
```

## Batch Operations
```bash
# Encrypt multiple files
./nova-encryptor-enhanced.sh --batch encrypt file1.pdf file2.jpg

# Decrypt multiple files  
./nova-encryptor-enhanced.sh --batch decrypt encrypted_*.json -p password
```

## File Types Supported
- 📄 Documents: PDF, DOCX, TXT, RTF
- 🖼️ Images: JPG, PNG, GIF, BMP
- 📦 Archives: ZIP, RAR, 7Z
- 📊 Data: JSON, XML, CSV, XLSX
- 💻 Code: Any programming language

## Example Workflow
1. **Generate Keys**: First time only
2. **Encrypt Files**: Select files to encrypt  
3. **Share Safely**: Send encrypted files + password separately
4. **Decrypt**: Recipients decrypt with password
5. **Secure Delete**: Remove originals after encryption

Enjoy secure encryption! 🛡️
"""
    
    with open('QUICK_START.md', 'w') as f:
        f.write(quick_start)
    print("✅ Created QUICK_START.md")
    
    return True

def run_verification():
    """Run verification tests"""
    print_step(8, "Running Verification Tests")
    
    # Test import
    try:
        import sys
        sys.path.insert(0, 'src')
        from nova_encryptor_enhanced import EnhancedUserInterface
        print("✅ Enhanced NovaEncryptor imports successfully")
    except ImportError as e:
        print(f"❌ Import test failed: {e}")
        return False
    
    # Test batch processor
    batch_script = Path('scripts') / 'batch_file_processor.py'
    if batch_script.exists():
        print("✅ Batch processor available")
    else:
        print("⚠️  Batch processor not found")
    
    # Test example files
    examples = list(Path('examples').glob('*'))
    if examples:
        print(f"✅ Created {len(examples)} example files")
    
    return True

def print_success_message():
    """Print final success message"""
    print("\n" + "=" * 70)
    print("🎉 NOVAENCRYPTOR v2.0 ENHANCED SETUP COMPLETE!")
    print("=" * 70)
    
    print("\n🚀 WHAT'S NEW:")
    print("  • 📁 Direct file & image encryption")
    print("  • 🔄 Batch processing capabilities") 
    print("  • 📊 File integrity verification")
    print("  • 🎨 Enhanced user interface")
    print("  • 🔐 Advanced security features")
    
    print("\n📋 NEXT STEPS:")
    print("1. Launch Enhanced NovaEncryptor:")
    if sys.platform == "win32":
        print("   nova-encryptor-enhanced.bat")
    else:
        print("   ./nova-encryptor-enhanced.sh")
    
    print("\n2. Generate your first keypair:")
    print("   • Select option 1 in the main menu")
    print("   • Choose a strong password")
    
    print("\n3. Try encrypting files:")
    print("   • Select option 3 for files/images")
    print("   • Select option 2 for text messages")
    
    print("\n4. Test batch operations:")
    print("   • Try: examples/test_document.txt")
    print("   • Use batch mode for multiple files")
    
    print("\n📁 IMPORTANT LOCATIONS:")
    config_path = Path.home() / '.nova_encryptor'
    print(f"   Config & Keys: {config_path}")
    print(f"   Examples: {Path('examples')}")
    print(f"   Documentation: QUICK_START.md")
    
    print("\n🔒 SECURITY REMINDERS:")
    print("   • Use strong, unique passwords")
    print("   • Backup your keys securely")
    print("   • Delete originals after encryption")
    print("   • Test decryption before deleting backups")
    
    print("\n✨ FEATURES TO EXPLORE:")
    print("   • File encryption with metadata preservation")
    print("   • Batch processing for multiple files")
    print("   • SHA256 integrity verification")
    print("   • Cross-platform compatibility")
    print("   • Comprehensive audit logging")
    
    print(f"\n📞 GET HELP:")
    print("   • Run with --info flag for feature overview")
    print("   • Check QUICK_START.md for examples")
    print("   • View audit logs (option 7 in menu)")

def main():
    """Main setup function"""
    print("🛡️  NovaEncryptor v2.0 Enhanced Setup")
    print("Complete File & Text Encryption System")
    print("=" * 60)
    
    steps = [
        check_requirements,
        create_directory_structure,
        setup_virtual_environment,
        install_dependencies,
        create_enhanced_config,
        create_launcher_scripts,
        create_example_files,
        run_verification
    ]
    
    for step_func in steps:
        if not step_func():
            print(f"\n❌ Setup failed at: {step_func.__name__}")
            print("Please check the errors above and try again.")
            sys.exit(1)
    
    print_success_message()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        sys.exit(1)
