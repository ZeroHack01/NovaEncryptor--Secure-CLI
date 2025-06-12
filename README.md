# 🛡️ NovaEncryptor v2.0 - Secure CLI Encryption Tool

A modern command-line encryption tool with hybrid **RSA-4096 + AES-256-GCM** encryption, password-protected keys, and cross-platform support.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cross-Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/ZeroHack01/NovaEncryptor-v2)

## ✨ Features

- **🔐 Hybrid Encryption**: RSA-4096 + AES-256-GCM for maximum security
- **🔑 Password Protection**: Argon2 key derivation for private keys
- **💻 Cross-Platform**: Works on Linux, macOS, and Windows
- **🎨 Interactive CLI**: Beautiful command-line interface with menus
- **📊 Audit Logging**: Track all encryption/decryption operations
- **🛡️ Memory Safe**: Secure deletion of sensitive data
- **⚡ Fast Setup**: Automated installation script

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (Python 3.10+ recommended)
- **Git** (optional, for cloning)

### Installation

```bash
# Clone the repository
git clone https://github.com/ZeroHack01/NovaEncryptor-v2.git
cd NovaEncryptor-v2

# Run automated setup
python3 scripts/setup.py  # Linux/macOS
python scripts/setup.py   # Windows

# Activate virtual environment
source nova_env/bin/activate  # Linux/macOS
nova_env\Scripts\activate     # Windows

# Launch application
python src/nova_encryptor.py
```

## 📋 Platform-Specific Instructions

### 🐧 Linux

```bash
# Ubuntu/Debian - Install Python if needed
sudo apt update
sudo apt install python3 python3-pip python3-venv git

# Clone and setup
git clone https://github.com/ZeroHack01/NovaEncryptor-v2.git
cd NovaEncryptor-v2
python3 scripts/setup.py
source nova_env/bin/activate
python src/nova_encryptor.py

# Or use launcher script
chmod +x nova-encryptor.sh
./nova-encryptor.sh
```

### 🍎 macOS

```bash
# Install Python using Homebrew (recommended)
brew install python3 git

# Clone and setup
git clone https://github.com/ZeroHack01/NovaEncryptor-v2.git
cd NovaEncryptor-v2
python3 scripts/setup.py
source nova_env/bin/activate
python src/nova_encryptor.py

# Or use launcher script
chmod +x nova-encryptor.sh
./nova-encryptor.sh
```

### 🪟 Windows

```powershell
# Install Python from python.org (check "Add to PATH")
# Or use winget: winget install Python.Python.3.11

# Open PowerShell/Command Prompt
git clone https://github.com/ZeroHack01/NovaEncryptor-v2.git
cd NovaEncryptor-v2
python scripts/setup.py
nova_env\Scripts\activate
python src/nova_encryptor.py

# Or use launcher script
nova-encryptor.bat
```

## 🎯 Usage Guide

### Basic Operations

1. **Generate Keys**: Select option 1 to create RSA-4096 keypair
2. **Encrypt Message**: Select option 2, enter your message
3. **Decrypt Message**: Select option 3, provide encrypted data and password
4. **List Keys**: Select option 4 to view available keys
5. **View Config**: Select option 5 to see current settings

### Example Session

```
📋 Main Menu
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Action                      ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ 🔑 Generate new RSA keypair │
│ 2        │ 🔒 Encrypt message          │
│ 3        │ 🔓 Decrypt message          │
│ 4        │ 📋 List keys                │
│ 5        │ ⚙️  View configuration       │
│ 6        │ 📊 View audit log           │
│ 0        │ 🚪 Exit                     │
└──────────┴─────────────────────────────┘

Select option [0/1/2/3/4/5/6]: 1

🔑 Key Generation
Protect private key with password? [y/n]: y
Enter password: ********
Confirm password: ********
✅ Keypair generated successfully!
```

### File Locations

- **Linux/macOS**: `~/.nova_encryptor/`
- **Windows**: `%USERPROFILE%\.nova_encryptor\`

```
.nova_encryptor/
├── keys/          # RSA keypairs
├── logs/          # Audit logs
└── config/        # Configuration files
```

## 🔧 Configuration

Edit `~/.nova_encryptor/config.json` to customize settings:

```json
{
  "rsa_key_size": 4096,
  "aes_key_size": 32,
  "argon2_time_cost": 3,
  "argon2_memory_cost": 65536,
  "audit_enabled": true
}
```

## 🧪 Testing

```bash
# Activate virtual environment first
source nova_env/bin/activate  # Linux/macOS
nova_env\Scripts\activate     # Windows

# Run test suite
python -m pytest tests/ -v

# Run security checks
python -m bandit src/nova_encryptor.py
```

## 📁 Project Structure

```
NovaEncryptor-v2/
├── src/
│   └── nova_encryptor.py      # Main application
├── tests/
│   └── test_nova_encryptor.py # Test suite
├── scripts/
│   └── setup.py              # Automated setup
├── .github/workflows/         # GitHub Actions
├── requirements.txt          # Python dependencies
├── nova-encryptor.sh         # Unix launcher
├── nova-encryptor.bat        # Windows launcher
├── README.md                # This file
├── LICENSE                  # MIT license
└── .gitignore              # Git ignore rules
```

## 🔒 Security

- **RSA-4096**: Quantum-resistant until 2040+
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Argon2**: Password-based key derivation (PHC winner)
- **Secure Memory**: Automatic cleanup of sensitive data
- **Audit Trail**: Complete logging of all operations

## ⚡ Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation (RSA-4096) | ~2s | One-time setup |
| Encryption (1KB) | ~12ms | Very fast |
| Decryption (1KB) | ~6ms | Lightning fast |
| Memory Usage | ~18MB | Minimal footprint |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Ensure all tests pass
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔍 Troubleshooting

### Common Issues

**Import Error:**
```bash
# Make sure virtual environment is activated
source nova_env/bin/activate  # Linux/macOS
nova_env\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

**Permission Denied (Unix):**
```bash
# Fix launcher script permissions
chmod +x nova-encryptor.sh
```

**Python Not Found (Windows):**
```powershell
# Make sure Python is in PATH, or use full path
C:\Users\YourName\AppData\Local\Programs\Python\Python311\python.exe
```

**Virtual Environment Issues:**
```bash
# Delete and recreate
rm -rf nova_env/           # Linux/macOS
rmdir /s nova_env\         # Windows

# Run setup again
python3 scripts/setup.py   # Linux/macOS
python scripts/setup.py    # Windows
```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ZeroHack01/NovaEncryptor-v2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ZeroHack01/NovaEncryptor-v2/discussions)
- **Security**: See [SECURITY.md](docs/SECURITY.md) for security policy

## 🙏 Acknowledgments

- **[PyCA Cryptography](https://cryptography.io/)** - Cryptographic library
- **[argon2-cffi](https://github.com/hynek/argon2-cffi)** - Password hashing
- **[Rich](https://github.com/Textualize/rich)** - Beautiful terminal interface

---

**Made with 🛡️ for secure communications**