# 🔐 NovaEncryptor - Secure CLI Encryption Tool

<div align="center">

![NovaEncryptor Logo](https://img.shields.io/badge/NovaEncryptor-Secure%20CLI-blue?style=for-the-badge&logo=shield&logoColor=white)

[![Python Version](https://img.shields.io/badge/Python-3.7+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES%20256%20%2B%20RSA%202048-red.svg?style=flat-square&logo=security&logoColor=white)](https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)](https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI)

**A powerful command-line encryption tool that combines military-grade AES-256 encryption with RSA-2048 key management for ultimate security.**

[🚀 Quick Start](#-quick-start) • [📚 Documentation](#-usage) • [🔧 Installation](#-installation) • [🛡️ Security](#-security-features) • [🤝 Contributing](#-contributing)

</div>

---

## ✨ Features

🔒 **Military-Grade Encryption**
- **AES-256** encryption for lightning-fast message security
- **RSA-2048** for bulletproof key management
- **Hybrid encryption** combining speed and security

🛡️ **Advanced Security**
- **EAX mode** for authenticated encryption
- **Data integrity** protection against tampering
- **Automatic key generation** with secure defaults

⚡ **Developer Friendly**
- **Simple CLI interface** for easy integration
- **Cross-platform compatibility** (Windows, macOS, Linux)
- **Lightweight** with minimal dependencies

🎨 **Beautiful Interface**
- **ASCII art** branding with pyfiglet
- **Clear output formatting** for better readability
- **Intuitive command structure**

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI.git

# Navigate to directory
cd NovaEncryptor--Secure-CLI

# Install dependencies
pip install pycryptodome pyfiglet

# Run NovaEncryptor
python3 novaencryptor.py
```

---

## 🔧 Installation

### Prerequisites

- **Python 3.7+** (Download from [python.org](https://python.org))
- **pip** package manager

### Step-by-Step Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI.git
   cd NovaEncryptor--Secure-CLI
   ```

2. **Set Up Virtual Environment** (Recommended)
   ```bash
   # Create virtual environment
   python3 -m venv novaenv
   
   # Activate virtual environment
   # On macOS/Linux:
   source novaenv/bin/activate
   # On Windows:
   novaenv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install pycryptodome pyfiglet
   ```

4. **Verify Installation**
   ```bash
   python3 novaencryptor.py
   ```

---

## 📚 Usage

### 🔐 Encrypting Messages

```bash
python3 novaencryptor.py
```

**Interactive Workflow:**
1. Choose `encrypt` when prompted
2. Enter your secret message
3. Receive encrypted output with:
   - 🔒 Encrypted message (Base64)
   - 🔑 Encrypted AES key (Base64)
   - 🎯 Nonce (Base64)
   - 🏷️ Authentication tag (Base64)

**Example:**
```
Enter 'encrypt' to encrypt a message or 'decrypt' to decrypt a message: encrypt
Enter the message to encrypt: Hello, this is a top secret message!

Encryption successful!
Encrypted Message: U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y=
Encrypted AES Key: kQiOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Nonce: YWJjZGVmZ2hpams=
Tag: YWJjZGVmZ2hpamtsbW5vcA==
```

### 🔓 Decrypting Messages

```bash
python3 novaencryptor.py
```

**Interactive Workflow:**
1. Choose `decrypt` when prompted
2. Input all required components:
   - Encrypted message
   - Encrypted AES key
   - Nonce
   - Authentication tag
3. Receive your original message

**Example:**
```
Enter 'encrypt' to encrypt a message or 'decrypt' to decrypt a message: decrypt
Enter the encrypted message: U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y=
Enter the encrypted AES key: kQiOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Enter the nonce: YWJjZGVmZ2hpams=
Enter the tag: YWJjZGVmZ2hpamtsbW5vcA==

Decryption successful!
Decrypted Message: Hello, this is a top secret message!
```

---

## 🛡️ Security Features

### Encryption Standards

| Component | Standard | Key Length | Security Level |
|-----------|----------|------------|----------------|
| **Message Encryption** | AES-256 | 256-bit | Military Grade |
| **Key Encryption** | RSA-2048 | 2048-bit | Enterprise Grade |
| **Authentication** | EAX Mode | N/A | Tamper-Proof |

### Security Benefits

🔐 **Confidentiality**: AES-256 ensures your messages remain private
🛡️ **Integrity**: EAX mode detects any tampering attempts  
🔑 **Key Security**: RSA-2048 protects encryption keys
⚡ **Performance**: Hybrid approach balances security and speed
🔄 **Key Management**: Automatic RSA key pair generation

---

## 📁 Project Structure

```
NovaEncryptor--Secure-CLI/
├── 📄 novaencryptor.py      # Main encryption/decryption script
├── 🔐 rsa_private.pem       # RSA private key (auto-generated)
├── 🔑 rsa_public.pem        # RSA public key (auto-generated)
├── 📖 README.md             # Project documentation
└── 📜 LICENSE               # MIT License
```

---

## ⚙️ Configuration

### Custom RSA Key Length

For enhanced security, you can modify the RSA key length in `novaencryptor.py`:

```python
# Change from RSA-2048 to RSA-4096 for maximum security
key = RSA.generate(4096)  # Default: 2048
```

### Environment Variables

Set optional environment variables for enhanced security:

```bash
export NOVA_KEY_PATH="/secure/path/to/keys/"
export NOVA_LOG_LEVEL="INFO"
```

---

## 🔍 Troubleshooting

### Common Issues

**❌ ModuleNotFoundError: No module named 'Crypto'**
```bash
pip install pycryptodome
```

**❌ Permission denied when generating keys**
```bash
chmod 755 ./
python3 novaencryptor.py
```

**❌ Virtual environment activation issues**
```bash
# Recreate virtual environment
rm -rf novaenv
python3 -m venv novaenv
source novaenv/bin/activate  # or novaenv\Scripts\activate on Windows
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **🍴 Fork the repository**
2. **🌱 Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **💻 Make your changes**
4. **✅ Test thoroughly**
5. **📝 Commit your changes** (`git commit -m 'Add amazing feature'`)
6. **🚀 Push to the branch** (`git push origin feature/amazing-feature`)
7. **🔄 Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/NovaEncryptor--Secure-CLI.git

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate

# Install development dependencies
pip install pycryptodome pyfiglet pytest black flake8
```

---

## 📋 Roadmap

- [ ] 🌐 **Web GUI Interface**
- [ ] 📱 **Mobile app support**
- [ ] 🔐 **Quantum-resistant encryption**
- [ ] 📊 **Batch file processing**
- [ ] 🌩️ **Cloud key management**
- [ ] 🔌 **Plugin architecture**

---

## ⚠️ Security Considerations

- 🔒 **Store RSA keys securely** - losing the private key means permanent data loss
- 🔄 **Regular key rotation** recommended for production use
- 🛡️ **Consider RSA-4096** for long-term security requirements
- 📝 **Keep encrypted outputs safe** - they contain sensitive data
- 🚫 **Never share private keys** or store them in version control

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**ZeroHack01**
- 🐙 GitHub: [@ZeroHack01](https://github.com/ZeroHack01)
- 📧 Email: [Contact via GitHub](https://github.com/ZeroHack01)

---

## 🙏 Acknowledgments

- 🔐 **PyCryptodome** team for the excellent cryptography library
- 🎨 **PyFiglet** for ASCII art capabilities
- 🛡️ **Security community** for best practices and standards
- 🌟 **Contributors** who help improve this project

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

[![GitHub stars](https://img.shields.io/github/stars/ZeroHack01/NovaEncryptor--Secure-CLI?style=social)](https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ZeroHack01/NovaEncryptor--Secure-CLI?style=social)](https://github.com/ZeroHack01/NovaEncryptor--Secure-CLI/network)

---

**🔐 Secure your data with NovaEncryptor - Because your privacy matters**

</div>
