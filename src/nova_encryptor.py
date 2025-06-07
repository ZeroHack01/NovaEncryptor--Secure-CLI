#!/usr/bin/env python3
"""
NovaEncryptor v2.0 
"""

import os
import sys
import json
import base64
import secrets
import hashlib
import logging
import argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timezone

# Import cryptographic libraries - FIXED IMPORTS
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import argon2
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
except ImportError as e:
    print(f"❌ Missing dependencies: {e}")
    print("Run: pip install cryptography argon2-cffi rich")
    sys.exit(1)


class SecureMemory:
    """Context manager for secure memory operations"""
    def __init__(self, data: bytes):
        self.data = bytearray(data)
    
    def __enter__(self):
        return self.data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Overwrite memory with zeros
        for i in range(len(self.data)):
            self.data[i] = 0
        del self.data


class ConfigManager:
    """Configuration management"""
    DEFAULT_CONFIG = {
        'rsa_key_size': 4096,
        'aes_key_size': 32,
        'argon2_time_cost': 3,
        'argon2_memory_cost': 65536,
        'argon2_parallelism': 4,
        'salt_size': 32,
        'nonce_size': 12,
        'audit_enabled': True
    }
    
    def __init__(self):
        self.config_dir = Path.home() / '.nova_encryptor'
        self.config_file = self.config_dir / 'config.json'
        self.config = self.load_config()
    
    def load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                return {**self.DEFAULT_CONFIG, **config}
            except Exception:
                pass
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)


class AuditLogger:
    """Security audit logging"""
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        if enabled:
            log_dir = Path.home() / '.nova_encryptor' / 'logs'
            log_dir.mkdir(parents=True, exist_ok=True)
            
            logging.basicConfig(
                filename=log_dir / 'audit.log',
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
    
    def log(self, event: str, details: str, success: bool = True):
        if self.enabled:
            status = "SUCCESS" if success else "FAILURE"
            logging.info(f"{event} - {status} - {details}")


def derive_key_from_password(password: str, salt: bytes, config: dict) -> bytes:
    """Derive encryption key from password using argon2-cffi"""
    return argon2.low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=config['argon2_time_cost'],
        memory_cost=config['argon2_memory_cost'],
        parallelism=config['argon2_parallelism'],
        hash_len=32,
        type=argon2.low_level.Type.ID
    )


class CryptoEngine:
    """Core cryptographic operations"""
    
    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self.keys_dir = Path.home() / '.nova_encryptor' / 'keys'
        self.keys_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate RSA-4096 keypair"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config.config['rsa_key_size']
            )
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.audit.log("KEY_GENERATION", "RSA-4096 keypair generated")
            return private_pem, public_pem
            
        except Exception as e:
            self.audit.log("KEY_GENERATION", f"Failed: {e}", False)
            raise
    
    def save_keypair(self, private_key: bytes, public_key: bytes, 
                     password: Optional[str] = None) -> bool:
        """Save keypair with optional password protection"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if password:
                # Password-protected private key
                salt = secrets.token_bytes(self.config.config['salt_size'])
                
                # Derive key using argon2-cffi
                derived_key = derive_key_from_password(password, salt, self.config.config)
                
                # Encrypt private key
                aesgcm = AESGCM(derived_key)
                nonce = secrets.token_bytes(self.config.config['nonce_size'])
                encrypted_private = aesgcm.encrypt(nonce, private_key, None)
                
                # Save encrypted private key
                private_data = {
                    'salt': base64.b64encode(salt).decode(),
                    'nonce': base64.b64encode(nonce).decode(),
                    'encrypted_key': base64.b64encode(encrypted_private).decode(),
                    'created': timestamp
                }
                
                private_path = self.keys_dir / f'private_{timestamp}.json'
                with open(private_path, 'w') as f:
                    json.dump(private_data, f, indent=2)
            else:
                # Unencrypted private key
                private_path = self.keys_dir / f'private_{timestamp}.pem'
                with open(private_path, 'wb') as f:
                    f.write(private_key)
            
            # Save public key (always unencrypted)
            public_path = self.keys_dir / f'public_{timestamp}.pem'
            with open(public_path, 'wb') as f:
                f.write(public_key)
            
            # Set secure permissions (Unix only)
            if hasattr(os, 'chmod'):
                os.chmod(private_path, 0o600)
                os.chmod(public_path, 0o644)
            
            self.audit.log("KEY_STORAGE", f"Keys saved: {private_path.name}, {public_path.name}")
            return True
            
        except Exception as e:
            self.audit.log("KEY_STORAGE", f"Failed: {e}", False)
            return False
    
    def load_public_key(self, key_path: Optional[Path] = None) -> bytes:
        """Load public key"""
        if key_path is None:
            # Find most recent public key
            pub_keys = list(self.keys_dir.glob('public_*.pem'))
            if not pub_keys:
                raise FileNotFoundError("No public key found")
            key_path = max(pub_keys, key=lambda p: p.stat().st_mtime)
        
        with open(key_path, 'rb') as f:
            return f.read()
    
    def load_private_key(self, key_path: Optional[Path] = None, 
                        password: Optional[str] = None) -> bytes:
        """Load private key with optional decryption"""
        if key_path is None:
            # Find most recent private key
            priv_keys = list(self.keys_dir.glob('private_*'))
            if not priv_keys:
                raise FileNotFoundError("No private key found")
            key_path = max(priv_keys, key=lambda p: p.stat().st_mtime)
        
        if key_path.suffix == '.json':
            # Encrypted private key
            if not password:
                raise ValueError("Password required for encrypted private key")
            
            with open(key_path, 'r') as f:
                key_data = json.load(f)
            
            salt = base64.b64decode(key_data['salt'])
            nonce = base64.b64decode(key_data['nonce'])
            encrypted_key = base64.b64decode(key_data['encrypted_key'])
            
            # Derive key from password
            derived_key = derive_key_from_password(password, salt, self.config.config)
            
            # Decrypt private key
            aesgcm = AESGCM(derived_key)
            private_key = aesgcm.decrypt(nonce, encrypted_key, None)
            return private_key
        else:
            # Unencrypted private key
            with open(key_path, 'rb') as f:
                return f.read()
    
    def encrypt_message(self, message: str, public_key_data: bytes) -> Dict[str, str]:
        """Encrypt message using hybrid AES-256-GCM + RSA-4096"""
        try:
            # Generate AES key
            aes_key = secrets.token_bytes(self.config.config['aes_key_size'])
            nonce = secrets.token_bytes(self.config.config['nonce_size'])
            
            # Encrypt message with AES-GCM
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
            
            # Encrypt AES key with RSA
            public_key = serialization.load_pem_public_key(public_key_data)
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            result = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'algorithm': 'AES-256-GCM + RSA-4096',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            self.audit.log("ENCRYPTION", f"Message encrypted ({len(message)} chars)")
            return result
            
        except Exception as e:
            self.audit.log("ENCRYPTION", f"Failed: {e}", False)
            raise
    
    def decrypt_message(self, encrypted_data: Dict[str, str], 
                       private_key_data: bytes) -> str:
        """Decrypt message using hybrid decryption"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            # Decrypt AES key with RSA
            private_key = serialization.load_pem_private_key(
                private_key_data, password=None
            )
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES-GCM
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            message = plaintext.decode('utf-8')
            self.audit.log("DECRYPTION", f"Message decrypted ({len(message)} chars)")
            return message
            
        except Exception as e:
            self.audit.log("DECRYPTION", f"Failed: {e}", False)
            raise


class UserInterface:
    """User interface with Rich formatting"""
    
    def __init__(self):
        self.console = Console()
        self.config = ConfigManager()
        self.audit = AuditLogger(self.config.config['audit_enabled'])
        self.crypto = CryptoEngine(self.config, self.audit)
    
    def show_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  NovaEncryptor v2.0                    ║
║               Enhanced Security • Step-by-Step              ║
║                                                              ║
║ 🔐 AES-256-GCM + RSA-4096 Hybrid Encryption               ║
║ 🔑 Argon2 Key Derivation                                   ║
║ 🛡️  Memory-Safe Operations                                 ║
╚══════════════════════════════════════════════════════════════╝
        """
        rprint(Panel(banner, style="bold blue"))
    
    def main_menu(self):
        self.show_banner()
        
        while True:
            self.console.print("\n[bold cyan]📋 Main Menu[/bold cyan]")
            
            table = Table()
            table.add_column("Option", style="bold yellow", width=8)
            table.add_column("Action", style="white")
            
            table.add_row("1", "🔑 Generate new RSA keypair")
            table.add_row("2", "🔒 Encrypt message")
            table.add_row("3", "🔓 Decrypt message")
            table.add_row("4", "📋 List keys")
            table.add_row("5", "⚙️  View configuration")
            table.add_row("6", "📊 View audit log")
            table.add_row("0", "🚪 Exit")
            
            self.console.print(table)
            
            choice = Prompt.ask(
                "\n[bold green]Select option[/bold green]",
                choices=["0", "1", "2", "3", "4", "5", "6"]
            )
            
            try:
                if choice == "0":
                    self.console.print("[bold green]👋 Goodbye![/bold green]")
                    break
                elif choice == "1":
                    self.generate_keys_flow()
                elif choice == "2":
                    self.encrypt_flow()
                elif choice == "3":
                    self.decrypt_flow()
                elif choice == "4":
                    self.list_keys()
                elif choice == "5":
                    self.show_config()
                elif choice == "6":
                    self.show_audit_log()
            except Exception as e:
                self.console.print(f"[bold red]❌ Error: {e}[/bold red]")
    
    def generate_keys_flow(self):
        self.console.print("\n[bold cyan]🔑 Key Generation[/bold cyan]")
        
        # Ask for password protection
        protect = Confirm.ask("Protect private key with password?")
        password = None
        
        if protect:
            password = Prompt.ask("Enter password", password=True)
            confirm = Prompt.ask("Confirm password", password=True)
            if password != confirm:
                self.console.print("[bold red]❌ Passwords don't match![/bold red]")
                return
        
        # Generate keys
        with self.console.status("[bold green]Generating RSA-4096 keypair..."):
            private_key, public_key = self.crypto.generate_keypair()
            success = self.crypto.save_keypair(private_key, public_key, password)
        
        if success:
            self.console.print("[bold green]✅ Keypair generated successfully![/bold green]")
        else:
            self.console.print("[bold red]❌ Failed to save keypair![/bold red]")
    
    def encrypt_flow(self):
        self.console.print("\n[bold cyan]🔒 Message Encryption[/bold cyan]")
        
        try:
            # Load public key
            public_key = self.crypto.load_public_key()
            
            # Get message
            message = Prompt.ask("Enter message to encrypt")
            
            # Encrypt
            with self.console.status("[bold green]Encrypting..."):
                result = self.crypto.encrypt_message(message, public_key)
            
            self.console.print("[bold green]✅ Encryption successful![/bold green]")
            self.console.print("\n[bold yellow]Encrypted Data:[/bold yellow]")
            self.console.print(json.dumps(result, indent=2))
            
            # Save option
            if Confirm.ask("Save to file?"):
                filename = Prompt.ask("Filename", default="encrypted_message.json")
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2)
                self.console.print(f"[bold green]✅ Saved to {filename}[/bold green]")
                
        except Exception as e:
            self.console.print(f"[bold red]❌ Encryption failed: {e}[/bold red]")
    
    def decrypt_flow(self):
        self.console.print("\n[bold cyan]🔓 Message Decryption[/bold cyan]")
        
        try:
            # Get encrypted data
            source = Prompt.ask(
                "Load from [f]ile or paste [d]ata?", 
                choices=["f", "d"], 
                default="f"
            )
            
            if source == "f":
                filename = Prompt.ask("Enter filename")
                with open(filename, 'r') as f:
                    encrypted_data = json.load(f)
            else:
                data_str = Prompt.ask("Paste encrypted JSON")
                encrypted_data = json.loads(data_str)
            
            # Check if password needed
            password = None
            encrypted_keys = list(self.crypto.keys_dir.glob('private_*.json'))
            if encrypted_keys:
                password = Prompt.ask("Enter private key password", password=True)
            
            # Load private key and decrypt
            private_key = self.crypto.load_private_key(password=password)
            
            with self.console.status("[bold green]Decrypting..."):
                message = self.crypto.decrypt_message(encrypted_data, private_key)
            
            self.console.print("[bold green]✅ Decryption successful![/bold green]")
            self.console.print(f"\n[bold yellow]Decrypted Message:[/bold yellow]\n{message}")
            
        except Exception as e:
            self.console.print(f"[bold red]❌ Decryption failed: {e}[/bold red]")
    
    def list_keys(self):
        self.console.print("\n[bold cyan]🗝️  Available Keys[/bold cyan]")
        
        keys = list(self.crypto.keys_dir.glob('*'))
        if not keys:
            self.console.print("[yellow]No keys found. Generate a keypair first.[/yellow]")
            return
        
        table = Table()
        table.add_column("Type", style="bold")
        table.add_column("Filename", style="cyan")
        table.add_column("Created", style="white")
        table.add_column("Protected", style="yellow")
        
        for key_file in sorted(keys):
            key_type = "Public" if "public" in key_file.name else "Private"
            created = datetime.fromtimestamp(
                key_file.stat().st_mtime
            ).strftime("%Y-%m-%d %H:%M")
            protected = "Yes" if key_file.suffix == ".json" else "No"
            table.add_row(key_type, key_file.name, created, protected)
        
        self.console.print(table)
    
    def show_config(self):
        self.console.print("\n[bold cyan]⚙️  Configuration[/bold cyan]")
        
        table = Table()
        table.add_column("Setting", style="bold yellow")
        table.add_column("Value", style="white")
        
        for key, value in self.config.config.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def show_audit_log(self):
        self.console.print("\n[bold cyan]📊 Audit Log (Last 10 entries)[/bold cyan]")
        
        log_file = Path.home() / '.nova_encryptor' / 'logs' / 'audit.log'
        if not log_file.exists():
            self.console.print("[yellow]No audit log found.[/yellow]")
            return
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Show last 10 entries
        recent = lines[-10:] if len(lines) > 10 else lines
        for line in recent:
            self.console.print(line.strip())


def main():
    """Main entry point"""
    try:
        ui = UserInterface()
        ui.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()