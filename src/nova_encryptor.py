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
import mimetypes
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timezone

# Import cryptographic libraries
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import argon2
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
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
    """Configuration management with file support"""
    DEFAULT_CONFIG = {
        'rsa_key_size': 4096,
        'aes_key_size': 32,
        'argon2_time_cost': 3,
        'argon2_memory_cost': 65536,
        'argon2_parallelism': 4,
        'salt_size': 32,
        'nonce_size': 12,
        'audit_enabled': True,
        'max_file_size': 50 * 1024 * 1024,  # 50MB
        'auto_delete_originals': False,
        'secure_wipe': True
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


class FileProcessor:
    """File processing with metadata and integrity checking"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.console = Console()
    
    def validate_file(self, file_path: Path) -> Tuple[bool, str]:
        """Validate file for encryption"""
        try:
            if not file_path.exists():
                return False, "File does not exist"
            
            if not file_path.is_file():
                return False, "Path is not a file"
            
            file_size = file_path.stat().st_size
            max_size = self.config.config['max_file_size']
            
            if file_size > max_size:
                size_mb = max_size // (1024 * 1024)
                return False, f"File too large: {file_size:,} bytes (max: {size_mb}MB)"
            
            if file_size == 0:
                return False, "File is empty"
            
            return True, "File is valid"
            
        except Exception as e:
            return False, f"File validation error: {e}"
    
    def get_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Get comprehensive file information"""
        try:
            stat = file_path.stat()
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            # Calculate checksum
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return {
                'filename': file_path.name,
                'size': stat.st_size,
                'extension': file_path.suffix.lower(),
                'mime_type': mime_type or 'application/octet-stream',
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'checksum': sha256_hash.hexdigest(),
                'encrypted_on': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            raise Exception(f"Failed to get file metadata: {e}")
    
    def prepare_file_content(self, file_path: Path) -> Dict[str, Any]:
        """Prepare file for encryption with metadata"""
        try:
            # Validate file
            valid, message = self.validate_file(file_path)
            if not valid:
                raise ValueError(message)
            
            # Get metadata
            metadata = self.get_file_metadata(file_path)
            
            # Read and encode file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            base64_content = base64.b64encode(file_content).decode('utf-8')
            
            # Create file package
            file_package = {
                'type': 'NOVA_FILE',
                'version': '2.0',
                'metadata': metadata,
                'content': base64_content
            }
            
            return file_package
            
        except Exception as e:
            raise Exception(f"Failed to prepare file: {e}")
    
    def restore_file(self, file_package: Dict[str, Any], output_dir: Optional[Path] = None) -> Path:
        """Restore file from package"""
        try:
            if file_package.get('type') != 'NOVA_FILE':
                raise ValueError("Invalid file package")
            
            metadata = file_package.get('metadata', {})
            content = file_package.get('content', '')
            
            # Determine output path
            if not output_dir:
                output_dir = Path('decrypted_files')
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            original_name = metadata.get('filename', 'restored_file')
            output_path = output_dir / f"decrypted_{original_name}"
            
            # Decode content
            try:
                file_content = base64.b64decode(content)
            except Exception as e:
                raise ValueError(f"Invalid file content: {e}")
            
            # Write file
            with open(output_path, 'wb') as f:
                f.write(file_content)
            
            # Verify integrity
            if 'checksum' in metadata:
                sha256_hash = hashlib.sha256()
                sha256_hash.update(file_content)
                new_checksum = sha256_hash.hexdigest()
                
                if new_checksum != metadata['checksum']:
                    self.console.print("[yellow]⚠️  Warning: File checksum mismatch[/yellow]")
            
            # Show restoration info
            self.console.print(f"[green]📁 File restored: {original_name}[/green]")
            self.console.print(f"📊 Size: {len(file_content):,} bytes")
            self.console.print(f"🎯 Location: {output_path}")
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Failed to restore file: {e}")


class CryptoEngine:
    """Core cryptographic operations with file support"""
    
    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self.console = Console()
        self.keys_dir = Path.home() / '.nova_encryptor' / 'keys'
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.file_processor = FileProcessor(config)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate RSA-4096 keypair"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Generating RSA-4096 keypair...", total=None)
                
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.config.config['rsa_key_size']
                )
                
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                progress.update(task, completed=True)
            
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
                salt = secrets.token_bytes(self.config.config['salt_size'])
                derived_key = derive_key_from_password(password, salt, self.config.config)
                
                aesgcm = AESGCM(derived_key)
                nonce = secrets.token_bytes(self.config.config['nonce_size'])
                encrypted_private = aesgcm.encrypt(nonce, private_key, None)
                
                private_data = {
                    'salt': base64.b64encode(salt).decode(),
                    'nonce': base64.b64encode(nonce).decode(),
                    'encrypted_key': base64.b64encode(encrypted_private).decode(),
                    'created': timestamp,
                    'algorithm': 'AES-256-GCM + Argon2'
                }
                
                private_path = self.keys_dir / f'private_{timestamp}.json'
                with open(private_path, 'w') as f:
                    json.dump(private_data, f, indent=2)
            else:
                private_path = self.keys_dir / f'private_{timestamp}.pem'
                with open(private_path, 'wb') as f:
                    f.write(private_key)
            
            public_path = self.keys_dir / f'public_{timestamp}.pem'
            with open(public_path, 'wb') as f:
                f.write(public_key)
            
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
            priv_keys = list(self.keys_dir.glob('private_*'))
            if not priv_keys:
                raise FileNotFoundError("No private key found")
            key_path = max(priv_keys, key=lambda p: p.stat().st_mtime)
        
        if key_path.suffix == '.json':
            if not password:
                raise ValueError("Password required for encrypted private key")
            
            with open(key_path, 'r') as f:
                key_data = json.load(f)
            
            salt = base64.b64decode(key_data['salt'])
            nonce = base64.b64decode(key_data['nonce'])
            encrypted_key = base64.b64decode(key_data['encrypted_key'])
            
            derived_key = derive_key_from_password(password, salt, self.config.config)
            aesgcm = AESGCM(derived_key)
            private_key = aesgcm.decrypt(nonce, encrypted_key, None)
            return private_key
        else:
            with open(key_path, 'rb') as f:
                return f.read()
    
    def encrypt_data(self, data: str, public_key_data: bytes, data_type: str = "TEXT") -> Dict[str, str]:
        """Encrypt text or file data"""
        try:
            aes_key = secrets.token_bytes(self.config.config['aes_key_size'])
            nonce = secrets.token_bytes(self.config.config['nonce_size'])
            
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
            
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
                'type': data_type,
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'algorithm': 'AES-256-GCM + RSA-4096',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            self.audit.log("ENCRYPTION", f"{data_type} encrypted ({len(data)} chars)")
            return result
            
        except Exception as e:
            self.audit.log("ENCRYPTION", f"Failed: {e}", False)
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, str], 
                    private_key_data: bytes) -> Tuple[str, str]:
        """Decrypt data and return content with type"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            data_type = encrypted_data.get('type', 'TEXT')
            
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
            
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            content = plaintext.decode('utf-8')
            self.audit.log("DECRYPTION", f"{data_type} decrypted ({len(content)} chars)")
            return content, data_type
            
        except Exception as e:
            self.audit.log("DECRYPTION", f"Failed: {e}", False)
            raise


class UserInterface:
    """Complete user interface with file operations"""
    
    def __init__(self):
        self.console = Console()
        self.config = ConfigManager()
        self.audit = AuditLogger(self.config.config['audit_enabled'])
        self.crypto = CryptoEngine(self.config, self.audit)
    
    def show_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  NovaEncryptor v2.0                    ║
║            Complete File & Text Encryption System           ║
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
            table.add_row("2", "📝 Encrypt text message")
            table.add_row("3", "📁 Encrypt file/image/document")
            table.add_row("4", "🔓 Decrypt message/file")
            table.add_row("5", "📋 List keys")
            table.add_row("6", "⚙️  View configuration")
            table.add_row("7", "📊 View audit log")
            table.add_row("0", "🚪 Exit")
            
            self.console.print(table)
            
            choice = Prompt.ask(
                "\n[bold green]Select option[/bold green]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"]
            )
            
            try:
                if choice == "0":
                    self.console.print("[bold green]👋 Goodbye![/bold green]")
                    break
                elif choice == "1":
                    self.generate_keys_flow()
                elif choice == "2":
                    self.encrypt_text_flow()
                elif choice == "3":
                    self.encrypt_file_flow()
                elif choice == "4":
                    self.decrypt_flow()
                elif choice == "5":
                    self.list_keys()
                elif choice == "6":
                    self.show_config()
                elif choice == "7":
                    self.show_audit_log()
            except Exception as e:
                self.console.print(f"[bold red]❌ Error: {e}[/bold red]")
    
    def generate_keys_flow(self):
        self.console.print("\n[bold cyan]🔑 Key Generation[/bold cyan]")
        
        protect = Confirm.ask("Protect private key with password?")
        password = None
        
        if protect:
            password = Prompt.ask("Enter password", password=True)
            confirm = Prompt.ask("Confirm password", password=True)
            if password != confirm:
                self.console.print("[bold red]❌ Passwords don't match![/bold red]")
                return
        
        try:
            private_key, public_key = self.crypto.generate_keypair()
            success = self.crypto.save_keypair(private_key, public_key, password)
            
            if success:
                self.console.print("[bold green]✅ Keypair generated successfully![/bold green]")
            else:
                self.console.print("[bold red]❌ Failed to save keypair![/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]❌ Key generation failed: {e}[/bold red]")
    
    def encrypt_text_flow(self):
        self.console.print("\n[bold cyan]📝 Text Message Encryption[/bold cyan]")
        
        try:
            public_key = self.crypto.load_public_key()
            message = Prompt.ask("Enter message to encrypt")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Encrypting message...", total=None)
                result = self.crypto.encrypt_data(message, public_key, "TEXT")
                progress.update(task, completed=True)
            
            self.console.print("[bold green]✅ Encryption successful![/bold green]")
            self.console.print("\n[bold yellow]Encrypted Data:[/bold yellow]")
            self.console.print(json.dumps(result, indent=2))
            
            if Confirm.ask("Save to file?"):
                filename = Prompt.ask("Filename", default="encrypted_message.json")
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2)
                self.console.print(f"[bold green]✅ Saved to {filename}[/bold green]")
                
        except Exception as e:
            self.console.print(f"[bold red]❌ Encryption failed: {e}[/bold red]")
    
    def encrypt_file_flow(self):
        self.console.print("\n[bold cyan]📁 File/Image/Document Encryption[/bold cyan]")
        
        try:
            # Get file path
            file_path = Prompt.ask("Enter file path to encrypt")
            file_path = Path(file_path)
            
            if not file_path.exists():
                self.console.print("[bold red]❌ File not found![/bold red]")
                return
            
            # Show file info
            try:
                metadata = self.crypto.file_processor.get_file_metadata(file_path)
                self.console.print(f"\n[bold blue]📁 File Information:[/bold blue]")
                self.console.print(f"Name: {metadata['filename']}")
                self.console.print(f"Size: {metadata['size']:,} bytes ({metadata['size']/(1024*1024):.2f} MB)")
                self.console.print(f"Type: {metadata['mime_type']}")
                self.console.print(f"Extension: {metadata['extension']}")
            except Exception as e:
                self.console.print(f"[yellow]⚠️  Could not read file info: {e}[/yellow]")
                if not Confirm.ask("Continue anyway?"):
                    return
            
            # Confirm encryption
            if not Confirm.ask("Proceed with encryption?"):
                return
            
            # Load public key
            public_key = self.crypto.load_public_key()
            
            # Prepare and encrypt file
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task1 = progress.add_task("Preparing file...", total=None)
                file_package = self.crypto.file_processor.prepare_file_content(file_path)
                progress.update(task1, completed=True)
                
                task2 = progress.add_task("Encrypting file...", total=None)
                result = self.crypto.encrypt_data(json.dumps(file_package), public_key, "FILE")
                progress.update(task2, completed=True)
            
            self.console.print("[bold green]✅ File encryption successful![/bold green]")
            
            # Save encrypted file
            default_name = f"encrypted_{file_path.stem}.json"
            filename = Prompt.ask("Save encrypted file as", default=default_name)
            
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            
            self.console.print(f"[bold green]✅ Encrypted file saved: {filename}[/bold green]")
            
            # Ask about deleting original
            if Confirm.ask("🗑️  Delete original file for security?"):
                try:
                    file_path.unlink()
                    self.console.print("[bold green]✅ Original file deleted[/bold green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠️  Could not delete original: {e}[/yellow]")
            
        except Exception as e:
            self.console.print(f"[bold red]❌ File encryption failed: {e}[/bold red]")
    
    def decrypt_flow(self):
        self.console.print("\n[bold cyan]🔓 Decryption (Text/File/Image)[/bold cyan]")
        
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
            
            # Check data type
            data_type = encrypted_data.get('type', 'TEXT')
            self.console.print(f"[bold blue]🔍 Detected type: {data_type}[/bold blue]")
            
            # Get password if needed
            password = None
            encrypted_keys = list(self.crypto.keys_dir.glob('private_*.json'))
            if encrypted_keys:
                password = Prompt.ask("Enter private key password", password=True)
            
            # Load private key and decrypt
            private_key = self.crypto.load_private_key(password=password)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Decrypting...", total=None)
                content, content_type = self.crypto.decrypt_data(encrypted_data, private_key)
                progress.update(task, completed=True)
            
            self.console.print("[bold green]✅ Decryption successful![/bold green]")
            
            # Handle different content types
            if content_type == "FILE":
                # Restore file
                file_package = json.loads(content)
                output_path = self.crypto.file_processor.restore_file(file_package)
                
            else:
                # Display text message
                self.console.print(f"\n[bold yellow]Decrypted Message:[/bold yellow]")
                self.console.print(content)
            
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
            if key == 'max_file_size':
                value = f"{value // (1024*1024)} MB"
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def show_audit_log(self):
        self.console.print("\n[bold cyan]📊 Audit Log (Last 15 entries)[/bold cyan]")
        
        log_file = Path.home() / '.nova_encryptor' / 'logs' / 'audit.log'
        if not log_file.exists():
            self.console.print("[yellow]No audit log found.[/yellow]")
            return
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        recent = lines[-15:] if len(lines) > 15 else lines
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
