#!/usr/bin/env python3
"""
Test suite for NovaEncryptor v2.0
Run with: python -m pytest tests/test_nova_encryptor.py -v
"""

import unittest
import tempfile
import json
import secrets
from pathlib import Path
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from nova_encryptor import (
        SecureMemory, ConfigManager, AuditLogger, CryptoEngine
    )
except ImportError as e:
    print(f"❌ Cannot import nova_encryptor: {e}")
    print("Make sure you're in the project root directory and have installed dependencies")
    sys.exit(1)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory operations"""
    
    def test_secure_memory_context(self):
        """Test secure memory context manager"""
        test_data = b"sensitive_data_123"
        
        with SecureMemory(test_data) as secure_data:
            # Data should be accessible
            self.assertEqual(bytes(secure_data), test_data)
        
        # After context, data should be zeroed
        # (secure_data is deleted, so we can't test directly)
        # This test ensures no exceptions are raised


class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = ConfigManager()
        # Override config path for testing
        self.config.config_dir = Path(self.temp_dir.name)
        self.config.config_file = self.config.config_dir / 'config.json'
    
    def tearDown(self):
        self.temp_dir.cleanup()
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ConfigManager()
        
        self.assertEqual(config.config['rsa_key_size'], 4096)
        self.assertEqual(config.config['aes_key_size'], 32)
        self.assertTrue(config.config['audit_enabled'])
    
    def test_save_load_config(self):
        """Test saving and loading configuration"""
        # Modify config
        self.config.config['rsa_key_size'] = 2048
        self.config.save_config()
        
        # Load new instance
        new_config = ConfigManager()
        new_config.config_dir = self.config.config_dir
        new_config.config_file = self.config.config_file
        loaded_config = new_config.load_config()
        
        self.assertEqual(loaded_config['rsa_key_size'], 2048)


class TestAuditLogger(unittest.TestCase):
    """Test audit logging functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        # Disabled audit for most tests to avoid file creation
        self.audit = AuditLogger(enabled=False)
    
    def tearDown(self):
        self.temp_dir.cleanup()
    
    def test_audit_logging_disabled(self):
        """Test audit logging when disabled"""
        # Should not raise exceptions when disabled
        self.audit.log("TEST_EVENT", "Test details", True)
        self.audit.log("TEST_EVENT", "Test details", False)
    
    def test_audit_logging_enabled(self):
        """Test audit logging when enabled"""
        # This would create actual log files, so we keep it simple
        audit = AuditLogger(enabled=True)
        
        # Should not raise exceptions
        audit.log("TEST_EVENT", "Test details", True)


class TestCryptoEngine(unittest.TestCase):
    """Test cryptographic operations"""
    
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create test config and audit
        self.config = ConfigManager()
        self.config.config_dir = Path(self.temp_dir.name)
        
        self.audit = AuditLogger(enabled=False)
        
        # Create crypto engine with test directory
        self.crypto = CryptoEngine(self.config, self.audit)
        self.crypto.keys_dir = Path(self.temp_dir.name) / 'keys'
        self.crypto.keys_dir.mkdir(parents=True, exist_ok=True)
    
    def tearDown(self):
        self.temp_dir.cleanup()
    
    def test_keypair_generation(self):
        """Test RSA keypair generation"""
        private_key, public_key = self.crypto.generate_keypair()
        
        # Check basic properties
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertIn(b'BEGIN PRIVATE KEY', private_key)
        self.assertIn(b'BEGIN PUBLIC KEY', public_key)
        self.assertGreater(len(private_key), 1000)  # RSA-4096 should be large
        self.assertGreater(len(public_key), 500)
    
    def test_keypair_save_load_unencrypted(self):
        """Test saving and loading unencrypted keypair"""
        private_key, public_key = self.crypto.generate_keypair()
        
        # Save without password
        success = self.crypto.save_keypair(private_key, public_key, None)
        self.assertTrue(success)
        
        # Load keys
        loaded_private = self.crypto.load_private_key()
        loaded_public = self.crypto.load_public_key()
        
        self.assertEqual(private_key, loaded_private)
        self.assertEqual(public_key, loaded_public)
    
    def test_keypair_save_load_encrypted(self):
        """Test saving and loading password-encrypted keypair"""
        private_key, public_key = self.crypto.generate_keypair()
        password = "test_password_123!"
        
        # Save with password
        success = self.crypto.save_keypair(private_key, public_key, password)
        self.assertTrue(success)
        
        # Load keys with password
        loaded_private = self.crypto.load_private_key(password=password)
        loaded_public = self.crypto.load_public_key()
        
        self.assertEqual(private_key, loaded_private)
        self.assertEqual(public_key, loaded_public)
    
    def test_encryption_decryption_cycle(self):
        """Test complete encryption/decryption cycle"""
        # Generate keypair
        private_key, public_key = self.crypto.generate_keypair()
        
        # Test message
        original_message = "This is a secret message! 🔐🛡️"
        
        # Encrypt message
        encrypted_data = self.crypto.encrypt_message(original_message, public_key)
        
        # Verify encrypted data structure
        required_fields = ['ciphertext', 'encrypted_key', 'nonce', 'algorithm', 'timestamp']
        for field in required_fields:
            self.assertIn(field, encrypted_data)
        
        self.assertEqual(encrypted_data['algorithm'], 'AES-256-GCM + RSA-4096')
        
        # Decrypt message
        decrypted_message = self.crypto.decrypt_message(encrypted_data, private_key)
        
        # Verify decryption
        self.assertEqual(original_message, decrypted_message)
    
    def test_encryption_with_unicode(self):
        """Test encryption with unicode characters"""
        private_key, public_key = self.crypto.generate_keypair()
        
        # Unicode test message
        original_message = "Hello 世界! 🌍 Здравствуй мир! مرحبا بالعالم!"
        
        # Encrypt and decrypt
        encrypted_data = self.crypto.encrypt_message(original_message, public_key)
        decrypted_message = self.crypto.decrypt_message(encrypted_data, private_key)
        
        self.assertEqual(original_message, decrypted_message)
    
    def test_encryption_large_message(self):
        """Test encryption with large message"""
        private_key, public_key = self.crypto.generate_keypair()
        
        # Large message (10KB)
        original_message = "A" * 10240
        
        # Encrypt and decrypt
        encrypted_data = self.crypto.encrypt_message(original_message, public_key)
        decrypted_message = self.crypto.decrypt_message(encrypted_data, private_key)
        
        self.assertEqual(original_message, decrypted_message)
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails to decrypt"""
        private_key, public_key = self.crypto.generate_keypair()
        password = "correct_password"
        wrong_password = "wrong_password"
        
        # Save with password
        self.crypto.save_keypair(private_key, public_key, password)
        
        # Try to load with wrong password
        with self.assertRaises(Exception):
            self.crypto.load_private_key(password=wrong_password)
    
    def test_corrupted_ciphertext_fails(self):
        """Test that corrupted ciphertext fails to decrypt"""
        private_key, public_key = self.crypto.generate_keypair()
        message = "Test message"
        
        # Encrypt message
        encrypted_data = self.crypto.encrypt_message(message, public_key)
        
        # Corrupt the ciphertext
        encrypted_data['ciphertext'] = encrypted_data['ciphertext'][:-10] + "corrupted=="
        
        # Decryption should fail
        with self.assertRaises(Exception):
            self.crypto.decrypt_message(encrypted_data, private_key)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Set up complete system
        self.config = ConfigManager()
        self.config.config_dir = Path(self.temp_dir.name)
        
        self.audit = AuditLogger(enabled=False)
        self.crypto = CryptoEngine(self.config, self.audit)
        self.crypto.keys_dir = Path(self.temp_dir.name) / 'keys'
        self.crypto.keys_dir.mkdir(parents=True, exist_ok=True)
    
    def tearDown(self):
        self.temp_dir.cleanup()
    
    def test_full_workflow_unencrypted_keys(self):
        """Test complete workflow with unencrypted keys"""
        # 1. Generate keypair
        private_key, public_key = self.crypto.generate_keypair()
        self.crypto.save_keypair(private_key, public_key, None)
        
        # 2. Encrypt message
        message = "Integration test message"
        public_key_loaded = self.crypto.load_public_key()
        encrypted_data = self.crypto.encrypt_message(message, public_key_loaded)
        
        # 3. Save encrypted data to file
        encrypted_file = Path(self.temp_dir.name) / 'encrypted.json'
        with open(encrypted_file, 'w') as f:
            json.dump(encrypted_data, f)
        
        # 4. Load encrypted data from file
        with open(encrypted_file, 'r') as f:
            loaded_encrypted_data = json.load(f)
        
        # 5. Decrypt message
        private_key_loaded = self.crypto.load_private_key()
        decrypted_message = self.crypto.decrypt_message(loaded_encrypted_data, private_key_loaded)
        
        # 6. Verify result
        self.assertEqual(message, decrypted_message)
    
    def test_full_workflow_encrypted_keys(self):
        """Test complete workflow with password-encrypted keys"""
        password = "integration_test_password_123!"
        
        # 1. Generate and save password-protected keypair
        private_key, public_key = self.crypto.generate_keypair()
        self.crypto.save_keypair(private_key, public_key, password)
        
        # 2. Encrypt message
        message = "Integration test with encrypted keys"
        public_key_loaded = self.crypto.load_public_key()
        encrypted_data = self.crypto.encrypt_message(message, public_key_loaded)
        
        # 3. Decrypt message (requires password)
        private_key_loaded = self.crypto.load_private_key(password=password)
        decrypted_message = self.crypto.decrypt_message(encrypted_data, private_key_loaded)
        
        # 4. Verify result
        self.assertEqual(message, decrypted_message)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)