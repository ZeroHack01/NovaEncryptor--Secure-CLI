import os
import base64
import pyfiglet  # For ASCII art
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class AESCipher:
    def __init__(self, key):
        self.key = key.ljust(32)[:32]  # Ensure key is 32 bytes
        self.cipher = AES.new(self.key, AES.MODE_EAX)  # Use the key directly

    def encrypt(self, plaintext):
        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return self.cipher.nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')


def generate_rsa_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    
    with open("rsa_private.pem", "wb") as private_file:
        private_file.write(private_key.export_key())
    with open("rsa_public.pem", "wb") as public_file:
        public_file.write(public_key.export_key())


def load_rsa_keys():
    with open("rsa_private.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
    with open("rsa_public.pem", "rb") as public_file:
        public_key = RSA.import_key(public_file.read())
    return private_key, public_key


def encrypt_message(message, rsa_public_key):
    aes_key = get_random_bytes(32)  # Generate a random AES key
    aes_cipher = AESCipher(aes_key)  # Pass aes_key directly

    nonce, ciphertext, tag = aes_cipher.encrypt(message)
    
    # Use PKCS1_OAEP for RSA encryption
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = base64.b64encode(cipher_rsa.encrypt(aes_key)).decode('utf-8')

    return base64.b64encode(ciphertext).decode('utf-8'), encrypted_aes_key, nonce, tag


def decrypt_message(encrypted_message, encrypted_aes_key, rsa_private_key, nonce, tag):
    # Use PKCS1_OAEP for RSA decryption
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    
    aes_cipher = AESCipher(aes_key)
    
    decrypted_message = aes_cipher.decrypt(nonce, base64.b64decode(encrypted_message), tag)
    return decrypted_message


def novaencryptor():
    # ASCII art for NovaEncryptor using pyfiglet
    ascii_banner = pyfiglet.figlet_format("NovaEncryptor")
    print(ascii_banner)

    action = input("Enter 'encrypt' to encrypt a message or 'decrypt' to decrypt a message: ").strip().lower()

    if action == 'encrypt':
        message = input("Enter the message to encrypt: ").strip()
        encrypted_message, encrypted_aes_key, nonce, tag = encrypt_message(message, rsa_public_key)
        print("\nEncryption successful!")
        print(f"Encrypted Message: {encrypted_message}")
        print(f"Encrypted AES Key: {encrypted_aes_key}")
        print(f"Nonce: {base64.b64encode(nonce).decode('utf-8')}")
        print(f"Tag: {base64.b64encode(tag).decode('utf-8')}")

    elif action == 'decrypt':
        try:
            encrypted_message = input("Enter the encrypted message: ").strip()
            encrypted_aes_key = input("Enter the encrypted AES key: ").strip()
            nonce = base64.b64decode(input("Enter the nonce: ").strip())
            tag = base64.b64decode(input("Enter the tag: ").strip())
            
            decrypted_message = decrypt_message(encrypted_message, encrypted_aes_key, rsa_private_key, nonce, tag)
            print("\nDecryption successful!")
            print(f"Decrypted Message: {decrypted_message}")
        except (ValueError, KeyError) as e:
            print(f"Decryption failed: {str(e)}")

    else:
        print("Invalid action. Please enter 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    # Check if RSA keys exist, otherwise generate them
    if not (os.path.exists("rsa_private.pem") and os.path.exists("rsa_public.pem")):
        print("RSA keys not found. Generating new keys...")
        generate_rsa_keys()
    
    # Load the RSA keys
    rsa_private_key, rsa_public_key = load_rsa_keys()
    
    # Start NovaEncryptor
    novaencryptor()
