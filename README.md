# NovaEncryptor--Secure-CLI
NovaEncryptor

NovaEncryptor is a command-line encryption tool designed to provide secure encryption and decryption using a hybrid approach combining AES-256 (Advanced Encryption Standard) for message encryption and RSA-2048 for securely encrypting the AES keys. The tool uses AES-256 for strong encryption of messages and RSA to ensure secure key management.


Features
    AES-256 Encryption: Encrypts your messages with a 256-bit AES key, one of the most secure encryption algorithms available.
    RSA-2048 Key Pair: Secures the AES key using RSA-2048, providing secure key exchange.
    Hybrid Encryption: Combines the speed of AES for message encryption with the security of RSA for key exchange.
    Authenticated Encryption (AES-EAX Mode): Ensures both confidentiality and data integrity, protecting the encrypted message from tampering.
    Automatic Key Generation: If RSA keys are not found, NovaEncryptor automatically generates new RSA public and private keys for secure communication.

Requirements
Before running NovaEncryptor, ensure that you have installed the following dependencies:

    Python 3.7+
    pycryptodome library for cryptography (Crypto module)
    pyfiglet for ASCII art display

You can install the required packages by running:
bash

pip install pycryptodome pyfiglet

Installation

    Clone the Repository: First, clone this repository to your local machine.

    bash

git clone https://github.com/yourusername/novaencryptor.git

Navigate to the Project Directory: Go into the project folder:

bash

cd novaencryptor

Set Up a Python Virtual Environment (Optional but Recommended): It is highly recommended to use a virtual environment to manage dependencies.

bash

python3 -m venv novaenv
source novaenv/bin/activate  # On Windows use: novaenv\Scripts\activate

Install the Dependencies: Install all the required Python libraries within the virtual environment.

bash

    pip install pycryptodome pyfiglet

Usage

NovaEncryptor allows you to either encrypt a message or decrypt an encrypted message. Follow the steps below:
Encrypting a Message

To encrypt a message:

    Run the NovaEncryptor script:

    bash

python3 novaencryptor.py

Select encrypt when prompted:

css

Enter 'encrypt' to encrypt a message or 'decrypt' to decrypt a message: encrypt

Enter your message, and the tool will provide the encrypted message, AES key, nonce, and tag:

kotlin

Enter the message to encrypt: Hello, this is a secure message!

The encrypted message and key will be displayed:

php

    Encryption successful!
    Encrypted Message: <Base64-encoded ciphertext>
    Encrypted AES Key: <Base64-encoded AES key>
    Nonce: <Base64-encoded nonce>
    Tag: <Base64-encoded tag>

Decrypting a Message

To decrypt an encrypted message:

    Run the NovaEncryptor script:

    bash

python3 novaencryptor.py

Select decrypt when prompted:

css

Enter 'encrypt' to encrypt a message or 'decrypt' to decrypt a message: decrypt

Input the encrypted message, AES key, nonce, and tag as prompted:

mathematica

Enter the encrypted message: <Your Base64-encoded ciphertext>
Enter the encrypted AES key: <Your Base64-encoded AES key>
Enter the nonce: <Your Base64-encoded nonce>
Enter the tag: <Your Base64-encoded tag>

If the inputs are correct, the tool will successfully decrypt and display the original message:

kotlin

    Decryption successful!
    Decrypted Message: Hello, this is a secure message!

Files and Structure

    novaencryptor.py: The main script containing the encryption and decryption logic.
    rsa_private.pem: The RSA private key file (auto-generated if not found).
    rsa_public.pem: The RSA public key file (auto-generated if not found).

Security Details

    AES-256: NovaEncryptor uses a 256-bit key length for AES encryption, ensuring a strong level of security.
    RSA-2048: The tool uses RSA with a 2048-bit key length for encrypting the AES key, which is suitable for most modern security needs.
    EAX Mode: The AES encryption is performed in EAX mode, providing both encryption and authentication (message integrity).

Notes

    Ensure that your RSA private and public keys are securely stored, as losing the private key means you will be unable to decrypt any previously encrypted messages.
    For enhanced security, consider upgrading to RSA-4096 for long-term protection.

License

This project is open-source and available under the MIT License.
