"""
Main CLI application for the secure cryptography system.
Provides interface for user authentication, data encryption, and digital signatures.
"""

import os
import base64
import sys
from pathlib import Path
from typing import Optional, Tuple
from crypto_utils import CryptoManager
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu(current_user: Optional[str] = None):
    """Print the main menu options."""
    print("\n" + "="*50)
    print("  Secure Cryptography System - Main Menu")
    print("="*50)
    if current_user:
        print(f"  👤 Logged in as: {current_user}")
        print("-"*50)
    else:
        print("  👤 Not logged in")
        print("-"*50)
    print("1. Sign Up (Register New User)")
    if current_user:
        print("2. Logout")
    else:
        print("2. Login")
    print("3. Modify Private Data")
    print("4. Sign Document/Message")
    print("5. Verify Signature")
    print("6. Verify Certificate")
    print("7. Sign User Certificate (CA Admin)")
    print("8. Encrypt Message (Asymmetric - BONUS)")
    print("9. Decrypt Message (Asymmetric - BONUS)")
    print("10. Modify Account (Change Password)")
    print("11. Exit")
    print("="*50)


def sign_up(crypto_manager: CryptoManager):
    """
    Register a new user with the system.
    - Collects username and password
    - Hashes password with salt
    - Generates RSA key pair
    - Creates CSR for certificate
    - Stores all user data securely
    """
    print("\n" + "-"*50)
    print("User Registration")
    print("-"*50)
    
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return
    
    # Check if user already exists
    existing_user = crypto_manager.load_user_data(username)
    if existing_user:
        print(f"Error: User '{username}' already exists.")
        return
    
    password = input("Enter password: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return
    
    try:
        # Hash password for authentication
        salt_auth, password_hash = crypto_manager.hash_password(password)
        
        # Derive encryption key for data protection
        salt_enc, encryption_key = crypto_manager.derive_key_from_password(password)
        
        # Generate RSA key pair (2048-bit)
        print("Generating RSA key pair...")
        private_key, public_key = crypto_manager.generate_key_pair(key_size=2048)
        
        # Save keys
        private_key_path = crypto_manager.keys_dir / f"{username}_private.pem"
        public_key_path = crypto_manager.keys_dir / f"{username}_public.pem"
        
        crypto_manager.save_private_key(private_key, private_key_path, password)
        crypto_manager.save_public_key(public_key, public_key_path)
        
        print("Keys generated and saved.")
        
        # Generate CSR
        print("Generating Certificate Signing Request (CSR)...")
        csr_pem = crypto_manager.generate_csr(private_key, username)
        csr_path = crypto_manager.certs_dir / f"{username}_csr.pem"
        with open(csr_path, 'wb') as f:
            f.write(csr_pem)
        
        print(f"CSR saved to {csr_path}")
        print("\nNote: You need to have your CSR signed by the CA to get a certificate.")
        print(f"Certificate file should be placed at: {crypto_manager.certs_dir}/{username}_cert.pem")
        
        # Store user metadata
        user_data = {
            "username": username,
            "password_salt": base64.b64encode(salt_auth).decode('utf-8'),
            "password_hash": base64.b64encode(password_hash).decode('utf-8'),
            "encryption_salt": base64.b64encode(salt_enc).decode('utf-8'),
            "private_key_path": str(private_key_path),
            "public_key_path": str(public_key_path),
            "csr_path": str(csr_path),
            "cert_path": str(crypto_manager.certs_dir / f"{username}_cert.pem"),
            "encrypted_data": None,
            "encrypted_nonce": None
        }
        
        crypto_manager.save_user_data(username, user_data)
        
        print(f"\n✓ User '{username}' registered successfully!")
        
    except Exception as e:
        print(f"Error during registration: {e}")
        import traceback
        traceback.print_exc()


def login(crypto_manager: CryptoManager) -> Optional[Tuple[str, str]]:
    """
    Authenticate a user with username and password.
    
    Returns:
        Tuple of (username, password) if successful, None otherwise
    """
    print("\n" + "-"*50)
    print("User Login")
    print("-"*50)
    
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return None
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return None
    
    password = input("Enter password: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return None
    
    # Verify password
    salt_auth = base64.b64decode(user_data["password_salt"])
    stored_hash = base64.b64decode(user_data["password_hash"])
    
    if crypto_manager.verify_password(password, salt_auth, stored_hash):
        print(f"\n✓ Login successful! Welcome, {username}.")
        return username, password
    else:
        print("\n✗ Invalid password.")
        return None


def modify_data(crypto_manager: CryptoManager, username: str, password: str):
    """
    Allow user to encrypt and store private data, or decrypt existing data.
    Uses ChaCha20Poly1305 authenticated encryption (AEAD).
    """
    print("\n" + "-"*50)
    print("Modify Private Data")
    print("-"*50)
    print("🔒 Your data will be encrypted using ChaCha20Poly1305 (Authenticated Encryption)")
    print("   - Encryption key derived from your password using Scrypt")
    print("   - Data protected with both confidentiality and authenticity")
    print("-"*50)
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return
    
    # Derive encryption key
    salt_enc = base64.b64decode(user_data["encryption_salt"])
    _, encryption_key = crypto_manager.derive_key_from_password(password, salt_enc)
    
    # Check if user has existing encrypted data
    if user_data.get("encrypted_data") and user_data.get("encrypted_nonce"):
        print("\n🔐 You have existing ENCRYPTED data stored.")
        print("   (Encrypted with ChaCha20Poly1305)")
        choice = input("(V)iew decrypted data, (R)eplace with new data, or (C)ancel? ").strip().upper()
        
        if choice == 'V':
            try:
                print("\n🔓 Decrypting your data...")
                nonce = base64.b64decode(user_data["encrypted_nonce"])
                ciphertext = base64.b64decode(user_data["encrypted_data"])
                plaintext = crypto_manager.decrypt_data(nonce, ciphertext, encryption_key)
                print(f"\n✓ Decryption successful!")
                print(f"\nYour decrypted private data:\n{plaintext}")
                print(f"\n🔒 Data is currently stored ENCRYPTED in the system.")
            except Exception as e:
                print(f"✗ Error decrypting data: {e}")
                print("This could mean the data was corrupted or the password is incorrect.")
            return
        elif choice == 'C':
            return
        # Continue to 'R' (replace) case
    
    # Get new data from user
    print("\nEnter your private data to ENCRYPT and store securely:")
    print("(Press Enter on a new line to finish, or type 'cancel' to abort):")
    lines = []
    while True:
        line = input()
        if line.strip().lower() == 'cancel':
            print("Operation cancelled.")
            return
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("No data entered.")
        return
    
    data = '\n'.join(lines)
    original_size = len(data.encode('utf-8'))
    
    try:
        print("\n🔒 Encrypting your data with ChaCha20Poly1305...")
        # Encrypt the data
        nonce, ciphertext = crypto_manager.encrypt_data(data, encryption_key)
        encrypted_size = len(ciphertext)
        
        # Update user data
        user_data["encrypted_data"] = base64.b64encode(ciphertext).decode('utf-8')
        user_data["encrypted_nonce"] = base64.b64encode(nonce).decode('utf-8')
        
        crypto_manager.save_user_data(username, user_data)
        
        print(f"\n✓ Private data ENCRYPTED and saved successfully!")
        print(f"\nEncryption Details:")
        print(f"  - Algorithm: ChaCha20Poly1305 (AEAD)")
        print(f"  - Original size: {original_size} bytes")
        print(f"  - Encrypted size: {encrypted_size} bytes (includes authentication tag)")
        print(f"  - Nonce: {len(nonce)} bytes (unique per encryption)")
        print(f"  - Status: 🔐 ENCRYPTED - Only you can decrypt with your password")
        
    except Exception as e:
        print(f"✗ Error encrypting data: {e}")


def sign_document(crypto_manager: CryptoManager, username: str, password: str):
    """
    Allow user to sign a message/document with their private key.
    """
    print("\n" + "-"*50)
    print("Sign Document/Message")
    print("-"*50)
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return
    
    # Load private key
    try:
        private_key_path = Path(user_data["private_key_path"])
        private_key = crypto_manager.load_private_key(private_key_path, password)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return
    
    # Get message to sign
    print("\nEnter the message/document to sign:")
    print("(Press Enter on a new line to finish, or type 'cancel' to abort)")
    lines = []
    while True:
        line = input()
        if line.strip().lower() == 'cancel':
            print("Operation cancelled.")
            return
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("No message entered.")
        return
    
    message = '\n'.join(lines)
    
    try:
        # Sign the message
        signature = crypto_manager.sign_data(message, private_key)
        
        # Save signature
        signature_path = crypto_manager.data_dir / f"{username}_signature_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        with open(signature_path, 'wb') as f:
            f.write(signature)
        
        # Also save as base64 for easy sharing
        signature_b64_path = crypto_manager.data_dir / f"{username}_signature_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(signature_b64_path, 'w') as f:
            f.write(f"Message:\n{message}\n\n")
            f.write(f"Signature (base64):\n{base64.b64encode(signature).decode('utf-8')}\n")
            f.write(f"\nTo verify, use the public key at: {user_data['public_key_path']}\n")
        
        print(f"\n✓ Message signed successfully!")
        print(f"Signature saved to: {signature_b64_path}")
        print(f"Binary signature saved to: {signature_path}")
        
    except Exception as e:
        print(f"Error signing message: {e}")
        import traceback
        traceback.print_exc()


def verify_signature(crypto_manager: CryptoManager):
    """
    Verify a digital signature against a message and public key.
    """
    print("\n" + "-"*50)
    print("Verify Signature")
    print("-"*50)
    print("✓ Verify that a message was signed by a specific user")
    print("-"*50)
    
    # Get signer username or public key path
    print("\nEnter the signer's username (to auto-find their public key):")
    print("Or enter the public key file path directly (e.g., data/keys/alice_public.pem)")
    user_input = input("Username or public key path: ").strip()
    
    if not user_input:
        print("Error: Input cannot be empty.")
        return
    
    # Try to find public key by username first
    public_key_path = None
    if not user_input.endswith('.pem') and not '/' in user_input:
        # Looks like a username
        user_data = crypto_manager.load_user_data(user_input)
        if user_data:
            public_key_path = Path(user_data["public_key_path"])
            print(f"✓ Found public key for '{user_input}': {public_key_path}")
        else:
            print(f"Error: User '{user_input}' not found.")
            return
    else:
        # Assume it's a file path
        public_key_path = Path(user_input)
        # If just filename, try keys directory
        if not public_key_path.is_absolute() and not public_key_path.exists():
            public_key_path = crypto_manager.keys_dir / public_key_path.name
    
    if not public_key_path.exists():
        print(f"Error: Public key file '{public_key_path}' not found.")
        print(f"Public keys are typically in: {crypto_manager.keys_dir}/")
        return
    
    # Get message
    print("\nEnter the original message:")
    print("(Press Enter on a new line to finish, or type 'cancel' to abort)")
    lines = []
    while True:
        line = input()
        if line.strip().lower() == 'cancel':
            print("Operation cancelled.")
            return
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("No message entered.")
        return
    
    message = '\n'.join(lines)
    
    # List recent signature files
    signature_files = sorted(crypto_manager.data_dir.glob("*_signature_*.bin"), 
                            key=lambda x: x.stat().st_mtime, reverse=True)
    
    if signature_files:
        print(f"\n📁 Found {len(signature_files)} signature file(s):")
        for i, file in enumerate(signature_files[:5], 1):  # Show last 5
            print(f"  {i}. {file.name}")
        print(f"\n   (Full path: {crypto_manager.data_dir}/)")
    
    # Get signature
    print("\nOptions:")
    print("  1. Enter the .bin signature file path (e.g., data/alice_signature_20251214_162717.bin)")
    print("  2. Or paste the base64 signature directly")
    print("  3. Or just the filename if it's in the data/ directory")
    signature_input = input("\nEnter signature file path or base64: ").strip()
    if not signature_input:
        print("Error: Signature cannot be empty.")
        return
    
    try:
        # Try to load signature from file first
        sig_file_path = Path(signature_input)
        
        # If just filename, try data directory
        if not sig_file_path.is_absolute() and not sig_file_path.exists():
            sig_file_path = crypto_manager.data_dir / signature_input
        
        if sig_file_path.exists():
            print(f"📂 Loading signature from file: {sig_file_path}")
            with open(sig_file_path, 'rb') as f:
                signature = f.read()
        else:
            # Assume it's base64 encoded
            print("📝 Parsing as base64 signature...")
            signature = base64.b64decode(signature_input)
        
        print(f"\n🔍 Verifying signature with public key...")
        # Load public key
        public_key = crypto_manager.load_public_key(Path(public_key_path))
        
        # Verify signature
        is_valid = crypto_manager.verify_signature(message, signature, public_key)
        
        if is_valid:
            print("\n✓ Signature is VALID!")
            print("   The message was signed by the owner of the public key.")
            print("   The message has not been tampered with.")
        else:
            print("\n✗ Signature is INVALID or message has been tampered with.")
            print("   Possible reasons:")
            print("   - Wrong public key used")
            print("   - Message was modified after signing")
            print("   - Signature file is corrupted")
            
    except Exception as e:
        print(f"\n✗ Error verifying signature: {e}")
        import traceback
        traceback.print_exc()


def sign_certificate(crypto_manager: CryptoManager):
    """
    Sign a user's CSR with the Root CA certificate.
    """
    print("\n" + "-"*50)
    print("Sign User Certificate (CA Administrator)")
    print("-"*50)
    
    username = input("Enter username to sign certificate for: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return
    
    # Check if CA files exist
    ca_key_path = crypto_manager.ca_dir / "root_ca.key"
    ca_cert_path = crypto_manager.ca_dir / "root_ca.crt"
    
    if not ca_key_path.exists() or not ca_cert_path.exists():
        print(f"Error: Root CA files not found.")
        print(f"Please run 'python generate_ca.py' first to create the CA.")
        return
    
    # Ask for CA password
    print("\nCA Private Key:")
    ca_password = input("Enter password for CA private key (or press Enter if unencrypted): ").strip()
    if not ca_password:
        ca_password = None
    
    # Sign the certificate
    success = crypto_manager.sign_user_csr(username, ca_key_path, ca_cert_path, ca_password)
    
    if success:
        print(f"\n✓ Certificate for '{username}' has been signed successfully!")
    else:
        print(f"\n✗ Failed to sign certificate for '{username}'.")


def encrypt_message_asymmetric(crypto_manager: CryptoManager):
    """
    Encrypt a message using RSA asymmetric encryption (BONUS feature).
    Encrypts a message with the recipient's public key.
    Only the recipient can decrypt with their private key.
    """
    print("\n" + "-"*50)
    print("Encrypt Message (Asymmetric Encryption - BONUS)")
    print("-"*50)
    print("🔒 Encrypt a message for a specific recipient")
    print("   - Only the recipient can decrypt (with their private key)")
    print("   - Uses RSA-OAEP encryption")
    print("   - Note: RSA can only encrypt small messages (~190 bytes max for 2048-bit keys)")
    print("-"*50)
    
    # Get recipient username
    recipient = input("Enter recipient username: ").strip()
    if not recipient:
        print("Error: Username cannot be empty.")
        return
    
    user_data = crypto_manager.load_user_data(recipient)
    if not user_data:
        print(f"Error: User '{recipient}' not found.")
        return
    
    # Load recipient's public key
    try:
        public_key_path = Path(user_data["public_key_path"])
        public_key = crypto_manager.load_public_key(public_key_path)
    except Exception as e:
        print(f"Error loading public key: {e}")
        return
    
    # Get message to encrypt
    print("\nEnter the message to encrypt:")
    print("(Press Enter on a new line to finish, or type 'cancel' to abort)")
    print("Note: Message must be under 190 bytes for 2048-bit RSA keys")
    lines = []
    while True:
        line = input()
        if line.strip().lower() == 'cancel':
            print("Operation cancelled.")
            return
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("No message entered.")
        return
    
    message = '\n'.join(lines)
    
    try:
        # Encrypt the message
        ciphertext = crypto_manager.encrypt_asymmetric(message, public_key)
        
        # Save encrypted message
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        encrypted_path = crypto_manager.data_dir / f"encrypted_{recipient}_{timestamp}.bin"
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)
        
        # Also save as base64 for easy sharing
        encrypted_b64_path = crypto_manager.data_dir / f"encrypted_{recipient}_{timestamp}.txt"
        with open(encrypted_b64_path, 'w') as f:
            f.write(f"Encrypted message for: {recipient}\n")
            f.write(f"Encrypted at: {datetime.now()}\n\n")
            f.write(f"Ciphertext (base64):\n{base64.b64encode(ciphertext).decode('utf-8')}\n")
        
        print(f"\n✓ Message encrypted successfully!")
        print(f"Encrypted message saved to: {encrypted_b64_path}")
        print(f"Binary ciphertext saved to: {encrypted_path}")
        print(f"\nMessage size: {len(message.encode('utf-8'))} bytes")
        print(f"Ciphertext size: {len(ciphertext)} bytes")
        
    except ValueError as e:
        print(f"\n✗ {e}")
    except Exception as e:
        print(f"Error encrypting message: {e}")
        import traceback
        traceback.print_exc()


def decrypt_message_asymmetric(crypto_manager: CryptoManager, username: str, password: str):
    """
    Decrypt a message using RSA asymmetric decryption (BONUS feature).
    Decrypts a message with the user's private key.
    Only you can decrypt messages encrypted with your public key.
    """
    print("\n" + "-"*50)
    print("Decrypt Message (Asymmetric Decryption - BONUS)")
    print("-"*50)
    print("🔓 Decrypt a message that was encrypted with YOUR public key")
    print("   Only you (the recipient) can decrypt messages intended for you")
    print("-"*50)
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return
    
    # Load private key
    try:
        private_key_path = Path(user_data["private_key_path"])
        private_key = crypto_manager.load_private_key(private_key_path, password)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return
    
    # List recent encrypted messages for this user
    encrypted_files = sorted(crypto_manager.data_dir.glob(f"encrypted_{username}_*.bin"), 
                           key=lambda x: x.stat().st_mtime, reverse=True)
    
    if encrypted_files:
        print(f"\n📁 Found {len(encrypted_files)} encrypted message(s) for you:")
        for i, file in enumerate(encrypted_files[:5], 1):  # Show last 5
            print(f"  {i}. {file.name}")
        print(f"\n   (Full path: {crypto_manager.data_dir}/)")
    
    # Get ciphertext
    print("\nOptions:")
    print("  1. Enter the .bin file path (e.g., data/encrypted_alice_20251214_010832.bin)")
    print("  2. Or paste the base64 ciphertext directly")
    print("  3. Or just the filename if it's in the data/ directory")
    ciphertext_input = input("\nEnter encrypted message file path or base64: ").strip()
    
    if not ciphertext_input:
        print("Error: Ciphertext cannot be empty.")
        return
    
    try:
        # Try to load from file first
        file_path = Path(ciphertext_input)
        
        # If just filename, try data directory
        if not file_path.is_absolute() and not file_path.exists():
            file_path = crypto_manager.data_dir / ciphertext_input
        
        if file_path.exists():
            print(f"📂 Loading from file: {file_path}")
            with open(file_path, 'rb') as f:
                ciphertext = f.read()
        else:
            # Assume it's base64 encoded
            print("📝 Parsing as base64 ciphertext...")
            ciphertext = base64.b64decode(ciphertext_input)
        
        print("\n🔓 Decrypting with your private key (RSA-OAEP)...")
        # Decrypt the message
        plaintext = crypto_manager.decrypt_asymmetric(ciphertext, private_key)
        
        print(f"\n✓ Message decrypted successfully!")
        print(f"\n📨 Decrypted message:\n{plaintext}")
        
    except Exception as e:
        print(f"\n✗ Error decrypting message: {e}")
        print("This could mean:")
        print("  - The file path is incorrect")
        print("  - The message was not encrypted with your public key")
        print("  - The ciphertext is corrupted")
        import traceback
        traceback.print_exc()


def modify_account(crypto_manager: CryptoManager, username: str, current_password: str):
    """
    Allow user to modify their account (change password).
    """
    print("\n" + "-"*50)
    print("Modify Account")
    print("-"*50)
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return
    
    print("\nYou can change your password.")
    print("Note: Changing your password will require re-encrypting your private data.")
    
    new_password = input("Enter new password (or press Enter to cancel): ").strip()
    if not new_password:
        print("Operation cancelled.")
        return
    
    confirm_password = input("Confirm new password: ").strip()
    if new_password != confirm_password:
        print("Error: Passwords do not match.")
        return
    
    try:
        # Hash new password
        salt_auth, password_hash = crypto_manager.hash_password(new_password)
        
        # Derive new encryption key
        salt_enc, encryption_key = crypto_manager.derive_key_from_password(new_password)
        
        # If user has encrypted data, we need to re-encrypt it with the new key
        if user_data.get("encrypted_data") and user_data.get("encrypted_nonce"):
            print("\nYou have encrypted data. Re-encrypting with new password...")
            # Decrypt with old key
            old_salt_enc = base64.b64decode(user_data["encryption_salt"])
            _, old_key = crypto_manager.derive_key_from_password(current_password, old_salt_enc)
            
            try:
                old_nonce = base64.b64decode(user_data["encrypted_nonce"])
                old_ciphertext = base64.b64decode(user_data["encrypted_data"])
                plaintext = crypto_manager.decrypt_data(old_nonce, old_ciphertext, old_key)
                
                # Re-encrypt with new key
                new_nonce, new_ciphertext = crypto_manager.encrypt_data(plaintext, encryption_key)
                user_data["encrypted_data"] = base64.b64encode(new_ciphertext).decode('utf-8')
                user_data["encrypted_nonce"] = base64.b64encode(new_nonce).decode('utf-8')
                print("✓ Data re-encrypted successfully.")
            except Exception as e:
                print(f"Warning: Could not re-encrypt existing data: {e}")
                print("Your encrypted data will be lost. Continue? (y/n): ", end="")
                if input().strip().lower() != 'y':
                    print("Password change cancelled.")
                    return
                user_data["encrypted_data"] = None
                user_data["encrypted_nonce"] = None
        
        # Re-encrypt private key with new password
        print("Re-encrypting private key with new password...")
        private_key_path = Path(user_data["private_key_path"])
        private_key = crypto_manager.load_private_key(private_key_path, current_password)
        crypto_manager.save_private_key(private_key, private_key_path, new_password)
        
        # Update user data
        user_data["password_salt"] = base64.b64encode(salt_auth).decode('utf-8')
        user_data["password_hash"] = base64.b64encode(password_hash).decode('utf-8')
        user_data["encryption_salt"] = base64.b64encode(salt_enc).decode('utf-8')
        
        crypto_manager.save_user_data(username, user_data)
        
        print("\n✓ Password changed successfully!")
        print("Please login again with your new password.")
        
    except Exception as e:
        print(f"Error changing password: {e}")
        import traceback
        traceback.print_exc()


def verify_certificate(crypto_manager: CryptoManager):
    """
    Verify a user's certificate against the Root CA.
    """
    print("\n" + "-"*50)
    print("Verify Certificate")
    print("-"*50)
    
    username = input("Enter username to verify certificate for: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return
    
    user_data = crypto_manager.load_user_data(username)
    if not user_data:
        print(f"Error: User '{username}' not found.")
        return
    
    cert_path = Path(user_data["cert_path"])
    if not cert_path.exists():
        print(f"Error: Certificate file not found at {cert_path}")
        print("You need to have your CSR signed by the CA first.")
        print("Use option 7 to sign the certificate.")
        return
    
    # Default CA certificate path
    ca_cert_path = crypto_manager.ca_dir / "root_ca.crt"
    if not ca_cert_path.exists():
        # Try alternative locations
        alt_paths = [
            Path("root_ca.crt"),
            Path("data/ca/root_ca.crt"),
            crypto_manager.data_dir / "root_ca.crt"
        ]
        found = False
        for alt_path in alt_paths:
            if alt_path.exists():
                ca_cert_path = alt_path
                found = True
                break
        
        if not found:
            print(f"Error: Root CA certificate not found at {ca_cert_path}")
            print("Please ensure root_ca.crt exists in the CA directory.")
            return
    
    try:
        # Load user certificate
        user_cert = crypto_manager.load_certificate(cert_path)
        
        print(f"\nCertificate Subject: {user_cert.subject}")
        print(f"Certificate Issuer: {user_cert.issuer}")
        print(f"Certificate Serial Number: {user_cert.serial_number}")
        print(f"Valid From: {user_cert.not_valid_before_utc}")
        print(f"Valid Until: {user_cert.not_valid_after_utc}")
        
        # Verify certificate chain
        is_valid = crypto_manager.verify_certificate_chain(user_cert, ca_cert_path)
        
        if is_valid:
            print("\n✓ Certificate is VALID and signed by the Root CA!")
        else:
            print("\n✗ Certificate verification FAILED.")
            
    except Exception as e:
        print(f"Error verifying certificate: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main application loop."""
    crypto_manager = CryptoManager()
    current_user = None
    current_password = None
    
    print("Welcome to the Secure Cryptography System!")
    print("This application demonstrates:")
    print("- Password-based authentication (Scrypt)")
    print("- Authenticated encryption (ChaCha20Poly1305)")
    print("- Digital signatures (RSA with PSS padding)")
    print("- Mini-PKI with X.509 certificates")
    print("- Asymmetric encryption (RSA with OAEP - BONUS)")
    
    while True:
        print_menu(current_user)
        choice = input("\nEnter your choice (1-11): ").strip()
        
        if choice == '1':
            sign_up(crypto_manager)
            input("\nPress Enter to continue...")
            
        elif choice == '2':
            if current_user:
                # Logout
                print(f"\n✓ Logged out successfully. Goodbye, {current_user}!")
                current_user = None
                current_password = None
            else:
                # Login
                result = login(crypto_manager)
                if result:
                    current_user, current_password = result
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            if not current_user:
                print("\n✗ Please login first.")
            else:
                modify_data(crypto_manager, current_user, current_password)
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            if not current_user:
                print("\n✗ Please login first.")
            else:
                sign_document(crypto_manager, current_user, current_password)
            input("\nPress Enter to continue...")
            
        elif choice == '5':
            verify_signature(crypto_manager)
            input("\nPress Enter to continue...")
            
        elif choice == '6':
            verify_certificate(crypto_manager)
            input("\nPress Enter to continue...")
            
        elif choice == '7':
            sign_certificate(crypto_manager)
            input("\nPress Enter to continue...")
            
        elif choice == '8':
            encrypt_message_asymmetric(crypto_manager)
            input("\nPress Enter to continue...")
            
        elif choice == '9':
            if not current_user:
                print("\n✗ Please login first.")
            else:
                decrypt_message_asymmetric(crypto_manager, current_user, current_password)
            input("\nPress Enter to continue...")
            
        elif choice == '10':
            if not current_user:
                print("\n✗ Please login first.")
            else:
                modify_account(crypto_manager, current_user, current_password)
                # After password change, user needs to login again
                if input("\nPassword changed. Login again? (y/n): ").strip().lower() == 'y':
                    result = login(crypto_manager)
                    if result:
                        current_user, current_password = result
            input("\nPress Enter to continue...")
            
        elif choice == '11':
            print("\nThank you for using the Secure Cryptography System!")
            print("Goodbye!")
            sys.exit(0)
            
        else:
            print("\nInvalid choice. Please enter a number between 1-11.")
            input("Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

