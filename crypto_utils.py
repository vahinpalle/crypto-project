"""
Cryptographic utilities module using pyca/cryptography library.
Implements password hashing, authenticated encryption, digital signatures, and PKI.
"""

import os
import base64
import json
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


class CryptoManager:
    """
    Manager class for all cryptographic operations including:
    - Password hashing and key derivation
    - Authenticated encryption (AEAD)
    - Digital signatures
    - Certificate operations and PKI
    """
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialize the CryptoManager.
        
        Args:
            data_dir: Directory to store user data, keys, and certificates
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.users_dir = self.data_dir / "users"
        self.users_dir.mkdir(exist_ok=True)
        self.keys_dir = self.data_dir / "keys"
        self.keys_dir.mkdir(exist_ok=True)
        self.certs_dir = self.data_dir / "certs"
        self.certs_dir.mkdir(exist_ok=True)
        self.ca_dir = self.data_dir / "ca"
        self.ca_dir.mkdir(exist_ok=True)
        
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Hash a password using Scrypt (memory-hard KDF, resistant to GPU attacks).
        Scrypt is preferred over PBKDF2 because it requires more memory,
        making hardware-accelerated attacks more expensive.
        
        Args:
            password: Plaintext password
            salt: Optional salt (generates new one if None)
            
        Returns:
            Tuple of (salt, hashed_password)
        """
        if salt is None:
            salt = os.urandom(16)  # 128-bit salt
            
        # Scrypt parameters: n=2^14 (16384) iterations, r=8, p=1
        # These parameters provide good security while remaining practical
        kdf = Scrypt(
            salt=salt,
            length=32,  # 256-bit output
            n=2**14,    # CPU/memory cost parameter
            r=8,        # Block size parameter
            p=1         # Parallelization parameter
        )
        
        password_bytes = password.encode('utf-8')
        password_hash = kdf.derive(password_bytes)
        
        return salt, password_hash
    
    def verify_password(self, password: str, salt: bytes, stored_hash: bytes) -> bool:
        """
        Verify a password against a stored hash using Scrypt.
        
        Args:
            password: Plaintext password to verify
            salt: Salt used for hashing
            stored_hash: Previously stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1
            )
            password_bytes = password.encode('utf-8')
            kdf.verify(password_bytes, stored_hash)
            return True
        except Exception:
            return False
    
    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive a symmetric encryption key from a password using Scrypt.
        This is separate from password hashing - we use it to derive
        encryption keys for protecting user data.
        
        Args:
            password: User password
            salt: Optional salt (generates new one if None)
            
        Returns:
            Tuple of (salt, derived_key)
        """
        if salt is None:
            salt = os.urandom(16)
            
        kdf = Scrypt(
            salt=salt,
            length=32,  # 32 bytes = 256 bits for ChaCha20Poly1305
            n=2**14,
            r=8,
            p=1
        )
        
        password_bytes = password.encode('utf-8')
        key = kdf.derive(password_bytes)
        
        return salt, key
    
    def encrypt_data(self, data: str, key: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt data using ChaCha20Poly1305 (AEAD).
        ChaCha20Poly1305 is preferred over AES-GCM because:
        1. It's faster on systems without AES hardware acceleration
        2. It's immune to timing attacks
        3. It's widely supported and standardized
        
        Args:
            data: Plaintext data to encrypt
            key: 32-byte encryption key
            associated_data: Optional authenticated associated data
            
        Returns:
            Tuple of (nonce, ciphertext)
        """
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # 96-bit nonce for ChaCha20Poly1305
        data_bytes = data.encode('utf-8')
        ciphertext = chacha.encrypt(nonce, data_bytes, associated_data)
        return nonce, ciphertext
    
    def decrypt_data(self, nonce: bytes, ciphertext: bytes, key: bytes, 
                     associated_data: bytes = b"") -> str:
        """
        Decrypt data using ChaCha20Poly1305.
        
        Args:
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            key: 32-byte decryption key
            associated_data: Same associated data used for encryption
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            Exception: If decryption fails (authentication failure)
        """
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode('utf-8')
    
    def generate_key_pair(self, key_size: int = 2048) -> tuple:
        """
        Generate an RSA key pair for digital signatures.
        Using 2048-bit RSA as minimum (3072 or 4096 recommended for long-term security).
        RSA is chosen over Ed25519 for this educational project to demonstrate
        PKCS padding schemes and X.509 certificate integration.
        
        Args:
            key_size: RSA key size in bits (default 2048)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, private_key, filepath: Path, password: str) -> None:
        """
        Save a private key to disk using PEM encoding with PKCS8 format,
        encrypted with BestAvailableEncryption (AES-256-CBC).
        
        Args:
            private_key: RSA private key object
            filepath: Path to save the key
            password: Password to encrypt the key
        """
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        )
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    def load_private_key(self, filepath: Path, password: str):
        """
        Load a private key from disk.
        
        Args:
            filepath: Path to the key file
            password: Password to decrypt the key
            
        Returns:
            Private key object
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        return private_key
    
    def save_public_key(self, public_key, filepath: Path) -> None:
        """
        Save a public key to disk using PEM encoding with SubjectPublicKeyInfo format.
        
        Args:
            public_key: RSA public key object
            filepath: Path to save the key
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    def load_public_key(self, filepath: Path):
        """
        Load a public key from disk.
        
        Args:
            filepath: Path to the key file
            
        Returns:
            Public key object
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        return public_key
    
    def generate_csr(self, private_key, username: str, organization: str = "CryptoCourse") -> bytes:
        """
        Generate a Certificate Signing Request (CSR) for a user's public key.
        The CSR contains the user's public key and identity information,
        which will be signed by the CA to create a certificate.
        
        Args:
            private_key: User's private key (used to sign the CSR)
            username: Username for the certificate subject
            organization: Organization name (default: CryptoCourse)
            
        Returns:
            CSR in PEM format (bytes)
        """
        # Build the subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        
        # Create the CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return csr.public_bytes(serialization.Encoding.PEM)
    
    def sign_data(self, data: str, private_key) -> bytes:
        """
        Sign data using RSA with PSS padding and SHA256.
        PSS (Probabilistic Signature Scheme) is chosen over PKCS1v15 because:
        1. It's provably secure and more resistant to certain attacks
        2. It's the recommended padding scheme in modern cryptography
        3. MGF1 (Mask Generation Function 1) is the standard MGF for PSS
        
        Args:
            data: Data to sign (string)
            private_key: RSA private key
            
        Returns:
            Digital signature (bytes)
        """
        data_bytes = data.encode('utf-8')
        
        # Pre-hash the data with SHA256
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data_bytes)
        message_digest = digest.finalize()
        
        # Sign using PSS padding with MGF1 and SHA256
        signature = private_key.sign(
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        
        return signature
    
    def verify_signature(self, data: str, signature: bytes, public_key) -> bool:
        """
        Verify a digital signature.
        
        Args:
            data: Original data that was signed
            signature: Digital signature to verify
            public_key: Public key of the signer
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            data_bytes = data.encode('utf-8')
            
            # Pre-hash the data with SHA256
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data_bytes)
            message_digest = digest.finalize()
            
            # Verify using PSS padding with MGF1 and SHA256
            public_key.verify(
                signature,
                message_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    def encrypt_asymmetric(self, data: str, public_key) -> bytes:
        """
        Encrypt data using RSA with OAEP padding (asymmetric encryption).
        OAEP (Optimal Asymmetric Encryption Padding) is chosen because:
        1. It's provably secure and recommended for RSA encryption
        2. It provides better security than PKCS1v15 padding
        3. It uses MGF1 (Mask Generation Function 1) with SHA256
        
        Note: RSA can only encrypt small messages. For 2048-bit keys,
        the maximum message size is ~245 bytes. For larger messages,
        hybrid encryption (RSA + symmetric) would be needed.
        
        Args:
            data: Plaintext data to encrypt (string)
            public_key: RSA public key of the recipient
            
        Returns:
            Encrypted ciphertext (bytes)
        """
        data_bytes = data.encode('utf-8')
        
        # Check message size (RSA with OAEP can encrypt up to key_size/8 - 2*hash_size - 2 bytes)
        # For 2048-bit key with SHA256: 256 - 32 - 2 = 222 bytes max
        max_size = 190  # Conservative limit for 2048-bit RSA with OAEP-SHA256
        if len(data_bytes) > max_size:
            raise ValueError(f"Message too large for RSA encryption. Maximum size: {max_size} bytes. "
                           f"Your message is {len(data_bytes)} bytes. Consider using hybrid encryption.")
        
        # Encrypt using OAEP padding with MGF1 and SHA256
        ciphertext = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt_asymmetric(self, ciphertext: bytes, private_key) -> str:
        """
        Decrypt data using RSA with OAEP padding.
        
        Args:
            ciphertext: Encrypted data (bytes)
            private_key: RSA private key of the recipient
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            Exception: If decryption fails
        """
        try:
            # Decrypt using OAEP padding with MGF1 and SHA256
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def load_certificate(self, filepath: Path) -> x509.Certificate:
        """
        Load an X.509 certificate from disk.
        
        Args:
            filepath: Path to certificate file (PEM format)
            
        Returns:
            Certificate object
        """
        with open(filepath, 'rb') as f:
            cert_pem = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    
    def verify_certificate_chain(self, user_cert: x509.Certificate, 
                                 ca_cert_path: Path) -> bool:
        """
        Verify that a user's certificate is valid and signed by the Root CA.
        This involves:
        1. Extracting the certificate's signature and tbs_certificate_bytes
        2. Hashing the tbs_certificate_bytes
        3. Verifying the signature using the CA's public key
        4. Checking that the signature algorithm matches (SHA256 with RSA)
        
        Args:
            user_cert: User's X.509 certificate
            ca_cert_path: Path to Root CA certificate
            
        Returns:
            True if certificate is valid and signed by CA, False otherwise
        """
        try:
            # Load the CA certificate
            ca_cert = self.load_certificate(ca_cert_path)
            ca_public_key = ca_cert.public_key()
            
            # Get the signature and certificate bytes from the user's certificate
            user_signature = user_cert.signature
            tbs_certificate_bytes = user_cert.tbs_certificate_bytes
            
            # Hash the tbs_certificate_bytes (X.509 certificates are signed over the hash)
            hash_algorithm = hashes.SHA256()
            digest = hashes.Hash(hash_algorithm, backend=default_backend())
            digest.update(tbs_certificate_bytes)
            message_digest = digest.finalize()
            
            # Verify the signature using the CA's public key
            # The CA signs the hash of tbs_certificate_bytes using PKCS1v15 padding
            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    user_signature,
                    message_digest,
                    padding.PKCS1v15(),  # CA uses PKCS1v15 for signing certificates
                    utils.Prehashed(hash_algorithm)  # Data is already hashed
                )
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def sign_user_csr(self, username: str, ca_key_path: Path, ca_cert_path: Path,
                      ca_password: Optional[str] = None, valid_days: int = 365) -> bool:
        """
        Sign a user's CSR with the Root CA.
        
        Args:
            username: Username whose CSR to sign
            ca_key_path: Path to CA private key
            ca_cert_path: Path to CA certificate
            ca_password: Password for CA private key (if encrypted)
            valid_days: Number of days the certificate should be valid
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load user data to find CSR path
            user_data = self.load_user_data(username)
            if not user_data:
                print(f"Error: User '{username}' not found.")
                return False
            
            csr_path = Path(user_data["csr_path"])
            if not csr_path.exists():
                print(f"Error: CSR not found at {csr_path}")
                return False
            
            # Load CSR
            with open(csr_path, 'rb') as f:
                csr_pem = f.read()
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
            
            # Load CA key
            with open(ca_key_path, 'rb') as f:
                ca_key_pem = f.read()
            
            if ca_password:
                ca_private_key = serialization.load_pem_private_key(
                    ca_key_pem,
                    password=ca_password.encode('utf-8'),
                    backend=default_backend()
                )
            else:
                ca_private_key = serialization.load_pem_private_key(
                    ca_key_pem,
                    password=None,
                    backend=default_backend()
                )
            
            # Load CA cert
            ca_cert = self.load_certificate(ca_cert_path)
            
            # Create certificate from CSR
            user_cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject  # Issued by CA
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=valid_days)
            ).sign(ca_private_key, hashes.SHA256(), default_backend())
            
            # Save signed certificate
            output_cert_path = Path(user_data["cert_path"])
            with open(output_cert_path, 'wb') as f:
                f.write(user_cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"\n✓ Certificate signed and saved to: {output_cert_path}")
            print(f"  Subject: {user_cert.subject}")
            print(f"  Valid Until: {user_cert.not_valid_after_utc}")
            return True
            
        except Exception as e:
            print(f"Error signing certificate: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_user_data(self, username: str, user_data: dict) -> None:
        """
        Save user metadata to JSON file.
        
        Args:
            username: Username
            user_data: Dictionary containing user metadata
        """
        user_file = self.users_dir / f"{username}.json"
        with open(user_file, 'w') as f:
            json.dump(user_data, f, indent=2, default=str)
    
    def load_user_data(self, username: str) -> dict:
        """
        Load user metadata from JSON file.
        
        Args:
            username: Username
            
        Returns:
            Dictionary containing user metadata, or None if not found
        """
        user_file = self.users_dir / f"{username}.json"
        if not user_file.exists():
            return None
        
        with open(user_file, 'r') as f:
            return json.load(f)

