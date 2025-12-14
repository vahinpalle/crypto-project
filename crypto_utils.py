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
    def __init__(self, data_dir: str = "data"):
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
        if salt is None:
            salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1
        )
        password_bytes = password.encode('utf-8')
        password_hash = kdf.derive(password_bytes)
        return salt, password_hash
    
    def verify_password(self, password: str, salt: bytes, stored_hash: bytes) -> bool:
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
        if salt is None:
            salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1
        )
        password_bytes = password.encode('utf-8')
        key = kdf.derive(password_bytes)
        return salt, key
    
    def encrypt_data(self, data: str, key: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        data_bytes = data.encode('utf-8')
        ciphertext = chacha.encrypt(nonce, data_bytes, associated_data)
        return nonce, ciphertext
    
    def decrypt_data(self, nonce: bytes, ciphertext: bytes, key: bytes, 
                     associated_data: bytes = b"") -> str:
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode('utf-8')
    
    def generate_key_pair(self, key_size: int = 2048) -> tuple:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, private_key, filepath: Path, password: str) -> None:
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
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        return private_key
    
    def save_public_key(self, public_key, filepath: Path) -> None:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    def load_public_key(self, filepath: Path):
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        return public_key
    
    def generate_csr(self, private_key, username: str, country: str, state: str, 
                     locality: str, organization: str) -> bytes:
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256(), default_backend())
        return csr.public_bytes(serialization.Encoding.PEM)
    
    def sign_data(self, data: str, private_key) -> bytes:
        data_bytes = data.encode('utf-8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data_bytes)
        message_digest = digest.finalize()
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
        try:
            data_bytes = data.encode('utf-8')
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data_bytes)
            message_digest = digest.finalize()
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
        data_bytes = data.encode('utf-8')
        max_size = 190
        if len(data_bytes) > max_size:
            raise ValueError(f"Message too large for RSA encryption. Maximum size: {max_size} bytes. "
                           f"Your message is {len(data_bytes)} bytes. Consider using hybrid encryption.")
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
        try:
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
        with open(filepath, 'rb') as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    
    def verify_certificate_chain(self, user_cert: x509.Certificate, 
                                 ca_cert_path: Path) -> bool:
        try:
            ca_cert = self.load_certificate(ca_cert_path)
            ca_public_key = ca_cert.public_key()
            user_signature = user_cert.signature
            tbs_certificate_bytes = user_cert.tbs_certificate_bytes
            hash_algorithm = hashes.SHA256()
            digest = hashes.Hash(hash_algorithm, backend=default_backend())
            digest.update(tbs_certificate_bytes)
            message_digest = digest.finalize()
            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    user_signature,
                    message_digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(hash_algorithm)
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
        try:
            user_data = self.load_user_data(username)
            if not user_data:
                print(f"Error: User '{username}' not found.")
                return False
            csr_path = Path(user_data["csr_path"])
            if not csr_path.exists():
                print(f"Error: CSR not found at {csr_path}")
                return False
            with open(csr_path, 'rb') as f:
                csr_pem = f.read()
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
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
            ca_cert = self.load_certificate(ca_cert_path)
            user_cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=valid_days)
            ).sign(ca_private_key, hashes.SHA256(), default_backend())
            output_cert_path = Path(user_data["cert_path"])
            with open(output_cert_path, 'wb') as f:
                f.write(user_cert.public_bytes(serialization.Encoding.PEM))
            print(f"\nCertificate signed and saved to: {output_cert_path}")
            print(f"  Subject: {user_cert.subject}")
            print(f"  Valid Until: {user_cert.not_valid_after_utc}")
            return True
        except Exception as e:
            print(f"Error signing certificate: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_user_data(self, username: str, user_data: dict) -> None:
        user_file = self.users_dir / f"{username}.json"
        with open(user_file, 'w') as f:
            json.dump(user_data, f, indent=2, default=str)
    
    def load_user_data(self, username: str) -> dict:
        user_file = self.users_dir / f"{username}.json"
        if not user_file.exists():
            return None
        with open(user_file, 'r') as f:
            return json.load(f)
