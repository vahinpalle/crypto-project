"""
Script to generate a Root CA certificate and private key for the mini-PKI system.
This CA will be used to sign user certificates.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def generate_root_ca(ca_dir: Path, password: str = None):
    """
    Generate a self-signed Root CA certificate and private key.
    
    Args:
        ca_dir: Directory to store CA files
        password: Optional password to encrypt the CA private key
    """
    ca_dir.mkdir(parents=True, exist_ok=True)
    
    print("Generating Root CA private key (4096-bit RSA)...")
    # Generate 4096-bit RSA key for the CA (stronger than user keys)
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Save CA private key
    ca_key_path = ca_dir / "root_ca.key"
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        encryption = serialization.NoEncryption()
    
    ca_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(ca_key_path, 'wb') as f:
        f.write(ca_key_pem)
    
    print(f"CA private key saved to: {ca_key_path}")
    
    # Build CA subject (same as issuer for self-signed cert)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoCourse CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
    ])
    
    # Create self-signed CA certificate (valid for 10 years)
    print("Generating Root CA certificate...")
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("root-ca.cryptocourse.local"),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save CA certificate
    ca_cert_path = ca_dir / "root_ca.crt"
    with open(ca_cert_path, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"CA certificate saved to: {ca_cert_path}")
    print("\n✓ Root CA generated successfully!")
    print(f"\nCA Certificate Details:")
    print(f"  Subject: {ca_cert.subject}")
    print(f"  Valid From: {ca_cert.not_valid_before_utc}")
    print(f"  Valid Until: {ca_cert.not_valid_after_utc}")
    print(f"  Serial Number: {ca_cert.serial_number}")


def sign_user_csr(csr_path: Path, ca_key_path: Path, ca_cert_path: Path, 
                  output_cert_path: Path, password: str = None, valid_days: int = 365):
    """
    Sign a user's CSR with the Root CA.
    
    Args:
        csr_path: Path to the user's CSR file
        ca_key_path: Path to CA private key
        ca_cert_path: Path to CA certificate
        output_cert_path: Path to save the signed certificate
        password: Password for CA private key (if encrypted)
        valid_days: Number of days the certificate should be valid
    """
    # Load CSR
    with open(csr_path, 'rb') as f:
        csr_pem = f.read()
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    
    # Load CA key
    with open(ca_key_path, 'rb') as f:
        ca_key_pem = f.read()
    
    if password:
        ca_private_key = serialization.load_pem_private_key(
            ca_key_pem,
            password=password.encode('utf-8'),
            backend=default_backend()
        )
    else:
        ca_private_key = serialization.load_pem_private_key(
            ca_key_pem,
            password=None,
            backend=default_backend()
        )
    
    # Load CA cert
    with open(ca_cert_path, 'rb') as f:
        ca_cert_pem = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    
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
    with open(output_cert_path, 'wb') as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ Certificate signed and saved to: {output_cert_path}")
    print(f"  Subject: {user_cert.subject}")
    print(f"  Valid Until: {user_cert.not_valid_after_utc}")


if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("Root CA Certificate Generator")
    print("="*60)
    
    # Determine CA directory
    ca_dir = Path("data/ca")
    if len(sys.argv) > 1:
        ca_dir = Path(sys.argv[1])
    
    # Ask for password (optional but recommended)
    print("\nCA Private Key Encryption:")
    print("You can protect the CA private key with a password (recommended).")
    use_password = input("Use password protection? (y/n): ").strip().lower() == 'y'
    
    password = None
    if use_password:
        password = input("Enter password for CA private key: ").strip()
        if not password:
            print("Warning: No password provided. CA key will be unencrypted.")
    
    generate_root_ca(ca_dir, password)
    
    print("\n" + "="*60)
    print("Next steps:")
    print("1. Users can now register and generate CSRs")
    print("2. Use this script's sign_user_csr() function to sign user CSRs")
    print("   Or create a separate script to automate certificate signing")
    print("="*60)

