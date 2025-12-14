"""
Helper script to sign a user's CSR with the Root CA certificate.
"""

import sys
from pathlib import Path
from generate_ca import sign_user_csr


def main():
    if len(sys.argv) < 2:
        print("Usage: python sign_certificate.py <username> [ca_password]")
        print("\nExample: python sign_certificate.py alice")
        print("\nThis will sign the CSR for 'alice' and save the certificate.")
        sys.exit(1)
    
    username = sys.argv[1]
    ca_password = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Paths
    csr_path = Path(f"data/certs/{username}_csr.pem")
    ca_key_path = Path("data/ca/root_ca.key")
    ca_cert_path = Path("data/ca/root_ca.crt")
    output_cert_path = Path(f"data/certs/{username}_cert.pem")
    
    # Check if files exist
    if not csr_path.exists():
        print(f"Error: CSR not found at {csr_path}")
        sys.exit(1)
    
    if not ca_key_path.exists():
        print(f"Error: CA private key not found at {ca_key_path}")
        print("Please run generate_ca.py first to create the Root CA.")
        sys.exit(1)
    
    if not ca_cert_path.exists():
        print(f"Error: CA certificate not found at {ca_cert_path}")
        print("Please run generate_ca.py first to create the Root CA.")
        sys.exit(1)
    
    # If password not provided, ask for it
    if ca_password is None:
        print("\nCA Private Key:")
        ca_password = input("Enter password for CA private key (or press Enter if unencrypted): ").strip()
        if not ca_password:
            ca_password = None
    
    try:
        sign_user_csr(csr_path, ca_key_path, ca_cert_path, output_cert_path, ca_password)
        print(f"\n✓ Certificate for '{username}' has been signed and saved!")
    except Exception as e:
        print(f"Error signing certificate: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

