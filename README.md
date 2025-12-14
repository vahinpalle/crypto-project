# Secure Cryptography System

A comprehensive Python CLI application demonstrating secure cryptographic practices including password authentication, authenticated encryption, digital signatures, and a mini-PKI (Public Key Infrastructure) system.

## Features

- **Password-Based Authentication**: Uses Scrypt (memory-hard KDF) for secure password hashing
- **Authenticated Encryption**: ChaCha20Poly1305 for protecting user data with authentication
- **Digital Signatures**: RSA with PSS padding and SHA256 for message signing
- **Mini-PKI**: X.509 certificate generation and verification with a Root CA

## Architecture

The application consists of two main modules:

1. **`crypto_utils.py`**: Contains the `CryptoManager` class with all cryptographic primitives
2. **`main.py`**: CLI interface for user interaction

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Setup

### 1. Generate Root CA Certificate

Before users can register, you need to create a Root CA:

```bash
python generate_ca.py
```

This will create:
- `data/ca/root_ca.key` - CA private key
- `data/ca/root_ca.crt` - CA certificate

You'll be prompted to set a password for the CA private key (recommended but optional).

### 2. Run the Application

```bash
python main.py
```

## Usage

### User Registration

1. Select option `1` from the main menu
2. Enter a username and password
3. The system will:
   - Hash your password with Scrypt
   - Generate a 2048-bit RSA key pair
   - Create a Certificate Signing Request (CSR)
   - Store your encrypted keys

### Signing User Certificates

After a user registers, you need to sign their CSR with the CA:

```bash
python sign_certificate.py <username>
```

This will create `data/certs/<username>_cert.pem` which the user can use for certificate verification.

### User Login

1. Select option `2` from the main menu
2. Enter your username and password
3. Password is verified against the stored hash

### Modify Private Data

1. Login first (option `2`)
2. Select option `3`
3. You can:
   - View your existing encrypted data
   - Encrypt and store new private data (bio, notes, etc.)
   - The data is encrypted using ChaCha20Poly1305 with a key derived from your password

### Sign Documents

1. Login first (option `2`)
2. Select option `4`
3. Enter the message/document to sign
4. The signature is saved to a file
5. You can share the signature and public key for verification

### Verify Signatures

1. Select option `5`
2. Provide:
   - Path to the public key (PEM file)
   - The original message
   - The signature file or base64-encoded signature
3. The system will verify the signature using RSA-PSS

### Verify Certificate

1. Select option `6`
2. Enter a username
3. The system will verify that the user's certificate is valid and signed by the Root CA

## Cryptographic Choices Explained

### Password Hashing: Scrypt
- **Why Scrypt?** Scrypt is a memory-hard key derivation function that requires significant memory to compute, making it resistant to GPU and ASIC-based attacks
- **Parameters**: n=2^14 (16384 iterations), r=8, p=1, output=256 bits

### Authenticated Encryption: ChaCha20Poly1305
- **Why ChaCha20Poly1305?** 
  - Faster on systems without AES hardware acceleration
  - Immune to timing attacks
  - Provides both confidentiality (ChaCha20) and authenticity (Poly1305)
  - Standardized and widely supported

### Digital Signatures: RSA with PSS Padding
- **Why RSA-PSS?** 
  - PSS (Probabilistic Signature Scheme) is provably secure
  - More resistant to certain attacks than PKCS1v15
  - Recommended by modern cryptographic standards
  - Uses MGF1 (Mask Generation Function 1) with SHA256

### Key Sizes
- **User RSA Keys**: 2048 bits (minimum recommended, 3072+ for long-term security)
- **CA RSA Key**: 4096 bits (stronger for the Certificate Authority)
- **Symmetric Keys**: 256 bits (derived via Scrypt)

## File Structure

```
.
├── crypto_utils.py          # Cryptographic operations
├── main.py                  # CLI application
├── generate_ca.py           # Root CA generation script
├── sign_certificate.py      # Certificate signing helper
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── data/                   # Data directory (created automatically)
    ├── users/              # User metadata (JSON)
    ├── keys/               # Private and public keys (PEM)
    ├── certs/              # Certificates and CSRs (PEM)
    └── ca/                 # Root CA files
```

## Security Notes

1. **Password Storage**: Passwords are never stored in cleartext. Only salts and hashes are stored.

2. **Key Protection**: Private keys are encrypted using AES-256-CBC (BestAvailableEncryption) before storage.

3. **Nonce/IV Management**: Unique nonces are generated for each encryption operation and stored with the ciphertext.

4. **Certificate Verification**: Certificate chain verification includes:
   - Signature verification using the CA's public key
   - Extraction of tbs_certificate_bytes for verification
   - Proper handling of signature algorithms

5. **Error Handling**: The application gracefully handles missing files, incorrect passwords, and cryptographic failures.

## Educational Purpose

This project is designed for educational purposes in a cryptography course. It demonstrates:
- Proper use of cryptographic primitives
- Secure password handling
- Authenticated encryption concepts
- Digital signature workflows
- PKI and certificate management

## Limitations

- This is an educational project and should not be used in production without additional security hardening
- Key management is simplified for educational purposes
- No certificate revocation list (CRL) implementation
- No key rotation mechanisms

## License

This project is provided as-is for educational purposes.

