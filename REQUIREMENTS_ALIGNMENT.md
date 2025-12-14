# Project Requirements Alignment

This document shows how the Secure Cryptography System aligns with the course project requirements.

## ✅ Core Requirements

### 1. Multiple Users Support
**Status: ✅ IMPLEMENTED**
- Users can register with unique usernames
- Each user has their own data, keys, and certificates
- User data is stored separately in `data/users/` directory

### 2. User Registration (Sign Up)
**Status: ✅ IMPLEMENTED**
- Menu option 1: Sign Up
- Collects username and password
- Generates RSA key pair (2048-bit)
- Creates Certificate Signing Request (CSR)
- Stores password hash (Scrypt) and encrypted keys

### 3. User Login
**Status: ✅ IMPLEMENTED**
- Menu option 2: Login
- Verifies password against stored hash using Scrypt
- Maintains session state for authenticated operations

### 4. Account Modification (Optional)
**Status: ✅ IMPLEMENTED**
- Menu option 10: Modify Account
- Users can change their password
- Automatically re-encrypts private data and private keys with new password
- Maintains data integrity during password change

### 5. Data Storage and Processing
**Status: ✅ IMPLEMENTED**
- User metadata stored in JSON files (`data/users/`)
- Keys stored in PEM format (`data/keys/`)
- Certificates and CSRs stored in PEM format (`data/certs/`)
- Encrypted data stored in user metadata

### 6. Authenticated Encryption for Data Protection
**Status: ✅ IMPLEMENTED**
- Menu option 3: Modify Private Data
- Uses **ChaCha20Poly1305** (AEAD cipher)
- Data encrypted with key derived from user's password (Scrypt)
- Unique nonce for each encryption operation
- Provides both confidentiality and authenticity

### 7. Digital Signatures
**Status: ✅ IMPLEMENTED**
- **Generation**: Menu option 4: Sign Document/Message
- **Verification**: Menu option 5: Verify Signature
- Uses **RSA with PSS padding** and **SHA256**
- PSS (Probabilistic Signature Scheme) with MGF1
- Signatures saved in binary and base64 formats

### 8. Mini-PKI (Public Key Infrastructure)
**Status: ✅ IMPLEMENTED**
- **Root CA**: Generated via `generate_ca.py`
- **CSR Generation**: Automatic during user registration
- **Certificate Signing**: Menu option 7: Sign User Certificate (CA Admin)
- **Certificate Verification**: Menu option 6: Verify Certificate
- All user public keys certified by Root CA
- Certificate chain verification implemented
- Uses X.509 certificates in PEM format

## 🎁 BONUS Features

### 9. Asymmetric Encryption (BONUS)
**Status: ✅ IMPLEMENTED**
- **Encryption**: Menu option 8: Encrypt Message (Asymmetric)
- **Decryption**: Menu option 9: Decrypt Message (Asymmetric)
- Uses **RSA with OAEP padding** and **SHA256**
- Encrypts messages with recipient's public key
- Decrypts with recipient's private key
- Handles message size limitations (max ~190 bytes for 2048-bit keys)

## Grade Distribution Alignment

| Requirement | Points | Status | Implementation |
|------------|--------|--------|----------------|
| User authentication | 0.5/4.0 | ✅ | Scrypt password hashing, login/signup |
| Key management | 0.5/4.0 | ✅ | RSA key generation, encrypted key storage (PKCS8, BestAvailableEncryption) |
| Authenticated encryption | 0.75/4.0 | ✅ | ChaCha20Poly1305 with password-derived keys |
| Digital signatures | 0.75/4.0 | ✅ | RSA-PSS with SHA256, sign/verify functionality |
| Mini-PKI | 1.0/4.0 | ✅ | Root CA, CSR generation, certificate signing, chain verification |
| **BONUS: Asymmetric encryption** | **+0.5/4.0** | ✅ | **RSA-OAEP encryption/decryption** |
| Report | 0.5/4.0 | 📝 | *To be written by student* |

**Total: 4.0/4.0 + 0.5 bonus = 4.5/4.0**

## Cryptographic Implementation Details

### Password Hashing
- **Algorithm**: Scrypt
- **Parameters**: n=2^14 (16384), r=8, p=1
- **Output**: 256-bit hash
- **Salt**: 128-bit random salt per user

### Authenticated Encryption
- **Algorithm**: ChaCha20Poly1305
- **Key Derivation**: Scrypt from user password
- **Key Size**: 256 bits
- **Nonce**: 96-bit random nonce per encryption

### Digital Signatures
- **Algorithm**: RSA with PSS padding
- **Key Size**: 2048 bits
- **Hash**: SHA256
- **Padding**: PSS with MGF1

### Asymmetric Encryption (BONUS)
- **Algorithm**: RSA with OAEP padding
- **Key Size**: 2048 bits
- **Hash**: SHA256
- **Padding**: OAEP with MGF1
- **Max Message Size**: ~190 bytes

### PKI
- **CA Key Size**: 4096 bits
- **User Key Size**: 2048 bits
- **Certificate Format**: X.509 (PEM)
- **CSR Format**: PKCS#10 (PEM)
- **Key Format**: PKCS#8 (PEM, encrypted)

## File Structure

```
.
├── crypto_utils.py          # All cryptographic operations
├── main.py                  # CLI application
├── generate_ca.py           # Root CA generator
├── sign_certificate.py      # Certificate signing helper
├── requirements.txt         # Dependencies
├── README.md               # User documentation
├── QUICKSTART.md           # Quick start guide
└── data/                   # Application data
    ├── users/              # User metadata (JSON)
    ├── keys/               # Private/public keys (PEM)
    ├── certs/              # Certificates and CSRs (PEM)
    └── ca/                 # Root CA files
```

## Menu Options Summary

1. **Sign Up** - Register new user
2. **Login** - Authenticate user
3. **Modify Private Data** - Encrypt/decrypt user data (AEAD)
4. **Sign Document/Message** - Create digital signature
5. **Verify Signature** - Verify digital signature
6. **Verify Certificate** - Verify X.509 certificate chain
7. **Sign User Certificate** - CA admin: sign user CSR
8. **Encrypt Message (Asymmetric)** - BONUS: RSA encryption
9. **Decrypt Message (Asymmetric)** - BONUS: RSA decryption
10. **Modify Account** - Change password
11. **Exit** - Quit application

## Security Features

✅ Passwords never stored in cleartext  
✅ Private keys encrypted with AES-256-CBC  
✅ Unique salts for password hashing  
✅ Unique nonces for each encryption  
✅ Proper key management and storage  
✅ Certificate chain verification  
✅ Secure cryptographic primitives (Scrypt, ChaCha20Poly1305, RSA-PSS, RSA-OAEP)

## Testing Checklist

- [x] User registration works
- [x] User login works
- [x] Password hashing and verification
- [x] Data encryption and decryption
- [x] Digital signature generation
- [x] Digital signature verification
- [x] CSR generation
- [x] Certificate signing
- [x] Certificate verification
- [x] Asymmetric encryption (BONUS)
- [x] Asymmetric decryption (BONUS)
- [x] Account modification (password change)

## Notes for Report

When writing your report, make sure to cover:

1. **Architecture**: Explain the modular design (CryptoManager class, CLI interface)
2. **Cryptographic Choices**: Justify why Scrypt, ChaCha20Poly1305, RSA-PSS, RSA-OAEP were chosen
3. **Key Management**: Explain how keys are generated, stored, and protected
4. **PKI Implementation**: Describe the certificate generation and verification process
5. **Security Considerations**: Discuss password storage, key encryption, nonce management
6. **Limitations**: RSA message size limits, educational vs. production use

