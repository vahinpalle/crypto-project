# Quick Start Guide

## Initial Setup (Do this once)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Root CA
```bash
python generate_ca.py
```
- Choose whether to password-protect the CA key (recommended: yes)
- If yes, enter and remember the password (you'll need it to sign certificates)
- This creates the Certificate Authority for your mini-PKI

## Complete Workflow Example

### Scenario: Alice wants to use the system

#### Step 1: Register Alice
```bash
python main.py
# Choose option 1: Sign Up
# Enter username: alice
# Enter password: alice123
```
This will:
- Create Alice's account
- Generate her RSA key pair
- Create a Certificate Signing Request (CSR)
- Store everything securely

#### Step 2: Sign Alice's Certificate (as CA administrator)
Open a new terminal and run:
```bash
python sign_certificate.py alice
# Enter the CA password (if you set one)
```
This creates `data/certs/alice_cert.pem`

#### Step 3: Login as Alice
Back in the main app:
```bash
# Choose option 2: Login
# Enter username: alice
# Enter password: alice123
```

#### Step 4: Store Private Data
```bash
# Choose option 3: Modify Private Data
# Enter your private notes/bio when prompted
# Press Enter twice to finish
```
Your data is now encrypted with ChaCha20Poly1305!

#### Step 5: Sign a Document
```bash
# Choose option 4: Sign Document/Message
# Enter your message when prompted
# Press Enter twice to finish
```
This creates:
- A binary signature file: `data/alice_signature_YYYYMMDD_HHMMSS.bin`
- A text file with the message and base64 signature: `data/alice_signature_YYYYMMDD_HHMMSS.txt`

#### Step 6: Verify a Signature (anyone can do this)
```bash
# Choose option 5: Verify Signature
# Enter public key path: data/keys/alice_public.pem
# Enter the original message
# Enter signature file path or paste base64 signature
```

#### Step 7: Verify Certificate
```bash
# Choose option 6: Verify Certificate
# Enter username: alice
```
This verifies Alice's certificate is signed by the Root CA.

## File Locations

After using the app, you'll have:

```
data/
├── users/
│   └── alice.json                    # Alice's metadata (password hash, salt, paths)
├── keys/
│   ├── alice_private.pem            # Alice's encrypted private key
│   └── alice_public.pem             # Alice's public key
├── certs/
│   ├── alice_csr.pem                # Certificate Signing Request
│   └── alice_cert.pem               # Signed certificate (after signing)
├── ca/
│   ├── root_ca.key                  # CA private key (keep secret!)
│   └── root_ca.crt                  # CA certificate
└── alice_signature_*.txt            # Signed documents
```

## Common Tasks

### Register a New User
1. Run `python main.py`
2. Choose option 1
3. Enter username and password

### Login
1. Choose option 2
2. Enter username and password
3. You must be logged in to use options 3 and 4

### Encrypt Private Data
1. Login first (option 2)
2. Choose option 3
3. Enter your data (can be multiple lines)
4. Press Enter twice when done

### Sign a Message
1. Login first (option 2)
2. Choose option 4
3. Enter your message
4. Press Enter twice when done
5. Share the signature file and public key for verification

### Verify Someone's Signature
1. Choose option 5 (no login needed)
2. Provide:
   - Path to their public key (e.g., `data/keys/bob_public.pem`)
   - The original message
   - Their signature (file path or base64 string)

### Sign Multiple Users' Certificates
For each user after they register:
```bash
python sign_certificate.py <username>
```

## Tips

- **Remember your passwords!** If you forget your user password, you can't decrypt your data or use your private key.
- **Keep the CA key safe!** The `root_ca.key` file is critical - if compromised, all certificates become untrustworthy.
- **Public keys are safe to share** - they're meant to be public.
- **Signatures prove authenticity** - they prove the message came from the owner of the private key.

## Troubleshooting

**"User already exists"**
- That username is taken, try a different one

**"Password verification failed"**
- Wrong password entered
- Password is case-sensitive

**"Certificate file not found"**
- Run `python sign_certificate.py <username>` to create the certificate first

**"CA certificate not found"**
- Make sure you ran `python generate_ca.py` first
- Check that `data/ca/root_ca.crt` exists

