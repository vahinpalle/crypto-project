# Secure Cryptography System

A CLI application built by Vahin, Revan, and Ayush for a cryptography course project. It handles password authentication, encrypted data storage, digital signatures, and a basic PKI setup using X.509 certificates.

## What This Does

Basically, it's a secure system where multiple users can:
- Register with username/password (passwords are hashed, never stored plain)
- Store private data encrypted with their password
- Sign messages/documents digitally
- Get X.509 certificates signed by a Root CA

All the crypto stuff uses proper libraries and follows best practices - Scrypt for password hashing, ChaCha20Poly1305 for encryption, RSA with PSS for signatures, etc.

## Quick Start

### Step 1: Install Dependencies

First, install the required Python package:

```bash
pip install -r requirements.txt
```

You only need the `cryptography` library (pyca/cryptography), which is the main one.

### Step 2: Generate the Root CA

Before anyone can register, you need to create the Certificate Authority that will sign user certificates. Run:

```bash
python generate_ca.py
```

It'll ask if you want to password-protect the CA key (you should - just pick a strong password and remember it, you'll need it later). This creates:
- `data/ca/root_ca.key` - The CA's private key
- `data/ca/root_ca.crt` - The CA certificate

**Important:** Keep that CA password safe. You'll need it every time you sign a user's certificate.

### Step 3: Run the Application

```bash
python main.py
```

That's it. The menu should pop up and you're good to go.

## How to Use It

### Registering a New User

1. Choose option `1` from the menu
2. Enter a username and password
3. Fill in the certificate info when it asks:
   - **Country**: 2-letter code only (like US, ES, FR, JP). Not the full country name - just the code.
   - **State/Province**: Whatever you want (e.g., "California", "Tokyo", "Madrid")
   - **City/Locality**: Your city
   - **Organization**: Your org name (defaults to "CryptoCourse" if you leave it blank)
   - The Common Name is automatically set to your username, so don't worry about that

The system will generate your RSA key pair (2048-bit), create a CSR (Certificate Signing Request), and save everything. Your password gets hashed with Scrypt before storage.

### Getting Your Certificate Signed

After registration, you have a CSR but not a signed certificate yet. To get it signed:

1. Choose option `7` (Sign User Certificate - CA Admin)
2. Enter the username
3. Enter the CA password (the one you set when running `generate_ca.py`)

This creates your signed X.509 certificate. You can then verify it works with option `6`.

### Logging In

1. Choose option `2`
2. Enter your username and password

If the password matches the stored hash, you're in. Pretty straightforward.

### Storing Private Data

Once logged in:

1. Choose option `3` (Modify Private Data)
2. If you already have data stored, you can view it decrypted or replace it
3. Enter your data (can be multiple lines, just press Enter twice when done)
4. It gets encrypted with ChaCha20Poly1305 using a key derived from your password

The encryption key is separate from your password hash - it's derived fresh each time using Scrypt. Your data is stored encrypted in your user JSON file.

### Signing Documents/Messages

1. Make sure you're logged in
2. Choose option `4`
3. Type your message (multi-line is fine, press Enter twice when done)
4. The system signs it with your private key using RSA-PSS with SHA256

Two files get created:
- A `.bin` file with the raw signature
- A `.txt` file with the message, signature (base64), and your public key location

You can share these for verification.

### Verifying Signatures

1. Choose option `5` (you don't need to be logged in for this)
2. Enter the signer's username OR the path to their public key file
3. Enter the original message
4. Provide the signature file path or paste the base64 signature

It'll tell you if the signature is valid or not. Anyone can verify signatures - you just need the public key.

### Verifying Certificates

1. Choose option `6`
2. Enter the username
3. The system checks if their certificate is valid and properly signed by your Root CA

This is useful to verify that a user's certificate hasn't been tampered with.

### Changing Account Info

Logged in users can modify their account with option `10`:
- Change username (renames all your files automatically)
- Change password (re-encrypts your data with the new password)
- Update certificate information (Country, State, City, Organization)

If you change certificate info, you'll need to get your certificate re-signed (option `7`) because the CSR gets regenerated.

### Bonus Features

Options `8` and `9` handle RSA asymmetric encryption/decryption. This is a bonus feature - you can encrypt small messages (< 190 bytes for 2048-bit keys) for a specific user. Only they can decrypt it with their private key.

**Note:** RSA can only encrypt small messages, so this is mainly for demonstrations. For real-world use, you'd combine RSA with symmetric encryption (hybrid encryption).

## Technical Details

### Password Hashing

Uses Scrypt with these parameters:
- n=16384 (CPU/memory cost)
- r=8 (block size)
- p=1 (parallelization)
- 256-bit output

Each user gets a unique 128-bit random salt. The salt and hash are stored separately in the user's JSON file (base64 encoded).

### Data Encryption

ChaCha20Poly1305 (AEAD cipher):
- 256-bit keys derived from password via Scrypt
- 96-bit nonces (random, unique per encryption)
- Provides both confidentiality and authenticity
- Nonce stored with ciphertext (base64 encoded)

### Digital Signatures

RSA-2048 with PSS padding:
- SHA256 for hashing
- MGF1 (Mask Generation Function 1) with SHA256
- PSS is more secure than older PKCS1v15 padding

### Certificates

X.509 certificates:
- User keys: 2048-bit RSA
- CA key: 4096-bit RSA (stronger for the authority)
- Certificates signed with SHA256 and PKCS1v15 padding
- Valid for 1 year by default

### File Structure

When you run the app, it creates a `data/` directory with:
- `users/` - JSON files with user metadata (passwords hashed, encrypted data, paths to keys)
- `keys/` - PEM files for private/public keys
- `certs/` - PEM files for CSRs and signed certificates
- `ca/` - Root CA key and certificate

Everything uses standard formats (PEM encoding, JSON for metadata, base64 for binary data in JSON).

## Security Notes

A few things worth mentioning:

- **Passwords are never stored in plaintext** - only Scrypt hashes and salts
- **Private keys are password-protected** - encrypted with AES-256-CBC before saving to disk
- **Unique nonces for every encryption** - prevents replay attacks
- **Proper certificate verification** - checks the full chain and signature validity

This is educational software though, so don't use it for anything mission-critical without proper security auditing first.

## Troubleshooting

**"Certificate signing failed"**: Make sure you entered the correct CA password. It's mandatory now.

**"Country code error"**: The country must be exactly 2 letters (like US, ES, JP). Full country names won't work.

**"User already exists"**: That username is taken. Pick a different one.

**"Invalid password" on login**: Either the password is wrong, or something went wrong with password storage. If you just registered, make sure you typed the password correctly both times.

**Can't find certificate files**: Make sure you ran `generate_ca.py` first, and that users have registered and had their CSRs signed.

## What's Not Included

This is a course project, so some production features are missing:
- Certificate revocation lists (CRLs)
- Key rotation mechanisms
- Rate limiting or brute force protection
- Network/API interface (it's CLI only)
- Key escrow or recovery mechanisms

But it covers all the core cryptographic concepts you'd need for a course project.

---

That should cover everything. If you run into issues, check that all the dependencies are installed and that the CA was set up correctly. Most problems come from missing CA files or wrong file paths.
