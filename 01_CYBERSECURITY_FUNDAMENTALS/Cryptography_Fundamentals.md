# Cryptography Fundamentals: Hashes, MACs, AEAD, and Timing Attack Immunity

## 1. Overview

Cryptography is the mathematical science of protecting information against unauthorized modification, inspection, and forgery. In application security, cryptographic mechanisms must be selected and implemented with mathematical precision: subtle implementation flaws (such as non-constant-time comparisons or nonce reuse) can invalidate an otherwise robust cipher.

This document examines modern cryptographic primitives: **Cryptographic Hash Functions**, **Keyed-Hash Message Authentication Codes (HMAC)**, **Authenticated Encryption with Associated Data (AEAD / AES-256-GCM)**, **Password-Based Key Derivation (PBKDF2 / Argon2)**, and **Timing-Attack Resistance**. Real-world implementations are drawn from **SHIVAY Security** and **KAKIBO Auth Engine**.

---

## 2. Problem Statement

Cryptographic vulnerabilities rarely stem from breaking underlying mathematical algorithms (like AES or SHA-256). Instead, they occur due to implementation errors:
- **Side-Channel Timing Attacks:** Using standard equality operators (`==`) to compare secret tokens or password hashes leaks information through processor execution time variations, allowing attackers to guess strings character-by-character.
- **Unauthenticated Encryption (CBC bit-flipping):** Encrypting without integrity verification allows attackers to manipulate ciphertext bytes to alter plaintext outcomes (e.g. padding oracle attacks).
- **Nonce / IV Reuse in Stream Ciphers:** Reusing an Initialization Vector (IV) with the same key in AES-GCM completely compromises authenticity and leaks plaintext XOR differences.
- **Weak Key Derivation:** Storing passwords with fast hash algorithms (MD5, SHA-1, SHA-256) enables rapid GPU brute-force attacks capable of testing billions of guesses per second.

---

## 3. Security Objectives

1. **Eliminate Timing Side-Channels:** Use constant-time comparison algorithms (`hmac.compare_digest`) for all secret, hash, and token verifications.
2. **Enforce Authenticated Encryption:** Combine confidentiality and authenticity using AES-256-GCM AEAD mode, preventing ciphertext tampering.
3. **Resist GPU Brute-Force Attacks:** Enforce memory-hard and computationally expensive key derivation (PBKDF2-HMAC-SHA256 with $\ge 600,000$ iterations or Argon2id).
4. **Cryptographically Secure Entropy:** Generate random salts, challenge tokens, and session keys strictly using operating-system CSPRNGs (`secrets` module / `/dev/urandom`).

---

## 4. Architecture & Cryptographic Workflows

### A. AEAD Authenticated Encryption (AES-256-GCM)

```
Plaintext Message ──┐
                    ▼
           ┌─────────────────┐
Key (256-bit) ──►│   AES-256-GCM   │◄── 96-bit Nonce (Unique per message)
           └────────┬────────┘
                    │
            ┌───────┴───────┐
            ▼               ▼
        Ciphertext     128-bit Tag (MAC)
```
*Decryption Invariant:* The AES-GCM engine decrypts ciphertext *only if* the 128-bit Authentication Tag matches. If even 1 bit of ciphertext or tag is modified, the engine aborts immediately with an authentication failure.

### B. Constant-Time Comparison vs. Short-Circuiting `==`

```
Standard Comparison (==):
Secret:    "SECRET_KEY_ALPHA"
Guess:     "SECRET_KEY_BETA"
Step 1-11: Match... (Takes ~11 CPU cycles)
Step 12:   'A' != 'B' -> Return FALSE immediately! (Leaked execution duration)

Constant-Time (hmac.compare_digest):
Evaluates ALL characters across the entire length using XOR accumulation:
diff |= a[i] ^ b[i]
Returns (diff == 0) in constant time regardless of where mismatches occur.
```

---

## 5. Technical Explanation & Primitive Comparison

| Primitive Type | Algorithm | Primary Usage | Security Properties |
| :--- | :--- | :--- | :--- |
| **Hash Function** | SHA-256 (RFC 6234) | Payload integrity, content addressing | One-way, collision-resistant, 256-bit digest. |
| **Message Auth Code** | HMAC-SHA256 (RFC 2104) | Webhook signatures, challenge tokens | Keyed integrity, repudiation defense, proof of authenticity. |
| **Time-Step OTP** | TOTP (RFC 6238) | Multi-factor authentication | Truncated HMAC-SHA1 calculated over 30-second UNIX time slices. |
| **AEAD Cipher** | AES-256-GCM (NIST SP 800-38D) | Confidential data at rest, credentials | 256-bit confidentiality + 128-bit Galois Message Authentication Code. |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (RFC 8018) | User password hashing | 600,000 iterations + 128-bit random salt to defeat rainbow tables. |

---

## 6. Implementation Details

Verified implementation of constant-time password hashing and constant-time token verification from `src/shivai/security/auth.py` and `auth.py`:

```python
import hashlib
import hmac
import secrets

def derive_password_hash(password: str, salt: str = None) -> tuple[str, str]:
    """
    Derives a cryptographic key from password using PBKDF2-HMAC-SHA256 with 600,000 iterations.
    Returns (hex_hash, salt).
    """
    if not salt:
        salt = secrets.token_hex(16)  # 128-bit cryptographic salt
    
    derived_key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt.encode('utf-8'),
        iterations=600_000,
        dklen=32  # 256-bit output
    )
    return derived_key.hex(), salt

def verify_token_constant_time(presented_token: str, expected_token: str) -> bool:
    """
    Constant-time comparison preventing side-channel timing attacks.
    """
    if not presented_token or not expected_token:
        return False
    return hmac.compare_digest(presented_token.strip(), expected_token.strip())
```

---

## 7. Relevant Source File References

- `src/shivai/security/auth.py`: Constant-time token comparison implementation (`hmac.compare_digest`).
- `src/shivai/security/totp.py`: Dynamic truncation and HMAC-SHA1 calculation for RFC 6238 TOTP.
- `src/shivai/security/webhook_verifier.py`: HMAC-SHA256 raw-body digest generation and constant-time equality check.
- `auth.py` (Kakeibo): AES-256-GCM encrypted secret management (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).

---

## 8. Testing Methodology & Verification Evidence

### Methodology
1. **Cryptographic Validation Suite:** Run `pytest tests/test_transferred_skills.py::TestTransferredSkills::test_webhook_raw_hmac_sha256`.
2. **Bit-Flipping Resistance Test:** Invert 1 bit of an HMAC signature or AES-GCM ciphertext and assert that verification strictly returns `False`.
3. **Salt Uniqueness Audit:** Generate 1,000 password hashes and verify that zero duplicate salts are emitted.

### Evidence
- **Status:** **`[TESTED]`**
- **Test Suite:** `tests/test_transferred_skills.py`
- **Result:** PASSED. Verification tests confirmed exact digest calculations, valid rejection on 1-bit payload modification, and constant-time comparison safety.

---

## 9. Limitations & Known Issues

- **PBKDF2 Memory Consumption:** While PBKDF2 is computationally intensive, it requires minimal memory. For ultra-high security consumer password storage, Argon2id is preferred because its memory-hard design defeats ASIC and FPGA password cracking hardware.
- **AES-GCM Nonce Exhaustion:** A 96-bit nonce must never be repeated with the same 256-bit AES key. If random nonces are used, an AES key must be rotated after no more than $2^{32}$ encryption operations to prevent collision.

---

## 10. Security Recommendations

1. **Always Use `secrets` Over `random`:** Python's standard `random` module uses the Mersenne Twister PRNG, which is completely deterministic and insecure for cryptographic tokens.
2. **Never Implement Custom Encryption Modes:** Always rely on standardized AEAD libraries (`pyca/cryptography`) rather than chaining primitive block ciphers manually.
3. **Enforce Salt Uniqueness at the Database Layer:** Add unique constraints to password salt columns to guarantee that identical passwords produce completely different hash strings.

---

## 11. References

- RFC 2104: *HMAC: Keyed-Hashing for Message Authentication*.
- NIST Special Publication 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*.
- RFC 8018: *PKCS #5: Password-Based Cryptography Specification Version 2.1*.
- Ferguson, N., Schneier, B., & Kohno, T. (2010): *Cryptography Engineering: Design Principles and Practical Applications*.
